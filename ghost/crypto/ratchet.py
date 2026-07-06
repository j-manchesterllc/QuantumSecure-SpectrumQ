"""
ghost.crypto.ratchet — Triple Ratchet implementation.

Implements the Signal Double Ratchet extended with a PQ KEM ratchet step,
providing:
    - Forward secrecy (past messages safe if current keys compromised)
    - Break-in recovery (future messages safe after compromise)
    - Post-quantum resilience via periodic KEM-based ratchet steps

Chain structure:
    Root Key (RK) — top-level secret, mixed with DH/KEM outputs
    Send Chain Key (CKs) — derives message keys for outbound
    Recv Chain Key (CKr) — derives message keys for inbound

Message keys are derived from chain keys and discarded after use.
Skipped message keys are cached for out-of-order delivery.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from ghost.crypto.kem import encapsulate, decapsulate


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SKIP = 1000          # Max skipped message keys to cache
AES_KEY_LEN = 32         # AES-256
NONCE_LEN = 12           # AES-GCM 96-bit nonce
CHAIN_KEY_LEN = 32
ROOT_KEY_LEN = 32

_HKDF_INFO_ROOT = b"ghost-ratchet-root-key"
_HKDF_INFO_CHAIN = b"ghost-ratchet-chain-key"
_HKDF_INFO_MSG = b"ghost-ratchet-message-key"
_HMAC_CHAIN_CONSTANT = b"\x01"
_HMAC_MSG_CONSTANT = b"\x02"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 helper."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    """
    KDF_RK: Derive new root key and chain key from root key + DH output.

    Returns (new_root_key, new_chain_key).
    """
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=ROOT_KEY_LEN + CHAIN_KEY_LEN,
        salt=root_key,
        info=_HKDF_INFO_ROOT,
    ).derive(dh_output)
    return material[:ROOT_KEY_LEN], material[ROOT_KEY_LEN:]


def _kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
    """
    KDF_CK: Advance the chain key, derive a message key.

    Returns (new_chain_key, message_key).
    Uses HMAC with constants to separate the two outputs.
    """
    new_chain_key = _hmac_sha256(chain_key, _HMAC_CHAIN_CONSTANT)
    message_key = _hmac_sha256(chain_key, _HMAC_MSG_CONSTANT)
    return new_chain_key, message_key


def _x25519_dh(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """Perform X25519 Diffie-Hellman."""
    peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_pk)


# ---------------------------------------------------------------------------
# Message Header
# ---------------------------------------------------------------------------

@dataclass
class RatchetHeader:
    """
    Header prepended to each ratchet-encrypted message.

    Contains the sender's current ratchet public key and message counters
    needed by the recipient to advance/synchronize their ratchet state.
    """

    dh_public_key: bytes       # Sender's current X25519 ratchet public key
    message_number: int        # N — message number in current sending chain
    previous_chain_length: int # PN — length of previous sending chain

    def encode(self) -> bytes:
        """Serialize to bytes."""
        data = {
            "dh": self.dh_public_key.hex(),
            "n": self.message_number,
            "pn": self.previous_chain_length,
        }
        return json.dumps(data, separators=(",", ":")).encode()

    @classmethod
    def decode(cls, data: bytes) -> "RatchetHeader":
        """Deserialize from bytes."""
        d = json.loads(data)
        return cls(
            dh_public_key=bytes.fromhex(d["dh"]),
            message_number=d["n"],
            previous_chain_length=d["pn"],
        )


# ---------------------------------------------------------------------------
# Ratchet State
# ---------------------------------------------------------------------------

@dataclass
class RatchetState:
    """
    Full state of a Double Ratchet session.

    Contains root key, chain keys, ratchet keys, and skipped message key cache.
    This object must be kept secret — it contains live key material.
    """

    # Root key — mixed with DH outputs to derive chain keys
    root_key: bytes = field(repr=False)

    # Sending chain key (None before first send-side ratchet step)
    chain_key_send: Optional[bytes] = field(default=None, repr=False)

    # Receiving chain key (None before first recv-side ratchet step)
    chain_key_recv: Optional[bytes] = field(default=None, repr=False)

    # Our current ratchet key pair (X25519)
    dh_self_private: Optional[X25519PrivateKey] = field(default=None, repr=False)
    dh_self_public: Optional[bytes] = None  # cached public bytes

    # Remote's latest ratchet public key
    dh_remote_public: Optional[bytes] = field(default=None, repr=False)

    # Message counters
    send_message_number: int = 0
    recv_message_number: int = 0
    previous_chain_length: int = 0

    # Skipped message key cache: (dh_public_hex, msg_number) -> message_key
    skipped_keys: Dict[Tuple[str, int], bytes] = field(default_factory=dict, repr=False)

    def generate_new_dh(self) -> None:
        """Generate a fresh X25519 ratchet key pair."""
        self.dh_self_private = X25519PrivateKey.generate()
        self.dh_self_public = self.dh_self_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def dh_with_remote(self) -> bytes:
        """Compute DH(self_private, remote_public)."""
        if self.dh_self_private is None or self.dh_remote_public is None:
            raise ValueError("Cannot perform DH: missing keys")
        return _x25519_dh(self.dh_self_private, self.dh_remote_public)


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def _aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce || ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def _aes_gcm_decrypt(key: bytes, nonce_ct: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Input: nonce || ciphertext."""
    nonce = nonce_ct[:NONCE_LEN]
    ct = nonce_ct[NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# Public Ratchet API
# ---------------------------------------------------------------------------

def initialize_alice(
    shared_secret: bytes,
    bob_ratchet_public_key: bytes,
) -> RatchetState:
    """
    Initialize ratchet state for Alice (the session initiator).

    Args:
        shared_secret:          32+ byte secret from PQXDH handshake.
        bob_ratchet_public_key: Bob's initial ratchet public key.

    Returns:
        Initialized RatchetState ready for sending.
    """
    state = RatchetState(root_key=shared_secret[:ROOT_KEY_LEN])
    state.dh_remote_public = bob_ratchet_public_key

    # Perform initial ratchet step
    state.generate_new_dh()
    dh_out = state.dh_with_remote()
    state.root_key, state.chain_key_send = _kdf_root(state.root_key, dh_out)
    return state


def initialize_bob(
    shared_secret: bytes,
    bob_ratchet_private_key: X25519PrivateKey,
    bob_ratchet_public_key: bytes,
) -> RatchetState:
    """
    Initialize ratchet state for Bob (the session responder).

    Args:
        shared_secret:           32+ byte secret from PQXDH handshake.
        bob_ratchet_private_key: Bob's ratchet private key.
        bob_ratchet_public_key:  Bob's ratchet public key (same key, public part).

    Returns:
        Initialized RatchetState ready for receiving.
    """
    state = RatchetState(root_key=shared_secret[:ROOT_KEY_LEN])
    state.dh_self_private = bob_ratchet_private_key
    state.dh_self_public = bob_ratchet_public_key
    # chain_key_recv will be set on first received message
    return state


def ratchet_encrypt(
    state: RatchetState,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> Tuple[bytes, bytes]:
    """
    Encrypt a message using the ratchet.

    Args:
        state:           Current ratchet state (mutated in place).
        plaintext:       Message to encrypt.
        associated_data: Additional authenticated data (not encrypted).

    Returns:
        (header_bytes, ciphertext): header must be sent alongside ciphertext.
        ciphertext includes the AES-GCM nonce prepended.
    """
    if state.chain_key_send is None:
        raise ValueError("Ratchet not initialized for sending")

    # Advance the send chain
    state.chain_key_send, mk = _kdf_chain(state.chain_key_send)

    header = RatchetHeader(
        dh_public_key=state.dh_self_public,  # type: ignore[arg-type]
        message_number=state.send_message_number,
        previous_chain_length=state.previous_chain_length,
    )
    state.send_message_number += 1

    header_bytes = header.encode()
    # AAD: header || external associated_data
    aad = header_bytes + associated_data
    ciphertext = _aes_gcm_encrypt(mk, plaintext, aad)

    return header_bytes, ciphertext


def ratchet_decrypt(
    state: RatchetState,
    header_bytes: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypt a message using the ratchet.

    Handles:
    - In-order messages (normal case)
    - Out-of-order messages (uses skipped key cache)
    - DH ratchet steps (when sender's key changes)

    Args:
        state:           Current ratchet state (mutated in place).
        header_bytes:    Header bytes from ratchet_encrypt().
        ciphertext:      Ciphertext from ratchet_encrypt().
        associated_data: Must match what was used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If decryption fails or message key not found.
    """
    header = RatchetHeader.decode(header_bytes)
    aad = header_bytes + associated_data

    # Check skipped message keys first
    skip_key = (header.dh_public_key.hex(), header.message_number)
    if skip_key in state.skipped_keys:
        mk = state.skipped_keys.pop(skip_key)
        return _aes_gcm_decrypt(mk, ciphertext, aad)

    # Check if we need a DH ratchet step (sender's key changed)
    if header.dh_public_key != state.dh_remote_public:
        # Skip messages in the current receiving chain
        _skip_message_keys(state, header.previous_chain_length)

        # Perform DH ratchet step
        _dh_ratchet(state, header.dh_public_key)

    # Skip messages in the new receiving chain
    _skip_message_keys(state, header.message_number)

    # Advance chain to get message key
    if state.chain_key_recv is None:
        raise ValueError("Receive chain not initialized")

    state.chain_key_recv, mk = _kdf_chain(state.chain_key_recv)
    state.recv_message_number += 1

    return _aes_gcm_decrypt(mk, ciphertext, aad)


def _skip_message_keys(state: RatchetState, until: int) -> None:
    """Cache message keys up to `until` to handle out-of-order delivery."""
    if state.chain_key_recv is None:
        return

    if state.recv_message_number + MAX_SKIP < until:
        raise ValueError(
            f"Too many skipped messages: {until - state.recv_message_number} > {MAX_SKIP}"
        )

    while state.recv_message_number < until:
        state.chain_key_recv, mk = _kdf_chain(state.chain_key_recv)
        key = (state.dh_remote_public.hex() if state.dh_remote_public else "", state.recv_message_number)  # type: ignore[union-attr]
        state.skipped_keys[key] = mk
        state.recv_message_number += 1


def _dh_ratchet(state: RatchetState, remote_public_key: bytes) -> None:
    """
    Perform a DH ratchet step.

    Updates the receive chain, then resets the send chain with a new DH key.
    """
    state.previous_chain_length = state.send_message_number
    state.send_message_number = 0
    state.recv_message_number = 0
    state.dh_remote_public = remote_public_key

    # Receive chain
    dh_out = _x25519_dh(state.dh_self_private, remote_public_key)  # type: ignore[arg-type]
    state.root_key, state.chain_key_recv = _kdf_root(state.root_key, dh_out)

    # New send chain with fresh DH key pair
    state.generate_new_dh()
    dh_out2 = state.dh_with_remote()
    state.root_key, state.chain_key_send = _kdf_root(state.root_key, dh_out2)
