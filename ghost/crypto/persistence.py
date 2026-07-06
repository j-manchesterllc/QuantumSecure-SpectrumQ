"""
ghost.crypto.persistence — Secure session state serialization.

Serializes RatchetState and GhostSession to/from encrypted JSON blobs,
allowing sessions to survive process restarts.

Encryption: AES-256-GCM with a storage key derived from a passphrase via
PBKDF2-HMAC-SHA256.  The storage key never appears on disk — only the
ciphertext + salt + nonce do.

Usage::

    # Save
    blob = serialize_ratchet(state, storage_key)
    path.write_bytes(blob)

    # Load
    state = deserialize_ratchet(path.read_bytes(), storage_key)
"""

from __future__ import annotations

import json
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)

from ghost.crypto.ratchet import RatchetState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommended minimum
_SALT_LEN = 32
_NONCE_LEN = 12
_KEY_LEN = 32
_VERSION = 1


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_storage_key(passphrase: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase)


# ---------------------------------------------------------------------------
# RatchetState serialization
# ---------------------------------------------------------------------------

def _ratchet_to_dict(state: RatchetState) -> dict:
    """Convert a RatchetState to a JSON-serializable dict."""
    skipped = {
        f"{dh_hex}:{n}": mk.hex()
        for (dh_hex, n), mk in state.skipped_keys.items()
    }
    sk_bytes: Optional[str] = None
    if state.dh_self_private is not None:
        sk_bytes = state.dh_self_private.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        ).hex()

    return {
        "version": _VERSION,
        "root_key": state.root_key.hex(),
        "chain_key_send": state.chain_key_send.hex() if state.chain_key_send else None,
        "chain_key_recv": state.chain_key_recv.hex() if state.chain_key_recv else None,
        "dh_self_private": sk_bytes,
        "dh_self_public": state.dh_self_public.hex() if state.dh_self_public else None,
        "dh_remote_public": state.dh_remote_public.hex() if state.dh_remote_public else None,
        "send_message_number": state.send_message_number,
        "recv_message_number": state.recv_message_number,
        "previous_chain_length": state.previous_chain_length,
        "skipped_keys": skipped,
    }


def _ratchet_from_dict(d: dict) -> RatchetState:
    """Reconstruct a RatchetState from a dict."""
    # Reconstruct X25519 private key
    dh_self_private: Optional[X25519PrivateKey] = None
    if d.get("dh_self_private"):
        dh_self_private = X25519PrivateKey.from_private_bytes(
            bytes.fromhex(d["dh_self_private"])
        )

    # Reconstruct skipped keys cache
    skipped: dict = {}
    for compound_key, mk_hex in d.get("skipped_keys", {}).items():
        dh_hex, _, n_str = compound_key.rpartition(":")
        skipped[(dh_hex, int(n_str))] = bytes.fromhex(mk_hex)

    state = RatchetState(
        root_key=bytes.fromhex(d["root_key"]),
        chain_key_send=bytes.fromhex(d["chain_key_send"]) if d.get("chain_key_send") else None,
        chain_key_recv=bytes.fromhex(d["chain_key_recv"]) if d.get("chain_key_recv") else None,
        dh_self_private=dh_self_private,
        dh_self_public=bytes.fromhex(d["dh_self_public"]) if d.get("dh_self_public") else None,
        dh_remote_public=bytes.fromhex(d["dh_remote_public"]) if d.get("dh_remote_public") else None,
        send_message_number=d["send_message_number"],
        recv_message_number=d["recv_message_number"],
        previous_chain_length=d["previous_chain_length"],
        skipped_keys=skipped,
    )
    return state


# ---------------------------------------------------------------------------
# Encrypted blob format: version(1) || salt(32) || nonce(12) || ciphertext
# ---------------------------------------------------------------------------

def serialize_ratchet(state: RatchetState, storage_key: bytes) -> bytes:
    """
    Serialize and encrypt a RatchetState.

    Args:
        state:       Ratchet state to persist.
        storage_key: 32-byte AES key for encryption. Derive with
                     derive_storage_key() or supply directly from a secure source.

    Returns:
        Encrypted blob bytes. Safe to write to disk.
    """
    plaintext = json.dumps(_ratchet_to_dict(state), separators=(",", ":")).encode()
    salt = os.urandom(_SALT_LEN)  # stored (not secret) — used for domain separation
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(storage_key).encrypt(nonce, plaintext, salt)
    version_byte = bytes([_VERSION])
    return version_byte + salt + nonce + ciphertext


def deserialize_ratchet(blob: bytes, storage_key: bytes) -> RatchetState:
    """
    Decrypt and deserialize a RatchetState.

    Args:
        blob:        Encrypted blob from serialize_ratchet().
        storage_key: Same 32-byte key used during serialization.

    Returns:
        Reconstructed RatchetState.

    Raises:
        ValueError: If decryption or deserialization fails.
    """
    if len(blob) < 1 + _SALT_LEN + _NONCE_LEN + 16:
        raise ValueError("Blob too short to be a valid serialized ratchet state")

    version = blob[0]
    if version != _VERSION:
        raise ValueError(f"Unsupported blob version: {version}")

    offset = 1
    salt = blob[offset: offset + _SALT_LEN]
    offset += _SALT_LEN
    nonce = blob[offset: offset + _NONCE_LEN]
    offset += _NONCE_LEN
    ciphertext = blob[offset:]

    try:
        plaintext = AESGCM(storage_key).decrypt(nonce, ciphertext, salt)
    except Exception as exc:
        raise ValueError(f"Ratchet state decryption failed: {exc}") from exc

    d = json.loads(plaintext)
    return _ratchet_from_dict(d)
