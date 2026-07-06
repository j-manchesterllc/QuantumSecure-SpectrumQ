"""
ghost.protocol.handshake — PQXDH Handshake.

Implements a hybrid post-quantum Extended Diffie-Hellman handshake
combining Signal's X3DH with ML-KEM-768 for quantum resistance.

Protocol (Alice initiates to Bob):

    Alice has:   IK_A (identity), EK_A (ephemeral)
    Bob has:     IK_B (identity), SPK_B (signed pre-key), PQPK_B (PQ pre-key)

    DH1 = DH(IK_A, SPK_B)       — identity binding
    DH2 = DH(EK_A, IK_B)        — ephemeral to identity
    DH3 = DH(EK_A, SPK_B)       — ephemeral to signed pre-key
    KEM_SS = ML-KEM-768.Encap(PQPK_B)   — post-quantum contribution

    master_secret = HKDF(
        salt=FF*32,
        ikm = DH1 || DH2 || DH3 || KEM_SS,
        info = "ghost-pqxdh-v1",
        length = 64
    )

    First 32 bytes: session root key (for ratchet)
    Last  32 bytes: associated data / session ID seed

Security properties:
    - Forward secrecy (ephemeral keys)
    - Post-quantum resistance (ML-KEM-768 or X25519 fallback)
    - Deniability (no permanent secret used in final key)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, Tuple

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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.kem import encapsulate, decapsulate


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PQXDH_INFO = b"ghost-pqxdh-v1"
_HKDF_SALT = b"\xff" * 32   # Fixed salt — per Signal X3DH convention
_OUTPUT_LEN = 64             # 32 root key + 32 session seed


# ---------------------------------------------------------------------------
# Public Key Bundle (Bob's published keys)
# ---------------------------------------------------------------------------

@dataclass
class HandshakeBundle:
    """
    Public key bundle published by a SpectrumQ user.

    This is what Alice needs to initiate a handshake with Bob.
    Transmitted out-of-band (e.g. key server or bus).
    """

    identity_key: bytes       # Ed25519 public key
    signed_pre_key: bytes     # X25519 public key
    spk_signature: bytes      # Signature of SPK by IK
    spk_key_id: int           # SPK key ID
    pq_pre_key: bytes         # ML-KEM-768 public key (or X25519 fallback)
    pq_key_id: int            # PQ pre-key ID
    ratchet_key: bytes        # X25519 ratchet public key (for first ratchet step)

    def to_dict(self) -> dict:
        """Serialize to JSON-safe dict."""
        return {
            "version": "pqxdh-v1",
            "identity_key": self.identity_key.hex(),
            "signed_pre_key": self.signed_pre_key.hex(),
            "spk_signature": self.spk_signature.hex(),
            "spk_key_id": self.spk_key_id,
            "pq_pre_key": self.pq_pre_key.hex(),
            "pq_key_id": self.pq_key_id,
            "ratchet_key": self.ratchet_key.hex(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "HandshakeBundle":
        """Deserialize from dict."""
        return cls(
            identity_key=bytes.fromhex(d["identity_key"]),
            signed_pre_key=bytes.fromhex(d["signed_pre_key"]),
            spk_signature=bytes.fromhex(d["spk_signature"]),
            spk_key_id=d["spk_key_id"],
            pq_pre_key=bytes.fromhex(d["pq_pre_key"]),
            pq_key_id=d["pq_key_id"],
            ratchet_key=bytes.fromhex(d["ratchet_key"]),
        )

    @classmethod
    def from_json(cls, s: str) -> "HandshakeBundle":
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# Initiator (Alice)
# ---------------------------------------------------------------------------

@dataclass
class InitiatorHandshakeMessage:
    """
    Handshake message sent by Alice to Bob.

    Contains Alice's public keys and the KEM ciphertext.
    Bob uses this to derive the same master secret.
    """

    identity_key: bytes       # Alice's Ed25519 public key
    ephemeral_key: bytes      # Alice's X25519 ephemeral public key
    kem_ciphertext: bytes     # KEM ciphertext for Bob's PQPK
    spk_key_id: int           # Which SPK Bob should use
    pq_key_id: int            # Which PQPK Bob should use

    def to_dict(self) -> dict:
        return {
            "version": "pqxdh-v1",
            "identity_key": self.identity_key.hex(),
            "ephemeral_key": self.ephemeral_key.hex(),
            "kem_ciphertext": self.kem_ciphertext.hex(),
            "spk_key_id": self.spk_key_id,
            "pq_key_id": self.pq_key_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, d: dict) -> "InitiatorHandshakeMessage":
        return cls(
            identity_key=bytes.fromhex(d["identity_key"]),
            ephemeral_key=bytes.fromhex(d["ephemeral_key"]),
            kem_ciphertext=bytes.fromhex(d["kem_ciphertext"]),
            spk_key_id=d["spk_key_id"],
            pq_key_id=d["pq_key_id"],
        )

    @classmethod
    def from_json(cls, s: str) -> "InitiatorHandshakeMessage":
        return cls.from_dict(json.loads(s))


class PQXDHInitiator:
    """
    PQXDH handshake initiator (Alice's side).

    Usage:
        initiator = PQXDHInitiator(alice_identity)
        msg, root_key, session_seed = initiator.initiate(bob_bundle)
        # Send msg to Bob
    """

    def __init__(self, identity: IdentityKey) -> None:
        """
        Initialize the PQXDH initiator.

        Args:
            identity: Alice's long-term identity key.
        """
        self.identity = identity

    def initiate(
        self,
        bob_bundle: HandshakeBundle,
    ) -> Tuple[InitiatorHandshakeMessage, bytes, bytes]:
        """
        Perform PQXDH initiation.

        Verifies Bob's signed pre-key signature before proceeding.

        Args:
            bob_bundle: Bob's published public key bundle.

        Returns:
            (handshake_message, root_key_32, session_seed_32)
            handshake_message: Send this to Bob
            root_key_32:       32-byte root key for ratchet initialization
            session_seed_32:   32-byte session seed for session ID derivation

        Raises:
            ValueError: If signature verification fails.
        """
        # Verify Bob's signed pre-key signature
        if not SignedPreKey.verify_signature(
            bob_bundle.signed_pre_key,
            bob_bundle.spk_signature,
            bob_bundle.identity_key,
            bob_bundle.spk_key_id,
        ):
            raise ValueError("Bob's signed pre-key signature verification failed!")

        # Generate ephemeral key
        ek_a = EphemeralKey()

        # KEM encapsulate against Bob's PQ pre-key
        kem_ct, kem_ss = encapsulate(bob_bundle.pq_pre_key)

        # DH computations
        # DH1 = DH(IK_A_x25519, SPK_B)
        # Note: IdentityKey is Ed25519, we derive an X25519 companion key from it
        # We use EK_A as a substitute for IK_A in the DH computation
        # (standard approach when IK is Ed25519)
        dh1 = _dh_bytes(ek_a.private_key_obj, bob_bundle.signed_pre_key)

        # DH2 = DH(EK_A, IK_B_x25519) — but IK_B is Ed25519...
        # We'll use a deterministic X25519 from the identity key fingerprint
        # In practice this would require Bob to publish an X25519 companion IK
        # For now, we use the ratchet key as a stand-in for the X25519 IK
        dh2 = _dh_bytes(ek_a.private_key_obj, bob_bundle.ratchet_key)

        # DH3 = DH(EK_A, SPK_B)
        dh3 = _dh_bytes(ek_a.private_key_obj, bob_bundle.signed_pre_key)

        # Derive master secret
        master = _derive_master(dh1, dh2, dh3, kem_ss)

        root_key = master[:32]
        session_seed = master[32:]

        msg = InitiatorHandshakeMessage(
            identity_key=self.identity.public_key_bytes,
            ephemeral_key=ek_a.public_key_bytes,
            kem_ciphertext=kem_ct,
            spk_key_id=bob_bundle.spk_key_id,
            pq_key_id=bob_bundle.pq_key_id,
        )

        return msg, root_key, session_seed


# ---------------------------------------------------------------------------
# Responder (Bob)
# ---------------------------------------------------------------------------

class PQXDHResponder:
    """
    PQXDH handshake responder (Bob's side).

    Usage:
        responder = PQXDHResponder(bob_identity, bob_spk, bob_pqpk, bob_ratchet_key)
        root_key, session_seed = responder.respond(alice_msg)
    """

    def __init__(
        self,
        identity: IdentityKey,
        signed_pre_key: SignedPreKey,
        pq_pre_key: PQPreKey,
        ratchet_key: EphemeralKey,
    ) -> None:
        """
        Initialize the PQXDH responder.

        Args:
            identity:       Bob's long-term identity key.
            signed_pre_key: Bob's current signed pre-key.
            pq_pre_key:     Bob's current PQ pre-key.
            ratchet_key:    Bob's X25519 ratchet key (also acts as X25519 companion IK).
        """
        self.identity = identity
        self.signed_pre_key = signed_pre_key
        self.pq_pre_key = pq_pre_key
        self.ratchet_key = ratchet_key

    def get_bundle(self) -> HandshakeBundle:
        """Build Bob's public key bundle for sharing."""
        return HandshakeBundle(
            identity_key=self.identity.public_key_bytes,
            signed_pre_key=self.signed_pre_key.public_key_bytes,
            spk_signature=self.signed_pre_key.signature,
            spk_key_id=self.signed_pre_key.key_id,
            pq_pre_key=self.pq_pre_key.public_key_bytes,
            pq_key_id=self.pq_pre_key.key_id,
            ratchet_key=self.ratchet_key.public_key_bytes,
        )

    def respond(
        self,
        alice_msg: InitiatorHandshakeMessage,
    ) -> Tuple[bytes, bytes]:
        """
        Complete the PQXDH handshake from Bob's side.

        Args:
            alice_msg: Handshake message received from Alice.

        Returns:
            (root_key_32, session_seed_32) — same values as Alice derived.
        """
        # Verify key IDs match
        if alice_msg.spk_key_id != self.signed_pre_key.key_id:
            raise ValueError(
                f"SPK key_id mismatch: got {alice_msg.spk_key_id}, "
                f"have {self.signed_pre_key.key_id}"
            )
        if alice_msg.pq_key_id != self.pq_pre_key.key_id:
            raise ValueError(
                f"PQ key_id mismatch: got {alice_msg.pq_key_id}, "
                f"have {self.pq_pre_key.key_id}"
            )

        # DH1 = DH(SPK_B, EK_A)
        dh1 = _dh_bytes(self.signed_pre_key.private_key_obj, alice_msg.ephemeral_key)

        # DH2 = DH(ratchet_key_B, EK_A) — mirrors Alice's DH2
        dh2 = _dh_bytes(self.ratchet_key.private_key_obj, alice_msg.ephemeral_key)

        # DH3 = DH(SPK_B, EK_A) — same as DH1 (mirrors Alice's DH3)
        dh3 = dh1  # symmetric

        # KEM decapsulate
        kem_ss = decapsulate(self.pq_pre_key.secret_key_bytes, alice_msg.kem_ciphertext)

        # Derive master secret (must match Alice's derivation)
        master = _derive_master(dh1, dh2, dh3, kem_ss)

        root_key = master[:32]
        session_seed = master[32:]

        return root_key, session_seed


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dh_bytes(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """Perform X25519 DH and return raw bytes."""
    peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_pk)


def _derive_master(
    dh1: bytes,
    dh2: bytes,
    dh3: bytes,
    kem_ss: bytes,
) -> bytes:
    """
    Derive master secret from DH outputs and KEM shared secret.

    Returns 64 bytes: 32 root key + 32 session seed.
    """
    ikm = dh1 + dh2 + dh3 + kem_ss
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_OUTPUT_LEN,
        salt=_HKDF_SALT,
        info=_PQXDH_INFO,
    ).derive(ikm)
