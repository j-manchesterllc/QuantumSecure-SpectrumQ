"""
ghost.identity.identity — GhostIdentity: full identity and key management.

A GhostIdentity contains:
    - Long-term Ed25519 identity key (IK)
    - Signed X25519 pre-key (SPK) — rotated periodically
    - PQ pre-key (PQPK) — ML-KEM-768 or fallback
    - X25519 ratchet key (acts as companion X25519 identity key)

The identity can be serialized to/from JSON for persistent storage.
Public bundle (to_bundle) contains only public keys for sharing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.kem import is_post_quantum, KEM_ALGORITHM
from ghost.protocol.handshake import HandshakeBundle, PQXDHResponder


@dataclass
class GhostIdentity:
    """
    A complete SpectrumQ identity.

    Holds all key material needed to participate in SpectrumQ sessions.
    The name is a human-readable label (not cryptographically significant).

    Security note: Store carefully — contains private key material.
    """

    name: str
    identity_key: IdentityKey = field(repr=False)
    signed_pre_key: SignedPreKey = field(repr=False)
    pq_pre_key: PQPreKey = field(repr=False)
    ratchet_key: EphemeralKey = field(repr=False)

    def __init__(self, name: str) -> None:
        """
        Generate a new GhostIdentity with fresh key material.

        Args:
            name: Human-readable name for this identity (e.g. "alice", "SETH").
        """
        self.name = name
        self.identity_key = IdentityKey()
        self.signed_pre_key = SignedPreKey(self.identity_key, key_id=1)
        self.pq_pre_key = PQPreKey(key_id=1)
        self.ratchet_key = EphemeralKey()

    # ---------------------------------------------------------------------------
    # Public bundle
    # ---------------------------------------------------------------------------

    def to_bundle(self) -> dict:
        """
        Build a public key bundle for sharing with other participants.

        Contains ONLY public keys — safe to transmit.

        Returns:
            Dict suitable for HandshakeBundle.from_dict().
        """
        return {
            "version": "pqxdh-v1",
            "name": self.name,
            "identity_key": self.identity_key.public_key_hex(),
            "signed_pre_key": self.signed_pre_key.public_key_hex(),
            "spk_signature": self.signed_pre_key.signature.hex(),
            "spk_key_id": self.signed_pre_key.key_id,
            "pq_pre_key": self.pq_pre_key.public_key_hex(),
            "pq_key_id": self.pq_pre_key.key_id,
            "ratchet_key": self.ratchet_key.public_key_hex(),
            "kem_algorithm": KEM_ALGORITHM,
            "pq_capable": is_post_quantum(),
        }

    def get_handshake_bundle(self) -> HandshakeBundle:
        """Return a HandshakeBundle for use with PQXDH."""
        return HandshakeBundle.from_dict(self.to_bundle())

    def get_responder(self) -> PQXDHResponder:
        """Return a configured PQXDHResponder for handling inbound handshakes."""
        return PQXDHResponder(
            identity=self.identity_key,
            signed_pre_key=self.signed_pre_key,
            pq_pre_key=self.pq_pre_key,
            ratchet_key=self.ratchet_key,
        )

    # ---------------------------------------------------------------------------
    # Signing helpers (delegate to identity key)
    # ---------------------------------------------------------------------------

    def sign(self, data: bytes) -> bytes:
        """Sign data with the identity key."""
        return self.identity_key.sign(data)

    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature against an Ed25519 public key."""
        return IdentityKey.verify(data, signature, public_key)

    # ---------------------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------------------

    def to_json(self, include_private: bool = True) -> str:
        """
        Serialize the identity to JSON.

        Args:
            include_private: If True, includes all private keys (for storage).
                             If False, returns public-only bundle.

        Returns:
            JSON string.

        SECURITY: Only store with include_private=True in trusted locations.
        """
        if not include_private:
            return json.dumps(self.to_bundle(), indent=2)

        d = {
            "version": "ghost-identity-v1",
            "name": self.name,
            "identity_key": self.identity_key.to_dict(include_private=True),
            "signed_pre_key": self.signed_pre_key.to_dict(include_private=True),
            "pq_pre_key": self.pq_pre_key.to_dict(include_private=True),
            "ratchet_key": self.ratchet_key.to_dict(include_private=True),
            "kem_algorithm": KEM_ALGORITHM,
        }
        return json.dumps(d, indent=2)

    @classmethod
    def from_json(cls, data: str) -> "GhostIdentity":
        """
        Load a GhostIdentity from JSON.

        The JSON must contain private keys (as produced by to_json(include_private=True)).

        Args:
            data: JSON string.

        Returns:
            GhostIdentity with all key material loaded.

        Raises:
            ValueError: If JSON is missing required fields or keys.
        """
        d = json.loads(data)

        if d.get("version") != "ghost-identity-v1":
            raise ValueError(f"Unknown identity format version: {d.get('version')!r}")

        # Create empty object without calling __init__
        obj = object.__new__(cls)
        obj.name = d["name"]

        # Load identity key
        ik_d = d["identity_key"]
        obj.identity_key = IdentityKey.from_private_hex(ik_d["private_key"])

        # Load signed pre-key
        spk_d = d["signed_pre_key"]
        spk_private = X25519PrivateKey.from_private_bytes(bytes.fromhex(spk_d["private_key"]))
        obj.signed_pre_key = object.__new__(SignedPreKey)
        obj.signed_pre_key._private_key = spk_private
        obj.signed_pre_key.key_id = spk_d["key_id"]
        obj.signed_pre_key.signature = bytes.fromhex(spk_d["signature"])

        # Load PQ pre-key
        pq_d = d["pq_pre_key"]
        obj.pq_pre_key = PQPreKey.from_bytes(
            pk=bytes.fromhex(pq_d["public_key"]),
            sk=bytes.fromhex(pq_d["secret_key"]),
            key_id=pq_d["key_id"],
        )

        # Load ratchet key
        rk_d = d["ratchet_key"]
        rk_private = X25519PrivateKey.from_private_bytes(bytes.fromhex(rk_d["private_key"]))
        obj.ratchet_key = EphemeralKey(rk_private)

        return obj

    def save(self, path: Path) -> None:
        """
        Save identity to a file.

        SECURITY: Ensure the file has restrictive permissions (0600).
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(include_private=True))
        path.chmod(0o600)

    @classmethod
    def load(cls, path: Path) -> "GhostIdentity":
        """Load identity from a file."""
        return cls.from_json(Path(path).read_text())

    def __repr__(self) -> str:
        return (
            f"GhostIdentity(name={self.name!r}, "
            f"ik={self.identity_key.public_key_hex()[:16]}..., "
            f"pq={is_post_quantum()})"
        )
