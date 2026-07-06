"""
ghost.crypto.keys — Key types for SpectrumQ.

Provides:
    IdentityKey  — long-term Ed25519 signing key pair
    SignedPreKey — X25519 key signed by identity key
    EphemeralKey — X25519 ephemeral key
    PQPreKey     — ML-KEM-768 pre-key (or fallback)

All key types support serialization to/from bytes and hex.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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

from ghost.crypto.kem import generate_keypair as kem_generate_keypair


# ---------------------------------------------------------------------------
# IdentityKey — Ed25519 long-term signing key
# ---------------------------------------------------------------------------


@dataclass
class IdentityKey:
    """
    Long-term Ed25519 identity key pair.

    Used to sign pre-keys and authenticate handshake messages.
    Never transmitted as secret key — only public key is shared.
    """

    _private_key: Ed25519PrivateKey = field(repr=False)

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None) -> None:
        """Generate a new identity key, or load from an existing private key."""
        if private_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw public key bytes (32 bytes for Ed25519)."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def private_key_bytes(self) -> bytes:
        """Return raw private key bytes. Keep secret."""
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary data. Returns 64-byte Ed25519 signature."""
        return self._private_key.sign(data)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
        """
        Verify an Ed25519 signature.

        Returns True on success, False on failure (never raises on bad sig).
        """
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pk.verify(signature, data)
            return True
        except Exception:
            return False

    def public_key_hex(self) -> str:
        """Return hex-encoded public key."""
        return self.public_key_bytes.hex()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "IdentityKey":
        """Load an IdentityKey from raw private key bytes."""
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_private_hex(cls, hex_str: str) -> "IdentityKey":
        """Load an IdentityKey from hex-encoded private key bytes."""
        return cls.from_private_bytes(bytes.fromhex(hex_str))

    def to_dict(self, include_private: bool = False) -> dict:
        """Serialize to dict. Never includes private key unless explicitly requested."""
        d: dict = {"type": "IdentityKey", "public_key": self.public_key_hex()}
        if include_private:
            d["private_key"] = self.private_key_bytes.hex()
        return d


# ---------------------------------------------------------------------------
# SignedPreKey — X25519 medium-term key, signed by IdentityKey
# ---------------------------------------------------------------------------


@dataclass
class SignedPreKey:
    """
    X25519 pre-key signed by the owner's IdentityKey.

    Rotated periodically (e.g. weekly).
    The signature proves ownership and prevents key substitution attacks.
    """

    _private_key: X25519PrivateKey = field(repr=False)
    signature: bytes = field(repr=False)
    key_id: int = 0

    def __init__(
        self,
        identity_key: IdentityKey,
        key_id: int = 0,
        private_key: Optional[X25519PrivateKey] = None,
    ) -> None:
        """
        Generate (or load) a signed pre-key, then sign the public key.

        Args:
            identity_key: The owner's long-term identity key used to sign.
            key_id:       Monotonically increasing key identifier.
            private_key:  If provided, use this key instead of generating.
        """
        if private_key is None:
            self._private_key = X25519PrivateKey.generate()
        else:
            self._private_key = private_key
        self.key_id = key_id
        # Sign: key_id (4 bytes big-endian) || public_key (32 bytes)
        self.signature = identity_key.sign(
            self.key_id.to_bytes(4, "big") + self.public_key_bytes
        )

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw X25519 public key bytes (32 bytes)."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def private_key_bytes(self) -> bytes:
        """Return raw private key bytes. Keep secret."""
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @property
    def private_key_obj(self) -> X25519PrivateKey:
        """Return the underlying private key object for DH operations."""
        return self._private_key

    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @staticmethod
    def verify_signature(
        public_key_bytes: bytes,
        signature: bytes,
        identity_public_key_bytes: bytes,
        key_id: int = 0,
    ) -> bool:
        """Verify a signed pre-key signature against an identity public key."""
        return IdentityKey.verify(
            key_id.to_bytes(4, "big") + public_key_bytes,
            signature,
            identity_public_key_bytes,
        )

    def to_dict(self, include_private: bool = False) -> dict:
        d: dict = {
            "type": "SignedPreKey",
            "key_id": self.key_id,
            "public_key": self.public_key_hex(),
            "signature": self.signature.hex(),
        }
        if include_private:
            d["private_key"] = self.private_key_bytes.hex()
        return d


# ---------------------------------------------------------------------------
# EphemeralKey — single-use X25519 key
# ---------------------------------------------------------------------------


@dataclass
class EphemeralKey:
    """
    Single-use X25519 ephemeral key.

    Generated fresh for each handshake or ratchet step.
    MUST NOT be reused.
    """

    _private_key: X25519PrivateKey = field(repr=False)

    def __init__(self, private_key: Optional[X25519PrivateKey] = None) -> None:
        """Generate a new ephemeral key, or load from an existing private key."""
        if private_key is None:
            self._private_key = X25519PrivateKey.generate()
        else:
            self._private_key = private_key

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def private_key_bytes(self) -> bytes:
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @property
    def private_key_obj(self) -> X25519PrivateKey:
        return self._private_key

    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "EphemeralKey":
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def to_dict(self, include_private: bool = False) -> dict:
        d: dict = {
            "type": "EphemeralKey",
            "public_key": self.public_key_hex(),
        }
        if include_private:
            d["private_key"] = self.private_key_bytes.hex()
        return d


# ---------------------------------------------------------------------------
# PQPreKey — ML-KEM-768 pre-key (post-quantum)
# ---------------------------------------------------------------------------


@dataclass
class PQPreKey:
    """
    Post-quantum pre-key using ML-KEM-768 (or fallback KEM).

    The public key is shared in the key bundle; the secret key is held locally.
    Used once per handshake to provide post-quantum forward secrecy.
    """

    _public_key: bytes = field(repr=False)
    _secret_key: bytes = field(repr=False)
    key_id: int = 0

    def __init__(self, key_id: int = 0) -> None:
        """Generate a new PQ pre-key."""
        self.key_id = key_id
        self._public_key, self._secret_key = kem_generate_keypair()

    @property
    def public_key_bytes(self) -> bytes:
        """Return KEM public key bytes."""
        return self._public_key

    @property
    def secret_key_bytes(self) -> bytes:
        """Return KEM secret key bytes. Keep secret."""
        return self._secret_key

    def public_key_hex(self) -> str:
        return self._public_key.hex()

    @classmethod
    def from_bytes(cls, pk: bytes, sk: bytes, key_id: int = 0) -> "PQPreKey":
        """Load a PQPreKey from raw bytes."""
        obj = object.__new__(cls)
        obj._public_key = pk
        obj._secret_key = sk
        obj.key_id = key_id
        return obj

    def to_dict(self, include_private: bool = False) -> dict:
        d: dict = {
            "type": "PQPreKey",
            "key_id": self.key_id,
            "public_key": self.public_key_hex(),
        }
        if include_private:
            d["secret_key"] = self._secret_key.hex()
        return d
