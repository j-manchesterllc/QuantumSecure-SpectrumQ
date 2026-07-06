"""
ghost.identity.keyserver — Local key bundle registry.

Acts as the device-local "key server": stores and serves GHOST identity bundles
for known contacts, and manages your own published bundle (the one you share
out-of-band or via the bus).

This is NOT a network service — it's an on-disk registry that the transport
layer reads from. A future version will sync bundles via the SETH bus.

Storage layout (all files under base_dir)::

    bundles/
        <identity_hex>.json   — one file per contact
    own/
        bundle.json           — your current published bundle
        identity.json         — your long-term identity key (encrypted)

All files are JSON. Sensitive key material (private keys) is encrypted
with AES-256-GCM before writing. Public bundles are stored plaintext.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.protocol.handshake import HandshakeBundle


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NONCE_LEN = 12


# ---------------------------------------------------------------------------
# Bundle serialization helpers
# ---------------------------------------------------------------------------

def bundle_to_dict(bundle: HandshakeBundle) -> dict:
    """Serialize a HandshakeBundle to a JSON-compatible dict."""
    return bundle.to_dict()


def dict_to_bundle(d: dict) -> HandshakeBundle:
    """Deserialize a HandshakeBundle from a dict."""
    return HandshakeBundle.from_dict(d)


# ---------------------------------------------------------------------------
# KeyServer
# ---------------------------------------------------------------------------

class KeyServer:
    """
    Local key bundle registry.

    Stores contact bundles (public, plaintext) and your own identity
    (private key encrypted at rest).

    Args:
        base_dir:    Root directory for key storage.
        storage_key: 32-byte AES key for encrypting private key material.
                     If None, private key storage/retrieval will raise.
    """

    def __init__(
        self,
        base_dir: str | Path,
        storage_key: Optional[bytes] = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.storage_key = storage_key

        # Create directory layout
        (self.base_dir / "bundles").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "own").mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------------------
    # Contact bundle management (public, plaintext on disk)
    # ---------------------------------------------------------------------------

    def store_bundle(self, bundle: HandshakeBundle) -> None:
        """
        Store a contact's public key bundle by identity key fingerprint.

        Args:
            bundle: The contact's HandshakeBundle.
        """
        fp = bundle.identity_key.hex()
        path = self.base_dir / "bundles" / f"{fp}.json"
        path.write_text(json.dumps(bundle_to_dict(bundle), indent=2))

    def load_bundle(self, identity_key_hex: str) -> Optional[HandshakeBundle]:
        """
        Load a contact's bundle by identity key fingerprint.

        Args:
            identity_key_hex: Hex of the contact's identity public key.

        Returns:
            HandshakeBundle or None if not found.
        """
        path = self.base_dir / "bundles" / f"{identity_key_hex}.json"
        if not path.exists():
            return None
        d = json.loads(path.read_text())
        return dict_to_bundle(d)

    def list_contacts(self) -> list[str]:
        """Return a list of known contact fingerprints (identity key hex)."""
        return [p.stem for p in (self.base_dir / "bundles").glob("*.json")]

    def delete_bundle(self, identity_key_hex: str) -> bool:
        """
        Delete a contact's bundle.

        Returns True if deleted, False if not found.
        """
        path = self.base_dir / "bundles" / f"{identity_key_hex}.json"
        if path.exists():
            path.unlink()
            return True
        return False

    # ---------------------------------------------------------------------------
    # Own identity management (private key encrypted at rest)
    # ---------------------------------------------------------------------------

    def store_own_identity(self, identity: IdentityKey) -> None:
        """
        Store your own identity key (private key encrypted with storage_key).

        Args:
            identity: Your IdentityKey.

        Raises:
            ValueError: If no storage_key was provided.
        """
        if self.storage_key is None:
            raise ValueError("storage_key required to store private identity key")

        nonce = os.urandom(_NONCE_LEN)
        sk_bytes = identity.private_key_bytes
        ct = AESGCM(self.storage_key).encrypt(nonce, sk_bytes, b"ghost-identity-key")
        path = self.base_dir / "own" / "identity.json"
        path.write_text(json.dumps({
            "version": 1,
            "nonce": nonce.hex(),
            "ciphertext": ct.hex(),
            "public_key": identity.public_key_bytes.hex(),
        }, indent=2))

    def load_own_identity(self) -> Optional[IdentityKey]:
        """
        Load your own identity key from encrypted storage.

        Returns:
            IdentityKey or None if not stored.

        Raises:
            ValueError: If decryption fails or no storage_key provided.
        """
        path = self.base_dir / "own" / "identity.json"
        if not path.exists():
            return None

        if self.storage_key is None:
            raise ValueError("storage_key required to load private identity key")

        d = json.loads(path.read_text())
        nonce = bytes.fromhex(d["nonce"])
        ct = bytes.fromhex(d["ciphertext"])

        try:
            sk_bytes = AESGCM(self.storage_key).decrypt(nonce, ct, b"ghost-identity-key")
        except Exception as exc:
            raise ValueError(f"Identity key decryption failed: {exc}") from exc

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.from_private_bytes(sk_bytes)
        return IdentityKey(private_key=private_key)

    def store_own_bundle(self, bundle: HandshakeBundle) -> None:
        """
        Store your own published bundle (public keys only).

        Args:
            bundle: Your current HandshakeBundle (public keys only).
        """
        path = self.base_dir / "own" / "bundle.json"
        path.write_text(json.dumps(bundle_to_dict(bundle), indent=2))

    def load_own_bundle(self) -> Optional[HandshakeBundle]:
        """
        Load your own published bundle.

        Returns:
            HandshakeBundle or None if not stored.
        """
        path = self.base_dir / "own" / "bundle.json"
        if not path.exists():
            return None
        return dict_to_bundle(json.loads(path.read_text()))

    # ---------------------------------------------------------------------------
    # Fingerprinting
    # ---------------------------------------------------------------------------

    @staticmethod
    def fingerprint(identity_key_bytes: bytes) -> str:
        """
        Return a human-readable fingerprint of an identity key.

        Format: groups of 4 hex chars separated by colons (like SSH fingerprints).
        Example: a2be:51794a:a38e:9d...

        Args:
            identity_key_bytes: Raw 32-byte identity public key.

        Returns:
            Formatted fingerprint string.
        """
        import hashlib
        digest = hashlib.sha256(b"ghost-fingerprint-v1" + identity_key_bytes).hexdigest()
        return ":".join(digest[i:i+4] for i in range(0, 32, 4))
