"""
ghost.crypto.kem — Key Encapsulation Mechanism (KEM).

Primary:  ML-KEM-768 via liboqs (post-quantum)
Fallback: X25519-based pseudo-KEM (classical, strong but not PQ)

The fallback is used automatically when liboqs is unavailable.
Both expose the same API:
    generate_keypair() -> (pk: bytes, sk: bytes)
    encapsulate(pk) -> (ciphertext: bytes, shared_secret: bytes)
    decapsulate(sk, ciphertext) -> shared_secret: bytes
"""

from __future__ import annotations

import os
import secrets
from typing import Tuple

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


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

_LIBOQS_AVAILABLE = False
_oqs = None

try:
    import oqs as _oqs_module  # type: ignore

    # Smoke test — newer liboqs-python (>=0.10) returns pk only from generate_keypair()
    _test_kem = _oqs_module.KeyEncapsulation("ML-KEM-768")
    _pk_test = _test_kem.generate_keypair()  # returns pk bytes only; sk in export_secret_key()
    assert isinstance(_pk_test, bytes) and len(_pk_test) > 0
    del _test_kem, _pk_test

    _oqs = _oqs_module
    _LIBOQS_AVAILABLE = True
    KEM_ALGORITHM = "ML-KEM-768"

except Exception:
    KEM_ALGORITHM = "X25519-HKDF-pseudo-KEM (liboqs unavailable)"


# ---------------------------------------------------------------------------
# liboqs ML-KEM-768 implementation
# ---------------------------------------------------------------------------

def _mlkem_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an ML-KEM-768 key pair using liboqs."""
    kem = _oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair()  # newer API: returns pk only
    sk = kem.export_secret_key()
    return bytes(pk), bytes(sk)


def _mlkem_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using the recipient's ML-KEM-768 public key."""
    kem = _oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(pk)
    return bytes(ciphertext), bytes(shared_secret)


def _mlkem_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate to recover the shared secret."""
    kem = _oqs.KeyEncapsulation("ML-KEM-768", secret_key=sk)
    shared_secret = kem.decap_secret(ciphertext)
    return bytes(shared_secret)


# ---------------------------------------------------------------------------
# X25519 pseudo-KEM fallback
#
# This is NOT a real KEM — it simulates one using ephemeral X25519 DH.
# Provides classical security but NOT post-quantum. Clearly marked.
# ---------------------------------------------------------------------------

_X25519_PK_LEN = 32


def _x25519_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate an X25519 key pair (fallback pseudo-KEM)."""
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return pk, sk_bytes


def _x25519_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
    """
    Pseudo-encapsulate: generate ephemeral X25519, DH with pk, derive shared secret.
    Ciphertext = ephemeral public key (32 bytes).
    """
    eph_sk = X25519PrivateKey.generate()
    eph_pk_bytes = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Load recipient public key
    recipient_pk = X25519PublicKey.from_public_bytes(pk)
    raw_dh = eph_sk.exchange(recipient_pk)

    # Derive shared secret via HKDF
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ghost-x25519-kem-ss",
    ).derive(raw_dh)

    # ciphertext is just the ephemeral public key
    return eph_pk_bytes, shared_secret


def _x25519_decapsulate(sk: bytes, ciphertext: bytes) -> bytes:
    """
    Pseudo-decapsulate: DH(sk, eph_pk) -> shared secret.
    ciphertext = ephemeral public key (32 bytes).
    """
    if len(ciphertext) != _X25519_PK_LEN:
        raise ValueError(
            f"X25519 pseudo-KEM: ciphertext must be {_X25519_PK_LEN} bytes, "
            f"got {len(ciphertext)}"
        )
    sk_obj = X25519PrivateKey.from_private_bytes(sk)
    eph_pk = X25519PublicKey.from_public_bytes(ciphertext)
    raw_dh = sk_obj.exchange(eph_pk)

    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ghost-x25519-kem-ss",
    ).derive(raw_dh)

    return shared_secret


# ---------------------------------------------------------------------------
# Public API — delegates to whichever backend is available
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a KEM key pair.

    Returns:
        (public_key, secret_key) as raw bytes.

    Uses ML-KEM-768 when liboqs is available, X25519 pseudo-KEM otherwise.
    """
    if _LIBOQS_AVAILABLE:
        return _mlkem_generate_keypair()
    return _x25519_generate_keypair()


def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the recipient's public key.

    Args:
        public_key: Recipient's KEM public key bytes.

    Returns:
        (ciphertext, shared_secret) — both as bytes.
        ciphertext is sent to the recipient; shared_secret is used locally.
    """
    if _LIBOQS_AVAILABLE:
        return _mlkem_encapsulate(public_key)
    return _x25519_encapsulate(public_key)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate to recover the shared secret.

    Args:
        secret_key:  Recipient's KEM secret key bytes.
        ciphertext:  Ciphertext from encapsulate().

    Returns:
        shared_secret: bytes — same value as produced by encapsulate().
    """
    if _LIBOQS_AVAILABLE:
        return _mlkem_decapsulate(secret_key, ciphertext)
    return _x25519_decapsulate(secret_key, ciphertext)


def is_post_quantum() -> bool:
    """Return True if the active backend is post-quantum (liboqs ML-KEM-768)."""
    return _LIBOQS_AVAILABLE
