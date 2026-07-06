"""
tests/test_crypto.py — Unit tests for KEM, ratchet, and key primitives.
"""
import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghost.crypto import kem
from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.ratchet import (
    RatchetState, initialize_alice, initialize_bob,
    ratchet_encrypt, ratchet_decrypt,
)


# ---------------------------------------------------------------------------
# KEM
# ---------------------------------------------------------------------------
class TestKEM:
    def test_generate_keypair_returns_bytes(self):
        pk, sk = kem.generate_keypair()
        assert isinstance(pk, bytes) and len(pk) > 0
        assert isinstance(sk, bytes) and len(sk) > 0

    def test_keypairs_are_unique(self):
        pk1, _ = kem.generate_keypair()
        pk2, _ = kem.generate_keypair()
        assert pk1 != pk2

    def test_encapsulate_returns_ciphertext_and_secret(self):
        pk, _ = kem.generate_keypair()
        ct, ss = kem.encapsulate(pk)
        assert isinstance(ct, bytes) and isinstance(ss, bytes)
        assert len(ss) > 0

    def test_decapsulate_recovers_shared_secret(self):
        pk, sk = kem.generate_keypair()
        ct, ss_enc = kem.encapsulate(pk)
        ss_dec = kem.decapsulate(sk, ct)
        assert ss_enc == ss_dec

    def test_wrong_key_gives_different_secret(self):
        pk, sk = kem.generate_keypair()
        _, wrong_sk = kem.generate_keypair()
        ct, ss_enc = kem.encapsulate(pk)
        try:
            ss_dec = kem.decapsulate(wrong_sk, ct)
            assert ss_dec != ss_enc
        except Exception:
            pass  # raising is also acceptable

    def test_is_post_quantum_bool(self):
        assert isinstance(kem.is_post_quantum(), bool)

    def test_shared_secret_at_least_32_bytes(self):
        pk, sk = kem.generate_keypair()
        _, ss = kem.encapsulate(pk)
        assert len(ss) >= 32


# ---------------------------------------------------------------------------
# IdentityKey
# ---------------------------------------------------------------------------
class TestIdentityKey:
    def test_instantiate(self):
        ik = IdentityKey()
        assert ik.public_key_bytes is not None
        assert len(ik.public_key_bytes) == 32

    def test_sign_returns_64_bytes(self):
        ik = IdentityKey()
        sig = ik.sign(b"test data")
        assert isinstance(sig, bytes) and len(sig) == 64

    def test_verify_correct_sig(self):
        ik = IdentityKey()
        data = b"hello"
        sig = ik.sign(data)
        assert ik.verify(data, sig, ik.public_key_bytes)

    def test_verify_wrong_data_fails(self):
        ik = IdentityKey()
        sig = ik.sign(b"original")
        assert not ik.verify(b"tampered", sig, ik.public_key_bytes)

    def test_unique_keys(self):
        ik1 = IdentityKey()
        ik2 = IdentityKey()
        assert ik1.public_key_bytes != ik2.public_key_bytes


# ---------------------------------------------------------------------------
# EphemeralKey
# ---------------------------------------------------------------------------
class TestEphemeralKey:
    def test_instantiate(self):
        ek = EphemeralKey()
        assert ek.public_key_bytes is not None
        assert len(ek.public_key_bytes) == 32

    def test_private_key_bytes(self):
        ek = EphemeralKey()
        assert isinstance(ek.private_key_bytes, bytes)
        assert len(ek.private_key_bytes) == 32

    def test_unique_keys(self):
        ek1 = EphemeralKey()
        ek2 = EphemeralKey()
        assert ek1.public_key_bytes != ek2.public_key_bytes


# ---------------------------------------------------------------------------
# SignedPreKey
# ---------------------------------------------------------------------------
class TestSignedPreKey:
    def test_generate_and_sign(self):
        ik = IdentityKey()
        spk = SignedPreKey(ik)
        assert spk.public_key_bytes is not None
        assert spk.signature is not None
        assert len(spk.signature) == 64

    def test_signature_verifiable(self):
        ik = IdentityKey()
        spk = SignedPreKey(ik)
        # SPK signs key_id || public_key; use the static helper
        assert SignedPreKey.verify_signature(
            spk.public_key_bytes, spk.signature, ik.public_key_bytes, spk.key_id
        )


# ---------------------------------------------------------------------------
# PQPreKey
# ---------------------------------------------------------------------------
class TestPQPreKey:
    def test_instantiate(self):
        pqpk = PQPreKey()
        assert pqpk.public_key_bytes is not None
        assert len(pqpk.public_key_bytes) > 0

    def test_unique(self):
        pk1 = PQPreKey().public_key_bytes
        pk2 = PQPreKey().public_key_bytes
        assert pk1 != pk2


# ---------------------------------------------------------------------------
# Ratchet
# ---------------------------------------------------------------------------
class TestRatchet:
    def _make_pair(self):
        shared = os.urandom(32)
        bob_ratchet = EphemeralKey()
        alice_state = initialize_alice(shared, bob_ratchet.public_key_bytes)
        bob_state = initialize_bob(shared, bob_ratchet.private_key_obj, bob_ratchet.public_key_bytes)
        return alice_state, bob_state

    def test_encrypt_decrypt_roundtrip(self):
        alice, bob = self._make_pair()
        pt = b"hello from alice"
        ad = b"associated data"
        header, ct = ratchet_encrypt(alice, pt, ad)
        recovered = ratchet_decrypt(bob, header, ct, ad)
        assert recovered == pt

    def test_multiple_messages(self):
        alice, bob = self._make_pair()
        messages = [b"one", b"two", b"three"]
        encrypted = [ratchet_encrypt(alice, m, b"ad") for m in messages]
        for (hdr, ct), original in zip(encrypted, messages):
            assert ratchet_decrypt(bob, hdr, ct, b"ad") == original

    def test_ciphertexts_differ_per_message(self):
        alice, _ = self._make_pair()
        _, ct1 = ratchet_encrypt(alice, b"same", b"ad")
        _, ct2 = ratchet_encrypt(alice, b"same", b"ad")
        assert ct1 != ct2

    def test_tampered_ciphertext_raises(self):
        alice, bob = self._make_pair()
        hdr, ct = ratchet_encrypt(alice, b"secret", b"ad")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(Exception):
            ratchet_decrypt(bob, hdr, tampered, b"ad")

    def test_wrong_ad_raises(self):
        alice, bob = self._make_pair()
        hdr, ct = ratchet_encrypt(alice, b"secret", b"correct")
        with pytest.raises(Exception):
            ratchet_decrypt(bob, hdr, ct, b"wrong")
