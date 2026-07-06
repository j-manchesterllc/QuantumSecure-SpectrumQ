"""
tests/test_v03.py — v0.3 hardened ratchet + persistence + key server tests.

Covers:
  - Out-of-order message decryption (skipped key cache)
  - Session state serialization / deserialization (encrypted at rest)
  - KeyServer: store/load bundles, own identity, fingerprinting
  - ML-KEM-768 active (PQ backend confirmed)
"""
import os
import sys
import tempfile
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.kem import is_post_quantum
from ghost.crypto.ratchet import initialize_alice, initialize_bob, ratchet_encrypt, ratchet_decrypt
from ghost.crypto.persistence import (
    serialize_ratchet, deserialize_ratchet, derive_storage_key,
)
from ghost.protocol.handshake import PQXDHInitiator, PQXDHResponder
from ghost.protocol.session import GhostSession, SessionState
from ghost.identity.keyserver import KeyServer, bundle_to_dict, dict_to_bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_active_pair():
    alice_ik = IdentityKey()
    bob_ik = IdentityKey()
    spk = SignedPreKey(bob_ik)
    pqpk = PQPreKey()
    rk = EphemeralKey()
    resp = PQXDHResponder(bob_ik, spk, pqpk, rk)

    a = GhostSession.create_initiator(alice_ik)
    hs = a.initiate_handshake(resp.get_bundle())
    b = GhostSession.create_responder(bob_ik)
    b.complete_handshake(hs, resp)
    return a, b


def make_ratchet_pair():
    shared = os.urandom(32)
    bob_rk = EphemeralKey()
    alice = initialize_alice(shared, bob_rk.public_key_bytes)
    bob = initialize_bob(shared, bob_rk.private_key_obj, bob_rk.public_key_bytes)
    return alice, bob


# ---------------------------------------------------------------------------
# PQ backend check
# ---------------------------------------------------------------------------

class TestPQBackend:
    def test_ml_kem_768_active(self):
        """Confirm we're running ML-KEM-768, not the X25519 fallback."""
        assert is_post_quantum(), (
            "ML-KEM-768 not active! Check LD_LIBRARY_PATH and liboqs install."
        )


# ---------------------------------------------------------------------------
# Out-of-order message delivery
# ---------------------------------------------------------------------------

class TestOutOfOrder:
    def test_skipped_single_message(self):
        """Decrypt msg N+1 before N, then decrypt N from cache."""
        alice, bob = make_ratchet_pair()
        # Encrypt 3 messages without sending yet
        h0, ct0 = ratchet_encrypt(alice, b"msg 0", b"")
        h1, ct1 = ratchet_encrypt(alice, b"msg 1", b"")
        h2, ct2 = ratchet_encrypt(alice, b"msg 2", b"")

        # Bob receives out of order: 2, 0, 1
        assert ratchet_decrypt(bob, h2, ct2, b"") == b"msg 2"
        assert ratchet_decrypt(bob, h0, ct0, b"") == b"msg 0"
        assert ratchet_decrypt(bob, h1, ct1, b"") == b"msg 1"

    def test_skipped_with_dh_ratchet(self):
        """Skipped keys survive a DH ratchet step."""
        alice, bob = make_ratchet_pair()

        # Alice sends 2 messages, Bob skips first
        h0, ct0 = ratchet_encrypt(alice, b"skipped", b"")
        h1, ct1 = ratchet_encrypt(alice, b"received", b"")

        # Bob decrypts msg 1 first (triggers key skip)
        assert ratchet_decrypt(bob, h1, ct1, b"") == b"received"
        # Now bob can decrypt skipped msg 0
        assert ratchet_decrypt(bob, h0, ct0, b"") == b"skipped"

    def test_replay_attack_rejected(self):
        """Re-decrypting the same message must fail (key consumed)."""
        alice, bob = make_ratchet_pair()
        h, ct = ratchet_encrypt(alice, b"once", b"")
        ratchet_decrypt(bob, h, ct, b"")  # first decrypt succeeds
        with pytest.raises(Exception):
            ratchet_decrypt(bob, h, ct, b"")  # replay must fail


# ---------------------------------------------------------------------------
# Session persistence
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_derive_storage_key_deterministic(self):
        salt = os.urandom(32)
        k1 = derive_storage_key(b"passphrase", salt)
        k2 = derive_storage_key(b"passphrase", salt)
        assert k1 == k2 and len(k1) == 32

    def test_derive_storage_key_different_salt(self):
        k1 = derive_storage_key(b"pw", os.urandom(32))
        k2 = derive_storage_key(b"pw", os.urandom(32))
        assert k1 != k2

    def test_serialize_deserialize_roundtrip(self):
        alice, _ = make_ratchet_pair()
        storage_key = os.urandom(32)
        blob = serialize_ratchet(alice, storage_key)
        assert isinstance(blob, bytes) and len(blob) > 64
        restored = deserialize_ratchet(blob, storage_key)
        assert restored.root_key == alice.root_key
        assert restored.chain_key_send == alice.chain_key_send
        assert restored.send_message_number == alice.send_message_number

    def test_wrong_key_raises(self):
        alice, _ = make_ratchet_pair()
        blob = serialize_ratchet(alice, os.urandom(32))
        with pytest.raises(ValueError):
            deserialize_ratchet(blob, os.urandom(32))

    def test_tampered_blob_raises(self):
        alice, _ = make_ratchet_pair()
        storage_key = os.urandom(32)
        blob = bytearray(serialize_ratchet(alice, storage_key))
        blob[-1] ^= 0xFF
        with pytest.raises(ValueError):
            deserialize_ratchet(bytes(blob), storage_key)

    def test_ratchet_works_after_restore(self):
        alice, bob = make_ratchet_pair()
        storage_key = os.urandom(32)

        # Send one message, save state, restore, send another
        h0, ct0 = ratchet_encrypt(alice, b"before restore", b"")
        blob = serialize_ratchet(alice, storage_key)
        alice2 = deserialize_ratchet(blob, storage_key)

        # Bob decrypts original message
        assert ratchet_decrypt(bob, h0, ct0, b"") == b"before restore"

        # Send from restored state
        h1, ct1 = ratchet_encrypt(alice2, b"after restore", b"")
        assert ratchet_decrypt(bob, h1, ct1, b"") == b"after restore"

    def test_skipped_keys_survive_serialization(self):
        alice, bob = make_ratchet_pair()
        storage_key = os.urandom(32)

        h0, ct0 = ratchet_encrypt(alice, b"skip me", b"")
        h1, ct1 = ratchet_encrypt(alice, b"first", b"")

        # Bob decrypts h1 first — h0 gets cached
        ratchet_decrypt(bob, h1, ct1, b"")

        # Serialize bob's state with cached skipped key
        blob = serialize_ratchet(bob, storage_key)
        bob2 = deserialize_ratchet(blob, storage_key)

        # Restored bob can decrypt the cached skipped message
        assert ratchet_decrypt(bob2, h0, ct0, b"") == b"skip me"


# ---------------------------------------------------------------------------
# KeyServer
# ---------------------------------------------------------------------------

class TestKeyServer:
    @pytest.fixture
    def keyserver(self, tmp_path):
        storage_key = os.urandom(32)
        return KeyServer(tmp_path, storage_key=storage_key), storage_key

    def test_store_and_load_bundle(self, keyserver):
        ks, _ = keyserver
        bob_ik = IdentityKey()
        spk = SignedPreKey(bob_ik)
        pqpk = PQPreKey()
        rk = EphemeralKey()
        resp = PQXDHResponder(bob_ik, spk, pqpk, rk)
        bundle = resp.get_bundle()

        ks.store_bundle(bundle)
        fp = bundle.identity_key.hex()
        loaded = ks.load_bundle(fp)

        assert loaded is not None
        assert loaded.identity_key == bundle.identity_key
        assert loaded.ratchet_key == bundle.ratchet_key
        assert loaded.pq_pre_key == bundle.pq_pre_key

    def test_load_nonexistent_bundle_returns_none(self, keyserver):
        ks, _ = keyserver
        assert ks.load_bundle("deadbeef" * 8) is None

    def test_list_contacts(self, keyserver):
        ks, _ = keyserver
        assert ks.list_contacts() == []

        for _ in range(3):
            bob_ik = IdentityKey()
            spk = SignedPreKey(bob_ik)
            resp = PQXDHResponder(bob_ik, spk, PQPreKey(), EphemeralKey())
            ks.store_bundle(resp.get_bundle())

        assert len(ks.list_contacts()) == 3

    def test_delete_bundle(self, keyserver):
        ks, _ = keyserver
        bob_ik = IdentityKey()
        spk = SignedPreKey(bob_ik)
        resp = PQXDHResponder(bob_ik, spk, PQPreKey(), EphemeralKey())
        bundle = resp.get_bundle()
        ks.store_bundle(bundle)
        fp = bundle.identity_key.hex()

        assert ks.delete_bundle(fp) is True
        assert ks.load_bundle(fp) is None
        assert ks.delete_bundle(fp) is False  # already gone

    def test_store_and_load_own_identity(self, keyserver):
        ks, _ = keyserver
        ik = IdentityKey()
        ks.store_own_identity(ik)
        loaded = ks.load_own_identity()
        assert loaded is not None
        assert loaded.public_key_bytes == ik.public_key_bytes

    def test_wrong_storage_key_raises(self, tmp_path):
        ks1 = KeyServer(tmp_path, storage_key=os.urandom(32))
        ks2 = KeyServer(tmp_path, storage_key=os.urandom(32))
        ik = IdentityKey()
        ks1.store_own_identity(ik)
        with pytest.raises(ValueError):
            ks2.load_own_identity()

    def test_fingerprint_format(self):
        ik = IdentityKey()
        fp = KeyServer.fingerprint(ik.public_key_bytes)
        parts = fp.split(":")
        assert len(parts) == 8
        assert all(len(p) == 4 for p in parts)

    def test_fingerprint_deterministic(self):
        ik = IdentityKey()
        assert KeyServer.fingerprint(ik.public_key_bytes) == KeyServer.fingerprint(ik.public_key_bytes)

    def test_fingerprint_unique_per_key(self):
        fp1 = KeyServer.fingerprint(IdentityKey().public_key_bytes)
        fp2 = KeyServer.fingerprint(IdentityKey().public_key_bytes)
        assert fp1 != fp2

    def test_store_and_load_own_bundle(self, keyserver):
        ks, _ = keyserver
        own_ik = IdentityKey()
        spk = SignedPreKey(own_ik)
        resp = PQXDHResponder(own_ik, spk, PQPreKey(), EphemeralKey())
        bundle = resp.get_bundle()

        ks.store_own_bundle(bundle)
        loaded = ks.load_own_bundle()
        assert loaded is not None
        assert loaded.identity_key == bundle.identity_key
