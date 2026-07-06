"""
tests/test_e2e.py — End-to-end: Alice and Bob exchange encrypted messages.

Full GHOST protocol stack:
  IdentityKey → PQXDHHandshake → GhostSession → encrypt → decrypt

If this passes, the protocol is working end-to-end.
"""
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.kem import is_post_quantum
from ghost.protocol.handshake import PQXDHInitiator, PQXDHResponder
from ghost.protocol.session import GhostSession, SessionState
from ghost.protocol.message import GhostMessage


def make_peer_pair():
    """
    Full PQXDH handshake → two ACTIVE_SESSION sessions.
    Returns (alice_session, bob_session).
    """
    alice_ik = IdentityKey()
    bob_ik = IdentityKey()
    bob_spk = SignedPreKey(bob_ik)
    bob_pqpk = PQPreKey()
    bob_ratchet = EphemeralKey()

    responder = PQXDHResponder(bob_ik, bob_spk, bob_pqpk, bob_ratchet)
    bob_bundle = responder.get_bundle()

    alice_session = GhostSession.create_initiator(alice_ik)
    hs_msg = alice_session.initiate_handshake(bob_bundle)

    bob_session = GhostSession.create_responder(bob_ik)
    bob_session.complete_handshake(hs_msg, responder)

    return alice_session, bob_session


class TestE2EExchange:
    @pytest.fixture
    def peers(self):
        return make_peer_pair()

    def test_sessions_active(self, peers):
        alice, bob = peers
        assert alice.state == SessionState.ACTIVE_SESSION
        assert bob.state == SessionState.ACTIVE_SESSION

    def test_alice_to_bob(self, peers):
        alice, bob = peers
        payload = {"text": "Hello Bob — GHOST is live.", "priority": "high"}
        assert bob.decrypt_message(alice.encrypt_message(payload)) == payload

    def test_multi_turn_conversation(self, peers):
        alice, bob = peers
        messages = [
            {"turn": 1, "text": "Hello Bob"},
            {"turn": 2, "text": "Protocol working?"},
            {"turn": 3, "text": "GHOST is secure"},
        ]
        for payload in messages:
            assert bob.decrypt_message(alice.encrypt_message(payload)) == payload

    def test_forward_secrecy_ciphertexts_differ(self, peers):
        alice, bob = peers
        payload = {"text": "same text"}
        enc1 = alice.encrypt_message(payload)
        _ = bob.decrypt_message(enc1)
        enc2 = alice.encrypt_message(payload)
        # Ratchet must produce unique ciphertext each time
        assert enc1 != enc2

    def test_tampered_message_rejected(self, peers):
        alice, bob = peers
        msg = alice.encrypt_message({"text": "secret"})
        # Decode→tamper payload bytes→re-encode
        import json, base64
        raw = json.loads(msg.encode())
        # Payload is hex-encoded — flip the last byte
        hex_payload = raw["payload"]
        payload_bytes = bytearray(bytes.fromhex(hex_payload))
        payload_bytes[-1] ^= 0xFF
        raw["payload"] = payload_bytes.hex()
        bad_msg = GhostMessage.decode(json.dumps(raw).encode())
        with pytest.raises(Exception):
            bob.decrypt_message(bad_msg)

    def test_terminated_session_blocked(self, peers):
        alice, _ = peers
        alice.terminate()
        assert alice.state == SessionState.TERMINATED
        with pytest.raises(Exception):
            alice.encrypt_message({"text": "fail"})

    def test_pq_status_reported(self):
        pq = is_post_quantum()
        assert isinstance(pq, bool)
        label = "ML-KEM-768 ✓" if pq else "X25519 fallback"
        print(f"\n  Crypto: {label}")


class TestPayloadVariety:
    @pytest.fixture
    def sessions(self):
        return make_peer_pair()

    def test_nested_dict(self, sessions):
        a, b = sessions
        p = {"type": "msg", "body": {"text": "nested", "tags": ["ghost", "pq"]}}
        assert b.decrypt_message(a.encrypt_message(p)) == p

    def test_unicode(self, sessions):
        a, b = sessions
        p = {"text": "こんにちは 🔐 мир سلام"}
        assert b.decrypt_message(a.encrypt_message(p)) == p

    def test_large_payload(self, sessions):
        a, b = sessions
        p = {"data": "x" * 8192}
        assert b.decrypt_message(a.encrypt_message(p)) == p

    def test_numeric_and_empty_values(self, sessions):
        a, b = sessions
        p = {"num": 42, "flag": False, "empty": "", "zero": 0}
        assert b.decrypt_message(a.encrypt_message(p)) == p
