"""
tests/test_protocol.py — Handshake, session state machine, and message framing tests.
"""
import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.protocol.handshake import PQXDHInitiator, PQXDHResponder
from ghost.protocol.session import GhostSession, SessionState, SessionError
from ghost.protocol.message import GhostMessage, MessageType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_bob_responder():
    bob_ik = IdentityKey()
    bob_spk = SignedPreKey(bob_ik)
    bob_pqpk = PQPreKey()
    bob_ratchet = EphemeralKey()
    return PQXDHResponder(bob_ik, bob_spk, bob_pqpk, bob_ratchet)


def make_active_pair():
    """Return (alice_session, bob_session) both in ACTIVE_SESSION."""
    alice_ik = IdentityKey()
    responder = make_bob_responder()

    alice_session = GhostSession.create_initiator(alice_ik)
    hs_msg = alice_session.initiate_handshake(responder.get_bundle())

    bob_session = GhostSession.create_responder(responder.identity)
    bob_session.complete_handshake(hs_msg, responder)

    return alice_session, bob_session


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------
class TestPQXDHHandshake:
    def test_initiate_returns_tuple(self):
        alice_ik = IdentityKey()
        initiator = PQXDHInitiator(alice_ik)
        responder = make_bob_responder()
        hs_msg, root_key, session_seed = initiator.initiate(responder.get_bundle())
        assert len(root_key) == 32
        assert len(session_seed) == 32
        assert hs_msg is not None

    def test_both_sides_same_root_key(self):
        alice_ik = IdentityKey()
        responder = make_bob_responder()
        hs_msg, alice_root, _ = PQXDHInitiator(alice_ik).initiate(responder.get_bundle())
        bob_root, _ = responder.respond(hs_msg)
        assert alice_root == bob_root

    def test_both_sides_same_session_seed(self):
        alice_ik = IdentityKey()
        responder = make_bob_responder()
        hs_msg, _, alice_seed = PQXDHInitiator(alice_ik).initiate(responder.get_bundle())
        _, bob_seed = responder.respond(hs_msg)
        assert alice_seed == bob_seed

    def test_unique_root_keys_per_handshake(self):
        alice_ik = IdentityKey()
        r1, r2 = make_bob_responder(), make_bob_responder()
        _, root1, _ = PQXDHInitiator(alice_ik).initiate(r1.get_bundle())
        _, root2, _ = PQXDHInitiator(alice_ik).initiate(r2.get_bundle())
        assert root1 != root2

    def test_bundle_attributes(self):
        b = make_bob_responder().get_bundle()
        for attr in ['identity_key', 'signed_pre_key', 'spk_signature', 'pq_pre_key', 'ratchet_key']:
            assert hasattr(b, attr), f"Missing: {attr}"

    def test_wrong_spk_id_raises(self):
        alice_ik = IdentityKey()
        responder = make_bob_responder()
        hs_msg, _, _ = PQXDHInitiator(alice_ik).initiate(responder.get_bundle())
        hs_msg.spk_key_id = "wrong-id"
        with pytest.raises(ValueError):
            responder.respond(hs_msg)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class TestGhostSession:
    def test_initial_state_init(self):
        session = GhostSession.create_initiator(IdentityKey())
        assert session.state == SessionState.INIT

    def test_active_after_handshake(self):
        alice, bob = make_active_pair()
        assert alice.state == SessionState.ACTIVE_SESSION
        assert bob.state == SessionState.ACTIVE_SESSION

    def test_has_session_id(self):
        alice, _ = make_active_pair()
        assert alice.session_id and len(alice.session_id) > 0

    def test_terminate(self):
        alice, _ = make_active_pair()
        alice.terminate()
        assert alice.state == SessionState.TERMINATED

    def test_encrypt_decrypt(self):
        alice, bob = make_active_pair()
        payload = {"text": "hello", "n": 42}
        assert bob.decrypt_message(alice.encrypt_message(payload)) == payload

    def test_cannot_encrypt_after_terminate(self):
        alice, _ = make_active_pair()
        alice.terminate()
        with pytest.raises(Exception):
            alice.encrypt_message({"text": "fail"})

    def test_multiple_messages(self):
        alice, bob = make_active_pair()
        for i in range(5):
            result = bob.decrypt_message(alice.encrypt_message({"n": i}))
            assert result["n"] == i

    def test_cannot_initiate_twice(self):
        alice_ik = IdentityKey()
        responder = make_bob_responder()
        session = GhostSession.create_initiator(alice_ik)
        session.initiate_handshake(responder.get_bundle())
        with pytest.raises(Exception):
            session.initiate_handshake(responder.get_bundle())


# ---------------------------------------------------------------------------
# Message framing
# ---------------------------------------------------------------------------
class TestGhostMessage:
    def _make_data_msg(self, session_id="s"):
        return GhostMessage.create_data(
            session_id=session_id,
            sender_ephemeral_key=b"\xaa" * 32,
            receiver_ephemeral_key=b"\xbb" * 32,
        )

    def test_create_data_message(self):
        msg = self._make_data_msg("sess-123")
        assert msg.type == MessageType.DATA
        assert msg.session_id == "sess-123"

    def test_encode_decode_roundtrip(self):
        msg = self._make_data_msg("sess-abc")
        decoded = GhostMessage.decode(msg.encode())
        assert decoded.session_id == msg.session_id
        assert decoded.type == msg.type
        assert decoded.message_id == msg.message_id

    def test_unique_message_ids(self):
        assert self._make_data_msg().message_id != self._make_data_msg().message_id

    def test_all_factory_methods_exist(self):
        for factory in ['create_data', 'create_handshake', 'create_rekey', 'create_control']:
            assert hasattr(GhostMessage, factory), f"Missing: {factory}"
