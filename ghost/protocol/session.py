"""
ghost.protocol.session — Session state machine for SpectrumQ.

Implements GhostSession managing the full lifecycle per STATE_MACHINE.md:

    INIT → HANDSHAKE → KEY_DERIVATION → ACTIVE_SESSION ⇄ REKEY
                                      ↓               ↓
                                 SUSPENDED       TERMINATED
                                      ↓
                                 TERMINATED
                         (any state) → COMPROMISED (terminal)

Only ACTIVE_SESSION state allows message encryption/decryption.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, TYPE_CHECKING

from ghost.crypto.keys import IdentityKey, SignedPreKey, EphemeralKey, PQPreKey
from ghost.crypto.ratchet import (
    RatchetState,
    initialize_alice,
    initialize_bob,
)
from ghost.protocol.handshake import (
    PQXDHInitiator,
    PQXDHResponder,
    HandshakeBundle,
    InitiatorHandshakeMessage,
)

if TYPE_CHECKING:
    from ghost.protocol.message import GhostMessage


class SessionState(str, Enum):
    """Session lifecycle states per STATE_MACHINE.md."""

    INIT = "INIT"
    HANDSHAKE = "HANDSHAKE"
    KEY_DERIVATION = "KEY_DERIVATION"
    ACTIVE_SESSION = "ACTIVE_SESSION"
    REKEY = "REKEY"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    COMPROMISED = "COMPROMISED"


class SessionError(Exception):
    """Raised when a session operation is invalid given current state."""
    pass


@dataclass
class GhostSession:
    """
    SpectrumQ session — manages the handshake, ratchet, and message flow.

    Lifecycle:
        Alice side:
            session = GhostSession.create_initiator(alice_identity)
            msg, handshake_bytes = session.initiate_handshake(bob_bundle)
            # send handshake_bytes to Bob
            # receive first message, session is now ACTIVE_SESSION

        Bob side:
            session = GhostSession.create_responder(bob_identity, bob_spk, bob_pqpk, bob_ratchet)
            session.complete_handshake(alice_handshake_msg)
            # session is now ACTIVE_SESSION
    """

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: SessionState = SessionState.INIT
    created_at: int = field(default_factory=lambda: int(time.time() * 1000))
    last_activity: int = field(default_factory=lambda: int(time.time() * 1000))

    # Identity
    local_identity: Optional[IdentityKey] = field(default=None, repr=False)
    remote_identity_key: Optional[bytes] = field(default=None, repr=False)

    # Ratchet state (active once ACTIVE_SESSION)
    ratchet_state: Optional[RatchetState] = field(default=None, repr=False)

    # Role
    is_initiator: bool = False

    # Message counters
    messages_sent: int = 0
    messages_received: int = 0

    # Rekey threshold
    rekey_after_messages: int = 100

    def _touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = int(time.time() * 1000)

    def _require_state(self, *allowed: SessionState) -> None:
        """Raise SessionError if not in one of the allowed states."""
        if self.state not in allowed:
            raise SessionError(
                f"Operation not permitted in state {self.state!r}. "
                f"Allowed: {[s.value for s in allowed]}"
            )

    def _transition(self, new_state: SessionState) -> None:
        """
        Transition to a new state.

        Validates that COMPROMISED and TERMINATED are terminal.
        """
        if self.state == SessionState.COMPROMISED:
            raise SessionError("Session is COMPROMISED — cannot transition")
        if self.state == SessionState.TERMINATED:
            raise SessionError("Session is TERMINATED — cannot transition")
        self.state = new_state
        self._touch()

    # ---------------------------------------------------------------------------
    # Factory constructors
    # ---------------------------------------------------------------------------

    @classmethod
    def create_initiator(
        cls,
        identity: IdentityKey,
        session_id: Optional[str] = None,
    ) -> "GhostSession":
        """Create a new session as the handshake initiator (Alice)."""
        return cls(
            session_id=session_id or str(uuid.uuid4()),
            local_identity=identity,
            is_initiator=True,
        )

    @classmethod
    def create_responder(
        cls,
        identity: IdentityKey,
        session_id: Optional[str] = None,
    ) -> "GhostSession":
        """Create a new session as the handshake responder (Bob)."""
        return cls(
            session_id=session_id or str(uuid.uuid4()),
            local_identity=identity,
            is_initiator=False,
        )

    # ---------------------------------------------------------------------------
    # Handshake — Initiator side
    # ---------------------------------------------------------------------------

    def initiate_handshake(
        self,
        bob_bundle: HandshakeBundle,
    ) -> InitiatorHandshakeMessage:
        """
        Initiate PQXDH handshake with Bob.

        Transitions: INIT → HANDSHAKE → KEY_DERIVATION → ACTIVE_SESSION

        Args:
            bob_bundle: Bob's public key bundle.

        Returns:
            InitiatorHandshakeMessage to send to Bob.

        Raises:
            SessionError: If not in INIT state.
            ValueError: If Bob's bundle is invalid.
        """
        self._require_state(SessionState.INIT)
        self._transition(SessionState.HANDSHAKE)

        if self.local_identity is None:
            raise SessionError("No local identity key")

        # Perform PQXDH
        initiator = PQXDHInitiator(self.local_identity)
        msg, root_key, session_seed = initiator.initiate(bob_bundle)

        self._transition(SessionState.KEY_DERIVATION)

        # Initialize Alice's ratchet with Bob's ratchet key
        self.ratchet_state = initialize_alice(root_key, bob_bundle.ratchet_key)

        self.remote_identity_key = bob_bundle.identity_key
        self._transition(SessionState.ACTIVE_SESSION)

        return msg

    # ---------------------------------------------------------------------------
    # Handshake — Responder side
    # ---------------------------------------------------------------------------

    def complete_handshake(
        self,
        alice_msg: InitiatorHandshakeMessage,
        responder: PQXDHResponder,
    ) -> None:
        """
        Complete PQXDH handshake from Bob's side.

        Transitions: INIT → HANDSHAKE → KEY_DERIVATION → ACTIVE_SESSION

        Args:
            alice_msg:  Handshake message from Alice.
            responder:  Configured PQXDHResponder with Bob's keys.

        Raises:
            SessionError: If not in INIT state.
        """
        self._require_state(SessionState.INIT)
        self._transition(SessionState.HANDSHAKE)

        root_key, session_seed = responder.respond(alice_msg)

        self._transition(SessionState.KEY_DERIVATION)

        # Initialize Bob's ratchet
        self.ratchet_state = initialize_bob(
            root_key,
            responder.ratchet_key.private_key_obj,
            responder.ratchet_key.public_key_bytes,
        )

        self.remote_identity_key = alice_msg.identity_key
        self._transition(SessionState.ACTIVE_SESSION)

    # ---------------------------------------------------------------------------
    # Message encryption / decryption
    # ---------------------------------------------------------------------------

    def encrypt_message(self, plaintext: Dict[str, Any]) -> "GhostMessage":
        """
        Encrypt a plaintext dict into a GhostMessage.

        Args:
            plaintext: Message content to encrypt.

        Returns:
            Signed and encrypted GhostMessage ready for transmission.

        Raises:
            SessionError: If not in ACTIVE_SESSION state.
        """
        from ghost.protocol.message import GhostMessage

        self._require_state(SessionState.ACTIVE_SESSION)

        if self.ratchet_state is None:
            raise SessionError("No ratchet state")

        msg = GhostMessage.create_data(
            session_id=self.session_id,
            sender_ephemeral_key=self.ratchet_state.dh_self_public or b"",
        )
        msg.encrypt_payload(plaintext, self)

        if self.local_identity:
            msg.sign(self.local_identity)

        self.messages_sent += 1
        self._touch()

        # Trigger rekey if threshold reached
        if self.messages_sent % self.rekey_after_messages == 0:
            self._transition(SessionState.REKEY)
            self._transition(SessionState.ACTIVE_SESSION)

        return msg

    def decrypt_message(self, msg: "GhostMessage") -> Dict[str, Any]:
        """
        Decrypt a received GhostMessage.

        Optionally verifies signature if remote identity key is known.

        Args:
            msg: Received GhostMessage.

        Returns:
            Decrypted plaintext dict.

        Raises:
            SessionError: If not in ACTIVE_SESSION or REKEY state.
            ValueError: If signature verification fails.
        """
        self._require_state(SessionState.ACTIVE_SESSION, SessionState.REKEY)

        if self.ratchet_state is None:
            raise SessionError("No ratchet state")

        # Verify signature if we know the remote identity key
        if self.remote_identity_key and msg.signature:
            if not msg.verify_signature(self.remote_identity_key):
                self._transition(SessionState.COMPROMISED)
                raise ValueError("Message signature verification failed — session COMPROMISED")

        plaintext = msg.decrypt_payload(self)
        self.messages_received += 1
        self._touch()

        return plaintext

    # ---------------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------------

    def suspend(self) -> None:
        """Suspend the session (e.g. due to inactivity)."""
        self._require_state(SessionState.ACTIVE_SESSION)
        self._transition(SessionState.SUSPENDED)

    def resume(self) -> None:
        """Resume a suspended session."""
        self._require_state(SessionState.SUSPENDED)
        self._transition(SessionState.ACTIVE_SESSION)

    def terminate(self) -> None:
        """
        Permanently terminate the session.

        Zeros out key material. Irreversible.
        """
        self._require_state(
            SessionState.ACTIVE_SESSION,
            SessionState.SUSPENDED,
            SessionState.REKEY,
        )
        # Zero out key material (best-effort in Python)
        if self.ratchet_state:
            self.ratchet_state.root_key = b"\x00" * 32
            self.ratchet_state.chain_key_send = None
            self.ratchet_state.chain_key_recv = None
        self.ratchet_state = None
        self._transition(SessionState.TERMINATED)

    def compromise(self, reason: str = "") -> None:
        """
        Mark session as COMPROMISED.

        Terminal state — cannot be recovered.
        """
        self.state = SessionState.COMPROMISED
        if self.ratchet_state:
            self.ratchet_state.root_key = b"\x00" * 32
            self.ratchet_state.chain_key_send = None
            self.ratchet_state.chain_key_recv = None
        self.ratchet_state = None

    @property
    def is_active(self) -> bool:
        """Return True if session can send/receive messages."""
        return self.state == SessionState.ACTIVE_SESSION

    def __repr__(self) -> str:
        return (
            f"GhostSession(id={self.session_id[:8]}..., "
            f"state={self.state.value}, "
            f"sent={self.messages_sent}, recv={self.messages_received})"
        )
