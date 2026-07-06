"""
ghost.protocol.message — Message framing and encryption for SpectrumQ.

Defines GhostMessage — the top-level message envelope per MESSAGE_SPEC.md.
Messages are typed (DATA, HANDSHAKE, REKEY, CONTROL), signed, and encrypted.

Wire format: JSON (Protobuf noted as future improvement).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ghost.protocol.session import GhostSession


class MessageType(str, Enum):
    """Valid message types per MESSAGE_SPEC.md."""

    DATA = "DATA"
    HANDSHAKE = "HANDSHAKE"
    REKEY = "REKEY"
    CONTROL = "CONTROL"


@dataclass
class GhostMessage:
    """
    SpectrumQ message envelope per MESSAGE_SPEC.md.

    All fields except payload are transmitted in the clear (but authenticated).
    The payload is encrypted using the session ratchet.
    The entire message is signed by the sender's identity key.
    """

    # --- Protocol fields ---
    version: str = "0.1"
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: MessageType = MessageType.DATA
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))

    # --- Key material (public, ephemeral) ---
    sender_ephemeral_key: bytes = field(default_factory=bytes, repr=False)
    receiver_ephemeral_key: bytes = field(default_factory=bytes, repr=False)

    # --- Encrypted payload ---
    payload: bytes = field(default_factory=bytes, repr=False)

    # --- Authentication ---
    signature: bytes = field(default_factory=bytes, repr=False)

    # --- Ratchet header (for DATA messages) ---
    ratchet_header: Optional[bytes] = field(default=None, repr=False)

    # ---------------------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------------------

    def encode(self) -> bytes:
        """
        Encode the message to bytes (JSON).

        Note: signature is computed over encode() output with signature=b"".
        Call after signing.
        """
        d = {
            "version": self.version,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "sender_ephemeral_key": self.sender_ephemeral_key.hex(),
            "receiver_ephemeral_key": self.receiver_ephemeral_key.hex(),
            "payload": self.payload.hex(),
            "signature": self.signature.hex(),
        }
        if self.ratchet_header is not None:
            d["ratchet_header"] = self.ratchet_header.hex()
        return json.dumps(d, separators=(",", ":")).encode()

    def encode_for_signing(self) -> bytes:
        """
        Encode message fields without signature for signing/verification.

        Canonical form: all fields except signature, sorted keys.
        """
        d = {
            "version": self.version,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "sender_ephemeral_key": self.sender_ephemeral_key.hex(),
            "receiver_ephemeral_key": self.receiver_ephemeral_key.hex(),
            "payload": self.payload.hex(),
        }
        if self.ratchet_header is not None:
            d["ratchet_header"] = self.ratchet_header.hex()
        # Sorted keys for deterministic canonical form
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def decode(cls, data: bytes) -> "GhostMessage":
        """Decode a message from bytes."""
        d = json.loads(data)
        return cls(
            version=d.get("version", "0.1"),
            message_id=d["message_id"],
            session_id=d["session_id"],
            type=MessageType(d["type"]),
            timestamp=d["timestamp"],
            sender_ephemeral_key=bytes.fromhex(d.get("sender_ephemeral_key", "")),
            receiver_ephemeral_key=bytes.fromhex(d.get("receiver_ephemeral_key", "")),
            payload=bytes.fromhex(d.get("payload", "")),
            signature=bytes.fromhex(d.get("signature", "")),
            ratchet_header=bytes.fromhex(d["ratchet_header"]) if "ratchet_header" in d else None,
        )

    # ---------------------------------------------------------------------------
    # Payload encryption / decryption
    # ---------------------------------------------------------------------------

    def encrypt_payload(
        self,
        plaintext: Dict[str, Any],
        session: "GhostSession",
    ) -> None:
        """
        Encrypt plaintext dict into self.payload using the session ratchet.

        Mutates self.payload and self.ratchet_header in place.

        Args:
            plaintext: Dict to encrypt (will be JSON-serialized).
            session:   Active GhostSession with initialized ratchet state.
        """
        from ghost.crypto.ratchet import ratchet_encrypt

        pt_bytes = json.dumps(plaintext, separators=(",", ":")).encode()
        aad = self._aad()

        header_bytes, ciphertext = ratchet_encrypt(
            session.ratchet_state, pt_bytes, aad
        )
        self.payload = ciphertext
        self.ratchet_header = header_bytes

    def decrypt_payload(
        self,
        session: "GhostSession",
    ) -> Dict[str, Any]:
        """
        Decrypt self.payload using the session ratchet.

        Args:
            session: Active GhostSession with initialized ratchet state.

        Returns:
            Decrypted plaintext as dict.

        Raises:
            ValueError: If decryption fails.
        """
        from ghost.crypto.ratchet import ratchet_decrypt

        if self.ratchet_header is None:
            raise ValueError("Message has no ratchet header — cannot decrypt")

        aad = self._aad()
        pt_bytes = ratchet_decrypt(
            session.ratchet_state, self.ratchet_header, self.payload, aad
        )
        return json.loads(pt_bytes)

    def _aad(self) -> bytes:
        """Associated data: stable message metadata for authenticated encryption."""
        return f"{self.version}:{self.message_id}:{self.session_id}:{self.type.value}".encode()

    # ---------------------------------------------------------------------------
    # Signing
    # ---------------------------------------------------------------------------

    def sign(self, identity_key: Any) -> None:
        """
        Sign the message with the sender's identity key.

        Mutates self.signature in place.

        Args:
            identity_key: IdentityKey instance with a sign() method.
        """
        canonical = self.encode_for_signing()
        self.signature = identity_key.sign(canonical)

    def verify_signature(self, sender_public_key: bytes) -> bool:
        """
        Verify the message signature against a sender public key.

        Args:
            sender_public_key: Ed25519 public key bytes.

        Returns:
            True if signature is valid, False otherwise.
        """
        from ghost.crypto.keys import IdentityKey

        canonical = self.encode_for_signing()
        return IdentityKey.verify(canonical, self.signature, sender_public_key)

    # ---------------------------------------------------------------------------
    # Factory helpers
    # ---------------------------------------------------------------------------

    @classmethod
    def create_data(
        cls,
        session_id: str,
        sender_ephemeral_key: bytes = b"",
        receiver_ephemeral_key: bytes = b"",
    ) -> "GhostMessage":
        """Create a new DATA message shell."""
        return cls(
            session_id=session_id,
            type=MessageType.DATA,
            sender_ephemeral_key=sender_ephemeral_key,
            receiver_ephemeral_key=receiver_ephemeral_key,
        )

    @classmethod
    def create_handshake(
        cls,
        session_id: str,
        payload_bytes: bytes,
        sender_ephemeral_key: bytes = b"",
    ) -> "GhostMessage":
        """Create a HANDSHAKE message with pre-encoded payload."""
        return cls(
            session_id=session_id,
            type=MessageType.HANDSHAKE,
            sender_ephemeral_key=sender_ephemeral_key,
            payload=payload_bytes,
        )

    @classmethod
    def create_rekey(cls, session_id: str) -> "GhostMessage":
        """Create a REKEY message."""
        return cls(session_id=session_id, type=MessageType.REKEY)

    @classmethod
    def create_control(
        cls,
        session_id: str,
        payload_bytes: bytes = b"",
    ) -> "GhostMessage":
        """Create a CONTROL message."""
        return cls(
            session_id=session_id,
            type=MessageType.CONTROL,
            payload=payload_bytes,
        )
