"""
ghost.transport.bus — SETH bus transport adapter for SpectrumQ.

Wraps the QuantumBus SDK (lib/quantum_bus.py) to send/receive GhostMessages
over the SETH agent bus.

Message type namespacing:
    ghost.handshake  — PQXDH handshake initiation
    ghost.message    — Encrypted DATA messages
    ghost.rekey      — Rekey requests
    ghost.control    — Control / session management
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add repo root to path so we can import lib.quantum_bus
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from lib.quantum_bus import QuantumBus  # type: ignore

from ghost.protocol.message import GhostMessage, MessageType


# ---------------------------------------------------------------------------
# Message type constants
# ---------------------------------------------------------------------------

MT_HANDSHAKE = "ghost.handshake"
MT_MESSAGE = "ghost.message"
MT_REKEY = "ghost.rekey"
MT_CONTROL = "ghost.control"

_TYPE_TO_BUS = {
    MessageType.HANDSHAKE: MT_HANDSHAKE,
    MessageType.DATA: MT_MESSAGE,
    MessageType.REKEY: MT_REKEY,
    MessageType.CONTROL: MT_CONTROL,
}


class BusTransport:
    """
    SETH bus transport adapter.

    Wraps QuantumBus to send/receive GhostMessages.
    Handles serialization and target routing.
    """

    def __init__(self, bus: Optional[QuantumBus] = None) -> None:
        """
        Initialize the bus transport.

        Args:
            bus: Optional pre-configured QuantumBus instance.
                 If None, creates one from environment variables.
        """
        self._bus = bus or QuantumBus()

    # ---------------------------------------------------------------------------
    # Send
    # ---------------------------------------------------------------------------

    def send_message(
        self,
        target_system: str,
        ghost_msg: GhostMessage,
        priority: int = 2,
    ) -> Dict[str, Any]:
        """
        Send an encrypted GhostMessage over the bus.

        Args:
            target_system: Destination system name (SETH, AEGIS, HERMES, etc.)
            ghost_msg:     GhostMessage to send.
            priority:      Bus priority (1=high, 2=normal, 3=low).

        Returns:
            Bus send response dict: {"success": True, "message_id": ..., "status": "queued"}
        """
        msg_type = _TYPE_TO_BUS.get(ghost_msg.type, MT_CONTROL)

        # Encode message — everything including encrypted payload
        encoded = ghost_msg.encode().decode()

        payload = {
            "ghost_message": encoded,
            "session_id": ghost_msg.session_id,
            "message_id": ghost_msg.message_id,
            "ghost_type": ghost_msg.type.value,
        }

        return self._bus.send(
            target=target_system,
            message_type=msg_type,
            payload=payload,
            priority=priority,
        )

    def send_handshake(
        self,
        target_system: str,
        handshake_data: Dict[str, Any],
        session_id: str = "",
        priority: int = 1,
    ) -> Dict[str, Any]:
        """
        Send a PQXDH handshake initiation message.

        Args:
            target_system:  Destination system name.
            handshake_data: Serialized handshake message dict.
            session_id:     Session ID for correlation.
            priority:       Bus priority (default: high for handshakes).

        Returns:
            Bus send response dict.
        """
        payload = {
            "handshake": handshake_data,
            "session_id": session_id,
            "protocol": "pqxdh-v1",
        }
        return self._bus.send(
            target=target_system,
            message_type=MT_HANDSHAKE,
            payload=payload,
            priority=priority,
        )

    def send_control(
        self,
        target_system: str,
        command: str,
        data: Optional[Dict[str, Any]] = None,
        session_id: str = "",
    ) -> Dict[str, Any]:
        """
        Send a CONTROL message (e.g. session termination, ping).

        Args:
            target_system: Destination system name.
            command:       Control command string.
            data:          Optional command data.
            session_id:    Session ID for correlation.

        Returns:
            Bus send response dict.
        """
        payload: Dict[str, Any] = {
            "command": command,
            "session_id": session_id,
        }
        if data:
            payload["data"] = data
        return self._bus.send(
            target=target_system,
            message_type=MT_CONTROL,
            payload=payload,
        )

    # ---------------------------------------------------------------------------
    # Poll
    # ---------------------------------------------------------------------------

    def poll_messages(self, limit: int = 20) -> List[GhostMessage]:
        """
        Poll the inbound bus queue for GhostMessages.

        Drains up to `limit` pending messages and deserializes them.
        Messages that fail to deserialize are silently dropped (logged to stderr).

        Args:
            limit: Maximum messages to fetch.

        Returns:
            List of deserialized GhostMessage objects.
        """
        messages = []
        for raw in self._bus.poll(limit=limit):
            try:
                msg = self._deserialize_bus_message(raw)
                if msg is not None:
                    messages.append(msg)
            except Exception as e:
                # Log but don't crash on malformed messages
                import sys
                print(f"[BusTransport] Failed to deserialize message {raw.get('id', '?')}: {e}", file=sys.stderr)
        return messages

    def poll_raw(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Poll the inbound bus queue and return raw dicts (for non-GhostMessage bus traffic).

        Args:
            limit: Maximum messages to fetch.

        Returns:
            List of raw message dicts from the bus.
        """
        return list(self._bus.poll(limit=limit))

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _deserialize_bus_message(self, raw: Dict[str, Any]) -> Optional[GhostMessage]:
        """
        Deserialize a raw bus message into a GhostMessage.

        Returns None if this is not a ghost.* message type.
        """
        msg_type = raw.get("messageType", "")
        if not msg_type.startswith("ghost."):
            return None

        payload = raw.get("payload", {})

        if msg_type == MT_HANDSHAKE:
            # Handshake messages — reconstruct as HANDSHAKE GhostMessage
            handshake_data = payload.get("handshake", {})
            session_id = payload.get("session_id", "")
            msg = GhostMessage.create_handshake(
                session_id=session_id,
                payload_bytes=json.dumps(handshake_data).encode(),
            )
            return msg

        elif msg_type in (MT_MESSAGE, MT_REKEY, MT_CONTROL):
            # Encoded GhostMessage
            encoded = payload.get("ghost_message")
            if not encoded:
                return None
            return GhostMessage.decode(encoded.encode())

        return None
