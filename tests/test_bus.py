"""
tests/test_bus.py — Bus integration tests (live, requires BUS_TOKEN_QUANTUM env var).

These tests hit the real sethassistant.digital bus API.
Skip if token is not available (CI without secrets).
"""
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Load .env if present
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "home", "ubuntu", ".env")
_env_path2 = "/home/ubuntu/.env"
for _p in [_env_path2, _env_path]:
    if os.path.exists(_p):
        with open(_p) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _, _v = _line.partition("=")
                    os.environ.setdefault(_k.strip(), _v.strip())
        break

# Skip all bus tests if token is missing
pytestmark = pytest.mark.skipif(
    not (os.environ.get("BUS_TOKEN_QUANTUM") or os.environ.get("QUANTUM_BUS_TOKEN")),
    reason="BUS_TOKEN_QUANTUM not set — skipping live bus tests",
)


from ghost.transport.bus import BusTransport
from lib.quantum_bus import QuantumBus


class TestQuantumBusSDK:
    """Tests for the raw QuantumBus SDK."""

    def test_init_without_error(self):
        bus = QuantumBus()
        assert bus is not None

    def test_send_to_seth_returns_success(self):
        bus = QuantumBus()
        result = bus.send("SETH", "ghost.test.ping", {"source": "test_bus.py", "msg": "ping"})
        assert result.get("success") is True
        assert "message_id" in result
        assert result.get("status") == "queued"

    def test_send_with_priority(self):
        bus = QuantumBus()
        result = bus.send("SETH", "ghost.test.ping", {"msg": "high priority"}, priority=1)
        assert result.get("success") is True

    def test_poll_returns_list(self):
        bus = QuantumBus()
        messages = bus.drain()
        assert isinstance(messages, list)

    def test_drain_messages_have_expected_fields(self):
        bus = QuantumBus()
        # Send a message to ourselves (QUANTUM -> QUANTUM)
        bus.send("QUANTUM", "ghost.test.self", {"echo": "self-test"})
        import time; time.sleep(0.5)  # brief wait for delivery
        messages = bus.drain()
        for msg in messages:
            assert "source" in msg
            assert "messageType" in msg
            assert "payload" in msg


class TestBusTransport:
    """Tests for the GHOST BusTransport adapter."""

    def test_init(self):
        transport = BusTransport()
        assert transport is not None

    def test_send_control_message(self):
        transport = BusTransport()
        result = transport.send_control("SETH", {"action": "status_check", "from": "GHOST"})
        assert result is not None

    def test_send_handshake_message(self):
        transport = BusTransport()
        fake_handshake = {
            "initiator": "GHOST",
            "ephemeral_key": "aabbccdd" * 8,
            "pq_ciphertext": "00112233" * 16,
        }
        result = transport.send_handshake("SETH", fake_handshake)
        assert result is not None

    def test_poll_inbound_SKIP(self):  # renamed — method is poll_messages
        pass

    def test_poll_messages(self):
        transport = BusTransport()
        messages = transport.poll_messages()
        assert isinstance(messages, list)
