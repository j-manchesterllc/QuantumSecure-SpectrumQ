"""
quantum_bus.py — GHOST/QUANTUM unified bus SDK
Wraps the three authenticated REST routes on sethassistant.digital/api/v1.
stdlib only, zero deps, Python 3.8+.

Usage:
    from lib.quantum_bus import QuantumBus
    bus = QuantumBus()                                      # reads BUS_TOKEN_QUANTUM from env
    bus.send("SETH", "secure.message", {"text": "hello"})  # send to any system
    for msg in bus.poll():                                  # drain replies (auto-marked delivered)
        handle(msg)                                         # fields: source, messageType, payload …

Never hardcode the token — keep it in BUS_TOKEN_QUANTUM env var only.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Generator, List, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://sethassistant.digital/api/v1"
SYSTEM_NAME = "QUANTUM"

# Valid targets on the bus
VALID_TARGETS = {"SETH", "AEGIS", "HERMES", "CLAW", "GHOST", "QUANTUM"}

# Retry / backoff config
_MAX_RETRIES = 4
_BACKOFF_BASE = 1.0   # seconds; doubles each retry
_BACKOFF_MAX = 30.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_token() -> str:
    token = (
        os.environ.get("BUS_TOKEN_QUANTUM")
        or os.environ.get("QUANTUM_BUS_TOKEN")
        or ""
    ).strip()
    if not token:
        raise EnvironmentError(
            "Neither BUS_TOKEN_QUANTUM nor QUANTUM_BUS_TOKEN is set. "
            "Export one before importing QuantumBus."
        )
    return token


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {_get_token()}",
        "Content-Type": "application/json",
        "User-Agent": "QuantumBus-SDK/0.1 (SpectrumQ; +https://quantumsecure.link)",
        "Accept": "application/json",
    }


def _request(
    method: str,
    path: str,
    body: Optional[Dict] = None,
    params: Optional[Dict] = None,
) -> Dict:
    """
    Execute an HTTP request with exponential backoff on 429 / 5xx.
    Returns the parsed JSON response dict.
    Raises RuntimeError on non-retriable errors.
    """
    url = BASE_URL + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    data = json.dumps(body).encode() if body else None
    headers = _headers()

    last_exc: Optional[Exception] = None
    for attempt in range(_MAX_RETRIES):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode()
                return json.loads(raw)

        except urllib.error.HTTPError as e:
            status = e.code
            raw = e.read().decode()

            if status in (429, 500, 502, 503, 504):
                # Retriable — exponential backoff
                delay = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
                time.sleep(delay)
                last_exc = e
                continue

            # Non-retriable HTTP error
            try:
                detail = json.loads(raw)
            except Exception:
                detail = raw
            raise RuntimeError(
                f"Bus HTTP {status} on {method} {path}: {detail}"
            ) from e

        except (urllib.error.URLError, OSError) as e:
            delay = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
            time.sleep(delay)
            last_exc = e
            continue

    raise RuntimeError(
        f"Bus request failed after {_MAX_RETRIES} attempts on {method} {path}"
    ) from last_exc


# ---------------------------------------------------------------------------
# Public SDK
# ---------------------------------------------------------------------------

class QuantumBus:
    """
    Thin client for the SETH unified agent bus.

    This instance always operates as QUANTUM (client-type).
    It can send to any system and poll its own inbound queue.
    """

    def __init__(self) -> None:
        # Eagerly validate the token is present at init time
        _get_token()

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send(
        self,
        target: str,
        message_type: str,
        payload: Dict[str, Any],
        priority: int = 2,
        source_session_id: Optional[str] = None,
    ) -> Dict:
        """
        Send a message to any system on the bus.

        Args:
            target:            Destination system (SETH | AEGIS | HERMES | CLAW | GHOST | QUANTUM)
            message_type:      Dot-namespaced type string e.g. "secure.message"
            payload:           Arbitrary JSON-serialisable dict (required, must not be empty)
            priority:          1=high, 2=normal (default), 3=low
            source_session_id: Optional session correlation id

        Returns:
            {"success": True, "message_id": "<uuid>", "status": "queued"}
        """
        target = target.upper()
        if target not in VALID_TARGETS:
            raise ValueError(
                f"Unknown target '{target}'. Valid targets: {sorted(VALID_TARGETS)}"
            )
        if not isinstance(payload, dict) or not payload:
            raise ValueError("payload must be a non-empty dict")

        body: Dict[str, Any] = {
            "source": SYSTEM_NAME,
            "target": target,
            "message_type": message_type,   # snake_case — server requirement
            "payload": payload,
            "priority": priority,
        }
        if source_session_id:
            body["source_session_id"] = source_session_id

        return _request("POST", "/agent-bus", body=body)

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(
        self,
        limit: int = 20,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Drain the QUANTUM inbound queue.

        Polling atomically flips matching rows pending → delivered.
        There is NO separate ack step for client-type systems.

        Yields message dicts with camelCase fields:
            id, source, target, messageType, payload,
            status, createdAt, deliveredAt

        Args:
            limit: Max messages to fetch in one call (default 20)
        """
        params = {
            "system": SYSTEM_NAME,
            "status": "pending",
            "limit": limit,
        }
        resp = _request("GET", "/poll", params=params)

        if not resp.get("success"):
            raise RuntimeError(f"Poll returned unsuccessful response: {resp}")

        messages: List[Dict] = resp.get("messages", [])
        for msg in messages:
            yield msg

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def send_to_seth(
        self,
        message_type: str,
        payload: Dict[str, Any],
        **kwargs,
    ) -> Dict:
        """Shorthand: send directly to SETH."""
        return self.send("SETH", message_type, payload, **kwargs)

    def drain(self, limit: int = 100) -> List[Dict]:
        """
        Drain all pending messages into a list (convenience wrapper over poll).
        Useful for batch processing.
        """
        return list(self.poll(limit=limit))
