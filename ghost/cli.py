"""
ghost.cli — SpectrumQ command-line interface.

Usage:
    python -m ghost init              # Generate identity, save to ~/.ghost/identity.json
    python -m ghost send SETH "hello" # Send a message via bus
    python -m ghost poll              # Drain inbound queue
    python -m ghost info              # Show identity public bundle
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Load env before any crypto/bus imports
# ---------------------------------------------------------------------------

def _load_env() -> None:
    """Load .env file from /home/ubuntu/.env if it exists."""
    env_path = Path("/home/ubuntu/.env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())


_load_env()


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

GHOST_DIR = Path.home() / ".ghost"
IDENTITY_FILE = GHOST_DIR / "identity.json"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    """Generate a new identity and save it."""
    from ghost.identity import GhostIdentity
    from ghost.crypto.kem import is_post_quantum, KEM_ALGORITHM

    if IDENTITY_FILE.exists() and not args.force:
        print(f"Identity already exists at {IDENTITY_FILE}")
        print("Use --force to regenerate (WARNING: this will destroy your current identity)")
        return 1

    name = args.name or input("Identity name [GHOST]: ").strip() or "GHOST"
    print(f"Generating identity '{name}'...")

    identity = GhostIdentity(name)
    identity.save(IDENTITY_FILE)

    print(f"✓ Identity saved to {IDENTITY_FILE}")
    print(f"  Identity key: {identity.identity_key.public_key_hex()[:32]}...")
    print(f"  KEM backend:  {KEM_ALGORITHM}")
    print(f"  Post-quantum: {is_post_quantum()}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Show the public key bundle."""
    from ghost.identity import GhostIdentity

    if not IDENTITY_FILE.exists():
        print(f"No identity found at {IDENTITY_FILE}. Run: python -m ghost init")
        return 1

    identity = GhostIdentity.load(IDENTITY_FILE)
    bundle = identity.to_bundle()
    print(json.dumps(bundle, indent=2))
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    """Send a message to a target system via bus."""
    from ghost.identity import GhostIdentity
    from ghost.transport import BusTransport
    from ghost.protocol import GhostSession
    from ghost.protocol.handshake import HandshakeBundle

    if not IDENTITY_FILE.exists():
        print(f"No identity found. Run: python -m ghost init")
        return 1

    identity = GhostIdentity.load(IDENTITY_FILE)
    transport = BusTransport()

    target = args.target.upper()
    text = args.message

    # For simplicity: create a one-shot session and send
    # In production this would use a persistent session store
    session = GhostSession.create_initiator(identity.identity_key)

    # Use own bundle as target (loopback) — normally you'd fetch the target's bundle
    # This is a demo: send via bus with metadata only (no encryption if no peer bundle)
    # We send a CONTROL message with the text payload
    from ghost.protocol.message import GhostMessage

    ctrl_msg = GhostMessage.create_control(
        session_id=session.session_id,
        payload_bytes=json.dumps({"text": text, "from": identity.name}).encode(),
    )
    ctrl_msg.sign(identity.identity_key)

    result = transport.send_message(target, ctrl_msg)
    print(f"✓ Sent to {target}: {result}")
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    """Poll inbound bus messages."""
    from ghost.transport import BusTransport

    transport = BusTransport()
    messages = transport.poll_raw(limit=args.limit)

    if not messages:
        print("No pending messages.")
        return 0

    print(f"Received {len(messages)} message(s):")
    for i, msg in enumerate(messages, 1):
        src = msg.get("source", "?")
        mt = msg.get("messageType", "?")
        payload = msg.get("payload", {})
        msg_id = msg.get("id", "?")
        print(f"\n[{i}] id={msg_id[:8]}... source={src} type={mt}")
        print(f"    payload={json.dumps(payload, indent=4)[:200]}")

    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """Entry point for the ghost CLI."""
    parser = argparse.ArgumentParser(
        prog="ghost",
        description="QuantumSecure SpectrumQ CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Generate identity")
    p_init.add_argument("--name", default="", help="Identity name")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing identity")

    # info
    subparsers.add_parser("info", help="Show public identity bundle")

    # send
    p_send = subparsers.add_parser("send", help="Send a message via bus")
    p_send.add_argument("target", help="Target system (SETH, AEGIS, etc.)")
    p_send.add_argument("message", help="Message text")

    # poll
    p_poll = subparsers.add_parser("poll", help="Poll inbound messages")
    p_poll.add_argument("--limit", type=int, default=20, help="Max messages to fetch")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "info": cmd_info,
        "send": cmd_send,
        "poll": cmd_poll,
    }

    handler = commands.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
