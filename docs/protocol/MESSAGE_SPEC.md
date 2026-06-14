# SpectrumQ Message Specification

## Overview

This document defines the formal structure of messages exchanged in SpectrumQ.

All messages are cryptographically encapsulated and transport-agnostic.

## Message Envelope

```json
{
  "version": "0.1",
  "message_id": "uuid",
  "session_id": "uuid",
  "type": "DATA | HANDSHAKE | REKEY | CONTROL",
  "timestamp": "unix_epoch_ms",
  "sender_ephemeral_key": "bytes",
  "receiver_ephemeral_key": "bytes",
  "payload": "encrypted_bytes",
  "signature": "bytes"
}
```

## Message Types
- HANDSHAKE
- DATA
- REKEY
- CONTROL

## Security Notes
- All payloads are encrypted at application layer
- Ephemeral keys MUST NOT be reused
- Replay protection required via timestamps and sequencing
- Transport layer may expose limited metadata

## Future Work
- Binary encoding (Protobuf or similar)
- Formal schema validation rules