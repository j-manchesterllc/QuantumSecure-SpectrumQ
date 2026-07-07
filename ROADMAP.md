# SpectrumQ Roadmap

This document tracks the planned development phases for SpectrumQ. The goal is a production-ready, metadata-resistant, post-quantum secure messaging protocol by v1.0, with decentralized group messaging infrastructure at v2.0.

---

## ✅ v0.4 — Onion Transport Layer *(shipped)*

- Custom onion routing layer for transport-level metadata resistance
- Bus adapter (`ghost/transport/bus.py`) for message relay
- Multi-layer payload encryption before transmission
- Foundation for future Tor/Arti integration

---

## 🔄 v0.5 — Safety Numbers + QR Identity *(in progress)*

- **Safety number verification** — SHA-512 fingerprint of both parties' identity public keys, formatted as a 60-digit numeric verification code (12 groups of 5 digits)
- **QR code generation** for out-of-band identity verification
- Verification ceremony: scan each other's QR or read safety numbers aloud to confirm no MITM
- Warning UI when identity keys change unexpectedly

---

## 📋 v0.6 — Tor/Arti Integration

- Integrate with [Arti](https://gitlab.torproject.org/tpo/core/arti) (Rust Tor implementation) via Python bindings
- Real `.onion` v3 addresses as persistent identity addresses
- Incoming connections over Tor — no server IP exposed
- Outgoing connections routed through Tor by default
- Replaces the custom onion layer for transport anonymity

---

## 📋 v0.7 — Store-and-Forward Relay

- Async offline message delivery — sender queues encrypted messages when recipient is offline
- TTL-based expiry (messages auto-delete from relay after configurable timeout)
- Relay stores only opaque ciphertext — no plaintext, no metadata visible to relay operator
- Delivery confirmation and receipt acknowledgment
- Enables reliable messaging without requiring both parties online simultaneously

---

## 📋 v1.0 — Native App + Tor by Default

- Native application: **React Native** (mobile) or **Tauri** (desktop), TBD based on community feedback
- Tor transport enabled by default — no IP addresses exchanged in normal operation
- No metadata stored or transmitted beyond what the protocol strictly requires
- Stable protocol specification — no more breaking changes after v1.0
- Reference implementation suitable for third-party client development
- Full setup documentation and first-run UX

---

## 💡 v2.0 — Group Messaging + Decentralized Infrastructure *(vision)*

- **Group messaging** via [MLS (Messaging Layer Security)](https://www.rfc-editor.org/rfc/rfc9420) — IETF-standardized, post-quantum upgradeable
- **Community relay nodes** — permissionless relay infrastructure; anyone can run a relay
- **HUSH token governance** — protocol parameter governance and relay incentive layer
- Group forward secrecy and post-compromise security via MLS TreeKEM
- Large-scale group support (hundreds of participants)

---

## Contributing to the Roadmap

If you have feedback on priorities, open a GitHub Discussion. Major protocol changes go through a design proposal process — see [CONTRIBUTING.md](CONTRIBUTING.md).
