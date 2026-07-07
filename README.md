# QuantumSecure-SpectrumQ — Post-Quantum Secure Messaging Protocol

![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Tests](https://img.shields.io/badge/tests-100%20passing-brightgreen.svg)

SpectrumQ is a research-grade post-quantum secure messaging protocol library combining ML-KEM-768 (FIPS 203) hybrid key encapsulation, a PQXDH handshake, and a Triple Ratchet for per-message forward secrecy — wrapped in an onion transport layer designed to resist traffic analysis. It exists because classical ECDH-only protocols are vulnerable to "harvest now, decrypt later" attacks; SpectrumQ makes that strategy cryptographically futile today.

---

## Security Model

| Layer | Primitive | Standard |
|---|---|---|
| Key Encapsulation | ML-KEM-768 + X25519 hybrid | FIPS 203 (ML-KEM) |
| Handshake | PQXDH (DH1‖DH2‖DH3‖KEM_SS) | Signal X3DH + PQ extension |
| Ratchet | Triple Ratchet (root + send + recv chains) | Signal Double Ratchet extended |
| Message Encryption | AES-256-GCM (per-message keys, discarded after use) | NIST SP 800-38D |
| Transport | Onion routing layer | Custom (Tor planned v0.6) |

**What this buys you:**

- **Post-quantum resistance** — ML-KEM-768 KEM contribution in every handshake means a future quantum computer cannot retroactively break sessions, even from captured traffic.
- **Forward secrecy** — Ratchet chain keys are replaced on every step; compromising current keys doesn't expose past messages.
- **Harvest-resistant** — Encrypted traffic captured today cannot be decrypted by a CRQC tomorrow.
- **Metadata resistance** — Onion transport layer obscures who is talking to whom.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           SpectrumQ Protocol            │
├──────────────┬──────────────────────────┤
│   Identity   │  ghost/identity/         │
│   ECDH+KEM   │  identity.py, keyserver  │
├──────────────┼──────────────────────────┤
│  Handshake   │  ghost/protocol/         │
│   PQXDH      │  handshake.py, session   │
├──────────────┼──────────────────────────┤
│   Ratchet    │  ghost/crypto/           │
│  Triple KDF  │  ratchet.py, kem.py      │
├──────────────┼──────────────────────────┤
│  Transport   │  ghost/transport/        │
│Onion/Bus/Tor │  onion.py, bus.py        │
└──────────────┴──────────────────────────┘
```

### Layer Details

**Identity (`ghost/identity/`)** — Long-term identity keys (ECDH + KEM public keys), signed pre-keys, and one-time pre-keys. Manages the keyserver bundle used in PQXDH.

**Handshake (`ghost/protocol/`)** — Implements PQXDH: three X25519 DH exchanges (identity binding, ephemeral-to-identity, ephemeral-to-prekey) combined with an ML-KEM-768 encapsulation. Output is a 64-byte master secret; first 32 bytes seed the ratchet root key.

**Ratchet (`ghost/crypto/`)** — Triple Ratchet extending the Signal Double Ratchet with a periodic PQ KEM ratchet step. Maintains root chain (RK), send chain (CKs), and receive chain (CKr). Message keys are derived and immediately discarded after use; skipped keys are cached for out-of-order delivery.

**Transport (`ghost/transport/`)** — Onion routing layer encrypts payloads in multiple layers before transmission. Bus adapter provides the underlying relay. Tor/Arti integration is planned for v0.6.

---

## Build & Install

```bash
# Clone
git clone https://github.com/j-manchesterllc/QuantumSecure-SpectrumQ
cd QuantumSecure-SpectrumQ

# Install liboqs (required for ML-KEM-768)
# See docs/liboqs-setup.md or run:
pip install -r requirements.txt

# Set env vars
cp .env.example .env
# Edit .env with your bus token

# Run tests
export LD_LIBRARY_PATH=/path/to/liboqs/build/lib
python -m pytest tests/ -v
```

> **Note:** Without liboqs installed, SpectrumQ automatically falls back to an X25519-based pseudo-KEM. The fallback maintains the same API and provides classical forward secrecy, but is **not post-quantum resistant**. Always install liboqs for production-equivalent security testing.

### Dependencies

| Package | Purpose |
|---|---|
| `cryptography>=41.0` | X25519, AES-256-GCM, HKDF, HMAC |
| `liboqs-python>=0.10` | ML-KEM-768 (optional; fallback activates if absent) |

---

## Test Results

```
100 tests passing across 6 test suites
```

Run the full suite:

```bash
python -m pytest tests/ -v --tb=short
```

---

## Honest Limitations

SpectrumQ is research-grade software. Before using it for anything sensitive, understand these gaps:

- **No break-in recovery (yet).** The current Triple Ratchet provides forward secrecy but post-compromise security (recovering safety after a key compromise) is not fully hardened. This is on the roadmap.
- **No Tor yet.** The onion transport layer is custom-built; real `.onion` address-based identity and Tor/Arti integration are planned for v0.6. Until then, transport-level anonymity is limited.
- **Device-bound history.** Message history and ratchet state live on the device. There is no multi-device sync, and losing a device means losing its message history.
- **No formal audit.** This library has not been reviewed by an independent cryptographer. Do not use it for life-critical, classified, or high-stakes communications without an independent security audit.
- **Research software.** Protocol details may change in breaking ways between versions until v1.0.

---

## Roadmap

| Version | Status | Milestone |
|---|---|---|
| v0.4 | ✅ Shipped | Onion transport layer |
| v0.5 | 🔄 In progress | Safety numbers + QR identity (SHA-512 fingerprint, 60-digit verification code) |
| v0.6 | 📋 Planned | Tor/Arti integration — real `.onion` addresses as identity |
| v0.7 | 📋 Planned | Store-and-forward relay — async offline delivery, TTL-based, opaque ciphertext |
| v1.0 | 📋 Planned | Native app (React Native or Tauri), Tor by default, no metadata |
| v2.0 | 💡 Vision | Group messaging (MLS protocol), community relay nodes, HUSH token governance |

See [ROADMAP.md](ROADMAP.md) for the full plan.

---

## Security Disclaimer

> ⚠️ **This is research-grade software.**
>
> SpectrumQ has not undergone a formal cryptographic audit. The post-quantum primitives (ML-KEM-768) are NIST-standardized (FIPS 203), but their integration in this protocol has not been independently verified.
>
> **Do not use SpectrumQ for life-critical, classified, or legally sensitive communications without an independent security audit.**
>
> For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## License

MIT — see [LICENSE](LICENSE).
