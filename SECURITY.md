# Security Policy

## What SpectrumQ Guarantees

When liboqs is installed and ML-KEM-768 is available:

- **ML-KEM-768 (FIPS 203)** key encapsulation in every handshake. A Cryptographically Relevant Quantum Computer (CRQC) cannot break the KEM contribution, meaning traffic captured today cannot be retroactively decrypted by a future quantum adversary.
- **Forward secrecy** via Triple Ratchet. Past message keys are derived, used, and discarded. Compromising current ratchet state does not expose previously sent messages.
- **AES-256-GCM per-message encryption** with unique nonces. Each message uses a freshly derived key; key reuse is not possible by design.
- **PQXDH handshake** — three X25519 Diffie-Hellman exchanges combined with the ML-KEM-768 shared secret, mixed via HKDF. Breaking the handshake requires breaking both classical ECDH and ML-KEM-768 simultaneously (hybrid security).
- **Authenticated encryption** — AES-256-GCM provides both confidentiality and integrity. Tampered ciphertexts are rejected before decryption.

## What SpectrumQ Does NOT Guarantee

- **No formal cryptographic audit.** The protocol design and implementation have not been reviewed by an independent cryptographer or security firm. The underlying primitives are well-studied, but their composition in SpectrumQ has not been verified.
- **No Tor transport (yet).** The current onion transport layer is a custom implementation. Real anonymity-preserving transport via Tor/Arti (`.onion` addresses as identity) is planned for v0.6 but is not present in current releases. Until then, a network-level adversary may be able to observe who is communicating with whom.
- **Device-bound keys.** Private keys and ratchet state are stored on-device. SpectrumQ does not provide multi-device key sync, key backup, or recovery mechanisms. Losing a device means losing access to that device's keys and message history.
- **No post-compromise security (break-in recovery) yet.** If ratchet state is exfiltrated from a device, an attacker with that state can decrypt future messages until the next KEM ratchet step. Full break-in recovery hardening is on the roadmap.
- **No protection against endpoint compromise.** If your device is compromised (malware, physical access), SpectrumQ cannot protect you. The protocol secures messages in transit, not at rest on a compromised device.
- **Research-grade software.** The protocol specification may change in breaking ways between minor versions until v1.0 stable.

## Supported Versions

| Version | Supported |
|---|---|
| 0.4.x (current) | ✅ Active development |
| < 0.4 | ❌ No support — early architecture only |

## Responsible Disclosure

**If you find a vulnerability in SpectrumQ, please disclose it responsibly.**

Do not open a public GitHub issue for security vulnerabilities. Instead:

1. **Preferred:** Open a [GitHub Security Advisory](https://github.com/j-manchesterllc/QuantumSecure-SpectrumQ/security/advisories/new) — this is private by default and lets us coordinate a fix before public disclosure.
2. **Alternative:** Email **security@quantumsecure.link** with a description of the vulnerability, steps to reproduce, and your assessment of impact.

We will acknowledge receipt within 72 hours and aim to provide a fix or mitigation plan within 14 days for critical issues.

We follow responsible disclosure practices: we will credit researchers who report valid vulnerabilities (unless they prefer anonymity), and we will not pursue legal action against good-faith security researchers.

## Scope

In-scope for security reports:

- Cryptographic weaknesses in the PQXDH handshake or Triple Ratchet implementation
- Key material leaks or improper key derivation
- Nonce reuse or authentication bypass in AES-256-GCM usage
- Timing side-channels in cryptographic operations
- Any issue allowing an attacker to read, forge, or replay messages

Out of scope:

- Theoretical weaknesses in NIST-standardized primitives (ML-KEM-768, AES-256-GCM) themselves — report those to NIST
- Issues requiring physical device access (out of threat model)
- Social engineering or phishing

## Research Use Warning

> ⚠️ This is research-grade software. Do not use SpectrumQ for life-critical, classified, or legally sensitive communications without an independent cryptographic audit. The authors make no warranty of fitness for any particular purpose. See LICENSE for full disclaimer.
