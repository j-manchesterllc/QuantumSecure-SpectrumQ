# SpectrumQ Threat Model

## Overview

This document defines the threat landscape for SpectrumQ and informs all cryptographic and architectural decisions.

## Adversary Model

SpectrumQ assumes the following adversaries:

- Passive network observers (ISP-level surveillance)
- Active network attackers (MITM)
- Compromised servers or relays
- Compromised client devices
- Global passive adversaries with traffic correlation capability
- Quantum-capable adversaries targeting classical cryptography
- Supply-chain attackers targeting dependencies

## Threat Categories

### 1. Metadata Collection
- Message timing analysis
- Communication graph reconstruction
- Contact inference

### 2. Traffic Analysis
- Packet size fingerprinting
- Timing correlation attacks
- Flow reconstruction

### 3. Endpoint Compromise
- Device malware
- Key extraction
- Memory scraping

### 4. Server Compromise
- Database leakage
- Log exposure
- Relay hijacking

### 5. Cryptographic Attacks
- Classical key exchange attacks
- Post-quantum algorithm weaknesses
- Downgrade attacks

### 6. Quantum Adversaries
- Shor's algorithm threat to RSA/ECC
- Long-term message decryption risk

## Design Implications

- Mandatory forward secrecy
- Hybrid classical + post-quantum key exchange
- Minimal metadata exposure
- Decentralized routing options
- Constant-time cryptographic implementations

## Security Principle

Assume all network communications are observed. Protect content and metadata independently where possible.