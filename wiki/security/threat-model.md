---
title: Bolyra Threat Model
visibility: public
sources:
  - docs/owasp-agentic-mapping.md
  - circuits/FORMAL-PROPERTIES.md
  - SECURITY.md
last-updated: 2026-06-28
staleness-threshold: 30d
tags: [security, threat-model, zkp, attack-surface]
---

Bolyra's threat model covers a ZKP-based identity and authorization protocol for
humans and AI agents. The protocol addresses identity-layer threats with
cryptographic guarantees but explicitly does not cover LLM reasoning-layer or
runtime execution-layer risks.

## Overview

Bolyra is an identity primitive, not an LLM guardrail system. Its attack surface
is the boundary between "who/what is authorized" and "what actions are
performed." Threats that operate below (cryptographic breaks) or above (prompt
injection, memory poisoning) this layer are out of scope.

The threat model was formally mapped against the OWASP Top 10 for Agentic
Applications (2026). Of 10 risks: **3 fully mitigated, 3 partially mitigated, 4
not addressed** (by design).

## Key Concepts

### Trust Assumptions

1. **Cryptographic hardness** -- discrete log on Baby Jubjub, Poseidon collision
   resistance, Groth16/PLONK soundness hold.
2. **Operator integrity** -- the entity issuing agent credentials (EdDSA signing
   key) is not compromised. A malicious operator can issue valid credentials for
   rogue agents.
3. **Proving device** -- the human's secret scalar never leaves the proving
   device. Server compromise does not leak reusable credentials.
4. **On-chain contract correctness** -- `IdentityRegistry.sol` is assumed to
   correctly enforce Merkle root history, hop count limits, and nonce replay
   protection.

### What Bolyra Defends Against

| Threat | Mitigation | Guarantee Level |
|--------|-----------|-----------------|
| Agent impersonation | Mutual ZKP handshake with nonce binding | Mathematical (Groth16/PLONK soundness) |
| Privilege escalation via delegation | Monotone scope attenuation in `Delegation.circom` (CC3) | In-circuit enforcement |
| Credential theft/replay | Secret never leaves prover; nullifiers are per-scope, per-session | Cryptographic |
| Sybil attacks | Semaphore v4 nullifiers: one identity per scope per human (S1.2) | Deterministic |
| Rogue sub-agents | Permission bitmask + expiry + Merkle revocation | Mathematical + on-chain |
| Delegation chain explosions | Hard 3-hop limit (on-chain) + expiry narrowing (CC4) | On-chain enforcement |

### What Bolyra Does NOT Defend Against

| Threat | Layer | Why Out of Scope |
|--------|-------|-----------------|
| Goal hijacking / prompt injection (ASI01) | LLM reasoning | Identity protocol cannot inspect intent |
| Code execution / sandbox escapes (ASI05) | Runtime | Outside authorization scope |
| Memory / RAG poisoning (ASI06) | Data | Protocol stores identity commitments, not agent memory |
| Social engineering of human approvers (ASI09) | UX / cognitive | Protocol authenticates identity, not informed consent |

## How It Works

Bolyra's security properties are enforced at three layers:

1. **Arithmetic circuits** (Circom) -- constraints are compiled into R1CS and
   cannot be bypassed without breaking the proving system. Scope subset checks,
   expiry comparisons, and cumulative-bit encoding are all in-circuit.

2. **Smart contract** (`IdentityRegistry.sol`) -- dual Merkle trees
   (human/agent), delegation nonce replay protection, hop count limits, and root
   history buffers (30 entries for revocation).

3. **SDK** -- client-side validation (`validateCumulativeBitEncoding`,
   `permissionsToBitmask`) catches invalid inputs before proof generation. This
   is defense-in-depth; the circuits are the ultimate enforcement.

### Blast Radius Bounding

A compromised agent's damage is bounded by:
- Its permission bitmask (set at credential issuance, immutable)
- Its expiry timestamp (hard cutoff)
- Delegation depth (max 3 hops, each with narrower scope and shorter expiry)
- Scope attenuation (each delegation hop can only remove permissions, never add)

## Current Status

- OWASP agentic mapping completed (v1.0, 2026-04-21)
- Formal circuit properties documented in `circuits/FORMAL-PROPERTIES.md`
- No external security audit has been performed yet
- Vulnerability reporting via GitHub Security Advisories or security@bolyra.ai
- 67 conformance test vectors covering the identity/authorization attack surface

## See Also

- [wiki/security/owasp-mapping.md](owasp-mapping.md) -- full OWASP risk-by-risk analysis
- [wiki/security/conformance.md](conformance.md) -- protocol conformance testing
- `circuits/FORMAL-PROPERTIES.md` -- formal soundness/completeness/privacy properties
- `SECURITY.md` -- vulnerability reporting policy
