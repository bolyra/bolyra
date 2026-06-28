---
title: OWASP Agentic Security Mapping
visibility: public
sources:
  - docs/owasp-agentic-mapping.md
last-updated: 2026-06-28
staleness-threshold: 30d
tags: [security, owasp, agentic, compliance]
---

Mapping of Bolyra's protocol primitives to the OWASP Top 10 for Agentic
Applications (2026). Bolyra provides cryptographic coverage for 6 of 10 risks
(3 full, 3 partial). The remaining 4 operate at the LLM reasoning or runtime
layer, which is outside the scope of an identity protocol.

## Overview

The OWASP Agentic Top 10 identifies security risks specific to autonomous AI
agent systems. Bolyra's mitigations are distinctive because they are enforced
**in arithmetic circuits** (ZKP soundness), not as runtime policy checks. An
attacker cannot bypass scope narrowing, credential expiry, or sybil resistance
without breaking the underlying cryptographic assumptions.

## Key Concepts

**Coverage levels:**
- **FULL** -- the risk is cryptographically mitigated at the identity/auth layer
- **PARTIAL** -- Bolyra constrains the attack surface but does not eliminate the risk
- **NOT ADDRESSED** -- the risk operates at a layer Bolyra does not touch

## How It Works

### Coverage Summary

| ID | Risk | Coverage | Primary Primitive |
|----|------|----------|-------------------|
| ASI01 | Agent Goal Hijacking | NOT ADDRESSED | -- (LLM reasoning layer) |
| ASI02 | Tool Misuse & Exploitation | PARTIAL | `AgentPolicy.circom` bitmask, `Delegation.circom` scope narrowing |
| ASI03 | Identity & Privilege Abuse | FULL | All circuits + `IdentityRegistry.sol` + SDK handshake |
| ASI04 | Supply Chain Compromise | PARTIAL | `AgentPolicy.circom` modelHash binding, operator-signed credentials |
| ASI05 | Unexpected Code Execution | NOT ADDRESSED | -- (runtime sandbox layer) |
| ASI06 | Memory & Context Poisoning | NOT ADDRESSED | -- (data/RAG layer) |
| ASI07 | Insecure Inter-Agent Comms | FULL | `proveHandshake()`, delegation chain linking, nonce binding |
| ASI08 | Cascading Agent Failures | PARTIAL | Delegation depth limit (3 hops), scope/expiry attenuation |
| ASI09 | Human-Agent Trust Exploitation | NOT ADDRESSED | -- (UX/cognitive layer) |
| ASI10 | Rogue Agents | FULL | Bitmask, expiry, Merkle revocation, nullifier audit trail |

### FULL Coverage Details

**ASI03 -- Identity & Privilege Abuse** (Bolyra's core design target):
- Sybil-resistant human identity via Semaphore v4 nullifiers (S1.2)
- Agent credentials are operator-signed, Merkle-enrolled, time-bounded (S2.1--S2.4)
- 64-bit permission bitmask with cumulative hierarchy enforcement (S2.7)
- Delegation chains with monotone scope attenuation (S3.2) and expiry narrowing (S3.3)
- Secret scalar never leaves the proving device

**ASI07 -- Insecure Inter-Agent Comms:**
- Mutual handshake requires both parties to generate ZKPs simultaneously
- Shared `sessionNonce` binds both proofs to the same session (S1.3), preventing relay attacks
- Scope commitment chaining (CC1, CC2) links each delegation hop cryptographically
- Proofs are self-verifiable without contacting a central authority

**ASI10 -- Rogue Agents:**
- Permission bitmask is committed at issuance; agent cannot prove undeclared permissions (S2.3)
- Hard credential expiry (S2.4) prevents indefinite operation
- Merkle tree removal provides revocation; root history buffers (30 entries) limit window
- Per-scope nullifiers create an audit trail for post-hoc detection

### PARTIAL Coverage Details

**ASI02 -- Tool Misuse:** Bolyra constrains which tool categories an agent can
access (via permission bitmask tiers), but does not inspect how the agent uses a
specific tool (e.g., SQL injection through a legitimately-accessed database).

**ASI04 -- Supply Chain Compromise:** The `credentialCommitment` includes
`modelHash` as a first-class component, preventing model substitution. But
Bolyra does not inspect the model binary for backdoors or verify MCP server
integrity at runtime.

**ASI08 -- Cascading Failures:** Delegation depth limits (3 hops) and monotone
scope/expiry attenuation bound the authorization blast radius, but do not prevent
operational cascades (retry storms, fan-out of valid-but-wrong decisions).

### Comparison with Centralized Approaches

| Dimension | Microsoft Entra Agent ID | WorkOS FGA | Bolyra (ZKP) |
|-----------|------------------------|------------|--------------|
| Identity guarantee | Centralized token issuance | IdP group mapping | No credential server to compromise |
| Scope enforcement | Runtime policy engine | ReBAC on resource subtrees | In-circuit arithmetic constraints |
| Inter-agent auth | Centralized trust broker | Not addressed | Self-verifiable mutual ZKPs |
| Single point of failure | IdP/policy engine | Policy engine | None (proofs are standalone) |
| LLM-layer coverage | Runtime guardrails | None | None |

**Best posture:** combine Bolyra for cryptographic identity guarantees with
centralized tooling for runtime monitoring and LLM-layer risks.

## Current Status

- Mapping is v1.0 (2026-04-21), based on Bolyra Phase 1 (Proof of Enrollment)
- References OWASP Agentic Top 10 2026 edition
- No changes needed unless OWASP publishes a revised risk list or Bolyra ships
  Phase 2 primitives that extend coverage

## See Also

- [wiki/security/threat-model.md](threat-model.md) -- overall threat model and attack surface
- `docs/owasp-agentic-mapping.md` -- full source document with per-risk analysis
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- `circuits/FORMAL-PROPERTIES.md` -- formal soundness properties referenced above
