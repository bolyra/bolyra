---
title: "Bolyra Mutual ZKP Authentication Protocol"
abbrev: "Bolyra-Auth"
docname: draft-bolyra-mutual-zkp-auth-01
category: exp
date: 2026-06
author:
  - fullname: Viswa
    organization: ZKProva Inc.
---

# Abstract

This document specifies the Bolyra mutual zero-knowledge proof (ZKP)
authentication protocol, enabling privacy-preserving handshakes between
human users and AI agents. The protocol uses two independent ZK circuits
(HumanUniqueness and AgentPolicy) whose proofs are bound together by a
shared session nonce.

# 1. Introduction

Bolyra provides mutual authentication where both the human and the AI
agent prove properties about their identity without revealing secrets.
The human proves enrollment in an identity set (sybil resistance); the
agent proves possession of a valid, scoped credential.

# 2. Terminology

- **Session nonce**: A fresh random value generated per handshake.
- **Session nullifier**: Per-session hash that prevents proof replay
  while remaining unlinkable across sessions.
- **External nullifier**: Stable per-identity value derived from scope
  and secret. Never exposed publicly.
- **External nullifier commitment**: One-way hash of the external
  nullifier, used on-chain for sybil gating and revocation.
- **Scope**: Application-specific identifier binding proofs to a context.

# 3. Protocol Overview

## 3.1 Two-Nullifier Architecture

The HumanUniqueness circuit produces two distinct nullifier-derived
outputs, each serving a different purpose:

### 3.1.1 Session Nullifier (Public Output)

```
sessionNullifier = Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
```

- **Purpose**: Replay prevention.
- **Properties**: Unique per handshake. Unlinkable across sessions
  (different sessionNonce → different output).
- **Visibility**: Revealed to the verifier and stored on-chain in the
  `sessionNullifiers` mapping.
- **Verifier MUST NOT** use this value for identity tracking.

### 3.1.2 External Nullifier Commitment (Public Output)

```
externalNullifier  = Poseidon₃(DOMAIN_HUMAN, scope, secret)
commitment         = Poseidon₁(externalNullifier)
```

- **Purpose**: Sybil gating and revocation.
- **Properties**: Stable across sessions for the same identity+scope.
  One-way: the raw externalNullifier cannot be recovered from the
  commitment.
- **Visibility**: Stored on-chain in the `registeredCommitments` mapping.
- **Verifier MUST NOT** log this value alongside session-specific data
  (timestamps, IP addresses) as this would re-enable linkability.

## 3.2 Public Signal Layout

| Index | Signal                        | Purpose                  |
|-------|-------------------------------|--------------------------|
| 0     | identityTreeRoot              | Merkle root of ID tree   |
| 1     | nullifierHash                 | Session nullifier        |
| 2     | scope                         | Application scope        |
| 3     | externalNullifierCommitment   | Sybil/revocation gating  |

## 3.3 Handshake Flow

1. Verifier generates a fresh `sessionNonce` and sends it to the prover.
2. Prover builds the HumanUniqueness witness with `sessionNonce` as a
   private input.
3. Circuit computes `nullifierHash` (session-scoped) and
   `externalNullifierCommitment` (identity-scoped).
4. Prover submits proof + public signals to the on-chain registry.
5. Registry checks:
   a. `identityTreeRoot` is in the accepted set.
   b. `nullifierHash` has not been consumed (replay guard).
   c. `externalNullifierCommitment` is not revoked.
   d. ZK proof verifies against all four public signals.
6. Registry marks `nullifierHash` as consumed and registers the
   commitment.

# 4. Privacy Threat Model

## 4.1 Cross-Verifier Linkability (Mitigated)

**Threat**: If the nullifier is constant across sessions (as in v2.0.0),
colluding verifiers can link all handshakes by the same human by
comparing nullifier values.

**Mitigation**: The v3.0.0 session nullifier includes `sessionNonce`,
making each handshake produce a unique nullifier. Two verifiers comparing
nullifier values from different sessions will see unrelated values.

## 4.2 Commitment-Based Linkability (Residual Risk)

**Threat**: If verifiers log `externalNullifierCommitment` alongside
session metadata, they can link sessions via the commitment.

**Mitigation**: The protocol specifies that verifiers MUST NOT log the
commitment alongside session-identifying data. The commitment is
designed for on-chain registry use only. Off-chain verifiers should
discard it after confirming non-revocation.

## 4.3 Sybil Resistance (Preserved)

**Requirement**: The same human cannot register multiple distinct
identities for the same scope.

**Mechanism**: `externalNullifierCommitment` is deterministic for a
given (scope, secret) pair. The registry stores it and can enforce
uniqueness constraints per scope.

## 4.4 Replay Resistance (Preserved)

**Requirement**: A proof cannot be submitted twice.

**Mechanism**: `sessionNullifiers[nullifierHash]` is marked `true`
after first use. Resubmitting the same proof reverts.

# 5. Domain Separation

All nullifier computations prepend a circuit-specific domain tag:

| Tag | Circuit          | Nullifier Formula                                        |
|-----|------------------|----------------------------------------------------------|
| 1   | HumanUniqueness  | Poseidon₄(1, scope, secret, sessionNonce)                |
| 2   | AgentPolicy      | Poseidon₃(2, agentSecret, policyScope)                   |
| 3   | Delegation       | Poseidon₄(3, delegatorSecret, delegateeCredComm, scope)  |

Domain tags are frozen constants (see FORMAL-PROPERTIES.md §P-DS-1).

# 6. Security Considerations

- **sessionNonce entropy**: The nonce MUST be generated with a CSPRNG
  and be at least 248 bits. Predictable nonces could allow targeted
  linkability attacks.
- **Commitment logging**: Implementors MUST treat
  `externalNullifierCommitment` as sensitive. It MUST NOT appear in
  application logs, analytics, or any system accessible to parties
  other than the on-chain registry.
- **Verifier collusion**: Even with the two-nullifier architecture,
  side-channel linkability (timing, IP, behavioral) remains possible.
  The protocol addresses cryptographic linkability only.

# 7. IANA Considerations

This document has no IANA actions.
