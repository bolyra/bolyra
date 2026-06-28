---
title: Bolyra Mutual ZKP Authentication Protocol
abbrev: Bolyra MZKA
docname: draft-bolyra-mutual-zkp-auth-01
category: exp
ipr: trust200902
area: Security
workgroup: N/A
keyword: ZKP, authentication, identity, agent
author:
  -
    ins: V. Ramineni
    name: Viswa Ramineni
    org: ZKProva Inc.
    email: viswa@zkprova.com
---

# Abstract

This document specifies a mutual authentication protocol in which a
human prover and an AI-agent prover each generate zero-knowledge proofs
(ZKPs) of enrollment in their respective Merkle trees. Verification
requires both proofs to bind to a shared session nonce, preventing
replay across sessions.

# Introduction

Conventional agent authentication relies on bearer tokens or API keys
that grant capabilities without proving identity properties.
Bolyra replaces this with mutual ZKP authentication: the human proves
uniqueness (Semaphore-style), the agent proves a signed credential with
cumulative-bit permissions, and both proofs bind to a fresh session
nonce.

# Terminology

- **Human Merkle Tree**: An incremental Merkle tree (LeanIMT, depth 20)
  whose leaves are Poseidon identity commitments.
- **Agent Merkle Tree**: An incremental Merkle tree whose leaves are
  EdDSA-signed agent credential hashes.
- **ROOT_HISTORY_SIZE**: The number of recent Merkle roots retained in
  a ring buffer on-chain (currently 30 for both trees).
- **Staleness Window (T_stale)**: The maximum time period during which
  a proof generated against a historical root remains valid, defined as
  `ROOT_HISTORY_SIZE × avg_enrollment_interval`.
- **Session Nonce**: A fresh random value bound into both proofs to
  prevent cross-session replay.
- **Nullifier**: A deterministic value derived from the prover's secret
  and the external nullifier, used to prevent double-signaling.

# Protocol Flow

1. Verifier generates a random session nonce `N`.
2. Human prover generates a Groth16 proof for HumanUniqueness with
   public signals: `(humanMerkleRoot, nullifierHash, nonceBinding)`.
3. Agent prover generates a Groth16/PLONK proof for AgentPolicy with
   public signals: `(agentMerkleRoot, policyHash, permissions, expiry,
   nonceBinding)`.
4. Verifier checks:
   a. Both `nonceBinding` values match `N`.
   b. `humanMerkleRoot` passes `isKnownHumanRoot()` against the
      on-chain root history buffer.
   c. `agentMerkleRoot` passes `isKnownAgentRoot()` against the
      on-chain root history buffer.
   d. Both ZKP proofs verify.
   e. `nullifierHash` has not been consumed.
5. On success, verifier consumes the nullifier and establishes the
   authenticated session.

# Root History Buffer

Both the human and agent Merkle trees maintain a ring buffer of
`ROOT_HISTORY_SIZE` (30) recent roots in the IdentityRegistry contract.
This buffer exists because new enrollments change the tree root, which
would otherwise immediately invalidate any in-flight proofs generated
against the previous root.

## Buffer Mechanics

The ring buffer uses a monotonically increasing write index:

```
humanRootHistory[humanRootHistoryIndex % ROOT_HISTORY_SIZE] = newRoot;
humanRootHistoryIndex++;
```

Lookup iterates all 30 slots and returns true if any slot matches the
queried root. The zero root (0x00...00) is always rejected regardless
of buffer contents.

## Staleness Window

The effective proof validity period is:

```
T_stale = ROOT_HISTORY_SIZE × avg_enrollment_interval
```

For example, with ROOT_HISTORY_SIZE=30 and an average enrollment rate
of 1 per minute, proofs remain valid for approximately 30 minutes.
With 1 enrollment per hour, the window extends to ~30 hours.

Verifiers MUST NOT accept proofs whose attested root has been evicted
from the ring buffer. The `isKnownHumanRoot()` and `isKnownAgentRoot()`
functions enforce this on-chain. Off-chain verifiers MUST replicate
this check against a locally synchronized copy of the buffer.

# Security Considerations

## Nonce Binding

Both proofs commit to a fresh session nonce `N`. Replaying a
`(humanProof, agentProof)` pair from a previous session without
rebinding the nonce will fail verification because the `nonceBinding`
public signal will not match the current session's `N`.

## Nullifier Uniqueness

The HumanUniqueness circuit derives the nullifier deterministically
from the prover's secret and the external nullifier. The registry
tracks consumed nullifiers to prevent double-signaling.

## Root Staleness and the History Buffer

Without a root history buffer, any new enrollment immediately
invalidates all in-flight proofs — a liveness problem that grows worse
as enrollment throughput increases. The ROOT_HISTORY_SIZE ring buffer
mitigates this by retaining the last 30 roots for each tree.

The staleness window `T_stale = ROOT_HISTORY_SIZE × avg_enrollment_interval`
defines the maximum proof validity period. Deployments with high
enrollment throughput have shorter validity windows. Operators SHOULD
monitor enrollment rates and adjust ROOT_HISTORY_SIZE if the effective
window drops below acceptable latency bounds for their use case.

Verifiers MUST call `isKnownHumanRoot(root)` (or `isKnownAgentRoot(root)`)
with the proof's claimed Merkle root before accepting the proof.
A root that returns `false` indicates the proof is stale and MUST be
rejected.

Note: ROOT_HISTORY_SIZE=30 provides parity between the human and agent
trees. Both trees use identical buffer mechanics. This is intentional:
asymmetric buffer sizes would create confusing UX where human proofs
expire at different rates than agent proofs in the same handshake.

## Human Merkle Root Staleness Window

The human tree's 30-root history buffer bounds the maximum staleness
to 30 enrollments. The effective time bound depends on enrollment
throughput:

| Throughput | Effective Window |
|---|---|
| 1 enrollment / minute | ~30 minutes |
| 1 enrollment / 10 minutes | ~5 hours |
| 1 enrollment / hour | ~30 hours |

Clients that receive a `HUMAN_ROOT_STALE` error (i.e., `isKnownHumanRoot()`
returns `false`) SHOULD:

1. Fetch the current `humanMerkleRoot` from the on-chain registry.
2. Regenerate the Merkle proof against the updated root.
3. Re-prove and resubmit the handshake.

This retry is transparent to the end user when the SDK handles it
automatically. Verifiers SHOULD include the current enrollment count
in error responses to help clients estimate whether their root is
recoverable (within the 30-root window) or definitively stale.

The 30-root depth was chosen to balance gas cost (30 storage slots per
tree) against liveness. Doubling the buffer to 60 would double on-chain
storage cost while only linearly extending the window. Operators with
extreme throughput requirements MAY deploy a custom registry with a
larger ROOT_HISTORY_SIZE.

## Cumulative-Bit Permission Monotonicity

The Delegation circuit enforces one-way scope narrowing. A delegated
credential can only reduce permissions, never expand them. This is
enforced at the circuit level, not just in the SDK.

## Agent Credential Expiry

Agent credentials include an `expiry` field checked against
`block.timestamp` (on-chain) or the current epoch (off-chain).
Expired credentials MUST be rejected even if the Merkle root is valid.

# IANA Considerations

This document has no IANA actions.

# References

- Semaphore v4: https://semaphore.pse.dev
- Groth16: Jens Groth, "On the Size of Pairing-Based Non-interactive Arguments", EUROCRYPT 2016
- PLONK: Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru, 2019
- Bolyra DID Method: did-method-bolyra.md
