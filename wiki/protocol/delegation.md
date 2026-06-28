---
title: Delegation Protocol
visibility: public
sources:
  - circuits/src/Delegation.circom
  - sdk/src/delegation.ts
  - sdk/src/types.ts
  - spec/draft-bolyra-mutual-zkp-auth-01.md
last-updated: 2026-06-28
staleness-threshold: 60d
tags: [delegation, scope-narrowing, chain-linking, zkp]
---

One-way scope-narrowing delegation through multi-hop agent chains. Each hop proves in zero knowledge that the delegatee's permissions are a strict subset of the delegator's, with identity-bound chain linking and phantom delegatee prevention.

## Overview

After a mutual handshake, the authenticated agent can delegate a subset of its permissions to another enrolled agent. Each delegation hop is an independent Groth16 proof that narrows permissions and expiry without revealing the actual bitmask values. The on-chain registry maintains chain state (scope commitments and hop count) to prevent forgery and enforce a maximum chain depth of 3 hops.

The critical invariant: delegation can only narrow, never expand. This is enforced in the circuit, not just the SDK.

## Key Concepts

**Identity-Bound Scope Commitment** -- Each scope commitment is `Poseidon3(permissionBitmask, credentialCommitment, expiryTimestamp)`. Including the credential commitment prevents impersonation (different credential cannot produce matching hash). Including expiry prevents self-assertion of longer lifetimes (UC3.2 fix).

**Chain Linking** -- Each delegation hop reads the previous `scopeCommitment` from on-chain state and proves the delegator's scope + credential + expiry hash to it. The circuit outputs a new `scopeCommitment` for the delegatee, which the registry writes back. This creates a verified chain from the original handshake.

**Delegation Token** -- `Poseidon4(previousScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)`. The delegator signs this with EdDSA, binding the delegation to a specific recipient with specific permissions.

**Phantom Delegatee Prevention (CIP-1)** -- The delegation circuit proves the delegatee's credential commitment is a leaf in the agent Merkle tree. The computed root is a public output checked on-chain against `agentRootExists`. Without this, permissions could be delegated to non-enrolled entities.

**Scope Subset Check** -- For each of 64 bits: `delegateeBits[i] * (1 - delegatorBits[i]) === 0`. If the delegatee has a bit set, the delegator must also have it set.

**Expiry Narrowing** -- `delegateeExpiry <= delegatorExpiry`, enforced via `LessEqThan(64)`. Plus a liveness check: `currentTimestamp < delegateeExpiry`.

## How It Works

### Delegation Flow

1. Agent A completes a handshake. Registry stores A's `scopeCommitment` as chain seed.

2. Agent A wants to delegate to Agent B with narrower permissions:
   - A signs a delegation token binding B's commitment, scope, and expiry
   - SDK generates a Delegation proof proving:
     - A's scope + credential hash to the stored `previousScopeCommitment`
     - B's scope is a subset of A's scope
     - B's expiry does not exceed A's expiry
     - A signed the delegation token
     - B is enrolled in the agent tree
   - Proof submitted to `IdentityRegistry.verifyDelegation()`

3. Registry verifies:
   - Session nonce was consumed by a prior handshake
   - `previousScopeCommitment` matches on-chain state
   - Delegation nullifier not reused
   - Hop count <= 3 (MAX_DELEGATION_HOPS)
   - Delegatee Merkle root valid
   - Groth16 proof valid
   - Writes new `scopeCommitment` to chain state

4. Agent B can now delegate further (up to hop limit) with even narrower scope.

### SDK API

```ts
const { proof, result } = await delegate({
  delegator: parentCredential,
  delegatorOperatorPrivateKey: operatorSecret,
  delegateeCommitment: childCredential.commitment,
  delegateeScope: 0b00000011n,          // read + write only
  delegateeExpiry: parentExpiry - 3600n, // 1 hour shorter
  previousScopeCommitment: handshake.scopeCommitment,
  sessionNonce: handshake.sessionNonce,
});

// result.newScopeCommitment -- chain link for next hop
// result.delegationNullifier -- replay prevention
// result.delegateeMerkleRoot -- checked on-chain
```

The SDK pre-validates scope narrowing and expiry narrowing before generating the proof, providing clean error messages:

- `ScopeEscalationError` if delegatee scope has bits not in delegator's bitmask
- `EXPIRY_ESCALATION` if delegatee expiry exceeds delegator expiry
- `CHAIN_LINK_MISMATCH` if `previousScopeCommitment` doesn't match the delegator's identity-bound chain link

### Public Signal Layout

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `newScopeCommitment` | Chain-linking output for next hop |
| 1 | `delegationNullifier` | Replay-prevention nullifier |
| 2 | `delegateeMerkleRoot` | Delegatee enrollment proof |
| 3 | `previousScopeCommitment` | Chain-linking input |
| 4 | `sessionNonce` | Session binding |
| 5 | `currentTimestamp` | Proof-time freshness |

### Security Fixes in Circuit

- **UC3.1**: Delegator signing key is bound to `delegatorCredCommitment` by recomputing it from components and asserting equality. Prevents using an unrelated key.
- **UC3.2**: Expiry included in scope commitment (`Poseidon3` instead of `Poseidon2`), preventing delegators from self-asserting longer lifetimes in the chain-linking check.
- **CIP-1**: Delegatee Merkle inclusion proof prevents phantom delegatee attacks.

## Current Status

- Delegation circuit is stable at ~55,000 constraints.
- Maximum chain depth: 3 hops (on-chain constant, not circuit-enforced).
- Each hop is an independent proof (iterative, not recursive).
- Off-chain verification available via `verifyDelegation()` for testing.
- Conformance suite: 8 delegation vectors + 3 delegation chain vectors.

## See Also

- [permissions-model.md](permissions-model.md) -- Cumulative bit encoding enforced during delegation
- [circuits-overview.md](circuits-overview.md) -- Delegation circuit constraint budget
- [zkp-handshake.md](zkp-handshake.md) -- Handshake that seeds the delegation chain
- `sdk/src/delegation.ts` -- Full SDK implementation
