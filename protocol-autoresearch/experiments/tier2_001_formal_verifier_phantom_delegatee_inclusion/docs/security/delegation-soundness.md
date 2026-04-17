# Delegation Soundness Analysis

**Date:** 2026-04-17  
**Severity:** Critical  
**Status:** Fixed in Delegation Circuit v2.0.0  
**Identifier:** CVE-BOLYRA-2026-001

## 1. Phantom Delegatee Vulnerability

### 1.1 Description

The Delegation circuit v1 accepted `delegateeCredCommitment` as a private input without constraining it to exist in any Merkle tree. This allowed an attacker to:

1. Choose an arbitrary field element as `delegateeCredCommitment`
2. Compute a valid `scopeCommitment = Poseidon(delegatorCred, fakeDelegatee, scope)`
3. Generate a valid Groth16 proof (all circuit constraints satisfied)
4. Submit the delegation on-chain
5. Use the resulting `scopeCommitment` in downstream circuits

### 1.2 Impact

- **Unauthorized delegation**: A delegator could create delegations to non-existent agents
- **Scope commitment pollution**: Downstream circuits consuming `scopeCommitment` would accept proofs referencing phantom delegatees
- **Identity impersonation**: An attacker could fabricate a commitment that collides with a future enrollment, pre-positioning delegations

### 1.3 Root Cause

Missing Merkle inclusion constraint on `delegateeCredCommitment`. The circuit verified the delegator's knowledge of their own secret but never verified the delegatee's existence in the protocol's identity tree.

## 2. The Fix

### 2.1 Circuit Changes

Added a `BinaryMerkleRoot(20)` inclusion check:

```circom
// v2: delegatee MUST exist in agent tree
component merkleCheck = BinaryMerkleRoot(20);
merkleCheck.leaf <== delegateeCredCommitment;
for (var i = 0; i < 20; i++) {
    merkleCheck.pathElements[i] <== merklePathElements[i];
    merkleCheck.pathIndices[i] <== merklePathIndices[i];
}
merkleCheck.root === agentTreeRoot;  // public input
```

New signals:
- **Public**: `agentTreeRoot` — the Merkle root of the agent identity tree
- **Private**: `merklePathElements[20]`, `merklePathIndices[20]` — authentication path

### 2.2 On-Chain Changes

`DelegationRegistry.submitDelegation()` now validates `agentTreeRoot` against the `IdentityRegistry`'s root history ring buffer:

```solidity
if (!rootHistory.isValidAgentRoot(proof.agentTreeRoot)) {
    revert UnknownAgentRoot(proof.agentTreeRoot);
}
```

This ensures the prover used a genuine, recent agent tree root — not a fabricated one that includes their phantom leaf.

## 3. Trust Model for agentTreeRoot

### 3.1 Current Model

The `agentTreeRoot` is **operator-attested**:
- The `IdentityRegistry` operator computes the Merkle root off-chain after enrollment
- The operator calls `enrollAgent(commitment, newRoot)` to push the root on-chain
- The 30-slot ring buffer provides a ~7.5 minute validity window

### 3.2 Trust Assumptions

| Assumption | Consequence if Violated |
|------------|------------------------|
| Operator correctly computes roots | Phantom agents could be enrolled |
| Poseidon is collision-resistant | Merkle proofs could be forged |
| Groth16 is knowledge-sound | Proofs could be fabricated without witness |
| Ring buffer not exhausted during prove | Valid proofs rejected (liveness, not soundness) |

### 3.3 Future Improvements

1. **On-chain tree insertion**: Prove correct insertion via a separate circuit, removing operator trust for root computation
2. **Longer buffer**: Increase from 30 to 100 slots for higher-throughput deployments
3. **Root attestation**: Multiple operators or a DAO attest to root correctness

## 4. Upgrade Path for Existing Delegations

### 4.1 Assessment

All v1 delegations are potentially unsound. There is no way to retroactively determine whether a v1 delegation's `delegateeCredCommitment` was legitimate without re-proving under v2.

### 4.2 Recommended Migration

**Phase 1 — Dual Verifier (Weeks 1-4)**
- Deploy v2 verifier alongside v1
- New delegations use v2 exclusively
- v1 delegations marked as "legacy" in UI

**Phase 2 — Re-delegation (Weeks 4-8)**
- Notify delegators of v1 delegations
- Provide SDK tooling to re-create delegations under v2
- v1 delegations continue to function but display warnings

**Phase 3 — Sunset (Week 8+)**
- Set expiry block for v1 verifier
- Reject v1 proofs after cutoff
- Archive v1 delegation records

### 4.3 Backward Compatibility

The `scopeCommitment` derivation is unchanged between v1 and v2. Downstream circuits consuming `scopeCommitment` require no changes. The only difference is that v2 proofs additionally guarantee delegatee existence.

## 5. Constraint Budget

| Component | Constraints |
|-----------|------------|
| Delegator commitment (Poseidon-2) | ~2,000 |
| Merkle inclusion (20 × Poseidon-2) | ~40,060 |
| Scope commitment (Poseidon-3) | ~2,000 |
| Nullifier (Poseidon-2) | ~2,000 |
| **Total** | **~42,060** |

Fits within 2^16 (65,536) Powers of Tau. No new ceremony required if existing PoT supports this count.
