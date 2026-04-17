# Delegation Circuit v2 — Specification

**Status:** Draft  
**Version:** 2.0.0  
**Date:** 2026-04-17  
**Authors:** Bolyra Protocol Team  
**Fixes:** CVE-BOLYRA-2026-001 (Phantom Delegatee Vulnerability)

## 1. Overview

The Delegation circuit enables a delegator to grant scoped authority to a delegatee within the Bolyra identity protocol. Version 2.0 adds a **Merkle inclusion proof** for the delegatee's credential commitment, closing the phantom delegatee vulnerability.

### 1.1 Vulnerability Summary

In v1, `delegateeCredCommitment` was a private input with **no inclusion constraint**. An attacker could fabricate any field element as the delegatee commitment, produce a valid Groth16 proof, and receive a binding `scopeCommitment` downstream. This allowed unauthorized delegation to non-existent identities.

## 2. Signal Table

### 2.1 Public Inputs

| Signal | Type | Description |
|--------|------|-------------|
| `agentTreeRoot` | field | Merkle root of the agent identity tree (validated on-chain against root history buffer) |
| `scopeCommitment` | field | `Poseidon(delegatorCredCommitment, delegateeCredCommitment, scope)` |
| `nullifierHash` | field | `Poseidon(delegatorSecret, scope)` — prevents double-delegation |

### 2.2 Private Inputs

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorSecret` | field | Delegator's secret key |
| `delegatorNonce` | field | Delegator's nonce |
| `delegateeCredCommitment` | field | Delegatee's credential commitment (leaf in agent tree) |
| `scope` | field | Delegation scope identifier |
| `merklePathElements[20]` | field[20] | Merkle proof sibling hashes |
| `merklePathIndices[20]` | field[20] | Merkle proof direction bits (0=left, 1=right) |

## 3. Constraints

### 3.1 Delegator Commitment (2 constraints)

```
delegatorCredCommitment = Poseidon(delegatorSecret, delegatorNonce)
```

### 3.2 Delegatee Merkle Inclusion (~40,000 constraints)

```
merkleCheck = BinaryMerkleRoot(20)
merkleCheck.leaf = delegateeCredCommitment
merkleCheck.pathElements[i] = merklePathElements[i]  for i in [0..19]
merkleCheck.pathIndices[i] = merklePathIndices[i]    for i in [0..19]
merkleCheck.root === agentTreeRoot
```

Each level requires:
- 1 Poseidon(2) hash (~2,000 constraints)
- 1 binary constraint on `pathIndices[i]` (1 constraint)
- 2 conditional swap constraints (2 constraints)

Total: ~20 × 2,003 ≈ 40,060 constraints for the Merkle proof.

### 3.3 Scope Commitment (3 constraints)

```
scopeCommitment === Poseidon(delegatorCredCommitment, delegateeCredCommitment, scope)
```

### 3.4 Nullifier (2 constraints)

```
nullifierHash === Poseidon(delegatorSecret, scope)
```

### 3.5 Total Constraint Budget

| Component | Constraints (approx) |
|-----------|---------------------|
| Delegator commitment | 2,000 |
| Merkle inclusion (20 levels) | 40,060 |
| Scope commitment | 2,000 |
| Nullifier | 2,000 |
| **Total** | **~42,060** |

Fits within 2^16 = 65,536 Powers of Tau constraint budget.

## 4. Merkle Proof Format

### 4.1 Tree Structure

- Binary Merkle tree, maximum depth 20 (supports up to 2^20 = 1,048,576 leaves)
- Hash function: Poseidon(2) over the BN254 scalar field
- Leaves: credential commitments (`Poseidon(secret, nonce)`)
- Empty leaves: 0 (zero value)

### 4.2 Authentication Path

```typescript
interface MerkleProof {
  leaf: bigint;               // delegateeCredCommitment
  pathElements: bigint[20];   // sibling hashes, bottom to top
  pathIndices: number[20];    // 0 = leaf is left child, 1 = leaf is right child
  root: bigint;               // expected root (must match agentTreeRoot)
}
```

### 4.3 Hash Consistency

The same Poseidon(2) instance MUST be used for:
1. Computing credential commitments (`Poseidon(secret, nonce)`)
2. Internal Merkle tree nodes (`Poseidon(left, right)`)

This ensures that `delegateeCredCommitment` as a leaf is compatible with the tree's internal hash function.

## 5. Root History Buffer Interface

The `agentTreeRoot` public input is validated on-chain against the `IdentityRegistry` contract's root history ring buffer:

```solidity
interface IRootHistory {
    function isValidAgentRoot(uint256 root) external view returns (bool);
}
```

- Buffer size: 30 slots (covers ~7.5 minutes at 15s prove time)
- The `DelegationRegistry.submitDelegation()` function calls `isValidAgentRoot(agentTreeRoot)` and reverts with `UnknownAgentRoot()` if the root is not found

## 6. Soundness Argument

### 6.1 Claim

A valid delegation proof guarantees that the delegatee's credential commitment was enrolled in the agent tree at a recent point in time (within the root history buffer window).

### 6.2 Argument

1. **Circuit soundness**: The Groth16 proof system guarantees that if the verifier accepts, then there exist private inputs satisfying all constraints. In particular, `merkleCheck.root === agentTreeRoot` is satisfied, meaning the prover knows a valid Merkle path from `delegateeCredCommitment` to `agentTreeRoot`.

2. **Merkle binding**: The BinaryMerkleRoot template uses Poseidon(2) which is collision-resistant over the BN254 scalar field. Finding a valid path to a root without the leaf being in the tree requires finding a Poseidon collision, which is computationally infeasible.

3. **On-chain root validation**: The `DelegationRegistry` checks that `agentTreeRoot` exists in the `IdentityRegistry`'s root history buffer. This prevents the prover from using a fabricated root that includes their phantom leaf.

4. **Freshness**: The 30-slot ring buffer ensures the root was valid within a recent window, preventing use of ancient roots that may have been compromised.

### 6.3 Trust Model

- The `agentTreeRoot` is trusted because it is maintained by the `IdentityRegistry` operator
- The operator is trusted to correctly compute Merkle roots after enrollment
- In future versions, the tree insertion itself may be proven in a separate circuit

## 7. Upgrade Path

### 7.1 Existing Delegations

Delegations created under v1 (without Merkle inclusion proof) SHOULD be treated as potentially unsound. Migration options:

1. **Soft migration**: Mark v1 delegations as "unverified" in UI; require re-delegation under v2
2. **Hard migration**: Set an expiry block for v1 delegations; reject after cutoff
3. **Parallel operation**: Run v1 and v2 verifiers simultaneously during transition

### 7.2 Circuit Version Constant

The circuit version is embedded in the public inputs via the `scopeCommitment` derivation. v1 and v2 scope commitments are compatible (same derivation), but v2 proofs additionally prove tree membership.
