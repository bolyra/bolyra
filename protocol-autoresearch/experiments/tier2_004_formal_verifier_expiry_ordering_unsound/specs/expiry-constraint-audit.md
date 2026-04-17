# Expiry Constraint Audit — Bolyra Identity Protocol

## 1. Summary

This document records which expiry and ordering invariants are enforced
in-circuit (inside the SNARK) versus on-chain (in Solidity verifier contracts),
the rationale for in-circuit enforcement, and the constraint cost breakdown.

## 2. Invariant Table

| Invariant | Circuit | Contract | Enforcement |
|-----------|---------|----------|-------------|
| `currentTimestamp < expiryTimestamp` | AgentPolicy.circom — `LessThan(64)` | AgentPolicyVerifier.sol — **REMOVED** (was redundant) | **In-circuit only** |
| `delegateeExpiry <= delegatorExpiry` | Delegation.circom — `LessEqThan(64)` | DelegationRegistry.sol — **REMOVED** (was redundant) | **In-circuit only** |
| `currentTimestamp < delegateeExpiry` | Delegation.circom — `LessThan(64)` | DelegationRegistry.sol — **REMOVED** | **In-circuit only** |
| `currentTimestamp` freshness (vs block.timestamp) | N/A | AgentPolicyVerifier.sol — `block.timestamp - 300 <= ts` | **On-chain only** |
| `agentTreeRoot` in root history buffer | N/A | DelegationRegistry.sol — `IRootHistory.isValidAgentRoot()` | **On-chain only** |
| Nullifier not already spent | N/A | Both verifiers — `spentNullifiers[hash]` | **On-chain only** |
| Timestamp range (64-bit) | Both circuits — `Num2Bits(64)` | N/A | **In-circuit only** |

## 3. Rationale for In-Circuit Enforcement

### Why not enforce expiry in Solidity alone?

1. **Proof-contract gap**: If expiry is only checked in Solidity, an attacker
   can generate a valid proof with an expired credential and race to submit it
   in the same block before the contract-side check executes. More critically,
   if the contract neglects to re-derive the ordering from public signals, the
   check is simply absent.

2. **Composability**: Proofs may be verified by third-party contracts that do
   not implement expiry checks. In-circuit enforcement ensures the invariant
   holds regardless of which contract verifies the proof.

3. **Proof semantics**: A valid proof should semantically mean "this credential
   is valid right now." Delegating expiry to external logic weakens this
   guarantee.

### What stays on-chain?

- **Timestamp freshness**: The circuit cannot access `block.timestamp`, so
  the contract must verify that `currentTimestamp` (a public signal) is
  recent relative to the block. This prevents proof pre-generation attacks.

- **Root history**: The circuit proves membership in a specific Merkle root,
  but cannot verify that root is still in the valid window. The contract
  checks `IRootHistory.isValidAgentRoot(root)`.

- **Nullifier tracking**: Nullifier spending is stateful and must be on-chain.

## 4. Constraint Cost Breakdown

### AgentPolicy Circuit

| Component | Constraints (approx) |
|-----------|---------------------|
| Poseidon(2) — agent commitment | ~250 |
| BinaryMerkleRoot(20) — Merkle inclusion | ~40,000 |
| Num2Bits(64) x2 — timestamp range checks | ~128 |
| **LessThan(64) — expiry check (NEW)** | **~130** |
| Poseidon(2) — nullifier | ~250 |
| **Total** | **~40,758** |

### Delegation Circuit (v3, with expiry)

| Component | Constraints (approx) |
|-----------|---------------------|
| Poseidon(2) — delegator commitment | ~250 |
| BinaryMerkleRoot(20) — delegatee inclusion | ~40,000 |
| Poseidon(3) — scope commitment | ~350 |
| Poseidon(2) — nullifier | ~250 |
| Num2Bits(64) x3 — timestamp range checks | ~192 |
| **LessEqThan(64) — delegatee <= delegator (NEW)** | **~130** |
| **LessThan(64) — currentTs < delegateeExpiry (NEW)** | **~130** |
| **Total** | **~41,302** |

### Net constraint increase

- AgentPolicy: **+130** constraints (~0.3% increase)
- Delegation: **+260** constraints (~0.6% increase)
- Combined: **+390** constraints

This is negligible relative to the ~40,000 constraint Merkle tree inclusion
proof and does not materially impact proving time.

## 5. Attack Scenario (Pre-Fix)

```
Attacker has credential with expiryTimestamp = 1700000000 (expired).

1. Attacker sets currentTimestamp = 1700000001 (after expiry).
2. Circuit only range-checks both values to 64 bits — no ordering check.
3. Proof is generated successfully.
4. Attacker submits proof to verifier contract.
5. IF contract does not re-check ordering: proof accepted, expired credential used.
6. IF contract does re-check: reverts, but attacker wasted gas; defense-in-depth
   should not rely on the contract catching what the circuit should enforce.
```

## 6. Post-Fix Verification Checklist

- [ ] `AgentPolicy.circom` contains `LessThan(64)` with `isNotExpired.out === 1`
- [ ] `Delegation.circom` contains `LessEqThan(64)` for delegatee/delegator ordering
- [ ] `Delegation.circom` contains `LessThan(64)` for current time vs delegatee expiry
- [ ] Both circuits declare timestamps as public signals
- [ ] Test: `currentTimestamp >= expiryTimestamp` → proof generation fails
- [ ] Test: `currentTimestamp === expiryTimestamp` → proof generation fails
- [ ] Test: `delegateeExpiry > delegatorExpiry` → proof generation fails
- [ ] Test: `delegateeExpiry === delegatorExpiry` → proof generation passes
- [ ] Solidity verifiers do NOT redundantly re-check expiry ordering
- [ ] Solidity verifiers DO check timestamp freshness vs `block.timestamp`
- [ ] Trusted setup re-run after circuit modification
- [ ] Constraint counts match expectations (~130 per LessThan/LessEqThan(64))
