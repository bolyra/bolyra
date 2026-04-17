# Bolyra Protocol — Circuit Invariant Property Registry

This document catalogues all named formal invariant properties across the three Bolyra circuits: **Identity**, **Credential**, and **Delegation**.

## Summary

| # | Property ID | Circuit | Category | Signals | Formal Statement |
|---|-------------|---------|----------|---------|------------------|
| P1 | `identity_commitment_range` | Identity | Field Overflow | `identityCommitment` | `0 ≤ identityCommitment < 2^64` |
| P2 | `human_root_field_range` | Identity | Field Overflow | `humanRoot` | `0 ≤ humanRoot < 2^253` |
| P3 | `agent_root_field_range` | Identity | Field Overflow | `agentRoot` | `0 ≤ agentRoot < 2^253` |
| P4 | `credential_expiry_range` | Credential | Field Overflow | `expiryTimestamp` | `0 ≤ expiryTimestamp < 2^64` |
| P5 | `cred_commitment_field_range` | Credential | Field Overflow | `credCommitment` | `0 ≤ credCommitment < 2^253` |
| P6 | `delegator_expiry_range` | Delegation | Field Overflow | `delegatorExpiry` | `0 ≤ delegatorExpiry < 2^64` |
| P7 | `delegatee_expiry_range` | Delegation | Field Overflow | `delegateeExpiry` | `0 ≤ delegateeExpiry < 2^64` |
| P8 | `scope_bitmask_range` | Delegation | Field Overflow | `delegatorScope`, `delegateeScope` | `0 ≤ scope < 2^64` for both |
| P9 | `identity_nullifier_uniqueness` | Identity | Nullifier Uniqueness | `secret`, `scope`, `nullifier` | `(s1,sc1) ≠ (s2,sc2) ⟹ H(s1,sc1) ≠ H(s2,sc2)` |
| P10 | `credential_nullifier_uniqueness` | Credential | Nullifier Uniqueness | `credCommitment`, `nonce`, `nullifier` | `(c1,n1) ≠ (c2,n2) ⟹ H(c1,n1) ≠ H(c2,n2)` |
| P11 | `delegation_nullifier_uniqueness` | Delegation | Nullifier Uniqueness | `delegatorCmt`, `delegateeCmt`, `nonce`, `nullifier` | `(d1,e1,n1) ≠ (d2,e2,n2) ⟹ H(d1,e1,n1) ≠ H(d2,e2,n2)` |
| P12 | `scope_monotonicity_bitmask` | Delegation | Scope Monotonicity | `delegatorScope`, `delegateeScope` | `delegateeScope & ~delegatorScope == 0` |
| P13 | `scope_empty_delegatee_valid` | Delegation | Scope Monotonicity | `delegateeScope` | `0 & ~delegatorScope == 0` (trivially true) |
| P14 | `scope_identity_valid` | Delegation | Scope Monotonicity | `delegatorScope`, `delegateeScope` | `s & ~s == 0` when scopes equal |
| P15 | `expiry_narrowing` | Delegation | Expiry Narrowing | `delegatorExpiry`, `delegateeExpiry` | `delegateeExpiry ≤ delegatorExpiry` |
| P16 | `expiry_zero_delegatee_valid` | Delegation | Expiry Narrowing | `delegateeExpiry` | `0 ≤ delegatorExpiry` (trivially true) |
| P17 | `expiry_equal_valid` | Delegation | Expiry Narrowing | `delegatorExpiry`, `delegateeExpiry` | `e == e ⟹ e ≤ e` |

## Category Details

### 1. Field Overflow (P1–P8)

All uint64-typed signals must be range-checked via `Num2Bits(64)` or equivalent `LessThan` constraint in the circuit. The Certora properties and circom_tester harness verify that:

- Witnesses at the boundary `2^64 - 1` are **accepted**
- Witnesses at `2^64` are **rejected** (constraint failure)
- Zero values are **accepted**

**Signal-to-constraint mapping:**

| Circuit | Signal | Range Check Component |
|---------|--------|-----------------------|
| Identity | `identityCommitment` | `Num2Bits(64)` on private input |
| Identity | `humanRoot` | Field element (Poseidon output, < p) |
| Identity | `agentRoot` | Field element (Poseidon output, < p) |
| Credential | `expiryTimestamp` | `Num2Bits(64)` + `LessThan(64)` for expiry comparison |
| Credential | `credCommitment` | Field element (Poseidon output, < p) |
| Delegation | `delegatorExpiry` | `Num2Bits(64)` |
| Delegation | `delegateeExpiry` | `Num2Bits(64)` |
| Delegation | `delegatorScope` | `Num2Bits(64)` for bitmask operations |
| Delegation | `delegateeScope` | `Num2Bits(64)` for bitmask operations |

### 2. Nullifier Uniqueness (P9–P11)

Nullifiers are computed as Poseidon hashes of distinct input tuples. The collision resistance of Poseidon (128-bit security) guarantees that distinct inputs produce distinct outputs with overwhelming probability.

**Nullifier formulas:**

| Circuit | Formula | Inputs |
|---------|---------|--------|
| Identity | `Poseidon2(secret, scope)` | Private `secret`, public `scope` |
| Credential | `Poseidon2(credCommitment, nonce)` | Private `credCommitment`, private `nonce` |
| Delegation | `Poseidon3(delegatorCmt, delegateeCmt, nonce)` | Private commitments + nonce |

**False-positive analysis:** With 500 random samples and a 254-bit Poseidon output, the birthday-bound collision probability is `500^2 / 2^255 ≈ 2^{-237}`, far below the `2^{-64}` threshold.

### 3. Scope Monotonicity (P12–P14)

The Delegation circuit enforces that the delegatee cannot gain permissions the delegator does not hold. This is enforced as a bitmask subset check:

```
delegateeScope AND (NOT delegatorScope) === 0
```

Equivalently: every bit set in `delegateeScope` must also be set in `delegatorScope`.

**Test coverage:**
- All-zeros scope (empty delegation) — accepted
- Identical scopes (full delegation) — accepted
- Strict subset — accepted
- Single extra bit in delegatee — rejected
- Complement scopes — rejected

### 4. Expiry Narrowing (P15–P17)

The Delegation circuit enforces temporal narrowing:

```
delegateeExpiry ≤ delegatorExpiry
```

This is checked via `LessThan(64)` on the uint64 expiry timestamps.

**Test coverage:**
- Equal expiries — accepted
- Zero delegatee expiry — accepted
- delegateeExpiry = delegatorExpiry - 1 — accepted
- delegateeExpiry = delegatorExpiry + 1 — rejected
- MAX_UINT64 delegatee with lower delegator — rejected

## Collision Probability Bound

For probabilistic uniqueness tests (P9–P11), we bound the false-positive probability:

- Poseidon output: 254 bits
- Sample size: N = 500
- Birthday probability: `≈ N² / 2^255 ≈ 2^{-237}`
- Required bound: `≤ 2^{-64}`
- **Margin: 173 bits** — well within safety threshold

Increasing N to 10,000 yields `2^{-228}`, still far below `2^{-64}`.
