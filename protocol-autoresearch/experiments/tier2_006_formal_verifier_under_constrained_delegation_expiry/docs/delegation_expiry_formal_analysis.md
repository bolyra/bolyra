# Formal Analysis: Delegation Expiry Narrowing Soundness

## 1. Overview

This document presents a formal soundness analysis of the delegation expiry
narrowing constraints in the Bolyra identity protocol's `DelegationWithExpiry`
circuit (v3.0.0). The analysis proves that no adversarial witness can produce
a valid proof where a delegatee's credential outlives the delegator's authority
or where an expired credential is accepted.

## 2. Circuit Under Analysis

**Source**: `Delegation.circom` (DelegationWithExpiry template)

The circuit enforces two temporal constraints:
1. `delegateeExpiry <= delegatorExpiry` — narrowing constraint
2. `currentTimestamp < delegateeExpiry` — liveness constraint

Both constraints operate on signals that are first range-checked to `[0, 2^64)`
via `Num2Bits(64)` decomposition.

## 3. Attack Vector: Field Element Wraparound

### 3.1 The Problem

Circom circuits operate over the BN254 scalar field `F_p` where:
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

The `LessThan(n)` component from circomlib compares two values by computing
`in[0] + 2^n - in[1]` and checking the `n`-th bit. This comparison is only
valid when both inputs are in `[0, 2^n)`. If a malicious prover supplies
a value outside this range (e.g., `p - 1`), the field arithmetic can produce
incorrect comparison results.

### 3.2 Concrete Attack Scenario (Without Range Checks)

Suppose the circuit did NOT range-check expiry values. An attacker could:

1. Set `delegateeExpiry = p - 1` (a valid field element)
2. Set `delegatorExpiry = 2000` (a normal value)
3. In `LessThan(64)`, the computation `(p-1) + 2^64 - 2000` would overflow
   the field, wrapping around to a small value
4. The comparison could incorrectly return `1` (true), allowing a delegatee
   with effectively infinite expiry

This is the **field element wraparound attack**.

### 3.3 The Defense: Num2Bits(64)

`Num2Bits(64)` decomposes a signal into 64 binary bits:
```
in === sum_{i=0}^{63} bits[i] * 2^i
where bits[i] * (bits[i] - 1) === 0 for all i
```

This constrains `in` to exactly the set `{0, 1, 2, ..., 2^64 - 1}`.

**Key insight**: Since `2^64 << p`, there is no field-element aliasing.
The constraint `in = sum(bits * 2^i)` has a **unique** solution in `F_p`
for each integer in `[0, 2^64)`. Any value >= `2^64` cannot satisfy the
constraint, because no combination of 64 binary bits sums to a value
that large.

## 4. Invariant Specifications

### I1: Delegation Expiry Narrowing
```
forall w: circuit_accepts(w) => delegateeExpiry(w) <= delegatorExpiry(w) in Z
```

**Proof**: Lines 95-96 of Delegation.circom apply `Num2Bits(64)` to both
expiry signals, bounding them to `[0, 2^64)`. Line 103-106 applies
`LessEqThan(64)` and asserts the output is 1. Since both inputs are
provably in `[0, 2^64)` and `LessEqThan(64)` correctly implements `<=`
for inputs in this range, the integer inequality holds.

### I2: Expired Delegation Rejection
```
forall w: circuit_accepts(w) => currentTimestamp(w) < delegateeExpiry(w) in Z
```

**Proof**: Line 89 applies `Num2Bits(64)` to `currentTimestamp`, bounding
it to `[0, 2^64)`. Line 95 does the same for `delegateeExpiry`. Lines
110-113 apply `LessThan(64)` and assert output is 1. Since both inputs
are bounded, the integer strict inequality holds.

### I3: Range-Checked Comparator Inputs
```
forall w: circuit_accepts(w) => all timestamp signals in [0, 2^64)
```

**Proof**: Direct from `Num2Bits(64)` constraints at lines 89, 93, 95.

### I4: Out-of-Range Rejection
```
forall w: any timestamp signal >= 2^64 => circuit rejects
```

**Proof**: Contrapositive of I3. If any signal >= `2^64`, `Num2Bits(64)`
cannot be satisfied, so the constraint system is unsatisfiable.

## 5. Constraint Count Analysis

| Component | Constraints | Count |
|-----------|-------------|-------|
| `Num2Bits(64)` x 3 | 64 binary + 1 sum each | 195 |
| `LessEqThan(64)` | Internal `LessThan(65)` | ~66 |
| `LessThan(64)` | `Num2Bits(65)` + extraction | ~66 |
| Equality assertions | `=== 1` x 2 | 2 |
| **Total** | | **~329** |

This matches the outline estimate of ~320 constraints within the expected
variance for circomlib version differences.

## 6. Boundary Test Matrix

| Case | currentTs | delegatorExp | delegateeExp | Expected | Rationale |
|------|-----------|-------------|-------------|----------|-----------|
| Nominal valid | 1000 | 2000 | 1500 | Accept | Normal case |
| Equal expiries | 1000 | 2000 | 2000 | Accept | <= boundary |
| delegatee - 1 | 1000 | 2000 | 1999 | Accept | Just under |
| ts - 1 | 1499 | 2000 | 1500 | Accept | Just not expired |
| ts = 0 | 0 | 2000 | 1500 | Accept | Genesis |
| Max 64-bit | 2^64-3 | 2^64-1 | 2^64-2 | Accept | Range boundary |
| delegatee + 1 | 1000 | 2000 | 2001 | **Reject** | Narrowing violated |
| ts = exp | 1500 | 2000 | 1500 | **Reject** | Expired (not strict <) |
| ts > exp | 2000 | 2000 | 1500 | **Reject** | Clearly expired |
| exp = 0 | 0 | 1000 | 0 | **Reject** | Zero expiry |
| All zero | 0 | 0 | 0 | **Reject** | ts not < exp |
| exp = 2^64 | 1000 | 2^64 | 2^64 | **Reject** | Range overflow |
| exp = p-1 | 1000 | 2000 | p-1 | **Reject** | Wraparound attack |

## 7. Integration Notes

The `DelegationExpiryCheck` fragment is designed to be verifiable in
isolation. In the full `DelegationWithExpiry` circuit, these same
constraints appear at lines 88-113. The isolated fragment allows:

1. Independent formal verification without the Poseidon/Merkle overhead
2. Faster test iteration (329 vs ~42,260 constraints)
3. Clear separation of temporal soundness from identity binding

## 8. Recommendations

1. **Contract-side timestamp validation**: The circuit accepts any
   `currentTimestamp` in `[0, 2^64)`. The verifier contract MUST check
   that the public input `currentTimestamp` is within an acceptable
   window of `block.timestamp` (e.g., +/- 5 minutes) to prevent
   timestamp manipulation.

2. **Minimum expiry enforcement**: Consider adding a minimum delegatee
   expiry (e.g., `delegateeExpiry > currentTimestamp + MIN_VALIDITY`)
   to prevent extremely short-lived delegations that could be used
   in timing attacks.

3. **Formal verification tooling**: When Circom-compatible formal
   verification tools mature (e.g., Ecne, Picus), these invariants
   should be machine-checked against the R1CS constraint system.
