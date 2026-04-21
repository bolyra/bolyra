# Nullifier Domain Separation — Symbolic Analysis

## Overview

This document provides a complete symbolic analysis of nullifier domain separation
across the three Bolyra identity protocol circuits: **HumanUniqueness**, **AgentPolicy**,
and **Delegation**.

## Problem Statement

Prior to domain separation (v1.x), all three circuits computed nullifiers using
`Poseidon(secret, scope)` with arity 2. This meant that if the same `(secret, scope)`
pair was used across circuits, identical nullifiers would be produced — potentially
enabling cross-circuit replay attacks or nullifier set confusion.

## Domain-Separated Nullifier Constructions

| Circuit          | Domain Tag | Input Vector                                           | Arity |
|------------------|------------|--------------------------------------------------------|-------|
| HumanUniqueness  | 1          | `[1, scope, secret]`                                   | 3     |
| AgentPolicy      | 2          | `[2, agentSecret, policyScope]`                        | 3     |
| Delegation       | 3          | `[3, delegatorSecret, delegateeCredCommitment, scope]` | 4     |

### Key Design Decisions

1. **Domain tags are field constants**, not witness values. Each circuit constrains
   `domainTag === DOMAIN_X` via a fixed-column equality gate. A prover cannot
   choose a different tag without violating the constraint system.

2. **Delegation uses arity 4** (vs. arity 3 for the other two), providing an
   additional structural separation layer beyond the domain tag.

3. **Domain tags are consecutive small integers** (1, 2, 3) — easy to audit,
   impossible to confuse, and far from the BN254/BLS12-381 field modulus.

## Pairwise Separation Analysis

### HumanUniqueness vs. AgentPolicy

| Property        | HumanUniqueness              | AgentPolicy                    |
|-----------------|------------------------------|--------------------------------|
| Domain tag      | 1                            | 2                              |
| Arity           | 3                            | 3                              |
| Input vector    | `[1, scope, secret]`         | `[2, agentSecret, policyScope]`|

**Separation:** Same arity, but `input[0]` is always `1` vs. `2`. For any valid
witness pair `(w_H, w_A)`, we have `w_H[0] = 1 ≠ 2 = w_A[0]`, so the Poseidon
preimages differ in at least position 0. A collision would require a second-preimage
attack on Poseidon — computationally infeasible at 128-bit security.

### HumanUniqueness vs. Delegation

| Property        | HumanUniqueness              | Delegation                                      |
|-----------------|------------------------------|--------------------------------------------------|
| Domain tag      | 1                            | 3                                                |
| Arity           | 3                            | 4                                                |
| Input vector    | `[1, scope, secret]`         | `[3, delegatorSecret, delegateeCredComm, scope]` |

**Separation:** Different arities (3 vs. 4). Poseidon with different arities uses
different internal state sizes and round constants. Finding `x ∈ F³` and `y ∈ F⁴`
such that `Poseidon₃(x) = Poseidon₄(y)` is a cross-parameter preimage attack —
strictly harder than standard preimage resistance.

### AgentPolicy vs. Delegation

| Property        | AgentPolicy                    | Delegation                                      |
|-----------------|--------------------------------|--------------------------------------------------|
| Domain tag      | 2                              | 3                                                |
| Arity           | 3                              | 4                                                |
| Input vector    | `[2, agentSecret, policyScope]`| `[3, delegatorSecret, delegateeCredComm, scope]` |

**Separation:** Different arities (3 vs. 4) AND different domain tags (2 vs. 3).
Double separation — collision requires both a cross-parameter attack and a
second-preimage in different Poseidon instances.

## Worst-Case Scenario: All Raw Values Equal

Even if an adversary controls all inputs such that:
```
scope = secret = agentSecret = policyScope = delegatorSecret = delegateeCredComm = V
```

The full Poseidon input vectors are:
- HumanUniqueness: `[1, V, V]`
- AgentPolicy:     `[2, V, V]`
- Delegation:      `[3, V, V, V]`

All pairs still differ in at least one position (domain tag) or arity.

## Security Assumption

**Poseidon2 Preimage Resistance (128-bit).** Given `y = Poseidon(x)`, finding
`x' ≠ x` such that `Poseidon(x') = y` requires `Ω(2¹²⁸)` operations.

This is a standard assumption for Poseidon over BN254/BLS12-381 scalar fields,
validated by algebraic cryptanalysis (Grassi et al., 2020) and adopted by
protocols including Semaphore v4, MACI, and Tornado Cash Nova.

## Test Results

See `tests/nullifier_domain_separation_symbolic.py` for the executable symbolic
analysis and `tests/nullifier_collision_independence_test.rs` for the Halo2
MockProver test suite confirming:

1. Each circuit satisfies its own constraints with the correct domain tag.
2. All three nullifiers are pairwise distinct on shared raw inputs.
3. Injecting a foreign circuit's nullifier violates the domain tag constraint.

## Conclusion

Domain separation is **proven** for all three pairwise circuit combinations under
the Poseidon2 preimage resistance assumption. No valid witness for circuit A can
produce a `nullifierHash` equal to a valid `nullifierHash` from circuit B.  □
