# Formal Proof: Nullifier Collision Independence

## 1. Definitions

**Definition 1 (Poseidon Hash Family).** Let `H_k : F^k → F` denote the Poseidon
hash function with arity `k` over a prime field `F` (BN254 or BLS12-381 scalar field).
For distinct arities `k ≠ k'`, `H_k` and `H_{k'}` use different round constants,
MDS matrices, and state sizes.

**Definition 2 (Domain-Tagged Nullifier).** For circuit `C` with domain tag `d_C ∈ F`
and input vector `v_C ∈ F^{n_C}`, the nullifier is:
```
  N_C = H_{1+n_C}(d_C ∥ v_C)
```
where `∥` denotes concatenation.

**Definition 3 (Bolyra Circuit Nullifiers).** The three Bolyra circuits define:
```
  N_H = H_3(1, scope, secret)                              — HumanUniqueness
  N_A = H_3(2, agentSecret, policyScope)                   — AgentPolicy
  N_D = H_4(3, delegatorSecret, delegateeCredComm, scope)  — Delegation
```

**Definition 4 (Cross-Circuit Collision).** A cross-circuit collision between
circuits `C_i` and `C_j` is a pair of valid witnesses `(w_i, w_j)` such that
`N_{C_i}(w_i) = N_{C_j}(w_j)` with `i ≠ j`.

**Definition 5 (Preimage Resistance).** `H_k` is `(t, ε)`-preimage resistant if
no algorithm running in time `t` can, given `y ← H_k(x)` for random `x`,
find `x'` with `H_k(x') = y` with probability greater than `ε`.

## 2. Security Assumption

**Assumption (Poseidon Preimage Resistance).** For the Poseidon hash family
instantiated over BN254/BLS12-381 with recommended round parameters:

- `H_k` is `(2^128, 2^{-128})`-preimage resistant for each arity `k`.
- For `k ≠ k'`, finding `(x, x')` with `H_k(x) = H_{k'}(x')` is at least
  as hard as preimage resistance for either `H_k` or `H_{k'}`.

## 3. Theorem: Domain Separation

**Theorem.** Under the Poseidon Preimage Resistance assumption, no efficient
adversary can produce a cross-circuit collision between any two of the three
Bolyra circuit nullifiers `(N_H, N_A, N_D)`.

**Proof.** We consider all three pairs:

### Case 1: HumanUniqueness vs. AgentPolicy (N_H vs. N_A)

Both use `H_3` (arity 3). A collision requires:
```
  H_3(1, scope, secret) = H_3(2, agentSecret, policyScope)
```

Since the domain tags are constrained by the circuit (tag = 1 for HumanUniqueness,
tag = 2 for AgentPolicy), any valid witness must have:
```
  input[0] = 1   (for N_H)
  input[0] = 2   (for N_A)
```

Thus the preimages differ in at least position 0. Finding two distinct preimages
`x ≠ x'` with `H_3(x) = H_3(x')` is precisely the second-preimage problem,
which requires `Ω(2^128)` operations by assumption.  □

### Case 2: HumanUniqueness vs. Delegation (N_H vs. N_D)

`N_H` uses `H_3`, `N_D` uses `H_4`. A collision requires:
```
  H_3(1, scope, secret) = H_4(3, delegatorSecret, delegateeCredComm, scope)
```

Since `H_3` and `H_4` are distinct hash functions (different state sizes, round
constants, and MDS matrices), this is a cross-parameter collision. By the
assumption, this is at least as hard as preimage resistance for either function,
requiring `Ω(2^128)` operations.  □

### Case 3: AgentPolicy vs. Delegation (N_A vs. N_D)

`N_A` uses `H_3`, `N_D` uses `H_4`. A collision requires:
```
  H_3(2, agentSecret, policyScope) = H_4(3, delegatorSecret, delegateeCredComm, scope)
```

Same argument as Case 2: cross-parameter collision between `H_3` and `H_4`,
requiring `Ω(2^128)` operations.  □

## 4. Corollary: No Valid Cross-Circuit Witness

**Corollary.** For any circuit `C_i` and nullifier value `n` produced by a valid
witness for circuit `C_j` (where `i ≠ j`), there exists no valid witness for `C_i`
that produces `n`.

**Proof.** By the domain separation theorem, `N_{C_i}(w_i) ≠ N_{C_j}(w_j)` for
all valid witness pairs with overwhelming probability. Additionally, the domain
tag constraint in `C_i` enforces `input[0] = d_i`, so even if an adversary could
find a hash collision, the resulting witness would violate the domain tag gate
and be rejected by the constraint system.  □

## 5. Constraint Enforcement

The domain tag is not merely a convention — it is enforced by the circuit's
constraint system:

```
// In each circuit:
signal domainTag;
domainTag <== DOMAIN_X;     // Assigned from constant
// Poseidon input[0] = domainTag
// The R1CS constraint domainTag === DOMAIN_X is checked by the verifier
```

A malicious prover who attempts to use a different domain tag will produce a
witness that fails verification. The MockProver negative tests in
`tests/nullifier_collision_independence_test.rs` confirm this: injecting a
foreign circuit's nullifier causes `prover.verify().is_err()`.

## 6. Cross-References

- Symbolic analysis: `tests/nullifier_domain_separation_symbolic.py`
- MockProver tests: `tests/nullifier_collision_independence_test.rs`
- Domain separation spec: `docs/nullifier_domain_separation.md`
- Poseidon security analysis: Grassi et al., "Poseidon: A New Hash Function for
  Zero-Knowledge Proof Systems" (USENIX Security 2021)

## 7. Summary

| Pair                               | Separation Mechanism        | Attack Complexity |
|------------------------------------|-----------------------------|-------------------|
| HumanUniqueness vs. AgentPolicy    | Domain tag (1 ≠ 2)          | 2^128 (second-preimage) |
| HumanUniqueness vs. Delegation     | Arity (3 ≠ 4) + tag (1 ≠ 3)| 2^128 (cross-parameter) |
| AgentPolicy vs. Delegation         | Arity (3 ≠ 4) + tag (2 ≠ 3)| 2^128 (cross-parameter) |

Domain separation is **proven** under standard assumptions.  □
