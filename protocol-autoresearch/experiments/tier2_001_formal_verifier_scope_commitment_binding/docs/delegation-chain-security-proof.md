# Delegation Chain Security Proof

## 1. Overview

This document provides the security argument for the Bolyra delegation scope
commitment chain. We prove that given a valid delegation proof at hop _i_,
it is computationally infeasible for the delegatee's actual permission scope
to exceed the delegator's scope.

## 2. Binding Game

**Game Bind(A, λ):**

1. Challenger generates circuit parameters `pp ← Setup(1^λ)`.
2. Adversary A receives `pp` and outputs:
   - A valid proof `π` for the `DelegationChainBinding` circuit
   - Public input `previousScopeCommitment`
   - Public output `currentScopeCommitment`
3. Challenger extracts witness `w` via the knowledge extractor:
   - `(delegatorScope, delegateeScope, credCommitment, previousCredCommitment) ← Extract(π)`
4. **A wins if** any of the following hold:
   - `delegateeScope & delegatorScope ≠ delegateeScope` (scope expansion)
   - `Poseidon(delegatorScope, previousCredCommitment) ≠ previousScopeCommitment` (chain break)
   - `Poseidon(delegateeScope, credCommitment) ≠ currentScopeCommitment` (output forgery)

**Theorem.** For any PPT adversary A, `Pr[A wins Bind(A, λ)] ≤ negl(λ)`,
assuming Poseidon-128 collision resistance and Groth16/PLONK knowledge soundness.

## 3. Reduction to Poseidon Collision Resistance

**Claim.** If adversary A can produce a valid proof where `delegatorScope_claimed ≠ delegatorScope_committed`, then we can construct adversary B that finds a Poseidon collision.

**Proof sketch.**

1. B receives a Poseidon challenge and runs A as a subroutine.
2. A produces proof π with public input `previousScopeCommitment = s`.
3. B extracts the witness: `(delegatorScope_w, previousCredCommitment_w)`.
4. By the circuit constraint: `Poseidon(delegatorScope_w, previousCredCommitment_w) = s`.
5. If A supplied different values `(delegatorScope', cred')` to compute `s`,
   then `Poseidon(delegatorScope', cred') = Poseidon(delegatorScope_w, previousCredCommitment_w) = s`.
6. Since `(delegatorScope', cred') ≠ (delegatorScope_w, previousCredCommitment_w)`,
   B outputs a collision.

This contradicts the collision-resistance assumption on Poseidon-128
(Grassi et al., USENIX Security 2021).

## 4. Subset Check Wiring Analysis

The circuit enforces the subset predicate via bitwise constraints:

```
for i in 0..7:
    delegateeBits[i] * (1 - delegatorBits[i]) === 0
```

**Signal aliasing is impossible** because:

- `delegatorBits` is computed from `delegatorScope` via `Num2Bits(8)`,
  which constrains each output bit to {0, 1} and their weighted sum to
  equal `delegatorScope`.
- The _same_ `delegatorScope` signal is wired to `Poseidon(delegatorScope, previousCredCommitment)`.
- Circom's rank-1 constraint system (R1CS) ensures that a signal has exactly
  one value per satisfying assignment. There is no way to "fork" the signal
  to provide different values to the subset check and the commitment hash.

Therefore, an attacker who passes the subset check with a narrower scope
cannot simultaneously satisfy the commitment constraint with a wider scope.

## 5. Cumulative-Bit Implication Enforcement

The Bolyra permission model requires:
- Bit 4 (FINANCIAL_UNLIMITED) → Bit 3 (FINANCIAL_MEDIUM) and Bit 2 (FINANCIAL_SMALL)
- Bit 3 (FINANCIAL_MEDIUM) → Bit 2 (FINANCIAL_SMALL)

The circuit enforces these via:
```
bit[4] * (1 - bit[3]) === 0
bit[4] * (1 - bit[2]) === 0
bit[3] * (1 - bit[2]) === 0
```

for both delegator and delegatee scopes. This prevents ill-formed permission
masks from entering the system, even if they would satisfy the subset check.

## 6. Adversarial Test Results

| Attack | Test | Result |
|--------|------|--------|
| Scope expansion (extra bit) | `adversarial.js` Case 1 | Constraint violation at witness gen |
| Commitment mismatch (random value) | `adversarial.js` Case 2 | Constraint violation at witness gen |
| Pre-image substitution (scope swap) | `adversarial.js` Case 3 | Constraint violation at witness gen |
| Cumulative-bit violation | `adversarial.js` Case 4 | Constraint violation at witness gen |
| Exhaustive 2^16 soundness | `soundness.js` | All 65 536 pairs match predicate |

## 7. Limitations

- **Multi-hop composition.** This analysis covers a single hop. Full chain
  security across _n_ hops follows by induction: each hop's
  `currentScopeCommitment` becomes the next hop's `previousScopeCommitment`,
  and scope can only narrow at each step.

- **Field overflow.** The 8-bit scope values are far below the BN254 field
  size (~254 bits), so field-overflow attacks are not applicable.

- **Poseidon security margin.** We rely on the 128-bit security claim from
  Grassi et al. 2021. Ongoing algebraic cryptanalysis (e.g., Keller & Rosemarin 2021)
  has not broken this claim for the parameter sets used by circomlib.

## 8. References

1. Grassi, L., Khovratovich, D., Rechberger, C., Roy, A., & Schofnegger, M.
   (2021). "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems."
   USENIX Security 2021.

2. Groth, J. (2016). "On the Size of Pairing-Based Non-Interactive Arguments."
   EUROCRYPT 2016.

3. Gabizon, A., Williamson, Z. J., & Ciobotaru, O. (2019). "PLONK:
   Permutations over Lagrange-bases for Oecumenical Noninteractive arguments
   of Knowledge." IACR ePrint 2019/953.
