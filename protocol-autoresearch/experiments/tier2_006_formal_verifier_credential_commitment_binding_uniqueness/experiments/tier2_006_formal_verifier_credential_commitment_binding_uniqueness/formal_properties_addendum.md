# Formal Property: P-COMMIT-BIND

> **Addendum to `circuits/FORMAL-PROPERTIES.md`**
>
> This file contains the formal property statement to be appended to the
> project's `circuits/FORMAL-PROPERTIES.md` when this experiment is promoted.

---

## P-COMMIT-BIND: Credential Commitment Binding Uniqueness

### Statement

For all `(m, ax, ay, b, e)` and `(m', ax', ay', b', e')` in `F_r^5`:

```
Poseidon5(m, ax, ay, b, e) = Poseidon5(m', ax', ay', b', e')
  => m = m' /\ ax = ax' /\ ay = ay' /\ b = b' /\ e = e'
```

where `F_r` is the BN254 scalar field with modulus:
```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

### Enforcement

Enforcement is split across two layers:

1. **Domain membership (circuit-level):** The `AgentPolicy` circuit enforces
   that `modelHash`, `opPkAx`, and `opPkAy` are valid elements of `F_r` via
   `InFieldBN254` range checks before they enter the Poseidon hash.
   `permissionBitmask` is constrained to 8 bits via `Num2Bits(8)`, and
   `expiryTimestamp` is constrained to 64 bits via `Num2Bits(64)` — both
   are trivially in `F_r`.

2. **Injectivity within domain (cryptographic assumption):** Given that all
   inputs are proven to be in `F_r`, the uniqueness of the commitment follows
   from the collision resistance of the Poseidon hash function with fixed
   arity 5. Poseidon is a sponge-based algebraic hash with provable security
   bounds against algebraic and statistical attacks.

### Security Reference

The collision-resistance argument for Poseidon is established in:

- Grassi, Khovratovich, Rechberger, Roy, Schofnegger. *Poseidon: A New Hash
  Function for Zero-Knowledge Proof Systems.* USENIX Security 2021, Section 5.

The paper proves that for Poseidon with capacity `c` and rate `r` over `F_p`,
finding a collision requires at least `min(2^{c/2}, p^{1/2})` operations under
the assumption that the S-box permutation (`x^5` for BN254) is
cryptographically strong.

For BN254 with `p ≈ 2^254`, the collision-resistance security level is
`min(2^{c/2}, 2^127)`, which exceeds 100 bits for any reasonable capacity.

### Attack Scenario (Prevented)

**Field-wrap attack:** Without the `InFieldBN254` check, an adversary could
potentially submit a witness with `modelHash' = modelHash + r` (a different
256-bit integer that reduces to the same field element). While the circuit
arithmetic would treat these identically (since `F_r` reduction is implicit),
the external verifier might associate the proof with a different model
identifier than intended. The `Num2Bits(254)` decomposition plus the
`(r - 1 - input)` range check formally prevent any input from exceeding
`r - 1`.

### Constraint Cost

Each `InFieldBN254` instance adds:
- `Num2Bits(254)`: 254 constraints (bit decomposition of input)
- `Num2Bits(254)`: 254 constraints (bit decomposition of `r - 1 - input`)
- 2 reconstruction constraints
- **Total per instance: ~510 constraints**

Three instances (modelHash, opPkAx, opPkAy): **~1530 constraints total.**

This is well within the `2^16 = 65536` constraint budget of `pot16.ptau`.

### Verification

The property is tested via:
1. **Witness-level rejection:** `AgentPolicy.field-binding.test.js` confirms
   that inputs at or above `r` fail witness generation.
2. **Collision-resistance smoke test:** 10,000 random distinct 5-tuples are
   hashed and all commitments are verified to be unique.
3. **Single-field sensitivity:** Modifying any single field in a 5-tuple
   produces a different commitment.
