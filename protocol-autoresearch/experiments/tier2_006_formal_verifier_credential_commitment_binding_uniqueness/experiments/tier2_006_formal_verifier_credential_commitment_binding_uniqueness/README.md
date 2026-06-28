# Experiment: Credential Commitment Binding Uniqueness

**ID:** `formal_verifier_credential_commitment_binding_uniqueness`
**Persona:** formal_verifier
**Dimension:** correctness
**Priority:** high

## Summary

Proves that `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiryTimestamp)` uniquely binds all five fields. The fix adds `InFieldBN254` range checks on `modelHash`, `opPkAx`, and `opPkAy` to enforce BN254 scalar field membership before hashing, preventing field-wrap attacks where `v' = v + r` would alias to the same commitment.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuit.circom` | Circuit | Modified AgentPolicy with InFieldBN254 checks on 3 signals |
| `lib/FieldCheck.circom` | Circuit | Reusable `InFieldBN254` template (Num2Bits(254) + strict < r check) |
| `test_field_binding.js` | Test | Mocha property tests: happy path, rejection, 10k collision smoke test |
| `test_experiment.py` | Test | Python specification-level tests (no circom dependency) |
| `formal_properties_addendum.md` | Spec | P-COMMIT-BIND formal property for FORMAL-PROPERTIES.md |

## Usage

### Run Python spec tests

```bash
cd experiments/tier2_006_formal_verifier_credential_commitment_binding_uniqueness
pytest test_experiment.py -v
```

### Run Mocha circuit tests (witness only)

```bash
# From project root
npm run test:circuits:fast -- --grep "field-binding"
```

### Run with full proofs (slow)

```bash
FULL_PROOF=1 npm run test:circuits:slow -- --grep "field-binding"
```

### Compile the modified circuit

```bash
npx circom circuits/src/AgentPolicy.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -o circuits/build
```

## How InFieldBN254 Works

The template enforces `input in [0, r-1]` using two `Num2Bits(254)` checks:

1. **`Num2Bits(254)` on input:** Proves input < 2^254
2. **`Num2Bits(254)` on `(r - 1 - input)`:** Proves `r - 1 - input >= 0`, i.e., `input <= r - 1`

If `input >= r`, the subtraction `(r - 1) - input` underflows in `F_r` to a value >= 2^254, which fails the bit decomposition constraint.

## Constraint Cost

| Component | Constraints |
|-----------|------------|
| InFieldBN254 (per instance) | ~510 (2 x Num2Bits(254)) |
| 3 instances (modelHash, opPkAx, opPkAy) | ~1530 |
| Existing AgentPolicy baseline | ~4000 |
| **Total with checks** | **~5530** |

Well within `pot16.ptau` budget (2^16 = 65,536 constraints).

## Dependencies

- `circomlib` — Num2Bits, Poseidon, LessThan, comparators (already in project)
- `circomlibjs` — off-circuit Poseidon for test reference hashing
- `circom_tester` — witness generation testing
- `chai` — assertion library for Mocha tests
- `pot16.ptau` — existing powers of tau (no new ceremony needed)

## Formal Property

See `formal_properties_addendum.md` for the full P-COMMIT-BIND property statement, security argument referencing the Poseidon paper (Section 5), and attack scenario description.

## Promotion Checklist

When promoting to mainline `circuits/`:

- [ ] Copy `lib/FieldCheck.circom` to `circuits/src/lib/FieldCheck.circom`
- [ ] Apply circuit changes from `circuit.circom` to `circuits/src/AgentPolicy.circom`
- [ ] Copy test to `circuits/test/AgentPolicy.field-binding.test.js`
- [ ] Append P-COMMIT-BIND from `formal_properties_addendum.md` to `circuits/FORMAL-PROPERTIES.md`
- [ ] Run `npm run compile:circuits` and verify R1CS constraint count delta
- [ ] Run `npm run test:circuits:fast` — all tests pass
- [ ] Run `npm run test:circuits:slow` — full proof round-trip passes
- [ ] Regenerate Solidity verifier if `.zkey` changes
- [ ] Commit with DCO: `git commit -s -m "fix(circuits): enforce BN254 field membership for modelHash and opPk inputs"`
