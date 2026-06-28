# Experiment: Formal Binding Harness for Delegation Scope Commitment Chain

**ID:** `formal_verifier_scope_commitment_binding`
**Persona:** formal_verifier
**Dimension:** correctness
**Priority:** high

## Summary

Proves that the delegation scope commitment chain is unforgeable across
delegation hops. The binding property guarantees that a delegatee cannot
claim broader permissions than the delegator granted, because:

1. The circuit enforces `delegateeScope ⊆ delegatorScope` via bitwise AND-mask.
2. Both scopes are committed via `Poseidon(scope, credCommitment)`, binding
   the scope to the credential.
3. The chain links hops by requiring `previousScopeCommitment` to match the
   recomputed Poseidon hash of the delegator's scope.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `circuits/src/DelegationChainBinding.circom` | Circuit | Augmented delegation circuit exposing scope commitments as public signals |
| `circuits/test/delegationChainBinding.adversarial.js` | Test | 4 adversarial attack vectors that must fail |
| `circuits/test/delegationChainBinding.soundness.js` | Test | Exhaustive 2^8 × 2^8 soundness enumeration |
| `circuits/FORMAL-PROPERTIES.md` | Spec | Binding(D) property statement (appended) |
| `docs/delegation-chain-security-proof.md` | Docs | Full security argument with reduction sketch |

## Usage

### Run adversarial tests (fast — witness only)

```bash
npm run test:circuits:fast -- --grep "adversarial"
```

### Run exhaustive soundness test (fast — witness only)

```bash
npm run test:circuits:fast -- --grep "soundness"
```

**Note:** The soundness test iterates 65 536 pairs. Expect ~5-10 minutes
depending on hardware.

### Run with full proofs (slow)

```bash
FULL_PROOF=1 npm run test:circuits:slow -- --grep "DelegationChainBinding"
```

### Compile the circuit

```bash
npx circom circuits/src/DelegationChainBinding.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -o circuits/build
```

## Dependencies

- `circom >=2.1.0`
- `circomlib` (Poseidon, Num2Bits)
- `circomlibjs` (off-circuit Poseidon for test reference hashing)
- `snarkjs >=0.7.6`
- `circom_tester`

## Security Argument

See `docs/delegation-chain-security-proof.md` for the full binding game
definition, reduction to Poseidon collision resistance, and wiring analysis.

## Estimated Constraints

~3 200 (two Poseidon-2 instances + Num2Bits + subset checks + implication checks).
