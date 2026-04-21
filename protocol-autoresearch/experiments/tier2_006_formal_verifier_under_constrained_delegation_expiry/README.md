# Experiment: Prove Delegation Expiry Narrowing is Sound

**ID**: `formal_verifier_under_constrained_delegation_expiry`  
**Persona**: Formal Verifier  
**Dimension**: Correctness  
**Priority**: Critical

## Summary

This experiment formally analyzes the delegation expiry narrowing constraints
in the Bolyra identity protocol's `DelegationWithExpiry` circuit. It proves
that the `Num2Bits(64)` range checks close the field-element wraparound
attack vector, ensuring that comparisons operate on bounded integers.

## Artifacts

| File | Description |
|------|-------------|
| `specs/delegation_expiry_soundness.spec` | Certora-style property spec with 4 invariants |
| `circuits/DelegationExpiryCheck.circom` | Isolated circuit fragment for expiry checks |
| `tests/test_delegation_expiry_boundary.py` | Boundary witness test harness (18 cases) |
| `docs/delegation_expiry_formal_analysis.md` | Soundness argument and attack vector analysis |

## Invariants

1. **I1**: `delegateeExpiry <= delegatorExpiry` for all valid witnesses (in Z, not F_p)
2. **I2**: `delegateeExpiry > currentTimestamp` for all valid witnesses (expired credentials rejected)
3. **I3**: All comparator inputs are range-checked to `[0, 2^64)` via `Num2Bits(64)`
4. **I4**: No witness with any expiry `>= 2^64` can satisfy the range-check sub-circuit

## Usage

### Prerequisites

```bash
npm install -g circom snarkjs
pip install pytest
```

### Compile the circuit

```bash
cd circuits
circom DelegationExpiryCheck.circom --r1cs --wasm --sym -o build/
```

### Run boundary tests

```bash
# With pytest
pytest tests/test_delegation_expiry_boundary.py -v

# Standalone
python tests/test_delegation_expiry_boundary.py
```

### Verify constraint count

```bash
snarkjs r1cs info circuits/build/DelegationExpiryCheck.r1cs
# Expected: ~329 constraints
```

## Key Finding: Wraparound Attack Closed

The existing `DelegationWithExpiry` circuit (v3.0.0) correctly applies
`Num2Bits(64)` to all three timestamp signals BEFORE they reach the
`LessThan`/`LessEqThan` comparators. This makes the field-element
wraparound attack impossible:

- `Num2Bits(64)` constrains inputs to `[0, 2^64)`
- Since `2^64 << p` (BN254), there is no field aliasing
- Comparators receive provably bounded integers
- No witness outside `[0, 2^64)` can satisfy the constraints

## Estimated Constraints

~329 total (3x Num2Bits(64) + LessEqThan(64) + LessThan(64) + 2 assertions)
