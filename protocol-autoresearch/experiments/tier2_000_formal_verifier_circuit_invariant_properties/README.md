# Formal Invariant Property Suite for Bolyra Circuits

Machine-checkable invariant properties covering all three Bolyra protocol circuits:
**Identity**, **Credential**, and **Delegation**.

## Properties (17 total)

| Category | Properties | Count |
|----------|-----------|-------|
| Field Overflow | P1–P8: All uint64 signals stay within `[0, 2^64)` | 8 |
| Nullifier Uniqueness | P9–P11: Distinct inputs → distinct nullifiers | 3 |
| Scope Monotonicity | P12–P14: `delegateeScope & ~delegatorScope == 0` | 3 |
| Expiry Narrowing | P15–P17: `delegateeExpiry ≤ delegatorExpiry` | 3 |

## Directory Structure

```
├── specs/invariants/
│   ├── circuit_invariants.cvl    # Certora CVL formal properties
│   └── property_registry.md      # Human-readable property catalogue
├── test/invariants/
│   ├── field_overflow.test.js             # P1, P4, P6, P7, P8
│   ├── nullifier_uniqueness.test.js       # P9, P10, P11
│   ├── delegation_scope_monotonicity.test.js  # P12, P13, P14
│   └── delegation_expiry_narrowing.test.js    # P15, P16, P17
├── scripts/
│   └── run_invariants.sh         # CI runner
└── README.md
```

## Prerequisites

```bash
npm install circom_tester circomlibjs snarkjs fast-check
# circom compiler >= 2.1 must be on PATH
# Certora Prover CLI (optional, for CVL verification)
```

## Usage

### Run all invariant tests

```bash
./scripts/run_invariants.sh
```

### Run in parallel

```bash
./scripts/run_invariants.sh --parallel
```

### Run individual suites

```bash
npx jest test/invariants/field_overflow.test.js
npx jest test/invariants/nullifier_uniqueness.test.js
npx jest test/invariants/delegation_scope_monotonicity.test.js
npx jest test/invariants/delegation_expiry_narrowing.test.js
```

### Certora CVL verification

```bash
certoraRun specs/invariants/circuit_invariants.cvl \
  --verify IdentityVerifier:specs/invariants/circuit_invariants.cvl
```

## Test Design

Each property has **both acceptance and rejection witnesses**:
- **Acceptance**: valid inputs that satisfy the circuit constraints
- **Rejection**: inputs that violate the invariant and must cause constraint failure

### Probabilistic uniqueness tests

Nullifier uniqueness (P9–P11) uses property-based testing via `fast-check` with N=500 random samples.

**Collision probability bound:**
- Poseidon output: 254 bits
- Birthday probability for N=500: `≈ N² / 2^255 ≈ 2^{-237}`
- Required: `≤ 2^{-64}`
- Safety margin: **173 bits**

## CI Integration

Add to `.github/workflows/ci.yml`:

```yaml
invariant-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 20
    - run: npm ci
    - run: chmod +x scripts/run_invariants.sh && ./scripts/run_invariants.sh
```

The script exits non-zero on any failure, making it suitable as a CI gate.

## Experiment Context

This artifact is part of the Bolyra protocol autoresearch loop:
- **Candidate ID**: `formal_verifier_circuit_invariant_properties`
- **Persona**: `formal_verifier`
- **Dimension**: correctness
- **Score**: 73/100 (consider)
- **Verdict**: consider
