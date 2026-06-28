# Experiment: MerkleDepthGuard Underconstraint Fix

**ID:** `formal_verifier_merkle_depth_guard_underconstraint`
**Priority:** Critical
**Dimension:** Correctness

## Problem

All three Bolyra circuits (HumanUniqueness, AgentPolicy, Delegation) pass
`merkleProofLength` to `BinaryMerkleRoot` as the depth parameter, but no
range check enforces `1 <= merkleProofLength <= MAX_DEPTH`.

If `merkleProofLength = 0`, `BinaryMerkleRoot` returns the leaf itself as the
root. This means any arbitrary commitment trivially "proves" membership
against a root equal to itself -- a complete bypass of tree membership.

## Solution

A reusable `MerkleDepthGuard(MAX_DEPTH)` template that enforces the range
using circomlib primitives:

- `Num2Bits(NUM_BITS)` -- bit-width range-limit
- `GreaterEqThan(NUM_BITS)` -- asserts `depth >= 1`
- `LessEqThan(NUM_BITS)` -- asserts `depth <= MAX_DEPTH`

Instantiated in all three circuits before `BinaryMerkleRoot`.

## Files

| File | Description |
|---|---|
| `circuits/src/lib/MerkleDepthGuard.circom` | Reusable depth guard template |
| `circuits/src/HumanUniqueness.circom` | Modified -- adds MerkleDepthGuard |
| `circuits/src/AgentPolicy.circom` | Modified -- adds MerkleDepthGuard |
| `circuits/src/Delegation.circom` | Modified -- adds MerkleDepthGuard |
| `circuits/test/fixtures/MerkleDepthGuardTest.circom` | Test wrapper (MAX_DEPTH=20) |
| `circuits/test/fixtures/MerkleDepthGuardTest16.circom` | Test wrapper (MAX_DEPTH=16) |
| `circuits/test/merkle_depth_guard.test.js` | Attack vector + boundary tests |
| `circuits/FORMAL-PROPERTIES.md` | MerkleDepthBound invariant documentation |

## Usage

```bash
# Run the depth guard tests
npx mocha circuits/test/merkle_depth_guard.test.js --timeout 60000

# Run all circuit tests (fast mode)
npm run test:circuits:fast
```

## Test Coverage

| Test Case | Expected | Rationale |
|---|---|---|
| depth=0 | REJECT | Leaf-as-root bypass attack |
| depth=1 | ACCEPT | Minimum valid (single-sibling proof) |
| depth=10 | ACCEPT | Mid-range sanity |
| depth=MAX_DEPTH | ACCEPT | Maximum valid depth |
| depth=MAX_DEPTH+1 | REJECT | Upper bound enforcement |
| depth=255 | REJECT | Large out-of-range value |

## Constraint Cost

~270 constraints per circuit (negligible relative to EdDSA/Poseidon costs).

## Dependencies

- circomlib (Num2Bits, GreaterEqThan, LessEqThan)
- circom_tester (witness-only fast tests)
- MAX_DEPTH = 20 (Semaphore v4 compatibility)
