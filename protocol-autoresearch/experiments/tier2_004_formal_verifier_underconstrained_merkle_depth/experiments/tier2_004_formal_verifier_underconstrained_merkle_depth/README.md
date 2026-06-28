# Experiment: Prove merkleProofLength is bounded and non-zero across all circuits

**ID:** `formal_verifier_underconstrained_merkle_depth`  
**Persona:** Formal Verifier  
**Dimension:** Correctness  
**Priority:** Critical  
**Status:** Implemented

## Problem

`BinaryMerkleRoot` accepts `merkleProofLength` as a private input with no
range check enforcing `1 <= depth <= MAX_DEPTH`. A malicious prover can:

1. **Supply depth=0** — the leaf becomes the root, bypassing tree membership
   entirely. Any leaf value that equals the public root passes.
2. **Supply depth > MAX_DEPTH** — the circuit reads uninitialized sibling
   slots beyond the array bounds, whose values are unconstrained and can
   be set by the prover to satisfy the Merkle path.

## Solution

A reusable `RangeCheckDepth(MAX_DEPTH)` template
(`circuits/src/lib/MerkleDepthCheck.circom`) that constrains:

```
1 <= merkleProofLength <= MAX_DEPTH
```

using `Num2Bits` + two `LessThan` comparators from circomlib.

## Affected Circuits

| Circuit | MAX_DEPTH | File |
|---|---|---|
| HumanUniqueness | 20 | `circuits/src/HumanUniqueness.circom` |
| AgentPolicy | 20 | `circuits/src/AgentPolicy.circom` |
| Delegation | 20 | `circuits/src/Delegation.circom` |
| ModelInstanceBinding | 16 | `circuits/src/ModelInstanceBinding.circom` |

## Artifacts

| Type | Path |
|---|---|
| Library circuit | `circuits/src/lib/MerkleDepthCheck.circom` |
| Formal spec | `circuits/formal/MerkleDepthBounded.spec` |
| Tests | `circuits/test/merkleDepthBound.test.js` |
| Test fixtures | `circuits/test/fixtures/RangeCheckDepthTest.circom` |
| Test fixtures | `circuits/test/fixtures/RangeCheckDepthTest16.circom` |
| Docs | `circuits/FORMAL-PROPERTIES.md` (new section) |

## Usage

### Run fast tests (witness-only)

```bash
npm run test:circuits:fast
```

### Run full proof tests

```bash
FULL_PROOF=1 npm run test:circuits:slow
```

### Constraint overhead

Approximately 19 constraints per circuit instantiation (~76 total across
all four circuits). Well within the `pot16.ptau` (2^16) budget.

## Formal Specification

The Certora-style invariant spec (`circuits/formal/MerkleDepthBounded.spec`)
declares:

- **Invariant `depthBounded`:** For any satisfying witness,
  `1 <= merkleProofLength <= MAX_DEPTH`.
- **Rule `depthZeroUnsatisfiable`:** No witness with `merkleProofLength=0`
  can satisfy the circuit constraints.
- **Rule `depthOverflowUnsatisfiable`:** No witness with
  `merkleProofLength > MAX_DEPTH` can satisfy the circuit constraints.
- **Rule `boundaryValuesSatisfiable`:** Depths 1 and MAX_DEPTH admit
  satisfying witnesses (ensures the check is not over-constrained).

## Design Decisions

1. **Single `valid` output** rather than inline assertions — allows the
   caller to assert `valid === 1`, making the constraint source clear in
   error messages.
2. **Num2Bits before LessThan** — prevents negative-field-element attacks
   where a prover supplies a value that wraps around the prime field to
   appear valid to the comparator.
3. **Template parameter `MAX_DEPTH`** — each circuit specifies its own
   maximum, avoiding a one-size-fits-all constant.
4. **ModelInstanceBinding uses MAX_DEPTH=16** — a shallower tree for the
   model registry, reflecting the expected smaller population.
