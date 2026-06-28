# Experiment: Constrain merkleProofLength === TREE_DEPTH (P-DEPTH-01)

**ID:** `formal_verifier_underconstrained_merkle_depth`
**Persona:** Formal Verifier
**Dimension:** Correctness
**Priority:** Critical

## Problem

The `merkleProofLength` private input in all three Bolyra circuits
(HumanUniqueness, AgentPolicy, Delegation) controls how many sibling hashes
`BinaryMerkleRoot` actually processes. Without constraining this value to
exactly the deployed tree depth, an attacker can supply a shorter proof path
targeting an intermediate Merkle node (subtree-root replay attack).

A prior experiment added a range check (`1 <= depth <= MAX_DEPTH`), but this
is insufficient: it still allows depths 1 through 19, any of which could
match an intermediate node in the tree.

## Solution

Add a single R1CS equality constraint in each circuit:

```circom
signal depthCheck;
depthCheck <== merkleProofLength - TREE_DEPTH;
depthCheck === 0;
```

This adds exactly 1 constraint per circuit (3 total) and is strictly stronger
than the prior ~19-constraint range check per circuit.

## Artifacts

| Type | Path | Description |
|---|---|---|
| Circuit | `circuits/src/HumanUniqueness.circom` | Depth pinned to TREE_DEPTH=20 |
| Circuit | `circuits/src/AgentPolicy.circom` | Same constraint |
| Circuit | `circuits/src/Delegation.circom` | Same constraint |
| Formal spec | `circuits/formal/MerkleDepthExactEquality.spec` | CVL pseudocode |
| Docs | `circuits/FORMAL-PROPERTIES.md` | P-DEPTH-01 invariant documentation |
| Test | `circuits/test/merkle_depth_invariant.test.js` | 8 fast + 2 slow cases |
| Test fixture | `circuits/test/fixtures/DepthExactTest.circom` | Minimal wrapper |

## Usage

### Compile circuits

```bash
npm run compile:circuits
```

### Run fast tests (witness-only)

```bash
npm run test:circuits:fast
```

### Run full proof tests

```bash
FULL_PROOF=1 npm run test:circuits:slow
```

### Verify constraint count

After compilation, each circuit's `.r1cs` should show exactly 1 additional
constraint compared to the version without the depth check.

### Regenerate verifier contracts

If the `.zkey` artifacts change due to the added constraint:

```bash
cd contracts && npm run compile:contracts
npm run test:contracts
```

## Test Coverage

| # | Case | Type | Expected |
|---|---|---|---|
| 1 | `merkleProofLength = 20` (full depth) | Positive | Witness succeeds |
| 2 | `merkleProofLength = 19` (off-by-one) | Negative | Constraint error |
| 3 | `merkleProofLength = 0` (leaf-as-root) | Negative | Constraint error |
| 4 | `merkleProofLength = 1` (near-root) | Negative | Constraint error |
| 5 | `merkleProofLength = 10` (mid-subtree) | Negative | Constraint error |
| 6 | `merkleProofLength = 21` (over-depth) | Negative | Constraint error |
| 7 | `merkleProofLength = 255` (large value) | Negative | Constraint error |
| 8 | `merkleProofLength = 5` (subtree replay) | Negative | Constraint error |

Full-proof tests (gated on `FULL_PROOF=1`):
- Valid proof at depth 20 generates and verifies
- Proof attempt at depth 19 fails witness generation

## Design Decisions

1. **Exact equality over range check** -- The deployed tree depth is a
   compile-time constant. No legitimate prover ever needs a different depth.
   Range checks leave a residual attack surface; equality eliminates it.

2. **Subtraction + zero-assert pattern** -- `depthCheck <== merkleProofLength - TREE_DEPTH; depthCheck === 0;` compiles to exactly 1 R1CS constraint.
   Using `===` directly on a difference from a template parameter is the
   cheapest possible enforcement.

3. **Removed RangeCheckDepth dependency** -- The prior `MerkleDepthCheck.circom`
   library and its `include` are no longer needed. The inline constraint is
   simpler, cheaper, and stronger.

4. **Template parameter renamed MAX_DEPTH -> TREE_DEPTH** -- Clarifies that
   this is the exact deployed depth, not a maximum. The parameter value (20)
   is unchanged.
