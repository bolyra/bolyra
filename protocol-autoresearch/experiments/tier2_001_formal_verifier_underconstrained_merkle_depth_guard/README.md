# Experiment: Under-Constrained Merkle Depth Range Check (P-RANGE-DEPTH)

**ID:** `formal_verifier_underconstrained_merkle_depth_guard`
**Persona:** Formal Verifier
**Dimension:** Correctness
**Priority:** Critical

## Problem

All four Bolyra circuits that use `BinaryMerkleRoot` accept a private
`merkleProofLength` input that controls how many sibling hashes are
processed. Without constraining this value:

- **merkleProofLength = 0:** the leaf is treated as the root, bypassing
  tree membership entirely.
- **merkleProofLength > MAX_DEPTH:** uninitialized sibling array slots
  (unconstrained in the witness) are read, enabling arbitrary root forgery.
- **Field overflow:** a large field element could bypass naive comparisons.

## Solution

Add three circomlib components per circuit to enforce
`1 <= merkleProofLength <= MAX_DEPTH`:

```circom
// Bit-width bound: prevents field-element overflow
component depthBits = Num2Bits(5);
depthBits.in <== merkleProofLength;

// Upper bound: merkleProofLength <= MAX_DEPTH
component depthUpper = LessThan(5);
depthUpper.in[0] <== merkleProofLength;
depthUpper.in[1] <== MAX_DEPTH + 1;
depthUpper.out === 1;

// Lower bound: merkleProofLength >= 1
component depthLower = LessThan(5);
depthLower.in[0] <== 0;
depthLower.in[1] <== merkleProofLength;
depthLower.out === 1;
```

Constraints are placed **before** the `BinaryMerkleRoot` instantiation to
ensure the prover cannot bypass them via witness manipulation.

## Artifacts

| Type | Path | Description |
|---|---|---|
| Circuit | `circuits/src/HumanUniqueness.circom` | Range check at TREE_DEPTH=20 |
| Circuit | `circuits/src/AgentPolicy.circom` | Range check at TREE_DEPTH=20 |
| Circuit | `circuits/src/Delegation.circom` | Range check at TREE_DEPTH=20 |
| Circuit | `circuits/src/ModelInstanceBinding.circom` | Range check at MAX_DEPTH=16 (replaces `RangeCheckDepth` library) |
| Test | `circuits/test/merkleDepthGuard.test.js` | 11 witness-generation tests |
| Fixture | `circuits/test/fixtures/DepthGuardTest.circom` | Minimal wrapper (depth 20) |
| Fixture | `circuits/test/fixtures/DepthGuardTest16.circom` | Minimal wrapper (depth 16) |
| Docs | `circuits/FORMAL-PROPERTIES.md` | P-RANGE-DEPTH invariant |

## Usage

### Compile circuits

```bash
npm run compile:circuits
```

Expect R1CS constraint counts to increase by ~18 per circuit compared to
the version without depth guards.

### Run fast tests (witness-only)

```bash
npm run test:circuits:fast
```

### Run full proof tests

```bash
FULL_PROOF=1 npm run test:circuits:slow
```

### Regenerate verifier contracts

If `.zkey` artifacts change due to the added constraints:

```bash
cd contracts && npm run compile:contracts
npm run test:contracts
```

## Test Coverage

### Suite 1: TREE_DEPTH = 20 (HumanUniqueness / AgentPolicy / Delegation)

| # | Case | Expected |
|---|---|---|
| 1 | `merkleProofLength = 20` | Witness succeeds |
| 2 | `merkleProofLength = 1` | Witness succeeds |
| 3 | `merkleProofLength = 10` | Witness succeeds |
| 4 | `merkleProofLength = 0` | Constraint error |
| 5 | `merkleProofLength = 21` | Constraint error |
| 6 | `merkleProofLength = 31` | Constraint error |
| 7 | `merkleProofLength = 32` | Constraint error |

### Suite 2: MAX_DEPTH = 16 (ModelInstanceBinding)

| # | Case | Expected |
|---|---|---|
| 8 | `merkleProofLength = 16` | Witness succeeds |
| 9 | `merkleProofLength = 1` | Witness succeeds |
| 10 | `merkleProofLength = 0` | Constraint error |
| 11 | `merkleProofLength = 17` | Constraint error |

## Design Decisions

1. **Range check over exact equality** -- This experiment explores the
   range-check approach (`1 <= depth <= MAX_DEPTH`) as an alternative to
   the exact-equality approach (`depth === TREE_DEPTH`). Range checking
   supports variable-depth trees (e.g., ModelInstanceBinding) where the
   tree may not always be at full depth.

2. **Inline constraints over library** -- Previous iterations used a
   separate `MerkleDepthCheck.circom` / `RangeCheckDepth` template. This
   experiment inlines the three components directly in each circuit,
   reducing include-path dependencies and making the constraint structure
   immediately auditable.

3. **5-bit width** -- `ceil(log2(20+1)) = 5` bits is sufficient for both
   TREE_DEPTH=20 and MAX_DEPTH=16. Using a uniform width simplifies
   cross-circuit auditing.

4. **Num2Bits as overflow guard** -- The `Num2Bits(5)` decomposition is
   not strictly redundant with `LessThan(5)` (which internally uses
   `Num2Bits(6)`). The explicit decomposition makes the bit-width bound
   visible to auditors and provides defense-in-depth against future
   `LessThan` implementation changes.

## Comparison with P-DEPTH-01 (Exact Equality)

| Property | Range Check (this) | Exact Equality (P-DEPTH-01) |
|---|---|---|
| Constraint | `1 <= depth <= MAX_DEPTH` | `depth === TREE_DEPTH` |
| Cost | ~18 constraints/circuit | 1 constraint/circuit |
| Subtree attacks | Allows depths 1..MAX_DEPTH | Closes all non-TREE_DEPTH |
| Variable depth | Supported | Not supported |
| Use case | ModelInstanceBinding | HumanUniqueness, AgentPolicy, Delegation |

For fixed-depth trees, exact equality (P-DEPTH-01) is strictly stronger.
For variable-depth registries, this range check is the correct approach.
