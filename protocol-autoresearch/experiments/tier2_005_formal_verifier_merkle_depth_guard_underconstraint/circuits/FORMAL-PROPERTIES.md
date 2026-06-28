<!-- This file contains ONLY the new property addition. In the full document,
     this section is appended to the existing FORMAL-PROPERTIES.md. -->

## Property: MerkleDepthBound

**Added by:** formal_verifier_merkle_depth_guard_underconstraint experiment
**Circuits affected:** HumanUniqueness, AgentPolicy, Delegation

### Invariant

For all circuits that use `BinaryMerkleRoot(MAX_DEPTH)`, the `merkleProofLength`
(depth) input satisfies:

```
1 <= merkleProofLength <= MAX_DEPTH
```

`depth = 0` is **never** a valid witness.

### Attack Vector Closed

Without the depth guard, an attacker can set `merkleProofLength = 0`. When
`BinaryMerkleRoot` receives `depth = 0`, it returns the leaf itself as the
computed root (no hashing rounds execute). This means **any** commitment
`C` trivially proves membership against a Merkle root equal to `C`:

```
BinaryMerkleRoot(leaf=C, depth=0, siblings=[...]) == C
```

The attacker constructs a proof where the public Merkle root equals their
arbitrary commitment, completely bypassing the tree membership check.

### Constraint Implementation

`MerkleDepthGuard(MAX_DEPTH)` uses three circomlib primitives:

| Primitive | Purpose |
|---|---|
| `Num2Bits(NUM_BITS)` | Range-limits `depth` to `ceil(log2(MAX_DEPTH+1))` bits, preventing field-element wrapping |
| `GreaterEqThan(NUM_BITS)` | Asserts `depth >= 1` (lower bound) |
| `LessEqThan(NUM_BITS)` | Asserts `depth <= MAX_DEPTH` (upper bound) |

Both comparator outputs are constrained to `=== 1`, so out-of-range values
abort witness generation.

### Estimated Constraint Cost

~270 constraints per circuit (Num2Bits: ~5, GreaterEqThan: ~130, LessEqThan: ~130).

### Formal Statement

```
For all valid witnesses W of {HumanUniqueness, AgentPolicy, Delegation}:
  W.merkleProofLength in {1, 2, ..., MAX_DEPTH}

Contrapositively:
  No witness with merkleProofLength = 0 or merkleProofLength > MAX_DEPTH
  satisfies the circuit constraints.
```

### Verification

- **Unit test:** `merkle_depth_guard.test.js` — depth=0 rejects (attack vector)
- **Unit test:** `merkle_depth_guard.test.js` — depth=MAX_DEPTH+1 rejects (upper bound)
- **Unit test:** `merkle_depth_guard.test.js` — depth=1 succeeds (single-sibling proof)
- **Unit test:** `merkle_depth_guard.test.js` — depth=MAX_DEPTH succeeds (full tree)
- **Integration:** existing circuit test suites for HumanUniqueness, AgentPolicy,
  and Delegation use valid `merkleProofLength` values and continue to pass.

### Dependencies

- circomlib `comparators.circom` (GreaterEqThan, LessEqThan)
- circomlib `bitify.circom` (Num2Bits)
- MAX_DEPTH = 20 for HumanUniqueness (Semaphore v4 ceremony compatibility)
- MAX_DEPTH = 20 for AgentPolicy and Delegation (current project default)
