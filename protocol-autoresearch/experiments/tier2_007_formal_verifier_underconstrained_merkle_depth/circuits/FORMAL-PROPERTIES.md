# Formal Properties

This document catalogues the formally specified invariants enforced by Bolyra's
circuit constraints. Each property has a unique identifier (P-*), a formal
statement, enforcement location, and description of the attack class it prevents.

---

## P-DEPTH-01: Merkle Proof Depth Exact Equality

**Invariant:** For all accepted witnesses in every Bolyra circuit that uses
`BinaryMerkleRoot`, the private input `merkleProofLength` equals the
compile-time `TREE_DEPTH` constant exactly.

**Formal statement:**

```
forall W in SatisfyingWitnesses(C):
    W.merkleProofLength == TREE_DEPTH
```

where `C in {HumanUniqueness(20), AgentPolicy(20), Delegation(20)}`.

**Enforcement locations:**

| Circuit | File | Lines | Constraint |
|---|---|---|---|
| HumanUniqueness | `circuits/src/HumanUniqueness.circom` | 30-31 | `depthCheck <== merkleProofLength - TREE_DEPTH; depthCheck === 0;` |
| AgentPolicy | `circuits/src/AgentPolicy.circom` | 37-38 | `depthCheck <== merkleProofLength - TREE_DEPTH; depthCheck === 0;` |
| Delegation | `circuits/src/Delegation.circom` | 36-37 | `depthCheck <== merkleProofLength - TREE_DEPTH; depthCheck === 0;` |

**Constraint cost:** Exactly 1 R1CS constraint per circuit (3 total across all
circuits). The subtraction `merkleProofLength - TREE_DEPTH` is a linear
combination computed by the compiler; only the equality assertion
`depthCheck === 0` produces an R1CS row.

**Proof sketch:** In the R1CS system, the constraint
`depthCheck === 0` is equivalent to asserting that the linear combination
`merkleProofLength - TREE_DEPTH = 0` over the scalar field F_p. Since
`TREE_DEPTH` is a compile-time constant baked into the R1CS, no witness
assignment where `merkleProofLength != TREE_DEPTH` can satisfy this constraint.
The field is prime (BN254: p ~ 2^254), so there is no wraparound for any
value in [0, p-1] that differs from `TREE_DEPTH`.

### Attack Vector: Subtree-Root Replay

**Threat model:** An attacker who controls the private witness inputs
(`merkleProofLength`, `merkleProofSiblings`, `merkleProofIndices`) attempts to
forge a valid proof without being enrolled in the full-depth Merkle tree.

**Attack mechanism:** Without the depth constraint, an attacker supplies
`merkleProofLength = d` where `d < TREE_DEPTH`. The `BinaryMerkleRoot`
template only hashes `d` sibling nodes, producing an intermediate node at
depth `d` in the tree rather than the true root at depth `TREE_DEPTH`. If
the verifier's root history buffer contains this intermediate node (e.g.,
because it was a valid subtree root at some point, or by collision), the
proof verifies despite the prover not being enrolled at a leaf.

**Specific scenarios closed:**

1. **depth=0:** The leaf value itself is treated as the Merkle root. Any
   prover who knows a valid root value can forge membership by setting
   `identityCommitment = root`.
2. **depth < TREE_DEPTH:** The prover targets an intermediate Merkle node.
   In trees with predictable structure (e.g., sparse Merkle trees with
   default zero-value subtrees), intermediate nodes may be computable.
3. **depth > TREE_DEPTH:** The prover reads uninitialized sibling array
   slots beyond index `TREE_DEPTH - 1`. These slots are unconstrained
   in the witness and can be set to arbitrary values.

**Why constant-equality is sufficient:** The deployed tree depth is fixed at
compile time (20 for all current circuits, matching the Semaphore v4
ceremony depth). There is no legitimate use case for proving membership at
a different depth. A range check `1 <= depth <= TREE_DEPTH` (as in the
earlier P-RANGE-DEPTH property) is strictly weaker: it still permits
subtree-root attacks at depths 1 through 19. The exact-equality constraint
eliminates the entire attack surface with minimal constraint overhead.

### Relationship to Prior Work

This property supersedes the earlier range-bounded check
(`RangeCheckDepth` template, ~19 constraints per circuit). The exact-equality
constraint is both stronger (eliminates all depths != TREE_DEPTH, not just
0 and > MAX_DEPTH) and cheaper (1 constraint vs ~19). The
`RangeCheckDepth` template and its `MerkleDepthCheck.circom` library may
be removed once this constraint is deployed.

---

## Formal Spec

See `circuits/formal/MerkleDepthExactEquality.spec` for the Certora CVL
pseudocode specification of P-DEPTH-01, including:

- **Invariant `depthExactlyTreeDepth`:** For any satisfying witness,
  `merkleProofLength == TREE_DEPTH`.
- **Rule `depthOffByOneUnsatisfiable`:** No witness with
  `merkleProofLength == TREE_DEPTH - 1` can satisfy the circuit.
- **Rule `depthZeroUnsatisfiable`:** No witness with
  `merkleProofLength == 0` can satisfy the circuit.
- **Rule `depthOverflowUnsatisfiable`:** No witness with
  `merkleProofLength > TREE_DEPTH` can satisfy the circuit.
- **Rule `exactDepthSatisfiable`:** `merkleProofLength == TREE_DEPTH`
  admits a satisfying witness (non-vacuity check).
