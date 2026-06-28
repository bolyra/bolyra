# Formal Properties

This document catalogues the formally specified invariants enforced by Bolyra's
circuit constraints. Each property has a unique identifier (P-*), a formal
statement, enforcement location, and description of the attack class it prevents.

---

## P-RANGE-DEPTH: Merkle Proof Depth Range Check

**Invariant:** For all accepted witnesses in every Bolyra circuit that uses
`BinaryMerkleRoot`, the private input `merkleProofLength` is range-checked
to `[1, MAX_DEPTH]` via `Num2Bits` + `LessThan` constraints prior to
`BinaryMerkleRoot` instantiation.

**Formal statement:**

```
forall W in SatisfyingWitnesses(C):
    1 <= W.merkleProofLength <= MAX_DEPTH
```

where `C in {HumanUniqueness(20), AgentPolicy(20), Delegation(20), ModelInstanceBinding(16)}`.

**Enforcement mechanism (per circuit):**

| Component | Purpose | Constraints |
|---|---|---|
| `Num2Bits(5)` | Decomposes `merkleProofLength` into 5 bits, preventing field-element overflow beyond [0, 31] | ~6 |
| `LessThan(5)` upper | Asserts `merkleProofLength < MAX_DEPTH + 1`, i.e. `merkleProofLength <= MAX_DEPTH` | ~6 |
| `LessThan(5)` lower | Asserts `0 < merkleProofLength`, i.e. `merkleProofLength >= 1` | ~6 |

Total: ~18 R1CS constraints per circuit, ~72 across all four circuits.

**Enforcement locations:**

| Circuit | File | MAX_DEPTH | Constraint block |
|---|---|---|---|
| HumanUniqueness | `circuits/src/HumanUniqueness.circom` | 20 | Section 1 (lines 28-44) |
| AgentPolicy | `circuits/src/AgentPolicy.circom` | 20 | Section 1 (lines 37-53) |
| Delegation | `circuits/src/Delegation.circom` | 20 | Section 1 (lines 34-50) |
| ModelInstanceBinding | `circuits/src/ModelInstanceBinding.circom` | 16 | Section 1 (lines 28-44) |

**Proof sketch:** The `Num2Bits(5)` decomposition constrains
`merkleProofLength` to [0, 2^5 - 1] = [0, 31]. The upper `LessThan(5)`
narrows this to [0, MAX_DEPTH]. The lower `LessThan(5)` further narrows
to [1, MAX_DEPTH]. Combined, the prover cannot assign any value outside
this range without violating at least one constraint.

### Attack Vector: Subtree-Root Replay

**Threat model:** An attacker who controls the private witness inputs
(`merkleProofLength`, `merkleProofSiblings`, `merkleProofIndices`) attempts to
forge a valid proof without being enrolled in the full-depth Merkle tree.

**Attack mechanism:** Without the depth constraint, an attacker supplies
`merkleProofLength = d` where `d` is 0 or exceeds `MAX_DEPTH`. The
`BinaryMerkleRoot` template only hashes `d` sibling nodes, producing either
the leaf itself (d=0) or reading uninitialized array slots (d > MAX_DEPTH).

**Specific scenarios closed:**

1. **depth=0:** The leaf value itself is treated as the Merkle root. Any
   prover who knows a valid root value can forge membership by setting
   `identityCommitment = root`.
2. **depth > MAX_DEPTH:** The prover reads uninitialized sibling array
   slots beyond index `MAX_DEPTH - 1`. These slots are unconstrained
   in the witness and can be set to arbitrary values.
3. **Field overflow:** Without `Num2Bits`, a malicious prover could
   supply a large field element (e.g., p-1) as `merkleProofLength`,
   bypassing naive integer comparisons.

### Relationship to P-DEPTH-01 (Exact Equality)

The range-check approach (`1 <= depth <= MAX_DEPTH`) is strictly weaker than
the exact-equality approach (`depth === TREE_DEPTH`) documented in P-DEPTH-01.
Range checking permits depths 1 through MAX_DEPTH, which still allows subtree
attacks at intermediate depths. However, range checking is appropriate for
circuits where the tree depth is not fixed at compile time (e.g.,
ModelInstanceBinding with variable-depth registries). For fixed-depth trees,
consider upgrading to the exact-equality constraint.

### Design Decision: 5-Bit Width

All four circuits use `Num2Bits(5)` and `LessThan(5)` regardless of actual
`MAX_DEPTH`. Since `ceil(log2(20+1)) = 5` and `ceil(log2(16+1)) = 5`, 5 bits
is the minimum sufficient for both depth parameters. Using a uniform width
simplifies auditing.

---
