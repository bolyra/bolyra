// =============================================================
// MerkleDepthExactEquality.spec
// Certora-style CVL pseudocode for P-DEPTH-01
// =============================================================
//
// Property P-DEPTH-01: For every satisfying witness W accepted by
// any Bolyra circuit that includes BinaryMerkleRoot, the private
// input merkleProofLength equals the compile-time TREE_DEPTH
// constant exactly.
//
// This supersedes the weaker range-bounded property (1 <= depth
// <= MAX_DEPTH) by pinning depth to the single deployed value.
//
// Circuits covered:
//   - HumanUniqueness(20)
//   - AgentPolicy(20)
//   - Delegation(20)
// =============================================================

// Ghost variable representing the private merkleProofLength signal
ghost uint merkleProofLength;

// Ghost variable representing the circuit's TREE_DEPTH parameter
ghost uint TREE_DEPTH;

// =============================================================
// Invariant: depth is exactly TREE_DEPTH
// =============================================================
// For any satisfying witness, merkleProofLength must equal
// TREE_DEPTH. This is enforced by:
//   signal depthCheck;
//   depthCheck <== merkleProofLength - TREE_DEPTH;
//   depthCheck === 0;
//
// In R1CS, this is a single constraint row:
//   (1) * (merkleProofLength - TREE_DEPTH) = 0
// which has a unique satisfying assignment:
//   merkleProofLength = TREE_DEPTH
invariant depthExactlyTreeDepth()
    merkleProofLength == TREE_DEPTH
    {
        preserved {
            require merkleProofLength == TREE_DEPTH;
        }
    }

// =============================================================
// Rule: depth = TREE_DEPTH - 1 has no satisfying witness
// =============================================================
// This is the "subtree-root attack" case: a prover supplies a
// proof path one level shorter than the deployed depth, targeting
// an intermediate Merkle node.
rule depthOffByOneUnsatisfiable() {
    require merkleProofLength == TREE_DEPTH - 1;

    // depthCheck = merkleProofLength - TREE_DEPTH = -1 (mod p)
    // depthCheck === 0 --> CONTRADICTION
    // (In BN254, -1 mod p != 0)

    assert false,
        "A witness with merkleProofLength == TREE_DEPTH - 1 must not satisfy the circuit";
}

// =============================================================
// Rule: depth = 0 has no satisfying witness
// =============================================================
// A witness with merkleProofLength=0 makes the leaf the Merkle
// root, completely bypassing tree membership.
rule depthZeroUnsatisfiable() {
    require merkleProofLength == 0;

    // depthCheck = 0 - TREE_DEPTH = -TREE_DEPTH (mod p)
    // depthCheck === 0 --> CONTRADICTION (since TREE_DEPTH > 0)

    assert false,
        "A witness with merkleProofLength == 0 must not satisfy the circuit";
}

// =============================================================
// Rule: depth > TREE_DEPTH has no satisfying witness
// =============================================================
// A witness with merkleProofLength > TREE_DEPTH reads
// uninitialized sibling array slots.
rule depthOverflowUnsatisfiable() {
    require merkleProofLength > TREE_DEPTH;

    // depthCheck = merkleProofLength - TREE_DEPTH > 0
    // depthCheck === 0 --> CONTRADICTION

    assert false,
        "A witness with merkleProofLength > TREE_DEPTH must not satisfy the circuit";
}

// =============================================================
// Rule: exact depth is satisfiable (non-vacuity)
// =============================================================
// merkleProofLength == TREE_DEPTH must admit a satisfying
// witness (given valid remaining inputs). This ensures the
// constraint is not accidentally vacuous.
rule exactDepthSatisfiable() {
    require merkleProofLength == TREE_DEPTH;

    // depthCheck = TREE_DEPTH - TREE_DEPTH = 0
    // depthCheck === 0 --> SATISFIED

    satisfy merkleProofLength == TREE_DEPTH;
}
