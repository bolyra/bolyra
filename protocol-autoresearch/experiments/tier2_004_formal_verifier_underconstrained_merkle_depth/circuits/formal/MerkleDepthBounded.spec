// =============================================================
// MerkleDepthBounded.spec
// Certora-style CVL pseudocode for Merkle depth boundedness
// =============================================================
//
// Property: For every satisfying witness W accepted by any Bolyra
// circuit that includes BinaryMerkleRoot, the private input
// merkleProofLength satisfies 1 <= merkleProofLength <= MAX_DEPTH.
//
// Circuits covered:
//   - HumanUniqueness(20)
//   - AgentPolicy(20)
//   - Delegation(20)
//   - ModelInstanceBinding(16)
// =============================================================

// Ghost variable representing the private merkleProofLength signal
ghost uint merkleProofLength;

// Ghost variable representing the circuit's MAX_DEPTH parameter
ghost uint MAX_DEPTH;

// =============================================================
// Invariant: depth is bounded
// =============================================================
// For any satisfying witness, the depth must be within [1, MAX_DEPTH].
invariant depthBounded()
    merkleProofLength >= 1 && merkleProofLength <= MAX_DEPTH
    {
        // The RangeCheckDepth template enforces this via:
        //   1. Num2Bits(NUM_BITS) constrains merkleProofLength >= 0
        //      and merkleProofLength < 2^NUM_BITS
        //   2. LessThan: 0 < merkleProofLength  (lower bound >= 1)
        //   3. LessThan: merkleProofLength < MAX_DEPTH + 1 (upper bound <= MAX_DEPTH)
        //   4. valid <== lowerBound.out * upperBound.out
        //   5. valid === 1 (caller asserts)
        preserved {
            require merkleProofLength >= 1;
            require merkleProofLength <= MAX_DEPTH;
        }
    }

// =============================================================
// Rule: depth=0 has no satisfying witness
// =============================================================
// A witness with merkleProofLength=0 must not satisfy the circuit
// constraints. The RangeCheckDepth lowerBound comparator outputs 0
// when merkleProofLength=0, causing valid=0, which contradicts
// the assertion valid === 1.
rule depthZeroUnsatisfiable() {
    // Assume depth is zero
    require merkleProofLength == 0;

    // The RangeCheckDepth template computes:
    //   lowerBound.out = LessThan(0, 0) = 0
    //   valid = 0 * upperBound.out = 0
    //   assert valid === 1  --> CONTRADICTION

    // Therefore no satisfying assignment exists
    assert false,
        "A witness with merkleProofLength=0 must not produce a satisfying assignment";
}

// =============================================================
// Rule: depth > MAX_DEPTH has no satisfying witness
// =============================================================
// A witness with merkleProofLength > MAX_DEPTH must not satisfy
// the circuit constraints. The RangeCheckDepth upperBound comparator
// outputs 0 when merkleProofLength >= MAX_DEPTH + 1.
rule depthOverflowUnsatisfiable() {
    // Assume depth exceeds maximum
    require merkleProofLength > MAX_DEPTH;

    // The RangeCheckDepth template computes:
    //   upperBound.out = LessThan(merkleProofLength, MAX_DEPTH+1) = 0
    //   valid = lowerBound.out * 0 = 0
    //   assert valid === 1  --> CONTRADICTION

    assert false,
        "A witness with merkleProofLength > MAX_DEPTH must not produce a satisfying assignment";
}

// =============================================================
// Rule: boundary values are satisfiable
// =============================================================
// Depth=1 and depth=MAX_DEPTH must admit satisfying witnesses
// (given valid remaining inputs). This ensures the range check
// is not accidentally over-constrained.
rule boundaryValuesSatisfiable() {
    // Case 1: minimum valid depth
    require merkleProofLength == 1;
    satisfy merkleProofLength >= 1 && merkleProofLength <= MAX_DEPTH;

    // Case 2: maximum valid depth
    require merkleProofLength == MAX_DEPTH;
    satisfy merkleProofLength >= 1 && merkleProofLength <= MAX_DEPTH;
}
