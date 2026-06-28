pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/@semaphore-protocol/circuits/tree.circom";

/// @title  DepthGuardTest
/// @notice Minimal test wrapper for P-RANGE-DEPTH at TREE_DEPTH=20.
///         Isolates the Num2Bits + LessThan range-check constraints
///         and BinaryMerkleRoot so the depth guard can be tested
///         without compiling the full HumanUniqueness circuit.
template DepthGuardTest(TREE_DEPTH) {
    signal input leaf;
    signal input merkleProofLength;
    signal input merkleProofSiblings[TREE_DEPTH];
    signal input merkleProofIndices[TREE_DEPTH];

    signal output root;

    // P-RANGE-DEPTH: 1 <= merkleProofLength <= TREE_DEPTH
    component depthBits = Num2Bits(5);
    depthBits.in <== merkleProofLength;

    component depthUpper = LessThan(5);
    depthUpper.in[0] <== merkleProofLength;
    depthUpper.in[1] <== TREE_DEPTH + 1;
    depthUpper.out === 1;

    component depthLower = LessThan(5);
    depthLower.in[0] <== 0;
    depthLower.in[1] <== merkleProofLength;
    depthLower.out === 1;

    // Merkle tree root computation
    component tree = BinaryMerkleRoot(TREE_DEPTH);
    tree.leaf <== leaf;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < TREE_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    root <== tree.out;
}

component main = DepthGuardTest(20);
