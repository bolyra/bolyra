pragma circom 2.1.0;

include "../../node_modules/@semaphore-protocol/circuits/tree.circom";

/// @title  DepthExactTest
/// @notice Minimal test wrapper for P-DEPTH-01.
///         Instantiates the exact-depth constraint and BinaryMerkleRoot
///         so we can test the depth check in isolation.
template DepthExactTest(TREE_DEPTH) {
    signal input leaf;
    signal input merkleProofLength;
    signal input merkleProofSiblings[TREE_DEPTH];
    signal input merkleProofIndices[TREE_DEPTH];

    signal output root;

    // P-DEPTH-01: exact equality constraint
    signal depthCheck;
    depthCheck <== merkleProofLength - TREE_DEPTH;
    depthCheck === 0;

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

component main = DepthExactTest(20);
