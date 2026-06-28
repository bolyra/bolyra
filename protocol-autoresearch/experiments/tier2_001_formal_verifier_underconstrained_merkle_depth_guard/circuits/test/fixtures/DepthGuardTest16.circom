pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/@semaphore-protocol/circuits/tree.circom";

/// @title  DepthGuardTest16
/// @notice Minimal test wrapper for P-RANGE-DEPTH at MAX_DEPTH=16.
///         Mirrors ModelInstanceBinding's depth parameter.
template DepthGuardTest16(MAX_DEPTH) {
    signal input leaf;
    signal input merkleProofLength;
    signal input merkleProofSiblings[MAX_DEPTH];
    signal input merkleProofIndices[MAX_DEPTH];

    signal output root;

    // P-RANGE-DEPTH: 1 <= merkleProofLength <= MAX_DEPTH
    component depthBits = Num2Bits(5);
    depthBits.in <== merkleProofLength;

    component depthUpper = LessThan(5);
    depthUpper.in[0] <== merkleProofLength;
    depthUpper.in[1] <== MAX_DEPTH + 1;
    depthUpper.out === 1;

    component depthLower = LessThan(5);
    depthLower.in[0] <== 0;
    depthLower.in[1] <== merkleProofLength;
    depthLower.out === 1;

    component tree = BinaryMerkleRoot(MAX_DEPTH);
    tree.leaf <== leaf;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < MAX_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    root <== tree.out;
}

component main = DepthGuardTest16(16);
