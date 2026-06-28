pragma circom 2.1.0;

include "../../src/lib/MerkleDepthCheck.circom";

/// @notice Test wrapper for RangeCheckDepth with MAX_DEPTH=16.
template RangeCheckDepthTest16() {
    signal input merkleProofLength;
    signal output valid;

    component rc = RangeCheckDepth(16);
    rc.merkleProofLength <== merkleProofLength;
    valid <== rc.valid;
    valid === 1;
}

component main = RangeCheckDepthTest16();
