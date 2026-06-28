pragma circom 2.1.0;

include "../../src/lib/MerkleDepthCheck.circom";

/// @notice Test wrapper for RangeCheckDepth with MAX_DEPTH=20.
///         Exposes valid as a public output and asserts it equals 1
///         so that invalid depths cause witness generation failure.
template RangeCheckDepthTest() {
    signal input merkleProofLength;
    signal output valid;

    component rc = RangeCheckDepth(20);
    rc.merkleProofLength <== merkleProofLength;
    valid <== rc.valid;
    valid === 1;
}

component main = RangeCheckDepthTest();
