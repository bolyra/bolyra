pragma circom 2.1.0;

include "../../src/lib/MerkleDepthGuard.circom";

/// @notice Test wrapper for MerkleDepthGuard with MAX_DEPTH=20.
///         Exposes the depth input and enforces the guard inline,
///         so invalid depths cause witness generation failure.
template MerkleDepthGuardTest() {
    signal input depth;
    signal output ok;

    component guard = MerkleDepthGuard(20);
    guard.depth <== depth;

    // If we reach here the guard passed; output 1.
    ok <== 1;
}

component main = MerkleDepthGuardTest();
