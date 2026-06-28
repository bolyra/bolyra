pragma circom 2.1.0;

include "../../src/lib/MerkleDepthGuard.circom";

/// @notice Test wrapper for MerkleDepthGuard with MAX_DEPTH=16.
///         Used to verify the guard works at non-default tree depths.
template MerkleDepthGuardTest16() {
    signal input depth;
    signal output ok;

    component guard = MerkleDepthGuard(16);
    guard.depth <== depth;

    ok <== 1;
}

component main = MerkleDepthGuardTest16();
