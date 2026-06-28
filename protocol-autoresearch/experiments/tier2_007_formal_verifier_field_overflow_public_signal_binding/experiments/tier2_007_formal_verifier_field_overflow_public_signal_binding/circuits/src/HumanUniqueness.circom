pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./RangeChecks.circom";

/// @title  HumanUniqueness
/// @notice Proves a human identity commitment exists in a Semaphore v4
///         Merkle tree of depth 20, with nullifier and nonce binding.
template HumanUniqueness(TREE_DEPTH) {
    // --- Private inputs ---
    signal input identitySecret;
    signal input merkleProofLength;
    signal input merkleProofSiblings[TREE_DEPTH];
    signal input merkleProofIndices[TREE_DEPTH];

    // --- Public inputs ---
    signal input humanMerkleRoot;
    signal input externalNullifier;
    signal input sessionNonce;

    // --- Public outputs ---
    signal output nullifierHash;
    signal output nonceBinding;

    // =====================================================
    // 0. P-RANGE-FIELD: Canonical field element checks
    //    Ensures public inputs are < 2^253, preventing
    //    modular aliasing (prover submits x+r instead of x).
    //    - humanMerkleRoot: Poseidon-implied < r (no check needed)
    //    - externalNullifier: UNRANGED -> add RangeCheck(253)
    //    - sessionNonce: UNRANGED -> add RangeCheck(253)
    //    Outputs (nullifierHash, nonceBinding): Poseidon outputs,
    //    inherently < r.
    // =====================================================
    component rcExternalNullifier = RangeCheck(253);
    rcExternalNullifier.in <== externalNullifier;

    component rcSessionNonce = RangeCheck(253);
    rcSessionNonce.in <== sessionNonce;

    // =====================================================
    // 1. P-RANGE-DEPTH: 1 <= merkleProofLength <= TREE_DEPTH
    //    Num2Bits bounds the bit-width to prevent field
    //    overflow; LessThan enforces the range.
    // =====================================================

    // Bit-width bound: merkleProofLength fits in 5 bits
    component depthBits = Num2Bits(5);
    depthBits.in <== merkleProofLength;

    // Upper bound: merkleProofLength < TREE_DEPTH + 1
    //            => merkleProofLength <= TREE_DEPTH
    component depthUpper = LessThan(5);
    depthUpper.in[0] <== merkleProofLength;
    depthUpper.in[1] <== TREE_DEPTH + 1;
    depthUpper.out === 1;

    // Lower bound: 0 < merkleProofLength
    //            => merkleProofLength >= 1
    component depthLower = LessThan(5);
    depthLower.in[0] <== 0;
    depthLower.in[1] <== merkleProofLength;
    depthLower.out === 1;

    // =====================================================
    // 2. Identity commitment
    // =====================================================
    component identityHasher = Poseidon(1);
    identityHasher.inputs[0] <== identitySecret;
    signal identityCommitment <== identityHasher.out;

    // =====================================================
    // 3. Merkle tree membership
    // =====================================================
    component tree = BinaryMerkleRoot(TREE_DEPTH);
    tree.leaf <== identityCommitment;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < TREE_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    tree.out === humanMerkleRoot;

    // =====================================================
    // 4. Nullifier hash
    // =====================================================
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== externalNullifier;
    nullifierHash <== nullifierHasher.out;

    // =====================================================
    // 5. Nonce binding
    // =====================================================
    component nonceHasher = Poseidon(2);
    nonceHasher.inputs[0] <== identitySecret;
    nonceHasher.inputs[1] <== sessionNonce;
    nonceBinding <== nonceHasher.out;
}

component main {public [humanMerkleRoot, externalNullifier, sessionNonce]} = HumanUniqueness(20);
