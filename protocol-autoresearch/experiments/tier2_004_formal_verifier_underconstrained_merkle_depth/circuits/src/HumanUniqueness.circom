pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./lib/MerkleDepthCheck.circom";

/// @title  HumanUniqueness
/// @notice Proves a human identity commitment exists in a Semaphore v4
///         Merkle tree of depth 20, with nullifier and nonce binding.
template HumanUniqueness(MAX_DEPTH) {
    // --- Private inputs ---
    signal input identitySecret;
    signal input merkleProofLength;
    signal input merkleProofSiblings[MAX_DEPTH];
    signal input merkleProofIndices[MAX_DEPTH];

    // --- Public inputs ---
    signal input humanMerkleRoot;
    signal input externalNullifier;
    signal input sessionNonce;

    // --- Public outputs ---
    signal output nullifierHash;
    signal output nonceBinding;

    // =====================================================
    // 1. Merkle depth boundedness: 1 <= depth <= MAX_DEPTH
    // =====================================================
    component depthCheck = RangeCheckDepth(MAX_DEPTH);
    depthCheck.merkleProofLength <== merkleProofLength;
    depthCheck.valid === 1;

    // =====================================================
    // 2. Identity commitment
    // =====================================================
    component identityHasher = Poseidon(1);
    identityHasher.inputs[0] <== identitySecret;
    signal identityCommitment <== identityHasher.out;

    // =====================================================
    // 3. Merkle tree membership
    // =====================================================
    component tree = BinaryMerkleRoot(MAX_DEPTH);
    tree.leaf <== identityCommitment;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < MAX_DEPTH; i++) {
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
