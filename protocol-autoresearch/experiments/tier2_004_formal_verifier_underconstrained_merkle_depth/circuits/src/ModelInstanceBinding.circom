pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./lib/MerkleDepthCheck.circom";

/// @title  ModelInstanceBinding
/// @notice Proves that a specific model instance (identified by modelHash +
///         instanceNonce) is registered in a model registry Merkle tree.
template ModelInstanceBinding(MAX_DEPTH) {
    // --- Private inputs ---
    signal input modelHash;
    signal input instanceNonce;
    signal input operatorPubKeyX;
    signal input merkleProofLength;
    signal input merkleProofSiblings[MAX_DEPTH];
    signal input merkleProofIndices[MAX_DEPTH];

    // --- Public inputs ---
    signal input modelRegistryRoot;
    signal input sessionNonce;

    // --- Public outputs ---
    signal output instanceCommitment;
    signal output nonceBinding;

    // =====================================================
    // 1. Merkle depth boundedness: 1 <= depth <= MAX_DEPTH
    // =====================================================
    component depthCheck = RangeCheckDepth(MAX_DEPTH);
    depthCheck.merkleProofLength <== merkleProofLength;
    depthCheck.valid === 1;

    // =====================================================
    // 2. Instance commitment
    // =====================================================
    component instanceHasher = Poseidon(3);
    instanceHasher.inputs[0] <== modelHash;
    instanceHasher.inputs[1] <== instanceNonce;
    instanceHasher.inputs[2] <== operatorPubKeyX;
    instanceCommitment <== instanceHasher.out;

    // =====================================================
    // 3. Merkle tree membership
    // =====================================================
    component tree = BinaryMerkleRoot(MAX_DEPTH);
    tree.leaf <== instanceCommitment;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < MAX_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    tree.out === modelRegistryRoot;

    // =====================================================
    // 4. Nonce binding
    // =====================================================
    component nonceHasher = Poseidon(2);
    nonceHasher.inputs[0] <== instanceCommitment;
    nonceHasher.inputs[1] <== sessionNonce;
    nonceBinding <== nonceHasher.out;
}

component main {public [modelRegistryRoot, sessionNonce]} = ModelInstanceBinding(16);
