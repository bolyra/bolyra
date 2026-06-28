pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";

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
    // 1. P-DEPTH-01: merkleProofLength === TREE_DEPTH
    //    Prevents subtree-root attacks where a shorter
    //    proof path matches an intermediate Merkle node.
    // =====================================================
    signal depthCheck;
    depthCheck <== merkleProofLength - TREE_DEPTH;
    depthCheck === 0;

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
