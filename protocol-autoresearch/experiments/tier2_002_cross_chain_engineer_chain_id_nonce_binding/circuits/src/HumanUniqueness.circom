pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./lib/MerkleDepthCheck.circom";

/// @title  HumanUniqueness
/// @notice Proves a human identity commitment exists in a Semaphore v4
///         Merkle tree of depth 20, with nullifier, nonce binding, and
///         cross-chain replay prevention via chainId binding.
///
/// @dev    effectiveNonce = Poseidon2(sessionNonce, chainId) replaces the
///         old nonceBinding output. The on-chain verifier asserts that the
///         chainId public signal equals block.chainid before accepting.
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
    signal input chainId;

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
    // 5. Effective nonce (chain-bound)
    //    effectiveNonce = Poseidon2(sessionNonce, chainId)
    //    Replaces the old nonceBinding = Poseidon2(identitySecret, sessionNonce).
    //    Binding chainId into the nonce commitment prevents a proof
    //    generated for chain A from being replayed on chain B.
    // =====================================================
    component effectiveNonceHasher = Poseidon(2);
    effectiveNonceHasher.inputs[0] <== sessionNonce;
    effectiveNonceHasher.inputs[1] <== chainId;
    signal effectiveNonce <== effectiveNonceHasher.out;

    // Bind the identity secret into the nonce commitment so only the
    // identity holder can produce it, then constrain as nonceBinding.
    component nonceHasher = Poseidon(2);
    nonceHasher.inputs[0] <== identitySecret;
    nonceHasher.inputs[1] <== effectiveNonce;
    nonceBinding <== nonceHasher.out;
}

component main {public [humanMerkleRoot, externalNullifier, sessionNonce, chainId]} = HumanUniqueness(20);
