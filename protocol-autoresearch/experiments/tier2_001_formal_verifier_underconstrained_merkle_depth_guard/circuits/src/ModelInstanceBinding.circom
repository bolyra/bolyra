pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";

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
    // 1. P-RANGE-DEPTH: 1 <= merkleProofLength <= MAX_DEPTH
    //    Num2Bits bounds the bit-width to prevent field
    //    overflow; LessThan enforces the range.
    // =====================================================

    // Bit-width bound: merkleProofLength fits in 5 bits
    component depthBits = Num2Bits(5);
    depthBits.in <== merkleProofLength;

    // Upper bound: merkleProofLength < MAX_DEPTH + 1
    //            => merkleProofLength <= MAX_DEPTH
    component depthUpper = LessThan(5);
    depthUpper.in[0] <== merkleProofLength;
    depthUpper.in[1] <== MAX_DEPTH + 1;
    depthUpper.out === 1;

    // Lower bound: 0 < merkleProofLength
    //            => merkleProofLength >= 1
    component depthLower = LessThan(5);
    depthLower.in[0] <== 0;
    depthLower.in[1] <== merkleProofLength;
    depthLower.out === 1;

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
