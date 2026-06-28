pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./lib/MerkleDepthCheck.circom";

/// @title  Delegation
/// @notice Proves one-way scope narrowing: a delegator narrows permissions
///         from parentPermissions to childPermissions, committed in a
///         delegation Merkle tree.
template Delegation(MAX_DEPTH) {
    // --- Private inputs ---
    signal input delegatorSecret;
    signal input parentPermissions;    // 8-bit cumulative
    signal input childPermissions;     // 8-bit cumulative, must be subset
    signal input delegateeCommitment;
    signal input expiry;
    signal input merkleProofLength;
    signal input merkleProofSiblings[MAX_DEPTH];
    signal input merkleProofIndices[MAX_DEPTH];

    // --- Public inputs ---
    signal input delegationMerkleRoot;
    signal input currentTimestamp;
    signal input sessionNonce;

    // --- Public outputs ---
    signal output delegationHash;
    signal output narrowedPermissions;
    signal output nonceBinding;

    // =====================================================
    // 1. Merkle depth boundedness: 1 <= depth <= MAX_DEPTH
    // =====================================================
    component depthCheck = RangeCheckDepth(MAX_DEPTH);
    depthCheck.merkleProofLength <== merkleProofLength;
    depthCheck.valid === 1;

    // =====================================================
    // 2. Scope narrowing: childPermissions is subset of parentPermissions
    // =====================================================
    component parentBits = Num2Bits(8);
    parentBits.in <== parentPermissions;
    component childBits = Num2Bits(8);
    childBits.in <== childPermissions;
    signal narrowCheck[8];
    for (var i = 0; i < 8; i++) {
        // childBits[i] * (1 - parentBits[i]) === 0
        narrowCheck[i] <== childBits.out[i] * (1 - parentBits.out[i]);
        narrowCheck[i] === 0;
    }
    narrowedPermissions <== childPermissions;

    // =====================================================
    // 3. Delegation commitment
    // =====================================================
    component delegationHasher = Poseidon(4);
    delegationHasher.inputs[0] <== delegatorSecret;
    delegationHasher.inputs[1] <== childPermissions;
    delegationHasher.inputs[2] <== delegateeCommitment;
    delegationHasher.inputs[3] <== expiry;
    delegationHash <== delegationHasher.out;

    // =====================================================
    // 4. Merkle tree membership
    // =====================================================
    component tree = BinaryMerkleRoot(MAX_DEPTH);
    tree.leaf <== delegationHash;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < MAX_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    tree.out === delegationMerkleRoot;

    // =====================================================
    // 5. Expiry check
    // =====================================================
    component expiryCheck = LessThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== expiry;
    expiryCheck.out === 1;

    // =====================================================
    // 6. Nonce binding
    // =====================================================
    component nonceHasher = Poseidon(2);
    nonceHasher.inputs[0] <== delegationHash;
    nonceHasher.inputs[1] <== sessionNonce;
    nonceBinding <== nonceHasher.out;
}

component main {public [delegationMerkleRoot, currentTimestamp, sessionNonce]} = Delegation(20);
