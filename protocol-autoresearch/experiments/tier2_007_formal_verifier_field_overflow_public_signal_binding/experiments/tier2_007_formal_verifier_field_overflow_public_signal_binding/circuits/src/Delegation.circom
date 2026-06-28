pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";
include "./RangeChecks.circom";

/// @title  Delegation
/// @notice Proves one-way scope narrowing: a delegator narrows permissions
///         from parentPermissions to childPermissions, committed in a
///         delegation Merkle tree.
template Delegation(TREE_DEPTH) {
    // --- Private inputs ---
    signal input delegatorSecret;
    signal input parentPermissions;    // 8-bit cumulative
    signal input childPermissions;     // 8-bit cumulative, must be subset
    signal input delegateeCommitment;
    signal input expiry;
    signal input merkleProofLength;
    signal input merkleProofSiblings[TREE_DEPTH];
    signal input merkleProofIndices[TREE_DEPTH];

    // --- Public inputs ---
    signal input delegationMerkleRoot;
    signal input currentTimestamp;
    signal input sessionNonce;

    // --- Public outputs ---
    signal output delegationHash;
    signal output narrowedPermissions;
    signal output nonceBinding;

    // =====================================================
    // 0. P-RANGE-FIELD: Canonical field element checks
    //    Ensures public inputs are < 2^253, preventing
    //    modular aliasing (prover submits x+r instead of x).
    //    - delegationMerkleRoot: Poseidon-implied < r (no check needed)
    //    - currentTimestamp: LessThan(64) implies Num2Bits (covered)
    //    - sessionNonce: UNRANGED -> add RangeCheck(253)
    //    Outputs (delegationHash, nonceBinding): Poseidon outputs.
    //    narrowedPermissions: = childPermissions with Num2Bits(8) (covered).
    // =====================================================
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
    component tree = BinaryMerkleRoot(TREE_DEPTH);
    tree.leaf <== delegationHash;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < TREE_DEPTH; i++) {
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
