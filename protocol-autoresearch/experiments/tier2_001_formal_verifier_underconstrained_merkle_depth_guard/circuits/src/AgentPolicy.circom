pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../node_modules/@semaphore-protocol/circuits/tree.circom";

/// @title  AgentPolicy
/// @notice Proves an AI agent holds a valid EdDSA-signed credential with
///         cumulative-bit permissions, committed into a Merkle registry.
template AgentPolicy(TREE_DEPTH) {
    // --- Private inputs ---
    signal input modelHash;
    signal input operatorPubKeyX;
    signal input operatorPubKeyY;
    signal input signatureR8x;
    signal input signatureR8y;
    signal input signatureS;
    signal input permissions;         // 8-bit cumulative
    signal input expiry;
    signal input merkleProofLength;
    signal input merkleProofSiblings[TREE_DEPTH];
    signal input merkleProofIndices[TREE_DEPTH];

    // --- Public inputs ---
    signal input agentMerkleRoot;
    signal input currentTimestamp;
    signal input requiredPermissions;  // bitmask
    signal input sessionNonce;

    // --- Public outputs ---
    signal output credentialHash;
    signal output nonceBinding;

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
    // 2. Credential commitment
    // =====================================================
    component credHasher = Poseidon(4);
    credHasher.inputs[0] <== modelHash;
    credHasher.inputs[1] <== operatorPubKeyX;
    credHasher.inputs[2] <== permissions;
    credHasher.inputs[3] <== expiry;
    credentialHash <== credHasher.out;

    // =====================================================
    // 3. EdDSA signature verification
    // =====================================================
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== operatorPubKeyX;
    sigVerifier.Ay <== operatorPubKeyY;
    sigVerifier.R8x <== signatureR8x;
    sigVerifier.R8y <== signatureR8y;
    sigVerifier.S <== signatureS;
    sigVerifier.M <== credentialHash;

    // =====================================================
    // 4. Merkle tree membership
    // =====================================================
    component tree = BinaryMerkleRoot(TREE_DEPTH);
    tree.leaf <== credentialHash;
    tree.depth <== merkleProofLength;
    for (var i = 0; i < TREE_DEPTH; i++) {
        tree.siblings[i] <== merkleProofSiblings[i];
        tree.indices[i] <== merkleProofIndices[i];
    }
    tree.out === agentMerkleRoot;

    // =====================================================
    // 5. Expiry check: currentTimestamp < expiry
    // =====================================================
    component expiryCheck = LessThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== expiry;
    expiryCheck.out === 1;

    // =====================================================
    // 6. Permission check: (permissions & requiredPermissions) === requiredPermissions
    // =====================================================
    component permBits = Num2Bits(8);
    permBits.in <== permissions;
    component reqBits = Num2Bits(8);
    reqBits.in <== requiredPermissions;
    // For each bit, if required then must be present
    signal permCheck[8];
    for (var i = 0; i < 8; i++) {
        // reqBits[i] * (1 - permBits[i]) === 0
        permCheck[i] <== reqBits.out[i] * (1 - permBits.out[i]);
        permCheck[i] === 0;
    }

    // =====================================================
    // 7. Nonce binding
    // =====================================================
    component nonceHasher = Poseidon(2);
    nonceHasher.inputs[0] <== credentialHash;
    nonceHasher.inputs[1] <== sessionNonce;
    nonceBinding <== nonceHasher.out;
}

component main {public [agentMerkleRoot, currentTimestamp, requiredPermissions, sessionNonce]} = AgentPolicy(20);
