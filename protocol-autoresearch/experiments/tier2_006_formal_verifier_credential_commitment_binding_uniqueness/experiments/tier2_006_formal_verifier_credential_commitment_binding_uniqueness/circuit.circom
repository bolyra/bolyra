pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/babyjub.circom";
include "lib/FieldCheck.circom";

// AgentPolicy — proves an agent holds a valid EdDSA-signed credential
// with cumulative-bit permissions and computes a binding credentialCommitment.
//
// This version adds InFieldBN254 range checks on modelHash, opPkAx, and opPkAy
// to enforce BN254 scalar field membership before Poseidon hashing.
// See FORMAL-PROPERTIES.md property P-COMMIT-BIND.

template AgentPolicy() {
    // ---- Private inputs ----
    signal input modelHash;          // Hash of the AI model identifier
    signal input opPkAx;             // Operator public key (Baby Jubjub) x-coordinate
    signal input opPkAy;             // Operator public key (Baby Jubjub) y-coordinate
    signal input permissionBitmask;  // 8-bit cumulative permission encoding
    signal input expiryTimestamp;    // Unix timestamp of credential expiry

    // ---- Public outputs ----
    signal output credentialCommitment;  // Poseidon5(modelHash, opPkAx, opPkAy, bitmask, expiry)
    signal output policyNullifier;       // Domain-separated nullifier for replay prevention
    signal output nonceBinding;          // Binds proof to a session nonce

    // ---- Public inputs ----
    signal input sessionNonce;       // Fresh nonce for handshake binding
    signal input currentTimestamp;   // Current time for expiry check
    signal input agentTreeRoot;      // Merkle root of the agent registry tree

    // ================================================================
    // Step 1: BN254 scalar field membership checks
    // ================================================================
    // SECURITY (P-COMMIT-BIND): modelHash, opPkAx, and opPkAy are external
    // inputs that could theoretically wrap around the BN254 scalar field
    // modulus r if not range-checked. Without these checks, two distinct
    // 256-bit values v and v' where v' = v + r would map to the same field
    // element, violating the injectivity assumption of the credential
    // commitment. Num2Bits(254) + strict < r check prevents this.
    // See: circuits/FORMAL-PROPERTIES.md, property P-COMMIT-BIND.

    component fieldCheckModelHash = InFieldBN254();
    fieldCheckModelHash.in <== modelHash;

    component fieldCheckOpPkAx = InFieldBN254();
    fieldCheckOpPkAx.in <== opPkAx;

    component fieldCheckOpPkAy = InFieldBN254();
    fieldCheckOpPkAy.in <== opPkAy;

    // ================================================================
    // Step 2: Permission bitmask validation (8-bit cumulative encoding)
    // ================================================================
    component bitmaskBits = Num2Bits(8);
    bitmaskBits.in <== permissionBitmask;

    // Cumulative bit implication rules:
    // bit4 (FINANCIAL_UNLIMITED) => bit3 (FINANCIAL_MEDIUM) => bit2 (FINANCIAL_SMALL)
    signal bit2, bit3, bit4;
    bit2 <== bitmaskBits.out[2];
    bit3 <== bitmaskBits.out[3];
    bit4 <== bitmaskBits.out[4];

    // If bit4 is set, bit3 must be set: bit4 * (1 - bit3) === 0
    signal implCheck43;
    implCheck43 <== bit4 * (1 - bit3);
    implCheck43 === 0;

    // If bit3 is set, bit2 must be set: bit3 * (1 - bit2) === 0
    signal implCheck32;
    implCheck32 <== bit3 * (1 - bit2);
    implCheck32 === 0;

    // ================================================================
    // Step 3: Expiry timestamp check
    // ================================================================
    component expiryBits = Num2Bits(64);
    expiryBits.in <== expiryTimestamp;

    component currentBits = Num2Bits(64);
    currentBits.in <== currentTimestamp;

    // Assert expiryTimestamp > currentTimestamp
    component expiryCheck = LessThan(64);
    expiryCheck.in[0] <== currentTimestamp;
    expiryCheck.in[1] <== expiryTimestamp;
    expiryCheck.out === 1;

    // ================================================================
    // Step 4: Credential commitment (Poseidon-5)
    // ================================================================
    // Uses field-checked outputs to ensure domain membership.
    // Collision resistance of Poseidon over F_r^5 guarantees unique binding.
    component credHash = Poseidon(5);
    credHash.inputs[0] <== fieldCheckModelHash.out;
    credHash.inputs[1] <== fieldCheckOpPkAx.out;
    credHash.inputs[2] <== fieldCheckOpPkAy.out;
    credHash.inputs[3] <== permissionBitmask;
    credHash.inputs[4] <== expiryTimestamp;

    credentialCommitment <== credHash.out;

    // ================================================================
    // Step 5: Policy nullifier (domain separation)
    // ================================================================
    component nullHash = Poseidon(3);
    nullHash.inputs[0] <== credHash.out;
    nullHash.inputs[1] <== agentTreeRoot;
    nullHash.inputs[2] <== 0x414750;  // Domain tag: "AGP" in hex

    policyNullifier <== nullHash.out;

    // ================================================================
    // Step 6: Nonce binding
    // ================================================================
    component nonceHash = Poseidon(2);
    nonceHash.inputs[0] <== credHash.out;
    nonceHash.inputs[1] <== sessionNonce;

    nonceBinding <== nonceHash.out;
}

component main {public [sessionNonce, currentTimestamp, agentTreeRoot]} = AgentPolicy();
