pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

// Validates cumulative-bit encoding: higher permission tiers imply lower ones.
// Bit layout (LSB-first):
//   0: READ_DATA
//   1: WRITE_DATA
//   2: FINANCIAL_SMALL   (< $100)
//   3: FINANCIAL_MEDIUM   (< $10K, implies bit 2)
//   4: FINANCIAL_UNLIMITED (implies bits 2+3)
//   5: SIGN_ON_BEHALF
//   6: SUB_DELEGATE
//   7: ACCESS_PII
template CumulativeBitCheck() {
    signal input bitmask;
    signal output valid;

    component n2b = Num2Bits(8);
    n2b.in <== bitmask;

    // FINANCIAL_MEDIUM (bit 3) implies FINANCIAL_SMALL (bit 2)
    // If bit3 == 1 then bit2 must == 1  =>  bit3 * (1 - bit2) === 0
    signal check_med;
    check_med <== n2b.out[3] * (1 - n2b.out[2]);
    check_med === 0;

    // FINANCIAL_UNLIMITED (bit 4) implies FINANCIAL_MEDIUM (bit 3) and FINANCIAL_SMALL (bit 2)
    signal check_unlim_med;
    check_unlim_med <== n2b.out[4] * (1 - n2b.out[3]);
    check_unlim_med === 0;

    signal check_unlim_small;
    check_unlim_small <== n2b.out[4] * (1 - n2b.out[2]);
    check_unlim_small === 0;

    valid <== 1;
}

// AgentPolicy: proves an agent holds a valid EdDSA-signed credential with
// a specific permission bitmask, and outputs a blinded scope commitment.
//
// CHANGE (scope-blinding-salt): scopeCommitment is now computed as
//   Poseidon(permissionBitmask, credentialCommitment, blindingSalt)
// instead of the previous 2-input variant. This prevents an observer from
// brute-forcing the 8-bit bitmask (256 values) against a known
// credentialCommitment to recover the exact permission set.
template AgentPolicy() {
    // --- Private inputs ---
    signal input modelHash;
    signal input operatorPubKeyX;
    signal input operatorPubKeyY;
    signal input permissionBitmask;
    signal input expiry;
    signal input blindingSalt;  // NEW: random 254-bit blinding salt

    // EdDSA signature over credential commitment
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;

    // --- Public inputs ---
    signal input sessionNonce;
    signal input currentTimestamp;

    // --- Public outputs ---
    signal output credentialCommitment;
    signal output scopeCommitment;
    signal output nonceBinding;

    // 1. Validate cumulative-bit encoding
    component bitCheck = CumulativeBitCheck();
    bitCheck.bitmask <== permissionBitmask;

    // 2. Compute credential commitment = Poseidon(modelHash, operatorPubKeyX, permissionBitmask, expiry)
    component credHash = Poseidon(4);
    credHash.inputs[0] <== modelHash;
    credHash.inputs[1] <== operatorPubKeyX;
    credHash.inputs[2] <== permissionBitmask;
    credHash.inputs[3] <== expiry;
    credentialCommitment <== credHash.out;

    // 3. Verify EdDSA signature over credentialCommitment
    component sigVerify = EdDSAPoseidonVerifier();
    sigVerify.enabled <== 1;
    sigVerify.Ax <== operatorPubKeyX;
    sigVerify.Ay <== operatorPubKeyY;
    sigVerify.R8x <== sigR8x;
    sigVerify.R8y <== sigR8y;
    sigVerify.S <== sigS;
    sigVerify.M <== credentialCommitment;

    // 4. Check expiry: currentTimestamp < expiry
    //    (simplified: expiry - currentTimestamp > 0, enforced via range check)
    signal expiryDiff;
    expiryDiff <== expiry - currentTimestamp;
    component expiryBits = Num2Bits(64);
    expiryBits.in <== expiryDiff; // Fails if negative (underflow)

    // 5. Compute blinded scope commitment = Poseidon(permissionBitmask, credentialCommitment, blindingSalt)
    //    THREE-INPUT Poseidon: prevents bitmask enumeration attack
    component scopeHash = Poseidon(3);
    scopeHash.inputs[0] <== permissionBitmask;
    scopeHash.inputs[1] <== credentialCommitment;
    scopeHash.inputs[2] <== blindingSalt;
    scopeCommitment <== scopeHash.out;

    // 6. Bind proof to session nonce
    component nonceHash = Poseidon(2);
    nonceHash.inputs[0] <== credentialCommitment;
    nonceHash.inputs[1] <== sessionNonce;
    nonceBinding <== nonceHash.out;
}

component main {public [sessionNonce, currentTimestamp]} = AgentPolicy();
