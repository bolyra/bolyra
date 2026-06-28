pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Delegation circuit: proves that a delegated credential is a valid
// scope-narrowing of a parent credential. The delegated permission
// bitmask must be a subset of the parent's bitmask (one-way narrowing).
//
// CHANGE (scope-blinding-salt): both parent and delegated scope commitments
// are now computed with 3-input Poseidon including a per-hop blindingSalt.
// Each delegation hop uses its own fresh salt.
template Delegation() {
    // --- Parent credential (private) ---
    signal input parentPermissionBitmask;
    signal input parentCredentialCommitment;
    signal input parentBlindingSalt;  // NEW: salt for parent scope commitment

    // --- Delegated credential (private) ---
    signal input delegatedPermissionBitmask;
    signal input delegatedCredentialCommitment;
    signal input delegatedBlindingSalt;  // NEW: fresh salt for delegated scope commitment

    // --- Delegation metadata (private) ---
    signal input delegatorSecret;  // Links delegation to parent identity
    signal input delegationExpiry;

    // --- Public inputs ---
    signal input currentTimestamp;

    // --- Public outputs ---
    signal output parentScopeCommitment;
    signal output delegatedScopeCommitment;
    signal output delegationBinding;

    // 1. Enforce scope narrowing: delegated bitmask must be a SUBSET of parent bitmask.
    //    For each bit: delegated[i] AND NOT parent[i] must be 0.
    //    Equivalently: delegated AND (NOT parent) === 0
    //    Which means: delegated AND parent === delegated
    component parentBits = Num2Bits(8);
    parentBits.in <== parentPermissionBitmask;

    component delegatedBits = Num2Bits(8);
    delegatedBits.in <== delegatedPermissionBitmask;

    // Check each bit: if delegated bit is set, parent bit must also be set
    signal narrowingCheck[8];
    for (var i = 0; i < 8; i++) {
        narrowingCheck[i] <== delegatedBits.out[i] * (1 - parentBits.out[i]);
        narrowingCheck[i] === 0;
    }

    // 2. Validate cumulative-bit encoding for delegated bitmask
    //    FINANCIAL_MEDIUM (bit 3) => FINANCIAL_SMALL (bit 2)
    signal check_med;
    check_med <== delegatedBits.out[3] * (1 - delegatedBits.out[2]);
    check_med === 0;

    //    FINANCIAL_UNLIMITED (bit 4) => FINANCIAL_MEDIUM (bit 3)
    signal check_unlim_med;
    check_unlim_med <== delegatedBits.out[4] * (1 - delegatedBits.out[3]);
    check_unlim_med === 0;

    //    FINANCIAL_UNLIMITED (bit 4) => FINANCIAL_SMALL (bit 2)
    signal check_unlim_small;
    check_unlim_small <== delegatedBits.out[4] * (1 - delegatedBits.out[2]);
    check_unlim_small === 0;

    // 3. Check delegation expiry
    signal expiryDiff;
    expiryDiff <== delegationExpiry - currentTimestamp;
    component expiryBits = Num2Bits(64);
    expiryBits.in <== expiryDiff;

    // 4. Compute BLINDED parent scope commitment
    //    Poseidon(parentPermissionBitmask, parentCredentialCommitment, parentBlindingSalt)
    component parentScopeHash = Poseidon(3);
    parentScopeHash.inputs[0] <== parentPermissionBitmask;
    parentScopeHash.inputs[1] <== parentCredentialCommitment;
    parentScopeHash.inputs[2] <== parentBlindingSalt;
    parentScopeCommitment <== parentScopeHash.out;

    // 5. Compute BLINDED delegated scope commitment
    //    Poseidon(delegatedPermissionBitmask, delegatedCredentialCommitment, delegatedBlindingSalt)
    component delegatedScopeHash = Poseidon(3);
    delegatedScopeHash.inputs[0] <== delegatedPermissionBitmask;
    delegatedScopeHash.inputs[1] <== delegatedCredentialCommitment;
    delegatedScopeHash.inputs[2] <== delegatedBlindingSalt;
    delegatedScopeCommitment <== delegatedScopeHash.out;

    // 6. Compute delegation binding = Poseidon(delegatorSecret, parentCredentialCommitment, delegatedCredentialCommitment)
    component bindingHash = Poseidon(3);
    bindingHash.inputs[0] <== delegatorSecret;
    bindingHash.inputs[1] <== parentCredentialCommitment;
    bindingHash.inputs[2] <== delegatedCredentialCommitment;
    delegationBinding <== bindingHash.out;
}

component main {public [currentTimestamp]} = Delegation();
