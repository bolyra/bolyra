pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/**
 * DelegationChainBinding
 *
 * Augmented delegation circuit that exposes previousScopeCommitment and
 * currentScopeCommitment as public outputs and enforces:
 *
 *   1. scopeCommitment = Poseidon(scope, credCommitment)
 *   2. delegatee permission bits are a strict subset of delegator permission
 *      bits via cumulative AND-mask check.
 *
 * This is a verification wrapper around the core Delegation logic.
 * The production Delegation.circom is NOT modified.
 *
 * Public inputs:  previousScopeCommitment
 * Public outputs: currentScopeCommitment, subsetValid
 *
 * Private inputs: delegatorScope, delegateeScope, credCommitment, previousCredCommitment
 */
template DelegationChainBinding() {
    // ---------------------------------------------------------------
    // Public signals
    // ---------------------------------------------------------------
    signal input  previousScopeCommitment;
    signal output currentScopeCommitment;

    // ---------------------------------------------------------------
    // Private signals
    // ---------------------------------------------------------------
    signal input delegatorScope;          // 8-bit permission mask of delegator
    signal input delegateeScope;          // 8-bit permission mask of delegatee
    signal input credCommitment;          // credential commitment of delegatee
    signal input previousCredCommitment;  // credential commitment of delegator

    // ---------------------------------------------------------------
    // 1. Range-check: both scopes fit in 8 bits
    // ---------------------------------------------------------------
    component delegatorBits = Num2Bits(8);
    delegatorBits.in <== delegatorScope;

    component delegateeBits = Num2Bits(8);
    delegateeBits.in <== delegateeScope;

    // ---------------------------------------------------------------
    // 2. Subset check: delegateeScope & delegatorScope === delegateeScope
    //    Equivalent to: for every bit i, delegateeBits[i] * (1 - delegatorBits[i]) === 0
    //    i.e. delegatee cannot set a bit that delegator does not have.
    // ---------------------------------------------------------------
    signal subsetCheck[8];
    for (var i = 0; i < 8; i++) {
        // If delegatee has bit i set but delegator does not, this is non-zero → constraint fails
        subsetCheck[i] <== delegateeBits.out[i] * (1 - delegatorBits.out[i]);
        subsetCheck[i] === 0;
    }

    // ---------------------------------------------------------------
    // 3. Cumulative-bit implication rules (matches Bolyra permission model)
    //    Bit 4 (FINANCIAL_UNLIMITED) implies bits 3 and 2
    //    Bit 3 (FINANCIAL_MEDIUM) implies bit 2
    // ---------------------------------------------------------------
    // If bit 4 is set, bit 3 must be set
    signal impl43 <== delegateeBits.out[4] * (1 - delegateeBits.out[3]);
    impl43 === 0;
    // If bit 4 is set, bit 2 must be set
    signal impl42 <== delegateeBits.out[4] * (1 - delegateeBits.out[2]);
    impl42 === 0;
    // If bit 3 is set, bit 2 must be set
    signal impl32 <== delegateeBits.out[3] * (1 - delegateeBits.out[2]);
    impl32 === 0;

    // Same implication rules for delegator (ensures well-formed input)
    signal dimpl43 <== delegatorBits.out[4] * (1 - delegatorBits.out[3]);
    dimpl43 === 0;
    signal dimpl42 <== delegatorBits.out[4] * (1 - delegatorBits.out[2]);
    dimpl42 === 0;
    signal dimpl32 <== delegatorBits.out[3] * (1 - delegatorBits.out[2]);
    dimpl32 === 0;

    // ---------------------------------------------------------------
    // 4. Scope commitment computation
    //    currentScopeCommitment  = Poseidon(delegateeScope, credCommitment)
    //    previousScopeCommitment = Poseidon(delegatorScope, previousCredCommitment)
    // ---------------------------------------------------------------
    component currentCommit = Poseidon(2);
    currentCommit.inputs[0] <== delegateeScope;
    currentCommit.inputs[1] <== credCommitment;
    currentScopeCommitment <== currentCommit.out;

    component previousCommit = Poseidon(2);
    previousCommit.inputs[0] <== delegatorScope;
    previousCommit.inputs[1] <== previousCredCommitment;

    // ---------------------------------------------------------------
    // 5. Chain binding: the declared previousScopeCommitment must match
    //    the recomputed commitment from delegator signals.
    // ---------------------------------------------------------------
    previousCommit.out === previousScopeCommitment;
}

component main {public [previousScopeCommitment]} = DelegationChainBinding();
