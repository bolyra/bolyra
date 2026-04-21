pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/**
 * @title DelegationExpiryCheck
 * @version 1.0.0
 * @notice Standalone circuit fragment enforcing range-checked 64-bit expiry
 *         comparison for the Bolyra identity protocol's Delegation circuit.
 *
 * This fragment isolates the expiry soundness logic for formal verification
 * and boundary testing. It enforces:
 *   1. All three timestamp inputs are range-checked to [0, 2^64) via Num2Bits(64)
 *   2. delegateeExpiry <= delegatorExpiry  (LessEqThan(64))
 *   3. currentTimestamp < delegateeExpiry  (LessThan(64))
 *
 * The Num2Bits(64) decomposition ensures that comparisons operate on bounded
 * integers, not raw field elements. This closes the wraparound attack vector
 * where a field element like p-1 could appear to satisfy a LessThan check
 * if the comparator operated on unreduced field elements.
 *
 * Constraint breakdown:
 *   - Num2Bits(64) x 3 signals:  3 * 65 = 195 constraints
 *     (64 binary constraints + 1 summation per signal)
 *   - LessEqThan(64):            ~66 constraints
 *     (LessThan(65) internally: Num2Bits(65) + output extraction)
 *   - LessThan(64):              ~66 constraints
 *   - Equality assertions:       2 constraints
 *   Total: ~329 constraints
 *
 * Public inputs:
 *   - currentTimestamp:  prover-supplied current time (unix epoch seconds)
 *   - delegatorExpiry:   delegator credential expiry (unix epoch seconds)
 *   - delegateeExpiry:   delegatee credential expiry (unix epoch seconds)
 *
 * Accepts iff:
 *   - All inputs in [0, 2^64)
 *   - delegateeExpiry <= delegatorExpiry
 *   - currentTimestamp < delegateeExpiry
 */
template DelegationExpiryCheck() {
    // ── Public inputs ─────────────────────────────────────────────────────
    signal input currentTimestamp;
    signal input delegatorExpiry;
    signal input delegateeExpiry;

    // ── Step 1: Range-check all inputs to [0, 2^64) ──────────────────────
    // This is the critical defense against field-element wraparound.
    // Num2Bits(64) constrains the input to have a valid 64-bit binary
    // representation, which is only possible for values in [0, 2^64).
    // Since 2^64 << p (BN254 scalar field prime ~ 2^254), there is no
    // ambiguity: exactly one field element corresponds to each 64-bit integer.

    component currentTsBits = Num2Bits(64);
    currentTsBits.in <== currentTimestamp;

    component delegatorExpiryBits = Num2Bits(64);
    delegatorExpiryBits.in <== delegatorExpiry;

    component delegateeExpiryBits = Num2Bits(64);
    delegateeExpiryBits.in <== delegateeExpiry;

    // ── Step 2: Enforce delegateeExpiry <= delegatorExpiry ────────────────
    // A delegatee's credential must not outlive the delegator's authority.
    // LessEqThan(64) operates on the range-checked values, so comparison
    // is in Z (integers), not F_p.
    component delegExpValid = LessEqThan(64);
    delegExpValid.in[0] <== delegateeExpiry;
    delegExpValid.in[1] <== delegatorExpiry;
    delegExpValid.out === 1;

    // ── Step 3: Enforce currentTimestamp < delegateeExpiry ────────────────
    // The delegation must not be expired at proof generation time.
    // LessThan(64) similarly operates on bounded integers.
    component isNotExpired = LessThan(64);
    isNotExpired.in[0] <== currentTimestamp;
    isNotExpired.in[1] <== delegateeExpiry;
    isNotExpired.out === 1;
}

component main {public [currentTimestamp, delegatorExpiry, delegateeExpiry]} = DelegationExpiryCheck();
