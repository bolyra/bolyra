// ============================================================================
// delegation_expiry_soundness.spec
// Certora-style property specification for delegation expiry narrowing
// ============================================================================
//
// Target circuit: DelegationWithExpiry (Delegation.circom v3.0.0)
// Protocol: Bolyra Identity Protocol
//
// These invariants prove that the delegation expiry narrowing constraint
// system is sound: no valid witness can produce a proof where the delegatee
// outlives the delegator or where an expired credential is accepted.
// ============================================================================

// ── Field parameters ────────────────────────────────────────────────────────
// BN254 scalar field prime
define P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
define MAX_64 = 18446744073709551615;  // 2^64 - 1
define RANGE_BOUND = 18446744073709551616;  // 2^64

// ============================================================================
// INVARIANT I1: Delegation Expiry Narrowing
// ============================================================================
// For all witnesses w where the proof verifies:
//   w.delegateeExpiry <= w.delegatorExpiry
// evaluated in Z (integers), NOT in F_p arithmetic.
//
// Rationale: A delegatee credential must never outlive the delegator's
// authority window. This is enforced by LessEqThan(64) at line 103-106
// of Delegation.circom. The integer interpretation is guaranteed because
// both inputs are range-checked to [0, 2^64) by Num2Bits(64) at lines 95-96.
// ============================================================================
invariant I1_delegatee_expiry_bounded {
    description: "delegateeExpiry <= delegatorExpiry in Z for all valid witnesses";
    
    forall witness w:
        circuit_accepts(w) =>
            to_integer(w.delegateeExpiry) <= to_integer(w.delegatorExpiry);
    
    proof_sketch: {
        // 1. Num2Bits(64) at line 95 constrains delegateeExpiry to [0, 2^64)
        // 2. Num2Bits(64) at line 93 constrains delegatorExpiry to [0, 2^64)
        // 3. LessEqThan(64) at line 103 enforces delegateeExpiry <= delegatorExpiry
        //    using the bit-decomposed values, so comparison is in Z not F_p
        // 4. Since both values are in [0, 2^64), the Z comparison is sound
    };
}

// ============================================================================
// INVARIANT I2: Expired Delegation Rejection
// ============================================================================
// For all witnesses w where the proof verifies:
//   w.delegateeExpiry > w.currentTimestamp
// i.e., expired delegatee credentials are always rejected.
//
// Rationale: Enforced by LessThan(64) at lines 110-113. The prover supplies
// currentTimestamp as a public input, and the circuit rejects if
// currentTimestamp >= delegateeExpiry. The verifier contract should
// additionally validate that currentTimestamp is within an acceptable
// window of block.timestamp.
// ============================================================================
invariant I2_expired_delegation_rejected {
    description: "delegateeExpiry > currentTimestamp for all valid witnesses";
    
    forall witness w:
        circuit_accepts(w) =>
            to_integer(w.delegateeExpiry) > to_integer(w.currentTimestamp);
    
    proof_sketch: {
        // 1. Num2Bits(64) at line 89 constrains currentTimestamp to [0, 2^64)
        // 2. Num2Bits(64) at line 95 constrains delegateeExpiry to [0, 2^64)
        // 3. LessThan(64) at line 110 enforces currentTimestamp < delegateeExpiry
        // 4. In [0, 2^64), LessThan is equivalent to integer < in Z
    };
}

// ============================================================================
// INVARIANT I3: Range-Checked Comparator Inputs
// ============================================================================
// The LessThan and LessEqThan comparators receive inputs that are
// range-checked to [0, 2^64) via Num2Bits(64) decomposition BEFORE
// comparison, ruling out field-element wraparound.
//
// Attack vector closed: Without range checks, a malicious prover could
// set delegateeExpiry = p - 1 (a huge field element). In F_p arithmetic:
//   p - 1 mod p = p - 1
// But LessThan operates on bit decomposition. If LessThan(64) receives
// a value >= 2^64 that has been reduced mod p, the bit decomposition
// would be of the reduced value, potentially allowing a wraparound
// where a large expiry appears small.
//
// The Num2Bits(64) constraint forces the input to have an exact 64-bit
// binary representation, which is only satisfiable for values in [0, 2^64).
// ============================================================================
invariant I3_range_checked_inputs {
    description: "LessThan/LessEqThan inputs are range-checked to [0, 2^64)";
    
    forall witness w:
        circuit_accepts(w) => (
            to_integer(w.currentTimestamp) >= 0 &&
            to_integer(w.currentTimestamp) < RANGE_BOUND &&
            to_integer(w.delegatorExpiry) >= 0 &&
            to_integer(w.delegatorExpiry) < RANGE_BOUND &&
            to_integer(w.delegateeExpiry) >= 0 &&
            to_integer(w.delegateeExpiry) < RANGE_BOUND
        );
    
    proof_sketch: {
        // Num2Bits(n) constrains: in = sum(bits[i] * 2^i) for i in [0,n)
        // Each bits[i] is constrained to {0, 1} via bits[i] * (bits[i] - 1) === 0
        // Therefore in must be in [0, 2^n) as an integer.
        // Since we use Num2Bits(64), the range is [0, 2^64).
        //
        // Lines 89-96 apply Num2Bits(64) to all three timestamp signals
        // BEFORE they reach the comparator components at lines 103, 110.
    };
}

// ============================================================================
// INVARIANT I4: Out-of-Range Witness Rejection
// ============================================================================
// No witness with delegateeExpiry >= 2^64 (as an integer in F_p) can
// satisfy the Num2Bits(64) range-check sub-circuit.
//
// This makes the comparator input domain provably bounded, closing the
// field-element wraparound attack vector completely.
// ============================================================================
invariant I4_out_of_range_rejection {
    description: "No witness with any expiry >= 2^64 can satisfy range check";
    
    forall witness w:
        (to_integer(w.delegateeExpiry) >= RANGE_BOUND ||
         to_integer(w.delegatorExpiry) >= RANGE_BOUND ||
         to_integer(w.currentTimestamp) >= RANGE_BOUND) =>
            !circuit_accepts(w);
    
    proof_sketch: {
        // Num2Bits(64) decomposes signal `in` into 64 binary bits.
        // Constraint: in === sum_{i=0}^{63} bits[i] * 2^i
        // Each bits[i] in {0,1}.
        //
        // Maximum representable value: sum_{i=0}^{63} 1 * 2^i = 2^64 - 1
        //
        // If in >= 2^64, then in cannot equal any sum of 64 binary digits,
        // so the constraint system is unsatisfiable.
        //
        // Note: in F_p, the prover cannot "wrap around" because the
        // constraint is in = sum(bits * 2^i) evaluated over F_p, and
        // 2^64 < p (since p ~ 2^254 for BN254). Therefore the only
        // field element satisfying the constraint is the unique integer
        // in [0, 2^64) matching the bit decomposition.
    };
}

// ============================================================================
// COMBINED SOUNDNESS THEOREM
// ============================================================================
// The conjunction of I1-I4 establishes:
//   For any valid proof produced by DelegationWithExpiry:
//   1. The delegatee's credential expires no later than the delegator's
//   2. The delegatee's credential has not yet expired
//   3. All temporal values are bounded 64-bit integers
//   4. No field arithmetic tricks can bypass these bounds
//
// This means delegation expiry narrowing is SOUND: a delegatee cannot
// extend their authority beyond the delegator's window, and cannot use
// an expired credential, regardless of adversarial witness construction.
// ============================================================================
theorem delegation_expiry_soundness {
    requires: I1_delegatee_expiry_bounded;
    requires: I2_expired_delegation_rejected;
    requires: I3_range_checked_inputs;
    requires: I4_out_of_range_rejection;
    
    ensures: forall witness w:
        circuit_accepts(w) => (
            0 <= to_integer(w.delegateeExpiry) < RANGE_BOUND &&
            0 <= to_integer(w.delegatorExpiry) < RANGE_BOUND &&
            0 <= to_integer(w.currentTimestamp) < RANGE_BOUND &&
            to_integer(w.delegateeExpiry) <= to_integer(w.delegatorExpiry) &&
            to_integer(w.currentTimestamp) < to_integer(w.delegateeExpiry)
        );
}
