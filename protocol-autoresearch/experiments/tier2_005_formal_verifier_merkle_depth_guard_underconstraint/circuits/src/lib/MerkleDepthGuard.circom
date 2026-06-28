pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// @title  MerkleDepthGuard
/// @notice Constrains 1 <= depth <= MAX_DEPTH using Num2Bits for bit-width
///         range-limiting, GreaterEqThan for the lower bound, and LessEqThan
///         for the upper bound.  Both comparator outputs are wired to === 1
///         constraints so that out-of-range depth values abort witness
///         generation.
///
/// @dev    Attack vector closed: without this guard, depth=0 causes
///         BinaryMerkleRoot to return the leaf itself as the root, allowing
///         any arbitrary commitment to trivially "prove" membership against
///         a root equal to itself.
///
/// @param  MAX_DEPTH  The maximum allowed Merkle proof depth (inclusive).
///                    For HumanUniqueness this is 20 (Semaphore v4 ceremony);
///                    other circuits may use different values.
template MerkleDepthGuard(MAX_DEPTH) {
    signal input depth;

    // Bit-width needed to represent values up to MAX_DEPTH (inclusive).
    // ceil(log2(MAX_DEPTH + 1)) ensures both bounds and the value itself
    // fit without overflow in the comparator circuits.
    var NUM_BITS = 1;
    var tmp = MAX_DEPTH;
    while ((1 << NUM_BITS) <= tmp) {
        NUM_BITS++;
    }

    // Range-limit depth to NUM_BITS bits (implicitly constrains >= 0
    // and < 2^NUM_BITS, which prevents field-element wrapping attacks).
    component n2b = Num2Bits(NUM_BITS);
    n2b.in <== depth;

    // --- Lower bound: depth >= 1 ---
    component lowerBound = GreaterEqThan(NUM_BITS);
    lowerBound.in[0] <== depth;
    lowerBound.in[1] <== 1;
    lowerBound.out === 1;

    // --- Upper bound: depth <= MAX_DEPTH ---
    component upperBound = LessEqThan(NUM_BITS);
    upperBound.in[0] <== depth;
    upperBound.in[1] <== MAX_DEPTH;
    upperBound.out === 1;
}
