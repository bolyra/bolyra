pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// @title  RangeCheckDepth
/// @notice Constrains 1 <= merkleProofLength <= MAX_DEPTH.
///         Uses Num2Bits to range-check bit-width, then two LessThan
///         comparators for the lower and upper bounds.
/// @param  MAX_DEPTH  The maximum allowed Merkle proof depth (inclusive).
template RangeCheckDepth(MAX_DEPTH) {
    signal input merkleProofLength;
    signal output valid;

    // Number of bits needed to represent MAX_DEPTH + 1
    // (so LessThan can compare up to MAX_DEPTH + 1 without overflow)
    var NUM_BITS = 1;
    var tmp = MAX_DEPTH + 1;
    while ((1 << NUM_BITS) <= tmp) {
        NUM_BITS++;
    }

    // Constrain merkleProofLength to fit in NUM_BITS bits (implicitly >= 0)
    component n2b = Num2Bits(NUM_BITS);
    n2b.in <== merkleProofLength;

    // --- Lower bound: merkleProofLength >= 1 ---
    // Equivalent to: 0 < merkleProofLength, i.e. LessThan(0, merkleProofLength)
    component lowerBound = LessThan(NUM_BITS);
    lowerBound.in[0] <== 0;
    lowerBound.in[1] <== merkleProofLength;
    // lowerBound.out === 1 iff 0 < merkleProofLength

    // --- Upper bound: merkleProofLength <= MAX_DEPTH ---
    // Equivalent to: merkleProofLength < MAX_DEPTH + 1
    component upperBound = LessThan(NUM_BITS);
    upperBound.in[0] <== merkleProofLength;
    upperBound.in[1] <== MAX_DEPTH + 1;
    // upperBound.out === 1 iff merkleProofLength < MAX_DEPTH + 1

    // Both conditions must hold
    valid <== lowerBound.out * upperBound.out;
}
