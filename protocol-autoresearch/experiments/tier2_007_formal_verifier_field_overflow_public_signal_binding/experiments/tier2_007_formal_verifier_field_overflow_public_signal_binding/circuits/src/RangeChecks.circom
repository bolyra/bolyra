pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/bitify.circom";

/// @title  RangeCheck
/// @notice Decomposes `in` into `n` bits via Num2Bits(n), enforcing
///         0 <= in < 2^n.  For n=253 on the BN254 curve this guarantees
///         the value is a canonical field element (< r ~= 2^254), closing
///         the modular-aliasing attack class where a prover submits
///         x + r instead of x.
template RangeCheck(n) {
    signal input in;
    component bits = Num2Bits(n);
    bits.in <== in;
}
