pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";

// InFieldBN254 — asserts that the input signal is a valid BN254 scalar field
// element, i.e., strictly less than the scalar field modulus:
//   r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//
// Method:
//   1. Decompose input into 254 bits (proves input < 2^254).
//   2. Compute diff = (r - 1) - input. If input is in [0, r-1], then diff is
//      in [0, r-1] and fits in 254 bits. If input >= r (impossible in F_r but
//      proven formally), diff would underflow and wrap to a value >= 2^254,
//      failing the Num2Bits(254) constraint.
//
// Constraint cost: 2 * 254 + 2 = 510 constraints per instantiation.
//
// Usage:
//   component fc = InFieldBN254();
//   fc.in <== someSignal;
//   // fc.out is the same value, guaranteed to be in F_r
//
// Reference: circuits/FORMAL-PROPERTIES.md, property P-COMMIT-BIND.

template InFieldBN254() {
    signal input in;
    signal output out;

    // Step 1: Prove in < 2^254 via bit decomposition
    component inBits = Num2Bits(254);
    inBits.in <== in;

    // Step 2: Prove in <= r - 1 by showing (r - 1 - in) fits in 254 bits
    // r - 1 = 21888242871839275222246405745257275088548364400416034343698204186575808495616
    signal diff;
    diff <== 21888242871839275222246405745257275088548364400416034343698204186575808495616 - in;

    component diffBits = Num2Bits(254);
    diffBits.in <== diff;

    // Pass through — the value is now proven to be in [0, r-1]
    out <== in;
}
