pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";

// CumulativeBitCheck: standalone sub-circuit that enforces the cumulative-bit
// implication rules on an 8-bit permission byte.
//
// Bit index (LSB-first, matches Num2Bits convention):
//   0 = READ_DATA
//   1 = WRITE_DATA
//   2 = FINANCIAL_SMALL       (< $100)
//   3 = FINANCIAL_MEDIUM      (< $10K) — implies bit 2
//   4 = FINANCIAL_UNLIMITED   — implies bits 2 + 3
//   5 = SIGN_ON_BEHALF
//   6 = SUB_DELEGATE
//   7 = ACCESS_PII
//
// Implication rules enforced:
//   Rule 1: bit[3] => bit[2]   (FINANCIAL_MEDIUM => FINANCIAL_SMALL)
//   Rule 2: bit[4] => bit[3]   (FINANCIAL_UNLIMITED => FINANCIAL_MEDIUM)
//   Rule 3: bit[4] => bit[2]   (FINANCIAL_UNLIMITED => FINANCIAL_SMALL)
//
// Each rule is encoded as: high_bit * (1 - low_bit) === 0
// If high_bit is 1 and low_bit is 0, the product is 1 which violates the constraint.
// If high_bit is 0, the product is 0 regardless of low_bit (no constraint).
// If low_bit is 1, the product is 0 regardless of high_bit (satisfied).
//
// Total constraints: 3 multiplication gates + 3 equality checks = ~6 R1CS constraints
// (plus 8 binary-enforcement constraints if permBits are not already constrained binary)

template CumulativeBitCheck() {
    // Input: 8 individual permission bits (must already be binary-constrained)
    // The caller is responsible for binary enforcement (e.g., via Num2Bits).
    // permBits[0] = LSB = READ_DATA, permBits[7] = MSB = ACCESS_PII
    signal input permBits[8];

    // Rule 1: FINANCIAL_MEDIUM (bit 3) implies FINANCIAL_SMALL (bit 2)
    // bit[3] * (1 - bit[2]) === 0
    signal rule1;
    rule1 <== permBits[3] * (1 - permBits[2]);
    rule1 === 0;

    // Rule 2: FINANCIAL_UNLIMITED (bit 4) implies FINANCIAL_MEDIUM (bit 3)
    // bit[4] * (1 - bit[3]) === 0
    signal rule2;
    rule2 <== permBits[4] * (1 - permBits[3]);
    rule2 === 0;

    // Rule 3: FINANCIAL_UNLIMITED (bit 4) implies FINANCIAL_SMALL (bit 2)
    // bit[4] * (1 - bit[2]) === 0
    // Note: This is technically implied by rules 1+2 together, but we enforce
    // it explicitly for defense-in-depth and to match the SDK validator.
    signal rule3;
    rule3 <== permBits[4] * (1 - permBits[2]);
    rule3 === 0;
}

// Wrapper template that accepts a single integer input (0..255) and
// decomposes it to bits before checking. Used for standalone testing.
template CumulativeBitCheckByte() {
    signal input permissionByte;

    // Decompose to 8 bits (LSB-first, matching circomlib Num2Bits)
    signal bits[8];
    var lc = 0;
    for (var i = 0; i < 8; i++) {
        bits[i] <-- (permissionByte >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;  // binary constraint
        lc += bits[i] * (1 << i);
    }
    lc === permissionByte;  // reconstruction constraint

    // Apply cumulative-bit implication rules
    component check = CumulativeBitCheck();
    for (var i = 0; i < 8; i++) {
        check.permBits[i] <== bits[i];
    }
}

component main = CumulativeBitCheckByte();
