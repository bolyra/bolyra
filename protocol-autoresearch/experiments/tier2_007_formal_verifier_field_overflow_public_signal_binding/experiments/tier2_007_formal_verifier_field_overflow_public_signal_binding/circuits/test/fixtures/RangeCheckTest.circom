pragma circom 2.1.0;

include "../../src/RangeChecks.circom";

/// @notice Minimal test wrapper that exposes a single RangeCheck(253).
///         Used by range_checks.test.js to verify field-overflow rejection
///         without compiling the full circuits.
template RangeCheckTest() {
    signal input in;
    component rc = RangeCheck(253);
    rc.in <== in;
}

component main = RangeCheckTest();
