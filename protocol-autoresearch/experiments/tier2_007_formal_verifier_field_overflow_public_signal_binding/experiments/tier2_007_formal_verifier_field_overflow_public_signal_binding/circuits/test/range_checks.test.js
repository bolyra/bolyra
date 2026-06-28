const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

// ---------------------------------------------------------------------------
// P-RANGE-FIELD: Public signal canonical field element checks
//
// Tests that RangeCheck(253) correctly constrains public inputs to
// [0, 2^253 - 1], rejecting values >= BN254 r (modular aliasing).
// Uses a minimal RangeCheckTest wrapper to avoid full-circuit overhead.
// ---------------------------------------------------------------------------

const TEST_FIXTURE_DIR = path.join(__dirname, "fixtures");
const INCLUDE_PATHS = [
    path.join(__dirname, "..", "node_modules"),
    path.join(__dirname, "..", "src"),
];

// BN254 scalar field order r
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// 2^253 - 1: maximum value that fits in 253 bits
const MAX_253 = (1n << 253n) - 1n;

describe("P-RANGE-FIELD: RangeCheck(253) canonical field element", function () {
    this.timeout(120_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(TEST_FIXTURE_DIR, "RangeCheckTest.circom"),
            { include: INCLUDE_PATHS }
        );
    });

    // =========================================================
    // Valid boundary values
    // =========================================================

    it("should accept in = 0 (minimum valid value)", async function () {
        const witness = await circuit.calculateWitness({ in: "0" }, true);
        expect(witness).to.not.be.null;
    });

    it("should accept in = 1 (trivial non-zero)", async function () {
        const witness = await circuit.calculateWitness({ in: "1" }, true);
        expect(witness).to.not.be.null;
    });

    it("should accept in = 2^253 - 1 (maximum 253-bit value)", async function () {
        const witness = await circuit.calculateWitness(
            { in: MAX_253.toString() },
            true
        );
        expect(witness).to.not.be.null;
    });

    it("should accept in = 2^252 (mid-range large value)", async function () {
        const mid = (1n << 252n).toString();
        const witness = await circuit.calculateWitness({ in: mid }, true);
        expect(witness).to.not.be.null;
    });

    // =========================================================
    // Invalid values: field overflow / aliasing
    // =========================================================

    it("should REJECT in = 2^253 (one bit too large)", async function () {
        const overflow = (1n << 253n).toString();
        try {
            await circuit.calculateWitness({ in: overflow }, true);
            expect.fail("Expected constraint failure for in = 2^253");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT in = BN254_r (field modulus — aliases to 0)", async function () {
        try {
            await circuit.calculateWitness(
                { in: BN254_R.toString() },
                true
            );
            expect.fail("Expected constraint failure for in = BN254_r");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT in = BN254_r + 1 (aliases to 1)", async function () {
        try {
            await circuit.calculateWitness(
                { in: (BN254_R + 1n).toString() },
                true
            );
            expect.fail("Expected constraint failure for in = BN254_r + 1");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT in = BN254_r + 42 (arbitrary aliased offset)", async function () {
        try {
            await circuit.calculateWitness(
                { in: (BN254_R + 42n).toString() },
                true
            );
            expect.fail(
                "Expected constraint failure for in = BN254_r + 42"
            );
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT in = BN254_r - 1 (r-1 > 2^253-1, still overflows 253 bits)", async function () {
        // r - 1 is ~2^254, which exceeds 2^253 - 1
        try {
            await circuit.calculateWitness(
                { in: (BN254_R - 1n).toString() },
                true
            );
            expect.fail("Expected constraint failure for in = BN254_r - 1");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT in = 2^254 (well beyond 253-bit range)", async function () {
        const big = (1n << 254n).toString();
        try {
            await circuit.calculateWitness({ in: big }, true);
            expect.fail("Expected constraint failure for in = 2^254");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });
});
