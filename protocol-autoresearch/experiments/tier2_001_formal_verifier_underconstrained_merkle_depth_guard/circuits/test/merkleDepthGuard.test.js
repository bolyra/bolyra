const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

// ---------------------------------------------------------------------------
// P-RANGE-DEPTH: 1 <= merkleProofLength <= MAX_DEPTH
//
// Tests the Num2Bits + LessThan range-check constraints that guard
// BinaryMerkleRoot against under-constrained merkleProofLength values.
// Uses minimal wrapper circuits (DepthGuardTest, DepthGuardTest16) to
// avoid compiling full circuits with EdDSA / Poseidon overhead.
// ---------------------------------------------------------------------------

const TEST_FIXTURE_DIR = path.join(__dirname, "fixtures");
const INCLUDE_PATHS = [
    path.join(__dirname, "..", "node_modules"),
    path.join(__dirname, "..", "src"),
];

// Helper: build a trivial zero-value Merkle witness.
function zeroMerkleWitness(depth, maxDepth) {
    return {
        leaf: "0",
        merkleProofLength: depth,
        merkleProofSiblings: new Array(maxDepth).fill("0"),
        merkleProofIndices: new Array(maxDepth).fill("0"),
    };
}

// =========================================================
// Suite 1: HumanUniqueness-style (TREE_DEPTH = 20)
// =========================================================
describe("P-RANGE-DEPTH: merkleProofLength guard (TREE_DEPTH=20)", function () {
    this.timeout(120_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(TEST_FIXTURE_DIR, "DepthGuardTest.circom"),
            { include: INCLUDE_PATHS }
        );
    });

    it("should accept witness with merkleProofLength = 20 (full depth)", async function () {
        const input = zeroMerkleWitness(20, 20);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    it("should accept witness with merkleProofLength = 1 (minimum valid)", async function () {
        const input = zeroMerkleWitness(1, 20);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    it("should accept witness with merkleProofLength = 10 (mid-range)", async function () {
        const input = zeroMerkleWitness(10, 20);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    it("should REJECT merkleProofLength = 0 (leaf-as-root attack)", async function () {
        const input = zeroMerkleWitness(0, 20);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT merkleProofLength = 21 (MAX_DEPTH + 1)", async function () {
        const input = zeroMerkleWitness(21, 20);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=21");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT merkleProofLength = 31 (max 5-bit value)", async function () {
        const input = zeroMerkleWitness(31, 20);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=31");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT merkleProofLength = 32 (overflows 5-bit Num2Bits)", async function () {
        const input = zeroMerkleWitness(32, 20);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=32");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });
});

// =========================================================
// Suite 2: ModelInstanceBinding-style (MAX_DEPTH = 16)
// =========================================================
describe("P-RANGE-DEPTH: merkleProofLength guard (MAX_DEPTH=16)", function () {
    this.timeout(120_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(TEST_FIXTURE_DIR, "DepthGuardTest16.circom"),
            { include: INCLUDE_PATHS }
        );
    });

    it("should accept witness with merkleProofLength = 16 (full depth)", async function () {
        const input = zeroMerkleWitness(16, 16);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    it("should accept witness with merkleProofLength = 1 (minimum valid)", async function () {
        const input = zeroMerkleWitness(1, 16);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    it("should REJECT merkleProofLength = 0 (leaf-as-root attack)", async function () {
        const input = zeroMerkleWitness(0, 16);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should REJECT merkleProofLength = 17 (MAX_DEPTH + 1)", async function () {
        const input = zeroMerkleWitness(17, 16);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected constraint failure for merkleProofLength=17");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });
});
