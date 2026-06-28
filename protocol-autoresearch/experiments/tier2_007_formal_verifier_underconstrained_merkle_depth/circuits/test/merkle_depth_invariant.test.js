const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

// ---------------------------------------------------------------------------
// P-DEPTH-01: merkleProofLength === TREE_DEPTH
//
// We test against a minimal wrapper circuit (DepthExactTest.circom) that
// instantiates the exact-equality constraint and a BinaryMerkleRoot to
// verify the constraint rejects all non-TREE_DEPTH values.
// ---------------------------------------------------------------------------

const TEST_FIXTURE_DIR = path.join(__dirname, "fixtures");
const INCLUDE_PATHS = [
    path.join(__dirname, "..", "node_modules"),
    path.join(__dirname, "..", "src"),
];

const TREE_DEPTH = 20;

// Helper: build a trivial Merkle proof of exactly `depth` siblings.
// For a zero-value tree, all siblings are 0 and all indices are 0.
function zeroMerkleWitness(depth, maxDepth) {
    const siblings = new Array(maxDepth).fill("0");
    const indices = new Array(maxDepth).fill("0");
    return {
        merkleProofLength: depth,
        merkleProofSiblings: siblings,
        merkleProofIndices: indices,
        // The leaf is the Poseidon(identitySecret) — for the test wrapper
        // we use a dummy leaf input directly.
        leaf: "0",
    };
}

describe("P-DEPTH-01: merkleProofLength === TREE_DEPTH", function () {
    this.timeout(120_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(TEST_FIXTURE_DIR, "DepthExactTest.circom"),
            { include: INCLUDE_PATHS }
        );
    });

    // =========================================================
    // Case 1: Valid proof at full depth succeeds
    // =========================================================
    it("should accept witness with merkleProofLength === TREE_DEPTH (20)", async function () {
        const input = zeroMerkleWitness(TREE_DEPTH, TREE_DEPTH);
        const witness = await circuit.calculateWitness(input, true);
        expect(witness).to.not.be.null;
    });

    // =========================================================
    // Case 2: merkleProofLength < TREE_DEPTH is rejected
    // =========================================================
    it("should reject witness with merkleProofLength < TREE_DEPTH (depth=19)", async function () {
        const input = zeroMerkleWitness(TREE_DEPTH - 1, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=19");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject witness with merkleProofLength = 0", async function () {
        const input = zeroMerkleWitness(0, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject witness with merkleProofLength = 1", async function () {
        const input = zeroMerkleWitness(1, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=1");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject witness with merkleProofLength = 10 (mid-range subtree)", async function () {
        const input = zeroMerkleWitness(10, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=10");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Case 3: merkleProofLength > TREE_DEPTH is rejected
    // =========================================================
    it("should reject witness with merkleProofLength > TREE_DEPTH (depth=21)", async function () {
        const input = zeroMerkleWitness(TREE_DEPTH + 1, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=21");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject witness with merkleProofLength = 255", async function () {
        const input = zeroMerkleWitness(255, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail("Expected witness generation to fail for depth=255");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Case 4: Subtree-root replay attack vector
    // =========================================================
    it("should reject subtree-root replay (depth=5 against intermediate node)", async function () {
        // Simulates an attacker who knows a valid intermediate node at
        // depth 5 and tries to prove membership with a truncated path.
        const input = zeroMerkleWitness(5, TREE_DEPTH);
        try {
            await circuit.calculateWitness(input, true);
            expect.fail(
                "Expected witness generation to fail for subtree-root replay at depth=5"
            );
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Full proof test (gated on FULL_PROOF=1)
    // =========================================================
    if (process.env.FULL_PROOF === "1") {
        const snarkjs = require("snarkjs");

        describe("Full Groth16 proof (slow)", function () {
            this.timeout(300_000);

            it("should generate and verify a valid proof at TREE_DEPTH=20", async function () {
                const wasmPath = path.join(
                    TEST_FIXTURE_DIR,
                    "DepthExactTest_js",
                    "DepthExactTest.wasm"
                );
                const zkeyPath = path.join(
                    __dirname,
                    "..",
                    "build",
                    "DepthExactTest.zkey"
                );

                const input = zeroMerkleWitness(TREE_DEPTH, TREE_DEPTH);
                const { proof, publicSignals } =
                    await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);

                const vkeyPath = path.join(
                    __dirname,
                    "..",
                    "build",
                    "DepthExactTest.vkey.json"
                );
                const vkey = require(vkeyPath);
                const isValid = await snarkjs.groth16.verify(
                    vkey,
                    publicSignals,
                    proof
                );
                expect(isValid).to.be.true;
            });

            it("should not produce a valid proof for depth=19", async function () {
                const wasmPath = path.join(
                    TEST_FIXTURE_DIR,
                    "DepthExactTest_js",
                    "DepthExactTest.wasm"
                );
                const zkeyPath = path.join(
                    __dirname,
                    "..",
                    "build",
                    "DepthExactTest.zkey"
                );

                const input = zeroMerkleWitness(TREE_DEPTH - 1, TREE_DEPTH);
                try {
                    await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
                    expect.fail("Should not produce proof for depth=19");
                } catch (err) {
                    expect(err.message).to.match(/assert|constraint|Error/i);
                }
            });
        });
    }
});
