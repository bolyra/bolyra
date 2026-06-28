const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

// We test against a minimal wrapper circuit that only instantiates
// RangeCheckDepth so we can isolate the depth check logic.
// For integration tests, the existing circuit test suites cover
// HumanUniqueness, AgentPolicy, Delegation, and ModelInstanceBinding.

const CIRCUIT_DIR = path.join(__dirname, "..", "src", "lib");
const TEST_CIRCUIT_DIR = path.join(__dirname, "fixtures");

describe("MerkleDepthBound", function () {
    this.timeout(60_000);

    let circuit;

    before(async function () {
        // Compile a test-only wrapper: RangeCheckDepthTest(20)
        circuit = await wasmTester(
            path.join(TEST_CIRCUIT_DIR, "RangeCheckDepthTest.circom"),
            {
                include: [
                    path.join(__dirname, "..", "node_modules"),
                    path.join(__dirname, "..", "src"),
                ],
            }
        );
    });

    // =========================================================
    // Negative cases (witness generation must fail)
    // =========================================================

    it("should reject depth=0 (witness generation fails)", async function () {
        try {
            await circuit.calculateWitness(
                { merkleProofLength: 0 },
                true // sanityCheck
            );
            expect.fail("Expected witness generation to fail for depth=0");
        } catch (err) {
            // circom_tester throws when constraints are not satisfied
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject depth=MAX_DEPTH+1 (witness generation fails)", async function () {
        try {
            await circuit.calculateWitness(
                { merkleProofLength: 21 }, // MAX_DEPTH=20, so 21 is out of range
                true
            );
            expect.fail(
                "Expected witness generation to fail for depth=MAX_DEPTH+1"
            );
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject large depth values", async function () {
        try {
            await circuit.calculateWitness(
                { merkleProofLength: 255 },
                true
            );
            expect.fail(
                "Expected witness generation to fail for depth=255"
            );
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Positive boundary cases (witness generation must succeed)
    // =========================================================

    it("should accept depth=1 (minimum valid)", async function () {
        const witness = await circuit.calculateWitness(
            { merkleProofLength: 1 },
            true
        );
        // Output signal 'valid' should be 1
        await circuit.assertOut(witness, { valid: 1 });
    });

    it("should accept depth=MAX_DEPTH (maximum valid)", async function () {
        const witness = await circuit.calculateWitness(
            { merkleProofLength: 20 }, // MAX_DEPTH=20
            true
        );
        await circuit.assertOut(witness, { valid: 1 });
    });

    it("should accept depth=10 (mid-range)", async function () {
        const witness = await circuit.calculateWitness(
            { merkleProofLength: 10 },
            true
        );
        await circuit.assertOut(witness, { valid: 1 });
    });

    // =========================================================
    // Full proof test (gated on FULL_PROOF=1)
    // =========================================================

    if (process.env.FULL_PROOF === "1") {
        const snarkjs = require("snarkjs");

        describe("Full Groth16 proof", function () {
            this.timeout(120_000);

            it("should generate and verify a valid proof for depth=10", async function () {
                const wasmPath = path.join(
                    TEST_CIRCUIT_DIR,
                    "RangeCheckDepthTest_js",
                    "RangeCheckDepthTest.wasm"
                );
                const zkeyPath = path.join(
                    __dirname,
                    "..",
                    "build",
                    "RangeCheckDepthTest.zkey"
                );

                const { proof, publicSignals } =
                    await snarkjs.groth16.fullProve(
                        { merkleProofLength: 10 },
                        wasmPath,
                        zkeyPath
                    );

                const vkeyPath = path.join(
                    __dirname,
                    "..",
                    "build",
                    "RangeCheckDepthTest.vkey.json"
                );
                const vkey = require(vkeyPath);
                const isValid = await snarkjs.groth16.verify(
                    vkey,
                    publicSignals,
                    proof
                );
                expect(isValid).to.be.true;
            });

            it("should not produce a valid proof for depth=0", async function () {
                // This test verifies that even if someone tries to
                // craft a proof with depth=0, verification fails.
                // Since witness generation fails, we just confirm that.
                try {
                    const wasmPath = path.join(
                        TEST_CIRCUIT_DIR,
                        "RangeCheckDepthTest_js",
                        "RangeCheckDepthTest.wasm"
                    );
                    const zkeyPath = path.join(
                        __dirname,
                        "..",
                        "build",
                        "RangeCheckDepthTest.zkey"
                    );
                    await snarkjs.groth16.fullProve(
                        { merkleProofLength: 0 },
                        wasmPath,
                        zkeyPath
                    );
                    expect.fail("Should not produce proof for depth=0");
                } catch (err) {
                    expect(err.message).to.match(/assert|constraint|Error/i);
                }
            });
        });
    }
});

// =========================================================
// Test for ModelInstanceBinding MAX_DEPTH=16
// =========================================================
describe("MerkleDepthBound (MAX_DEPTH=16)", function () {
    this.timeout(60_000);

    let circuit16;

    before(async function () {
        circuit16 = await wasmTester(
            path.join(TEST_CIRCUIT_DIR, "RangeCheckDepthTest16.circom"),
            {
                include: [
                    path.join(__dirname, "..", "node_modules"),
                    path.join(__dirname, "..", "src"),
                ],
            }
        );
    });

    it("should reject depth=0", async function () {
        try {
            await circuit16.calculateWitness({ merkleProofLength: 0 }, true);
            expect.fail("Expected failure for depth=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject depth=17 (MAX_DEPTH+1)", async function () {
        try {
            await circuit16.calculateWitness({ merkleProofLength: 17 }, true);
            expect.fail("Expected failure for depth=17");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should accept depth=1", async function () {
        const witness = await circuit16.calculateWitness(
            { merkleProofLength: 1 },
            true
        );
        await circuit16.assertOut(witness, { valid: 1 });
    });

    it("should accept depth=16", async function () {
        const witness = await circuit16.calculateWitness(
            { merkleProofLength: 16 },
            true
        );
        await circuit16.assertOut(witness, { valid: 1 });
    });
});
