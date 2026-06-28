const { expect } = require("chai");
const path = require("path");
const { wasm: wasmTester } = require("circom_tester");

// Test the MerkleDepthGuard template in isolation via lightweight wrapper
// circuits.  Integration coverage (guard wired into HumanUniqueness,
// AgentPolicy, Delegation) is handled by the existing circuit test suites;
// here we focus on the boundary values of the depth range check.

const FIXTURES = path.join(__dirname, "fixtures");

// ---------- MAX_DEPTH = 20 (Semaphore v4 / main circuits) ----------

describe("MerkleDepthGuard (MAX_DEPTH=20)", function () {
    this.timeout(60_000);

    let circuit;

    before(async function () {
        circuit = await wasmTester(
            path.join(FIXTURES, "MerkleDepthGuardTest.circom"),
            {
                include: [
                    path.join(__dirname, "..", "node_modules"),
                    path.join(__dirname, "..", "src"),
                ],
            }
        );
    });

    // =========================================================
    // Attack vector: depth=0 (leaf-as-root bypass)
    // =========================================================

    it("should reject depth=0 (leaf-as-root bypass)", async function () {
        try {
            await circuit.calculateWitness({ depth: 0 }, true);
            expect.fail("Expected witness generation to fail for depth=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Upper bound: depth=MAX_DEPTH+1 must fail
    // =========================================================

    it("should reject depth=MAX_DEPTH+1 (21)", async function () {
        try {
            await circuit.calculateWitness({ depth: 21 }, true);
            expect.fail(
                "Expected witness generation to fail for depth=MAX_DEPTH+1"
            );
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Large out-of-range value
    // =========================================================

    it("should reject depth=255", async function () {
        try {
            await circuit.calculateWitness({ depth: 255 }, true);
            expect.fail("Expected witness generation to fail for depth=255");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    // =========================================================
    // Valid boundary: depth=1 (single-sibling proof)
    // =========================================================

    it("should accept depth=1 (minimum valid)", async function () {
        const witness = await circuit.calculateWitness({ depth: 1 }, true);
        await circuit.assertOut(witness, { ok: 1 });
    });

    // =========================================================
    // Valid boundary: depth=MAX_DEPTH
    // =========================================================

    it("should accept depth=MAX_DEPTH (20)", async function () {
        const witness = await circuit.calculateWitness({ depth: 20 }, true);
        await circuit.assertOut(witness, { ok: 1 });
    });

    // =========================================================
    // Mid-range sanity check
    // =========================================================

    it("should accept depth=10 (mid-range)", async function () {
        const witness = await circuit.calculateWitness({ depth: 10 }, true);
        await circuit.assertOut(witness, { ok: 1 });
    });
});

// ---------- MAX_DEPTH = 16 (alternative tree depth) ----------

describe("MerkleDepthGuard (MAX_DEPTH=16)", function () {
    this.timeout(60_000);

    let circuit16;

    before(async function () {
        circuit16 = await wasmTester(
            path.join(FIXTURES, "MerkleDepthGuardTest16.circom"),
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
            await circuit16.calculateWitness({ depth: 0 }, true);
            expect.fail("Expected failure for depth=0");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should reject depth=17 (MAX_DEPTH+1)", async function () {
        try {
            await circuit16.calculateWitness({ depth: 17 }, true);
            expect.fail("Expected failure for depth=17");
        } catch (err) {
            expect(err.message).to.match(/assert|constraint|Error/i);
        }
    });

    it("should accept depth=1", async function () {
        const witness = await circuit16.calculateWitness({ depth: 1 }, true);
        await circuit16.assertOut(witness, { ok: 1 });
    });

    it("should accept depth=16", async function () {
        const witness = await circuit16.calculateWitness({ depth: 16 }, true);
        await circuit16.assertOut(witness, { ok: 1 });
    });
});
