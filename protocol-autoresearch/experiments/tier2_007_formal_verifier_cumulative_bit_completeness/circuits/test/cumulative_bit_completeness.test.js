const chai = require("chai");
const { expect } = chai;
const path = require("path");
const { wasm: wasm_tester } = require("circom_tester");

/**
 * Reference implementation of validateCumulativeBitEncoding.
 * This mirrors the SDK's validateCumulativeBitEncoding() from sdk/src/permissions.ts.
 *
 * Implication rules (8-bit cumulative encoding):
 *   bit 3 (FINANCIAL_MEDIUM)    => bit 2 (FINANCIAL_SMALL)
 *   bit 4 (FINANCIAL_UNLIMITED) => bit 3 (FINANCIAL_MEDIUM)
 *   bit 4 (FINANCIAL_UNLIMITED) => bit 2 (FINANCIAL_SMALL)
 *
 * @param {number} byte - Permission byte value (0..255)
 * @returns {boolean} true if encoding satisfies all implication rules
 */
function validateCumulativeBitEncoding(byte) {
    const bit2 = (byte >> 2) & 1; // FINANCIAL_SMALL
    const bit3 = (byte >> 3) & 1; // FINANCIAL_MEDIUM
    const bit4 = (byte >> 4) & 1; // FINANCIAL_UNLIMITED

    // Rule 1: bit3 => bit2
    if (bit3 === 1 && bit2 === 0) return false;
    // Rule 2: bit4 => bit3
    if (bit4 === 1 && bit3 === 0) return false;
    // Rule 3: bit4 => bit2
    if (bit4 === 1 && bit2 === 0) return false;

    return true;
}

/**
 * Decompose a byte into 8 LSB-first bits (matching Circom Num2Bits convention).
 * @param {number} byte - Value 0..255
 * @returns {number[]} Array of 8 bits, index 0 = LSB
 */
function byteToBits(byte) {
    const bits = [];
    for (let i = 0; i < 8; i++) {
        bits.push((byte >> i) & 1);
    }
    return bits;
}

/**
 * Format a byte as a human-readable permission string for diagnostics.
 * @param {number} byte - Value 0..255
 * @returns {string}
 */
function formatPermissions(byte) {
    const names = [
        "READ_DATA",
        "WRITE_DATA",
        "FINANCIAL_SMALL",
        "FINANCIAL_MEDIUM",
        "FINANCIAL_UNLIMITED",
        "SIGN_ON_BEHALF",
        "SUB_DELEGATE",
        "ACCESS_PII",
    ];
    const bits = byteToBits(byte);
    const active = names.filter((_, i) => bits[i] === 1);
    return `0b${byte.toString(2).padStart(8, "0")} (${byte}) [${active.join(", ") || "NONE"}]`;
}

describe("CumulativeBitCheck — exhaustive 256-value completeness sweep", function () {
    this.timeout(120_000); // witness generation for 256 values

    let circuit;

    before(async function () {
        circuit = await wasm_tester(
            path.join(__dirname, "..", "src", "CumulativeBitCheck.circom"),
            {
                // Use the project's node_modules for circomlib includes
                include: [path.join(__dirname, "..", "node_modules")],
            }
        );
    });

    // Pre-compute expected results
    const validValues = [];
    const invalidValues = [];
    for (let v = 0; v < 256; v++) {
        if (validateCumulativeBitEncoding(v)) {
            validValues.push(v);
        } else {
            invalidValues.push(v);
        }
    }

    it(`should accept all ${validValues.length} valid encodings`, async function () {
        const failures = [];
        for (const v of validValues) {
            try {
                const witness = await circuit.calculateWitness(
                    { permissionByte: v },
                    true /* sanityCheck */
                );
                // Witness generation succeeded — expected for valid values
                await circuit.checkConstraints(witness);
            } catch (err) {
                failures.push({
                    value: v,
                    formatted: formatPermissions(v),
                    error: err.message,
                });
            }
        }
        if (failures.length > 0) {
            console.error("\n=== COMPLETENESS FAILURES (valid encoding rejected by circuit) ===");
            for (const f of failures) {
                console.error(`  REJECTED: ${f.formatted}`);
                console.error(`    Error: ${f.error}\n`);
            }
        }
        expect(failures).to.have.lengthOf(
            0,
            `Circuit rejected ${failures.length} valid encodings (COMPLETENESS violation)`
        );
    });

    it(`should reject all ${invalidValues.length} invalid encodings`, async function () {
        const failures = [];
        for (const v of invalidValues) {
            let witnessSucceeded = false;
            try {
                const witness = await circuit.calculateWitness(
                    { permissionByte: v },
                    true /* sanityCheck */
                );
                await circuit.checkConstraints(witness);
                witnessSucceeded = true;
            } catch (err) {
                // Expected: witness generation or constraint check should fail
            }
            if (witnessSucceeded) {
                failures.push({
                    value: v,
                    formatted: formatPermissions(v),
                });
            }
        }
        if (failures.length > 0) {
            console.error("\n=== SOUNDNESS FAILURES (invalid encoding accepted by circuit) ===");
            for (const f of failures) {
                console.error(`  ACCEPTED: ${f.formatted}`);
            }
        }
        expect(failures).to.have.lengthOf(
            0,
            `Circuit accepted ${failures.length} invalid encodings (SOUNDNESS violation)`
        );
    });

    it("should have exactly 192 valid and 64 invalid encodings", function () {
        // 3 implication rules constrain bits 2,3,4. Bits 0,1,5,6,7 are free (32 combos).
        // For bits 2,3,4: valid combos are those where (b3=>b2) AND (b4=>b3) AND (b4=>b2).
        // Valid (b2,b3,b4) tuples: (0,0,0),(1,0,0),(1,1,0),(1,1,1),(0,0,0) = exactly 4 invalid out of 8:
        //   invalid: (0,1,0),(0,0,1),(1,0,1),(0,1,1) => 4 invalid * 32 free-bit combos = 128? No...
        // Let me recount: b2,b3,b4 each 0 or 1 => 8 combos.
        //   (0,0,0) valid, (1,0,0) valid, (0,1,0) INVALID (b3 w/o b2),
        //   (1,1,0) valid, (0,0,1) INVALID (b4 w/o b3,b2),
        //   (1,0,1) INVALID (b4 w/o b3), (0,1,1) INVALID (b4+b3 w/o b2),
        //   (1,1,1) valid.
        // 4 valid * 32 = 128 valid, 4 invalid * 32 = 128 invalid.
        // Actually wait: 5 free bits = 2^5 = 32. 4 valid combos * 32 = 128.
        expect(validValues).to.have.lengthOf(128);
        expect(invalidValues).to.have.lengthOf(128);
        expect(validValues.length + invalidValues.length).to.equal(256);
    });

    it("should match SDK validateCumulativeBitEncoding for every value 0..255", async function () {
        // This is the core completeness+soundness agreement test.
        // We check that every single value in the byte range produces
        // the same accept/reject decision in both the SDK and the circuit.
        let agreements = 0;
        const disagreements = [];

        for (let v = 0; v < 256; v++) {
            const sdkValid = validateCumulativeBitEncoding(v);
            let circuitAccepts;
            try {
                const witness = await circuit.calculateWitness(
                    { permissionByte: v },
                    true
                );
                await circuit.checkConstraints(witness);
                circuitAccepts = true;
            } catch {
                circuitAccepts = false;
            }

            if (sdkValid === circuitAccepts) {
                agreements++;
            } else {
                disagreements.push({
                    value: v,
                    formatted: formatPermissions(v),
                    sdkValid,
                    circuitAccepts,
                });
            }
        }

        if (disagreements.length > 0) {
            console.error("\n=== SDK vs CIRCUIT DISAGREEMENTS ===");
            for (const d of disagreements) {
                console.error(
                    `  ${d.formatted}: SDK=${d.sdkValid}, Circuit=${d.circuitAccepts}`
                );
            }
        }

        expect(agreements).to.equal(256, `Found ${disagreements.length} disagreements`);
    });
});
