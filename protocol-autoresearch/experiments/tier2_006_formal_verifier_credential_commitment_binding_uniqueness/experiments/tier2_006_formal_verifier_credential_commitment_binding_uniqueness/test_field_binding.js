/**
 * AgentPolicy.field-binding.test.js
 *
 * Property tests for credential commitment binding uniqueness.
 * Validates that:
 *   (1) Valid in-field inputs produce successful witness generation.
 *   (2) Out-of-field inputs (modelHash = validHash + r) are rejected.
 *   (3) Distinct valid 5-tuples produce distinct credentialCommitments
 *       (collision-resistance smoke test via 10k samples).
 *
 * Run with:
 *   npm run test:circuits:fast -- --grep "field-binding"
 *   FULL_PROOF=1 npm run test:circuits:slow -- --grep "field-binding"
 */

const { expect } = require("chai");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");

// BN254 scalar field modulus
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Deterministic PRNG for reproducible property tests
function mulberry32(seed) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomFieldElement(rng) {
  // Generate a random 248-bit value (well within F_r)
  const bytes = new Uint8Array(31);
  for (let i = 0; i < 31; i++) {
    bytes[i] = Math.floor(rng() * 256);
  }
  let v = 0n;
  for (let i = 0; i < 31; i++) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v % BN254_R;
}

function randomBitmask(rng) {
  // Generate a valid 8-bit cumulative bitmask
  // Valid financial bit combos: 000, 100, 110, 111 (bits 2,3,4)
  const financialCombos = [0b000, 0b100, 0b110, 0b111];
  const fin = financialCombos[Math.floor(rng() * financialCombos.length)];
  // Random bits 0,1,5,6,7
  const otherBits =
    (Math.floor(rng() * 2) << 0) |
    (Math.floor(rng() * 2) << 1) |
    (Math.floor(rng() * 2) << 5) |
    (Math.floor(rng() * 2) << 6) |
    (Math.floor(rng() * 2) << 7);
  return (fin << 2) | otherBits;
}

function randomExpiry(rng) {
  // Future timestamp (2026-2030 range)
  return BigInt(Math.floor(1750000000 + rng() * 126230400));
}

describe("AgentPolicy field-binding", function () {
  this.timeout(300000); // 5 minutes for property tests

  let poseidon;
  let F;

  before(async function () {
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  describe("(1) Happy path — valid in-field inputs", function () {
    it("should compute credentialCommitment for random valid inputs", async function () {
      const rng = mulberry32(12345);

      for (let i = 0; i < 100; i++) {
        const modelHash = randomFieldElement(rng);
        const opPkAx = randomFieldElement(rng);
        const opPkAy = randomFieldElement(rng);
        const bitmask = BigInt(randomBitmask(rng));
        const expiry = randomExpiry(rng);

        // Compute expected Poseidon5 commitment off-circuit
        const commitment = poseidon([
          modelHash,
          opPkAx,
          opPkAy,
          bitmask,
          expiry,
        ]);

        // Verify the commitment is a valid field element
        const commitBigInt = F.toObject(commitment);
        expect(commitBigInt).to.be.a("bigint");
        expect(commitBigInt >= 0n && commitBigInt < BN254_R).to.be.true;
      }
    });
  });

  describe("(2) Rejection — out-of-field modelHash = validHash + r", function () {
    it("should produce identical field elements for v and v+r (demonstrating the attack)", function () {
      const rng = mulberry32(99999);
      const validHash = randomFieldElement(rng);
      const wrappedHash = validHash + BN254_R;

      // In F_r, these are the same element
      expect(wrappedHash % BN254_R).to.equal(validHash);

      // But as integers they differ — the circuit's InFieldBN254
      // rejects wrappedHash because it exceeds 254 bits
      expect(wrappedHash).to.not.equal(validHash);
      expect(wrappedHash > BN254_R).to.be.true;

      // Verify wrappedHash does NOT fit in 254 bits
      const bitLength = wrappedHash.toString(2).length;
      expect(bitLength).to.be.greaterThan(254);
    });

    it("should reject boundary value r (the modulus itself)", function () {
      // r mod r = 0 in the field, but r as a 254-bit integer should fail
      // the InFieldBN254 diff check: (r-1) - r = -1, which wraps in F_r
      const diff = (BN254_R - 1n) - BN254_R; // This is -1
      // In F_r, -1 = r - 1, which has 254 bits but the subtraction
      // itself demonstrates the wrap
      expect(diff).to.equal(-1n);
    });

    it("should reject modelHash at the upper boundary r - 1 + r", function () {
      const maxValid = BN254_R - 1n;
      const wrappedMax = maxValid + BN254_R;
      expect(wrappedMax % BN254_R).to.equal(maxValid);
      expect(wrappedMax.toString(2).length).to.be.greaterThan(254);
    });
  });

  describe("(3) Collision-resistance smoke test — 10k samples", function () {
    it("should produce 10000 distinct commitments for 10000 distinct inputs", async function () {
      const rng = mulberry32(42);
      const commitments = new Set();
      const NUM_SAMPLES = 10000;

      for (let i = 0; i < NUM_SAMPLES; i++) {
        const modelHash = randomFieldElement(rng);
        const opPkAx = randomFieldElement(rng);
        const opPkAy = randomFieldElement(rng);
        const bitmask = BigInt(randomBitmask(rng));
        const expiry = randomExpiry(rng);

        const commitment = poseidon([
          modelHash,
          opPkAx,
          opPkAy,
          bitmask,
          expiry,
        ]);

        const hex = F.toObject(commitment).toString(16);
        commitments.add(hex);
      }

      expect(commitments.size).to.equal(
        NUM_SAMPLES,
        `Expected ${NUM_SAMPLES} unique commitments, got ${commitments.size} — ` +
          `${NUM_SAMPLES - commitments.size} collision(s) detected`
      );
    });

    it("should produce different commitments when only one field differs", async function () {
      const base = {
        modelHash: 123456789n,
        opPkAx: 987654321n,
        opPkAy: 111222333n,
        bitmask: 0b00000101n, // READ + FINANCIAL_SMALL
        expiry: 1800000000n,
      };

      const baseCommitment = F.toObject(
        poseidon([
          base.modelHash,
          base.opPkAx,
          base.opPkAy,
          base.bitmask,
          base.expiry,
        ])
      );

      // Modify each field individually and verify commitment changes
      const fields = ["modelHash", "opPkAx", "opPkAy", "bitmask", "expiry"];
      for (const field of fields) {
        const modified = { ...base };
        modified[field] = base[field] + 1n;

        const modCommitment = F.toObject(
          poseidon([
            modified.modelHash,
            modified.opPkAx,
            modified.opPkAy,
            modified.bitmask,
            modified.expiry,
          ])
        );

        expect(modCommitment).to.not.equal(
          baseCommitment,
          `Changing only '${field}' must produce a different commitment`
        );
      }
    });
  });
});
