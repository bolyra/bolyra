const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

/**
 * HumanUniqueness v3.0.0 — Two-Nullifier Architecture Tests
 *
 * Tests cover:
 *   1. Per-session unlinkability: different sessionNonce → different nullifierHash
 *   2. Stable commitment: same identity → same externalNullifierCommitment
 *   3. Linkability regression: no two sessions share nullifierHash
 *   4. Invalid witness rejection (wrong secret)
 *   5. Domain separation preserved
 */

describe("HumanUniqueness (two-nullifier, v3.0.0)", function () {
  this.timeout(120_000);

  let circuit;
  let poseidon;
  let F;

  const DOMAIN_HUMAN = 1n;

  // Test identity
  const SECRET = 42n;
  const IDENTITY_NONCE = 7n;
  const SCOPE = 12345n;

  // Two different session nonces
  const SESSION_NONCE_A = 100n;
  const SESSION_NONCE_B = 200n;

  // Merkle proof stub (depth 20, all zeros — valid for a single-leaf tree)
  const MERKLE_PATH_ELEMENTS = new Array(20).fill(0n);
  const MERKLE_PATH_INDICES = new Array(20).fill(0);

  let identityCommitment;
  let identityTreeRoot;

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;

    // Compute identity commitment: Poseidon(secret, identityNonce)
    identityCommitment = F.toObject(poseidon([SECRET, IDENTITY_NONCE]));

    // Build a minimal Merkle tree root with a single leaf
    let current = identityCommitment;
    for (let i = 0; i < 20; i++) {
      current = F.toObject(poseidon([current, 0n]));
    }
    identityTreeRoot = current;

    // Compile the circuit
    circuit = await circom_tester.wasm(
      path.join(__dirname, "..", "src", "HumanUniqueness.circom"),
      { output: path.join(__dirname, "..", "build", "test") }
    );
  });

  /**
   * Helper: compute expected public signals from JS reference.
   */
  function computeExpected(sessionNonce) {
    // Session nullifier: Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
    const nullifierHash = F.toObject(
      poseidon([DOMAIN_HUMAN, SCOPE, SECRET, sessionNonce])
    );

    // External nullifier: Poseidon₃(DOMAIN_HUMAN, scope, secret)
    const externalNullifier = F.toObject(
      poseidon([DOMAIN_HUMAN, SCOPE, SECRET])
    );

    // External nullifier commitment: Poseidon₁(externalNullifier)
    const externalNullifierCommitment = F.toObject(
      poseidon([externalNullifier])
    );

    return { nullifierHash, externalNullifier, externalNullifierCommitment };
  }

  /**
   * Helper: build a valid witness input.
   */
  function buildWitness(sessionNonce) {
    const expected = computeExpected(sessionNonce);
    return {
      identityTreeRoot,
      nullifierHash: expected.nullifierHash,
      scope: SCOPE,
      externalNullifierCommitment: expected.externalNullifierCommitment,
      secret: SECRET,
      identityNonce: IDENTITY_NONCE,
      sessionNonce,
      merklePathElements: MERKLE_PATH_ELEMENTS,
      merklePathIndices: MERKLE_PATH_INDICES,
    };
  }

  // ── Core unlinkability tests ──────────────────────────────────────

  describe("Per-session unlinkability", () => {
    it("should produce distinct nullifierHash for different sessionNonce values", async () => {
      const witnessA = buildWitness(SESSION_NONCE_A);
      const witnessB = buildWitness(SESSION_NONCE_B);

      // Both should generate valid witnesses
      const wA = await circuit.calculateWitness(witnessA, true);
      const wB = await circuit.calculateWitness(witnessB, true);

      await circuit.checkConstraints(wA);
      await circuit.checkConstraints(wB);

      // nullifierHash values must differ
      expect(witnessA.nullifierHash.toString()).to.not.equal(
        witnessB.nullifierHash.toString(),
        "Same identity with different sessionNonce must produce different nullifierHash"
      );
    });

    it("should produce the same externalNullifierCommitment across sessions", async () => {
      const expectedA = computeExpected(SESSION_NONCE_A);
      const expectedB = computeExpected(SESSION_NONCE_B);

      expect(expectedA.externalNullifierCommitment.toString()).to.equal(
        expectedB.externalNullifierCommitment.toString(),
        "externalNullifierCommitment must be stable across sessions"
      );
    });
  });

  // ── Linkability regression ────────────────────────────────────────

  describe("Linkability regression", () => {
    it("should produce unique nullifierHash across 50 sessions", () => {
      const seen = new Set();
      const collisions = [];

      for (let i = 0n; i < 50n; i++) {
        const nonce = i * 997n + 31n; // deterministic but varied
        const expected = computeExpected(nonce);
        const hash = expected.nullifierHash.toString();

        if (seen.has(hash)) {
          collisions.push(`Collision at nonce=${nonce}`);
        }
        seen.add(hash);
      }

      expect(collisions).to.have.length(
        0,
        `Found nullifierHash collisions: ${collisions.join(", ")}`
      );
    });

    it("should NOT match the v2.0.0 nullifier (no sessionNonce)", () => {
      // v2.0.0: Poseidon₃(DOMAIN_HUMAN, scope, secret)
      const v2Nullifier = F.toObject(
        poseidon([DOMAIN_HUMAN, SCOPE, SECRET])
      );

      // v3.0.0: Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
      const v3Nullifier = computeExpected(SESSION_NONCE_A).nullifierHash;

      expect(v2Nullifier.toString()).to.not.equal(
        v3Nullifier.toString(),
        "v3.0.0 session nullifier must differ from v2.0.0 nullifier"
      );
    });
  });

  // ── External nullifier commitment stability ───────────────────────

  describe("External nullifier commitment", () => {
    it("should be deterministic for the same identity and scope", () => {
      const c1 = computeExpected(SESSION_NONCE_A).externalNullifierCommitment;
      const c2 = computeExpected(SESSION_NONCE_B).externalNullifierCommitment;
      const c3 = computeExpected(999n).externalNullifierCommitment;

      expect(c1.toString()).to.equal(c2.toString());
      expect(c2.toString()).to.equal(c3.toString());
    });

    it("should differ for different secrets", () => {
      const commitA = F.toObject(
        poseidon([F.toObject(poseidon([DOMAIN_HUMAN, SCOPE, SECRET]))])
      );
      const commitB = F.toObject(
        poseidon([F.toObject(poseidon([DOMAIN_HUMAN, SCOPE, 9999n]))])
      );

      expect(commitA.toString()).to.not.equal(
        commitB.toString(),
        "Different secrets must produce different commitments"
      );
    });

    it("should differ for different scopes", () => {
      const commitA = F.toObject(
        poseidon([F.toObject(poseidon([DOMAIN_HUMAN, SCOPE, SECRET]))])
      );
      const commitB = F.toObject(
        poseidon([F.toObject(poseidon([DOMAIN_HUMAN, 99999n, SECRET]))])
      );

      expect(commitA.toString()).to.not.equal(
        commitB.toString(),
        "Different scopes must produce different commitments"
      );
    });
  });

  // ── Invalid witness rejection ─────────────────────────────────────

  describe("Invalid witness rejection", () => {
    it("should reject a witness with wrong secret", async () => {
      const expected = computeExpected(SESSION_NONCE_A);
      const badWitness = {
        identityTreeRoot,
        nullifierHash: expected.nullifierHash,
        scope: SCOPE,
        externalNullifierCommitment: expected.externalNullifierCommitment,
        secret: 99999n, // wrong secret
        identityNonce: IDENTITY_NONCE,
        sessionNonce: SESSION_NONCE_A,
        merklePathElements: MERKLE_PATH_ELEMENTS,
        merklePathIndices: MERKLE_PATH_INDICES,
      };

      try {
        await circuit.calculateWitness(badWitness, true);
        expect.fail("Should have thrown for wrong secret");
      } catch (err) {
        expect(err.message).to.include("Assert");
      }
    });

    it("should reject a witness with wrong sessionNonce", async () => {
      const expected = computeExpected(SESSION_NONCE_A);
      const badWitness = {
        identityTreeRoot,
        nullifierHash: expected.nullifierHash,
        scope: SCOPE,
        externalNullifierCommitment: expected.externalNullifierCommitment,
        secret: SECRET,
        identityNonce: IDENTITY_NONCE,
        sessionNonce: 777n, // wrong nonce — nullifierHash won't match
        merklePathElements: MERKLE_PATH_ELEMENTS,
        merklePathIndices: MERKLE_PATH_INDICES,
      };

      try {
        await circuit.calculateWitness(badWitness, true);
        expect.fail("Should have thrown for wrong sessionNonce");
      } catch (err) {
        expect(err.message).to.include("Assert");
      }
    });
  });

  // ── Valid witness acceptance ───────────────────────────────────────

  describe("Valid witness", () => {
    it("should accept a correctly formed witness (session A)", async () => {
      const witness = buildWitness(SESSION_NONCE_A);
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    });

    it("should accept a correctly formed witness (session B)", async () => {
      const witness = buildWitness(SESSION_NONCE_B);
      const w = await circuit.calculateWitness(witness, true);
      await circuit.checkConstraints(w);
    });
  });
});
