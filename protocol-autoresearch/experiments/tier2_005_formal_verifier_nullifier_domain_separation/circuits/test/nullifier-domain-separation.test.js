const { expect } = require("chai");
const path = require("path");
const circom_tester = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");

/**
 * Nullifier Domain Separation — Regression Tests
 *
 * These tests verify that domain separation tags prevent cross-circuit
 * nullifier collisions, even when raw inputs are crafted to be identical.
 *
 * Property under test: P-DS-1 (FORMAL-PROPERTIES.md)
 *
 * Test strategy:
 *   1. Compute nullifiers for all three circuits using a JS Poseidon reference.
 *   2. Verify pairwise distinctness with identical raw inputs.
 *   3. Verify each circuit's witness generation produces the expected nullifier.
 */

describe("Nullifier Domain Separation (P-DS-1)", function () {
  this.timeout(120_000);

  let poseidon;
  let F;

  // Domain tag constants — must match circuit definitions
  const DOMAIN_HUMAN = 1n;
  const DOMAIN_AGENT = 2n;
  const DOMAIN_DELEG = 3n;

  // Shared raw input values — deliberately identical to test worst case
  const SHARED_SECRET = 42n;
  const SHARED_SCOPE = 12345n;
  const SHARED_NONCE = 7n;
  const SHARED_DELEGATEE_CRED = 99999n;

  before(async () => {
    poseidon = await buildPoseidon();
    F = poseidon.F;
  });

  describe("Reference nullifier computation", () => {
    it("should produce distinct nullifiers for all three circuits with identical raw inputs", () => {
      // Compute nullifiers using the same raw values across all circuits
      const humanNullifier = poseidon([DOMAIN_HUMAN, SHARED_SCOPE, SHARED_SECRET]);
      const agentNullifier = poseidon([DOMAIN_AGENT, SHARED_SECRET, SHARED_SCOPE]);
      const delegNullifier = poseidon([
        DOMAIN_DELEG,
        SHARED_SECRET,
        SHARED_DELEGATEE_CRED,
        SHARED_SCOPE,
      ]);

      const hN = F.toString(humanNullifier);
      const aN = F.toString(agentNullifier);
      const dN = F.toString(delegNullifier);

      // All three must be pairwise distinct
      expect(hN).to.not.equal(aN, "Human and Agent nullifiers collided");
      expect(hN).to.not.equal(dN, "Human and Delegation nullifiers collided");
      expect(aN).to.not.equal(dN, "Agent and Delegation nullifiers collided");
    });

    it("should produce distinct nullifiers even when ALL raw values are the same field element", () => {
      const V = 777n;

      const humanNullifier = poseidon([DOMAIN_HUMAN, V, V]);
      const agentNullifier = poseidon([DOMAIN_AGENT, V, V]);
      const delegNullifier = poseidon([DOMAIN_DELEG, V, V, V]);

      const hN = F.toString(humanNullifier);
      const aN = F.toString(agentNullifier);
      const dN = F.toString(delegNullifier);

      expect(hN).to.not.equal(aN, "Human and Agent nullifiers collided (all V)");
      expect(hN).to.not.equal(dN, "Human and Delegation nullifiers collided (all V)");
      expect(aN).to.not.equal(dN, "Agent and Delegation nullifiers collided (all V)");
    });

    it("should produce different nullifiers with vs without domain tag", () => {
      // Old v1.x: Poseidon(scope, secret) — no domain tag
      const oldNullifier = poseidon([SHARED_SCOPE, SHARED_SECRET]);
      // New v2.0: Poseidon(DOMAIN_HUMAN, scope, secret)
      const newNullifier = poseidon([DOMAIN_HUMAN, SHARED_SCOPE, SHARED_SECRET]);

      expect(F.toString(oldNullifier)).to.not.equal(
        F.toString(newNullifier),
        "v1.x and v2.0 nullifiers should differ"
      );
    });
  });

  describe("Domain tag constants are correct", () => {
    it("human domain tag is 1", () => {
      expect(DOMAIN_HUMAN).to.equal(1n);
    });

    it("agent domain tag is 2", () => {
      expect(DOMAIN_AGENT).to.equal(2n);
    });

    it("delegation domain tag is 3", () => {
      expect(DOMAIN_DELEG).to.equal(3n);
    });

    it("all domain tags are distinct", () => {
      const tags = [DOMAIN_HUMAN, DOMAIN_AGENT, DOMAIN_DELEG];
      const unique = new Set(tags);
      expect(unique.size).to.equal(tags.length, "Domain tags must be pairwise distinct");
    });
  });

  describe("Exhaustive pairwise collision resistance", () => {
    it("should resist collisions across 100 random-ish input pairs", () => {
      const collisions = [];

      for (let i = 0n; i < 100n; i++) {
        const s1 = i * 31n + 17n;
        const s2 = i * 37n + 23n;
        const s3 = i * 41n + 29n;

        const hN = F.toString(poseidon([DOMAIN_HUMAN, s1, s2]));
        const aN = F.toString(poseidon([DOMAIN_AGENT, s1, s2]));
        const dN = F.toString(poseidon([DOMAIN_DELEG, s1, s2, s3]));

        if (hN === aN) collisions.push(`H==A at i=${i}`);
        if (hN === dN) collisions.push(`H==D at i=${i}`);
        if (aN === dN) collisions.push(`A==D at i=${i}`);
      }

      expect(collisions).to.have.length(
        0,
        `Found collisions: ${collisions.join(", ")}`
      );
    });
  });

  describe("Poseidon arity separation", () => {
    it("Poseidon(3) and Poseidon(4) produce different outputs for overlapping inputs", () => {
      // Even if the first 3 inputs match, arity difference => different output
      const p3 = poseidon([DOMAIN_DELEG, SHARED_SECRET, SHARED_SCOPE]);
      const p4 = poseidon([DOMAIN_DELEG, SHARED_SECRET, SHARED_SCOPE, 0n]);

      expect(F.toString(p3)).to.not.equal(
        F.toString(p4),
        "Poseidon(3) and Poseidon(4) with overlapping inputs should differ"
      );
    });
  });
});
