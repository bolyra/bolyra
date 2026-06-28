import { describe, it } from "mocha";
import { strict as assert } from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  ProofEnvelope,
  BolyraEnvelopeError,
  BOLYRA_PROOF_CONTENT_TYPE,
  ENVELOPE_VERSION,
} from "../src/proof-envelope.js";
import type { ProofEnvelopeData, CircuitId } from "../src/proof-envelope.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VECTORS_PATH = path.resolve(
  __dirname,
  "../../spec/test-vectors/proof-envelope-roundtrip.json",
);

interface TestVector {
  id: string;
  description: string;
  envelope: ProofEnvelopeData;
  canonicalJson: string;
}

function loadVectors(): TestVector[] {
  const raw = fs.readFileSync(VECTORS_PATH, "utf-8");
  return JSON.parse(raw).vectors;
}

function makeEnvelope(overrides?: Partial<ProofEnvelopeData>): ProofEnvelopeData {
  return {
    version: ENVELOPE_VERSION,
    circuit: "HumanUniqueness",
    publicSignals: ["123", "456", "789"],
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [
        ["3", "4"],
        ["5", "6"],
        ["1", "0"],
      ],
      pi_c: ["7", "8", "1"],
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ProofEnvelope", () => {
  describe("constants", () => {
    it("exports the correct MIME content type", () => {
      assert.equal(BOLYRA_PROOF_CONTENT_TYPE, "application/bolyra-proof+json");
    });

    it("exports version 1", () => {
      assert.equal(ENVELOPE_VERSION, "1");
    });
  });

  describe("serialize() / parse() round-trip", () => {
    it("round-trips a minimal envelope", () => {
      const env = new ProofEnvelope(makeEnvelope());
      const json = env.serialize();
      const parsed = ProofEnvelope.parse(json);
      assert.equal(parsed.serialize(), json);
    });

    it("round-trips an envelope with sessionToken", () => {
      const env = new ProofEnvelope(
        makeEnvelope({ sessionToken: "tok_abc123" }),
      );
      const json = env.serialize();
      const parsed = ProofEnvelope.parse(json);
      assert.equal(parsed.sessionToken, "tok_abc123");
      assert.equal(parsed.serialize(), json);
    });

    it("round-trips an envelope with delegationChain", () => {
      const env = new ProofEnvelope(
        makeEnvelope({
          circuit: "Delegation",
          delegationChain: [
            {
              delegatorCommitment: "111",
              delegateCommitment: "222",
              scopeMask: 255,
              expiry: 1719878400,
            },
          ],
        }),
      );
      const json = env.serialize();
      const parsed = ProofEnvelope.parse(json);
      assert.equal(parsed.delegationChain!.length, 1);
      assert.equal(parsed.serialize(), json);
    });
  });

  describe("test vector fidelity", () => {
    const vectors = loadVectors();

    for (const vec of vectors) {
      it(`produces canonical JSON for vector "${vec.id}"`, () => {
        const env = new ProofEnvelope(vec.envelope);
        assert.equal(env.serialize(), vec.canonicalJson);
      });

      it(`round-trips vector "${vec.id}"`, () => {
        const env = new ProofEnvelope(vec.envelope);
        const json = env.serialize();
        const parsed = ProofEnvelope.parse(json);
        assert.equal(parsed.serialize(), json);
      });
    }
  });

  describe("schema validation errors", () => {
    it("rejects unsupported version", () => {
      assert.throws(
        () => new ProofEnvelope(makeEnvelope({ version: "2" })),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError &&
          err.code === "UNSUPPORTED_VERSION",
      );
    });

    it("rejects unknown circuit", () => {
      assert.throws(
        () =>
          new ProofEnvelope(
            makeEnvelope({ circuit: "FooCircuit" as CircuitId }),
          ),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError &&
          err.code === "UNKNOWN_CIRCUIT",
      );
    });

    it("rejects empty publicSignals", () => {
      assert.throws(
        () => new ProofEnvelope(makeEnvelope({ publicSignals: [] })),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError &&
          err.code === "INVALID_PUBLIC_SIGNALS",
      );
    });

    it("rejects pi_a with wrong length", () => {
      assert.throws(
        () =>
          new ProofEnvelope(
            makeEnvelope({
              proof: {
                pi_a: ["1", "2"],
                pi_b: [
                  ["3", "4"],
                  ["5", "6"],
                  ["1", "0"],
                ],
                pi_c: ["7", "8", "1"],
              },
            }),
          ),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError && err.code === "INVALID_PROOF",
      );
    });

    it("rejects pi_b element with wrong inner length", () => {
      assert.throws(
        () =>
          new ProofEnvelope(
            makeEnvelope({
              proof: {
                pi_a: ["1", "2", "1"],
                pi_b: [
                  ["3", "4", "extra"],
                  ["5", "6"],
                  ["1", "0"],
                ],
                pi_c: ["7", "8", "1"],
              },
            }),
          ),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError && err.code === "INVALID_PROOF",
      );
    });

    it("rejects scopeMask out of range", () => {
      assert.throws(
        () =>
          new ProofEnvelope(
            makeEnvelope({
              circuit: "Delegation",
              delegationChain: [
                {
                  delegatorCommitment: "a",
                  delegateCommitment: "b",
                  scopeMask: 256,
                  expiry: 1719878400,
                },
              ],
            }),
          ),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError &&
          err.code === "INVALID_DELEGATION_CHAIN",
      );
    });

    it("rejects invalid JSON", () => {
      assert.throws(
        () => ProofEnvelope.parse("not json at all"),
        (err: unknown) =>
          err instanceof BolyraEnvelopeError && err.code === "INVALID_JSON",
      );
    });
  });

  describe("forward compatibility", () => {
    it("tolerates unknown top-level keys", () => {
      const env = new ProofEnvelope(makeEnvelope());
      const json = JSON.parse(env.serialize());
      json.futureField = "hello";
      const parsed = ProofEnvelope.parse(JSON.stringify(json));
      assert.equal(parsed.circuit, "HumanUniqueness");
    });
  });
});
