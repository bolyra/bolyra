/**
 * @file envelope.test.ts
 * @description Unit tests for the application/bolyra-proof+cbor envelope
 * encoder/decoder. Covers round-trip fidelity, version rejection,
 * circuit-id validation, arity checks, and truncated CBOR rejection.
 */

import { describe, it, expect } from "vitest";
import { encode as cborEncode } from "cbor-x";
import {
  encodeProofEnvelope,
  decodeProofEnvelope,
  envelopeToProofResult,
  buildContentType,
  ENVELOPE_VERSION,
  BOLYRA_PROOF_CONTENT_TYPE,
  CIRCUIT_SIGNAL_ARITY,
  type CircuitId,
  type ProvingSystem,
  type ProofResult,
} from "./envelope.js";

// ── Helpers ──────────────────────────────────────────────────────────

function makeProofResult(signalCount: number): ProofResult {
  return {
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],
      pi_c: ["7", "8", "1"],
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: Array.from({ length: signalCount }, (_, i) =>
      String(1000000000000000000n + BigInt(i))
    ),
  };
}

const CIRCUIT_COMBOS: Array<{ circuit: CircuitId; ps: ProvingSystem }> = [
  { circuit: "HumanUniqueness", ps: "groth16" },
  { circuit: "AgentPolicy", ps: "groth16" },
  { circuit: "AgentPolicy", ps: "plonk" },
  { circuit: "Delegation", ps: "groth16" },
  { circuit: "Delegation", ps: "plonk" },
];

// ── Round-trip tests ─────────────────────────────────────────────────

describe("Proof Envelope: round-trip", () => {
  for (const { circuit, ps } of CIRCUIT_COMBOS) {
    it(`${circuit}/${ps}: encode then decode preserves all fields`, () => {
      const arity = CIRCUIT_SIGNAL_ARITY[circuit];
      const proofResult = makeProofResult(arity);

      const encoded = encodeProofEnvelope(proofResult, circuit, ps);
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.length).toBeGreaterThan(0);

      const decoded = decodeProofEnvelope(encoded);
      expect(decoded.version).toBe(ENVELOPE_VERSION);
      expect(decoded.circuitId).toBe(circuit);
      expect(decoded.provingSystem).toBe(ps);
      expect(decoded.publicSignals).toEqual(proofResult.publicSignals);

      // Proof bytes round-trip to original object
      const restored = envelopeToProofResult(decoded);
      expect(restored.proof).toEqual(proofResult.proof);
      expect(restored.publicSignals).toEqual(proofResult.publicSignals);
    });
  }

  it("preserves metadata through round-trip", () => {
    const proofResult = makeProofResult(3);
    const nonce = new Uint8Array(32).fill(0xab);
    const metadata = { nonce, timestamp: 1750000000, chainId: 84532 };

    const encoded = encodeProofEnvelope(
      proofResult,
      "HumanUniqueness",
      "groth16",
      metadata
    );
    const decoded = decodeProofEnvelope(encoded);

    expect(decoded.metadata).toBeDefined();
    expect(decoded.metadata!.timestamp).toBe(1750000000);
    expect(decoded.metadata!.chainId).toBe(84532);
    expect(new Uint8Array(decoded.metadata!.nonce as Uint8Array)).toEqual(nonce);
  });
});

// ── Validation / rejection tests ─────────────────────────────────────

describe("Proof Envelope: validation", () => {
  it("rejects unknown envelope version", () => {
    const proofResult = makeProofResult(3);
    const encoded = encodeProofEnvelope(
      proofResult,
      "HumanUniqueness",
      "groth16"
    );

    // Tamper: re-encode with version 99
    const tampered = cborEncode({
      ...Object.fromEntries(
        Object.entries(
          (() => {
            const d = decodeProofEnvelope(encoded);
            return { ...d };
          })()
        )
      ),
      version: 99,
    });

    expect(() => decodeProofEnvelope(tampered)).toThrow(
      /Unsupported envelope version 99/
    );
  });

  it("rejects unknown circuit ID", () => {
    const raw = cborEncode({
      version: 1,
      circuitId: "FakeCircuit",
      provingSystem: "groth16",
      proof: new Uint8Array([1, 2, 3]),
      publicSignals: ["1", "2", "3"],
    });

    expect(() => decodeProofEnvelope(raw)).toThrow(/Unknown circuit ID/);
  });

  it("rejects unknown proving system", () => {
    const raw = cborEncode({
      version: 1,
      circuitId: "HumanUniqueness",
      provingSystem: "nova",
      proof: new Uint8Array([1, 2, 3]),
      publicSignals: ["1", "2", "3"],
    });

    expect(() => decodeProofEnvelope(raw)).toThrow(/Unknown proving system/);
  });

  it("rejects wrong signal arity for HumanUniqueness", () => {
    const raw = cborEncode({
      version: 1,
      circuitId: "HumanUniqueness",
      provingSystem: "groth16",
      proof: new Uint8Array([1, 2, 3]),
      publicSignals: ["1", "2"], // expects 3
    });

    expect(() => decodeProofEnvelope(raw)).toThrow(
      /expects 3 public signals, got 2/
    );
  });

  it("rejects wrong signal arity for AgentPolicy", () => {
    const raw = cborEncode({
      version: 1,
      circuitId: "AgentPolicy",
      provingSystem: "groth16",
      proof: new Uint8Array([1, 2, 3]),
      publicSignals: ["1", "2", "3"], // expects 4
    });

    expect(() => decodeProofEnvelope(raw)).toThrow(
      /expects 4 public signals, got 3/
    );
  });

  it("rejects truncated CBOR", () => {
    const proofResult = makeProofResult(3);
    const encoded = encodeProofEnvelope(
      proofResult,
      "HumanUniqueness",
      "groth16"
    );

    // Truncate to half
    const truncated = encoded.slice(0, Math.floor(encoded.length / 2));
    expect(() => decodeProofEnvelope(truncated)).toThrow(
      /Failed to decode CBOR/
    );
  });

  it("rejects empty buffer", () => {
    expect(() => decodeProofEnvelope(new Uint8Array(0))).toThrow();
  });

  it("rejects non-map CBOR (array)", () => {
    const raw = cborEncode([1, 2, 3]);
    expect(() => decodeProofEnvelope(raw)).toThrow(/must be a CBOR map/);
  });

  it("rejects missing version field", () => {
    const raw = cborEncode({
      circuitId: "HumanUniqueness",
      provingSystem: "groth16",
      proof: new Uint8Array([1]),
      publicSignals: ["1", "2", "3"],
    });
    expect(() => decodeProofEnvelope(raw)).toThrow(/version/);
  });

  it("rejects non-string public signal entries", () => {
    const raw = cborEncode({
      version: 1,
      circuitId: "HumanUniqueness",
      provingSystem: "groth16",
      proof: new Uint8Array([1]),
      publicSignals: ["1", 2, "3"], // index 1 is number, not string
    });
    expect(() => decodeProofEnvelope(raw)).toThrow(/publicSignals\[1\] must be a string/);
  });
});

// ── Content-Type builder ─────────────────────────────────────────────

describe("Proof Envelope: Content-Type", () => {
  it("builds correct Content-Type header", () => {
    const ct = buildContentType("AgentPolicy", "groth16");
    expect(ct).toBe(
      `${BOLYRA_PROOF_CONTENT_TYPE}; circuit=AgentPolicy; ps=groth16; v=${ENVELOPE_VERSION}`
    );
  });

  it("builds Content-Type for plonk", () => {
    const ct = buildContentType("Delegation", "plonk");
    expect(ct).toContain("ps=plonk");
    expect(ct).toContain("circuit=Delegation");
  });
});

// ── Encoder input validation ─────────────────────────────────────────

describe("Proof Envelope: encoder validation", () => {
  it("rejects invalid circuit ID on encode", () => {
    const proofResult = makeProofResult(3);
    expect(() =>
      encodeProofEnvelope(
        proofResult,
        "BadCircuit" as CircuitId,
        "groth16"
      )
    ).toThrow(/Unknown circuit ID/);
  });

  it("rejects invalid proving system on encode", () => {
    const proofResult = makeProofResult(3);
    expect(() =>
      encodeProofEnvelope(
        proofResult,
        "HumanUniqueness",
        "nova" as ProvingSystem
      )
    ).toThrow(/Unknown proving system/);
  });
});
