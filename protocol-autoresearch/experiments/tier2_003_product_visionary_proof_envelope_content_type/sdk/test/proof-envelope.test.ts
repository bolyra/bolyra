/**
 * @file proof-envelope.test.ts
 * @description Unit tests for the application/bolyra-proof+cbor envelope.
 * Covers round-trip fidelity, malformed input rejection, forward compatibility,
 * delegation chain, and size comparison vs raw JSON.
 */

import { describe, it, expect } from "vitest";
import { encode as cborEncode } from "cbor-x";
import {
  encode,
  decode,
  buildContentType,
  CONTENT_TYPE,
  ENVELOPE_VERSION,
  ProofEnvelopeError,
  type ProofEnvelope,
  type CircuitId,
  type ProvingSystem,
} from "../src/proof-envelope.js";

// ── Helpers ──────────────────────────────────────────────────────────

function makeEnvelope(overrides?: Partial<ProofEnvelope>): ProofEnvelope {
  return {
    version: ENVELOPE_VERSION,
    circuitId: "HumanUniqueness",
    provingSystem: "groth16",
    proofBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]),
    publicSignals: ["1000000000000000000", "2000000000000000000", "3000000000000000000"],
    ...overrides,
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

describe("ProofEnvelope: round-trip", () => {
  for (const { circuit, ps } of CIRCUIT_COMBOS) {
    it(`${circuit}/${ps}: encode then decode preserves all fields`, () => {
      const envelope = makeEnvelope({ circuitId: circuit, provingSystem: ps });
      const encoded = encode(envelope);
      expect(encoded).toBeInstanceOf(Uint8Array);
      expect(encoded.length).toBeGreaterThan(0);

      const decoded = decode(encoded);
      expect(decoded.version).toBe(ENVELOPE_VERSION);
      expect(decoded.circuitId).toBe(circuit);
      expect(decoded.provingSystem).toBe(ps);
      expect(decoded.publicSignals).toEqual(envelope.publicSignals);
      expect(new Uint8Array(decoded.proofBytes)).toEqual(envelope.proofBytes);
    });
  }

  it("preserves delegation chain through round-trip", () => {
    const chain = [
      { data: new Uint8Array([0x01, 0x02, 0x03]) },
      { data: new Uint8Array([0x04, 0x05, 0x06]) },
    ];
    const envelope = makeEnvelope({ delegationChain: chain });
    const decoded = decode(encode(envelope));

    expect(decoded.delegationChain).toBeDefined();
    expect(decoded.delegationChain!.length).toBe(2);
    expect(new Uint8Array(decoded.delegationChain![0].data)).toEqual(chain[0].data);
    expect(new Uint8Array(decoded.delegationChain![1].data)).toEqual(chain[1].data);
  });

  it("omits delegationChain when not provided", () => {
    const envelope = makeEnvelope();
    const decoded = decode(encode(envelope));
    expect(decoded.delegationChain).toBeUndefined();
  });
});

// ── Forward compatibility ────────────────────────────────────────────

describe("ProofEnvelope: forward compatibility", () => {
  it("ignores unknown future keys in CBOR map", () => {
    const envelope = makeEnvelope();
    const encoded = encode(envelope);

    // Manually decode, add an unknown key (99), and re-encode
    const map = new Map<number, unknown>();
    map.set(1, ENVELOPE_VERSION);
    map.set(2, "HumanUniqueness");
    map.set(3, "groth16");
    map.set(4, envelope.proofBytes);
    map.set(5, [...envelope.publicSignals]);
    map.set(99, "future-field-value"); // unknown key

    const tamperedBytes = cborEncode(map);
    const decoded = decode(tamperedBytes);

    expect(decoded.version).toBe(ENVELOPE_VERSION);
    expect(decoded.circuitId).toBe("HumanUniqueness");
    expect(decoded.provingSystem).toBe("groth16");
  });
});

// ── Validation / rejection tests ─────────────────────────────────────

describe("ProofEnvelope: decode validation", () => {
  it("rejects empty buffer", () => {
    expect(() => decode(new Uint8Array(0))).toThrow(ProofEnvelopeError);
  });

  it("rejects truncated CBOR", () => {
    const encoded = encode(makeEnvelope());
    const truncated = encoded.slice(0, Math.floor(encoded.length / 2));
    expect(() => decode(truncated)).toThrow(/CBOR_DECODE_FAILED/);
  });

  it("rejects non-map CBOR (array)", () => {
    const raw = cborEncode([1, 2, 3]);
    expect(() => decode(raw)).toThrow(/INVALID_STRUCTURE/);
  });

  it("rejects unsupported envelope version", () => {
    const map = new Map<number, unknown>();
    map.set(1, 99);
    map.set(2, "HumanUniqueness");
    map.set(3, "groth16");
    map.set(4, new Uint8Array([1]));
    map.set(5, ["1"]);
    expect(() => decode(cborEncode(map))).toThrow(/UNSUPPORTED_VERSION/);
  });

  it("rejects unknown circuit ID", () => {
    const map = new Map<number, unknown>();
    map.set(1, 1);
    map.set(2, "FakeCircuit");
    map.set(3, "groth16");
    map.set(4, new Uint8Array([1]));
    map.set(5, ["1"]);
    expect(() => decode(cborEncode(map))).toThrow(/UNKNOWN_CIRCUIT_ID/);
  });

  it("rejects unknown proving system", () => {
    const map = new Map<number, unknown>();
    map.set(1, 1);
    map.set(2, "HumanUniqueness");
    map.set(3, "nova");
    map.set(4, new Uint8Array([1]));
    map.set(5, ["1"]);
    expect(() => decode(cborEncode(map))).toThrow(/UNKNOWN_PROVING_SYSTEM/);
  });

  it("rejects empty proofBytes", () => {
    const map = new Map<number, unknown>();
    map.set(1, 1);
    map.set(2, "HumanUniqueness");
    map.set(3, "groth16");
    map.set(4, new Uint8Array(0));
    map.set(5, ["1"]);
    expect(() => decode(cborEncode(map))).toThrow(/EMPTY_PROOF/);
  });

  it("rejects non-string public signal entries", () => {
    const map = new Map<number, unknown>();
    map.set(1, 1);
    map.set(2, "HumanUniqueness");
    map.set(3, "groth16");
    map.set(4, new Uint8Array([1]));
    map.set(5, ["1", 2, "3"]);
    expect(() => decode(cborEncode(map))).toThrow(/INVALID_SIGNAL_TYPE/);
  });

  it("rejects missing version field", () => {
    const map = new Map<number, unknown>();
    map.set(2, "HumanUniqueness");
    map.set(3, "groth16");
    map.set(4, new Uint8Array([1]));
    map.set(5, ["1"]);
    expect(() => decode(cborEncode(map))).toThrow(/INVALID_VERSION/);
  });

  it("rejects delegation chain exceeding max depth", () => {
    const chain = Array.from({ length: 9 }, () => ({
      data: new Uint8Array([0x01]),
    }));
    expect(() => encode(makeEnvelope({ delegationChain: chain }))).toThrow(
      /DELEGATION_TOO_DEEP/
    );
  });
});

// ── Encode validation ────────────────────────────────────────────────

describe("ProofEnvelope: encode validation", () => {
  it("rejects invalid circuit ID on encode", () => {
    expect(() =>
      encode(makeEnvelope({ circuitId: "BadCircuit" as CircuitId }))
    ).toThrow(/UNKNOWN_CIRCUIT_ID/);
  });

  it("rejects invalid proving system on encode", () => {
    expect(() =>
      encode(makeEnvelope({ provingSystem: "nova" as ProvingSystem }))
    ).toThrow(/UNKNOWN_PROVING_SYSTEM/);
  });
});

// ── Content-Type builder ─────────────────────────────────────────────

describe("ProofEnvelope: Content-Type", () => {
  it("builds correct Content-Type header", () => {
    const ct = buildContentType("AgentPolicy", "groth16");
    expect(ct).toBe(
      `${CONTENT_TYPE}; circuit=AgentPolicy; ps=groth16; v=${ENVELOPE_VERSION}`
    );
  });

  it("builds Content-Type for plonk", () => {
    const ct = buildContentType("Delegation", "plonk");
    expect(ct).toContain("ps=plonk");
    expect(ct).toContain("circuit=Delegation");
  });
});

// ── Size benchmark ───────────────────────────────────────────────────

describe("ProofEnvelope: size efficiency", () => {
  it("CBOR envelope is smaller than equivalent JSON", () => {
    const envelope = makeEnvelope({
      proofBytes: new Uint8Array(256).fill(0xaa),
      publicSignals: Array.from({ length: 5 }, (_, i) =>
        String(1000000000000000000n + BigInt(i))
      ),
    });

    const cborBytes = encode(envelope);

    const jsonEquiv = JSON.stringify({
      version: envelope.version,
      circuitId: envelope.circuitId,
      provingSystem: envelope.provingSystem,
      proofBytes: Array.from(envelope.proofBytes),
      publicSignals: envelope.publicSignals,
    });
    const jsonBytes = new TextEncoder().encode(jsonEquiv);

    // CBOR should be meaningfully smaller than JSON for binary data
    expect(cborBytes.length).toBeLessThan(jsonBytes.length);
  });

  it("encoded envelope does not exceed 2x raw proof bytes", () => {
    const proofBytes = new Uint8Array(512).fill(0xbb);
    const envelope = makeEnvelope({ proofBytes });
    const encoded = encode(envelope);

    // Overhead should be modest — envelope < 2x the raw proof
    expect(encoded.length).toBeLessThan(proofBytes.length * 2);
  });
});
