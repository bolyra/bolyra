import { describe, it } from 'mocha';
import { expect } from 'chai';
import {
  encodeProofEnvelope,
  decodeProofEnvelope,
  proofEnvelopeToJSON,
  proofEnvelopeFromJSON,
  negotiateProofContentType,
  CircuitId,
  ProvingSystem,
  ENVELOPE_VERSION,
  CONTENT_TYPE_CBOR,
  CONTENT_TYPE_JSON,
} from '../src/envelope.js';
import type { ProofEnvelope } from '../src/types/envelope.js';

/* ------------------------------------------------------------------ */
/*  Fixtures                                                          */
/* ------------------------------------------------------------------ */

const DUMMY_GROTH16_PROOF = {
  pi_a: ['1', '2', '1'],
  pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
  pi_c: ['7', '8', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};

const DUMMY_PLONK_PROOF = {
  A: ['1', '2'],
  B: ['3', '4'],
  C: ['5', '6'],
  Z: ['7', '8'],
  protocol: 'plonk',
  curve: 'bn128',
};

const DUMMY_PUBLIC_SIGNALS = [
  '12345678901234567890',
  '98765432109876543210',
  '11111111111111111111',
];

function makeEnvelope(
  circuit: CircuitId,
  provingSystem: ProvingSystem,
  metadata?: Record<string, string>
): ProofEnvelope {
  return {
    version: ENVELOPE_VERSION,
    circuit,
    provingSystem,
    proof: provingSystem === ProvingSystem.Groth16 ? DUMMY_GROTH16_PROOF : DUMMY_PLONK_PROOF,
    publicSignals: DUMMY_PUBLIC_SIGNALS,
    ...(metadata ? { metadata } : {}),
  };
}

/* ------------------------------------------------------------------ */
/*  CBOR round-trip                                                   */
/* ------------------------------------------------------------------ */

describe('ProofEnvelope CBOR codec', () => {
  const circuits: CircuitId[] = [
    CircuitId.Human,
    CircuitId.Agent,
    CircuitId.Delegation,
    CircuitId.ModelInstance,
  ];
  const provingSystems: ProvingSystem[] = [
    ProvingSystem.Groth16,
    ProvingSystem.PLONK,
  ];

  for (const circuit of circuits) {
    for (const ps of provingSystems) {
      it(`round-trips CircuitId=${CircuitId[circuit]} x ProvingSystem=${ProvingSystem[ps]}`, () => {
        const original = makeEnvelope(circuit, ps);
        const encoded = encodeProofEnvelope(original);

        // Version prefix check
        expect(encoded[0]).to.equal(0x00);
        expect(encoded[1]).to.equal(0x01);

        const decoded = decodeProofEnvelope(encoded);
        expect(decoded.version).to.equal(ENVELOPE_VERSION);
        expect(decoded.circuit).to.equal(circuit);
        expect(decoded.provingSystem).to.equal(ps);
        expect(decoded.publicSignals).to.deep.equal(DUMMY_PUBLIC_SIGNALS);
        expect(decoded.proof).to.deep.equal(original.proof);
      });
    }
  }

  it('preserves optional metadata', () => {
    const original = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16, {
      createdAt: '2026-06-20T00:00:00Z',
      correlationId: 'test-123',
    });
    const decoded = decodeProofEnvelope(encodeProofEnvelope(original));
    expect(decoded.metadata).to.deep.equal(original.metadata);
  });

  it('omits metadata key when not provided', () => {
    const original = makeEnvelope(CircuitId.Agent, ProvingSystem.PLONK);
    const decoded = decodeProofEnvelope(encodeProofEnvelope(original));
    expect(decoded.metadata).to.be.undefined;
  });
});

/* ------------------------------------------------------------------ */
/*  Validation: negative tests                                        */
/* ------------------------------------------------------------------ */

describe('ProofEnvelope validation', () => {
  it('rejects unknown version prefix', () => {
    const encoded = encodeProofEnvelope(
      makeEnvelope(CircuitId.Human, ProvingSystem.Groth16)
    );
    // Corrupt version prefix to 0x0099
    encoded[0] = 0x00;
    encoded[1] = 0x99;
    expect(() => decodeProofEnvelope(encoded)).to.throw(RangeError, /version prefix/);
  });

  it('rejects unknown circuit enum on encode', () => {
    const bad = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16);
    (bad as any).circuit = 99;
    expect(() => encodeProofEnvelope(bad)).to.throw(RangeError, /CircuitId/);
  });

  it('rejects unknown proving system enum on encode', () => {
    const bad = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16);
    (bad as any).provingSystem = 42;
    expect(() => encodeProofEnvelope(bad)).to.throw(RangeError, /ProvingSystem/);
  });

  it('rejects version mismatch inside CBOR body', () => {
    const env = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16);
    // Encode with correct version, then mutate the inner CBOR version
    // by re-encoding with a bad version (but correct prefix)
    const badEnv = { ...env, version: 0x0002 };
    // Manually build: correct prefix + bad inner version
    const cborg = require('cborg');
    const payload = cborg.encode({
      version: 0x0002,
      circuit: 0,
      provingSystem: 0,
      proof: DUMMY_GROTH16_PROOF,
      publicSignals: DUMMY_PUBLIC_SIGNALS,
    });
    const data = new Uint8Array(2 + payload.length);
    // Set prefix to a valid version so it passes prefix check
    // but inner version is 0x0002
    data[0] = 0x00;
    data[1] = 0x01;
    data.set(payload, 2);
    expect(() => decodeProofEnvelope(data)).to.throw(RangeError, /version/);
  });

  it('rejects data shorter than 4 bytes', () => {
    expect(() => decodeProofEnvelope(new Uint8Array([0x00, 0x01]))).to.throw(
      TypeError,
      /too short/
    );
  });

  it('rejects non-object proof', () => {
    const bad = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16);
    (bad as any).proof = 'not-an-object';
    expect(() => encodeProofEnvelope(bad)).to.throw(TypeError, /proof/);
  });

  it('rejects non-array publicSignals', () => {
    const bad = makeEnvelope(CircuitId.Human, ProvingSystem.Groth16);
    (bad as any).publicSignals = 'not-an-array';
    expect(() => encodeProofEnvelope(bad)).to.throw(TypeError, /publicSignals/);
  });
});

/* ------------------------------------------------------------------ */
/*  JSON round-trip                                                   */
/* ------------------------------------------------------------------ */

describe('ProofEnvelope JSON codec', () => {
  it('round-trips through toJSON/fromJSON', () => {
    const original = makeEnvelope(CircuitId.Delegation, ProvingSystem.PLONK, {
      createdAt: '2026-06-20T12:00:00Z',
    });
    const json = proofEnvelopeToJSON(original);

    // JSON uses human-readable labels
    expect(json.version).to.equal('0x0001');
    expect(json.circuit).to.equal('delegation');
    expect(json.provingSystem).to.equal('plonk');

    const restored = proofEnvelopeFromJSON(json);
    expect(restored).to.deep.equal(original);
  });

  it('rejects unknown circuit label', () => {
    const json = proofEnvelopeToJSON(
      makeEnvelope(CircuitId.Human, ProvingSystem.Groth16)
    );
    json.circuit = 'unknown-circuit';
    expect(() => proofEnvelopeFromJSON(json)).to.throw(RangeError, /circuit label/);
  });

  it('rejects unknown provingSystem label', () => {
    const json = proofEnvelopeToJSON(
      makeEnvelope(CircuitId.Human, ProvingSystem.Groth16)
    );
    json.provingSystem = 'stark';
    expect(() => proofEnvelopeFromJSON(json)).to.throw(RangeError, /provingSystem label/);
  });

  it('rejects invalid version hex', () => {
    const json = proofEnvelopeToJSON(
      makeEnvelope(CircuitId.Human, ProvingSystem.Groth16)
    );
    json.version = 'not-hex';
    expect(() => proofEnvelopeFromJSON(json)).to.throw(TypeError, /version string/);
  });
});

/* ------------------------------------------------------------------ */
/*  Content negotiation                                               */
/* ------------------------------------------------------------------ */

describe('negotiateProofContentType', () => {
  it('prefers CBOR for wildcard Accept', () => {
    expect(negotiateProofContentType('*/*')).to.equal(CONTENT_TYPE_CBOR);
  });

  it('returns CBOR for explicit CBOR accept', () => {
    expect(negotiateProofContentType('application/bolyra-proof+cbor')).to.equal(
      CONTENT_TYPE_CBOR
    );
  });

  it('returns JSON for explicit JSON accept', () => {
    expect(negotiateProofContentType('application/bolyra-proof+json')).to.equal(
      CONTENT_TYPE_JSON
    );
  });

  it('returns null for unrelated accept', () => {
    expect(negotiateProofContentType('text/html')).to.be.null;
  });

  it('prefers CBOR when both are listed', () => {
    expect(
      negotiateProofContentType(
        'application/bolyra-proof+json, application/bolyra-proof+cbor'
      )
    ).to.equal(CONTENT_TYPE_CBOR);
  });
});
