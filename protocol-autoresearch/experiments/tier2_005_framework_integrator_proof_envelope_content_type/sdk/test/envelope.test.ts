import { describe, it } from 'mocha';
import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  BOLYRA_CONTENT_TYPE,
  ENVELOPE_VERSION,
  ProofType,
  createEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  validateEnvelope,
  EnvelopeValidationError,
} from '../src/envelope.js';
import type { ProofEnvelope } from '../src/envelope.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeValidEnvelope(overrides?: Partial<ProofEnvelope>): ProofEnvelope {
  return {
    version: '1.0',
    proofType: ProofType.Handshake,
    publicSignals: ['100', '200', '300'],
    proof: {
      pi_a: ['1', '2', '1'],
      pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
      pi_c: ['7', '8', '1'],
      protocol: 'groth16' as const,
      curve: 'bn128' as const,
    },
    metadata: {
      issuedAt: 1719878400,
      nonce: 'test-nonce-abc',
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('ProofEnvelope', () => {
  describe('constants', () => {
    it('exports the correct MIME content type', () => {
      assert.equal(BOLYRA_CONTENT_TYPE, 'application/bolyra+json');
    });

    it('exports version 1.0', () => {
      assert.equal(ENVELOPE_VERSION, '1.0');
    });

    it('ProofType enum has expected values', () => {
      assert.equal(ProofType.Handshake, 'handshake');
      assert.equal(ProofType.Delegation, 'delegation');
      assert.equal(ProofType.AgentPolicy, 'agent_policy');
    });
  });

  // -------------------------------------------------------------------------
  // Round-trip serialization
  // -------------------------------------------------------------------------

  describe('serialize / deserialize round-trip', () => {
    it('round-trips a handshake envelope', () => {
      const env = makeValidEnvelope();
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.deepStrictEqual(restored, env);
    });

    it('round-trips a delegation envelope', () => {
      const env = makeValidEnvelope({ proofType: ProofType.Delegation });
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.equal(restored.proofType, 'delegation');
    });

    it('round-trips an agent_policy envelope', () => {
      const env = makeValidEnvelope({ proofType: ProofType.AgentPolicy });
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.equal(restored.proofType, 'agent_policy');
    });

    it('round-trips a PLONK proof', () => {
      const env = makeValidEnvelope({
        proof: {
          ...makeValidEnvelope().proof,
          protocol: 'plonk' as const,
        },
      });
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.equal(restored.proof.protocol, 'plonk');
    });

    it('preserves metadata nonce', () => {
      const env = makeValidEnvelope({ metadata: { issuedAt: 1719878400, nonce: 'n123' } });
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.equal(restored.metadata.nonce, 'n123');
    });

    it('preserves extra metadata fields', () => {
      const env = makeValidEnvelope({
        metadata: { issuedAt: 1719878400, sdkVersion: '0.2.0', custom: 'value' },
      });
      const json = serializeEnvelope(env);
      const restored = deserializeEnvelope(json);
      assert.equal((restored.metadata as any).custom, 'value');
    });
  });

  // -------------------------------------------------------------------------
  // Validation rejects malformed envelopes
  // -------------------------------------------------------------------------

  describe('validation errors', () => {
    it('rejects unsupported major version', () => {
      const env = makeValidEnvelope({ version: '2.0' });
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'UNSUPPORTED_VERSION',
      );
    });

    it('accepts compatible minor version bump', () => {
      const env = makeValidEnvelope({ version: '1.1' });
      assert.doesNotThrow(() => validateEnvelope(env));
    });

    it('rejects missing version', () => {
      const env = { ...makeValidEnvelope() } as any;
      delete env.version;
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects unknown proofType', () => {
      const env = makeValidEnvelope({ proofType: 'unknown' as any });
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects empty publicSignals', () => {
      const env = makeValidEnvelope({ publicSignals: [] });
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects pi_a with wrong length', () => {
      const env = makeValidEnvelope({
        proof: { ...makeValidEnvelope().proof, pi_a: ['1', '2'] as any },
      });
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects pi_b inner array with wrong length', () => {
      const env = makeValidEnvelope({
        proof: {
          ...makeValidEnvelope().proof,
          pi_b: [['3', '4', '5'], ['5', '6'], ['1', '0']] as any,
        },
      });
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects missing proof', () => {
      const env = { ...makeValidEnvelope() } as any;
      delete env.proof;
      assert.throws(() => validateEnvelope(env));
    });

    it('rejects missing metadata', () => {
      const env = { ...makeValidEnvelope() } as any;
      delete env.metadata;
      assert.throws(() => validateEnvelope(env));
    });

    it('rejects missing metadata.issuedAt', () => {
      const env = makeValidEnvelope({ metadata: {} as any });
      assert.throws(() => validateEnvelope(env));
    });

    it('rejects invalid JSON in deserialize', () => {
      assert.throws(
        () => deserializeEnvelope('not json'),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'INVALID_JSON',
      );
    });

    it('rejects additional properties at top level', () => {
      const env = { ...makeValidEnvelope(), extraField: true };
      assert.throws(
        () => validateEnvelope(env),
        (err: unknown) =>
          err instanceof EnvelopeValidationError &&
          err.code === 'SCHEMA_VIOLATION',
      );
    });

    it('rejects invalid protocol', () => {
      const env = makeValidEnvelope({
        proof: { ...makeValidEnvelope().proof, protocol: 'fflonk' as any },
      });
      assert.throws(() => validateEnvelope(env));
    });
  });

  // -------------------------------------------------------------------------
  // createEnvelope factory
  // -------------------------------------------------------------------------

  describe('createEnvelope()', () => {
    it('creates a valid envelope from raw snarkjs output', () => {
      const proof = {
        pi_a: ['1', '2', '1'],
        pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
        pi_c: ['7', '8', '1'],
        protocol: 'groth16',
        curve: 'bn128',
      };
      const env = createEnvelope(ProofType.Handshake, ['100', '200'], proof, { nonce: 'n1' });
      assert.equal(env.version, '1.0');
      assert.equal(env.proofType, 'handshake');
      assert.deepStrictEqual(env.publicSignals, ['100', '200']);
      assert.equal(env.proof.protocol, 'groth16');
      assert.equal(env.metadata.nonce, 'n1');
      assert.equal(typeof env.metadata.issuedAt, 'number');
    });

    it('defaults curve to bn128 when omitted', () => {
      const proof = {
        pi_a: ['1', '2', '1'],
        pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
        pi_c: ['7', '8', '1'],
        protocol: 'groth16',
      };
      const env = createEnvelope(ProofType.AgentPolicy, ['42'], proof);
      assert.equal(env.proof.curve, 'bn128');
    });
  });

  // -------------------------------------------------------------------------
  // Conformance test vectors
  // -------------------------------------------------------------------------

  describe('conformance vectors', () => {
    const vectorsPath = path.resolve(__dirname, '../../spec/conformance/envelope-vectors.json');
    let vectors: any;

    before(() => {
      const raw = fs.readFileSync(vectorsPath, 'utf-8');
      vectors = JSON.parse(raw);
    });

    it('loads the vectors file', () => {
      assert.ok(vectors.valid);
      assert.ok(vectors.invalid);
    });

    for (const label of ['handshake', 'delegation', 'agent_policy']) {
      it(`accepts valid ${label} vector`, function () {
        if (!vectors) this.skip();
        const vec = vectors.valid.find((v: any) => v.id === label);
        if (!vec) { this.skip(); return; }
        const env = deserializeEnvelope(JSON.stringify(vec.envelope));
        assert.equal(env.proofType, label);
      });
    }

    it('rejects all invalid vectors', function () {
      if (!vectors) this.skip();
      for (const vec of vectors.invalid) {
        assert.throws(
          () => deserializeEnvelope(JSON.stringify(vec.envelope)),
          undefined,
          `Expected vector "${vec.id}" to be rejected`,
        );
      }
    });
  });
});
