import { describe, it } from 'mocha';
import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import {
  CONTENT_TYPE,
  ENVELOPE_VERSION,
  serializeEnvelope,
  deserializeEnvelope,
  validateEnvelope,
  envelopeFromSnarkjsProof,
  ProofEnvelope,
} from '../src/envelope';

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'envelope_v1.json');

function loadFixture(): ProofEnvelope {
  const raw = fs.readFileSync(FIXTURE_PATH, 'utf-8');
  return JSON.parse(raw);
}

describe('ProofEnvelope', () => {
  describe('CONTENT_TYPE', () => {
    it('should equal application/bolyra-proof+json', () => {
      expect(CONTENT_TYPE).to.equal('application/bolyra-proof+json');
    });
  });

  describe('round-trip serialization', () => {
    it('should serialize and deserialize without loss', () => {
      const envelope = loadFixture();
      const json = serializeEnvelope(envelope);
      const restored = deserializeEnvelope(json);
      expect(restored).to.deep.equal(envelope);
    });
  });

  describe('version validation', () => {
    it('should reject unknown major version', () => {
      const envelope = loadFixture();
      envelope.version = '2.0';
      const json = JSON.stringify(envelope);
      expect(() => deserializeEnvelope(json)).to.throw(
        'Unsupported envelope major version 2'
      );
    });

    it('should accept compatible minor version', () => {
      const envelope = loadFixture();
      envelope.version = '1.1';
      const json = JSON.stringify(envelope);
      const restored = deserializeEnvelope(json);
      expect(restored.version).to.equal('1.1');
    });
  });

  describe('missing required fields', () => {
    it('should throw on missing circuit', () => {
      const envelope = loadFixture();
      delete (envelope as any).circuit;
      expect(() => validateEnvelope(envelope)).to.throw();
    });

    it('should throw on missing proof', () => {
      const envelope = loadFixture();
      delete (envelope as any).proof;
      expect(() => validateEnvelope(envelope)).to.throw();
    });

    it('should throw on missing metadata', () => {
      const envelope = loadFixture();
      delete (envelope as any).metadata;
      expect(() => validateEnvelope(envelope)).to.throw();
    });

    it('should throw on empty circuit string', () => {
      const envelope = loadFixture();
      envelope.circuit = '';
      expect(() => validateEnvelope(envelope)).to.throw();
    });
  });

  describe('proof field type errors', () => {
    it('should reject non-array pi_a', () => {
      const envelope = loadFixture();
      (envelope.proof as any).pi_a = 'not-an-array';
      expect(() => validateEnvelope(envelope)).to.throw();
    });

    it('should reject invalid protocol', () => {
      const envelope = loadFixture();
      (envelope.proof as any).protocol = 'fflonk';
      expect(() => validateEnvelope(envelope)).to.throw();
    });
  });

  describe('envelopeFromSnarkjsProof', () => {
    it('should wrap snarkjs output into a valid envelope', () => {
      const proof = {
        pi_a: ['1', '2', '1'],
        pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
        pi_c: ['7', '8', '1'],
        protocol: 'groth16',
      };
      const signals = ['100', '200'];
      const envelope = envelopeFromSnarkjsProof('AgentPolicy', proof, signals);
      expect(envelope.version).to.equal(ENVELOPE_VERSION);
      expect(envelope.circuit).to.equal('AgentPolicy');
      expect(envelope.publicSignals).to.deep.equal(signals);
      expect(envelope.proof.protocol).to.equal('groth16');
      expect(envelope.metadata.prover).to.equal('@bolyra/sdk');
      // Validate via schema
      expect(() => validateEnvelope(envelope)).to.not.throw();
    });
  });

  describe('fixture interop', () => {
    it('should parse the golden fixture file', () => {
      const raw = fs.readFileSync(FIXTURE_PATH, 'utf-8');
      const envelope = deserializeEnvelope(raw);
      expect(envelope.version).to.equal('1.0');
      expect(envelope.circuit).to.equal('HumanUniqueness');
      expect(envelope.publicSignals).to.have.length(3);
      expect(envelope.proof.protocol).to.equal('groth16');
    });
  });
});
