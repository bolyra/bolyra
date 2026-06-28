import { describe, it } from 'mocha';
import { expect } from 'chai';
import {
  serializeEnvelope,
  deserializeEnvelope,
  createProofEnvelope,
  negotiateVersion,
  formatFromContentType,
  contentTypeForFormat,
  BolyraEnvelopeError,
  EnvelopeErrorCode,
  ENVELOPE_VERSION,
  CONTENT_TYPE_JSON,
  CONTENT_TYPE_CBOR,
  ProofEnvelope,
  Groth16Proof,
  PlonkProof,
} from '../src/envelope.js';
import vectors from '../../spec/conformance/proof-envelope-vectors.json' assert { type: 'json' };

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SAMPLE_GROTH16_PROOF: Groth16Proof = {
  pi_a: [
    '12460009539498507921589972156498240752498492653032760918337596032576801079813',
    '7034942776944714629850657751222977373098804636068737751899440101686589921471',
    '1',
  ],
  pi_b: [
    ['11559732032986387107991004021392285783925812861821192530917403151452391805634', '10857046999023057135944570762232829481370756359578518086990519993285655852781'],
    ['4082367875863433681332203403145435568316851327593401208105741076214120093531', '8495653923123431417604973247489272438418190587263600148770280649306958101930'],
    ['1', '0'],
  ],
  pi_c: [
    '18268476393859726240024243690098815996414291509483744488906068736354485436599',
    '12460009539498507921589972156498240752498492653032760918337596032576801079813',
    '1',
  ],
  protocol: 'groth16',
  curve: 'bn128',
};

const SAMPLE_PLONK_PROOF: PlonkProof = {
  A: ['12460009539498507921589972156498240752498492653032760918337596032576801079813', '7034942776944714629850657751222977373098804636068737751899440101686589921471', '1'],
  B: ['11559732032986387107991004021392285783925812861821192530917403151452391805634', '10857046999023057135944570762232829481370756359578518086990519993285655852781', '1'],
  C: ['4082367875863433681332203403145435568316851327593401208105741076214120093531', '8495653923123431417604973247489272438418190587263600148770280649306958101930', '1'],
  Z: ['18268476393859726240024243690098815996414291509483744488906068736354485436599', '12460009539498507921589972156498240752498492653032760918337596032576801079813', '1'],
  T1: ['7034942776944714629850657751222977373098804636068737751899440101686589921471', '12460009539498507921589972156498240752498492653032760918337596032576801079813', '1'],
  T2: ['11559732032986387107991004021392285783925812861821192530917403151452391805634', '4082367875863433681332203403145435568316851327593401208105741076214120093531', '1'],
  T3: ['10857046999023057135944570762232829481370756359578518086990519993285655852781', '8495653923123431417604973247489272438418190587263600148770280649306958101930', '1'],
  Wxi: ['18268476393859726240024243690098815996414291509483744488906068736354485436599', '7034942776944714629850657751222977373098804636068737751899440101686589921471', '1'],
  Wxiw: ['12460009539498507921589972156498240752498492653032760918337596032576801079813', '11559732032986387107991004021392285783925812861821192530917403151452391805634', '1'],
  eval_a: '12460009539498507921589972156498240752498492653032760918337596032576801079813',
  eval_b: '7034942776944714629850657751222977373098804636068737751899440101686589921471',
  eval_c: '11559732032986387107991004021392285783925812861821192530917403151452391805634',
  eval_s1: '10857046999023057135944570762232829481370756359578518086990519993285655852781',
  eval_s2: '4082367875863433681332203403145435568316851327593401208105741076214120093531',
  eval_zw: '8495653923123431417604973247489272438418190587263600148770280649306958101930',
  eval_r: '18268476393859726240024243690098815996414291509483744488906068736354485436599',
  protocol: 'plonk',
  curve: 'bn128',
};

function makeEnvelope(
  circuitId: ProofEnvelope['circuitId'] = 'bolyra:circuit:HumanUniqueness',
  provingSystem: ProofEnvelope['provingSystem'] = 'groth16',
  proof: Groth16Proof | PlonkProof = SAMPLE_GROTH16_PROOF,
): ProofEnvelope {
  return createProofEnvelope(
    circuitId,
    provingSystem,
    ['1234567890', '9876543210', '1111111111'],
    proof,
    { chain: 84532, registryAddress: '0x' + 'ab'.repeat(20), issuedAt: 1719000000000 },
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ProofEnvelope', () => {
  describe('createProofEnvelope', () => {
    it('should create envelope with correct version', () => {
      const env = makeEnvelope();
      expect(env.version).to.equal(ENVELOPE_VERSION);
      expect(env.circuitId).to.equal('bolyra:circuit:HumanUniqueness');
    });

    it('should default issuedAt to now if omitted', () => {
      const before = Date.now();
      const env = createProofEnvelope(
        'bolyra:circuit:AgentPolicy',
        'groth16',
        ['42'],
        SAMPLE_GROTH16_PROOF,
      );
      expect(env.metadata.issuedAt).to.be.gte(before);
    });
  });

  describe('JSON round-trip', () => {
    it('should serialize and deserialize Groth16 envelope', () => {
      const env = makeEnvelope('bolyra:circuit:HumanUniqueness', 'groth16', SAMPLE_GROTH16_PROOF);
      const buf = serializeEnvelope(env, 'json');
      const restored = deserializeEnvelope(buf, CONTENT_TYPE_JSON);
      expect(restored).to.deep.equal(env);
    });

    it('should serialize and deserialize PLONK envelope', () => {
      const env = makeEnvelope('bolyra:circuit:AgentPolicy', 'plonk', SAMPLE_PLONK_PROOF);
      const buf = serializeEnvelope(env, 'json');
      const restored = deserializeEnvelope(buf, CONTENT_TYPE_JSON);
      expect(restored).to.deep.equal(env);
    });
  });

  describe('CBOR round-trip', () => {
    it('should serialize and deserialize via CBOR', () => {
      const env = makeEnvelope('bolyra:circuit:Delegation', 'groth16', SAMPLE_GROTH16_PROOF);
      const buf = serializeEnvelope(env, 'cbor');
      const restored = deserializeEnvelope(buf, CONTENT_TYPE_CBOR);
      expect(restored).to.deep.equal(env);
    });

    it('CBOR encoding should be smaller than JSON', () => {
      const env = makeEnvelope();
      const jsonBuf = serializeEnvelope(env, 'json');
      const cborBuf = serializeEnvelope(env, 'cbor');
      expect(cborBuf.length).to.be.lessThan(jsonBuf.length);
    });
  });

  describe('schema validation rejection', () => {
    it('should reject unknown provingSystem', () => {
      const env = makeEnvelope();
      (env as any).provingSystem = 'fflonk';
      expect(() => serializeEnvelope(env, 'json')).to.throw(BolyraEnvelopeError);
    });

    it('should reject missing publicSignals', () => {
      const env = makeEnvelope();
      delete (env as any).publicSignals;
      expect(() => serializeEnvelope(env, 'json')).to.throw(BolyraEnvelopeError);
    });

    it('should reject additional properties', () => {
      const env = makeEnvelope() as any;
      env.extraField = 'not allowed';
      expect(() => serializeEnvelope(env, 'json')).to.throw(BolyraEnvelopeError);
    });

    it('should reject invalid version format', () => {
      const env = makeEnvelope();
      (env as any).version = 'v1';
      expect(() => serializeEnvelope(env, 'json')).to.throw(BolyraEnvelopeError);
    });

    it('should reject non-decimal publicSignals', () => {
      const env = makeEnvelope();
      env.publicSignals = ['0xDEAD'];
      expect(() => serializeEnvelope(env, 'json')).to.throw(BolyraEnvelopeError);
    });
  });

  describe('version negotiation', () => {
    it('should accept version 1.0.0', () => {
      expect(negotiateVersion('1.0.0')).to.equal('1.0.0');
    });

    it('should accept compatible 1.x.y versions', () => {
      expect(negotiateVersion('1.2.3')).to.equal(ENVELOPE_VERSION);
    });

    it('should reject version 2.0.0', () => {
      expect(() => negotiateVersion('2.0.0')).to.throw(BolyraEnvelopeError);
    });

    it('should throw UNKNOWN_VERSION error code', () => {
      try {
        negotiateVersion('3.0.0');
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraEnvelopeError);
        expect((err as BolyraEnvelopeError).code).to.equal(EnvelopeErrorCode.UNKNOWN_VERSION);
      }
    });
  });

  describe('content-type helpers', () => {
    it('should map format to content type', () => {
      expect(contentTypeForFormat('json')).to.equal(CONTENT_TYPE_JSON);
      expect(contentTypeForFormat('cbor')).to.equal(CONTENT_TYPE_CBOR);
    });

    it('should parse content type to format', () => {
      expect(formatFromContentType(CONTENT_TYPE_JSON)).to.equal('json');
      expect(formatFromContentType(CONTENT_TYPE_CBOR)).to.equal('cbor');
    });

    it('should reject unknown content type', () => {
      expect(() => formatFromContentType('application/json')).to.throw(BolyraEnvelopeError);
    });
  });

  describe('deserialization error handling', () => {
    it('should throw on corrupt JSON', () => {
      const buf = Buffer.from('{not json}}}', 'utf-8');
      expect(() => deserializeEnvelope(buf, CONTENT_TYPE_JSON)).to.throw(BolyraEnvelopeError);
    });

    it('should throw on corrupt CBOR', () => {
      const buf = Buffer.from([0xff, 0xfe, 0x00]);
      expect(() => deserializeEnvelope(buf, CONTENT_TYPE_CBOR)).to.throw(BolyraEnvelopeError);
    });

    it('should throw DESERIALIZATION_FAILED code', () => {
      try {
        deserializeEnvelope(Buffer.from('!!!'), CONTENT_TYPE_JSON);
        expect.fail('should have thrown');
      } catch (err) {
        expect(err).to.be.instanceOf(BolyraEnvelopeError);
        expect((err as BolyraEnvelopeError).code).to.equal(EnvelopeErrorCode.DESERIALIZATION_FAILED);
      }
    });
  });

  describe('conformance test vectors', () => {
    for (const vector of (vectors as any).vectors) {
      it(`should validate vector: ${vector.description}`, () => {
        const env: ProofEnvelope = vector.envelope;
        const buf = serializeEnvelope(env, 'json');
        const restored = deserializeEnvelope(buf, CONTENT_TYPE_JSON);
        expect(restored.circuitId).to.equal(env.circuitId);
        expect(restored.provingSystem).to.equal(env.provingSystem);
        expect(restored.publicSignals).to.deep.equal(env.publicSignals);
      });
    }
  });
});
