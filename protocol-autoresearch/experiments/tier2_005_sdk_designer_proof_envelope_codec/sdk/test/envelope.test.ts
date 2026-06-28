import { describe, it } from 'mocha';
import { expect } from 'chai';
import {
  encode,
  decode,
  fromRaw,
  ENVELOPE_VERSION,
  EnvelopeError,
} from '../src/envelope.js';
import { SIGNAL_MAPS } from '../src/signals.js';
import type { BolyraEnvelope, SnarkjsProof } from '../src/envelope.js';
import type { BolyraCircuit } from '../src/signals.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MOCK_PROOF: SnarkjsProof = {
  pi_a: ['1', '2', '1'],
  pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
  pi_c: ['7', '8', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};

function mockSignals(circuit: BolyraCircuit): string[] {
  return SIGNAL_MAPS[circuit].map((_, i) => String(1000 + i));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('BolyraEnvelope', () => {
  // -----------------------------------------------------------------------
  // Round-trip: encode → decode is identity
  // -----------------------------------------------------------------------
  describe('round-trip encode/decode', () => {
    for (const circuit of ['HumanUniqueness', 'AgentPolicy', 'Delegation'] as BolyraCircuit[]) {
      it(`round-trips for ${circuit}`, () => {
        const signals = mockSignals(circuit);
        const envelope = encode(circuit, 'groth16', MOCK_PROOF, signals);

        expect(envelope.version).to.equal(ENVELOPE_VERSION);
        expect(envelope.circuit).to.equal(circuit);
        expect(envelope.provingSystem).to.equal('groth16');

        const decoded = decode(envelope);
        expect(decoded.publicSignals).to.deep.equal(signals);
        expect(decoded.proof).to.deep.equal(MOCK_PROOF);
      });
    }

    it('round-trips with plonk proving system', () => {
      const signals = mockSignals('AgentPolicy');
      const plonkProof: SnarkjsProof = { ...MOCK_PROOF, protocol: 'plonk' };
      const envelope = encode('AgentPolicy', 'plonk', plonkProof, signals);
      expect(envelope.provingSystem).to.equal('plonk');
      const decoded = decode(envelope);
      expect(decoded.publicSignals).to.deep.equal(signals);
    });
  });

  // -----------------------------------------------------------------------
  // fromRaw produces correct named fields
  // -----------------------------------------------------------------------
  describe('fromRaw named fields', () => {
    it('maps HumanUniqueness signals to correct names', () => {
      const signals = ['111', '222', '333', '444', '555'];
      const env = fromRaw('HumanUniqueness', 'groth16', MOCK_PROOF, signals);
      expect(env.signals.nullifierHash).to.equal('111');
      expect(env.signals.nonceBinding).to.equal('222');
      expect(env.signals.humanMerkleRoot).to.equal('333');
      expect(env.signals.externalNullifier).to.equal('444');
      expect(env.signals.sessionNonce).to.equal('555');
    });

    it('maps AgentPolicy signals to correct names', () => {
      const signals = ['10', '20', '30', '40', '50', '60'];
      const env = fromRaw('AgentPolicy', 'groth16', MOCK_PROOF, signals);
      expect(env.signals.credentialHash).to.equal('10');
      expect(env.signals.nonceBinding).to.equal('20');
      expect(env.signals.agentMerkleRoot).to.equal('30');
      expect(env.signals.currentTimestamp).to.equal('40');
      expect(env.signals.requiredPermissions).to.equal('50');
      expect(env.signals.sessionNonce).to.equal('60');
    });

    it('maps Delegation signals to correct names', () => {
      const signals = ['100', '200', '300', '400', '500', '600'];
      const env = fromRaw('Delegation', 'groth16', MOCK_PROOF, signals);
      expect(env.signals.delegationHash).to.equal('100');
      expect(env.signals.narrowedPermissions).to.equal('200');
      expect(env.signals.nonceBinding).to.equal('300');
      expect(env.signals.delegationMerkleRoot).to.equal('400');
      expect(env.signals.currentTimestamp).to.equal('500');
      expect(env.signals.sessionNonce).to.equal('600');
    });
  });

  // -----------------------------------------------------------------------
  // Error cases
  // -----------------------------------------------------------------------
  describe('error handling', () => {
    it('throws UNKNOWN_CIRCUIT for invalid circuit name', () => {
      expect(() =>
        encode('FakeCircuit' as any, 'groth16', MOCK_PROOF, ['1']),
      ).to.throw(EnvelopeError)
        .with.property('code', 'UNKNOWN_CIRCUIT');
    });

    it('throws UNKNOWN_PROVING_SYSTEM for invalid proving system', () => {
      const signals = mockSignals('HumanUniqueness');
      expect(() =>
        encode('HumanUniqueness', 'fflonk' as any, MOCK_PROOF, signals),
      ).to.throw(EnvelopeError)
        .with.property('code', 'UNKNOWN_PROVING_SYSTEM');
    });

    it('throws SIGNAL_COUNT_MISMATCH on wrong signal count', () => {
      expect(() =>
        encode('HumanUniqueness', 'groth16', MOCK_PROOF, ['1', '2']),
      ).to.throw(EnvelopeError)
        .with.property('code', 'SIGNAL_COUNT_MISMATCH');
    });

    it('throws UNSUPPORTED_VERSION on version mismatch in decode', () => {
      const envelope: BolyraEnvelope = {
        version: '2.0.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { nullifierHash: '1', nonceBinding: '2', humanMerkleRoot: '3', externalNullifier: '4', sessionNonce: '5' },
        proof: MOCK_PROOF,
      };
      expect(() => decode(envelope)).to.throw(EnvelopeError)
        .with.property('code', 'UNSUPPORTED_VERSION');
    });

    it('throws UNKNOWN_CIRCUIT when decoding envelope with bad circuit', () => {
      const envelope = {
        version: '1.0.0',
        circuit: 'Nonexistent' as any,
        provingSystem: 'groth16' as const,
        signals: {},
        proof: MOCK_PROOF,
      };
      expect(() => decode(envelope)).to.throw(EnvelopeError)
        .with.property('code', 'UNKNOWN_CIRCUIT');
    });

    it('throws MISSING_SIGNAL when a signal key is absent', () => {
      const envelope: BolyraEnvelope = {
        version: '1.0.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { nullifierHash: '1', nonceBinding: '2' }, // missing 3 fields
        proof: MOCK_PROOF,
      };
      expect(() => decode(envelope)).to.throw(EnvelopeError)
        .with.property('code', 'MISSING_SIGNAL');
    });
  });

  // -----------------------------------------------------------------------
  // JSON serialisation round-trip
  // -----------------------------------------------------------------------
  describe('JSON serialisation', () => {
    it('survives JSON.stringify → JSON.parse round-trip', () => {
      const signals = mockSignals('Delegation');
      const envelope = encode('Delegation', 'groth16', MOCK_PROOF, signals);
      const json = JSON.stringify(envelope);
      const restored: BolyraEnvelope = JSON.parse(json);
      const decoded = decode(restored);
      expect(decoded.publicSignals).to.deep.equal(signals);
    });
  });
});
