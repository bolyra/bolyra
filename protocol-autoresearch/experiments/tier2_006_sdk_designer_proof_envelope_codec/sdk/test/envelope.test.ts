import { describe, it } from 'mocha';
import { expect } from 'chai';
import {
  encode,
  decode,
  fromRaw,
  ENVELOPE_VERSION,
  EnvelopeVersionError,
  UnknownCircuitError,
  SignalCountMismatch,
  InvalidProvingSystemError,
} from '../src/envelope.js';
import type { BolyraEnvelope, SnarkProof, CircuitName, ProvingSystem } from '../src/envelope.js';
import {
  HUMAN_UNIQUENESS_SIGNALS,
  AGENT_POLICY_SIGNALS,
  DELEGATION_SIGNALS,
  SIGNAL_MAPS,
} from '../src/circuits/signal-maps.js';
import * as fs from 'fs';
import * as path from 'path';

const FIXTURES_PATH = path.join(__dirname, 'fixtures', 'envelope-v1-samples.json');

function loadFixtures(): Record<string, any> {
  return JSON.parse(fs.readFileSync(FIXTURES_PATH, 'utf-8'));
}

const MOCK_GROTH16_PROOF: SnarkProof = {
  pi_a: ['12345678901234567890', '98765432109876543210', '1'],
  pi_b: [
    ['11111111111111111111', '22222222222222222222'],
    ['33333333333333333333', '44444444444444444444'],
    ['1', '0'],
  ],
  pi_c: ['55555555555555555555', '66666666666666666666', '1'],
  protocol: 'groth16',
  curve: 'bn128',
};

describe('BolyraEnvelope', () => {
  describe('encode()', () => {
    it('should encode HumanUniqueness with 3 signals', () => {
      const signals = [
        '19014214495641488759237505126948346942972912379615652741039992445865937985820',
        '8645981980787649023086883978738420956569850792831678695889709075406549402649',
        '2093865978272815678578934025076480206012199430301740489153086633322790357691',
      ];

      const envelope = encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, signals);

      expect(envelope.version).to.equal(ENVELOPE_VERSION);
      expect(envelope.circuit).to.equal('HumanUniqueness');
      expect(envelope.provingSystem).to.equal('groth16');
      expect(envelope.signals.humanMerkleRoot).to.equal(signals[0]);
      expect(envelope.signals.nullifierHash).to.equal(signals[1]);
      expect(envelope.signals.nonceBinding).to.equal(signals[2]);
      expect(Object.keys(envelope.signals)).to.have.lengthOf(3);
    });

    it('should encode AgentPolicy with 4 signals', () => {
      const signals = ['1000', '7', '2000', '1735689600'];
      const envelope = encode('AgentPolicy', 'groth16', MOCK_GROTH16_PROOF, signals);

      expect(envelope.circuit).to.equal('AgentPolicy');
      expect(envelope.signals.credentialCommitment).to.equal('1000');
      expect(envelope.signals.permissionsBitmask).to.equal('7');
      expect(envelope.signals.scopeCommitment).to.equal('2000');
      expect(envelope.signals.expiryTimestamp).to.equal('1735689600');
    });

    it('should encode Delegation with 4 signals', () => {
      const signals = ['100', '200', '3', '400'];
      const envelope = encode('Delegation', 'groth16', MOCK_GROTH16_PROOF, signals);

      expect(envelope.circuit).to.equal('Delegation');
      expect(envelope.signals.delegatorCredCommitment).to.equal('100');
      expect(envelope.signals.delegateeCredCommitment).to.equal('200');
      expect(envelope.signals.narrowedPermissionsBitmask).to.equal('3');
      expect(envelope.signals.delegationNullifier).to.equal('400');
    });

    it('should accept AgentPolicy with plonk proving system', () => {
      const signals = ['1000', '7', '2000', '1735689600'];
      const envelope = encode('AgentPolicy', 'plonk', MOCK_GROTH16_PROOF, signals);
      expect(envelope.provingSystem).to.equal('plonk');
    });

    it('should reject HumanUniqueness with plonk proving system', () => {
      const signals = ['1', '2', '3'];
      expect(() => encode('HumanUniqueness', 'plonk', MOCK_GROTH16_PROOF, signals))
        .to.throw(InvalidProvingSystemError);
    });

    it('should throw UnknownCircuitError for unknown circuit', () => {
      expect(() => encode('FakeCircuit' as CircuitName, 'groth16', MOCK_GROTH16_PROOF, ['1']))
        .to.throw(UnknownCircuitError);
    });

    it('should throw SignalCountMismatch for wrong signal count', () => {
      expect(() => encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, ['1', '2']))
        .to.throw(SignalCountMismatch);
      expect(() => encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, ['1', '2', '3', '4']))
        .to.throw(SignalCountMismatch);
    });
  });

  describe('decode()', () => {
    it('should round-trip HumanUniqueness', () => {
      const signals = ['100', '200', '300'];
      const envelope = encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, signals);
      const json = JSON.parse(JSON.stringify(envelope));
      const decoded = decode(json);

      expect(decoded.circuit).to.equal('HumanUniqueness');
      expect(decoded.publicSignals).to.deep.equal([100n, 200n, 300n]);
      expect(decoded.signals.humanMerkleRoot).to.equal('100');
    });

    it('should round-trip AgentPolicy', () => {
      const signals = ['1000', '7', '2000', '1735689600'];
      const envelope = encode('AgentPolicy', 'groth16', MOCK_GROTH16_PROOF, signals);
      const json = JSON.parse(JSON.stringify(envelope));
      const decoded = decode(json);

      expect(decoded.publicSignals).to.deep.equal([1000n, 7n, 2000n, 1735689600n]);
    });

    it('should round-trip Delegation', () => {
      const signals = ['100', '200', '3', '400'];
      const envelope = encode('Delegation', 'groth16', MOCK_GROTH16_PROOF, signals);
      const json = JSON.parse(JSON.stringify(envelope));
      const decoded = decode(json);

      expect(decoded.publicSignals).to.deep.equal([100n, 200n, 3n, 400n]);
    });

    it('should reject version 2.0.0', () => {
      const envelope = {
        version: '2.0.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { humanMerkleRoot: '1', nullifierHash: '2', nonceBinding: '3' },
        proof: MOCK_GROTH16_PROOF,
      };
      expect(() => decode(envelope)).to.throw(EnvelopeVersionError);
    });

    it('should accept version 1.1.0 (same major)', () => {
      const envelope = {
        version: '1.1.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { humanMerkleRoot: '1', nullifierHash: '2', nonceBinding: '3' },
        proof: MOCK_GROTH16_PROOF,
      };
      const decoded = decode(envelope);
      expect(decoded.version).to.equal('1.1.0');
    });

    it('should reject unknown circuit', () => {
      const envelope = {
        version: '1.0.0',
        circuit: 'UnknownCircuit',
        provingSystem: 'groth16',
        signals: {},
        proof: MOCK_GROTH16_PROOF,
      };
      expect(() => decode(envelope)).to.throw(UnknownCircuitError);
    });

    it('should reject missing signals', () => {
      const envelope = {
        version: '1.0.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { humanMerkleRoot: '1', nullifierHash: '2' },
        proof: MOCK_GROTH16_PROOF,
      };
      expect(() => decode(envelope)).to.throw(SignalCountMismatch);
    });

    it('should reject extra signals', () => {
      const envelope = {
        version: '1.0.0',
        circuit: 'HumanUniqueness',
        provingSystem: 'groth16',
        signals: { humanMerkleRoot: '1', nullifierHash: '2', nonceBinding: '3', extra: '4' },
        proof: MOCK_GROTH16_PROOF,
      };
      expect(() => decode(envelope)).to.throw(SignalCountMismatch);
    });
  });

  describe('fromRaw()', () => {
    it('should produce identical output to encode()', () => {
      const signals = ['100', '200', '300'];
      const encoded = encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, signals);
      const fromRawResult = fromRaw('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, signals);
      expect(fromRawResult).to.deep.equal(encoded);
    });
  });

  describe('JSON serialization fidelity', () => {
    it('should survive JSON.stringify/parse round-trip', () => {
      const signals = ['100', '200', '300'];
      const envelope = encode('HumanUniqueness', 'groth16', MOCK_GROTH16_PROOF, signals);
      const json = JSON.stringify(envelope);
      const parsed = JSON.parse(json);
      const decoded = decode(parsed);

      expect(decoded.signals.humanMerkleRoot).to.equal('100');
      expect(decoded.publicSignals).to.deep.equal([100n, 200n, 300n]);
    });
  });

  describe('fixture compatibility', () => {
    it('should decode all fixture samples', () => {
      const fixtures = loadFixtures();
      for (const [key, sample] of Object.entries(fixtures.samples)) {
        const decoded = decode(sample as Record<string, unknown>);
        expect(decoded.version).to.equal('1.0.0');
        const signalMap = SIGNAL_MAPS[decoded.circuit];
        expect(decoded.publicSignals).to.have.lengthOf(signalMap.length);
      }
    });
  });

  describe('signal-maps', () => {
    it('HumanUniqueness has 3 signals', () => {
      expect(HUMAN_UNIQUENESS_SIGNALS).to.have.lengthOf(3);
    });

    it('AgentPolicy has 4 signals', () => {
      expect(AGENT_POLICY_SIGNALS).to.have.lengthOf(4);
    });

    it('Delegation has 4 signals', () => {
      expect(DELEGATION_SIGNALS).to.have.lengthOf(4);
    });
  });
});
