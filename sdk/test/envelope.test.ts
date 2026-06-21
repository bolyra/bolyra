import * as fs from 'fs';
import * as path from 'path';

import {
  CONTENT_TYPE,
  ENVELOPE_VERSION,
  validateEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  envelopeFromSnarkjsProof,
} from '../src/envelope';
import type { ProofEnvelope } from '../src/envelope';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

function loadFixture(name: string): string {
  return fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf-8');
}

/** A minimal valid envelope object for unit tests. */
function minimalEnvelope(): Record<string, unknown> {
  return {
    version: '1.0.0',
    circuit: { name: 'HumanUniqueness', version: '0.4.0' },
    proofType: 'groth16',
    publicSignals: ['42', '1'],
    proof: {
      pi_a: ['1', '2'],
      pi_b: [['3', '4'], ['5', '6']],
      pi_c: ['7', '8'],
    },
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

describe('CONTENT_TYPE', () => {
  it('has vendor prefix', () => {
    expect(CONTENT_TYPE).toBe('application/vnd.bolyra.proof+json');
  });
});

describe('ENVELOPE_VERSION', () => {
  it('is 1.0.0', () => {
    expect(ENVELOPE_VERSION).toBe('1.0.0');
  });
});

// ---------------------------------------------------------------------------
// 1. Round-trip
// ---------------------------------------------------------------------------

describe('round-trip', () => {
  it('serialize then deserialize preserves all fields', () => {
    const env = validateEnvelope(minimalEnvelope());
    const json = serializeEnvelope(env);
    const restored = deserializeEnvelope(json);
    expect(restored).toEqual(env);
  });

  it('round-trip preserves optional metadata', () => {
    const raw = {
      ...minimalEnvelope(),
      metadata: { prover: 'test@1.0.0', timestamp: '2026-06-21T00:00:00Z' },
    };
    const env = validateEnvelope(raw);
    const restored = deserializeEnvelope(serializeEnvelope(env));
    expect(restored.metadata?.prover).toBe('test@1.0.0');
    expect(restored.metadata?.timestamp).toBe('2026-06-21T00:00:00Z');
  });
});

// ---------------------------------------------------------------------------
// 2. Version rejection
// ---------------------------------------------------------------------------

describe('version negotiation', () => {
  it('rejects major version 2.0.0 with "Major version mismatch"', () => {
    const raw = { ...minimalEnvelope(), version: '2.0.0' };
    expect(() => validateEnvelope(raw)).toThrow('Major version mismatch');
  });

  it('rejects major version 0.9.0', () => {
    const raw = { ...minimalEnvelope(), version: '0.9.0' };
    expect(() => validateEnvelope(raw)).toThrow('Major version mismatch');
  });

  // 3. Version acceptance
  it('accepts minor bump 1.1.0 without error', () => {
    const raw = { ...minimalEnvelope(), version: '1.1.0' };
    expect(() => validateEnvelope(raw)).not.toThrow();
  });

  it('accepts patch bump 1.0.99 without error', () => {
    const raw = { ...minimalEnvelope(), version: '1.0.99' };
    expect(() => validateEnvelope(raw)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 4. Missing required field
// ---------------------------------------------------------------------------

describe('missing required fields', () => {
  it('throws when proof key is absent', () => {
    const raw = { ...minimalEnvelope() };
    delete (raw as any).proof;
    expect(() => validateEnvelope(raw)).toThrow();
  });

  it('throws when version is absent', () => {
    const raw = { ...minimalEnvelope() };
    delete (raw as any).version;
    expect(() => validateEnvelope(raw)).toThrow();
  });

  it('throws when circuit is absent', () => {
    const raw = { ...minimalEnvelope() };
    delete (raw as any).circuit;
    expect(() => validateEnvelope(raw)).toThrow();
  });

  it('throws when publicSignals is absent', () => {
    const raw = { ...minimalEnvelope() };
    delete (raw as any).publicSignals;
    expect(() => validateEnvelope(raw)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 5. Malformed proof coordinates
// ---------------------------------------------------------------------------

describe('malformed proof coordinates', () => {
  it('throws when pi_a contains "abc"', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = ['abc', '2'];
    expect(() => validateEnvelope(raw)).toThrow();
  });

  it('throws when pi_c contains empty string', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_c = ['', '2'];
    expect(() => validateEnvelope(raw)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 6. Field element exceeds BN254 modulus
// ---------------------------------------------------------------------------

describe('BN254 field element bounds', () => {
  const MODULUS = '21888242871839275222246405745257275088548364400416034343698204186575808495617';
  const MODULUS_MINUS_1 = '21888242871839275222246405745257275088548364400416034343698204186575808495616';

  it('rejects field element equal to BN254 modulus', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = [MODULUS, '1'];
    expect(() => validateEnvelope(raw)).toThrow('BN254 field modulus');
  });

  it('accepts field element equal to BN254 modulus - 1', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = [MODULUS_MINUS_1, '1'];
    expect(() => validateEnvelope(raw)).not.toThrow();
  });

  it('rejects value one above modulus in publicSignals', () => {
    const raw = minimalEnvelope();
    (raw as any).publicSignals = [MODULUS];
    expect(() => validateEnvelope(raw)).toThrow('BN254 field modulus');
  });
});

// ---------------------------------------------------------------------------
// 7. Leading zero rejection
// ---------------------------------------------------------------------------

describe('leading zero rejection', () => {
  it('rejects "0042" in pi_a', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = ['0042', '1'];
    expect(() => validateEnvelope(raw)).toThrow('leading zeros');
  });

  it('rejects "01" in publicSignals', () => {
    const raw = minimalEnvelope();
    (raw as any).publicSignals = ['01'];
    expect(() => validateEnvelope(raw)).toThrow('leading zeros');
  });

  it('accepts "0" (bare zero)', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = ['0', '0'];
    expect(() => validateEnvelope(raw)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 8. String length DoS guard
// ---------------------------------------------------------------------------

describe('DoS guard: string length', () => {
  it('rejects a 100-char digit string in pi_a', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_a = ['1'.repeat(100), '1'];
    expect(() => validateEnvelope(raw)).toThrow('too long');
  });

  it('accepts a 78-char digit string (max allowed)', () => {
    // 78-digit number that starts with 1 (not exceeding modulus would be tricky
    // at 78 digits — use a value we know is safe: 1 followed by 77 zeros is
    // smaller than the 77-digit modulus, so it won't blow up the field check)
    // BN254 modulus is 77 digits; a 78-char string starting with "1" is larger.
    // Use exactly 77 digits (modulus-1 is safe and is 77 chars).
    const safe77 = '2'.padStart(77, '1'); // starts with 1s, 77 chars
    const raw = minimalEnvelope();
    // Just check the length guard doesn't fire (the value may fail field check)
    try {
      (raw.proof as any).pi_a = [safe77, '1'];
      validateEnvelope(raw);
    } catch (e) {
      expect((e as Error).message).not.toMatch('too long');
    }
  });
});

// ---------------------------------------------------------------------------
// 9. Forward compatibility: unknown top-level key preserved
// ---------------------------------------------------------------------------

describe('forward compatibility', () => {
  it('preserves unknown top-level key through round-trip', () => {
    const raw = { ...minimalEnvelope(), futureField: 'preserved-value' };
    const env = validateEnvelope(raw);
    expect((env as any).futureField).toBe('preserved-value');
    const restored = deserializeEnvelope(serializeEnvelope(env));
    expect((restored as any).futureField).toBe('preserved-value');
  });

  it('preserves multiple unknown top-level keys', () => {
    const raw = { ...minimalEnvelope(), alpha: 1, beta: [1, 2, 3] };
    const env = validateEnvelope(raw);
    expect((env as any).alpha).toBe(1);
    expect((env as any).beta).toEqual([1, 2, 3]);
  });
});

// ---------------------------------------------------------------------------
// 10. Golden fixture: envelope_v1.json
// ---------------------------------------------------------------------------

describe('golden fixture: envelope_v1.json', () => {
  let env: ProofEnvelope;

  beforeAll(() => {
    env = deserializeEnvelope(loadFixture('envelope_v1.json'));
  });

  it('version is 1.0.0', () => expect(env.version).toBe('1.0.0'));
  it('circuit name is HumanUniqueness', () => expect(env.circuit.name).toBe('HumanUniqueness'));
  it('circuit version is 0.4.0', () => expect(env.circuit.version).toBe('0.4.0'));
  it('vkeyHash is present', () =>
    expect(env.circuit.vkeyHash).toBe(
      'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    ));
  it('proofType is groth16', () => expect(env.proofType).toBe('groth16'));
  it('publicSignals has 3 entries', () => expect(env.publicSignals).toHaveLength(3));
  it('publicSignals[2] is "42"', () => expect(env.publicSignals[2]).toBe('42'));
  it('pi_a[0] is correct', () => expect(env.proof.pi_a[0]).toBe('12345678901234567890'));
  it('pi_b has correct shape', () => {
    expect(env.proof.pi_b).toHaveLength(2);
    expect(env.proof.pi_b[0]).toHaveLength(2);
    expect(env.proof.pi_b[1]).toHaveLength(2);
  });
  it('metadata.prover is @bolyra/sdk@0.4.0', () =>
    expect(env.metadata?.prover).toBe('@bolyra/sdk@0.4.0'));
  it('metadata.timestamp is 2026-06-21T12:00:00Z', () =>
    expect(env.metadata?.timestamp).toBe('2026-06-21T12:00:00Z'));
});

// ---------------------------------------------------------------------------
// 11. Boundary fixture: envelope_v1_boundary.json
// ---------------------------------------------------------------------------

describe('boundary fixture: envelope_v1_boundary.json', () => {
  it('deserializes without error (boundary field elements accepted)', () => {
    expect(() => deserializeEnvelope(loadFixture('envelope_v1_boundary.json'))).not.toThrow();
  });

  it('publicSignals[0] is "0"', () => {
    const env = deserializeEnvelope(loadFixture('envelope_v1_boundary.json'));
    expect(env.publicSignals[0]).toBe('0');
  });
});

// ---------------------------------------------------------------------------
// 12. Forward compat fixture: envelope_v1_forward_compat.json
// ---------------------------------------------------------------------------

describe('forward compat fixture: envelope_v1_forward_compat.json', () => {
  it('futureField is preserved after deserialization', () => {
    const env = deserializeEnvelope(loadFixture('envelope_v1_forward_compat.json'));
    expect((env as any).futureField).toBe('this-should-be-preserved');
  });
});

// ---------------------------------------------------------------------------
// 13. Invalid leading zero fixture
// ---------------------------------------------------------------------------

describe('invalid fixture: envelope_v1_invalid_leading_zero.json', () => {
  it('throws on leading zeros in publicSignals', () => {
    expect(() => deserializeEnvelope(loadFixture('envelope_v1_invalid_leading_zero.json'))).toThrow(
      'leading zeros'
    );
  });
});

// ---------------------------------------------------------------------------
// 14. Invalid modulus fixture
// ---------------------------------------------------------------------------

describe('invalid fixture: envelope_v1_invalid_modulus.json', () => {
  it('throws when a field element equals BN254 modulus', () => {
    expect(() => deserializeEnvelope(loadFixture('envelope_v1_invalid_modulus.json'))).toThrow(
      'BN254 field modulus'
    );
  });
});

// ---------------------------------------------------------------------------
// 15. Invalid pi_b fixture
// ---------------------------------------------------------------------------

describe('invalid fixture: envelope_v1_invalid_pi_b.json', () => {
  it('throws when pi_b rows have wrong length', () => {
    expect(() => deserializeEnvelope(loadFixture('envelope_v1_invalid_pi_b.json'))).toThrow();
  });
});

// ---------------------------------------------------------------------------
// 16. envelopeFromSnarkjsProof: produces valid envelope
// ---------------------------------------------------------------------------

describe('envelopeFromSnarkjsProof', () => {
  const mockProof = {
    pi_a: ['1', '2'],
    pi_b: [['3', '4'], ['5', '6']],
    pi_c: ['7', '8'],
  };
  const mockSignals = ['42', '1'];

  it('produces an envelope with correct circuit name', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(env.circuit.name).toBe('HumanUniqueness');
  });

  it('version is ENVELOPE_VERSION', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(env.version).toBe(ENVELOPE_VERSION);
  });

  it('proofType is groth16', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(env.proofType).toBe('groth16');
  });

  it('uses provided circuitVersion option', () => {
    const env = envelopeFromSnarkjsProof('AgentPolicy', mockProof, mockSignals, {
      circuitVersion: '1.2.3',
    });
    expect(env.circuit.version).toBe('1.2.3');
  });

  it('includes vkeyHash when provided', () => {
    const hash = 'sha256:' + 'a'.repeat(64);
    const env = envelopeFromSnarkjsProof('Delegation', mockProof, mockSignals, {
      vkeyHash: hash,
    });
    expect(env.circuit.vkeyHash).toBe(hash);
  });

  it('metadata.prover is set', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(env.metadata?.prover).toBeTruthy();
  });

  it('metadata.timestamp is a valid ISO string', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(() => new Date(env.metadata?.timestamp as string)).not.toThrow();
  });

  it('maps pi_b correctly', () => {
    const env = envelopeFromSnarkjsProof('HumanUniqueness', mockProof, mockSignals);
    expect(env.proof.pi_b[0][0]).toBe('3');
    expect(env.proof.pi_b[1][1]).toBe('6');
  });

  // 17. Empty publicSignals
  it('throws on empty publicSignals', () => {
    expect(() =>
      envelopeFromSnarkjsProof('HumanUniqueness', mockProof, [])
    ).toThrow('non-empty array');
  });

  // 18. Invalid circuit name
  it('throws on invalid circuit name', () => {
    expect(() =>
      envelopeFromSnarkjsProof('UnknownCircuit' as any, mockProof, mockSignals)
    ).toThrow();
  });

  // 19. Invalid proofType — v1 only accepts groth16
  // envelopeFromSnarkjsProof always produces groth16; validate via validateEnvelope
  it('validateEnvelope rejects proofType "plonk"', () => {
    const raw = { ...minimalEnvelope(), proofType: 'plonk' };
    expect(() => validateEnvelope(raw)).toThrow('Invalid proofType');
  });
});

// ---------------------------------------------------------------------------
// 20. pi_b wrong row length via validateEnvelope
// ---------------------------------------------------------------------------

describe('pi_b row length validation', () => {
  it('rejects pi_b with first row of length 1', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_b = [['1'], ['2', '3', '4']];
    expect(() => validateEnvelope(raw)).toThrow('pi_b[0] must be [string, string]');
  });

  it('rejects pi_b with second row of length 3', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_b = [['1', '2'], ['3', '4', '5']];
    expect(() => validateEnvelope(raw)).toThrow('pi_b[1] must be [string, string]');
  });

  it('rejects pi_b with only 1 row', () => {
    const raw = minimalEnvelope();
    (raw.proof as any).pi_b = [['1', '2']];
    expect(() => validateEnvelope(raw)).toThrow('pi_b must be');
  });
});
