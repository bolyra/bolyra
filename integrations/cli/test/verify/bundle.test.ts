import { parseBundle } from '../../src/verify/bundle';
import { isVerifyDenial } from '../../src/verify/verdict';

/**
 * Structural bundle parsing tests (Task 5).
 *
 * These fixtures are structurally valid but cryptographically meaningless: the
 * proof coordinates are small decimal field-element strings, not real Groth16
 * witnesses. `parseBundle` only decodes + structurally validates; it never
 * checks the proof math, so tiny placeholder field elements are sufficient.
 */

/** Build a structurally-valid ProofEnvelope for the given circuit slot. */
function makeEnvelope(circuitName: string): Record<string, unknown> {
  return {
    version: '1.0.0',
    circuit: { name: circuitName, version: '0.4.0' },
    proofType: 'groth16',
    publicSignals: ['1', '2', '3'],
    proof: {
      pi_a: ['1', '2'],
      pi_b: [
        ['3', '4'],
        ['5', '6'],
      ],
      pi_c: ['7', '8'],
    },
  };
}

/** A complete, structurally-valid `bvp/1` bundle object. */
function makeBundle(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bvp: 1,
    agent: {
      envelope: makeEnvelope('AgentPolicy'),
      credential: {
        model_hash: '12345',
        operator_pubkey: { x: '11', y: '22' },
        permission_bitmask: '3',
        expiry: 4102444800,
      },
    },
    binding: {
      agent_name: 'agent-1',
      project_key: 'proj-1',
      program: 'claude-code',
      model: 'claude-opus-4',
      capabilities: ['read', 'write'],
      expiry: 4102444800, // binding v2: == credential expiry
    },
    sig: {
      R8: { x: '33', y: '44' },
      S: '55',
    },
    ...overrides,
  };
}

/** Assert `fn` throws a VerifyDenial with the expected code. */
function expectDenial(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (err) {
    expect(isVerifyDenial(err)).toBe(true);
    if (isVerifyDenial(err)) {
      expect(err.code).toBe(code);
    }
    return;
  }
  throw new Error(`expected a VerifyDenial(${code}) but nothing was thrown`);
}

describe('parseBundle', () => {
  it('parses a structurally-valid JSON bundle', () => {
    const parsed = parseBundle(JSON.stringify(makeBundle()));
    expect(parsed.bvp).toBe(1);
    expect(parsed.agent.envelope.circuit.name).toBe('AgentPolicy');
    expect(parsed.agent.credential.model_hash).toBe('12345');
    expect(parsed.agent.credential.expiry).toBe(4102444800);
    expect(parsed.binding.capabilities).toEqual(['read', 'write']);
    expect(parsed.sig.S).toBe('55');
    expect(parsed.human).toBeUndefined();
    expect(parsed.delegation).toBeUndefined();
  });

  it('accepts a base64url-encoded bundle', () => {
    const json = JSON.stringify(makeBundle());
    const b64 = Buffer.from(json, 'utf8').toString('base64url');
    const parsed = parseBundle(b64);
    expect(parsed.agent.credential.permission_bitmask).toBe('3');
  });

  it('parses an optional human slot', () => {
    const parsed = parseBundle(
      JSON.stringify(makeBundle({ human: { envelope: makeEnvelope('HumanUniqueness') } }))
    );
    expect(parsed.human?.envelope.circuit.name).toBe('HumanUniqueness');
  });

  it('parses a delegation chain whose final hop reveals its leaf', () => {
    const parsed = parseBundle(
      JSON.stringify(
        makeBundle({
          delegation: [
            { envelope: makeEnvelope('Delegation') },
            {
              envelope: makeEnvelope('Delegation'),
              leaf: {
                delegatee_scope: '1',
                delegatee_commitment: '99',
                delegatee_expiry: 4102444800,
              },
            },
          ],
        })
      )
    );
    expect(parsed.delegation).toHaveLength(2);
    expect(parsed.delegation?.[0].leaf).toBeUndefined();
    expect(parsed.delegation?.[1].leaf?.delegatee_commitment).toBe('99');
  });

  it('rejects undecodable / truncated base64url input as invalid_bundle', () => {
    // A base64url blob that decodes to bytes but not valid JSON.
    const truncated = Buffer.from('{"bvp":1,"age', 'utf8').toString('base64url');
    expectDenial(() => parseBundle(truncated), 'invalid_bundle');
  });

  it('rejects an unsupported bvp version', () => {
    expectDenial(() => parseBundle(JSON.stringify(makeBundle({ bvp: 2 }))), 'unsupported_version');
  });

  it('rejects an agent envelope in the wrong circuit slot as invalid_proof', () => {
    const bad = makeBundle();
    (bad.agent as { envelope: Record<string, unknown> }).envelope = makeEnvelope('Delegation');
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_proof');
  });

  it('rejects a structurally-invalid envelope as invalid_proof', () => {
    const bad = makeBundle();
    // Blow away publicSignals so validateEnvelope throws.
    (bad.agent as { envelope: Record<string, unknown> }).envelope = {
      ...makeEnvelope('AgentPolicy'),
      publicSignals: [],
    };
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_proof');
  });

  it('rejects a missing agent.credential as invalid_bundle', () => {
    const bad = makeBundle();
    delete (bad.agent as Record<string, unknown>).credential;
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_bundle');
  });

  it('rejects a delegation chain whose final hop omits its leaf', () => {
    const bad = makeBundle({
      delegation: [{ envelope: makeEnvelope('Delegation') }],
    });
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'delegation_invalid');
  });

  it('rejects a bundle that is not a plain object', () => {
    expectDenial(() => parseBundle('[1,2,3]'), 'invalid_bundle');
  });

  it('rejects a malformed sig block as invalid_bundle', () => {
    const bad = makeBundle({ sig: { R8: { x: '1' }, S: '2' } });
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_bundle');
  });

  it('rejects an obsolete v1 binding (no expiry) as unsupported_version', () => {
    const bad = makeBundle();
    delete (bad.binding as Record<string, unknown>).expiry;
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'unsupported_version');
  });

  it('rejects a non-integer binding.expiry as invalid_bundle', () => {
    const bad = makeBundle();
    (bad.binding as Record<string, unknown>).expiry = 'later';
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_bundle');
  });

  it('rejects an unexpected extra binding field as invalid_bundle', () => {
    const bad = makeBundle();
    (bad.binding as Record<string, unknown>).surprise = 'x';
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_bundle');
  });

  it('an extra field on a no-expiry binding is invalid_bundle, NOT unsupported_version', () => {
    // Only a WELL-FORMED five-field v1 binding earns unsupported_version; the
    // unexpected-key check runs first, so a malformed no-expiry binding is
    // invalid_bundle.
    const bad = makeBundle();
    delete (bad.binding as Record<string, unknown>).expiry;
    (bad.binding as Record<string, unknown>).surprise = 'x';
    expectDenial(() => parseBundle(JSON.stringify(bad)), 'invalid_bundle');
  });
});
