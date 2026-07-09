/**
 * Tests for verify/proofs.ts — this task OWNS vkeyHash pinning, vkey
 * resolution, the Groth16 math path, the human-proof branch, public-signal
 * length checks, and the `nonce_missing` nullifier gate.
 *
 * The Groth16 path is REAL: we generate genuine AgentPolicy + HumanUniqueness
 * proofs at test time via the SDK against the checked-out circuit artifacts
 * (BOLYRA_CIRCUITS_DIR, defaulting to <repo>/circuits/build), wrap them in
 * proof envelopes stamping the true vkeyHash, and assert end-to-end verify.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  proveHandshake,
  envelopeFromSnarkjsProof,
  type ProofEnvelope,
  type CircuitName,
} from '@bolyra/sdk';
import {
  computeVkeyHash,
  resolveVkeyPath,
  verifyEnvelopeProof,
  verifyAgentProof,
  verifyHumanProofIfPresent,
  requireNullifier,
} from '../../src/verify/proofs';
import type { ParsedBundle } from '../../src/verify/bundle';
import { VerifyDenial } from '../../src/verify/verdict';

const CIRCUITS_DIR =
  process.env.BOLYRA_CIRCUITS_DIR ?? path.resolve(__dirname, '../../../../circuits/build');

const OPTS = { circuitsDir: CIRCUITS_DIR };

/** Load a circuit vkey object from the resolved build dir. */
function loadVkey(circuit: CircuitName): object {
  const p = resolveVkeyPath(circuit, OPTS);
  return JSON.parse(fs.readFileSync(p, 'utf8')) as object;
}

/** Capture the `code` of a thrown VerifyDenial (throws if none/other). */
async function denialCode(fn: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await fn();
  } catch (err) {
    if (err instanceof VerifyDenial) return err.code;
    throw err;
  }
  throw new Error('expected a VerifyDenial to be thrown, but none was');
}

/** A structurally-plausible (but not necessarily valid) envelope. */
function makeEnvelope(
  circuit: CircuitName,
  fields: { vkeyHash?: string; publicSignals: string[]; proof?: ProofEnvelope['proof'] },
): ProofEnvelope {
  return {
    version: '1.0.0',
    circuit: {
      name: circuit,
      version: '0.4.0',
      ...(fields.vkeyHash ? { vkeyHash: fields.vkeyHash } : {}),
    },
    proofType: 'groth16',
    publicSignals: fields.publicSignals,
    proof: fields.proof ?? {
      pi_a: ['1', '2'],
      pi_b: [
        ['1', '2'],
        ['3', '4'],
      ],
      pi_c: ['1', '2'],
    },
  };
}

describe('computeVkeyHash', () => {
  it('is sha256:<hex> and stable / canonical (key-order independent)', () => {
    const a = { alpha: [1, 2], beta: 'x', gamma: { p: 1, q: 2 } };
    const b = { gamma: { q: 2, p: 1 }, beta: 'x', alpha: [1, 2] };
    const h = computeVkeyHash(a);
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(computeVkeyHash(b)).toBe(h); // canonicalization sorts keys
  });

  it('matches the envelope vkeyHash regex the SDK enforces', () => {
    const h = computeVkeyHash(loadVkey('AgentPolicy'));
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe('resolveVkeyPath', () => {
  it('resolves each circuit filename under the circuits dir', () => {
    expect(resolveVkeyPath('AgentPolicy', OPTS)).toContain('AgentPolicy_groth16_vkey.json');
    expect(resolveVkeyPath('Delegation', OPTS)).toContain('Delegation_groth16_vkey.json');
    expect(resolveVkeyPath('HumanUniqueness', OPTS)).toContain('HumanUniqueness_vkey.json');
  });

  it('throws internal_error when the vkey is unresolvable', async () => {
    const code = await denialCode(() =>
      resolveVkeyPath('AgentPolicy', { circuitsDir: '/nonexistent-bolyra-dir', env: {} }),
    );
    expect(code).toBe('internal_error');
  });
});

describe('verifyEnvelopeProof — pinning + structural denials', () => {
  it('denies invalid_proof when vkeyHash is absent', async () => {
    const env = makeEnvelope('AgentPolicy', {
      publicSignals: ['1', '2', '3', '4', '5', '6'],
    });
    expect(await denialCode(() => verifyEnvelopeProof(env, 'AgentPolicy', OPTS))).toBe(
      'invalid_proof',
    );
  });

  it('denies invalid_proof when vkeyHash mismatches the resolved key', async () => {
    const env = makeEnvelope('AgentPolicy', {
      vkeyHash: `sha256:${'0'.repeat(64)}`,
      publicSignals: ['1', '2', '3', '4', '5', '6'],
    });
    expect(await denialCode(() => verifyEnvelopeProof(env, 'AgentPolicy', OPTS))).toBe(
      'invalid_proof',
    );
  });

  it('denies internal_error when the vkey cannot be resolved', async () => {
    const env = makeEnvelope('AgentPolicy', {
      publicSignals: ['1', '2', '3', '4', '5', '6'],
    });
    const code = await denialCode(() =>
      verifyEnvelopeProof(env, 'AgentPolicy', { circuitsDir: '/nonexistent-bolyra-dir', env: {} }),
    );
    expect(code).toBe('internal_error');
  });

  it('denies invalid_proof when publicSignals are too short (matched vkeyHash)', async () => {
    const vkeyHash = computeVkeyHash(loadVkey('AgentPolicy'));
    const env = makeEnvelope('AgentPolicy', {
      vkeyHash,
      publicSignals: ['1', '2', '3'], // < 6 for AgentPolicy
    });
    expect(await denialCode(() => verifyEnvelopeProof(env, 'AgentPolicy', OPTS))).toBe(
      'invalid_proof',
    );
  });

  it('denies invalid_proof when HumanUniqueness has < 3 public signals', async () => {
    const vkeyHash = computeVkeyHash(loadVkey('HumanUniqueness'));
    const env = makeEnvelope('HumanUniqueness', {
      vkeyHash,
      publicSignals: ['1', '2'], // < 3
    });
    expect(await denialCode(() => verifyEnvelopeProof(env, 'HumanUniqueness', OPTS))).toBe(
      'invalid_proof',
    );
  });
});

describe('requireNullifier — nonce_missing gate', () => {
  it('returns the nullifier at publicSignals[1]', () => {
    expect(requireNullifier(['root', '123456', 'scope'])).toBe('123456');
  });

  it('denies nonce_missing when the nullifier is missing', async () => {
    expect(await denialCode(() => requireNullifier(['root']))).toBe('nonce_missing');
  });

  it('denies nonce_missing when the nullifier is zero', async () => {
    expect(await denialCode(() => requireNullifier(['root', '0', 'scope']))).toBe('nonce_missing');
  });
});

describe('REAL groth16 path (generates proofs via the SDK)', () => {
  jest.setTimeout(120000);

  let agentEnvelope: ProofEnvelope;
  let humanEnvelope: ProofEnvelope;

  beforeAll(async () => {
    const human = await createHumanIdentity(123456789n);
    const agent = await createAgentCredential(
      12345n,
      42n,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      BigInt(Math.floor(Date.now() / 1000) + 86400),
    );

    const { humanProof, agentProof } = await proveHandshake(human, agent, {
      config: { circuitDir: CIRCUITS_DIR },
      backend: 'snarkjs',
    });

    agentEnvelope = envelopeFromSnarkjsProof('AgentPolicy', agentProof.proof, agentProof.publicSignals, {
      vkeyHash: computeVkeyHash(loadVkey('AgentPolicy')),
    });
    humanEnvelope = envelopeFromSnarkjsProof(
      'HumanUniqueness',
      humanProof.proof,
      humanProof.publicSignals,
      { vkeyHash: computeVkeyHash(loadVkey('HumanUniqueness')) },
    );
  });

  it('verifies a genuine AgentPolicy proof', async () => {
    await expect(verifyEnvelopeProof(agentEnvelope, 'AgentPolicy', OPTS)).resolves.toBeUndefined();
  });

  it('verifies a genuine HumanUniqueness proof', async () => {
    await expect(
      verifyEnvelopeProof(humanEnvelope, 'HumanUniqueness', OPTS),
    ).resolves.toBeUndefined();
  });

  it('denies invalid_proof for a tampered proof coordinate', async () => {
    const tampered: ProofEnvelope = {
      ...agentEnvelope,
      proof: {
        ...agentEnvelope.proof,
        pi_a: ['1', agentEnvelope.proof.pi_a[1]], // off-curve after tamper
      },
    };
    expect(await denialCode(() => verifyEnvelopeProof(tampered, 'AgentPolicy', OPTS))).toBe(
      'invalid_proof',
    );
  });

  it('verifyAgentProof accepts a bundle with a genuine agent proof', async () => {
    const bundle = {
      agent: { envelope: agentEnvelope },
    } as unknown as ParsedBundle;
    await expect(verifyAgentProof(bundle, OPTS)).resolves.toBeUndefined();
  });

  it('verifyHumanProofIfPresent verifies the human proof when present', async () => {
    const bundle = {
      agent: { envelope: agentEnvelope },
      human: { envelope: humanEnvelope },
    } as unknown as ParsedBundle;
    await expect(verifyHumanProofIfPresent(bundle, OPTS)).resolves.toBeUndefined();
  });

  it('verifyHumanProofIfPresent is a no-op when the human slot is absent (OQ-3)', async () => {
    const bundle = {
      agent: { envelope: agentEnvelope },
    } as unknown as ParsedBundle;
    await expect(verifyHumanProofIfPresent(bundle, OPTS)).resolves.toBeUndefined();
  });
});
