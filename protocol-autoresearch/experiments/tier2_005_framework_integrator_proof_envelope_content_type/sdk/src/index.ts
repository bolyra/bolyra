/**
 * @bolyra/sdk — public API surface
 *
 * This file shows the envelope integration points. In the real SDK,
 * proveHandshake() and delegate() call snarkjs internally; here we
 * wrap their output in ProofEnvelope before returning.
 */

export {
  BOLYRA_CONTENT_TYPE,
  ENVELOPE_VERSION,
  ProofType,
  createEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  validateEnvelope,
  EnvelopeValidationError,
} from './envelope.js';

export type {
  ProofEnvelope,
  SnarkProof,
  EnvelopeMetadata,
} from './envelope.js';

import { createEnvelope, ProofType } from './envelope.js';
import type { ProofEnvelope } from './envelope.js';

// ---------------------------------------------------------------------------
// Existing SDK types (unchanged)
// ---------------------------------------------------------------------------

export interface HumanIdentity {
  readonly identityCommitment: bigint;
  readonly secret: bigint;
}

export interface AgentCredential {
  readonly modelHash: bigint;
  readonly permissions: number;
  readonly expiry: number;
}

// ---------------------------------------------------------------------------
// proveHandshake — now returns ProofEnvelope
// ---------------------------------------------------------------------------

/**
 * Prove a human–agent handshake.
 *
 * Returns a `ProofEnvelope` with `proofType: 'handshake'` that wraps
 * the snarkjs Groth16 proof output.
 *
 * @example
 * ```ts
 * const envelope = await proveHandshake(human, agent, nonce);
 * console.log(envelope.proofType); // 'handshake'
 * const json = serializeEnvelope(envelope);
 * // POST json with Content-Type: application/bolyra+json
 * ```
 */
export async function proveHandshake(
  _human: HumanIdentity,
  _agent: AgentCredential,
  nonce: string,
): Promise<ProofEnvelope> {
  // In the real SDK, snarkjs.groth16.fullProve() is called here.
  // The raw proof + publicSignals are wrapped in a ProofEnvelope.
  const rawProof = await generateSnarkProof('HumanUniqueness', {});
  return createEnvelope(
    ProofType.Handshake,
    rawProof.publicSignals,
    rawProof.proof,
    { nonce },
  );
}

// ---------------------------------------------------------------------------
// delegate — now returns ProofEnvelope
// ---------------------------------------------------------------------------

/**
 * Produce a delegation proof narrowing permissions.
 *
 * Returns a `ProofEnvelope` with `proofType: 'delegation'`.
 */
export async function delegate(
  _delegator: AgentCredential,
  _narrowedPermissions: number,
): Promise<ProofEnvelope> {
  const rawProof = await generateSnarkProof('Delegation', {});
  return createEnvelope(
    ProofType.Delegation,
    rawProof.publicSignals,
    rawProof.proof,
  );
}

// ---------------------------------------------------------------------------
// Internal proving stub (real SDK calls snarkjs)
// ---------------------------------------------------------------------------

async function generateSnarkProof(
  _circuit: string,
  _input: Record<string, unknown>,
): Promise<{
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve: string };
  publicSignals: string[];
}> {
  // Placeholder — real implementation uses snarkjs.groth16.fullProve()
  return {
    proof: {
      pi_a: ['1', '2', '1'],
      pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
      pi_c: ['7', '8', '1'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    publicSignals: ['100', '200', '300'],
  };
}
