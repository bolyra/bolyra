/**
 * Groth16 proof verification for the `bolyra verify` external verifier
 * (spec §5 steps 4–5, §10, feature F6).
 *
 * Every embedded proof envelope is verified against a LOCALLY-resolved
 * verification key, and the envelope's advertised `vkeyHash` is pinned to the
 * hash of that resolved key. Pinning is MANDATORY: an envelope that omits
 * `vkeyHash`, or advertises one that does not match the key we verify against,
 * is rejected as `invalid_proof` — this stops a prover from swapping in a
 * different (attacker-controlled) circuit while still producing a
 * mathematically-valid Groth16 proof.
 *
 * Denials follow the shared contract: throw `VerifyDenial(<code>, ...)`; the
 * core orchestrator maps that to the wire deny verdict. A vkey that cannot be
 * resolved at all is an operator/config fault (`internal_error`, non-zero
 * exit), not a proof fault.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as snarkjs from 'snarkjs';
import { canonicalize } from '@bolyra/receipts';
import type { CircuitName, ProofEnvelope, ProofData } from '@bolyra/sdk';
import type { ParsedBundle } from './bundle';
import { VerifyDenial } from './verdict';

/** Options controlling where circuit verification keys are resolved from. */
export interface ProofVerifyOptions {
  /** Explicit circuits build dir (from `--circuits-dir`). Highest precedence. */
  circuitsDir?: string;
  /** Environment to read `BOLYRA_CIRCUITS_DIR` from. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
}

/** The vkey filename each circuit's Groth16 key ships under (mirrors the SDK). */
const VKEY_FILENAME: Record<CircuitName, string> = {
  AgentPolicy: 'AgentPolicy_groth16_vkey.json',
  Delegation: 'Delegation_groth16_vkey.json',
  HumanUniqueness: 'HumanUniqueness_vkey.json',
};

/** Minimum public-signal count each circuit MUST expose (spec §10). */
const MIN_PUBLIC_SIGNALS: Record<CircuitName, number> = {
  AgentPolicy: 6,
  Delegation: 6,
  HumanUniqueness: 3,
};

/**
 * Content-addressed identity of a verification key.
 *
 * `sha256:<hex>` over the canonical (sorted-key) JSON encoding of the vkey.
 * THIS IS A SHARED CONTRACT: the fixture/envelope generator stamps
 * `envelope.circuit.vkeyHash` with the exact same function, so the verifier and
 * the generator agree byte-for-byte. Do not change the encoding without
 * updating every producer of `vkeyHash`.
 */
export function computeVkeyHash(vkey: object): string {
  const hex = crypto.createHash('sha256').update(canonicalize(vkey)).digest('hex');
  return `sha256:${hex}`;
}

/**
 * Resolve the on-disk path to a circuit's Groth16 verification key.
 *
 * Precedence: `opts.circuitsDir` (`--circuits-dir`) → `BOLYRA_CIRCUITS_DIR`
 * → the bundled `@bolyra/circuits` package (best-effort). If none yield an
 * existing file the key cannot be resolved, which is an operator/config fault:
 * `internal_error` (core exits non-zero), NOT a proof denial.
 */
export function resolveVkeyPath(
  circuit: CircuitName,
  opts: ProofVerifyOptions = {},
): string {
  const filename = VKEY_FILENAME[circuit];
  const env = opts.env ?? process.env;

  const candidates: string[] = [];
  if (opts.circuitsDir) candidates.push(path.join(opts.circuitsDir, filename));
  if (env.BOLYRA_CIRCUITS_DIR) candidates.push(path.join(env.BOLYRA_CIRCUITS_DIR, filename));

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }

  // Best-effort: fall back to the bundled @bolyra/circuits package.
  try {
    const bundled = require.resolve(`@bolyra/circuits/build/${filename}`);
    if (fs.existsSync(bundled)) return bundled;
  } catch {
    // package not installed / entry not exported — fall through to denial.
  }

  throw new VerifyDenial('internal_error', 'circuit vkey not resolvable', { circuit });
}

/** Resolve + read + JSON-parse a circuit's verification key. */
function loadVkey(circuit: CircuitName, opts: ProofVerifyOptions): object {
  const vkeyPath = resolveVkeyPath(circuit, opts);
  try {
    return JSON.parse(fs.readFileSync(vkeyPath, 'utf8')) as object;
  } catch (err) {
    throw new VerifyDenial('internal_error', 'circuit vkey not resolvable', {
      circuit,
      reason: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Reconstruct the snarkjs Groth16 proof object from an envelope's affine
 * coordinates. The envelope stores only the two affine field elements per G1
 * point (and the 2×2 G2 matrix); snarkjs `groth16.verify` expects the full
 * projective form with the trailing `["1"]` / `["1","0"]` coordinates plus the
 * `protocol`/`curve` tags. This is a pure re-hydration — no math.
 */
function toSnarkjsProof(proof: ProofData): Record<string, unknown> {
  return {
    pi_a: [proof.pi_a[0], proof.pi_a[1], '1'],
    pi_b: [
      [proof.pi_b[0][0], proof.pi_b[0][1]],
      [proof.pi_b[1][0], proof.pi_b[1][1]],
      ['1', '0'],
    ],
    pi_c: [proof.pi_c[0], proof.pi_c[1], '1'],
    protocol: 'groth16',
    curve: 'bn128',
  };
}

/**
 * Verify a single proof envelope against `circuit`.
 *
 * 1. vkeyHash pinning (MANDATORY): the envelope MUST carry a `vkeyHash` that
 *    equals the hash of the locally-resolved vkey → else `invalid_proof`.
 * 2. public-signal length: at least the circuit's required count → else
 *    `invalid_proof`.
 * 3. Groth16 math: `snarkjs.groth16.verify` MUST return true → else
 *    `invalid_proof`.
 *
 * @throws VerifyDenial `internal_error` if the vkey cannot be resolved.
 * @throws VerifyDenial `invalid_proof` on any of the three checks above.
 */
export async function verifyEnvelopeProof(
  envelope: ProofEnvelope,
  circuit: CircuitName,
  opts: ProofVerifyOptions = {},
): Promise<void> {
  const vkey = loadVkey(circuit, opts);

  // (1) Mandatory vkeyHash pinning.
  const expectedHash = computeVkeyHash(vkey);
  if (envelope.circuit.vkeyHash === undefined || envelope.circuit.vkeyHash !== expectedHash) {
    throw new VerifyDenial('invalid_proof', 'vkeyHash absent or mismatched', {
      circuit,
      expected: expectedHash,
      got: envelope.circuit.vkeyHash ?? null,
    });
  }

  // (2) Public-signal length.
  const minSignals = MIN_PUBLIC_SIGNALS[circuit];
  if (envelope.publicSignals.length < minSignals) {
    throw new VerifyDenial('invalid_proof', 'too few public signals', {
      circuit,
      expected: minSignals,
      got: envelope.publicSignals.length,
    });
  }

  // (3) Groth16 verification (no logger argument — keep snarkjs quiet).
  const ok = await snarkjs.groth16.verify(
    vkey,
    envelope.publicSignals,
    toSnarkjsProof(envelope.proof),
  );
  if (!ok) {
    throw new VerifyDenial('invalid_proof', 'groth16 verification failed', { circuit });
  }
}

/** Verify the mandatory AgentPolicy proof carried by the bundle. */
export async function verifyAgentProof(
  bundle: ParsedBundle,
  opts: ProofVerifyOptions = {},
): Promise<void> {
  await verifyEnvelopeProof(bundle.agent.envelope, 'AgentPolicy', opts);
}

/**
 * Verify the human uniqueness proof IFF the bundle carries one. An absent human
 * slot is a valid presentation (agent-only handshake) and is a no-op (OQ-3).
 */
export async function verifyHumanProofIfPresent(
  bundle: ParsedBundle,
  opts: ProofVerifyOptions = {},
): Promise<void> {
  if (bundle.human === undefined) return;
  await verifyEnvelopeProof(bundle.human.envelope, 'HumanUniqueness', opts);
}

/**
 * Extract the agent's nullifier (AgentPolicy publicSignals[1]) as the one-time
 * handshake identifier used for replay protection.
 *
 * A missing entry or a zero value means the proof lacks a usable nullifier and
 * cannot be pinned in the nonce store → `nonce_missing` (spec §5, F6).
 */
export function requireNullifier(agentPublicSignals: string[]): string {
  const nullifier = agentPublicSignals[1];
  if (nullifier === undefined || nullifier === '0') {
    throw new VerifyDenial('nonce_missing', 'proof lacks a usable nullifier');
  }
  return nullifier;
}
