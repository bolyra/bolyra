/**
 * BolyraEnvelope — self-describing proof envelope with named public signals.
 *
 * Replaces bare `{ proof, publicSignals: bigint[] }` with a versioned,
 * circuit-aware envelope that maps positional signals to human-readable names.
 *
 * @module
 */

import {
  SIGNAL_MAPS,
  VALID_CIRCUITS,
  VALID_PROVING_SYSTEMS,
  type BolyraCircuit,
  type BolyraProvingSystem,
} from './signals.js';

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/** Current envelope schema version. */
export const ENVELOPE_VERSION = '1.0.0';

/** Supported major version for decode validation. */
const SUPPORTED_MAJOR = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** snarkjs proof object (passthrough). */
export interface SnarkjsProof {
  readonly pi_a: readonly string[];
  readonly pi_b: readonly (readonly string[])[];
  readonly pi_c: readonly string[];
  readonly protocol: string;
  readonly curve: string;
}

/** Named public signals keyed by field name. Values are string-encoded bigints. */
export type NamedSignals = Record<string, string>;

/** Self-describing proof envelope. */
export interface BolyraEnvelope {
  readonly version: string;
  readonly circuit: BolyraCircuit;
  readonly provingSystem: BolyraProvingSystem;
  readonly signals: NamedSignals;
  readonly proof: SnarkjsProof;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class EnvelopeError extends Error {
  constructor(public readonly code: string, message: string) {
    super(`[${code}] ${message}`);
    this.name = 'EnvelopeError';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseMajor(version: string): number {
  const n = parseInt(version.split('.')[0], 10);
  if (Number.isNaN(n)) {
    throw new EnvelopeError('INVALID_VERSION', `Cannot parse version: ${version}`);
  }
  return n;
}

function getSignalNames(circuit: string): readonly string[] {
  if (!VALID_CIRCUITS.has(circuit)) {
    throw new EnvelopeError(
      'UNKNOWN_CIRCUIT',
      `Unknown circuit "${circuit}". Expected one of: ${[...VALID_CIRCUITS].join(', ')}`,
    );
  }
  return SIGNAL_MAPS[circuit as BolyraCircuit];
}

// ---------------------------------------------------------------------------
// encode
// ---------------------------------------------------------------------------

/**
 * Encode raw snarkjs output into a BolyraEnvelope.
 *
 * Zips the positional `rawSignals` array with the signal map for `circuit`
 * to produce a named `signals` record.
 *
 * @param circuit       - Circuit that produced the proof
 * @param provingSystem - Proving system used (groth16 | plonk)
 * @param rawProof      - snarkjs proof object
 * @param rawSignals    - snarkjs publicSignals array (positional bigint strings)
 * @returns A fully populated BolyraEnvelope
 */
export function encode(
  circuit: BolyraCircuit,
  provingSystem: BolyraProvingSystem,
  rawProof: SnarkjsProof,
  rawSignals: readonly string[],
): BolyraEnvelope {
  if (!VALID_PROVING_SYSTEMS.has(provingSystem)) {
    throw new EnvelopeError(
      'UNKNOWN_PROVING_SYSTEM',
      `Unknown proving system "${provingSystem}". Expected one of: groth16, plonk`,
    );
  }

  const names = getSignalNames(circuit);

  if (rawSignals.length !== names.length) {
    throw new EnvelopeError(
      'SIGNAL_COUNT_MISMATCH',
      `Expected ${names.length} signals for ${circuit}, got ${rawSignals.length}`,
    );
  }

  const signals: Record<string, string> = {};
  for (let i = 0; i < names.length; i++) {
    signals[names[i]] = String(rawSignals[i]);
  }

  return {
    version: ENVELOPE_VERSION,
    circuit,
    provingSystem,
    signals,
    proof: rawProof,
  };
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

/**
 * Decode a BolyraEnvelope back to positional `{ proof, publicSignals }`
 * suitable for `snarkjs.groth16.verify()` / `snarkjs.plonk.verify()`.
 *
 * @param envelope - A BolyraEnvelope (e.g. received over the wire)
 * @returns Object with `proof` and `publicSignals` (positional string array)
 * @throws EnvelopeError on version mismatch or unknown circuit
 */
export function decode(envelope: BolyraEnvelope): {
  proof: SnarkjsProof;
  publicSignals: string[];
} {
  // Version gate
  const major = parseMajor(envelope.version);
  if (major !== SUPPORTED_MAJOR) {
    throw new EnvelopeError(
      'UNSUPPORTED_VERSION',
      `Envelope version ${envelope.version} (major ${major}) is not supported. Expected major ${SUPPORTED_MAJOR}.`,
    );
  }

  const names = getSignalNames(envelope.circuit);
  const publicSignals: string[] = new Array(names.length);

  for (let i = 0; i < names.length; i++) {
    const val = envelope.signals[names[i]];
    if (val === undefined) {
      throw new EnvelopeError(
        'MISSING_SIGNAL',
        `Signal "${names[i]}" missing from envelope for circuit ${envelope.circuit}`,
      );
    }
    publicSignals[i] = String(val);
  }

  return { proof: envelope.proof, publicSignals };
}

// ---------------------------------------------------------------------------
// fromRaw (migration convenience)
// ---------------------------------------------------------------------------

/**
 * Convenience alias for `encode()` — entry point for migrating existing
 * callers from bare `{ proof, publicSignals }` to envelopes.
 *
 * @example
 * ```ts
 * // Before (positional — error-prone):
 * const root = publicSignals[0]; // wait, is it [0] or [2]?
 *
 * // After (named — self-documenting):
 * const env = fromRaw('HumanUniqueness', 'groth16', proof, publicSignals);
 * const root = env.signals.humanMerkleRoot; // ✓
 * ```
 */
export function fromRaw(
  circuit: BolyraCircuit,
  provingSystem: BolyraProvingSystem,
  rawProof: SnarkjsProof,
  rawSignals: readonly string[],
): BolyraEnvelope {
  return encode(circuit, provingSystem, rawProof, rawSignals);
}
