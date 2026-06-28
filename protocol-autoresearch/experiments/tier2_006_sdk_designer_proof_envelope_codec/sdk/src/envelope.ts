/**
 * BolyraEnvelope — self-describing proof envelope with named public signals.
 *
 * Replaces bare { proof, publicSignals: bigint[] } with a versioned,
 * typed envelope that maps signal names to values.
 */

import {
  type CircuitName,
  type ProvingSystem,
  SIGNAL_MAPS,
  VALID_PROVING_SYSTEMS,
} from './circuits/signal-maps.js';

export { type CircuitName, type ProvingSystem } from './circuits/signal-maps.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const ENVELOPE_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SnarkProof {
  readonly pi_a: string[];
  readonly pi_b: string[][];
  readonly pi_c: string[];
  readonly protocol: string;
  readonly curve: string;
}

export interface BolyraEnvelope {
  readonly version: string;
  readonly circuit: CircuitName;
  readonly provingSystem: ProvingSystem;
  readonly signals: Record<string, string>;
  readonly proof: SnarkProof;
}

export interface DecodedEnvelope {
  readonly version: string;
  readonly circuit: CircuitName;
  readonly provingSystem: ProvingSystem;
  readonly signals: Record<string, string>;
  readonly proof: SnarkProof;
  /** Ordered bigint array matching the circuit's positional signal layout. */
  readonly publicSignals: bigint[];
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class EnvelopeVersionError extends Error {
  constructor(version: string) {
    super(`Unsupported envelope version: ${version}`);
    this.name = 'EnvelopeVersionError';
  }
}

export class UnknownCircuitError extends Error {
  constructor(circuit: string) {
    super(`Unknown circuit: ${circuit}`);
    this.name = 'UnknownCircuitError';
  }
}

export class SignalCountMismatch extends Error {
  constructor(circuit: string, expected: number, got: number) {
    super(`Signal count mismatch for ${circuit}: expected ${expected}, got ${got}`);
    this.name = 'SignalCountMismatch';
  }
}

export class InvalidProvingSystemError extends Error {
  constructor(circuit: string, provingSystem: string) {
    super(`Invalid proving system '${provingSystem}' for circuit '${circuit}'`);
    this.name = 'InvalidProvingSystemError';
  }
}

// ---------------------------------------------------------------------------
// encode()
// ---------------------------------------------------------------------------

/**
 * Encode a raw proof and positional public signals into a BolyraEnvelope.
 *
 * @param circuit - Circuit that produced the proof
 * @param provingSystem - Proving system used (groth16 or plonk)
 * @param rawProof - Opaque proof object from snarkjs
 * @param rawSignals - Positional public signals array (string-encoded bigints)
 * @returns Versioned BolyraEnvelope with named signals
 */
export function encode(
  circuit: CircuitName,
  provingSystem: ProvingSystem,
  rawProof: SnarkProof,
  rawSignals: string[],
): BolyraEnvelope {
  const signalNames = SIGNAL_MAPS[circuit];
  if (!signalNames) {
    throw new UnknownCircuitError(circuit);
  }

  const validSystems = VALID_PROVING_SYSTEMS[circuit];
  if (!validSystems.includes(provingSystem)) {
    throw new InvalidProvingSystemError(circuit, provingSystem);
  }

  if (rawSignals.length !== signalNames.length) {
    throw new SignalCountMismatch(circuit, signalNames.length, rawSignals.length);
  }

  const signals: Record<string, string> = {};
  for (let i = 0; i < signalNames.length; i++) {
    signals[signalNames[i]] = rawSignals[i];
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
// decode()
// ---------------------------------------------------------------------------

/**
 * Decode and validate a BolyraEnvelope, producing ordered publicSignals[].
 *
 * @param envelope - Raw envelope object (e.g. parsed from JSON)
 * @returns DecodedEnvelope with both named signals and positional bigint array
 */
export function decode(
  envelope: Record<string, unknown>,
): DecodedEnvelope {
  const version = envelope.version as string;
  if (!version || typeof version !== 'string') {
    throw new EnvelopeVersionError(String(version));
  }

  const majorVersion = parseInt(version.split('.')[0], 10);
  if (isNaN(majorVersion) || majorVersion > 1) {
    throw new EnvelopeVersionError(version);
  }

  const circuit = envelope.circuit as string;
  if (!(circuit in SIGNAL_MAPS)) {
    throw new UnknownCircuitError(circuit);
  }
  const circuitName = circuit as CircuitName;

  const provingSystem = envelope.provingSystem as string;
  const validSystems = VALID_PROVING_SYSTEMS[circuitName];
  if (!validSystems.includes(provingSystem as ProvingSystem)) {
    throw new InvalidProvingSystemError(circuitName, provingSystem);
  }

  const signalNames = SIGNAL_MAPS[circuitName];
  const signals = envelope.signals as Record<string, string>;
  if (!signals || typeof signals !== 'object') {
    throw new SignalCountMismatch(circuitName, signalNames.length, 0);
  }

  const signalKeys = Object.keys(signals);
  if (signalKeys.length !== signalNames.length) {
    throw new SignalCountMismatch(circuitName, signalNames.length, signalKeys.length);
  }

  const publicSignals: bigint[] = [];
  for (const name of signalNames) {
    if (!(name in signals)) {
      throw new SignalCountMismatch(circuitName, signalNames.length, signalKeys.length);
    }
    publicSignals.push(BigInt(signals[name]));
  }

  return {
    version,
    circuit: circuitName,
    provingSystem: provingSystem as ProvingSystem,
    signals,
    proof: envelope.proof as SnarkProof,
    publicSignals,
  };
}

// ---------------------------------------------------------------------------
// fromRaw() — migration helper
// ---------------------------------------------------------------------------

/**
 * Migration helper: wrap a raw snarkjs proof output into a BolyraEnvelope.
 *
 * This is a thin alias for encode() that serves as the upgrade path for
 * integrators currently using positional publicSignals[] arrays.
 *
 * @example
 * ```ts
 * // Before (positional):
 * const { proof, publicSignals } = await snarkjs.groth16.fullProve(...);
 * const root = publicSignals[0]; // fragile positional indexing
 *
 * // After (named):
 * const envelope = fromRaw('HumanUniqueness', 'groth16', proof, publicSignals);
 * const root = envelope.signals.humanMerkleRoot; // self-documenting
 * ```
 */
export function fromRaw(
  circuit: CircuitName,
  provingSystem: ProvingSystem,
  rawProof: SnarkProof,
  rawSignals: string[],
): BolyraEnvelope {
  return encode(circuit, provingSystem, rawProof, rawSignals);
}
