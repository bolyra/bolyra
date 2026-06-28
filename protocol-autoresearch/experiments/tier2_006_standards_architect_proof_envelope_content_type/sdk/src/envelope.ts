/**
 * Proof envelope codec for `application/bolyra-proof+cbor` and
 * `application/bolyra-proof+json`.
 *
 * Wire layout (CBOR variant):
 *   bytes 0-1 : version prefix (big-endian uint16, currently 0x0001)
 *   bytes 2-N : CBOR-encoded map { version, circuit, provingSystem,
 *               proof, publicSignals, metadata? }
 *
 * @module
 */

import * as cborg from 'cborg';
import {
  ENVELOPE_VERSION,
  CircuitId,
  ProvingSystem,
  type ProofEnvelope,
  type EnvelopeMetadata,
} from './types/envelope.js';

// Re-export types for convenience
export { CircuitId, ProvingSystem, ENVELOPE_VERSION } from './types/envelope.js';
export type { ProofEnvelope, EnvelopeMetadata } from './types/envelope.js';

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

export const CONTENT_TYPE_CBOR = 'application/bolyra-proof+cbor';
export const CONTENT_TYPE_JSON = 'application/bolyra-proof+json';

/* ------------------------------------------------------------------ */
/*  Validation helpers                                                */
/* ------------------------------------------------------------------ */

const VALID_CIRCUITS = new Set<number>([
  CircuitId.Human,
  CircuitId.Agent,
  CircuitId.Delegation,
  CircuitId.ModelInstance,
]);

const VALID_PROVING_SYSTEMS = new Set<number>([
  ProvingSystem.Groth16,
  ProvingSystem.PLONK,
]);

function assertValidEnvelope(env: ProofEnvelope): void {
  if (env.version !== ENVELOPE_VERSION) {
    throw new RangeError(
      `Unsupported envelope version 0x${env.version.toString(16).padStart(4, '0')}; ` +
      `expected 0x${ENVELOPE_VERSION.toString(16).padStart(4, '0')}`
    );
  }
  if (!VALID_CIRCUITS.has(env.circuit)) {
    throw new RangeError(`Unknown CircuitId: ${env.circuit}`);
  }
  if (!VALID_PROVING_SYSTEMS.has(env.provingSystem)) {
    throw new RangeError(`Unknown ProvingSystem: ${env.provingSystem}`);
  }
  if (!env.proof || typeof env.proof !== 'object') {
    throw new TypeError('proof must be a non-null object');
  }
  if (!Array.isArray(env.publicSignals)) {
    throw new TypeError('publicSignals must be an array');
  }
}

/* ------------------------------------------------------------------ */
/*  CBOR codec                                                        */
/* ------------------------------------------------------------------ */

/**
 * Encode a `ProofEnvelope` into CBOR bytes with a 2-byte version
 * prefix.  The result is suitable for use as an HTTP body with
 * `Content-Type: application/bolyra-proof+cbor`.
 */
export function encodeProofEnvelope(envelope: ProofEnvelope): Uint8Array {
  assertValidEnvelope(envelope);

  const cborPayload = cborg.encode({
    version: envelope.version,
    circuit: envelope.circuit,
    provingSystem: envelope.provingSystem,
    proof: envelope.proof,
    publicSignals: envelope.publicSignals,
    ...(envelope.metadata ? { metadata: envelope.metadata } : {}),
  });

  // Prepend 2-byte big-endian version prefix
  const result = new Uint8Array(2 + cborPayload.length);
  result[0] = (envelope.version >> 8) & 0xff;
  result[1] = envelope.version & 0xff;
  result.set(cborPayload, 2);
  return result;
}

/**
 * Decode CBOR bytes (with 2-byte version prefix) into a validated
 * `ProofEnvelope`.
 *
 * @throws {RangeError} on version mismatch or unknown enum values
 * @throws {TypeError}  on malformed CBOR or missing required fields
 */
export function decodeProofEnvelope(data: Uint8Array): ProofEnvelope {
  if (data.length < 4) {
    throw new TypeError('Envelope too short: expected at least 4 bytes');
  }

  const prefixVersion = (data[0] << 8) | data[1];
  if (prefixVersion !== ENVELOPE_VERSION) {
    throw new RangeError(
      `Unsupported envelope version prefix 0x${prefixVersion.toString(16).padStart(4, '0')}; ` +
      `expected 0x${ENVELOPE_VERSION.toString(16).padStart(4, '0')}`
    );
  }

  let decoded: Record<string, unknown>;
  try {
    decoded = cborg.decode(data.subarray(2)) as Record<string, unknown>;
  } catch (err) {
    throw new TypeError(`Malformed CBOR payload: ${(err as Error).message}`);
  }

  if (typeof decoded !== 'object' || decoded === null) {
    throw new TypeError('CBOR payload must be a map');
  }

  const envelope: ProofEnvelope = {
    version: decoded.version as number,
    circuit: decoded.circuit as number,
    provingSystem: decoded.provingSystem as number,
    proof: decoded.proof as Record<string, unknown>,
    publicSignals: decoded.publicSignals as string[],
    ...(decoded.metadata ? { metadata: decoded.metadata as EnvelopeMetadata } : {}),
  };

  assertValidEnvelope(envelope);
  return envelope;
}

/* ------------------------------------------------------------------ */
/*  JSON codec (+json fallback)                                       */
/* ------------------------------------------------------------------ */

const CIRCUIT_LABELS: Record<CircuitId, string> = {
  [CircuitId.Human]: 'human',
  [CircuitId.Agent]: 'agent',
  [CircuitId.Delegation]: 'delegation',
  [CircuitId.ModelInstance]: 'model-instance',
};

const CIRCUIT_FROM_LABEL: Record<string, CircuitId> = Object.fromEntries(
  Object.entries(CIRCUIT_LABELS).map(([k, v]) => [v, Number(k) as CircuitId])
) as Record<string, CircuitId>;

const PROVING_SYSTEM_LABELS: Record<ProvingSystem, string> = {
  [ProvingSystem.Groth16]: 'groth16',
  [ProvingSystem.PLONK]: 'plonk',
};

const PROVING_SYSTEM_FROM_LABEL: Record<string, ProvingSystem> = Object.fromEntries(
  Object.entries(PROVING_SYSTEM_LABELS).map(([k, v]) => [v, Number(k) as ProvingSystem])
) as Record<string, ProvingSystem>;

/** JSON-serializable representation of a proof envelope. */
export interface ProofEnvelopeJSON {
  version: string;        // e.g. "0x0001"
  circuit: string;        // human | agent | delegation | model-instance
  provingSystem: string;  // groth16 | plonk
  proof: Record<string, unknown>;
  publicSignals: string[];
  metadata?: EnvelopeMetadata;
}

/**
 * Serialize a `ProofEnvelope` to the JSON fallback format
 * (`application/bolyra-proof+json`).
 */
export function proofEnvelopeToJSON(envelope: ProofEnvelope): ProofEnvelopeJSON {
  assertValidEnvelope(envelope);
  return {
    version: `0x${envelope.version.toString(16).padStart(4, '0')}`,
    circuit: CIRCUIT_LABELS[envelope.circuit],
    provingSystem: PROVING_SYSTEM_LABELS[envelope.provingSystem],
    proof: envelope.proof,
    publicSignals: envelope.publicSignals,
    ...(envelope.metadata ? { metadata: envelope.metadata } : {}),
  };
}

/**
 * Parse a JSON fallback object into a validated `ProofEnvelope`.
 *
 * @throws {RangeError} on unknown enum labels or version mismatch
 * @throws {TypeError}  on missing / malformed fields
 */
export function proofEnvelopeFromJSON(json: ProofEnvelopeJSON): ProofEnvelope {
  if (typeof json !== 'object' || json === null) {
    throw new TypeError('Expected a JSON object');
  }

  const version = parseInt(json.version, 16);
  if (Number.isNaN(version)) {
    throw new TypeError(`Invalid version string: ${json.version}`);
  }

  const circuit = CIRCUIT_FROM_LABEL[json.circuit];
  if (circuit === undefined) {
    throw new RangeError(`Unknown circuit label: "${json.circuit}"`);
  }

  const provingSystem = PROVING_SYSTEM_FROM_LABEL[json.provingSystem];
  if (provingSystem === undefined) {
    throw new RangeError(`Unknown provingSystem label: "${json.provingSystem}"`);
  }

  const envelope: ProofEnvelope = {
    version,
    circuit,
    provingSystem,
    proof: json.proof,
    publicSignals: json.publicSignals,
    ...(json.metadata ? { metadata: json.metadata } : {}),
  };

  assertValidEnvelope(envelope);
  return envelope;
}

/* ------------------------------------------------------------------ */
/*  Content negotiation helpers                                       */
/* ------------------------------------------------------------------ */

/**
 * Given an HTTP `Accept` header value, return the best matching
 * Bolyra proof content type, or `null` if neither is acceptable.
 */
export function negotiateProofContentType(
  accept: string
): typeof CONTENT_TYPE_CBOR | typeof CONTENT_TYPE_JSON | null {
  const lower = accept.toLowerCase();
  // Prefer CBOR when both are acceptable or wildcard
  if (lower.includes('application/bolyra-proof+cbor') || lower.includes('*/*') || lower.includes('application/*')) {
    return CONTENT_TYPE_CBOR;
  }
  if (lower.includes('application/bolyra-proof+json')) {
    return CONTENT_TYPE_JSON;
  }
  return null;
}
