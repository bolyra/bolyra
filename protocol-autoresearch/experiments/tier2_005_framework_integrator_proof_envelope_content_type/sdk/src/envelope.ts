/**
 * Bolyra Proof Envelope — canonical JSON envelope for all ZKP proof payloads.
 *
 * Content-Type: application/bolyra+json
 * Spec: spec/proof-envelope.md
 */

import Ajv from 'ajv';
import envelopeSchema from './envelope.schema.json';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** MIME content type for Bolyra proof envelopes. */
export const BOLYRA_CONTENT_TYPE = 'application/bolyra+json' as const;

/** Current envelope schema version. */
export const ENVELOPE_VERSION = '1.0' as const;

/** Maximum envelope size in bytes (64 KiB). */
const MAX_ENVELOPE_BYTES = 65_536;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Proof types corresponding to Bolyra circuits. */
export enum ProofType {
  Handshake = 'handshake',
  Delegation = 'delegation',
  AgentPolicy = 'agent_policy',
}

/** Proof data matching snarkjs Groth16/PLONK output. */
export interface SnarkProof {
  readonly pi_a: [string, string, string];
  readonly pi_b: [[string, string], [string, string], [string, string]];
  readonly pi_c: [string, string, string];
  readonly protocol: 'groth16' | 'plonk';
  readonly curve: 'bn128';
}

/** Metadata attached to every proof envelope. */
export interface EnvelopeMetadata {
  readonly issuedAt: number;
  readonly nonce?: string;
  readonly sdkVersion?: string;
  readonly [key: string]: unknown;
}

/** Canonical proof envelope for HTTP transport. */
export interface ProofEnvelope {
  readonly version: string;
  readonly proofType: ProofType;
  readonly publicSignals: readonly string[];
  readonly proof: SnarkProof;
  readonly metadata: EnvelopeMetadata;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const ajv = new Ajv({ allErrors: true });
const validate = ajv.compile(envelopeSchema);

export class EnvelopeValidationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(`[${code}] ${message}`);
    this.name = 'EnvelopeValidationError';
  }
}

/**
 * Parse the major version from a "major.minor" version string.
 */
function parseMajorVersion(version: string): number {
  const major = parseInt(version.split('.')[0], 10);
  if (isNaN(major)) throw new EnvelopeValidationError('INVALID_VERSION', `Invalid version: ${version}`);
  return major;
}

/**
 * Validate an unknown value against the ProofEnvelope JSON Schema.
 * Returns the validated envelope or throws EnvelopeValidationError.
 */
export function validateEnvelope(data: unknown): ProofEnvelope {
  if (!validate(data)) {
    throw new EnvelopeValidationError(
      'SCHEMA_VIOLATION',
      'Envelope does not match JSON Schema',
      validate.errors,
    );
  }

  const envelope = data as ProofEnvelope;
  const major = parseMajorVersion(envelope.version);
  const supportedMajor = parseMajorVersion(ENVELOPE_VERSION);
  if (major !== supportedMajor) {
    throw new EnvelopeValidationError(
      'UNSUPPORTED_VERSION',
      `Unsupported major version ${major}; expected ${supportedMajor}`,
    );
  }

  return envelope;
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a ProofEnvelope to a canonical JSON string.
 * Validates before serializing.
 */
export function serializeEnvelope(envelope: ProofEnvelope): string {
  validateEnvelope(envelope);
  return JSON.stringify(envelope);
}

/**
 * Deserialize a JSON string into a validated ProofEnvelope.
 * Throws on invalid JSON, schema violations, or unsupported version.
 */
export function deserializeEnvelope(json: string): ProofEnvelope {
  if (typeof json === 'string' && json.length > MAX_ENVELOPE_BYTES) {
    throw new EnvelopeValidationError('ENVELOPE_TOO_LARGE', `Envelope exceeds ${MAX_ENVELOPE_BYTES} bytes`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new EnvelopeValidationError('INVALID_JSON', 'Input is not valid JSON');
  }

  return validateEnvelope(parsed);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a ProofEnvelope from raw snarkjs proof output.
 */
export function createEnvelope(
  proofType: ProofType,
  publicSignals: string[],
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve?: string },
  metadata?: Partial<EnvelopeMetadata>,
): ProofEnvelope {
  const envelope: ProofEnvelope = {
    version: ENVELOPE_VERSION,
    proofType,
    publicSignals,
    proof: {
      pi_a: proof.pi_a as [string, string, string],
      pi_b: proof.pi_b as [[string, string], [string, string], [string, string]],
      pi_c: proof.pi_c as [string, string, string],
      protocol: proof.protocol as 'groth16' | 'plonk',
      curve: (proof.curve ?? 'bn128') as 'bn128',
    },
    metadata: {
      issuedAt: Math.floor(Date.now() / 1000),
      ...metadata,
    },
  };

  validateEnvelope(envelope);
  return envelope;
}
