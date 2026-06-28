import { z } from 'zod';

/**
 * MIME content type for Bolyra proof envelopes.
 */
export const CONTENT_TYPE = 'application/bolyra-proof+json' as const;

/** Current envelope schema version. */
export const ENVELOPE_VERSION = '1.0' as const;

/** Proof data matching snarkjs Groth16/PLONK output. */
export interface ProofData {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: 'groth16' | 'plonk';
}

/** Metadata attached to every proof envelope. */
export interface ProofMetadata {
  prover: string;
  timestamp: string; // ISO 8601
}

/** Canonical proof envelope for HTTP transport. */
export interface ProofEnvelope {
  version: string;
  circuit: string;
  publicSignals: string[];
  proof: ProofData;
  metadata: ProofMetadata;
}

// ── Zod schemas ──────────────────────────────────────────────────────────────

const ProofDataSchema = z.object({
  pi_a: z.array(z.string()),
  pi_b: z.array(z.array(z.string())),
  pi_c: z.array(z.string()),
  protocol: z.enum(['groth16', 'plonk']),
});

const ProofMetadataSchema = z.object({
  prover: z.string().min(1),
  timestamp: z.string().datetime(),
});

export const ProofEnvelopeSchema = z.object({
  version: z.string(),
  circuit: z.string().min(1),
  publicSignals: z.array(z.string()),
  proof: ProofDataSchema,
  metadata: ProofMetadataSchema,
});

// ── Version helpers ──────────────────────────────────────────────────────────

function parseMajorVersion(version: string): number {
  const major = parseInt(version.split('.')[0], 10);
  if (isNaN(major)) throw new Error(`Invalid version string: ${version}`);
  return major;
}

function assertSupportedVersion(version: string): void {
  const major = parseMajorVersion(version);
  const supportedMajor = parseMajorVersion(ENVELOPE_VERSION);
  if (major !== supportedMajor) {
    throw new Error(
      `Unsupported envelope major version ${major}; expected ${supportedMajor}`
    );
  }
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Serialize a ProofEnvelope to a JSON string.
 */
export function serializeEnvelope(envelope: ProofEnvelope): string {
  ProofEnvelopeSchema.parse(envelope);
  return JSON.stringify(envelope);
}

/**
 * Deserialize a JSON string into a validated ProofEnvelope.
 * Throws on validation failure or unsupported major version.
 */
export function deserializeEnvelope(raw: string): ProofEnvelope {
  const parsed = JSON.parse(raw);
  const envelope = ProofEnvelopeSchema.parse(parsed);
  assertSupportedVersion(envelope.version);
  return envelope;
}

/**
 * Validate an unknown object as a ProofEnvelope.
 * Returns the validated envelope or throws a ZodError.
 */
export function validateEnvelope(data: unknown): ProofEnvelope {
  const envelope = ProofEnvelopeSchema.parse(data);
  assertSupportedVersion(envelope.version);
  return envelope;
}

/**
 * Wrap raw snarkjs proof output into a ProofEnvelope.
 */
export function envelopeFromSnarkjsProof(
  circuit: string,
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string },
  publicSignals: string[],
  prover: string = '@bolyra/sdk'
): ProofEnvelope {
  return {
    version: ENVELOPE_VERSION,
    circuit,
    publicSignals,
    proof: {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: proof.protocol as 'groth16' | 'plonk',
    },
    metadata: {
      prover,
      timestamp: new Date().toISOString(),
    },
  };
}
