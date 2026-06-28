/**
 * Proof Envelope — versioned wire format for Bolyra ZKP proofs.
 *
 * Media types:
 *   application/bolyra-proof+json
 *   application/bolyra-proof+cbor
 */

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import * as cborx from 'cbor-x';
import proofEnvelopeSchema from '../../spec/proof-envelope-schema.json';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const ENVELOPE_VERSION = '1.0.0';

export const CONTENT_TYPE_JSON = 'application/bolyra-proof+json';
export const CONTENT_TYPE_CBOR = 'application/bolyra-proof+cbor';

export type ProvingSystem = 'groth16' | 'plonk';

export type CircuitId =
  | 'bolyra:circuit:HumanUniqueness'
  | 'bolyra:circuit:AgentPolicy'
  | 'bolyra:circuit:Delegation';

export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: 'groth16';
  curve?: 'bn128';
}

export interface PlonkProof {
  A: [string, string, string];
  B: [string, string, string];
  C: [string, string, string];
  Z: [string, string, string];
  T1: [string, string, string];
  T2: [string, string, string];
  T3: [string, string, string];
  Wxi: [string, string, string];
  Wxiw: [string, string, string];
  eval_a: string;
  eval_b: string;
  eval_c: string;
  eval_s1: string;
  eval_s2: string;
  eval_zw: string;
  eval_r?: string;
  protocol: 'plonk';
  curve?: 'bn128';
}

export interface EnvelopeMetadata {
  chain?: number;
  registryAddress?: string;
  issuedAt: number;
}

export interface ProofEnvelope {
  version: string;
  circuitId: CircuitId;
  provingSystem: ProvingSystem;
  publicSignals: string[];
  proof: Groth16Proof | PlonkProof;
  metadata: EnvelopeMetadata;
}

export type EnvelopeFormat = 'json' | 'cbor';

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export enum EnvelopeErrorCode {
  SCHEMA_VALIDATION_FAILED = 'ENVELOPE_SCHEMA_VALIDATION_FAILED',
  UNKNOWN_VERSION = 'ENVELOPE_UNKNOWN_VERSION',
  UNKNOWN_CONTENT_TYPE = 'ENVELOPE_UNKNOWN_CONTENT_TYPE',
  DESERIALIZATION_FAILED = 'ENVELOPE_DESERIALIZATION_FAILED',
}

export class BolyraEnvelopeError extends Error {
  constructor(
    public readonly code: EnvelopeErrorCode,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'BolyraEnvelopeError';
  }
}

// ---------------------------------------------------------------------------
// Validator (lazy singleton)
// ---------------------------------------------------------------------------

let _validator: ReturnType<Ajv['compile']> | null = null;

function getValidator() {
  if (!_validator) {
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    _validator = ajv.compile(proofEnvelopeSchema);
  }
  return _validator;
}

function validateEnvelope(data: unknown): asserts data is ProofEnvelope {
  const validate = getValidator();
  if (!validate(data)) {
    throw new BolyraEnvelopeError(
      EnvelopeErrorCode.SCHEMA_VALIDATION_FAILED,
      `Proof envelope schema validation failed: ${validate.errors?.map((e) => `${e.instancePath} ${e.message}`).join('; ')}`,
      validate.errors,
    );
  }
}

// ---------------------------------------------------------------------------
// Version negotiation
// ---------------------------------------------------------------------------

const SUPPORTED_VERSIONS = ['1.0.0'];

export function negotiateVersion(requestedVersion: string): string {
  if (SUPPORTED_VERSIONS.includes(requestedVersion)) {
    return requestedVersion;
  }
  // Accept any 1.x.x (minor/patch compatible)
  const [major] = requestedVersion.split('.');
  if (major === '1') {
    return ENVELOPE_VERSION;
  }
  throw new BolyraEnvelopeError(
    EnvelopeErrorCode.UNKNOWN_VERSION,
    `Unsupported envelope version: ${requestedVersion}. Supported: ${SUPPORTED_VERSIONS.join(', ')}`,
  );
}

// ---------------------------------------------------------------------------
// Content-type helpers
// ---------------------------------------------------------------------------

export function contentTypeForFormat(format: EnvelopeFormat): string {
  return format === 'cbor' ? CONTENT_TYPE_CBOR : CONTENT_TYPE_JSON;
}

export function formatFromContentType(contentType: string): EnvelopeFormat {
  const ct = contentType.toLowerCase().trim();
  if (ct === CONTENT_TYPE_JSON || ct.startsWith(CONTENT_TYPE_JSON)) return 'json';
  if (ct === CONTENT_TYPE_CBOR || ct.startsWith(CONTENT_TYPE_CBOR)) return 'cbor';
  throw new BolyraEnvelopeError(
    EnvelopeErrorCode.UNKNOWN_CONTENT_TYPE,
    `Unknown content type: ${contentType}. Expected ${CONTENT_TYPE_JSON} or ${CONTENT_TYPE_CBOR}`,
  );
}

// ---------------------------------------------------------------------------
// Serialize / Deserialize
// ---------------------------------------------------------------------------

export function serializeEnvelope(envelope: ProofEnvelope, format: EnvelopeFormat = 'json'): Buffer {
  validateEnvelope(envelope);

  if (format === 'cbor') {
    return Buffer.from(cborx.encode(envelope));
  }
  return Buffer.from(JSON.stringify(envelope), 'utf-8');
}

export function deserializeEnvelope(buf: Buffer | Uint8Array, contentType: string): ProofEnvelope {
  const format = formatFromContentType(contentType);

  let parsed: unknown;
  try {
    if (format === 'cbor') {
      parsed = cborx.decode(Buffer.from(buf));
    } else {
      parsed = JSON.parse(Buffer.from(buf).toString('utf-8'));
    }
  } catch (err) {
    throw new BolyraEnvelopeError(
      EnvelopeErrorCode.DESERIALIZATION_FAILED,
      `Failed to deserialize ${contentType} envelope: ${(err as Error).message}`,
    );
  }

  // Version check before full schema validation
  if (
    typeof parsed === 'object' &&
    parsed !== null &&
    'version' in parsed &&
    typeof (parsed as Record<string, unknown>).version === 'string'
  ) {
    negotiateVersion((parsed as Record<string, unknown>).version as string);
  }

  validateEnvelope(parsed);
  return parsed;
}

// ---------------------------------------------------------------------------
// Factory helper
// ---------------------------------------------------------------------------

export function createProofEnvelope(
  circuitId: CircuitId,
  provingSystem: ProvingSystem,
  publicSignals: string[],
  proof: Groth16Proof | PlonkProof,
  metadata: Partial<EnvelopeMetadata> & { issuedAt?: number } = {},
): ProofEnvelope {
  return {
    version: ENVELOPE_VERSION,
    circuitId,
    provingSystem,
    publicSignals,
    proof,
    metadata: {
      issuedAt: metadata.issuedAt ?? Date.now(),
      ...(metadata.chain !== undefined && { chain: metadata.chain }),
      ...(metadata.registryAddress !== undefined && { registryAddress: metadata.registryAddress }),
    },
  };
}
