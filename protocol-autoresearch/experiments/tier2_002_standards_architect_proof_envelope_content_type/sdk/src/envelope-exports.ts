/**
 * Re-exports for ProofEnvelope types and helpers.
 * Import this from sdk/src/index.ts.
 */
export {
  // Types
  type ProofEnvelope,
  type Groth16Proof,
  type PlonkProof,
  type EnvelopeMetadata,
  type CircuitId,
  type ProvingSystem,
  type EnvelopeFormat,

  // Constants
  ENVELOPE_VERSION,
  CONTENT_TYPE_JSON,
  CONTENT_TYPE_CBOR,

  // Error types
  BolyraEnvelopeError,
  EnvelopeErrorCode,

  // Functions
  serializeEnvelope,
  deserializeEnvelope,
  createProofEnvelope,
  negotiateVersion,
  contentTypeForFormat,
  formatFromContentType,
} from './envelope.js';
