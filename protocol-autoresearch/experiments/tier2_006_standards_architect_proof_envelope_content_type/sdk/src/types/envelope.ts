/**
 * Type definitions for the Bolyra proof envelope.
 *
 * The envelope wraps a ZKP proof with metadata (circuit identifier,
 * proving system, version) so consumers can unambiguously parse and
 * route proofs without guessing the layout.
 *
 * @module
 */

/** Wire-format version. Big-endian uint16 prefix in CBOR encoding. */
export const ENVELOPE_VERSION: number = 0x0001;

/**
 * Circuit identifier enum.  Values are persisted on the wire — never
 * reorder or reuse a retired value; append only.
 */
export enum CircuitId {
  /** HumanUniqueness — Semaphore v4-style enrollment proof. */
  Human = 0,
  /** AgentPolicy — EdDSA-signed credential with cumulative-bit permissions. */
  Agent = 1,
  /** Delegation — one-way scope-narrowing delegation proof. */
  Delegation = 2,
  /** ModelInstance — reserved for per-model-instance binding (future). */
  ModelInstance = 3,
}

/**
 * Proving system enum.  Values are persisted on the wire.
 */
export enum ProvingSystem {
  Groth16 = 0,
  PLONK = 1,
}

/**
 * Optional metadata attached to an envelope.
 */
export interface EnvelopeMetadata {
  /** ISO-8601 timestamp of proof generation. */
  createdAt?: string;
  /** Opaque application-level correlation id. */
  correlationId?: string;
  /** Additional key-value pairs (string values only). */
  [key: string]: string | undefined;
}

/**
 * Typed proof envelope returned by `decodeProofEnvelope` and accepted
 * by `encodeProofEnvelope`.
 */
export interface ProofEnvelope {
  /** Envelope wire-format version (currently 0x0001). */
  version: number;
  /** Which circuit produced this proof. */
  circuit: CircuitId;
  /** Which proving system was used. */
  provingSystem: ProvingSystem;
  /**
   * The proof object.  Shape depends on the proving system:
   * - Groth16: `{ pi_a, pi_b, pi_c, protocol, curve }`
   * - PLONK:   snarkjs PLONK output map
   */
  proof: Record<string, unknown>;
  /** Array of public signal strings (decimal-encoded field elements). */
  publicSignals: string[];
  /** Optional envelope metadata. */
  metadata?: EnvelopeMetadata;
}
