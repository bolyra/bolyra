/**
 * @module @bolyra/sdk/envelope
 * @description Reference encoder/decoder for the application/bolyra-proof+cbor
 * wire format. Serializes ProofResult objects to CBOR envelopes and parses
 * incoming envelopes with schema validation per the CDDL spec.
 *
 * @see spec/bolyra-proof-content-type.cddl
 * @see spec/draft-bolyra-proof-envelope-00.md
 */

import { encode as cborEncode, decode as cborDecode } from "cbor-x";

// ── Constants ────────────────────────────────────────────────────────

export const BOLYRA_PROOF_CONTENT_TYPE = "application/bolyra-proof+cbor";

export const ENVELOPE_VERSION = 1;

export const VALID_CIRCUIT_IDS = [
  "HumanUniqueness",
  "AgentPolicy",
  "Delegation",
] as const;

export type CircuitId = (typeof VALID_CIRCUIT_IDS)[number];

export const VALID_PROVING_SYSTEMS = ["groth16", "plonk"] as const;

export type ProvingSystem = (typeof VALID_PROVING_SYSTEMS)[number];

/** Expected public signal count per circuit. */
export const CIRCUIT_SIGNAL_ARITY: Record<CircuitId, number> = {
  HumanUniqueness: 3,
  AgentPolicy: 4,
  Delegation: 5,
};

// ── Types ────────────────────────────────────────────────────────────

export interface ProofEnvelopeMetadata {
  nonce?: Uint8Array;
  timestamp?: number;
  chainId?: number;
  [key: string]: unknown;
}

export interface ProofEnvelope {
  version: number;
  circuitId: CircuitId;
  provingSystem: ProvingSystem;
  proof: Uint8Array;
  publicSignals: string[];
  metadata?: ProofEnvelopeMetadata;
}

/**
 * Minimal ProofResult shape compatible with snarkjs output.
 * The `proof` field is the proving-system-specific proof object.
 */
export interface ProofResult {
  proof: Record<string, unknown>;
  publicSignals: string[];
}

// ── Encoder ──────────────────────────────────────────────────────────

/**
 * Encode a ProofResult into a CBOR envelope.
 *
 * @param proofResult  snarkjs-compatible proof result
 * @param circuitId    Which circuit produced this proof
 * @param provingSystem  groth16 or plonk
 * @param metadata     Optional envelope metadata
 * @returns CBOR-encoded Uint8Array
 */
export function encodeProofEnvelope(
  proofResult: ProofResult,
  circuitId: CircuitId,
  provingSystem: ProvingSystem,
  metadata?: ProofEnvelopeMetadata
): Uint8Array {
  validateCircuitId(circuitId);
  validateProvingSystem(provingSystem);

  const proofBytes = new TextEncoder().encode(
    JSON.stringify(proofResult.proof)
  );

  const envelope: Record<string, unknown> = {
    version: ENVELOPE_VERSION,
    circuitId,
    provingSystem,
    proof: proofBytes,
    publicSignals: proofResult.publicSignals,
  };

  if (metadata) {
    envelope.metadata = metadata;
  }

  return cborEncode(envelope);
}

// ── Decoder ──────────────────────────────────────────────────────────

/**
 * Decode a CBOR envelope into a ProofEnvelope, with schema validation.
 *
 * @param buf  CBOR-encoded bytes
 * @returns Validated ProofEnvelope
 * @throws Error on malformed input, unknown version, or schema mismatch
 */
export function decodeProofEnvelope(buf: Uint8Array): ProofEnvelope {
  let decoded: Record<string, unknown>;
  try {
    decoded = cborDecode(buf) as Record<string, unknown>;
  } catch (e) {
    throw new Error(
      `Failed to decode CBOR envelope: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("Envelope must be a CBOR map");
  }

  // Version
  const version = decoded.version;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new Error("Missing or invalid 'version' field");
  }
  if (version !== ENVELOPE_VERSION) {
    throw new Error(
      `Unsupported envelope version ${version} (expected ${ENVELOPE_VERSION})`
    );
  }

  // Circuit ID
  const circuitId = decoded.circuitId;
  if (typeof circuitId !== "string") {
    throw new Error("Missing or invalid 'circuitId' field");
  }
  validateCircuitId(circuitId);

  // Proving system
  const provingSystem = decoded.provingSystem;
  if (typeof provingSystem !== "string") {
    throw new Error("Missing or invalid 'provingSystem' field");
  }
  validateProvingSystem(provingSystem);

  // Proof bytes
  const proof = decoded.proof;
  if (!(proof instanceof Uint8Array)) {
    throw new Error("Missing or invalid 'proof' field (expected bstr)");
  }

  // Public signals
  const publicSignals = decoded.publicSignals;
  if (!Array.isArray(publicSignals)) {
    throw new Error("Missing or invalid 'publicSignals' field (expected array)");
  }
  for (let i = 0; i < publicSignals.length; i++) {
    if (typeof publicSignals[i] !== "string") {
      throw new Error(`publicSignals[${i}] must be a string`);
    }
  }

  // Validate signal arity
  const expectedArity = CIRCUIT_SIGNAL_ARITY[circuitId as CircuitId];
  if (publicSignals.length !== expectedArity) {
    throw new Error(
      `Circuit '${circuitId}' expects ${expectedArity} public signals, got ${publicSignals.length}`
    );
  }

  // Metadata (optional)
  let metadata: ProofEnvelopeMetadata | undefined;
  if (decoded.metadata !== undefined) {
    if (
      typeof decoded.metadata !== "object" ||
      decoded.metadata === null ||
      Array.isArray(decoded.metadata)
    ) {
      throw new Error("'metadata' must be a CBOR map");
    }
    metadata = decoded.metadata as ProofEnvelopeMetadata;
  }

  return {
    version: version as number,
    circuitId: circuitId as CircuitId,
    provingSystem: provingSystem as ProvingSystem,
    proof: proof as Uint8Array,
    publicSignals: publicSignals as string[],
    metadata,
  };
}

/**
 * Extract the ProofResult (snarkjs-compatible) from a decoded envelope.
 */
export function envelopeToProofResult(envelope: ProofEnvelope): ProofResult {
  const proofJson = new TextDecoder().decode(envelope.proof);
  return {
    proof: JSON.parse(proofJson),
    publicSignals: envelope.publicSignals,
  };
}

/**
 * Build the Content-Type header value for a proof envelope.
 */
export function buildContentType(
  circuitId: CircuitId,
  provingSystem: ProvingSystem
): string {
  return `${BOLYRA_PROOF_CONTENT_TYPE}; circuit=${circuitId}; ps=${provingSystem}; v=${ENVELOPE_VERSION}`;
}

// ── Validators ───────────────────────────────────────────────────────

function validateCircuitId(id: string): asserts id is CircuitId {
  if (!(VALID_CIRCUIT_IDS as readonly string[]).includes(id)) {
    throw new Error(
      `Unknown circuit ID '${id}'. Valid: ${VALID_CIRCUIT_IDS.join(", ")}`
    );
  }
}

function validateProvingSystem(ps: string): asserts ps is ProvingSystem {
  if (!(VALID_PROVING_SYSTEMS as readonly string[]).includes(ps)) {
    throw new Error(
      `Unknown proving system '${ps}'. Valid: ${VALID_PROVING_SYSTEMS.join(", ")}`
    );
  }
}
