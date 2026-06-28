/**
 * @module @bolyra/sdk/proof-envelope
 * @description Encoder/decoder for the application/bolyra-proof+cbor wire format.
 *
 * CDDL schema: spec/proof-envelope.cddl
 * Spec: spec/proof-envelope-content-type.md
 */

import { encode as cborEncode, decode as cborDecode } from "cbor-x";

// ── Constants ────────────────────────────────────────────────────────

export const CONTENT_TYPE = "application/bolyra-proof+cbor";
export const ENVELOPE_VERSION = 1;

// CDDL integer keys for compact CBOR encoding
const KEY_VERSION = 1;
const KEY_CIRCUIT_ID = 2;
const KEY_PROVING_SYSTEM = 3;
const KEY_PROOF_BYTES = 4;
const KEY_PUBLIC_SIGNALS = 5;
const KEY_DELEGATION_CHAIN = 6;

export const VALID_CIRCUIT_IDS = [
  "HumanUniqueness",
  "AgentPolicy",
  "Delegation",
] as const;

export type CircuitId = (typeof VALID_CIRCUIT_IDS)[number];

export const VALID_PROVING_SYSTEMS = ["groth16", "plonk"] as const;

export type ProvingSystem = (typeof VALID_PROVING_SYSTEMS)[number];

const MAX_ENVELOPE_BYTES = 65536; // 64 KiB
const MAX_DELEGATION_DEPTH = 8;

// ── Types ────────────────────────────────────────────────────────────

export interface DelegationChainEntry {
  /** Raw bytes of the delegated credential blob. */
  readonly data: Uint8Array;
}

export interface ProofEnvelope {
  readonly version: number;
  readonly circuitId: CircuitId;
  readonly provingSystem: ProvingSystem;
  readonly proofBytes: Uint8Array;
  readonly publicSignals: readonly string[];
  readonly delegationChain?: readonly DelegationChainEntry[];
}

// ── Error ────────────────────────────────────────────────────────────

export class ProofEnvelopeError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(`[${code}] ${message}`);
    this.name = "ProofEnvelopeError";
  }
}

// ── Encoder ──────────────────────────────────────────────────────────

/**
 * Encode a ProofEnvelope into a CBOR byte buffer using integer keys
 * per the CDDL schema.
 *
 * @throws {ProofEnvelopeError} if any field violates spec constraints
 */
export function encode(envelope: ProofEnvelope): Uint8Array {
  validateEnvelope(envelope);

  const map = new Map<number, unknown>();
  map.set(KEY_VERSION, envelope.version);
  map.set(KEY_CIRCUIT_ID, envelope.circuitId);
  map.set(KEY_PROVING_SYSTEM, envelope.provingSystem);
  map.set(KEY_PROOF_BYTES, envelope.proofBytes);
  map.set(KEY_PUBLIC_SIGNALS, [...envelope.publicSignals]);

  if (envelope.delegationChain && envelope.delegationChain.length > 0) {
    map.set(
      KEY_DELEGATION_CHAIN,
      envelope.delegationChain.map((e) => e.data)
    );
  }

  const encoded = cborEncode(map);
  if (encoded.byteLength > MAX_ENVELOPE_BYTES) {
    throw new ProofEnvelopeError(
      "ENVELOPE_TOO_LARGE",
      `Encoded envelope is ${encoded.byteLength} bytes, exceeds max ${MAX_ENVELOPE_BYTES}`
    );
  }
  return new Uint8Array(encoded);
}

// ── Decoder ──────────────────────────────────────────────────────────

/**
 * Decode a CBOR buffer into a ProofEnvelope with full schema validation.
 *
 * Unknown integer keys are silently ignored for forward compatibility.
 *
 * @throws {ProofEnvelopeError} on invalid CBOR, missing fields, or constraint violations
 */
export function decode(data: Uint8Array): ProofEnvelope {
  if (data.byteLength === 0) {
    throw new ProofEnvelopeError("EMPTY_INPUT", "Cannot decode empty buffer");
  }
  if (data.byteLength > MAX_ENVELOPE_BYTES) {
    throw new ProofEnvelopeError(
      "ENVELOPE_TOO_LARGE",
      `Input is ${data.byteLength} bytes, exceeds max ${MAX_ENVELOPE_BYTES}`
    );
  }

  let raw: unknown;
  try {
    raw = cborDecode(data);
  } catch (e) {
    throw new ProofEnvelopeError(
      "CBOR_DECODE_FAILED",
      `Failed to decode CBOR: ${e instanceof Error ? e.message : String(e)}`
    );
  }

  // The encoder emits a Map with integer keys
  let map: Map<number, unknown>;
  if (raw instanceof Map) {
    map = raw as Map<number, unknown>;
  } else if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
    // Fallback: some CBOR libs decode maps as plain objects with string keys
    map = new Map<number, unknown>();
    for (const [k, v] of Object.entries(raw)) {
      map.set(Number(k), v);
    }
  } else {
    throw new ProofEnvelopeError("INVALID_STRUCTURE", "Envelope must be a CBOR map");
  }

  // version
  const version = map.get(KEY_VERSION);
  if (typeof version !== "number" || !Number.isInteger(version) || version < 0) {
    throw new ProofEnvelopeError("INVALID_VERSION", "Missing or invalid 'version' field");
  }
  if (version !== ENVELOPE_VERSION) {
    throw new ProofEnvelopeError(
      "UNSUPPORTED_VERSION",
      `Unsupported envelope version ${version} (expected ${ENVELOPE_VERSION})`
    );
  }

  // circuitId
  const circuitId = map.get(KEY_CIRCUIT_ID);
  if (typeof circuitId !== "string") {
    throw new ProofEnvelopeError("INVALID_CIRCUIT_ID", "Missing or invalid 'circuitId' field");
  }
  if (!(VALID_CIRCUIT_IDS as readonly string[]).includes(circuitId)) {
    throw new ProofEnvelopeError(
      "UNKNOWN_CIRCUIT_ID",
      `Unknown circuit ID '${circuitId}'. Valid: ${VALID_CIRCUIT_IDS.join(", ")}`
    );
  }

  // provingSystem
  const provingSystem = map.get(KEY_PROVING_SYSTEM);
  if (typeof provingSystem !== "string") {
    throw new ProofEnvelopeError("INVALID_PROVING_SYSTEM", "Missing or invalid 'provingSystem' field");
  }
  if (!(VALID_PROVING_SYSTEMS as readonly string[]).includes(provingSystem)) {
    throw new ProofEnvelopeError(
      "UNKNOWN_PROVING_SYSTEM",
      `Unknown proving system '${provingSystem}'. Valid: ${VALID_PROVING_SYSTEMS.join(", ")}`
    );
  }

  // proofBytes
  const proofBytes = map.get(KEY_PROOF_BYTES);
  if (!(proofBytes instanceof Uint8Array)) {
    throw new ProofEnvelopeError("INVALID_PROOF_BYTES", "Missing or invalid 'proofBytes' field (expected bstr)");
  }
  if (proofBytes.length === 0) {
    throw new ProofEnvelopeError("EMPTY_PROOF", "proofBytes must not be empty");
  }

  // publicSignals
  const publicSignals = map.get(KEY_PUBLIC_SIGNALS);
  if (!Array.isArray(publicSignals)) {
    throw new ProofEnvelopeError("INVALID_PUBLIC_SIGNALS", "Missing or invalid 'publicSignals' field (expected array)");
  }
  for (let i = 0; i < publicSignals.length; i++) {
    if (typeof publicSignals[i] !== "string") {
      throw new ProofEnvelopeError(
        "INVALID_SIGNAL_TYPE",
        `publicSignals[${i}] must be a string, got ${typeof publicSignals[i]}`
      );
    }
  }

  // delegationChain (optional)
  let delegationChain: DelegationChainEntry[] | undefined;
  const rawChain = map.get(KEY_DELEGATION_CHAIN);
  if (rawChain !== undefined) {
    if (!Array.isArray(rawChain)) {
      throw new ProofEnvelopeError("INVALID_DELEGATION_CHAIN", "delegationChain must be an array");
    }
    if (rawChain.length > MAX_DELEGATION_DEPTH) {
      throw new ProofEnvelopeError(
        "DELEGATION_TOO_DEEP",
        `Delegation chain has ${rawChain.length} entries, max is ${MAX_DELEGATION_DEPTH}`
      );
    }
    delegationChain = rawChain.map((entry, i) => {
      if (!(entry instanceof Uint8Array)) {
        throw new ProofEnvelopeError(
          "INVALID_DELEGATION_ENTRY",
          `delegationChain[${i}] must be bstr`
        );
      }
      return { data: new Uint8Array(entry) };
    });
  }

  return {
    version,
    circuitId: circuitId as CircuitId,
    provingSystem: provingSystem as ProvingSystem,
    proofBytes: new Uint8Array(proofBytes),
    publicSignals: publicSignals as string[],
    ...(delegationChain ? { delegationChain } : {}),
  };
}

/**
 * Build the Content-Type header value for a proof envelope.
 */
export function buildContentType(
  circuitId: CircuitId,
  provingSystem: ProvingSystem
): string {
  return `${CONTENT_TYPE}; circuit=${circuitId}; ps=${provingSystem}; v=${ENVELOPE_VERSION}`;
}

// ── Validation ───────────────────────────────────────────────────────

function validateEnvelope(envelope: ProofEnvelope): void {
  if (envelope.version !== ENVELOPE_VERSION) {
    throw new ProofEnvelopeError("UNSUPPORTED_VERSION", `Unsupported version: ${envelope.version}`);
  }
  if (!(VALID_CIRCUIT_IDS as readonly string[]).includes(envelope.circuitId)) {
    throw new ProofEnvelopeError("UNKNOWN_CIRCUIT_ID", `Unknown circuit ID: ${envelope.circuitId}`);
  }
  if (!(VALID_PROVING_SYSTEMS as readonly string[]).includes(envelope.provingSystem)) {
    throw new ProofEnvelopeError("UNKNOWN_PROVING_SYSTEM", `Unknown proving system: ${envelope.provingSystem}`);
  }
  if (envelope.proofBytes.length === 0) {
    throw new ProofEnvelopeError("EMPTY_PROOF", "proofBytes must not be empty");
  }
  if (envelope.delegationChain && envelope.delegationChain.length > MAX_DELEGATION_DEPTH) {
    throw new ProofEnvelopeError(
      "DELEGATION_TOO_DEEP",
      `Delegation chain has ${envelope.delegationChain.length} entries, max is ${MAX_DELEGATION_DEPTH}`
    );
  }
}
