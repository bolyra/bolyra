/**
 * Proof envelope wire format: application/vnd.bolyra.proof+json
 *
 * Self-describing envelope for ZKP proofs with typed fields,
 * circuit identity binding, and version negotiation.
 */

/** Content-Type for HTTP headers. */
export const CONTENT_TYPE = 'application/vnd.bolyra.proof+json';

/** Current envelope version. */
export const ENVELOPE_VERSION = '1.0.0';

/** Valid circuit names. */
export type CircuitName = 'HumanUniqueness' | 'AgentPolicy' | 'Delegation';

/** Valid proof systems. v1 supports groth16 only (PLONK has different shape). */
export type ProofType = 'groth16';

/** Circuit identity with version and vkey binding. */
export interface CircuitIdentity {
  name: CircuitName;
  version: string;
  vkeyHash?: string; // sha256:<64 lowercase hex chars>
}

/** Groth16 proof coordinates. All values are decimal strings. */
export interface ProofData {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
}

/** Informational metadata. Verifiers MUST NOT reject based on these. */
export interface ProofMetadata {
  prover?: string;
  timestamp?: string; // RFC 3339
  [key: string]: unknown; // forward-compatible
}

/** The canonical proof envelope. */
export interface ProofEnvelope {
  version: string;
  circuit: CircuitIdentity;
  proofType: ProofType;
  publicSignals: string[];
  proof: ProofData;
  metadata?: ProofMetadata;
  [key: string]: unknown; // forward-compatible: unknown top-level fields preserved
}

// BN254 scalar field modulus (defined locally to avoid circular deps with identity.ts)
const BN254_FIELD_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const VALID_CIRCUITS: ReadonlySet<string> = new Set(['HumanUniqueness', 'AgentPolicy', 'Delegation']);
const VALID_PROOF_TYPES: ReadonlySet<string> = new Set(['groth16']); // v1: groth16 only

/**
 * Validate a decimal field element string.
 * - Rejects strings > 78 chars (DoS prevention before BigInt parsing)
 * - Rejects leading zeros (except "0" itself)
 * - Rejects values >= BN254 field modulus
 */
function validateFieldElement(s: string, label: string): void {
  if (typeof s !== 'string') {
    throw new Error(`${label}: must be a string, got ${typeof s}`);
  }
  // Reject strings > 78 chars before BigInt parsing (DoS prevention)
  if (s.length > 78) {
    throw new Error(`${label}: string too long (${s.length} chars, max 78)`);
  }
  // No leading zeros except "0" itself
  if (!/^(0|[1-9]\d*)$/.test(s)) {
    throw new Error(`${label}: must be a decimal string without leading zeros, got ${JSON.stringify(s)}`);
  }
  const n = BigInt(s);
  if (n >= BN254_FIELD_ORDER) {
    throw new Error(`${label}: value >= BN254 field modulus`);
  }
}

/** Parse a semver string into [major, minor, patch]. */
function parseSemver(v: string): [number, number, number] {
  const m = v.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) throw new Error(`Invalid semver: ${v}`);
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

/**
 * Check envelope version against the current supported version.
 * Major mismatch = reject. Minor/patch mismatch = accept (forward-compat).
 */
function checkVersion(envelopeVersion: string): void {
  const [major] = parseSemver(envelopeVersion);
  const [currentMajor] = parseSemver(ENVELOPE_VERSION);
  if (major !== currentMajor) {
    throw new Error(
      `Incompatible envelope version: ${envelopeVersion} (current: ${ENVELOPE_VERSION}). Major version mismatch.`
    );
  }
}

/**
 * Validate a raw object as a ProofEnvelope.
 * Throws on any structural or value violation.
 * Unknown top-level fields are preserved (forward-compat).
 */
export function validateEnvelope(envelope: Record<string, unknown>): ProofEnvelope {
  // Version
  if (typeof envelope.version !== 'string') {
    throw new Error('Missing or invalid version');
  }
  checkVersion(envelope.version);

  // Circuit identity
  const circuit = envelope.circuit as Record<string, unknown> | undefined;
  if (!circuit || typeof circuit !== 'object' || Array.isArray(circuit)) {
    throw new Error('Missing or invalid circuit');
  }
  if (typeof circuit.name !== 'string' || !VALID_CIRCUITS.has(circuit.name)) {
    throw new Error(`Invalid circuit.name: ${circuit.name}`);
  }
  if (typeof circuit.version !== 'string') {
    throw new Error('Missing circuit.version');
  }
  if (circuit.vkeyHash !== undefined) {
    if (
      typeof circuit.vkeyHash !== 'string' ||
      !/^sha256:[0-9a-f]{64}$/.test(circuit.vkeyHash)
    ) {
      throw new Error(
        `Invalid circuit.vkeyHash: must be sha256:<64 lowercase hex chars>, got ${JSON.stringify(circuit.vkeyHash)}`
      );
    }
  }

  // Proof type
  if (typeof envelope.proofType !== 'string' || !VALID_PROOF_TYPES.has(envelope.proofType)) {
    throw new Error(`Invalid proofType: ${envelope.proofType}`);
  }

  // Public signals
  const signals = envelope.publicSignals;
  if (!Array.isArray(signals) || signals.length === 0) {
    throw new Error('publicSignals must be a non-empty array');
  }
  (signals as unknown[]).forEach((s, i) => validateFieldElement(s as string, `publicSignals[${i}]`));

  // Proof coordinates
  const proof = envelope.proof as Record<string, unknown> | undefined;
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new Error('Missing proof');
  }

  const pi_a = proof.pi_a as unknown[];
  if (!Array.isArray(pi_a) || pi_a.length !== 2) {
    throw new Error('proof.pi_a must be [string, string]');
  }
  pi_a.forEach((s, i) => validateFieldElement(s as string, `pi_a[${i}]`));

  const pi_b = proof.pi_b as unknown[];
  if (!Array.isArray(pi_b) || pi_b.length !== 2) {
    throw new Error('proof.pi_b must be [[s,s],[s,s]]');
  }
  for (let r = 0; r < 2; r++) {
    const row = pi_b[r] as unknown[];
    if (!Array.isArray(row) || row.length !== 2) {
      throw new Error(`proof.pi_b[${r}] must be [string, string]`);
    }
    row.forEach((s, c) => validateFieldElement(s as string, `pi_b[${r}][${c}]`));
  }

  const pi_c = proof.pi_c as unknown[];
  if (!Array.isArray(pi_c) || pi_c.length !== 2) {
    throw new Error('proof.pi_c must be [string, string]');
  }
  pi_c.forEach((s, i) => validateFieldElement(s as string, `pi_c[${i}]`));

  return envelope as unknown as ProofEnvelope;
}

/**
 * Serialize a ProofEnvelope to a JSON string.
 * Unknown top-level fields are included (forward-compat).
 */
export function serializeEnvelope(envelope: ProofEnvelope): string {
  return JSON.stringify(envelope);
}

/**
 * Deserialize and validate a JSON string into a ProofEnvelope.
 * Throws on parse errors or validation failures.
 */
export function deserializeEnvelope(json: string): ProofEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new Error(`Failed to parse envelope JSON: ${(e as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Envelope must be a JSON object');
  }
  return validateEnvelope(parsed as Record<string, unknown>);
}

/**
 * Wrap raw snarkjs proof output into a ProofEnvelope.
 * The resulting envelope passes validateEnvelope() if inputs are valid field elements.
 */
export function envelopeFromSnarkjsProof(
  circuitName: CircuitName,
  proof: { pi_a: string[]; pi_b: string[][]; pi_c: string[] },
  publicSignals: string[],
  options?: { circuitVersion?: string; vkeyHash?: string },
): ProofEnvelope {
  if (!Array.isArray(publicSignals) || publicSignals.length === 0) {
    throw new Error('publicSignals must be a non-empty array');
  }
  if (!VALID_CIRCUITS.has(circuitName)) {
    throw new Error(`Invalid circuit name: ${circuitName}`);
  }

  const envelope: ProofEnvelope = {
    version: ENVELOPE_VERSION,
    circuit: {
      name: circuitName,
      version: options?.circuitVersion ?? '0.4.0',
      ...(options?.vkeyHash ? { vkeyHash: options.vkeyHash } : {}),
    },
    proofType: 'groth16',
    publicSignals,
    proof: {
      pi_a: [proof.pi_a[0], proof.pi_a[1]],
      pi_b: [
        [proof.pi_b[0][0], proof.pi_b[0][1]],
        [proof.pi_b[1][0], proof.pi_b[1][1]],
      ],
      pi_c: [proof.pi_c[0], proof.pi_c[1]],
    },
    metadata: {
      prover: '@bolyra/sdk@0.5.1',
      timestamp: new Date().toISOString(),
    },
  };

  return envelope;
}
