/**
 * Canonical proof envelope for HTTP transport.
 * MIME type: application/bolyra-proof+json
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const BOLYRA_PROOF_CONTENT_TYPE = "application/bolyra-proof+json";
export const ENVELOPE_VERSION = "1";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CircuitId = "HumanUniqueness" | "AgentPolicy" | "Delegation";

const VALID_CIRCUITS: ReadonlySet<string> = new Set<CircuitId>([
  "HumanUniqueness",
  "AgentPolicy",
  "Delegation",
]);

export interface SnarkProof {
  readonly pi_a: readonly string[];
  readonly pi_b: readonly (readonly string[])[];
  readonly pi_c: readonly string[];
}

export interface DelegationLink {
  readonly delegatorCommitment: string;
  readonly delegateCommitment: string;
  readonly scopeMask: number;
  readonly expiry: number;
}

export interface ProofEnvelopeData {
  readonly version: string;
  readonly circuit: CircuitId;
  readonly publicSignals: readonly string[];
  readonly proof: SnarkProof;
  readonly sessionToken?: string;
  readonly delegationChain?: readonly DelegationLink[];
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class BolyraEnvelopeError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(`[${code}] ${message}`);
    this.name = "BolyraEnvelopeError";
  }
}

// ---------------------------------------------------------------------------
// ProofEnvelope class
// ---------------------------------------------------------------------------

export class ProofEnvelope {
  readonly version: string;
  readonly circuit: CircuitId;
  readonly publicSignals: readonly string[];
  readonly proof: SnarkProof;
  readonly sessionToken?: string;
  readonly delegationChain?: readonly DelegationLink[];

  constructor(data: ProofEnvelopeData) {
    ProofEnvelope.validate(data);
    this.version = data.version;
    this.circuit = data.circuit;
    this.publicSignals = [...data.publicSignals];
    this.proof = {
      pi_a: [...data.proof.pi_a],
      pi_b: data.proof.pi_b.map((row) => [...row]),
      pi_c: [...data.proof.pi_c],
    };
    if (data.sessionToken !== undefined) {
      this.sessionToken = data.sessionToken;
    }
    if (data.delegationChain !== undefined) {
      this.delegationChain = data.delegationChain.map((link) => ({ ...link }));
    }
  }

  // -------------------------------------------------------------------------
  // Serialize — canonical key-ordered JSON
  // -------------------------------------------------------------------------

  serialize(): string {
    const obj: Record<string, unknown> = {
      version: this.version,
      circuit: this.circuit,
      publicSignals: this.publicSignals,
      proof: {
        pi_a: this.proof.pi_a,
        pi_b: this.proof.pi_b,
        pi_c: this.proof.pi_c,
      },
    };
    if (this.sessionToken !== undefined) {
      obj.sessionToken = this.sessionToken;
    }
    if (this.delegationChain !== undefined) {
      obj.delegationChain = this.delegationChain.map((link) => ({
        delegatorCommitment: link.delegatorCommitment,
        delegateCommitment: link.delegateCommitment,
        scopeMask: link.scopeMask,
        expiry: link.expiry,
      }));
    }
    return JSON.stringify(obj);
  }

  // -------------------------------------------------------------------------
  // Parse — deserialize and validate
  // -------------------------------------------------------------------------

  static parse(json: string): ProofEnvelope {
    let raw: unknown;
    try {
      raw = JSON.parse(json);
    } catch {
      throw new BolyraEnvelopeError("INVALID_JSON", "Input is not valid JSON");
    }
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new BolyraEnvelopeError(
        "INVALID_ENVELOPE",
        "Envelope must be a JSON object",
      );
    }
    const data = raw as Record<string, unknown>;
    return new ProofEnvelope({
      version: data.version as string,
      circuit: data.circuit as CircuitId,
      publicSignals: data.publicSignals as string[],
      proof: data.proof as SnarkProof,
      sessionToken: data.sessionToken as string | undefined,
      delegationChain: data.delegationChain as DelegationLink[] | undefined,
    });
  }

  // -------------------------------------------------------------------------
  // Validate
  // -------------------------------------------------------------------------

  static validate(data: ProofEnvelopeData): void {
    if (data.version !== ENVELOPE_VERSION) {
      throw new BolyraEnvelopeError(
        "UNSUPPORTED_VERSION",
        `Expected version "${ENVELOPE_VERSION}", got "${data.version}"`,
      );
    }

    if (!VALID_CIRCUITS.has(data.circuit)) {
      throw new BolyraEnvelopeError(
        "UNKNOWN_CIRCUIT",
        `Unknown circuit "${data.circuit}". Expected one of: ${[...VALID_CIRCUITS].join(", ")}`,
      );
    }

    if (
      !Array.isArray(data.publicSignals) ||
      data.publicSignals.length === 0
    ) {
      throw new BolyraEnvelopeError(
        "INVALID_PUBLIC_SIGNALS",
        "publicSignals must be a non-empty array of strings",
      );
    }
    for (const s of data.publicSignals) {
      if (typeof s !== "string") {
        throw new BolyraEnvelopeError(
          "INVALID_PUBLIC_SIGNALS",
          "Each public signal must be a string",
        );
      }
    }

    if (!data.proof || typeof data.proof !== "object") {
      throw new BolyraEnvelopeError(
        "INVALID_PROOF",
        "proof must be an object with pi_a, pi_b, pi_c",
      );
    }

    if (!Array.isArray(data.proof.pi_a) || data.proof.pi_a.length !== 3) {
      throw new BolyraEnvelopeError(
        "INVALID_PROOF",
        "proof.pi_a must be an array of 3 strings",
      );
    }

    if (!Array.isArray(data.proof.pi_b) || data.proof.pi_b.length !== 3) {
      throw new BolyraEnvelopeError(
        "INVALID_PROOF",
        "proof.pi_b must be an array of 3 two-element arrays",
      );
    }
    for (const row of data.proof.pi_b) {
      if (!Array.isArray(row) || row.length !== 2) {
        throw new BolyraEnvelopeError(
          "INVALID_PROOF",
          "Each element of proof.pi_b must be a 2-element array",
        );
      }
    }

    if (!Array.isArray(data.proof.pi_c) || data.proof.pi_c.length !== 3) {
      throw new BolyraEnvelopeError(
        "INVALID_PROOF",
        "proof.pi_c must be an array of 3 strings",
      );
    }

    if (data.delegationChain !== undefined) {
      if (
        !Array.isArray(data.delegationChain) ||
        data.delegationChain.length === 0
      ) {
        throw new BolyraEnvelopeError(
          "INVALID_DELEGATION_CHAIN",
          "delegationChain must be a non-empty array if present",
        );
      }
      for (const link of data.delegationChain) {
        if (
          typeof link.delegatorCommitment !== "string" ||
          typeof link.delegateCommitment !== "string"
        ) {
          throw new BolyraEnvelopeError(
            "INVALID_DELEGATION_CHAIN",
            "Each delegation link must have string delegatorCommitment and delegateCommitment",
          );
        }
        if (
          typeof link.scopeMask !== "number" ||
          !Number.isInteger(link.scopeMask) ||
          link.scopeMask < 0 ||
          link.scopeMask > 255
        ) {
          throw new BolyraEnvelopeError(
            "INVALID_DELEGATION_CHAIN",
            "scopeMask must be an integer in [0, 255]",
          );
        }
        if (
          typeof link.expiry !== "number" ||
          !Number.isInteger(link.expiry) ||
          link.expiry <= 0
        ) {
          throw new BolyraEnvelopeError(
            "INVALID_DELEGATION_CHAIN",
            "expiry must be a positive integer",
          );
        }
      }
    }
  }
}
