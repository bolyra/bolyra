/**
 * Verdict types for the hosted verify endpoint — External Verifier Contract v1
 * (spec/external-verifier-contract-v1.md §3, §9).
 *
 * Ported from `integrations/cli/src/verify/verdict.ts` with ONE deliberate
 * difference: this verifier is `classical`-class (Bolyra Core), so every
 * verdict carries `"kind": "classical"` — a non-`zk` verifier MUST set `kind`
 * explicitly per spec §3.5.
 */

/** Instruction to the caller to burn a one-time nonce (host nonce mode, §3.2). */
export interface ConsumeNonce {
  issuer_key: string;
  nonce: string;
  retain_until: number;
}

export interface AllowVerdict {
  verdict: 'allow';
  kind: 'classical';
  consume_nonces?: ConsumeNonce[];
}

/** The spec §9 denial registry — EXACTLY these 15 codes. */
export type DenyCode =
  | 'malformed_input'
  | 'unsupported_version'
  | 'invalid_bundle'
  | 'invalid_proof'
  | 'untrusted_root'
  | 'delegation_invalid'
  | 'invalid_signature'
  | 'request_mismatch'
  | 'model_mismatch'
  | 'unknown_capability'
  | 'scope_exceeded'
  | 'expired'
  | 'nonce_missing'
  | 'nonce_replayed'
  | 'internal_error';

export interface DenyVerdict {
  verdict: 'deny';
  kind: 'classical';
  code: DenyCode;
  message: string;
  detail?: Record<string, unknown>;
}

export type Verdict = AllowVerdict | DenyVerdict;

/** Build a `classical`-kind allow verdict. `consume_nonces` omitted when empty. */
export function allow(consumeNonces?: ConsumeNonce[]): AllowVerdict {
  return consumeNonces === undefined || consumeNonces.length === 0
    ? { verdict: 'allow', kind: 'classical' }
    : { verdict: 'allow', kind: 'classical', consume_nonces: consumeNonces };
}

/** Build a `classical`-kind deny verdict. `detail` included only when provided. */
export function deny(
  code: DenyCode,
  message: string,
  detail?: Record<string, unknown>,
): DenyVerdict {
  return detail === undefined
    ? { verdict: 'deny', kind: 'classical', code, message }
    : { verdict: 'deny', kind: 'classical', code, message, detail };
}

/**
 * Shared denial signal: verify modules throw `VerifyDenial`; the core
 * orchestrator catches it and converts to a wire `DenyVerdict`. Any other
 * throw maps to `internal_error` (fail closed).
 */
export class VerifyDenial extends Error {
  constructor(
    public readonly code: DenyCode,
    message: string,
    public readonly detail?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'VerifyDenial';
  }

  toVerdict(): DenyVerdict {
    return deny(this.code, this.message, this.detail);
  }
}

export function isVerifyDenial(err: unknown): err is VerifyDenial {
  return err instanceof VerifyDenial;
}
