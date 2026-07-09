/**
 * Verdict + denial-code taxonomy for the `bolyra verify` external verifier.
 *
 * These wire types match the external-verifier contract: a verifier returns
 * either an `allow` (optionally instructing the caller to consume a one-time
 * nonce) or a `deny` carrying one of the fixed spec §8 denial codes.
 */

/**
 * Instruction to the caller to burn a one-time handshake nonce after a
 * successful verification, so the same proof cannot be replayed.
 */
export interface ConsumeNonce {
  /** Issuer key that scopes the nonce namespace. */
  issuer_key: string;
  /** The nonce value that was consumed. */
  nonce: string;
  /** Unix seconds until which the consumed nonce must be retained. */
  retain_until: number;
}

/** Successful verification. */
export interface AllowVerdict {
  verdict: 'allow';
  /** Present only when the verifier wants the caller to burn a nonce. */
  consume_nonce?: ConsumeNonce;
}

/**
 * The approved spec §8 denial taxonomy — EXACTLY these 15 codes.
 * Do not add, remove, or rename a member without a spec change.
 */
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

/** Failed verification, tagged with a stable denial code. */
export interface DenyVerdict {
  verdict: 'deny';
  code: DenyCode;
  message: string;
  /** Optional structured context (e.g. echoed SDK error details). */
  detail?: Record<string, unknown>;
}

export type Verdict = AllowVerdict | DenyVerdict;

/** Build an `allow` verdict, optionally with a nonce-consumption instruction. */
export function allow(consumeNonce?: ConsumeNonce): AllowVerdict {
  return consumeNonce === undefined
    ? { verdict: 'allow' }
    : { verdict: 'allow', consume_nonce: consumeNonce };
}

/** Build a `deny` verdict. `detail` is included only when provided. */
export function deny(
  code: DenyCode,
  message: string,
  detail?: Record<string, unknown>
): DenyVerdict {
  return detail === undefined
    ? { verdict: 'deny', code, message }
    : { verdict: 'deny', code, message, detail };
}

/** A value that looks like a `BolyraError`: carries a string `.code`. */
interface BolyraErrorLike {
  code: string;
  message?: string;
  details?: Record<string, unknown>;
}

function isBolyraErrorLike(err: unknown): err is BolyraErrorLike {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    typeof (err as { code: unknown }).code === 'string'
  );
}

/**
 * Build a `deny` verdict from a caught error, echoing the originating SDK
 * error code into `detail.sdk_code` (and merging `err.details` if present).
 *
 * Context-dependent mapping — the SAME SDK code can map to different wire
 * codes depending on where it was thrown — is the CALLER's responsibility.
 * This helper only echoes the SDK code for auditability; it does not map.
 */
export function fromBolyraError(
  err: unknown,
  code: DenyCode,
  message?: string
): DenyVerdict {
  if (isBolyraErrorLike(err)) {
    const detail: Record<string, unknown> = {
      ...(err.details ?? {}),
      sdk_code: err.code,
    };
    return deny(code, message ?? err.message ?? err.code, detail);
  }
  return deny(code, message ?? (err instanceof Error ? err.message : String(err)));
}

/**
 * Shared denial signal for verifier modules.
 *
 * A verify/* module throws `VerifyDenial` when a check fails; the core
 * orchestrator (verify/core.ts) catches it and converts to a `DenyVerdict`
 * via `.toVerdict()`. Any *unexpected* (non-VerifyDenial) throw is mapped by
 * the core to `internal_error` + non-zero exit, per spec §7.3. This keeps each
 * module independently testable (assert the thrown code) while the wire mapping
 * stays in one place.
 */
export class VerifyDenial extends Error {
  constructor(
    public readonly code: DenyCode,
    message: string,
    public readonly detail?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VerifyDenial';
  }

  toVerdict(): DenyVerdict {
    return deny(this.code, this.message, this.detail);
  }
}

/** Type guard: is this a `VerifyDenial` thrown by a verifier module? */
export function isVerifyDenial(err: unknown): err is VerifyDenial {
  return err instanceof VerifyDenial;
}
