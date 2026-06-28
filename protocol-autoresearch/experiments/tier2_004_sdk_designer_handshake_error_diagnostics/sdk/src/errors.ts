/**
 * Bolyra SDK — Structured error hierarchy with machine-readable codes
 * and developer-friendly recovery hints.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { ErrorCode, HintMap, interpolateHint } from './error-codes.js';

export { ErrorCode } from './error-codes.js';

/**
 * Base error for every SDK failure.
 *
 * - `code`  — machine-readable enum for programmatic branching
 * - `hint`  — human-readable recovery guidance with interpolated context
 * - `cause` — optional upstream error for full chain inspection
 */
export class BolyraError extends Error {
  public readonly code: ErrorCode;
  public readonly hint: string;
  public override readonly cause?: unknown;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string,
    opts?: { hint?: string; cause?: unknown; details?: Record<string, unknown> },
  ) {
    super(message, { cause: opts?.cause });
    this.name = 'BolyraError';
    this.code = code;
    this.hint = opts?.hint ?? HintMap[code];
    this.cause = opts?.cause;
    this.details = opts?.details;
  }

  /* ------------------------------------------------------------------ */
  /*  Static factory helpers — one per error code                        */
  /* ------------------------------------------------------------------ */

  static staleRoot(delta: number): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.STALE_ROOT], { delta });
    return new BolyraError(
      ErrorCode.STALE_ROOT,
      `Merkle root is ${delta} block(s) behind the on-chain head`,
      { hint, details: { delta } },
    );
  }

  static expiredCredential(expiry: number, now?: number): BolyraError {
    const currentTime = now ?? Math.floor(Date.now() / 1000);
    const agoSeconds = currentTime - expiry;
    const ago = agoSeconds < 3600
      ? `${agoSeconds}s`
      : `${Math.floor(agoSeconds / 3600)}h ${agoSeconds % 3600}s`;
    const hint = interpolateHint(HintMap[ErrorCode.EXPIRED_CREDENTIAL], {
      ago,
      expiry,
    });
    return new BolyraError(
      ErrorCode.EXPIRED_CREDENTIAL,
      `Agent credential expired at ${expiry}`,
      { hint, details: { expiry, ago } },
    );
  }

  static scopeMismatch(required: number, provided: number): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.SCOPE_MISMATCH], {
      required: required.toString(2).padStart(8, '0'),
      provided: provided.toString(2).padStart(8, '0'),
    });
    return new BolyraError(
      ErrorCode.SCOPE_MISMATCH,
      `Scope 0b${provided.toString(2).padStart(8, '0')} does not satisfy required 0b${required.toString(2).padStart(8, '0')}`,
      { hint, details: { required, provided } },
    );
  }

  static nonceReused(nonce: string): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.NONCE_REUSED], { nonce });
    return new BolyraError(
      ErrorCode.NONCE_REUSED,
      `Session nonce ${nonce} already consumed`,
      { hint, details: { nonce } },
    );
  }

  static nullifierSpent(nullifier: string): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.NULLIFIER_SPENT], {
      nullifier,
    });
    return new BolyraError(
      ErrorCode.NULLIFIER_SPENT,
      `Nullifier ${nullifier} already spent`,
      { hint, details: { nullifier } },
    );
  }

  static proofInvalid(reason: string, cause?: unknown): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.PROOF_INVALID], { reason });
    return new BolyraError(
      ErrorCode.PROOF_INVALID,
      `Proof verification failed: ${reason}`,
      { hint, cause },
    );
  }

  static registryRevert(
    errorName: string,
    errorArgs: string,
    cause?: unknown,
  ): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.REGISTRY_REVERT], {
      errorName,
      errorArgs,
    });
    return new BolyraError(
      ErrorCode.REGISTRY_REVERT,
      `IdentityRegistry reverted: ${errorName}(${errorArgs})`,
      { hint, cause, details: { errorName, errorArgs } },
    );
  }

  static unknown(message: string, cause?: unknown): BolyraError {
    const hint = interpolateHint(HintMap[ErrorCode.UNKNOWN], { message });
    return new BolyraError(ErrorCode.UNKNOWN, message, { hint, cause });
  }

  /**
   * Wrap any thrown value as a BolyraError, preserving it if already typed.
   */
  static wrap(err: unknown): BolyraError {
    if (err instanceof BolyraError) return err;
    const message =
      err instanceof Error ? err.message : String(err);
    return BolyraError.unknown(message, err);
  }
}
