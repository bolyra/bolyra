/**
 * Bolyra SDK — Machine-readable error codes and hint templates.
 *
 * Every BolyraError carries one of these codes so callers can branch on
 * `err.code` without string-matching messages.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

export enum ErrorCode {
  /** Merkle root provided is behind the on-chain head. */
  STALE_ROOT = 'STALE_ROOT',

  /** Agent credential expiry timestamp is in the past. */
  EXPIRED_CREDENTIAL = 'EXPIRED_CREDENTIAL',

  /** Delegated scope bits exceed the delegator's scope. */
  SCOPE_MISMATCH = 'SCOPE_MISMATCH',

  /** Session nonce was already consumed on-chain. */
  NONCE_REUSED = 'NONCE_REUSED',

  /** Nullifier has already been spent in a prior handshake. */
  NULLIFIER_SPENT = 'NULLIFIER_SPENT',

  /** ZK proof failed verification (witness generation or Groth16/PLONK check). */
  PROOF_INVALID = 'PROOF_INVALID',

  /** On-chain transaction reverted with a known IdentityRegistry custom error. */
  REGISTRY_REVERT = 'REGISTRY_REVERT',

  /** Catch-all for errors that don't map to a known code. */
  UNKNOWN = 'UNKNOWN',
}

/**
 * Hint templates use `{placeholder}` syntax for runtime interpolation.
 * Each placeholder corresponds to a named field in the factory's params.
 */
export const HintMap: Record<ErrorCode, string> = {
  [ErrorCode.STALE_ROOT]:
    'Root is {delta} blocks behind head; re-fetch with registry.latestRoot() and re-prove.',
  [ErrorCode.EXPIRED_CREDENTIAL]:
    'Agent credential expired {ago} ago (expiry timestamp {expiry}). Rotate the credential with createAgentCredential().',
  [ErrorCode.SCOPE_MISMATCH]:
    'Required scope 0b{required} is not a subset of provided scope 0b{provided}. Narrow via delegate() before retrying.',
  [ErrorCode.NONCE_REUSED]:
    'Session nonce {nonce} was already consumed. Generate a fresh nonce for each handshake.',
  [ErrorCode.NULLIFIER_SPENT]:
    'Nullifier {nullifier} has already been spent. This identity has already completed a handshake in this epoch.',
  [ErrorCode.PROOF_INVALID]:
    'Proof verification failed: {reason}. Check that circuit artifacts match the deployed verifier.',
  [ErrorCode.REGISTRY_REVERT]:
    'IdentityRegistry reverted with {errorName}({errorArgs}). See spec/error-codes.md for recovery steps.',
  [ErrorCode.UNKNOWN]:
    'Unexpected error: {message}. File a bug at github.com/bolyra/bolyra/issues.',
};

/**
 * Interpolate `{key}` placeholders in a hint template.
 */
export function interpolateHint(
  template: string,
  params: Record<string, string | number>,
): string {
  return template.replace(/\{(\w+)\}/g, (_, key) =>
    params[key] !== undefined ? String(params[key]) : `{${key}}`,
  );
}
