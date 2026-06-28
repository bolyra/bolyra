/**
 * Bolyra SDK — Proof verification wrappers that translate raw snarkjs /
 * rapidsnark failures into typed BolyraError instances.
 *
 * This module wraps the low-level verification calls and ensures every
 * thrown error is a BolyraError with the correct code and a helpful hint.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { BolyraError } from './errors.js';
import { ErrorCode } from './error-codes.js';

/** Minimal snarkjs groth16/plonk verify signature. */
type VerifyFn = (
  vkey: unknown,
  publicSignals: string[],
  proof: unknown,
) => Promise<boolean>;

/**
 * Wrap a snarkjs/rapidsnark verify call, translating failures to BolyraError.
 */
export async function verifyProofSafe(
  verifyFn: VerifyFn,
  vkey: unknown,
  publicSignals: string[],
  proof: unknown,
): Promise<boolean> {
  try {
    const valid = await verifyFn(vkey, publicSignals, proof);
    if (!valid) {
      throw BolyraError.proofInvalid(
        'Groth16/PLONK verification returned false',
      );
    }
    return true;
  } catch (err) {
    if (err instanceof BolyraError) throw err;
    throw classifyVerificationError(err);
  }
}

/**
 * Classify a raw verification/witness-generation error into the most
 * specific BolyraError code.
 */
export function classifyVerificationError(err: unknown): BolyraError {
  const message =
    err instanceof Error ? err.message : String(err);
  const lower = message.toLowerCase();

  // Expired credential detection
  if (
    lower.includes('expired') ||
    lower.includes('expiry') ||
    lower.includes('timestamp')
  ) {
    return new BolyraError(
      ErrorCode.EXPIRED_CREDENTIAL,
      message,
      { hint: 'Credential appears expired. Rotate with createAgentCredential().', cause: err },
    );
  }

  // Nonce mismatch / reuse
  if (lower.includes('nonce') && (lower.includes('reuse') || lower.includes('already') || lower.includes('mismatch'))) {
    return new BolyraError(
      ErrorCode.NONCE_REUSED,
      message,
      { hint: 'Session nonce conflict detected. Generate a fresh nonce for each handshake.', cause: err },
    );
  }

  // Nullifier spent
  if (lower.includes('nullifier') && (lower.includes('spent') || lower.includes('already'))) {
    return BolyraError.nullifierSpent(extractHex(message) ?? 'unknown');
  }

  // Stale root
  if (lower.includes('root') && (lower.includes('stale') || lower.includes('not found') || lower.includes('mismatch'))) {
    return BolyraError.staleRoot(0);
  }

  // Scope issues
  if (lower.includes('scope') || lower.includes('permission')) {
    return new BolyraError(
      ErrorCode.SCOPE_MISMATCH,
      message,
      { hint: 'Permission scope validation failed. Check cumulative bit encoding.', cause: err },
    );
  }

  // Default: proof invalid
  return BolyraError.proofInvalid(message, err);
}

/**
 * Wrap the public verifyHandshake() entrypoint to ensure all errors
 * are typed BolyraErrors with cause chains preserved.
 *
 * @param fn - The underlying verifyHandshake implementation
 * @returns A wrapped function that only throws BolyraError
 */
export function wrapVerifyHandshake<
  TArgs extends unknown[],
  TResult,
>(
  fn: (...args: TArgs) => Promise<TResult>,
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs): Promise<TResult> => {
    try {
      return await fn(...args);
    } catch (err) {
      throw BolyraError.wrap(err);
    }
  };
}

/** Extract the first hex string from an error message. */
function extractHex(msg: string): string | null {
  const match = msg.match(/0x[0-9a-fA-F]+/);
  return match ? match[0] : null;
}
