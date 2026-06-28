import { randomBytes } from 'crypto';

/**
 * Branded type for session nonces — prevents callers from passing
 * an arbitrary Buffer where a single-use nonce is expected.
 */
export type SessionNonce = Buffer & { readonly __brand: 'SessionNonce' };

/**
 * Generate a cryptographically random 32-byte session nonce.
 * Each nonce is single-use; replaying (humanProof, agentProof) with
 * a previously-used nonce will fail verification by design.
 */
export function generateSessionNonce(): SessionNonce {
  return randomBytes(32) as SessionNonce;
}
