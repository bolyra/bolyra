/**
 * Human identity and proof generation for the Bolyra protocol.
 *
 * @module human
 */

import { poseidon1, poseidon2, poseidon3, poseidon4 } from "poseidon-lite";
import type { HumanIdentity, HumanProof } from "./types";

/** Domain tag for HumanUniqueness circuit nullifiers (frozen constant). */
const DOMAIN_HUMAN = 1n;

/**
 * Create a human identity from a secret.
 *
 * @param secret - The human prover's secret key.
 * @param identityNonce - Optional nonce (defaults to 0n).
 * @returns A HumanIdentity with the computed commitment.
 */
export function createHumanIdentity(
  secret: bigint,
  identityNonce: bigint = 0n
): HumanIdentity {
  const identityCommitment = poseidon2([secret, identityNonce]);
  return { secret, identityNonce, identityCommitment };
}

/**
 * Compute the per-session nullifier hash.
 *
 * nullifierHash = Poseidon₄(DOMAIN_HUMAN, scope, secret, sessionNonce)
 *
 * Each handshake uses a fresh sessionNonce, producing a unique nullifier
 * that cannot be linked across sessions.
 */
export function computeSessionNullifier(
  scope: bigint,
  secret: bigint,
  sessionNonce: bigint
): bigint {
  return poseidon4([DOMAIN_HUMAN, scope, secret, sessionNonce]);
}

/**
 * Compute the stable external nullifier (private — never exposed directly).
 *
 * externalNullifier = Poseidon₃(DOMAIN_HUMAN, scope, secret)
 *
 * This is the v2.0.0 nullifier, now kept as a private intermediate.
 */
export function computeExternalNullifier(
  scope: bigint,
  secret: bigint
): bigint {
  return poseidon3([DOMAIN_HUMAN, scope, secret]);
}

/**
 * Compute the external nullifier commitment (public, on-chain).
 *
 * commitment = Poseidon₁(externalNullifier)
 *
 * This one-way commitment is used for sybil gating and revocation
 * without revealing the raw nullifier.
 */
export function computeExternalNullifierCommitment(
  scope: bigint,
  secret: bigint
): bigint {
  const extNull = computeExternalNullifier(scope, secret);
  return poseidon1([extNull]);
}

/**
 * Generate a random session nonce.
 */
export function generateSessionNonce(): bigint {
  const bytes = new Uint8Array(31); // 31 bytes < BN254 field size
  crypto.getRandomValues(bytes);
  let nonce = 0n;
  for (const b of bytes) {
    nonce = (nonce << 8n) | BigInt(b);
  }
  return nonce;
}

/**
 * Build the circuit witness for a HumanUniqueness proof.
 *
 * @param identity - The human identity (secret + nonce).
 * @param scope - Application scope identifier.
 * @param sessionNonce - Per-session nonce for nullifier unlinkability.
 * @param merkleProof - Merkle path elements and indices.
 * @param identityTreeRoot - The current Merkle root.
 * @returns The witness object for the circom circuit.
 */
export function buildHumanWitness(
  identity: HumanIdentity,
  scope: bigint,
  sessionNonce: bigint,
  merkleProof: {
    pathElements: bigint[];
    pathIndices: number[];
  },
  identityTreeRoot: bigint
) {
  const nullifierHash = computeSessionNullifier(
    scope,
    identity.secret,
    sessionNonce
  );
  const externalNullifierCommitment = computeExternalNullifierCommitment(
    scope,
    identity.secret
  );

  return {
    // Public inputs
    identityTreeRoot,
    nullifierHash,
    scope,
    externalNullifierCommitment,
    // Private inputs
    secret: identity.secret,
    identityNonce: identity.identityNonce,
    sessionNonce,
    merklePathElements: merkleProof.pathElements,
    merklePathIndices: merkleProof.pathIndices,
  };
}

/**
 * Verify a human proof's public signals.
 *
 * Checks:
 *   1. Session nullifier matches the derivation from provided inputs.
 *   2. External nullifier commitment is correctly derived.
 *
 * Note: Full ZK proof verification requires the on-chain verifier or
 * snarkjs.groth16.verify with the vkey. This function validates signal
 * consistency only.
 */
export function verifyHumanSignals(
  proof: HumanProof,
  scope: bigint,
  secret: bigint,
  sessionNonce: bigint
): boolean {
  const expectedNullifier = computeSessionNullifier(
    scope,
    secret,
    sessionNonce
  );
  const expectedCommitment = computeExternalNullifierCommitment(scope, secret);

  return (
    proof.nullifierHash === expectedNullifier &&
    proof.externalNullifierCommitment === expectedCommitment
  );
}
