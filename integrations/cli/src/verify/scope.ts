/**
 * Scope anchoring, effective-scope subset, and STRICT expiry checks for the
 * `bolyra verify` external verifier.
 *
 * This module is the F1/F2 forgery anchor. A malicious prover can present an
 * arbitrary credential preimage alongside a proof, so the verifier MUST
 * recompute `scopeCommitment` from the claimed preimage and bind it to the
 * proof's public signal. If the recompute does not match, the preimage is a
 * forgery (F1: fabricated credential; F2: inflated bitmask) and verification
 * is denied.
 *
 * CODE-VERIFIED field order (confirmed against `AgentPolicy.circom` and
 * `sdk/src/identity.ts`), do NOT reorder:
 *   credentialCommitment = poseidon5(modelHash, opX, opY, permissionBitmask, expiry)
 *   scopeCommitment      = poseidon3(permissionBitmask, credentialCommitment, expiry)
 *
 * AgentPolicy `publicSignals` layout:
 *   [0]=agentMerkleRoot [1]=nullifierHash [2]=scopeCommitment
 *   [3]=requiredScopeMask [4]=currentTimestamp [5]=sessionNonce
 *
 * Expiry is STRICT: the circuit constrains `LessThan(currentTimestamp,
 * expiryTimestamp)` (`AgentPolicy.circom:156`), so `now == expiry` is EXPIRED.
 */

import {
  poseidon5,
  poseidon3,
  validateCumulativeBitEncoding,
} from '@bolyra/sdk';
import { VerifyDenial } from './verdict';

/**
 * The credential preimage a prover claims for a proof. All fields are field
 * elements (bigint). `bitmask` is the 8-bit cumulative permission encoding.
 */
export interface CredentialPreimage {
  modelHash: bigint;
  opX: bigint;
  opY: bigint;
  bitmask: bigint;
  expiry: bigint;
}

/**
 * Recompute the `scopeCommitment` from a claimed credential preimage, using
 * the exact circuit field order. This is the anchor: the returned value MUST
 * equal the proof's `publicSignals[2]` for the preimage to be authentic.
 */
export async function recomputeScopeCommitment(
  cred: CredentialPreimage,
): Promise<bigint> {
  const credentialCommitment = await poseidon5(
    cred.modelHash,
    cred.opX,
    cred.opY,
    cred.bitmask,
    cred.expiry,
  );
  return poseidon3(cred.bitmask, credentialCommitment, cred.expiry);
}

/**
 * Assert that a claimed credential preimage hashes to the `scopeCommitment`
 * carried by the proof (`publicSignals[2]`).
 *
 * Defends against F1 (fabricated credential) and F2 (inflated bitmask): any
 * tampering with the preimage changes the recomputed commitment, so a mismatch
 * proves the preimage does not belong to the proof.
 *
 * @throws {VerifyDenial} `invalid_proof` when the recompute does not match.
 */
export async function assertScopeAnchored(
  cred: CredentialPreimage,
  agentScopeCommitmentSignal: bigint,
): Promise<void> {
  const recomputed = await recomputeScopeCommitment(cred);
  if (recomputed !== agentScopeCommitmentSignal) {
    throw new VerifyDenial(
      'invalid_proof',
      'credential preimage does not match proof scopeCommitment',
      {
        recomputed_scope_commitment: recomputed.toString(),
        proof_scope_commitment: agentScopeCommitmentSignal.toString(),
      },
    );
  }
}

/**
 * Pure subset test on cumulative-permission bitmasks: is every bit set in
 * `required` also set in `effective`? Equivalent to `required ⊆ effective`.
 *
 * `(required & ~effective) === 0n` selects exactly the required bits that are
 * absent from effective; zero means none are missing, i.e. required is a
 * subset of effective.
 */
export function subsetOK(required: bigint, effective: bigint): boolean {
  return (required & ~effective) === 0n;
}

/**
 * Assert that the request's `required` scope is within the credential's
 * `effective` scope (one-way narrowing). Both are validated as well-formed
 * cumulative encodings, so the subset check reflects true permission-tier
 * containment rather than raw bit patterns.
 *
 * @throws {VerifyDenial} `scope_exceeded` when `required` is not a subset of
 * `effective`.
 */
export function assertSubset(required: bigint, effective: bigint): void {
  // Clarify subset semantics: both masks must be valid cumulative encodings
  // for the `&~` containment test to correspond to permission-tier subset.
  validateCumulativeBitEncoding(effective);
  validateCumulativeBitEncoding(required);
  if (!subsetOK(required, effective)) {
    throw new VerifyDenial(
      'scope_exceeded',
      'required scope exceeds the credential effective scope',
      {
        required_scope: required.toString(),
        effective_scope: effective.toString(),
        excess_bits: (required & ~effective).toString(),
      },
    );
  }
}

/**
 * STRICT liveness: a credential is live only while `nowUnix < expiry`.
 * Equality (`nowUnix === expiry`) is EXPIRED, matching the circuit's
 * `LessThan(currentTimestamp, expiryTimestamp)` constraint.
 */
export function expiryLive(nowUnix: bigint, expiry: bigint): boolean {
  return nowUnix < expiry;
}

/**
 * Assert that a credential has not expired at `nowUnix`, using STRICT
 * comparison — `nowUnix === expiry` throws.
 *
 * @throws {VerifyDenial} `expired` when `!(nowUnix < expiry)`.
 */
export function assertNotExpired(nowUnix: bigint, expiry: bigint): void {
  if (!expiryLive(nowUnix, expiry)) {
    throw new VerifyDenial(
      'expired',
      'credential is expired at the current timestamp',
      {
        now_unix: nowUnix.toString(),
        expiry: expiry.toString(),
      },
    );
  }
}
