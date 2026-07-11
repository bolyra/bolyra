/**
 * Scope anchoring (F1/F2), effective-scope subset, and STRICT expiry checks.
 *
 * Ported from `integrations/cli/src/verify/scope.ts` for the Workers runtime:
 * Poseidon via `poseidon-lite` (pure JS, same circomlibjs-derived constants —
 * validated against the SDK implementation on the repo conformance fixtures).
 *
 * CODE-VERIFIED field order (AgentPolicy.circom / sdk identity.ts):
 *   credentialCommitment = poseidon5(modelHash, opX, opY, permissionBitmask, expiry)
 *   scopeCommitment      = poseidon3(permissionBitmask, credentialCommitment, expiry)
 *
 * AgentPolicy publicSignals layout:
 *   [0]=agentMerkleRoot [1]=nullifierHash [2]=scopeCommitment
 *   [3]=requiredScopeMask [4]=currentTimestamp [5]=sessionNonce
 */

import { poseidon3, poseidon5 } from 'poseidon-lite';
import { validateCumulativeBitEncoding } from '@bolyra/sdk/dist/identity.js';
import { VerifyDenial } from './verdict';

export interface CredentialPreimage {
  modelHash: bigint;
  opX: bigint;
  opY: bigint;
  bitmask: bigint;
  expiry: bigint;
}

/** Recompute `credentialCommitment` from the revealed preimage. */
export function recomputeCredentialCommitment(cred: CredentialPreimage): bigint {
  return poseidon5([cred.modelHash, cred.opX, cred.opY, cred.bitmask, cred.expiry]);
}

/** Recompute `scopeCommitment` from the revealed preimage (circuit field order). */
export function recomputeScopeCommitment(cred: CredentialPreimage): bigint {
  const credentialCommitment = recomputeCredentialCommitment(cred);
  return poseidon3([cred.bitmask, credentialCommitment, cred.expiry]);
}

/**
 * Bind the revealed credential preimage to the proof's `scopeCommitment`
 * public signal. Any tampering with the preimage (fabricated credential /
 * inflated bitmask) changes the recompute — fail closed with `invalid_proof`.
 */
export function assertScopeAnchored(
  cred: CredentialPreimage,
  agentScopeCommitmentSignal: bigint,
): void {
  const recomputed = recomputeScopeCommitment(cred);
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

/** `required ⊆ effective` on permission bitmasks. */
export function subsetOK(required: bigint, effective: bigint): boolean {
  return (required & ~effective) === 0n;
}

/**
 * Assert the required scope is within the credential's effective scope. Both
 * masks are validated as well-formed cumulative encodings first (an ill-formed
 * mask throws the SDK's InvalidPermissionError, which the core maps to
 * `internal_error` — same observable behavior as the CLI reference verifier).
 */
export function assertSubset(required: bigint, effective: bigint): void {
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

/** STRICT liveness: live only while `nowUnix < expiry`; equality is EXPIRED. */
export function assertNotExpired(nowUnix: bigint, expiry: bigint): void {
  if (!(nowUnix < expiry)) {
    throw new VerifyDenial('expired', 'credential is expired at the current timestamp', {
      now_unix: nowUnix.toString(),
      expiry: expiry.toString(),
    });
  }
}
