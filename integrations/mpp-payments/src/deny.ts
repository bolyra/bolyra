/**
 * Machine-readable denial responses — RFC 9457 Problem Details
 * (`application/problem+json`), the same error style mppx itself uses for
 * payment failures. Every denial carries the stable `code` member (the EVC
 * §9 taxonomy plus the gate-local `missing_authorization`).
 */

import type { DenyCode, DenyVerdict } from './types';

/** HTTP status per denial code. */
export const DENY_STATUS: Record<DenyCode, number> = {
  // Authorization was never established — 401.
  missing_authorization: 401,
  malformed_input: 401,
  unsupported_version: 401,
  invalid_bundle: 401,
  invalid_proof: 401,
  invalid_signature: 401,
  untrusted_root: 401,
  delegation_invalid: 401,
  // A mandate was presented and understood, but does not authorize THIS
  // spend — 403.
  request_mismatch: 403,
  model_mismatch: 403,
  unknown_capability: 403,
  scope_exceeded: 403,
  expired: 403,
  nonce_missing: 403,
  nonce_replayed: 403,
  // The gate or its verifier could not produce a trustworthy decision —
  // fail closed with a server fault, never an allow.
  internal_error: 500,
};

const TITLES: Record<DenyCode, string> = {
  missing_authorization: 'Authorization Required',
  malformed_input: 'Malformed Authorization Request',
  unsupported_version: 'Unsupported Presentation Version',
  invalid_bundle: 'Invalid Presentation Bundle',
  invalid_proof: 'Invalid Proof',
  invalid_signature: 'Invalid Binding Signature',
  untrusted_root: 'Untrusted Issuer',
  delegation_invalid: 'Invalid Delegation',
  request_mismatch: 'Mandate Does Not Cover This Request',
  model_mismatch: 'Model Mismatch',
  unknown_capability: 'Unknown Capability',
  scope_exceeded: 'Spend Exceeds Delegated Tier',
  expired: 'Mandate Expired',
  nonce_missing: 'Nonce Missing',
  nonce_replayed: 'Presentation Replayed',
  internal_error: 'Authorization Verification Unavailable',
};

/** The Problem Details body shape emitted on every denial. */
export interface DenyProblem {
  type: string;
  title: string;
  status: number;
  detail: string;
  /** Stable machine-readable denial code (EVC §9 + `missing_authorization`). */
  code: DenyCode;
  /**
   * The verifier's machine-readable reason (`verdict.detail.reason`), e.g.
   * `credential_not_active` on a hosted-registry deny. Present only when the
   * verdict carried it as a string.
   */
  reason?: string;
  /** The credential the verifier named (`verdict.detail.credential_id`), when a string. */
  credential_id?: string;
}

/** The verdict members a Problem Details body is built from. */
export type DenyProblemInput = Pick<DenyVerdict, 'code' | 'message' | 'detail'>;

/**
 * Build the Problem Details body for a deny verdict. Of `verdict.detail`,
 * ONLY `reason` and `credential_id` are copied, and only when they are
 * strings — any other detail member stays out of the HTTP body.
 */
export function denyProblem(verdict: DenyProblemInput): DenyProblem {
  const status = DENY_STATUS[verdict.code] ?? 500;
  const reason = verdict.detail?.reason;
  const credentialId = verdict.detail?.credential_id;
  return {
    type: `https://bolyra.ai/problems/mpp/${verdict.code.replace(/_/g, '-')}`,
    title: TITLES[verdict.code] ?? 'Authorization Denied',
    status,
    detail: verdict.message,
    code: verdict.code,
    ...(typeof reason === 'string' ? { reason } : {}),
    ...(typeof credentialId === 'string' ? { credential_id: credentialId } : {}),
  };
}

/** Build the fail-closed HTTP response for a deny verdict. */
export function denyResponse(verdict: DenyProblemInput): Response {
  const problem = denyProblem(verdict);
  return new Response(JSON.stringify(problem), {
    status: problem.status,
    headers: { 'content-type': 'application/problem+json' },
  });
}
