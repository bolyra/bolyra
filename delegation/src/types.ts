import type { Permission } from "./permissions";

/**
 * Receipt claims (JWT body). Field names mirror standard JWT claims where
 * possible so that any JWT-aware verifier can do basic checks even without
 * @bolyra/delegation installed.
 */
export interface ReceiptClaims {
  /** Issuer — the human (or upstream agent) that signed the delegation. */
  iss: string;
  /** Subject — the agent the delegation grants authority to. */
  sub: string;
  /** Audience — the tool, merchant, or scope the delegation is valid for. */
  aud: string;
  /** Action being delegated, e.g. "purchase", "post", "read". */
  act: string;
  /** 8-bit cumulative permission bits (see PERM). */
  perm: Permission;
  /** Optional cap on a single invocation, e.g. { amount: 50, currency: "USD" }. */
  max?: { amount: number; currency: string };
  /** Issued-at, unix seconds. */
  iat: number;
  /** Expiry, unix seconds. */
  exp: number;
  /** Receipt id — used for revocation lookups and audit. */
  jti: string;
}

/**
 * Wire format: a compact JWS string (EdDSA over the claims). Phase 2 swaps
 * this for SD-JWT (selective disclosure); phase 3 wraps it in a ZKP. The
 * `Receipt` type stays stable across phases.
 */
export type Receipt = string;

export interface AllowOptions {
  /** Identifier for the agent being granted authority. */
  agent: string;
  /** Action the agent is allowed to perform. */
  action: string;
  /** Tool, merchant, or scope identifier. */
  audience: string;
  /** 8-bit cumulative permission. See PERM. */
  permission: Permission;
  /** Optional per-invocation cap. */
  maxAmount?: { amount: number; currency: string };
  /**
   * Receipt lifetime. Number = seconds. String = duration like "5m" or "1h".
   * Defaults to "1h".
   */
  expiresIn?: number | string;
  /** Optional override for issuer string. Default: derived from public key. */
  issuer?: string;
  /** Optional explicit jti (for tests / deterministic flows). */
  jti?: string;
}

export interface VerifyOptions {
  /** Required: agent the verifier expects to present this receipt. */
  expectedAgent: string;
  /** Required: action the agent is attempting. */
  expectedAction: string;
  /** Required: tool/merchant/scope identifier the verifier represents. */
  expectedAudience: string;
  /**
   * Required: human/issuer public key (or a list of trusted issuer keys).
   * Each entry is a CryptoKey or a base64url-encoded raw Ed25519 public key.
   */
  trustedIssuers: TrustedIssuer | TrustedIssuer[];
  /** Optional: caller's per-invocation amount, checked against receipt.max. */
  invocationAmount?: { amount: number; currency: string };
  /** Optional: clock skew tolerance in seconds. Default 30. */
  clockToleranceSeconds?: number;
}

export type TrustedIssuer = string | CryptoKey;

export type VerifyFailureReason =
  | "invalid_signature"
  | "expired"
  | "not_yet_valid"
  | "audience_mismatch"
  | "agent_mismatch"
  | "action_mismatch"
  | "permission_violation"
  | "amount_exceeds_cap"
  | "currency_mismatch"
  | "malformed";

export type VerifyResult =
  | { valid: true; claims: ReceiptClaims }
  | { valid: false; reason: VerifyFailureReason; detail?: string };
