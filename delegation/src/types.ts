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
  /** RFC 7800 confirmation — present in v0.2 issuer JWS, absent in v0.1. */
  cnf?: { jwk: { kty: "OKP"; crv: "Ed25519"; x: string } };
  /** IETF status-list pointer — present when the issuer published one. */
  status?: { status_list: { uri: string; idx: number } };
}

/**
 * Wire format: a compact JWS string (EdDSA over the claims). Phase 2 swaps
 * this for SD-JWT (selective disclosure); phase 3 wraps it in a ZKP. The
 * `Receipt` type stays stable across phases.
 */
export type Receipt = string;

export interface AllowOptionsV01 {
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

export interface VerifyOptionsV01 {
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
  // ---- v0.1 inherited (10) ----
  | "invalid_signature" | "expired" | "not_yet_valid" | "audience_mismatch"
  | "agent_mismatch" | "action_mismatch" | "permission_violation"
  | "amount_exceeds_cap" | "currency_mismatch" | "malformed"
  // ---- SD-JWT structural (6) ----
  | "sd_jwt_malformed" | "kid_missing" | "kid_resolver_error"
  | "unknown_issuer_kid" | "unsupported_alg" | "typ_mismatch"
  // ---- cnf (2) ----
  | "cnf_missing" | "cnf_jwk_invalid"
  // ---- KB-JWT (11) ----
  | "kb_nonce_required" | "kb_jwt_missing" | "kb_jwt_malformed"
  | "kb_jwt_invalid_signature" | "kb_jwt_typ_mismatch"
  | "kb_jwt_audience_mismatch" | "kb_jwt_nonce_mismatch"
  | "kb_jwt_sd_hash_mismatch" | "kb_jwt_expired" | "kb_jwt_iat_in_future"
  | "holder_key_thumbprint_mismatch"
  // ---- status-list (6) ----
  | "status_check_unconfigured" | "status_list_unreachable"
  | "status_list_signature_invalid" | "status_list_issuer_mismatch"
  | "status_revoked" | "status_suspended"
  // ---- legacy gate (1) ----
  | "legacy_v01_rejected";

export type VerifyResultV01 =
  | { valid: true; claims: ReceiptClaims }
  | { valid: false; reason: VerifyFailureReason; detail?: string };

// ---- v0.2 additions ----

export interface AllowOptions {
  iss: string;
  sub: string;
  aud: string;
  act: string;
  /**
   * Permission scope. v0.2 widens this from the v0.1 `Permission` enum to
   * `string` so issuers can mint permissions outside the cumulative-bit set
   * (e.g. SAAS-specific scopes). The cumulative-bit `permImplies()` check in
   * `verify-claims.ts` only fires when both sides are recognized Permission
   * values; otherwise the comparator falls back to literal equality.
   */
  perm: string;
  max?: { amount: number; currency: string };
  ttlSeconds?: number;
  jti?: string;
  agentPubKey: CryptoKey | string;
  statusList?: { uri: string; idx: number };
}

export interface PresentOptions {
  nonce: string;
  audience: string;
}

export type IssuerKeyResolver =
  (iss: string, kid: string) => Promise<CryptoKey | null>;

export interface StatusListResult {
  status: "valid" | "invalid" | "suspended";
  /** Unix-epoch ms when the status-list token was retrieved. */
  fetchedAt: number;
}

export type StatusListChecker =
  (uri: string, idx: number, expectedIss: string) => Promise<StatusListResult>;

export interface VerifyOptions {
  audience: string;
  expectedSubject?: string;
  action?: string;
  perm?: string;
  amount?: number;
  currency?: string;
  trustedIssuers: IssuerKeyResolver;
  kbNonce?: string;
  kbMaxAgeSeconds?: number;
  clockSkewSeconds?: number;
  statusListChecker?: StatusListChecker;
  acceptLegacyV01?: boolean;
}

export type VerifyResult =
  | { ok: true; claims: ReceiptClaims; legacyV01: boolean }
  | { ok: false; reason: VerifyFailureReason };
