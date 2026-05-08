import type { Permission } from "./permissions";

/**
 * Receipt claims (JWT body). v0.1 carried `act` and `perm` as required fields;
 * the v0.2 SD-JWT surface no longer requires them on the receipt body (they
 * move into selective-disclosure form), so they are optional here so the
 * canonical v0.2 receipt shape compiles. v0.1 issuance still populates them.
 */
export type ReceiptClaims = {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  parent_jti?: string;
  /** v0.1-required action; optional in v0.2 receipts where it lives in disclosures. */
  act?: string;
  /** v0.1-required cumulative permission; optional in v0.2 where it lives in disclosures. */
  perm?: Permission;
  /** Optional cap on a single invocation, e.g. { amount: 50, currency: "USD" }. */
  max?: { amount: number; currency: string };
  /** RFC 7800 confirmation key (Ed25519 holder JWK). v0.2 SD-JWT bindings always populate this. */
  cnf?: { jwk: { kty: "OKP"; crv: "Ed25519"; x: string } };
  /** IETF status-list slot (draft-ietf-oauth-status-list-20). v0.2 SD-JWT bindings always populate this. */
  status?: { status_list: { uri: string; idx: number } };
};

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
  | "BAD_FORMAT"
  | "INVALID_SIGNATURE"
  | "EXPIRED"
  | "FUTURE_NBF"
  | "WRONG_ISSUER"
  | "WRONG_AUDIENCE"
  | "WRONG_SUBJECT"
  | "MISSING_CLAIM"
  | "PARENT_NOT_FOUND"
  | "DELEGATION_LOOP"
  | "DISCLOSURE_TAMPERED"
  | "DISCLOSURE_HASH_MISMATCH"
  | "UNDISCLOSED_CLAIM_REQUIRED"
  | "DUPLICATE_DISCLOSURE"
  | "MALFORMED_DISCLOSURE"
  | "SD_ALG_UNSUPPORTED"
  | "CNF_MISSING"
  | "CNF_KEY_MISMATCH"
  | "KB_MISSING"
  | "KB_BAD_FORMAT"
  | "KB_INVALID_SIGNATURE"
  | "KB_WRONG_NONCE"
  | "KB_WRONG_AUDIENCE"
  | "KB_WRONG_SD_HASH"
  | "KB_TYP_INVALID"
  | "KB_ALG_UNSUPPORTED"
  | "KB_IAT_FUTURE"
  | "KB_IAT_TOO_OLD"
  | "KB_BINDING_MISMATCH"
  | "STATUS_REVOKED"
  | "STATUS_SUSPENDED"
  | "STATUS_FETCH_FAILED"
  | "STATUS_LIST_INVALID"
  | "STATUS_LIST_SIG_INVALID"
  | "STATUS_INDEX_OUT_OF_RANGE"
  | "UNKNOWN";

/**
 * Legacy v0.1 failure reasons (lowercase). Kept separate from the canonical
 * v0.2 `VerifyFailureReason` union — Task 1b plan dictates UPPER_SNAKE_CASE
 * for the v0.2 surface; v0.1 verify.ts still emits its original lowercase
 * literals so call sites that branch on them keep compiling.
 */
export type VerifyFailureReasonV01 =
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

export type VerifyResultV01 =
  | { valid: true; claims: ReceiptClaims }
  | { valid: false; reason: VerifyFailureReasonV01; detail?: string };

// ---- v0.2 additions ----

export type Ed25519JWK = { kty: "OKP"; crv: "Ed25519"; x: string };

export type AllowOptions = {
  issuerPrivateKey: Uint8Array;
  issuerKid: string;
  subject: string;
  audience: string;
  ttlSeconds: number;
  agentPubKey: Ed25519JWK;
  statusList: { uri: string; idx: number };
  parentJti?: string;
  permissions?: { sub_delegate?: boolean };
};

export type PresentOptions = {
  sdJwt: string;
  holderPrivateKey: Uint8Array;
  nonce: string;
  audience: string;
  disclose?: string[];
};

export type IssuerKeyResolver =
  (iss: string, kid: string) => Promise<CryptoKey | null>;

export type StatusListResult =
  | { ok: true }
  | {
      ok: false;
      reason:
        | "STATUS_REVOKED"
        | "STATUS_SUSPENDED"
        | "STATUS_FETCH_FAILED"
        | "STATUS_LIST_INVALID"
        | "STATUS_LIST_SIG_INVALID"
        | "STATUS_INDEX_OUT_OF_RANGE";
    };

export type StatusListChecker = (
  uri: string,
  idx: number,
) => Promise<StatusListResult>;

export type VerifyOptions = {
  /**
   * Canonical v0.2 expected audience. Optional at the type level so the
   * legacy v0.1 path (which uses `audience`) can share this single options
   * shape; the v0.2 dispatcher still requires it at runtime.
   */
  expectedAudience?: string;
  expectedIssuer?: string;
  /**
   * Canonical v0.2 issuer key resolver. Optional at the type level so the
   * legacy v0.1 path (which uses `trustedIssuers`) can share this shape.
   * The v0.2 dispatcher still requires it at runtime.
   */
  resolveIssuerKey?: IssuerKeyResolver;
  checkStatus?: StatusListChecker;
  /** Required if the SD-JWT presentation is expected to carry a KB-JWT. */
  expectedNonce?: string;
  /** Maximum acceptable iat-skew on KB-JWT (seconds). Default 60. */
  maxKbIatSkewSeconds?: number;

  // ---- Legacy v0.1 path fields (consumed by verifyV01).
  // All optional so the canonical v0.2 shape still compiles. The v0.1 path
  // accepts either the new names below or the old aliases (expectedAgent,
  // expectedAction, invocationAmount, clockToleranceSeconds, trustedIssuers
  // as a TrustedIssuer | TrustedIssuer[]).
  /** v0.1: caller-expected audience (alias used by verifyV01 in lieu of expectedAudience). */
  audience?: string;
  /** v0.1: subject (agent) the verifier expects. */
  expectedSubject?: string;
  /** v0.1 alias of expectedSubject. */
  expectedAgent?: string;
  /** v0.1: action the agent is attempting. */
  action?: string;
  /** v0.1 alias of action. */
  expectedAction?: string;
  /** v0.1: required permission bitmask. */
  perm?: number;
  /** v0.1: caller's invocation amount. */
  amount?: number;
  /** v0.1: caller's invocation currency. Pairs with `amount`. */
  currency?: string;
  /** v0.1 grouped form of {amount, currency}. */
  invocationAmount?: { amount: number; currency: string };
  /** v0.1: clock skew tolerance in seconds. Default 30. */
  clockSkewSeconds?: number;
  /** v0.1 alias of clockSkewSeconds. */
  clockToleranceSeconds?: number;
  /** v0.1: issuer key resolver, OR a single TrustedIssuer / array of them. */
  trustedIssuers?: IssuerKeyResolver | TrustedIssuer | TrustedIssuer[];
};

export type VerifyResult =
  | { ok: true; claims: ReceiptClaims }
  | { ok: false; reasons: VerifyFailureReason[] };
