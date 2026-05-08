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
  /**
   * v0.1-required cumulative permission; optional in v0.2 where it lives in disclosures.
   * v0.2 stores the human-readable label (e.g., "FINANCIAL_SMALL") in the body claim;
   * v0.1 issuance still uses the numeric `Permission` cumulative-bit form. Accepts either.
   */
  perm?: string | Permission;
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

/**
 * v0.2 SD-JWT issuance options. Mirrors the spec §5.1 surface: the issuer key
 * is supplied as a positional second argument to allow(), and the receipt-body
 * fields (iss/sub/aud/act/perm/max/jti) live alongside the agent's holder key
 * (cnf material) and an optional status-list slot.
 *
 * Note: this canonical shape supersedes the placeholder shape established in
 * Task 1b's types.test.ts. Field renames vs the placeholder:
 *   subject  → sub
 *   audience → aud
 *   issuerPrivateKey/issuerKid moved to the positional `issuerKey` arg of allow()
 *   agentPubKey: Ed25519JWK → agentPubKey: CryptoKey | string (JWK-as-JSON)
 *   ttlSeconds, statusList → optional (defaults: ttl=300, no status slot)
 * `parentJti` and `permissions.sub_delegate` are preserved as optional additions
 * for downstream delegation-chain support.
 */
export type AllowOptions = {
  /** Issuer DID/URL. Becomes the JWS `iss` claim. */
  iss: string;
  /** Subject (typically the agent identifier). Becomes the JWS `sub` claim. */
  sub: string;
  /** Audience (RP/merchant). Becomes the JWS `aud` claim. */
  aud: string;
  /** Action label, e.g. "checkout.charge". Becomes the JWS `act` claim. */
  act: string;
  /**
   * Permission identifier carried as a string body claim. v0.2 keeps the
   * numeric cumulative-bit Permission (see ./permissions) inside disclosures;
   * the body field is the human-readable label.
   */
  perm: string;
  /** Optional cap on a single invocation. */
  max?: { amount: number; currency: string };
  /** Receipt lifetime in seconds. Defaults to 300 when omitted. */
  ttlSeconds?: number;
  /** Optional explicit jti (deterministic flows / tests). Defaults to UUIDv4. */
  jti?: string;
  /**
   * Agent's holder public key. Accepted forms:
   *   - CryptoKey (Ed25519 public key)
   *   - JSON-stringified JWK (must parse + import as OKP/Ed25519)
   * The cnf claim is derived via exportJWK() on the resolved CryptoKey.
   */
  agentPubKey: CryptoKey | string;
  /** Optional IETF status-list slot. URI must use https:// at runtime. */
  statusList?: { uri: string; idx: number };
  /** Optional parent jti for delegation chaining. */
  parentJti?: string;
  /** Optional sub-delegation flag. Reserved for delegation chains. */
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

/**
 * Canonical v0.2 status-list result. See plan §1b lines 230-234 and spec §5.4:
 * fetchStatusList resolves the slot's "valid|invalid|suspended" disposition and
 * timestamps when the status-list token was retrieved. Failure modes throw
 * sentinel errors (StatusListIssuerMismatchError, StatusListSignatureError,
 * etc.) rather than encoding them in the union — the orchestrator (verify.ts)
 * catches those errors and maps them to VerifyFailureReason.
 */
export interface StatusListResult {
  status: "valid" | "invalid" | "suspended";
  /** Unix-epoch seconds when the status-list token was retrieved. */
  fetchedAt: number;
}

export type StatusListChecker = (
  uri: string,
  idx: number,
  expectedIss: string,
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

  // ---- Task 12 KB-JWT support (consumed by verify-kb.ts).
  // verifyKbJwt reads these directly. The Task 13 orchestrator may also accept
  // `expectedNonce` / `maxKbIatSkewSeconds` and forward into these fields.
  /** Task 12: required nonce the KB-JWT payload must echo. */
  kbNonce?: string;
  /** Task 12: maximum acceptable KB-JWT age in seconds (iat freshness). Default 60. */
  kbMaxAgeSeconds?: number;

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
  /**
   * v0.1: required permission. Accepts either the numeric cumulative bitmask
   * (legacy v0.1 surface) or a string label (v0.2 surface, e.g.
   * "FINANCIAL_UNLIMITED"). `permImplies` in ./permissions resolves both.
   */
  perm?: string | number;
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
