// src/verify.ts — v0.2 orchestrator (Task 13).
//
// Implements spec §5.3 decision tree: structural triage → header check →
// issuer-key resolution → JWS signature verify → claim checks (delegated to
// verify-claims.ts) → cnf + KB-JWT verify (delegated to verify-kb.ts) →
// status-list check (delegated to status-list.ts).
//
// Reason translation: internal helpers emit lowercase enum literals
// (VerifyFailureReasonV01, KbFailureReason). This module is the single point
// where they are translated into the canonical UPPER_SNAKE_CASE
// VerifyFailureReason union via two module-scope Record<,> maps. The Record
// type makes the translation exhaustive — adding a new lowercase literal to
// either internal enum without updating the map is a tsc error.
//
// Note on legacy paths: a tilde-less receipt is treated as a v0.1
// compact-JWS. The orchestrator only routes it to verifyV01 when the caller
// opts in via opts.acceptLegacyV01; otherwise it returns LEGACY_V01_REJECTED.
import { jwtVerify, decodeProtectedHeader, decodeJwt, errors as joseErrors } from "jose";
import type {
  ReceiptClaims,
  VerifyOptions,
  VerifyResult,
  VerifyFailureReason,
  VerifyFailureReasonV01,
  IssuerKeyResolver,
} from "./types";
import { verifyV01 } from "./legacy-v01";
import { checkIssuerClaims } from "./verify-claims";
import { verifyKbJwt } from "./verify-kb";
import type { KbFailureReason } from "./verify-kb";
import { StatusListIssuerMismatchError, StatusListSignatureError } from "./status-list";

const ISS_TYP = "bolyra-delegation+sd-jwt";

/**
 * Translates the lowercase VerifyFailureReasonV01 strings produced by
 * checkIssuerClaims into the canonical UPPER_SNAKE_CASE VerifyFailureReason
 * union. Record<> over the source union ensures the table is exhaustive — tsc
 * will fail if a new V01 reason is added without a mapping.
 */
const claimReasonMap: Record<VerifyFailureReasonV01, VerifyFailureReason> = {
  invalid_signature: "INVALID_SIGNATURE",
  expired: "EXPIRED",
  not_yet_valid: "FUTURE_NBF",
  audience_mismatch: "WRONG_AUDIENCE",
  agent_mismatch: "WRONG_SUBJECT",
  action_mismatch: "WRONG_ACTION",
  permission_violation: "PERMISSION_VIOLATION",
  amount_exceeds_cap: "AMOUNT_EXCEEDS_CAP",
  currency_mismatch: "CURRENCY_MISMATCH",
  malformed: "BAD_FORMAT",
};

/**
 * Translates the lowercase KbFailureReason strings produced by verifyKbJwt
 * into the canonical UPPER_SNAKE_CASE VerifyFailureReason union. Same
 * exhaustiveness guarantee as claimReasonMap.
 */
const kbReasonMap: Record<KbFailureReason, VerifyFailureReason> = {
  kb_jwt_malformed: "KB_BAD_FORMAT",
  kb_jwt_typ_mismatch: "KB_TYP_INVALID",
  unsupported_alg: "KB_ALG_UNSUPPORTED",
  cnf_jwk_invalid: "CNF_JWK_INVALID",
  holder_key_thumbprint_mismatch: "KB_BINDING_MISMATCH",
  kb_jwt_invalid_signature: "KB_INVALID_SIGNATURE",
  kb_jwt_audience_mismatch: "KB_WRONG_AUDIENCE",
  kb_jwt_nonce_mismatch: "KB_WRONG_NONCE",
  kb_jwt_sd_hash_mismatch: "KB_WRONG_SD_HASH",
  kb_jwt_iat_in_future: "KB_IAT_FUTURE",
  kb_jwt_expired: "KB_IAT_TOO_OLD",
};

export async function verify(
  receipt: string,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  // Step 1: structural triage on the '~' separator.
  const tildeCount = (receipt.match(/~/g) ?? []).length;
  if (tildeCount === 0) {
    // Plain compact-JWS — possibly v0.1. Only route to verifyV01 when the
    // caller opts in; otherwise reject with the typed sentinel reason.
    if (opts.acceptLegacyV01) {
      const v01 = await verifyV01(receipt, opts);
      if (v01.ok) return { ok: true, claims: v01.claims, legacyV01: true };
      // verifyV01 emits its own (extended) lowercase reason set; map the
      // subset that intersects VerifyFailureReason directly. Anything outside
      // the V01 enum (unknown_issuer_kid, kid_resolver_error,
      // legacy_v01_rejected) is mapped via a small inline switch so the
      // public surface stays UPPER_SNAKE_CASE.
      return { ok: false, reason: mapV01BridgeReason(v01.reason), detail: v01.detail };
    }
    return { ok: false, reason: "LEGACY_V01_REJECTED" };
  }
  if (tildeCount === 1 && receipt.endsWith("~")) {
    // Issuer-form (no KB-JWT appended). Spec §5.3: KB-JWT is mandatory for
    // verify(); a presented receipt always has the trailing ~kbjwt segment.
    return { ok: false, reason: "KB_MISSING" };
  }
  if (tildeCount !== 2) return { ok: false, reason: "SD_JWT_MALFORMED" };

  const [jws, , kbJwt] = receipt.split("~");
  if (!jws || !kbJwt) return { ok: false, reason: "SD_JWT_MALFORMED" };

  // Step 2: header introspection. typ + alg + kid all required before we even
  // think about resolving a key.
  let hdr: Record<string, unknown>;
  try {
    hdr = decodeProtectedHeader(jws) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "SD_JWT_MALFORMED" };
  }
  if (hdr.alg !== "EdDSA") return { ok: false, reason: "UNSUPPORTED_ALG" };
  if (hdr.typ !== ISS_TYP) return { ok: false, reason: "TYP_MISMATCH" };
  const kid = typeof hdr.kid === "string" ? hdr.kid : "";
  if (!kid) return { ok: false, reason: "KID_MISSING" };

  // Step 3: peek payload to learn iss, then call resolver. We decode without
  // verifying so the resolver can be invoked with (iss, kid). The signature
  // is verified below in Step 4 against the resolved key.
  let preClaims: Record<string, unknown>;
  try {
    preClaims = decodeJwt(jws) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "SD_JWT_MALFORMED" };
  }
  const iss = String(preClaims.iss ?? "");

  // F2 fix: pre-check exp on the decoded (unverified) claims so an expired
  // receipt reports the canonical `EXPIRED` reason instead of being masked
  // by jose's generic signature error. jose's jwtVerify automatically
  // validates exp/nbf and throws a single opaque error for both bad
  // signature and expired token, which previously surfaced as
  // INVALID_SIGNATURE and misled design partners debugging clock issues.
  // A tampered-but-expired token still ends up rejected — the failure
  // reason is the only thing that changes, from less- to more-informative.
  // <= matches jose's boundary: jwtVerify treats exp + tolerance === now as
  // already expired, so a strict < here would let the exact-boundary case
  // fall through to the catch below and surface as INVALID_SIGNATURE again.
  const nowEarly = Math.floor(Date.now() / 1000);
  const skewEarly = opts.clockSkewSeconds ?? 30;
  const expEarly = preClaims.exp;
  if (typeof expEarly === "number" && expEarly + skewEarly <= nowEarly) {
    return { ok: false, reason: "EXPIRED" };
  }

  // VerifyOptions.trustedIssuers is a union (IssuerKeyResolver | TrustedIssuer
  // | TrustedIssuer[]) for v0.1 compatibility. The v0.2 surface requires the
  // resolver function form. Per the project convention we narrow at the call
  // site rather than widening the public type.
  const resolver = opts.trustedIssuers as IssuerKeyResolver | undefined;
  if (typeof resolver !== "function") {
    // Not a resolver function — caller is using the legacy-array form on the
    // v0.2 path. Bridge: bail rather than silently accepting the wrong shape.
    return { ok: false, reason: "KID_RESOLVER_ERROR", detail: "trustedIssuers must be an IssuerKeyResolver function on the v0.2 path" };
  }

  let issuerKey: CryptoKey | null;
  try {
    issuerKey = await resolver(iss, kid);
  } catch {
    return { ok: false, reason: "KID_RESOLVER_ERROR" };
  }
  if (!issuerKey) return { ok: false, reason: "UNKNOWN_ISSUER_KID" };

  // Step 4: verify the issuer-JWS signature. typ-pinning here is redundant
  // with Step 2 but cheap, and means a typ mutation slipping past the header
  // check still gets caught.
  //
  // F2: pass `clockTolerance` so jose's internal exp/iat check uses the same
  // skew as `checkIssuerClaims`. Without this, jose's default 0s tolerance
  // throws a generic signature error on an expired receipt, which we used to
  // map to INVALID_SIGNATURE — misleading for design partners debugging
  // clock issues. The pre-check above also catches this when the configured
  // skew is tight; this `clockTolerance` ensures jose stops emitting the
  // generic error so `checkIssuerClaims` becomes the single source of truth
  // for expiry → EXPIRED reason translation.
  let claims: ReceiptClaims;
  try {
    const v = await jwtVerify(jws, issuerKey as unknown as CryptoKey, {
      typ: ISS_TYP,
      clockTolerance: opts.clockSkewSeconds ?? 30,
    });
    claims = v.payload as unknown as ReceiptClaims;
  } catch (err) {
    // The pre-check above can pass and the clock still cross exp + skew
    // while an async issuer resolver is in flight; jose then throws
    // JWTExpired here. Keep that case fail-closed but report the honest
    // reason instead of collapsing it into INVALID_SIGNATURE.
    if (err instanceof joseErrors.JWTExpired) {
      return { ok: false, reason: "EXPIRED" };
    }
    return { ok: false, reason: "INVALID_SIGNATURE" };
  }

  const now = Math.floor(Date.now() / 1000);

  // Step 5: claim checks (exp/iat/aud/sub/act/perm/cap). checkIssuerClaims
  // emits lowercase VerifyFailureReasonV01 — translate via Record map.
  const claimReason = checkIssuerClaims(claims, opts, now);
  if (claimReason) return { ok: false, reason: claimReasonMap[claimReason] };

  // Step 6: cnf required + KB-JWT verify. Spec §5.3 step (f) / §8.1: caller
  // MUST supply a kbNonce. Undefined nonce means the verifier forgot to bind
  // a fresh challenge — fail-closed with KB_NONCE_REQUIRED. Empty-string is
  // a legitimate value and is exact-matched against payload.nonce downstream.
  const cnf = claims.cnf;
  if (!cnf?.jwk) return { ok: false, reason: "CNF_MISSING" };
  if (opts.kbNonce === undefined) return { ok: false, reason: "KB_NONCE_REQUIRED" };
  const kbReason = await verifyKbJwt(kbJwt, jws, cnf.jwk, opts, now);
  if (kbReason) return { ok: false, reason: kbReasonMap[kbReason] };

  // Step 7: status-list check (only if the receipt advertises a status slot).
  // Spec §5.3 step (k): discriminate failure modes via sentinel error
  // classes — no string matching. Issuer-mismatch and signature failures are
  // typed; anything else (network, parse, timeout, HTTP 4xx/5xx) buckets to
  // STATUS_LIST_UNREACHABLE.
  const status = claims.status?.status_list;
  if (status) {
    if (!opts.checkStatus) return { ok: false, reason: "STATUS_CHECK_UNCONFIGURED" };
    try {
      const r = await opts.checkStatus(status.uri, status.idx, iss);
      if (r.status === "invalid") return { ok: false, reason: "STATUS_REVOKED" };
      if (r.status === "suspended") return { ok: false, reason: "STATUS_SUSPENDED" };
    } catch (e) {
      if (e instanceof StatusListIssuerMismatchError) {
        return { ok: false, reason: "STATUS_LIST_ISSUER_MISMATCH" };
      }
      if (e instanceof StatusListSignatureError) {
        return { ok: false, reason: "STATUS_LIST_SIG_INVALID" };
      }
      return { ok: false, reason: "STATUS_LIST_UNREACHABLE" };
    }
  }

  return { ok: true, claims, legacyV01: false };
}

/**
 * Maps the V01-bridge reason set (which is a superset of VerifyFailureReasonV01
 * — adds unknown_issuer_kid, kid_resolver_error, legacy_v01_rejected) onto
 * the public UPPER_SNAKE_CASE union. The intersection with claimReasonMap is
 * intentional: keeping this small inline mapper avoids leaking the bridge
 * enum into the v0.2 surface while still translating every value verifyV01
 * can produce.
 */
function mapV01BridgeReason(reason: string): VerifyFailureReason {
  if (reason in claimReasonMap) {
    return claimReasonMap[reason as VerifyFailureReasonV01];
  }
  switch (reason) {
    case "unknown_issuer_kid": return "UNKNOWN_ISSUER_KID";
    case "kid_resolver_error": return "KID_RESOLVER_ERROR";
    case "legacy_v01_rejected": return "LEGACY_V01_REJECTED";
    default: return "UNKNOWN";
  }
}
