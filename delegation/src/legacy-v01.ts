import { jwtVerify, decodeProtectedHeader, decodeJwt, errors as joseErrors } from "jose";
import type { JWTPayload } from "jose";
import type {
  ReceiptClaims,
  VerifyOptions,
  IssuerKeyResolver,
  TrustedIssuer,
} from "./types";
import { hasPermission, validateCumulativeBitEncoding } from "./permissions";
import { importKeyPair } from "./keys";

/**
 * v0.1 verify reasons preserved by this module, plus the new v0.2-bridge
 * additions: `unknown_issuer_kid`, `kid_resolver_error`, `legacy_v01_rejected`.
 */
export type VerifyReasonV01 =
  | "invalid_signature"
  | "expired"
  | "not_yet_valid"
  | "audience_mismatch"
  | "agent_mismatch"
  | "action_mismatch"
  | "permission_violation"
  | "amount_exceeds_cap"
  | "currency_mismatch"
  | "malformed"
  | "unknown_issuer_kid"
  | "kid_resolver_error"
  | "legacy_v01_rejected";

export type VerifyResultV01Bridged =
  | { ok: true; claims: ReceiptClaims; legacyV01: true }
  | { ok: false; reason: VerifyReasonV01; detail?: string };

/**
 * Back-compat verify entry point for v0.1 (compact-JWS) receipts.
 *
 * Accepts both the new v0.2-style option names (`audience`, `expectedSubject`,
 * `action`, `perm`, `amount`/`currency`, `clockSkewSeconds`, `trustedIssuers`
 * as IssuerKeyResolver) and the legacy v0.1 names (`expectedAudience`,
 * `expectedAgent`, `expectedAction`, `invocationAmount`, `clockToleranceSeconds`,
 * `trustedIssuers` as TrustedIssuer | TrustedIssuer[]).
 *
 * The first executable check is the tilde gate: any input containing `~` is
 * rejected with `legacy_v01_rejected` so that an SD-JWT input accidentally
 * routed here is bounced back to the v0.2 dispatcher rather than failing on a
 * confusing parse error.
 */
export async function verifyV01(
  receipt: string,
  opts: VerifyOptions,
): Promise<VerifyResultV01Bridged> {
  // --- Tilde gate. Must be the first executable check. v0.1 receipts are
  // compact JWS (header.payload.sig) and never contain '~'. SD-JWT receipts
  // do (disclosure separator), so any '~' means "this is not a v0.1 receipt."
  if (typeof receipt === "string" && receipt.includes("~")) {
    return { ok: false, reason: "legacy_v01_rejected" };
  }

  // Normalize v0.1/v0.2 option aliases into a single canonical bag.
  const audience = opts.audience ?? opts.expectedAudience;
  const expectedSubject = opts.expectedSubject ?? opts.expectedAgent;
  const action = opts.action ?? opts.expectedAction;
  const perm = opts.perm;
  const clockSkewSeconds = opts.clockSkewSeconds ?? opts.clockToleranceSeconds ?? 30;
  const invocation = opts.invocationAmount
    ?? (opts.amount !== undefined && opts.currency !== undefined
        ? { amount: opts.amount, currency: opts.currency }
        : undefined);

  if (!audience) {
    return { ok: false, reason: "malformed", detail: "audience required" };
  }

  // Resolve verification key. Three input shapes are supported:
  //  1. IssuerKeyResolver function (preferred).
  //  2. Array of TrustedIssuer (legacy v0.1).
  //  3. Single TrustedIssuer (legacy v0.1).
  const resolverInput = opts.trustedIssuers;
  if (resolverInput == null) {
    return { ok: false, reason: "malformed", detail: "no trusted issuers supplied" };
  }

  // Read protected header + payload (without verifying yet) so the resolver
  // can be invoked with iss/kid. The header must parse — if it doesn't, the
  // input is malformed. The payload, however, may fail to parse on a tampered
  // receipt (mutating one base64url char often yields invalid JSON); that is
  // a signature-tier failure, not a malformed-input failure, so we treat
  // payload-decode failure as a hint that the signature won't verify and let
  // jwtVerify produce the canonical `invalid_signature` reason below.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(receipt);
  } catch (err) {
    return {
      ok: false,
      reason: "malformed",
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  let unverifiedPayload: JWTPayload;
  try {
    unverifiedPayload = decodeJwt(receipt);
  } catch {
    // A legitimate signed receipt always has a JSON-decodable payload. If the
    // payload can't be parsed, the receipt was tampered and the signature
    // would not verify against any trusted key. Return invalid_signature.
    return { ok: false, reason: "invalid_signature" };
  }
  const kid = (header.kid as string | undefined) ?? "";
  const iss = (unverifiedPayload.iss as string | undefined) ?? "";

  // Build the candidate-key list.
  let candidateKeys: CryptoKey[];
  if (typeof resolverInput === "function") {
    // It's a resolver. Call with (iss, kid) and treat null as unknown.
    try {
      const k = await (resolverInput as IssuerKeyResolver)(iss, kid);
      if (k == null) {
        return { ok: false, reason: "unknown_issuer_kid" };
      }
      candidateKeys = [k];
    } catch (err) {
      return {
        ok: false,
        reason: "kid_resolver_error",
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  } else {
    // Legacy: TrustedIssuer | TrustedIssuer[].
    const issuers = Array.isArray(resolverInput)
      ? (resolverInput as TrustedIssuer[])
      : [resolverInput as TrustedIssuer];
    if (issuers.length === 0) {
      return { ok: false, reason: "malformed", detail: "no trusted issuers supplied" };
    }
    candidateKeys = await Promise.all(issuers.map(coerceIssuerKey));
  }

  // --- Pre-jose future-time check. v0.1 has no nbf claim, so we use iat.
  const iat = unverifiedPayload.iat;
  const now = Math.floor(Date.now() / 1000);
  if (typeof iat === "number" && iat - clockSkewSeconds > now) {
    return { ok: false, reason: "not_yet_valid" };
  }

  // Try each candidate key until one verifies.
  let lastError: unknown = null;
  for (const key of candidateKeys) {
    try {
      const { payload } = await jwtVerify(receipt, key, {
        audience,
        clockTolerance: clockSkewSeconds,
      });
      return checkSemantics(payload, { expectedSubject, action, perm, invocation });
    } catch (err) {
      lastError = err;
      // Try next key.
    }
  }
  return mapJoseError(lastError);
}

interface SemanticOpts {
  expectedSubject?: string;
  action?: string;
  perm?: number;
  invocation?: { amount: number; currency: string };
}

function checkSemantics(
  payload: JWTPayload,
  s: SemanticOpts,
): VerifyResultV01Bridged {
  const claims = payload as unknown as ReceiptClaims;

  if (s.expectedSubject !== undefined && claims.sub !== s.expectedSubject) {
    return {
      ok: false,
      reason: "agent_mismatch",
      detail: `expected ${s.expectedSubject}, got ${claims.sub}`,
    };
  }
  if (s.action !== undefined && claims.act !== s.action) {
    return {
      ok: false,
      reason: "action_mismatch",
      detail: `expected ${s.action}, got ${claims.act}`,
    };
  }

  if (claims.perm === undefined) {
    return { ok: false, reason: "malformed", detail: "missing perm claim" };
  }
  const permViolation = validateCumulativeBitEncoding(claims.perm);
  if (permViolation) {
    return { ok: false, reason: "permission_violation", detail: permViolation };
  }
  if (s.perm !== undefined && !hasPermission(claims.perm, s.perm)) {
    return {
      ok: false,
      reason: "permission_violation",
      detail: `granted ${claims.perm} does not include required ${s.perm}`,
    };
  }

  if (s.invocation && claims.max) {
    if (claims.max.currency !== s.invocation.currency) {
      return {
        ok: false,
        reason: "currency_mismatch",
        detail: `cap is ${claims.max.currency}, invocation is ${s.invocation.currency}`,
      };
    }
    if (s.invocation.amount > claims.max.amount) {
      return {
        ok: false,
        reason: "amount_exceeds_cap",
        detail: `invocation ${s.invocation.amount} > cap ${claims.max.amount}`,
      };
    }
  }

  // Permission gating for financial actions: if the receipt covers a financial
  // action, the permission tier must be at least FINANCIAL_SMALL.
  if (claims.act && (claims.act.startsWith("purchase") || claims.act.startsWith("pay"))) {
    if (!hasPermission(claims.perm, 1 << 2)) {
      return {
        ok: false,
        reason: "permission_violation",
        detail: "financial action requires FINANCIAL_SMALL or higher",
      };
    }
  }

  return { ok: true, claims, legacyV01: true };
}

async function coerceIssuerKey(issuer: TrustedIssuer): Promise<CryptoKey> {
  if (typeof issuer === "string") {
    // Treat as base64url-encoded raw Ed25519 public key (32 bytes).
    const { publicKey } = await importKeyPair({
      publicJwk: { kty: "OKP", crv: "Ed25519", x: issuer },
    });
    if (!publicKey) throw new Error("could not import issuer key");
    return publicKey;
  }
  return issuer;
}

function mapJoseError(err: unknown): VerifyResultV01Bridged {
  if (err instanceof joseErrors.JWTExpired) {
    return { ok: false, reason: "expired" };
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === "aud") return { ok: false, reason: "audience_mismatch" };
    return { ok: false, reason: "malformed", detail: err.message };
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return { ok: false, reason: "invalid_signature" };
  }
  if (err instanceof joseErrors.JWTInvalid || err instanceof joseErrors.JWSInvalid) {
    return { ok: false, reason: "malformed", detail: err.message };
  }
  return {
    ok: false,
    reason: "invalid_signature",
    detail: err instanceof Error ? err.message : String(err),
  };
}
