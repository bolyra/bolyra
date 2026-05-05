import { jwtVerify, errors as joseErrors } from "jose";
import type { JWTPayload } from "jose";
import type {
  Receipt,
  ReceiptClaims,
  VerifyOptions,
  VerifyResult,
  TrustedIssuer,
} from "./types";
import { hasPermission, validateCumulativeBitEncoding } from "./permissions";
import { importKeyPair } from "./keys";

/**
 * Verify a delegation receipt against the caller's expectations.
 * Returns { valid: true, claims } on success, { valid: false, reason } otherwise.
 *
 * The verifier MUST supply expectedAgent, expectedAction, expectedAudience,
 * and at least one trusted issuer key. Mismatches return a typed reason.
 */
export async function verify(
  receipt: Receipt,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const issuers = Array.isArray(opts.trustedIssuers)
    ? opts.trustedIssuers
    : [opts.trustedIssuers];

  if (issuers.length === 0) {
    return { valid: false, reason: "malformed", detail: "no trusted issuers supplied" };
  }

  const tolerance = opts.clockToleranceSeconds ?? 30;

  // Try each trusted issuer key until one verifies. This lets the caller pass
  // a list of acceptable signers without building a key resolver themselves.
  let lastError: unknown = null;
  for (const issuer of issuers) {
    const key = await coerceIssuerKey(issuer);
    try {
      const { payload } = await jwtVerify(receipt, key, {
        audience: opts.expectedAudience,
        clockTolerance: tolerance,
      });
      return checkSemantics(payload, opts);
    } catch (err) {
      lastError = err;
      // Try the next issuer.
    }
  }

  return mapJoseError(lastError);
}

function checkSemantics(payload: JWTPayload, opts: VerifyOptions): VerifyResult {
  const claims = payload as unknown as ReceiptClaims;

  if (claims.sub !== opts.expectedAgent) {
    return { valid: false, reason: "agent_mismatch", detail: `expected ${opts.expectedAgent}, got ${claims.sub}` };
  }
  if (claims.act !== opts.expectedAction) {
    return { valid: false, reason: "action_mismatch", detail: `expected ${opts.expectedAction}, got ${claims.act}` };
  }

  const permViolation = validateCumulativeBitEncoding(claims.perm);
  if (permViolation) {
    return { valid: false, reason: "permission_violation", detail: permViolation };
  }

  if (opts.invocationAmount && claims.max) {
    if (claims.max.currency !== opts.invocationAmount.currency) {
      return {
        valid: false,
        reason: "currency_mismatch",
        detail: `cap is ${claims.max.currency}, invocation is ${opts.invocationAmount.currency}`,
      };
    }
    if (opts.invocationAmount.amount > claims.max.amount) {
      return {
        valid: false,
        reason: "amount_exceeds_cap",
        detail: `invocation ${opts.invocationAmount.amount} > cap ${claims.max.amount}`,
      };
    }
  }

  // Permission gating for financial actions: if the receipt covers a financial
  // action, the permission tier must be at least FINANCIAL_SMALL. Higher-tier
  // checks are the verifier's responsibility (use hasPermission).
  if (claims.act.startsWith("purchase") || claims.act.startsWith("pay")) {
    if (!hasPermission(claims.perm, 1 << 2)) {
      return { valid: false, reason: "permission_violation", detail: "financial action requires FINANCIAL_SMALL or higher" };
    }
  }

  return { valid: true, claims };
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

function mapJoseError(err: unknown): VerifyResult {
  if (err instanceof joseErrors.JWTExpired) {
    return { valid: false, reason: "expired" };
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === "aud") return { valid: false, reason: "audience_mismatch" };
    return { valid: false, reason: "malformed", detail: err.message };
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return { valid: false, reason: "invalid_signature" };
  }
  if (err instanceof joseErrors.JWTInvalid || err instanceof joseErrors.JWSInvalid) {
    return { valid: false, reason: "malformed", detail: err.message };
  }
  return {
    valid: false,
    reason: "invalid_signature",
    detail: err instanceof Error ? err.message : String(err),
  };
}
