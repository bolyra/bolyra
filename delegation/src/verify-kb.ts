import { compactVerify, importJWK, decodeProtectedHeader } from "jose";
import type { VerifyOptions } from "./types";
import { jwkThumbprint } from "./jwk-thumbprint";
import { createHash } from "node:crypto";

interface CnfJwk { kty: "OKP"; crv: "Ed25519"; x: string; }

/**
 * KB-JWT-specific failure reasons (lowercase). These are the internal contract
 * with the Task 13 orchestrator (verify.ts), which translates them into the
 * canonical UPPER_SNAKE_CASE `VerifyFailureReason` union when assembling its
 * result. Keeping the lowercase strings stable here lets the orchestrator's
 * translation table stay a single source of truth — same pattern as
 * `VerifyFailureReasonV01` produced by `checkIssuerClaims` in verify-claims.ts.
 */
export type KbFailureReason =
  | "kb_jwt_malformed"
  | "kb_jwt_typ_mismatch"
  | "unsupported_alg"
  | "cnf_jwk_invalid"
  | "holder_key_thumbprint_mismatch"
  | "kb_jwt_invalid_signature"
  | "kb_jwt_audience_mismatch"
  | "kb_jwt_nonce_mismatch"
  | "kb_jwt_sd_hash_mismatch"
  | "kb_jwt_iat_in_future"
  | "kb_jwt_expired";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Returns null on pass, or a KbFailureReason.
 *
 * Step lettering follows spec §5.3:
 *   (g) typ FIRST, then alg
 *   (h) RFC 7638 thumbprint compare — only fires when KB header carries a kid
 *       that disagrees with thumbprint(cnf.jwk). cnf.jwk is the canonical key.
 *   (i) signature verify with cnf-jwk-derived key
 */
export async function verifyKbJwt(
  kbJwt: string,
  issuerJws: string,
  cnfJwk: CnfJwk,
  opts: VerifyOptions,
  now: number,
): Promise<KbFailureReason | null> {
  let hdr: Record<string, unknown>;
  try { hdr = decodeProtectedHeader(kbJwt) as Record<string, unknown>; }
  catch { return "kb_jwt_malformed"; }

  // (g) typ FIRST, then alg.
  if (hdr.typ !== "kb+jwt") return "kb_jwt_typ_mismatch";
  if (hdr.alg !== "EdDSA") return "unsupported_alg";

  // Import cnf.jwk — canonical signing key per §3.3.
  let key: CryptoKey;
  try { key = (await importJWK(cnfJwk, "EdDSA")) as CryptoKey; }
  catch { return "cnf_jwk_invalid"; }

  // (h) Thumbprint compare. Only meaningful when the KB header advertises a kid.
  // jose does not surface a kid mismatch on its own; we enforce it here so the
  // failure reason matches the spec's decision tree rather than leaking through
  // as a generic signature error in (i).
  const cnfThumbprint = await jwkThumbprint(cnfJwk);
  if (typeof hdr.kid === "string" && hdr.kid.length > 0 && hdr.kid !== cnfThumbprint) {
    return "holder_key_thumbprint_mismatch";
  }

  // (i) Signature verify via compactVerify (Chunk 4 convention — typ already
  // asserted manually above so we don't depend on jwtVerify({typ}) semantics).
  let payloadBytes: Uint8Array;
  try {
    const v = await compactVerify(kbJwt, key);
    payloadBytes = v.payload;
  } catch {
    return "kb_jwt_invalid_signature";
  }

  let payload: Record<string, unknown>;
  try { payload = JSON.parse(Buffer.from(payloadBytes).toString("utf8")); }
  catch { return "kb_jwt_malformed"; }

  if (payload.aud !== opts.audience) return "kb_jwt_audience_mismatch";
  // kbNonce-undefined is caught upstream in verify.ts (spec §5.3 step (f) →
  // kb_nonce_required). By the time we get here, opts.kbNonce is defined.
  if (payload.nonce !== opts.kbNonce) return "kb_jwt_nonce_mismatch";

  const expectedHash = b64url(createHash("sha256").update(`${issuerJws}~`).digest());
  if (payload.sd_hash !== expectedHash) return "kb_jwt_sd_hash_mismatch";

  if (typeof payload.iat !== "number") return "kb_jwt_malformed";
  const maxAge = opts.kbMaxAgeSeconds ?? 60;  // spec §5.3 default
  const skew = opts.clockSkewSeconds ?? 30;
  if ((payload.iat as number) - skew > now) return "kb_jwt_iat_in_future";
  if (now - (payload.iat as number) > maxAge + skew) return "kb_jwt_expired";

  return null;
}
