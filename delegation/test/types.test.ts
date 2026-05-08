import type {
  VerifyFailureReason,
  VerifyOptions,
  VerifyResult,
  AllowOptions,
  PresentOptions,
  IssuerKeyResolver,
  StatusListChecker,
  StatusListResult,
  ReceiptClaims,
} from "../src/types";

describe("types v0.2 surface", () => {
  it("exports the 36 failure reasons", () => {
    const reasons: VerifyFailureReason[] = [
      "invalid_signature","expired","not_yet_valid","audience_mismatch",
      "agent_mismatch","action_mismatch","permission_violation",
      "amount_exceeds_cap","currency_mismatch","malformed",
      "sd_jwt_malformed","kid_missing","kid_resolver_error",
      "unknown_issuer_kid","unsupported_alg","typ_mismatch",
      "cnf_missing","cnf_jwk_invalid",
      "kb_nonce_required","kb_jwt_missing","kb_jwt_malformed",
      "kb_jwt_invalid_signature","kb_jwt_typ_mismatch",
      "kb_jwt_audience_mismatch","kb_jwt_nonce_mismatch",
      "kb_jwt_sd_hash_mismatch","kb_jwt_expired","kb_jwt_iat_in_future",
      "holder_key_thumbprint_mismatch",
      "status_check_unconfigured","status_list_unreachable",
      "status_list_signature_invalid","status_list_issuer_mismatch",
      "status_revoked","status_suspended",
      "legacy_v01_rejected",
    ];
    expect(reasons.length).toBe(36); // 10 v0.1 + 6 SD-JWT + 2 cnf + 11 KB-JWT + 6 status + 1 legacy
  });

  it("VerifyResult.ok shape", () => {
    const ok: VerifyResult = { ok: true, claims: {} as ReceiptClaims, legacyV01: false };
    const bad: VerifyResult = { ok: false, reason: "expired" };
    expect(ok.ok).toBe(true);
    expect(bad.ok).toBe(false);
  });

  it("AllowOptions has agentPubKey and statusList", () => {
    const o: AllowOptions = {
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: {} as CryptoKey,
      statusList: { uri: "https://x", idx: 0 },
    };
    expect(o.iss).toBe("i");
  });

  it("resolver and checker shapes", () => {
    const r: IssuerKeyResolver = async (_iss, _kid) => null;
    const c: StatusListChecker = async (_u, _i, _e) =>
      ({ status: "valid", fetchedAt: Date.now() });
    expect(typeof r).toBe("function");
    expect(typeof c).toBe("function");
  });

  it("PresentOptions has nonce + audience", () => {
    const p: PresentOptions = { nonce: "n", audience: "a" };
    expect(p.nonce).toBe("n");
  });

  it("StatusListResult discriminates", () => {
    const r: StatusListResult = { status: "suspended", fetchedAt: Date.now() };
    expect(r.status).toBe("suspended");
  });

  it("ReceiptClaims accepts cnf and status fields", () => {
    const c: ReceiptClaims = {
      iss: "i", sub: "s", aud: "a", iat: 0, exp: 1, jti: "j",
      act: "x", perm: "p" as never,
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "AAAA" } },
      status: { status_list: { uri: "https://x", idx: 0 } },
    };
    expect(c.cnf?.jwk.crv).toBe("Ed25519");
  });
});
