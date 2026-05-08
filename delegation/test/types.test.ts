import type {
  AllowOptions,
  PresentOptions,
  IssuerKeyResolver,
  StatusListChecker,
  StatusListResult,
  VerifyOptions,
  VerifyResult,
  VerifyFailureReason,
  ReceiptClaims,
} from "../src/types";

describe("v0.2 types surface", () => {
  test("exports the canonical failure reasons", () => {
    // Task 13 extended the union additively with the orchestrator's surface
    // reasons (KID_MISSING, UNKNOWN_ISSUER_KID, KID_RESOLVER_ERROR,
    // STATUS_CHECK_UNCONFIGURED, STATUS_LIST_ISSUER_MISMATCH,
    // STATUS_LIST_UNREACHABLE, LEGACY_V01_REJECTED, SD_JWT_MALFORMED,
    // UNSUPPORTED_ALG, TYP_MISMATCH, KB_NONCE_REQUIRED, CNF_JWK_INVALID,
    // PERMISSION_VIOLATION, AMOUNT_EXCEEDS_CAP, CURRENCY_MISMATCH,
    // WRONG_ACTION). Original 36 → 52 after Task 13.
    const reasons: VerifyFailureReason[] = [
      // v0.1 carry-overs + Task 13 v0.1-bridge translations
      "BAD_FORMAT",
      "INVALID_SIGNATURE",
      "EXPIRED",
      "FUTURE_NBF",
      "WRONG_ISSUER",
      "WRONG_AUDIENCE",
      "WRONG_SUBJECT",
      "WRONG_ACTION",
      "MISSING_CLAIM",
      "PARENT_NOT_FOUND",
      "DELEGATION_LOOP",
      "PERMISSION_VIOLATION",
      "AMOUNT_EXCEEDS_CAP",
      "CURRENCY_MISMATCH",
      // SD-JWT specific
      "DISCLOSURE_TAMPERED",
      "DISCLOSURE_HASH_MISMATCH",
      "UNDISCLOSED_CLAIM_REQUIRED",
      "DUPLICATE_DISCLOSURE",
      "MALFORMED_DISCLOSURE",
      "SD_ALG_UNSUPPORTED",
      "SD_JWT_MALFORMED",
      "UNSUPPORTED_ALG",
      "TYP_MISMATCH",
      "KID_MISSING",
      "KID_RESOLVER_ERROR",
      "UNKNOWN_ISSUER_KID",
      "LEGACY_V01_REJECTED",
      // cnf binding
      "CNF_MISSING",
      "CNF_KEY_MISMATCH",
      "CNF_JWK_INVALID",
      // KB-JWT
      "KB_MISSING",
      "KB_NONCE_REQUIRED",
      "KB_BAD_FORMAT",
      "KB_INVALID_SIGNATURE",
      "KB_WRONG_NONCE",
      "KB_WRONG_AUDIENCE",
      "KB_WRONG_SD_HASH",
      "KB_TYP_INVALID",
      "KB_ALG_UNSUPPORTED",
      "KB_IAT_FUTURE",
      "KB_IAT_TOO_OLD",
      "KB_BINDING_MISMATCH",
      // status
      "STATUS_REVOKED",
      "STATUS_SUSPENDED",
      "STATUS_CHECK_UNCONFIGURED",
      "STATUS_FETCH_FAILED",
      "STATUS_LIST_INVALID",
      "STATUS_LIST_SIG_INVALID",
      "STATUS_LIST_ISSUER_MISMATCH",
      "STATUS_LIST_UNREACHABLE",
      "STATUS_INDEX_OUT_OF_RANGE",
      // legacy/unknown
      "UNKNOWN",
    ];
    expect(reasons.length).toBe(52);
  });

  test("VerifyResult.ok shape", () => {
    // Task 13: VerifyResult ok-branch now carries a legacyV01 flag and the
    // err-branch reports a single canonical UPPER_SNAKE_CASE reason (singular).
    const ok: VerifyResult = { ok: true, claims: {} as ReceiptClaims, legacyV01: false };
    const bad: VerifyResult = { ok: false, reason: "BAD_FORMAT" };
    expect(ok.ok).toBe(true);
    expect(bad.ok).toBe(false);
  });

  test("AllowOptions has agentPubKey and statusList", () => {
    const _o: AllowOptions = {
      iss: "https://issuer.example",
      sub: "agent:x",
      aud: "https://rp.example",
      act: "checkout.charge",
      perm: "FINANCIAL_SMALL",
      ttlSeconds: 600,
      agentPubKey: JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "..." }),
      statusList: { uri: "https://issuer.example/sl/1", idx: 0 },
    };
    expect(_o.sub).toBe("agent:x");
  });

  test("resolver and checker shapes", () => {
    const r: IssuerKeyResolver = async (_iss, _kid) => null;
    const checker: StatusListChecker = async () => ({ status: "valid", fetchedAt: 0 });
    expect(typeof r).toBe("function");
    expect(typeof checker).toBe("function");
  });

  test("PresentOptions has nonce + audience", () => {
    const _p: PresentOptions = {
      sdJwt: "...",
      holderPrivateKey: new Uint8Array(),
      nonce: "n",
      audience: "https://rp.example",
    };
    expect(_p.nonce).toBe("n");
  });

  test("StatusListResult shape (status + fetchedAt)", () => {
    const r1: StatusListResult = { status: "valid", fetchedAt: 1 };
    const r2: StatusListResult = { status: "invalid", fetchedAt: 2 };
    const r3: StatusListResult = { status: "suspended", fetchedAt: 3 };
    expect(r1.status).toBe("valid");
    expect(r2.status).toBe("invalid");
    expect(r3.status).toBe("suspended");
  });

  test("ReceiptClaims accepts cnf and status fields", () => {
    const c: ReceiptClaims = {
      iss: "https://issuer.example",
      sub: "agent:x",
      aud: "https://rp.example",
      iat: 1,
      exp: 2,
      jti: "j",
      cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: "..." } },
      status: { status_list: { uri: "https://issuer.example/sl/1", idx: 0 } },
    };
    expect(c.cnf?.jwk.x).toBe("...");
    expect(c.status?.status_list.idx).toBe(0);
  });
});
