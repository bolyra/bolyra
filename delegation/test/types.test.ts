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
  test("exports the 36 failure reasons", () => {
    const reasons: VerifyFailureReason[] = [
      // v0.1 carry-overs (10)
      "BAD_FORMAT",
      "INVALID_SIGNATURE",
      "EXPIRED",
      "FUTURE_NBF",
      "WRONG_ISSUER",
      "WRONG_AUDIENCE",
      "WRONG_SUBJECT",
      "MISSING_CLAIM",
      "PARENT_NOT_FOUND",
      "DELEGATION_LOOP",
      // SD-JWT specific (6)
      "DISCLOSURE_TAMPERED",
      "DISCLOSURE_HASH_MISMATCH",
      "UNDISCLOSED_CLAIM_REQUIRED",
      "DUPLICATE_DISCLOSURE",
      "MALFORMED_DISCLOSURE",
      "SD_ALG_UNSUPPORTED",
      // cnf binding (2)
      "CNF_MISSING",
      "CNF_KEY_MISMATCH",
      // KB-JWT (11)
      "KB_MISSING",
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
      // status (6)
      "STATUS_REVOKED",
      "STATUS_SUSPENDED",
      "STATUS_FETCH_FAILED",
      "STATUS_LIST_INVALID",
      "STATUS_LIST_SIG_INVALID",
      "STATUS_INDEX_OUT_OF_RANGE",
      // legacy/unknown (1)
      "UNKNOWN",
    ];
    expect(reasons.length).toBe(36);
  });

  test("VerifyResult.ok shape", () => {
    const ok: VerifyResult = { ok: true, claims: {} as ReceiptClaims };
    const bad: VerifyResult = { ok: false, reasons: ["BAD_FORMAT"] };
    expect(ok.ok).toBe(true);
    expect(bad.ok).toBe(false);
  });

  test("AllowOptions has agentPubKey and statusList", () => {
    const _o: AllowOptions = {
      issuerPrivateKey: new Uint8Array(),
      issuerKid: "k1",
      subject: "agent:x",
      audience: "https://rp.example",
      ttlSeconds: 600,
      agentPubKey: { kty: "OKP", crv: "Ed25519", x: "..." },
      statusList: { uri: "https://issuer.example/sl/1", idx: 0 },
    };
    expect(_o.subject).toBe("agent:x");
  });

  test("resolver and checker shapes", () => {
    const resolver: IssuerKeyResolver = async () => ({
      kty: "OKP",
      crv: "Ed25519",
      x: "...",
    });
    const checker: StatusListChecker = async () => ({ ok: true });
    expect(typeof resolver).toBe("function");
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

  test("StatusListResult discriminates", () => {
    const r1: StatusListResult = { ok: true };
    const r2: StatusListResult = { ok: false, reason: "STATUS_REVOKED" };
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
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
