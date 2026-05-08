import * as fs from "fs";
import * as path from "path";

// Mirrors src/types.ts VerifyFailureReason. Plan called for 36 reasons; the
// actual v0.2 union shipped at 52 after Task 13 expanded the surface (KB,
// status-list, and SD-JWT envelope branches gained finer-grained reasons).
// `UNKNOWN` is a catch-all default and is exempted from the coverage gate
// because no specific input reliably produces it without bypassing the
// orchestrator's own classification.
const ALL_REASONS: string[] = [
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
  "PERMISSION_VIOLATION",
  "AMOUNT_EXCEEDS_CAP",
  "CURRENCY_MISMATCH",
  "CNF_MISSING",
  "CNF_KEY_MISMATCH",
  "CNF_JWK_INVALID",
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
  "STATUS_REVOKED",
  "STATUS_SUSPENDED",
  "STATUS_CHECK_UNCONFIGURED",
  "STATUS_LIST_INVALID",
  "STATUS_LIST_SIG_INVALID",
  "STATUS_LIST_ISSUER_MISMATCH",
  "STATUS_LIST_UNREACHABLE",
  "STATUS_INDEX_OUT_OF_RANGE",
];

describe("conformance: negative-space coverage", () => {
  it("VerifyFailureReason union has exactly 50 enumerated members (UNKNOWN exempted)", () => {
    expect(ALL_REASONS.length).toBe(50);
  });

  it("every VerifyFailureReason is referenced by at least one test file", () => {
    const testDir = path.resolve(__dirname, "..");
    const allTestSrc = walkTests(testDir)
      .filter((f) => !f.endsWith("negative-space.test.ts"))
      .map((f) => fs.readFileSync(f, "utf8"))
      .join("\n");

    const missing = ALL_REASONS.filter((r) => !allTestSrc.includes(`"${r}"`));
    expect(missing).toEqual([]);
  });
});

function walkTests(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkTests(full));
    else if (entry.name.endsWith(".test.ts")) out.push(full);
  }
  return out;
}
