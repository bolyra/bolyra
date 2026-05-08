import { checkIssuerClaims } from "../src/verify-claims";
import type { ReceiptClaims, VerifyOptions } from "../src/types";

const baseOpts: VerifyOptions = {
  audience: "merchant-x",
  trustedIssuers: async () => null, // unused here
};

const baseClaims = (over: Partial<ReceiptClaims> = {}): ReceiptClaims => ({
  iss: "i", sub: "s", aud: "merchant-x", act: "x", perm: "FINANCIAL_SMALL",
  iat: 1000, exp: 9999, jti: "j", ...over,
});

describe("checkIssuerClaims", () => {
  const NOW = 5000;

  it("ok when all match", () => {
    expect(checkIssuerClaims(baseClaims(), baseOpts, NOW)).toBeNull();
  });

  it("expired", () => {
    expect(checkIssuerClaims(baseClaims({ exp: 4000 }), baseOpts, NOW)).toBe("expired");
  });

  it("not_yet_valid", () => {
    expect(checkIssuerClaims(baseClaims({ iat: 6000 }), baseOpts, NOW)).toBe("not_yet_valid");
  });

  it("audience_mismatch", () => {
    expect(checkIssuerClaims(baseClaims(), { ...baseOpts, audience: "other" }, NOW)).toBe("audience_mismatch");
  });

  it("agent_mismatch via expectedSubject", () => {
    const r = checkIssuerClaims(baseClaims({ sub: "a" }), { ...baseOpts, expectedSubject: "b" }, NOW);
    expect(r).toBe("agent_mismatch");
  });

  it("action_mismatch", () => {
    const r = checkIssuerClaims(baseClaims({ act: "x" }), { ...baseOpts, action: "y" }, NOW);
    expect(r).toBe("action_mismatch");
  });

  it("permission_violation when required perm not implied by claim", () => {
    const r = checkIssuerClaims(
      baseClaims({ perm: "READ_DATA" }),
      { ...baseOpts, perm: "FINANCIAL_UNLIMITED" },
      NOW,
    );
    expect(r).toBe("permission_violation");
  });

  it("amount_exceeds_cap", () => {
    const r = checkIssuerClaims(
      baseClaims({ max: { amount: 100, currency: "USD" } }),
      { ...baseOpts, amount: 200, currency: "USD" },
      NOW,
    );
    expect(r).toBe("amount_exceeds_cap");
  });

  it("currency_mismatch", () => {
    const r = checkIssuerClaims(
      baseClaims({ max: { amount: 100, currency: "USD" } }),
      { ...baseOpts, amount: 50, currency: "EUR" },
      NOW,
    );
    expect(r).toBe("currency_mismatch");
  });
});
