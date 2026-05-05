import {
  allow,
  verify,
  generateKeyPair,
  PERM,
  validateCumulativeBitEncoding,
  narrows,
} from "../src";

describe("@bolyra/delegation", () => {
  describe("allow + verify", () => {
    it("round-trips a valid receipt", async () => {
      const { privateKey, publicKey } = await generateKeyPair();
      const receipt = await allow(
        {
          agent: "agent_alice",
          action: "purchase",
          audience: "example.com",
          permission: PERM.FINANCIAL_SMALL,
          maxAmount: { amount: 50, currency: "USD" },
        },
        privateKey,
        publicKey,
      );

      const result = await verify(receipt, {
        expectedAgent: "agent_alice",
        expectedAction: "purchase",
        expectedAudience: "example.com",
        trustedIssuers: publicKey,
      });

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.claims.sub).toBe("agent_alice");
        expect(result.claims.act).toBe("purchase");
        expect(result.claims.aud).toBe("example.com");
      }
    });

    it("rejects when audience does not match", async () => {
      const { privateKey, publicKey } = await generateKeyPair();
      const receipt = await allow(
        {
          agent: "agent_alice",
          action: "post",
          audience: "example.com",
          permission: PERM.WRITE_DATA,
        },
        privateKey,
        publicKey,
      );

      const result = await verify(receipt, {
        expectedAgent: "agent_alice",
        expectedAction: "post",
        expectedAudience: "attacker.com",
        trustedIssuers: publicKey,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.reason).toBe("audience_mismatch");
    });

    it("rejects when amount exceeds cap", async () => {
      const { privateKey, publicKey } = await generateKeyPair();
      const receipt = await allow(
        {
          agent: "agent_alice",
          action: "purchase",
          audience: "example.com",
          permission: PERM.FINANCIAL_SMALL,
          maxAmount: { amount: 50, currency: "USD" },
        },
        privateKey,
        publicKey,
      );

      const result = await verify(receipt, {
        expectedAgent: "agent_alice",
        expectedAction: "purchase",
        expectedAudience: "example.com",
        trustedIssuers: publicKey,
        invocationAmount: { amount: 75, currency: "USD" },
      });

      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.reason).toBe("amount_exceeds_cap");
    });

    it("rejects when signed by an untrusted key", async () => {
      const { privateKey } = await generateKeyPair();
      const { publicKey: otherPublicKey } = await generateKeyPair();
      const receipt = await allow(
        {
          agent: "agent_alice",
          action: "read",
          audience: "example.com",
          permission: PERM.READ_DATA,
        },
        privateKey,
        otherPublicKey,
      );

      const result = await verify(receipt, {
        expectedAgent: "agent_alice",
        expectedAction: "read",
        expectedAudience: "example.com",
        trustedIssuers: otherPublicKey,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.reason).toBe("invalid_signature");
    });
  });

  describe("permissions", () => {
    it("rejects FINANCIAL_MEDIUM without FINANCIAL_SMALL", () => {
      expect(validateCumulativeBitEncoding(PERM.FINANCIAL_MEDIUM)).toMatch(
        /FINANCIAL_MEDIUM.*requires FINANCIAL_SMALL/,
      );
    });
    it("accepts FINANCIAL_MEDIUM | FINANCIAL_SMALL", () => {
      expect(
        validateCumulativeBitEncoding(PERM.FINANCIAL_MEDIUM | PERM.FINANCIAL_SMALL),
      ).toBeNull();
    });
    it("narrows() detects subset correctly", () => {
      const wider = PERM.READ_DATA | PERM.WRITE_DATA | PERM.FINANCIAL_SMALL;
      const narrower = PERM.READ_DATA;
      expect(narrows(wider, narrower)).toBe(true);
      expect(narrows(narrower, wider)).toBe(false);
    });
  });
});
