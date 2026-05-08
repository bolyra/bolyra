import { generateKeyPair, SignJWT } from "jose";
import { verify } from "../../src/verify";
import { staticIssuerResolver } from "../../src/kid-resolver";

describe("conformance: v0.1 back-compat", () => {
  it("verifies a v0.1 plain-JWS receipt when acceptLegacyV01 is true", async () => {
    const issuer = await generateKeyPair("EdDSA", { crv: "Ed25519" });

    const v01Receipt = await new SignJWT({
      iss: "https://issuer.example",
      sub: "did:bolyra:holder",
      aud: "https://merchant.example",
      act: "spend",
      perm: 0x04, // FINANCIAL_SMALL bit (v0.1 numeric cumulative-bit encoding)
      max: { amount: 5000, currency: "USD" },
    })
      .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(issuer.privateKey);

    const result = await verify(v01Receipt, {
      audience: "https://merchant.example",
      action: "spend",
      perm: "FINANCIAL_SMALL",
      amount: 1000,
      currency: "USD",
      acceptLegacyV01: true,
      trustedIssuers: staticIssuerResolver({
        "https://issuer.example": { k1: issuer.publicKey as unknown as CryptoKey },
      }),
    });

    expect(result.ok).toBe(true);
    if (result.ok) expect(result.legacyV01).toBe(true);
  });

  it("rejects v0.1 receipts when acceptLegacyV01 is false (default)", async () => {
    const issuer = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const v01Receipt = await new SignJWT({
      iss: "x",
      aud: "y",
      act: "spend",
      perm: 0x01, // READ_DATA bit (v0.1 numeric cumulative-bit encoding)
    })
      .setProtectedHeader({ alg: "EdDSA", kid: "k1" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(issuer.privateKey);

    const result = await verify(v01Receipt, {
      audience: "y",
      action: "spend",
      perm: "READ_DATA",
      trustedIssuers: staticIssuerResolver({
        x: { k1: issuer.publicKey as unknown as CryptoKey },
      }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("LEGACY_V01_REJECTED");
  });
});
