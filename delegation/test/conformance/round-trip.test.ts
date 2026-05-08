import { generateKeyPair } from "jose";
import { allow } from "../../src/allow";
import { present } from "../../src/present";
import { verify } from "../../src/verify";
import { staticIssuerResolver } from "../../src/kid-resolver";

describe("conformance: full allow → present → verify happy path", () => {
  it("issues, presents, and verifies a v0.2 receipt end-to-end", async () => {
    const issuer = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const holder = await generateKeyPair("EdDSA", { crv: "Ed25519" });

    const receipt = await allow(
      {
        iss: "https://issuer.example",
        sub: "did:bolyra:holder",
        aud: "https://merchant.example",
        act: "spend",
        perm: "FINANCIAL_SMALL",
        agentPubKey: holder.publicKey as unknown as CryptoKey,
        ttlSeconds: 3600,
        max: { amount: 5000, currency: "USD" },
      },
      { privateKey: issuer.privateKey as unknown as CryptoKey, kid: "k1" },
    );

    const presented = await present(receipt, holder.privateKey as unknown as CryptoKey, {
      audience: "https://merchant.example",
      nonce: "nonce-abc-123",
    } as any);

    expect(presented.split("~").length).toBe(3); // <jws>, "", <kb-jwt>
    expect(presented.split("~")[1]).toBe(""); // empty disclosure slot
    expect(presented.split("~")[2].split(".").length).toBe(3); // KB-JWT

    const result = await verify(presented, {
      audience: "https://merchant.example",
      action: "spend",
      perm: "FINANCIAL_SMALL",
      kbNonce: "nonce-abc-123",
      amount: 1000,
      currency: "USD",
      trustedIssuers: staticIssuerResolver({
        "https://issuer.example": { k1: issuer.publicKey as unknown as CryptoKey },
      }),
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.legacyV01).toBe(false);
      expect(result.claims.iss).toBe("https://issuer.example");
      expect(result.claims.act).toBe("spend");
    }
  });
});
