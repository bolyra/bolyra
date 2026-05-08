import { generateKeyPair } from "jose";
import { allow } from "../../src/allow";

describe("conformance: SD-JWT (draft-ietf-oauth-selective-disclosure-jwt-20)", () => {
  it("emits header media type bolyra-delegation+sd-jwt and empty _sd disclosures", async () => {
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
    expect(receipt.endsWith("~")).toBe(true);
    expect(receipt.split("~").length).toBe(2);
    const [jws] = receipt.split("~");
    const headerB64 = jws.split(".")[0];
    const header = JSON.parse(Buffer.from(headerB64, "base64").toString("utf8"));
    expect(header.typ).toBe("bolyra-delegation+sd-jwt");
    expect(header.alg).toBe("EdDSA");
    expect(header._sd_alg).toBe("sha-256");
    const payloadB64 = jws.split(".")[1];
    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
    expect(payload._sd).toEqual([]);
  });
});
