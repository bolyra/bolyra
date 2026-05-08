import { generateKeyPair } from "jose";
import { deflateSync } from "zlib";
import { allow } from "../../src/allow";
import { present } from "../../src/present";
import { verify } from "../../src/verify";
import { publishStatusList, fetchStatusList } from "../../src/status-list";
import { staticIssuerResolver } from "../../src/kid-resolver";
import type { StatusListChecker, IssuerKeyResolver } from "../../src/types";

describe("conformance: status-list issuer binding", () => {
  it("rejects a status-list token signed by the wrong issuer at the expected URI", async () => {
    const issuerA = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const issuerB = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const holder = await generateKeyPair("EdDSA", { crv: "Ed25519" });

    // Receipt expects status list from issuer A
    const receipt = await allow(
      {
        iss: "https://issuer-a.example",
        sub: "did:bolyra:holder",
        aud: "https://merchant.example",
        act: "spend",
        perm: "FINANCIAL_SMALL",
        agentPubKey: holder.publicKey as unknown as CryptoKey,
        ttlSeconds: 3600,
        statusList: { uri: "https://issuer-a.example/status/1", idx: 0 },
      },
      { privateKey: issuerA.privateKey as unknown as CryptoKey, kid: "k1" },
    );

    const presented = await present(receipt, holder.privateKey as unknown as CryptoKey, {
      audience: "https://merchant.example",
      nonce: "n1",
    } as any);

    // Attacker serves a status list at the right URI but signed by issuer B.
    // Status-list payload claims iss = issuer-b.example so fetchStatusList's
    // peek-then-bind step detects the mismatch BEFORE signature verification.
    const bitstring = deflateSync(Buffer.from(new Uint8Array(64))).toString("base64url");
    const wrongIssuerToken = await publishStatusList(
      {
        iss: "https://issuer-b.example",
        sub: "https://issuer-a.example/status/1",
        bits: 2,
        bitstring,
        ttlSeconds: 3600,
      },
      { privateKey: issuerB.privateKey as unknown as CryptoKey, kid: "k1" },
    );

    const verifyKey: IssuerKeyResolver = async (iss, _kid) => {
      if (iss === "https://issuer-a.example") return issuerA.publicKey as unknown as CryptoKey;
      if (iss === "https://issuer-b.example") return issuerB.publicKey as unknown as CryptoKey;
      return null;
    };
    const stubFetch: typeof globalThis.fetch = async (_url) =>
      new Response(wrongIssuerToken, {
        status: 200,
        headers: { "content-type": "application/statuslist+jwt" },
      });
    const checker: StatusListChecker = (uri, idx, expectedIss) =>
      fetchStatusList(uri, idx, expectedIss, { fetch: stubFetch, verifyKey });

    const result = await verify(presented, {
      audience: "https://merchant.example",
      action: "spend",
      perm: "FINANCIAL_SMALL",
      kbNonce: "n1",
      trustedIssuers: staticIssuerResolver({
        "https://issuer-a.example": { k1: issuerA.publicKey as unknown as CryptoKey },
      }),
      checkStatus: checker,
    } as any);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("STATUS_LIST_ISSUER_MISMATCH");
  });
});
