import { generateKeyPair } from "jose";
import { allow } from "../src/allow";
import { present } from "../src/present";
import { verify } from "../src/verify";
import { staticIssuerResolver } from "../src/kid-resolver";

describe("verify() — v0.2 orchestrator", () => {
  it("happy path: allow → present → verify ok:true", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "did:web:bolyra.ai", sub: "agent-1", aud: "merchant-x",
      act: "checkout.charge", perm: "FINANCIAL_SMALL",
      max: { amount: 100, currency: "USD" },
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n1", audience: "merchant-x" } as any);

    const r = await verify(presented, {
      audience: "merchant-x",
      action: "checkout.charge",
      perm: "FINANCIAL_SMALL",
      amount: 50, currency: "USD",
      trustedIssuers: staticIssuerResolver({ "did:web:bolyra.ai": { k1: issPub as unknown as CryptoKey } }),
      kbNonce: "n1",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.legacyV01).toBe(false);
      expect(r.claims.act).toBe("checkout.charge");
    }
  });

  it("kb_jwt_missing when receipt has no KB-JWT (issuer-form)", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p", agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const r = await verify(receipt, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k1: issPub as unknown as CryptoKey } }),
      kbNonce: "n",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("KB_MISSING");
  });

  it("unknown_issuer_kid when resolver returns null", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p", agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" } as any);
    const r = await verify(presented, {
      audience: "a",
      trustedIssuers: async () => null,
      kbNonce: "n",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("UNKNOWN_ISSUER_KID");
  });

  it("kid_resolver_error when resolver throws", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p", agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" } as any);
    const r = await verify(presented, {
      audience: "a",
      trustedIssuers: async () => { throw new Error("DNS failure"); },
      kbNonce: "n",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("KID_RESOLVER_ERROR");
  });

  it("status_check_unconfigured when receipt has status but no checker provided", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
      statusList: { uri: "https://issuer.example/status/1", idx: 0 },
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" } as any);
    const r = await verify(presented, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k1: issPub as unknown as CryptoKey } }),
      kbNonce: "n",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("STATUS_CHECK_UNCONFIGURED");
  });
});
