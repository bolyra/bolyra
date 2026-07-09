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
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n1", audience: "merchant-x" });

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
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" });
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
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" });
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
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" });
    const r = await verify(presented, {
      audience: "a",
      trustedIssuers: staticIssuerResolver({ i: { k1: issPub as unknown as CryptoKey } }),
      kbNonce: "n",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("STATUS_CHECK_UNCONFIGURED");
  });

  it("expired receipt reports EXPIRED, not INVALID_SIGNATURE (F2, shipped in 0.2.2)", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "did:web:bolyra.ai", sub: "agent-1", aud: "merchant-x",
      act: "checkout.charge", perm: "FINANCIAL_SMALL",
      agentPubKey: agentPub as unknown as CryptoKey,
      ttlSeconds: -3600,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n1", audience: "merchant-x" });

    const r = await verify(presented, {
      audience: "merchant-x",
      trustedIssuers: staticIssuerResolver({ "did:web:bolyra.ai": { k1: issPub as unknown as CryptoKey } }),
      kbNonce: "n1",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("EXPIRED");
  });

  it("receipt crossing expiry during a slow issuer resolver reports EXPIRED, not INVALID_SIGNATURE", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");

    const baseMs = Math.floor(Date.now() / 1000) * 1000;
    jest.useFakeTimers({ now: baseMs });
    try {
      // exp = now - 29; with 30s skew the receipt is still (barely) valid
      // at the pre-check, and expires 1s later.
      const receipt = await allow({
        iss: "did:web:bolyra.ai", sub: "agent-1", aud: "merchant-x",
        act: "checkout.charge", perm: "FINANCIAL_SMALL",
        agentPubKey: agentPub as unknown as CryptoKey,
        ttlSeconds: -29,
      }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
      const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n1", audience: "merchant-x" });

      // Slow resolver: the clock crosses the expiry boundary while the
      // issuer key lookup is in flight (e.g. a network DID/JWKS fetch).
      const slowResolver = async (iss: string, kid: string) => {
        jest.setSystemTime(baseMs + 5000);
        return iss === "did:web:bolyra.ai" && kid === "k1"
          ? (issPub as unknown as CryptoKey)
          : null;
      };

      const r = await verify(presented, {
        audience: "merchant-x",
        trustedIssuers: slowResolver,
        kbNonce: "n1",
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe("EXPIRED");
    } finally {
      jest.useRealTimers();
    }
  });

  it("receipt expiring exactly on the skew boundary reports EXPIRED (F2 boundary)", async () => {
    const { privateKey: issPriv, publicKey: issPub } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");

    // Freeze the clock on a whole second so exp + skew === now exactly:
    // ttlSeconds -30 gives exp = now - 30, and the default skew is 30s.
    jest.useFakeTimers({ now: Math.floor(Date.now() / 1000) * 1000 });
    try {
      const receipt = await allow({
        iss: "did:web:bolyra.ai", sub: "agent-1", aud: "merchant-x",
        act: "checkout.charge", perm: "FINANCIAL_SMALL",
        agentPubKey: agentPub as unknown as CryptoKey,
        ttlSeconds: -30,
      }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
      const presented = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n1", audience: "merchant-x" });

      const r = await verify(presented, {
        audience: "merchant-x",
        trustedIssuers: staticIssuerResolver({ "did:web:bolyra.ai": { k1: issPub as unknown as CryptoKey } }),
        kbNonce: "n1",
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe("EXPIRED");
    } finally {
      jest.useRealTimers();
    }
  });
});
