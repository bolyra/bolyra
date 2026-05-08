import { generateKeyPair, exportJWK, decodeJwt, decodeProtectedHeader } from "jose";
import { allow } from "../src/allow";

describe("allow() — SD-JWT issuance", () => {
  it("mints a receipt ending in '~' with cnf, status, and tight iat/exp", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    const before = Math.floor(Date.now() / 1000);
    const receipt = await allow({
      iss: "did:web:bolyra.ai",
      sub: "agent-7",
      aud: "merchant-x",
      act: "checkout.charge",
      perm: "FINANCIAL_SMALL",
      max: { amount: 100, currency: "USD" },
      ttlSeconds: 60,
      jti: "j-1",
      agentPubKey: agentPub as unknown as CryptoKey,
      statusList: { uri: "https://issuer.example/status/1", idx: 42 },
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });

    expect(receipt.endsWith("~")).toBe(true);
    const jws = receipt.slice(0, -1);
    const hdr = decodeProtectedHeader(jws);
    expect(hdr.alg).toBe("EdDSA");
    expect(hdr.typ).toBe("bolyra-delegation+sd-jwt");
    expect(hdr.kid).toBe("k1");
    expect((hdr as Record<string, unknown>)._sd_alg).toBe("sha-256");

    const claims = decodeJwt(jws) as Record<string, unknown>;
    expect(claims.iss).toBe("did:web:bolyra.ai");
    expect(claims.jti).toBe("j-1");

    const cnfJwk = (claims.cnf as Record<string, unknown>).jwk as Record<string, unknown>;
    expect(Object.keys(cnfJwk).sort()).toEqual(["crv", "kty", "x"]);
    expect(cnfJwk.kty).toBe("OKP");
    expect(cnfJwk.crv).toBe("Ed25519");
    expect(typeof cnfJwk.x).toBe("string");

    expect(((claims.status as Record<string, unknown>).status_list as Record<string, unknown>).idx).toBe(42);
    expect(claims._sd).toEqual([]);

    const iat = claims.iat as number;
    const exp = claims.exp as number;
    expect(iat).toBeGreaterThanOrEqual(before);
    expect(iat).toBeLessThanOrEqual(before + 5);
    expect(exp).toBe(iat + 60);
  });

  it("defaults ttlSeconds to 300 and jti to a UUID v4", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k" });
    const claims = decodeJwt(receipt.slice(0, -1)) as Record<string, unknown>;
    const iat = claims.iat as number;
    expect(claims.exp).toBe(iat + 300);
    expect(claims.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("accepts agentPubKey as a JWK-as-JSON string", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    const jwk = await exportJWK(agentPub);
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: JSON.stringify(jwk),
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k" });
    const claims = decodeJwt(receipt.slice(0, -1)) as Record<string, unknown>;
    const cnfJwk = (claims.cnf as Record<string, unknown>).jwk as Record<string, unknown>;
    expect(cnfJwk.x).toBe(jwk.x);
  });

  it("throws 'agentPubKey missing' on undefined", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: undefined as unknown as CryptoKey,
    }, { privateKey: privateKey as unknown as CryptoKey, kid: "k" })).rejects.toThrow(/agentPubKey missing/);
  });

  it("throws 'agentPubKey unparseable' on non-JSON string", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: "not-json",
    }, { privateKey: privateKey as unknown as CryptoKey, kid: "k" })).rejects.toThrow(/agentPubKey unparseable/);
  });

  it("throws on non-Ed25519 cnf (e.g. RSA)", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: rsaPub } = await generateKeyPair("RS256");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: rsaPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k" })).rejects.toThrow(/Ed25519/);
  });

  it("throws on non-https status URI (http://)", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
      statusList: { uri: "http://insecure.example", idx: 0 },
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k" })).rejects.toThrow(/https/);
  });

  it("throws on bare-host status URI (no scheme)", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
      statusList: { uri: "issuer.example/status/1", idx: 0 },
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k" })).rejects.toThrow(/https/);
  });

  it("throws on empty kid", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    await expect(allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "" })).rejects.toThrow(/kid empty/);
  });
});
