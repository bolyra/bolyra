import { SignJWT, generateKeyPair, decodeJwt, decodeProtectedHeader } from "jose";
import { allow } from "../src/allow";
import { present } from "../src/present";
import { createHash } from "node:crypto";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("present() — KB-JWT append", () => {
  it("appends a KB-JWT with correct sd_hash, aud, nonce, iat", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "merchant-x", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });

    const presented = await present(receipt, agentPriv as unknown as CryptoKey, {
      nonce: "n-123",
      audience: "merchant-x",
    });

    const parts = presented.split("~");
    expect(parts.length).toBe(3);
    expect(parts[1]).toBe("");
    const kb = parts[2];
    const hdr = decodeProtectedHeader(kb);
    expect(hdr.alg).toBe("EdDSA");
    expect(hdr.typ).toBe("kb+jwt");
    const claims = decodeJwt(kb) as Record<string, unknown>;
    expect(claims.aud).toBe("merchant-x");
    expect(claims.nonce).toBe("n-123");
    expect(typeof claims.iat).toBe("number");

    const expected = b64url(createHash("sha256").update(`${parts[0]}~`).digest());
    expect(claims.sd_hash).toBe(expected);
  });

  it("throws if the receipt has no cnf", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv } = await generateKeyPair("EdDSA");
    const noCnfJws = await new SignJWT({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "bolyra-delegation+sd-jwt", kid: "k1", _sd_alg: "sha-256" })
      .sign(issPriv);
    const receipt = `${noCnfJws}~`;
    await expect(present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" }))
      .rejects.toThrow(/cnf/i);
  });

  it("throws if receipt was already presented (already has KB-JWT appended)", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { privateKey: agentPriv, publicKey: agentPub } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    const once = await present(receipt, agentPriv as unknown as CryptoKey, { nonce: "n", audience: "a" });
    await expect(present(once, agentPriv as unknown as CryptoKey, { nonce: "n2", audience: "a" }))
      .rejects.toThrow(/already presented/i);
  });

  it("throws on holder-key thumbprint mismatch (wrong agent key)", async () => {
    const { privateKey: issPriv } = await generateKeyPair("EdDSA");
    const { publicKey: agentPub } = await generateKeyPair("EdDSA");
    const { privateKey: wrongPriv } = await generateKeyPair("EdDSA");
    const receipt = await allow({
      iss: "i", sub: "s", aud: "a", act: "x", perm: "p",
      agentPubKey: agentPub as unknown as CryptoKey,
    }, { privateKey: issPriv as unknown as CryptoKey, kid: "k1" });
    await expect(present(receipt, wrongPriv as unknown as CryptoKey, { nonce: "n", audience: "a" }))
      .rejects.toThrow(/thumbprint/i);
  });
});
