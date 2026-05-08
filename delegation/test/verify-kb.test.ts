import { generateKeyPair, SignJWT, exportJWK } from "jose";
import type { KeyLike } from "jose";
import { verifyKbJwt } from "../src/verify-kb";
import { jwkThumbprint } from "../src/jwk-thumbprint";
import { createHash } from "node:crypto";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function makeKb(opts: {
  holderPriv: KeyLike;
  jws: string;
  aud: string;
  nonce: string;
  iat?: number;
  typ?: string;
  sdHashOverride?: string;
}): Promise<string> {
  const sdHash = opts.sdHashOverride ?? b64url(createHash("sha256").update(`${opts.jws}~`).digest());
  return new SignJWT({ aud: opts.aud, nonce: opts.nonce, sd_hash: sdHash, iat: opts.iat ?? Math.floor(Date.now() / 1000) })
    .setProtectedHeader({ alg: "EdDSA", typ: opts.typ ?? "kb+jwt" })
    .sign(opts.holderPriv);
}

describe("verifyKbJwt", () => {
  const baseClaim = { iss: "i", sub: "s", aud: "a", act: "x", perm: "p", iat: 0, exp: 9999, jti: "j" } as const;

  it("ok on happy path", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const kb = await makeKb({ holderPriv: privateKey, jws: "jws-placeholder", aud: "merch", nonce: "n1" });
    const r = await verifyKbJwt(kb, "jws-placeholder", cnfJwk, {
      audience: "merch", trustedIssuers: async () => null,
      kbNonce: "n1", kbMaxAgeSeconds: 60,
    }, Math.floor(Date.now() / 1000));
    expect(r).toBeNull();
  });

  it("kb_jwt_typ_mismatch", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const kb = await makeKb({ holderPriv: privateKey, jws: "j", aud: "a", nonce: "n", typ: "wrong+jwt" });
    const r = await verifyKbJwt(kb, "j", cnfJwk, { audience: "a", trustedIssuers: async () => null, kbNonce: "n" }, 0);
    expect(r).toBe("kb_jwt_typ_mismatch");
  });

  it("kb_jwt_sd_hash_mismatch", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const kb = await makeKb({ holderPriv: privateKey, jws: "real", aud: "a", nonce: "n", sdHashOverride: "deadbeef" });
    const r = await verifyKbJwt(kb, "real", cnfJwk, { audience: "a", trustedIssuers: async () => null, kbNonce: "n" }, 0);
    expect(r).toBe("kb_jwt_sd_hash_mismatch");
  });

  it("kb_jwt_audience_mismatch", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const kb = await makeKb({ holderPriv: privateKey, jws: "j", aud: "wrong", nonce: "n" });
    const r = await verifyKbJwt(kb, "j", cnfJwk, { audience: "right", trustedIssuers: async () => null, kbNonce: "n" }, 0);
    expect(r).toBe("kb_jwt_audience_mismatch");
  });

  it("kb_jwt_nonce_mismatch", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const kb = await makeKb({ holderPriv: privateKey, jws: "j", aud: "a", nonce: "wrong" });
    const r = await verifyKbJwt(kb, "j", cnfJwk, { audience: "a", trustedIssuers: async () => null, kbNonce: "expected" }, 0);
    expect(r).toBe("kb_jwt_nonce_mismatch");
  });

  it("kb_jwt_invalid_signature when KB-JWT was signed with a key whose pub differs from cnf.jwk (header.kid absent)", async () => {
    // Spec §5.3 step (i): cnf-jwk-derived key cannot verify the signature.
    // Header carries no kid, so step (h) thumbprint check is a no-op and we
    // fall through to (i).
    const { privateKey: signer } = await generateKeyPair("EdDSA");
    const { publicKey: otherPub } = await generateKeyPair("EdDSA");
    const otherJwk = await exportJWK(otherPub);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: otherJwk.x as string };
    const kb = await makeKb({ holderPriv: signer, jws: "j", aud: "a", nonce: "n" });
    const r = await verifyKbJwt(kb, "j", cnfJwk, { audience: "a", trustedIssuers: async () => null, kbNonce: "n" }, 0);
    expect(r).toBe("kb_jwt_invalid_signature");
  });

  it("holder_key_thumbprint_mismatch when KB-JWT header.kid ≠ RFC 7638 thumbprint(cnf.jwk)", async () => {
    // Spec §5.3 step (h): if KB header carries a kid, it MUST equal the cnf
    // thumbprint. Holder signs with the right key (sig would verify) but
    // declares a wrong kid → rejected at step (h) before signature verify.
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const holderJwk = await exportJWK(publicKey);
    const cnfJwk = { kty: "OKP" as const, crv: "Ed25519" as const, x: holderJwk.x as string };
    const sdHash = b64url(createHash("sha256").update("j~").digest());
    const kb = await new SignJWT({ aud: "a", nonce: "n", sd_hash: sdHash, iat: 0 })
      .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt", kid: "not-the-real-thumbprint" })
      .sign(privateKey);
    const r = await verifyKbJwt(kb, "j", cnfJwk, { audience: "a", trustedIssuers: async () => null, kbNonce: "n" }, 0);
    expect(r).toBe("holder_key_thumbprint_mismatch");
  });
});
