import { deflateSync } from "node:zlib";
import { generateKeyPair, decodeProtectedHeader, decodeJwt } from "jose";
import {
  publishStatusList,
  readStatusListPayload,
  StatusListSignatureError,
  setStatusBit,
} from "../src/status-list";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Pre-allocated 2-byte (8-slot) all-VALID bitstring. Status lists are
// fixed-capacity per IETF draft-ietf-oauth-status-list-20 §6 — issuers
// allocate the slot count up front; setStatusBit only mutates existing slots.
function freshBitstring(byteLen: number): string {
  return b64url(deflateSync(Buffer.alloc(byteLen)));
}

describe("publishStatusList / readStatusListPayload", () => {
  it("round-trips iss, exp, ttl, and the bitstring", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    let bs = freshBitstring(2);
    bs = setStatusBit(bs, 0, 0x01);
    bs = setStatusBit(bs, 7, 0x02);

    const jws = await publishStatusList(
      {
        iss: "https://issuer.example",
        sub: "https://issuer.example/status/1",
        bits: 2,
        bitstring: bs,
        ttlSeconds: 60,
      },
      { privateKey: privateKey as unknown as CryptoKey, kid: "k-status-1" },
    );

    const hdr = decodeProtectedHeader(jws);
    expect(hdr.alg).toBe("EdDSA");
    expect(hdr.typ).toBe("statuslist+jwt");
    expect(hdr.kid).toBe("k-status-1");

    const claims = decodeJwt(jws) as Record<string, unknown>;
    expect(claims.iss).toBe("https://issuer.example");
    expect(claims.sub).toBe("https://issuer.example/status/1");
    expect(claims.ttl).toBe(60);
    expect((claims.status_list as Record<string, unknown>).bits).toBe(2);
    expect((claims.status_list as Record<string, unknown>).lst).toBe(bs);

    const payload = await readStatusListPayload(jws, publicKey as unknown as CryptoKey);
    expect(payload.iss).toBe("https://issuer.example");
    expect(payload.bitstring).toBe(bs);
    expect(payload.ttl).toBe(60);
    expect(typeof payload.exp).toBe("number");
  });

  it("omits ttl when not provided and defaults exp to ~1 year", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const jws = await publishStatusList(
      {
        iss: "i", sub: "s", bits: 2, bitstring: "",
      },
      { privateKey: privateKey as unknown as CryptoKey, kid: "k" },
    );
    const claims = decodeJwt(jws) as Record<string, unknown>;
    expect(claims.ttl).toBeUndefined();
    const payload = await readStatusListPayload(jws, publicKey as unknown as CryptoKey);
    expect(payload.ttl).toBeUndefined();
    const now = Math.floor(Date.now() / 1000);
    expect(payload.exp).toBeGreaterThan(now + 360 * 24 * 60 * 60);
  });

  it("throws StatusListSignatureError on tampered signature", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    const { publicKey: otherPub } = await generateKeyPair("EdDSA");
    const jws = await publishStatusList(
      { iss: "i", sub: "s", bits: 2, bitstring: "" },
      { privateKey: privateKey as unknown as CryptoKey, kid: "k" },
    );
    await expect(
      readStatusListPayload(jws, otherPub as unknown as CryptoKey),
    ).rejects.toBeInstanceOf(StatusListSignatureError);
  });

  it("throws StatusListSignatureError when typ is wrong", async () => {
    const { SignJWT, generateKeyPair: gk } = await import("jose");
    const { privateKey, publicKey } = await gk("EdDSA");
    const jws = await new SignJWT({
      iss: "i", sub: "s",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60,
      status_list: { bits: 2, lst: "" },
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "JWT", kid: "k" })
      .sign(privateKey);
    await expect(
      readStatusListPayload(jws, publicKey as unknown as CryptoKey),
    ).rejects.toBeInstanceOf(StatusListSignatureError);
  });
});
