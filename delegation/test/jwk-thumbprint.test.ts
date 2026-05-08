import { calculateJwkThumbprint, generateKeyPair, exportJWK } from "jose";
import { jwkThumbprint } from "../src/jwk-thumbprint";

describe("jwkThumbprint (RFC 7638)", () => {
  it("matches jose's calculateJwkThumbprint for a fresh Ed25519 key", async () => {
    const { publicKey } = await generateKeyPair("EdDSA");
    const jwk = await exportJWK(publicKey);
    // Oracle: jose's reference implementation.
    const expected = await calculateJwkThumbprint(jwk, "sha256");
    const actual = await jwkThumbprint({
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x as string,
    });
    expect(actual).toBe(expected);
  });

  it("returns a 43-char base64url string with no padding", async () => {
    const tp = await jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "AAAA" });
    expect(tp).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes → 43 chars b64url, no =
  });

  it("is field-order independent (RFC 7638 canonicalization)", async () => {
    const a = await jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "AAAA" });
    const b = await jwkThumbprint({ x: "AAAA", crv: "Ed25519", kty: "OKP" } as never);
    expect(a).toBe(b);
  });

  it("rejects non-OKP/Ed25519 JWKs", async () => {
    await expect(jwkThumbprint({ kty: "RSA" } as unknown as never)).rejects.toThrow();
  });
});
