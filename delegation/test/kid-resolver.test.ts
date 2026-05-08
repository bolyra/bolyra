import { generateKeyPair } from "jose";
import { staticIssuerResolver, ResolverError } from "../src/kid-resolver";

describe("staticIssuerResolver", () => {
  test("returns key for known (iss, kid)", async () => {
    const { publicKey } = await generateKeyPair("EdDSA");
    const key = publicKey as unknown as CryptoKey;
    const resolve = staticIssuerResolver({
      "https://issuer.example": { "k1": key },
    });
    const got = await resolve("https://issuer.example", "k1");
    expect(got).toBe(key);
  });

  test("returns null on unknown iss", async () => {
    const { publicKey } = await generateKeyPair("EdDSA");
    const key = publicKey as unknown as CryptoKey;
    const resolve = staticIssuerResolver({
      "https://issuer.example": { "k1": key },
    });
    const got = await resolve("https://other.example", "k1");
    expect(got).toBeNull();
  });

  test("returns null on unknown kid under known iss", async () => {
    const { publicKey } = await generateKeyPair("EdDSA");
    const key = publicKey as unknown as CryptoKey;
    const resolve = staticIssuerResolver({
      "https://issuer.example": { "k1": key },
    });
    const got = await resolve("https://issuer.example", "k2");
    expect(got).toBeNull();
  });

  test("ResolverError is throwable + instanceof-checkable", () => {
    const err = new ResolverError("boom");
    expect(err).toBeInstanceOf(ResolverError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("ResolverError");
    expect(err.message).toBe("boom");
  });

  test("ResolverError preserves cause field", () => {
    const inner = new Error("inner");
    const err = new ResolverError("wrap", inner);
    expect(err.cause).toBe(inner);
  });
});
