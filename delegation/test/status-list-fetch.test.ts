import { generateKeyPair } from "jose";
import { deflateSync } from "node:zlib";
import {
  fetchStatusList,
  publishStatusList,
  setStatusBit,
  StatusListIssuerMismatchError,
  StatusListSignatureError,
} from "../src/status-list";

// jose's generateKeyPair returns `KeyLike` (`CryptoKey | KeyObject`) which TS
// strict-mode can't assign to a bare `CryptoKey`. Cast at the boundary, as
// other test files in this repo do (see present.test.ts).
const ck = (k: unknown) => k as CryptoKey;

const b64url = (b: Buffer) =>
  b.toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

const empty = () => b64url(Buffer.from(deflateSync(new Uint8Array(8))));

const mockFetch = (jws: string): typeof globalThis.fetch =>
  (async () =>
    new Response(jws, {
      status: 200,
      headers: { "content-type": "application/statuslist+jwt" },
    })) as unknown as typeof globalThis.fetch;

describe("fetchStatusList — direct-call StatusListChecker", () => {
  it("returns invalid for a revoked slot (idx 3 -> 0x01)", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const bs = setStatusBit(empty(), 3, 0x01);
    const jws = await publishStatusList(
      { iss: "did:web:bolyra.ai", sub: "https://x/status/1", bits: 2, ttlSeconds: 60, bitstring: bs },
      { privateKey: ck(privateKey), kid: "sk" },
    );
    const r = await fetchStatusList(
      "https://x/status/1", 3, "did:web:bolyra.ai",
      { fetch: mockFetch(jws), verifyKey: ck(publicKey) },
    );
    expect(r.status).toBe("invalid");
  });

  it("returns suspended for a slot set to 0x02", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const bs = setStatusBit(empty(), 5, 0x02);
    const jws = await publishStatusList(
      { iss: "iss", sub: "https://x/status/2", bits: 2, ttlSeconds: 60, bitstring: bs },
      { privateKey: ck(privateKey), kid: "sk" },
    );
    const r = await fetchStatusList(
      "https://x/status/2", 5, "iss",
      { fetch: mockFetch(jws), verifyKey: ck(publicKey) },
    );
    expect(r.status).toBe("suspended");
  });

  it("maps reserved slot value 0b11 to 'invalid' (fail-closed)", async () => {
    // Hand-build a bitstring with idx 0 = 0b11.
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const raw = new Uint8Array(8);
    raw[0] = 0b00000011;
    const reservedBs = b64url(Buffer.from(deflateSync(raw)));
    const jws = await publishStatusList(
      { iss: "iss", sub: "https://x/status/r", bits: 2, ttlSeconds: 60, bitstring: reservedBs },
      { privateKey: ck(privateKey), kid: "sk" },
    );
    const r = await fetchStatusList(
      "https://x/status/r", 0, "iss",
      { fetch: mockFetch(jws), verifyKey: ck(publicKey) },
    );
    expect(r.status).toBe("invalid");
  });

  it("throws StatusListIssuerMismatchError when token iss != expectedIss", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const jws = await publishStatusList(
      {
        iss: "did:web:other.example", sub: "https://x/status/1",
        bits: 2, ttlSeconds: 60, bitstring: empty(),
      },
      { privateKey: ck(privateKey), kid: "sk" },
    );
    await expect(
      fetchStatusList(
        "https://x/status/1", 0, "did:web:bolyra.ai",
        { fetch: mockFetch(jws), verifyKey: ck(publicKey) },
      ),
    ).rejects.toBeInstanceOf(StatusListIssuerMismatchError);
  });

  it("propagates StatusListSignatureError on bad signature", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    const { publicKey: wrongKey } = await generateKeyPair("EdDSA");
    const jws = await publishStatusList(
      { iss: "iss", sub: "https://x/status/1", bits: 2, ttlSeconds: 60, bitstring: empty() },
      { privateKey: ck(privateKey), kid: "sk" },
    );
    await expect(
      fetchStatusList(
        "https://x/status/1", 0, "iss",
        { fetch: mockFetch(jws), verifyKey: ck(wrongKey) },
      ),
    ).rejects.toBeInstanceOf(StatusListSignatureError);
  });

  it("rejects http:// URIs without issuing any fetch", async () => {
    let called = 0;
    const spy: typeof globalThis.fetch = (async () => {
      called++;
      return new Response("nope", { status: 200 });
    }) as unknown as typeof globalThis.fetch;
    const { publicKey } = await generateKeyPair("EdDSA");
    await expect(
      fetchStatusList(
        "http://x/status/1", 0, "iss",
        { fetch: spy, verifyKey: ck(publicKey) },
      ),
    ).rejects.toThrow(/https/i);
    expect(called).toBe(0);
  });

  it("uses IssuerKeyResolver when verifyKey is a function (called with tokenIss, tokenKid from JWS header)", async () => {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA");
    const bs = setStatusBit(empty(), 1, 0x01);
    const jws = await publishStatusList(
      { iss: "did:web:bolyra.ai", sub: "https://x/status/r", bits: 2, ttlSeconds: 60, bitstring: bs },
      { privateKey: ck(privateKey), kid: "sk-2026-04" },
    );
    const seen: { iss?: string; kid?: string } = {};
    const resolver = async (iss: string, kid: string): Promise<CryptoKey | null> => {
      seen.iss = iss;
      seen.kid = kid;
      return ck(publicKey);
    };
    const r = await fetchStatusList(
      "https://x/status/r", 1, "did:web:bolyra.ai",
      { fetch: mockFetch(jws), verifyKey: resolver },
    );
    expect(r.status).toBe("invalid");
    expect(seen.iss).toBe("did:web:bolyra.ai");
    expect(seen.kid).toBe("sk-2026-04");
  });
});
