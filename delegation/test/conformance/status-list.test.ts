import { generateKeyPair } from "jose";
import { deflateSync, inflateSync } from "zlib";
import { setStatusBit, publishStatusList } from "../../src/status-list";

// Helper: build the canonical base64url(zlib-deflate(raw-bytes)) bitstring
// directly here so the conformance vector exercises only the public surface.
function encodeRaw(raw: Uint8Array): string {
  return deflateSync(Buffer.from(raw)).toString("base64url");
}
function decodeRaw(b64u: string): Uint8Array {
  return new Uint8Array(inflateSync(Buffer.from(b64u, "base64url")));
}

describe("conformance: status-list (draft-ietf-oauth-status-list-20)", () => {
  it("encodes 2-bit slots, zlib-compressed, base64url", () => {
    const empty = encodeRaw(new Uint8Array(64));
    let lst = setStatusBit(empty, 0, 0x01); // INVALID
    lst = setStatusBit(lst, 5, 0x02);       // SUSPENDED
    lst = setStatusBit(lst, 17, 0x01);      // INVALID

    // Round-trip through zlib-decode and inspect raw bytes per draft-20 LE-within-byte layout.
    const raw = decodeRaw(lst);
    // slot 0 → byte 0, bits 0-1: INVALID = 0b01
    expect(raw[0] & 0b11).toBe(0x01);
    // slot 1 → byte 0, bits 2-3: VALID = 0b00 (untouched)
    expect((raw[0] >> 2) & 0b11).toBe(0x00);
    // slot 5 → byte 1, bits 2-3: SUSPENDED = 0b10
    expect((raw[1] >> 2) & 0b11).toBe(0x02);
    // slot 17 → byte 4, bits 2-3: INVALID = 0b01
    expect((raw[4] >> 2) & 0b11).toBe(0x01);
    // slot 100 → byte 25 (untouched in our 64-byte fixture): VALID
    expect((raw[25] >> 0) & 0b11).toBe(0x00);
  });

  it("status-list token has typ statuslist+jwt and status_list claim with bits=2", async () => {
    const issuer = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const lst = encodeRaw(new Uint8Array(64));
    const token = await publishStatusList(
      {
        iss: "https://issuer.example",
        sub: "https://issuer.example/status/1",
        bits: 2,
        bitstring: lst,
        ttlSeconds: 3600,
      },
      { privateKey: issuer.privateKey as unknown as CryptoKey, kid: "k1" },
    );

    const [headerB64, payloadB64] = token.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64").toString("utf8"));
    expect(header.typ).toBe("statuslist+jwt");
    expect(header.alg).toBe("EdDSA");
    expect(header.kid).toBe("k1");

    const payload = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
    expect(payload.iss).toBe("https://issuer.example");
    expect(payload.status_list.bits).toBe(2);
    expect(typeof payload.status_list.lst).toBe("string");
  });
});
