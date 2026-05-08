import { deflateSync, inflateSync } from "node:zlib";
import { setStatusBit } from "../src/status-list";

const STATUS_VALID = 0x00 as const;
const STATUS_INVALID = 0x01 as const;
const STATUS_SUSPENDED = 0x02 as const;

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}
function buildBitstring(bytes: Uint8Array): string {
  return b64url(deflateSync(Buffer.from(bytes)));
}
function rawBitstring(bs: string): Uint8Array {
  return new Uint8Array(inflateSync(b64urlDecode(bs)));
}

describe("setStatusBit (2-bit slots, zlib RFC 1950)", () => {
  it("flips idx 5 from VALID to INVALID without touching neighbors", () => {
    const initial = buildBitstring(new Uint8Array(8));   // 32 slots, all VALID
    const after = setStatusBit(initial, 5, STATUS_INVALID);
    const raw = rawBitstring(after);
    // idx 5 → byte 1 (5 / 4 = 1), bit-offset 2 ((5 % 4) * 2 = 2)
    // expected byte 1 = (0b01 << 2) = 0b00000100 = 0x04
    expect(raw[1]).toBe(0x04);
    expect(raw[0]).toBe(0x00); // idx 0-3 untouched
    expect(raw[2]).toBe(0x00); // idx 8-11 untouched
  });

  it("clears a slot back to VALID", () => {
    const a = setStatusBit(buildBitstring(new Uint8Array(8)), 3, STATUS_SUSPENDED);
    const b = setStatusBit(a, 3, STATUS_VALID);
    expect(rawBitstring(b)[0]).toBe(0x00);
  });

  it("preserves LE-within-byte ordering: idx 0 = INVALID, idx 1 = SUSPENDED ⇒ byte 0 = 0x09", () => {
    let bs = buildBitstring(new Uint8Array(1));
    bs = setStatusBit(bs, 0, STATUS_INVALID);     // bits 0-1 = 0b01
    bs = setStatusBit(bs, 1, STATUS_SUSPENDED);   // bits 2-3 = 0b10
    // expected byte: (0b01 << 0) | (0b10 << 2) = 0b00001001 = 0x09
    expect(rawBitstring(bs)[0]).toBe(0x09);
  });

  it("rejects out-of-range idx", () => {
    const enc = buildBitstring(new Uint8Array(8));
    expect(() => setStatusBit(enc, 9999, STATUS_INVALID)).toThrow(/out of range/i);
  });

  it("rejects reserved or invalid status (no 0x03 on write)", () => {
    const enc = buildBitstring(new Uint8Array(8));
    // @ts-expect-error 0x03 is reserved per draft; never accepted on write
    expect(() => setStatusBit(enc, 0, 0x03)).toThrow(/reserved|invalid status/i);
  });

  it("decompresses a zlib (RFC 1950) bitstring — gzip would throw here", () => {
    // Hand-built fixture: deflate of [0x00] — known-good zlib byte sequence.
    // If the implementation uses gzip (RFC 1952), inflateSync of its output throws.
    const fixture = b64url(deflateSync(Buffer.from([0x00])));
    const after = setStatusBit(fixture, 0, STATUS_INVALID);
    expect(rawBitstring(after)[0]).toBe(0x01);
  });
});
