import { deflateSync, inflateSync } from "node:zlib";

// Internal helpers — module-private. Public surface from spec §5.4 is
// setStatusBit, readStatusListPayload, publishStatusList, fetchStatusList only.
function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s: string): Buffer {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}
function decodeBitstring(encoded: string): Uint8Array {
  return new Uint8Array(inflateSync(b64urlDecode(encoded)));
}
function encodeBitstring(raw: Uint8Array): string {
  return b64url(deflateSync(Buffer.from(raw)));
}

export function setStatusBit(
  bitstring: string,
  idx: number,
  status: 0x00 | 0x01 | 0x02,
): string {
  if (status !== 0x00 && status !== 0x01 && status !== 0x02) {
    throw new Error(`setStatusBit: reserved or invalid status: 0x${(status as number).toString(16)}`);
  }
  const raw = decodeBitstring(bitstring);
  const byteIdx = Math.floor(idx / 4);
  if (byteIdx >= raw.length) {
    throw new Error(`setStatusBit: idx out of range: ${idx}`);
  }
  const shift = (idx % 4) * 2;
  const mask = ~(0b11 << shift) & 0xff;
  raw[byteIdx] = (raw[byteIdx] & mask) | (status << shift);
  return encodeBitstring(raw);
}

// Read side — internal, used by fetchStatusList (Task 10). Reserved code 0b11
// maps to "invalid" (fail-closed on unknown status, per spec §4.5).
export type SlotStatus = "valid" | "invalid" | "suspended";
function readStatusBitInternal(bitstring: string, idx: number): SlotStatus {
  const raw = decodeBitstring(bitstring);
  const byteIdx = Math.floor(idx / 4);
  if (byteIdx >= raw.length) {
    throw new Error(`readStatusBit: idx out of range: ${idx}`);
  }
  const shift = (idx % 4) * 2;
  const bits = (raw[byteIdx] >> shift) & 0b11;
  if (bits === 0b00) return "valid";
  if (bits === 0b01) return "invalid";
  if (bits === 0b10) return "suspended";
  return "invalid"; // 0b11 reserved → fail-closed
}
