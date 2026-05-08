import { deflateSync, inflateSync } from "node:zlib";
import { SignJWT, compactVerify, decodeProtectedHeader } from "jose";

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

export class StatusListSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StatusListSignatureError";
  }
}

export interface PublishStatusListOptions {
  iss: string;
  sub: string;
  bits: 2;
  bitstring: string;
  ttlSeconds?: number;
}

const ONE_YEAR_S = 365 * 24 * 60 * 60;

export async function publishStatusList(
  opts: PublishStatusListOptions,
  signingKey: { privateKey: CryptoKey; kid: string },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (opts.ttlSeconds ?? ONE_YEAR_S);
  const payload: Record<string, unknown> = {
    iss: opts.iss,
    sub: opts.sub,
    iat: now,
    exp,
    status_list: { bits: opts.bits, lst: opts.bitstring },
  };
  if (opts.ttlSeconds !== undefined) payload.ttl = opts.ttlSeconds;
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA", typ: "statuslist+jwt", kid: signingKey.kid })
    .sign(signingKey.privateKey);
}

export interface StatusListPayload {
  bitstring: string;
  iss: string;
  exp: number;
  ttl?: number;
}

export async function readStatusListPayload(
  jws: string,
  verifyKey: CryptoKey,
): Promise<StatusListPayload> {
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(jws) as Record<string, unknown>;
  } catch (e) {
    throw new StatusListSignatureError(`malformed header: ${(e as Error).message}`);
  }
  if (header.typ !== "statuslist+jwt") {
    throw new StatusListSignatureError(
      `wrong typ: expected statuslist+jwt, got ${String(header.typ)}`,
    );
  }
  let verified;
  try {
    verified = await compactVerify(jws, verifyKey);
  } catch (e) {
    throw new StatusListSignatureError(`signature verify failed: ${(e as Error).message}`);
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(new TextDecoder().decode(verified.payload));
  } catch (e) {
    throw new StatusListSignatureError(`payload parse failed: ${(e as Error).message}`);
  }
  const sl = payload.status_list as { bits: number; lst: string } | undefined;
  if (!sl || sl.bits !== 2 || typeof sl.lst !== "string") {
    throw new StatusListSignatureError("status_list claim malformed");
  }
  if (typeof payload.exp !== "number") {
    throw new StatusListSignatureError("exp claim missing or non-numeric");
  }
  const out: StatusListPayload = {
    bitstring: sl.lst,
    iss: String(payload.iss),
    exp: payload.exp,
  };
  if (typeof payload.ttl === "number") out.ttl = payload.ttl;
  return out;
}

import type { IssuerKeyResolver, StatusListResult } from "./types";

export class StatusListIssuerMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StatusListIssuerMismatchError";
  }
}

export interface FetchStatusListOpts {
  fetch?: typeof globalThis.fetch;
  cacheTtlSeconds?: number; // accepted for spec parity; v0.2 does not cache
  verifyKey?: CryptoKey | IssuerKeyResolver;
}

// base64url decode (JOSE standard) — JWS header peek MUST NOT use standard base64.
function b64urlToBuf(s: string): Buffer {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  const padded = s + "=".repeat(pad);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

export async function fetchStatusList(
  uri: string,
  idx: number,
  expectedIss: string,
  opts?: FetchStatusListOpts,
): Promise<StatusListResult> {
  // Security invariant: HTTPS-only. Reject before any fetch is issued.
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch (e) {
    throw new Error(`status list uri parse failed: ${(e as Error).message}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`status list uri must be https, got ${parsed.protocol}`);
  }

  const f = opts?.fetch ?? globalThis.fetch;
  const res = await f(uri);
  if (!res.ok) throw new Error(`status list unreachable: ${res.status}`);
  const jws = await res.text();

  // Peek at the JWS protected header to learn (kid) and at the payload to
  // learn (iss) BEFORE we decide which verification key to use.
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("status list jws malformed");
  let header: Record<string, unknown>;
  let payloadPeek: Record<string, unknown>;
  try {
    header = JSON.parse(b64urlToBuf(parts[0]).toString("utf8"));
    payloadPeek = JSON.parse(b64urlToBuf(parts[1]).toString("utf8"));
  } catch (e) {
    throw new Error(`status list jws decode failed: ${(e as Error).message}`);
  }
  const tokenIss = String(payloadPeek.iss ?? "");
  const tokenKid = typeof header.kid === "string" ? header.kid : "";

  if (tokenIss !== expectedIss) {
    throw new StatusListIssuerMismatchError(
      `status_list_issuer_mismatch: token iss ${tokenIss} != expected ${expectedIss}`,
    );
  }

  // Resolve the verification key. Either a direct CryptoKey, or a resolver
  // that we call with the iss/kid we just peeked.
  let key: CryptoKey | undefined;
  if (opts?.verifyKey && typeof opts.verifyKey === "function") {
    const resolved = await (opts.verifyKey as IssuerKeyResolver)(tokenIss, tokenKid);
    key = resolved ?? undefined;
  } else if (opts?.verifyKey) {
    key = opts.verifyKey as CryptoKey;
  }
  if (!key) {
    throw new Error(`status list signer not found: ${tokenIss}/${tokenKid}`);
  }

  // readStatusListPayload throws StatusListSignatureError on sig OR typ failure.
  const payload = await readStatusListPayload(jws, key);
  const slot = readStatusBitInternal(payload.bitstring, idx);
  return { status: slot, fetchedAt: Math.floor(Date.now() / 1000) };
}
