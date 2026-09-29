/**
 * Signature layer for issuer-quoted payee binding (spec §4.2).
 *
 * A strict compact-JWS parser sits in FRONT of jose's `compactVerify`: every
 * structural decision (shape, canonical base64url, fatal UTF-8, plain-object
 * header/payload, no prototype-named members, exact `alg`, no `crit`, no
 * unencoded payload, no token-supplied key sources) is made here with a
 * stable `reason`, and only then is the signature checked. jose enforces the
 * raw `r || s` signature length for ES256/ES384 and verifies the original
 * encoded signing input.
 *
 * This module knows nothing about the profile's claims policy.
 */
import { compactVerify, type CryptoKey } from 'jose';
import { createHash } from 'node:crypto';

export type JwsAlg = 'ES256' | 'ES384';

export type JwsRejectReason =
  | 'compact_shape'
  | 'size'
  | 'base64url'
  | 'utf8'
  | 'header_object'
  | 'payload_object'
  | 'alg'
  | 'crit'
  | 'b64'
  | 'key_source'
  | 'typ'
  | 'signature';

export class JwsRejected extends Error {
  readonly name = 'JwsRejected';
  constructor(readonly reason: JwsRejectReason, detail?: string) {
    super(detail === undefined ? `jws rejected: ${reason}` : `jws rejected: ${reason} (${detail})`);
  }
}

export interface VerifiedCompactJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  /** Lowercase hex SHA-256 over the exact compact token (UTF-8 bytes). */
  tokenSha256: string;
}

export const MAX_COMPACT_JWS_CHARS = 8 * 1024;
const BASE64URL_PART = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_MEMBERS = ['__proto__', 'constructor', 'prototype'] as const;
const TOKEN_KEY_SOURCES = ['jwk', 'jku', 'x5u', 'x5c'] as const;
const utf8 = new TextDecoder('utf-8', { fatal: true });

function decodeCanonicalBase64url(part: string): Buffer {
  if (!BASE64URL_PART.test(part)) throw new JwsRejected('base64url');
  const bytes = Buffer.from(part, 'base64url');
  if (bytes.toString('base64url') !== part) throw new JwsRejected('base64url', 'non-canonical');
  return bytes;
}

/** Parse a JSON part into a plain object with no prototype-named own members. */
export function parseJsonObjectPart(
  bytes: Buffer,
  reason: 'header_object' | 'payload_object',
): Record<string, unknown> {
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    throw new JwsRejected('utf8');
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new JwsRejected(reason, 'not json');
  }
  if (!isPlainObject(value)) throw new JwsRejected(reason);
  for (const name of FORBIDDEN_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(value, name)) throw new JwsRejected(reason, name);
  }
  return value;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * Parse the protected header with the same shape rules as verification, but
 * WITHOUT verifying anything. Callers use it to pick a key by `kid`; every
 * decision still goes through {@link verifyCompactEs} afterwards.
 */
export function peekHeader(compact: string): Record<string, unknown> {
  if (typeof compact !== 'string') throw new JwsRejected('compact_shape');
  if (compact.length > MAX_COMPACT_JWS_CHARS) throw new JwsRejected('size');
  const parts = compact.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new JwsRejected('compact_shape');
  return parseJsonObjectPart(decodeCanonicalBase64url(parts[0]), 'header_object');
}

/**
 * Verify one compact JWS with exactly one expected algorithm and key.
 * Throws {@link JwsRejected}; never returns a partially verified result.
 */
export async function verifyCompactEs(
  compact: string,
  expected: { key: CryptoKey; alg: JwsAlg },
): Promise<VerifiedCompactJws> {
  if (typeof compact !== 'string') throw new JwsRejected('compact_shape');
  if (compact.length > MAX_COMPACT_JWS_CHARS) throw new JwsRejected('size');
  const parts = compact.split('.');
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new JwsRejected('compact_shape');

  const [headerPart, payloadPart, signaturePart] = parts;
  const headerBytes = decodeCanonicalBase64url(headerPart);
  const payloadBytes = decodeCanonicalBase64url(payloadPart);
  decodeCanonicalBase64url(signaturePart); // shape only; jose re-decodes and length-checks

  const header = parseJsonObjectPart(headerBytes, 'header_object');
  if (header.alg !== expected.alg) throw new JwsRejected('alg');
  if ('crit' in header) throw new JwsRejected('crit');
  if ('b64' in header) throw new JwsRejected('b64');
  for (const source of TOKEN_KEY_SOURCES) {
    if (source in header) throw new JwsRejected('key_source', source);
  }
  if ('typ' in header && header.typ !== 'JWT') throw new JwsRejected('typ');

  const payload = parseJsonObjectPart(payloadBytes, 'payload_object');

  try {
    await compactVerify(compact, expected.key, { algorithms: [expected.alg] });
  } catch {
    throw new JwsRejected('signature');
  }

  return {
    header,
    payload,
    tokenSha256: createHash('sha256').update(compact, 'utf8').digest('hex'),
  };
}
