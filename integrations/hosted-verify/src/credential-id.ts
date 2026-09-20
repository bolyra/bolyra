/**
 * Managed-credential identity.
 *
 *   credential_id = lowercase_hex( SHA-256( DST || LP(K) || LP(B) ) )
 *
 *   DST   = UTF8("bolyra:managed-credential-id:" + CREDENTIAL_ID_VERSION) || 0x00
 *   LP(x) = uint32_be(byte_length(x)) || x
 *   K     = UTF8 of the CANONICAL operator key id (`operatorKeyId`, "x:y",
 *           decimal, no leading zeros) — derived HERE from the key's
 *           coordinates, so a caller cannot pass a non-canonical spelling and
 *           mint a second id for the same key
 *   B     = the 32-byte big-endian encoding of the binding digest
 *           (`bindingDigest(binding)`, already reduced mod the BN254 order)
 *
 * The id derives only from the verified signer and the canonical signed
 * binding — never from presentation fields (nonce, proof envelope, the
 * revealed credential expiry). The encoding is injective: fixed DST, then two
 * length-prefixed fields, the second always 32 bytes. Changing the digest
 * algorithm is a new CREDENTIAL_ID_VERSION, which changes the DST and so
 * every id.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { operatorKeyId } from './verify/operators';

export const CREDENTIAL_ID_VERSION = 'v1';

/** Exactly 64 lowercase hex characters; anything else is "no such credential". */
export const CREDENTIAL_ID_PATTERN = /^[0-9a-f]{64}$/;

export const CREDENTIAL_ID_DST = `bolyra:managed-credential-id:${CREDENTIAL_ID_VERSION}`;

const encoder = new TextEncoder();

/** uint32_be(length) || bytes */
function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

/** 32-byte big-endian encoding of a non-negative bigint below 2^256. */
export function bigintToBytes32(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 256n) {
    throw new RangeError('value must be in [0, 2^256)');
  }
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function credentialId(operator: { x: bigint; y: bigint }, bindingDigest: bigint): string {
  const dst = encoder.encode(CREDENTIAL_ID_DST);
  const k = lengthPrefixed(encoder.encode(operatorKeyId(operator.x, operator.y)));
  const b = lengthPrefixed(bigintToBytes32(bindingDigest));
  const payload = new Uint8Array(dst.length + 1 + k.length + b.length);
  payload.set(dst, 0);
  payload[dst.length] = 0x00;
  payload.set(k, dst.length + 1);
  payload.set(b, dst.length + 1 + k.length);
  return bytesToHex(sha256(payload));
}
