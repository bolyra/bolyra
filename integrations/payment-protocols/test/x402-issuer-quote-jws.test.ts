/**
 * Signature layer for issuer-quoted payee binding: compact JWS (ES256/ES384)
 * verification against an independent vector (RFC 7515 Appendix A.3) and the
 * parser contract from spec §4.2. Profile policy (claims, products, rails)
 * is NOT exercised here — see x402-evc-issuer-quote.test.ts.
 */
import { importJWK, type CryptoKey } from 'jose';
import { createHash } from 'node:crypto';

import { verifyCompactEs, JwsRejected } from '../src/x402-issuer-quote/jws';
import vector from './fixtures/x402-issuer-quote/rfc7515-a3.json';

const b64u = (bytes: Uint8Array | Buffer) => Buffer.from(bytes).toString('base64url');
const parts = () => vector.compact.split('.');
let key: CryptoKey;

beforeAll(async () => {
  key = (await importJWK(vector.publicJwk, 'ES256')) as CryptoKey;
});

describe('verifyCompactEs: RFC 7515 A.3 (independent ES256 vector)', () => {
  test('verifies the RFC vector and returns the parsed header and payload', async () => {
    const out = await verifyCompactEs(vector.compact, { key, alg: 'ES256' });
    expect(out.header).toEqual({ alg: 'ES256' });
    expect(out.payload).toEqual(vector.payload);
    expect(out.tokenSha256).toBe(createHash('sha256').update(vector.compact, 'utf8').digest('hex'));
  });

  test('the signature is exactly R||S from the RFC (64 raw bytes)', () => {
    const sig = Buffer.from(parts()[2], 'base64url');
    expect([...sig]).toEqual([...vector.r, ...vector.s]);
  });

  test.each([
    ['tampered payload', () => { const [h, , s] = parts(); return `${h}.${b64u(Buffer.from('{"iss":"eve"}'))}.${s}`; }, 'signature'],
    ['DER-encoded signature', () => {
      const der = (n: number[]) => { const b = Buffer.from(n); const pad = b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b; return Buffer.concat([Buffer.from([0x02, pad.length]), pad]); };
      const body = Buffer.concat([der(vector.r), der(vector.s)]);
      const [h, p] = parts(); return `${h}.${p}.${b64u(Buffer.concat([Buffer.from([0x30, body.length]), body]))}`;
    }, 'signature'],
    ['truncated signature (byte-level, still canonical base64url)', () => { const [h, p, s] = parts(); return `${h}.${p}.${b64u(Buffer.from(s, 'base64url').subarray(0, 63))}`; }, 'signature'],
    ['truncated signature (char-level, non-canonical)', () => { const [h, p, s] = parts(); return `${h}.${p}.${s.slice(0, -4)}`; }, 'base64url'],
    ['two parts', () => { const [h, p] = parts(); return `${h}.${p}`; }, 'compact_shape'],
    ['four parts', () => `${vector.compact}.extra`, 'compact_shape'],
    ['empty signature part (detached)', () => { const [h, p] = parts(); return `${h}.${p}.`; }, 'compact_shape'],
    ['base64 padding', () => `${vector.compact}==`, 'base64url'],
    ['non-canonical base64url', () => { const [h, p, s] = parts(); return `${h}.${p}.${s.slice(0, -1)}${s.endsWith('Q') ? 'R' : 'Q'}`; }, 'base64url'],
    ['whitespace inside', () => `${vector.compact.slice(0, 5)} ${vector.compact.slice(5)}`, 'base64url'],
    ['invalid UTF-8 in header', () => { const [, p, s] = parts(); return `${b64u(Buffer.from([0xff, 0xfe, 0x7b]))}.${p}.${s}`; }, 'utf8'],
    ['header is an array', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('["ES256"]'))}.${p}.${s}`; }, 'header_object'],
    ['header carries own __proto__', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","__proto__":{"x":1}}'))}.${p}.${s}`; }, 'header_object'],
    ['payload carries own constructor', () => { const [h, , s] = parts(); return `${h}.${b64u(Buffer.from('{"constructor":{}}'))}.${s}`; }, 'payload_object'],
    ['alg none', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"none"}'))}.${p}.${s}`; }, 'alg'],
    ['alg ES384 with a P-256 key', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES384"}'))}.${p}.${s}`; }, 'alg'],
    ['alg RS256', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"RS256"}'))}.${p}.${s}`; }, 'alg'],
    ['crit present', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","crit":["exp"]}'))}.${p}.${s}`; }, 'crit'],
    ['b64 present', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","b64":false}'))}.${p}.${s}`; }, 'b64'],
    ['embedded jwk', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","jwk":{}}'))}.${p}.${s}`; }, 'key_source'],
    ['jku', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","jku":"https://x"}'))}.${p}.${s}`; }, 'key_source'],
    ['x5c', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","x5c":[]}'))}.${p}.${s}`; }, 'key_source'],
    ['typ not JWT', () => { const [, p, s] = parts(); return `${b64u(Buffer.from('{"alg":"ES256","typ":"JOSE"}'))}.${p}.${s}`; }, 'typ'],
  ])('rejects %s', async (_label, make, reason) => {
    await expect(verifyCompactEs(make(), { key, alg: 'ES256' })).rejects.toMatchObject({ name: 'JwsRejected', reason });
  });

  test('rejects an oversized token before parsing', async () => {
    const [h, p, s] = parts();
    await expect(verifyCompactEs(`${h}.${p}${'A'.repeat(9000)}.${s}`, { key, alg: 'ES256' }))
      .rejects.toMatchObject({ name: 'JwsRejected', reason: 'size' });
  });

  test('rejects non-string input', async () => {
    await expect(verifyCompactEs(42 as unknown as string, { key, alg: 'ES256' }))
      .rejects.toMatchObject({ name: 'JwsRejected', reason: 'compact_shape' });
  });

  test('JwsRejected is an Error with a stable reason', () => {
    const e = new JwsRejected('alg');
    expect(e).toBeInstanceOf(Error);
    expect(e.reason).toBe('alg');
  });
});
