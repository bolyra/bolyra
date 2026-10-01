import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseChallenge, selectLeg, classifyLeg, defaultPayeeMatch, peekJwsHeader, inspectJwsPayload, tokenSha256, PLACEHOLDER_URN, LIMITS, decodeBase64Strict, decodeBase64UrlStrict } from '../../src/core/x402.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '../../../..');
const observed = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations/payment-protocols/test/fixtures/x402-issuer-quote/tavily-challenge-observed.json'), 'utf8'));
const header = observed.paymentRequiredHeader;
const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');
const b64u = (s) => Buffer.from(s).toString('base64url');

test('parseChallenge on the observed header: two legs, both usable, decoded equals the fixture', () => {
  const p = parseChallenge(header);
  assert.equal(p.ok, true); assert.equal(p.legs.length, 2); assert.ok(p.legs.every((l) => l.leg !== null));
  assert.deepEqual(p.decoded, observed.decoded);
  assert.match(p.headerSha256, /^[0-9a-f]{64}$/);
  assert.equal(p.legs[1].leg.payTo, PLACEHOLDER_URN);
});

test('parseChallenge reports per-leg problems without failing the header', () => {
  const p = parseChallenge(encode({ ...observed.decoded, accepts: [observed.decoded.accepts[0], { scheme: 'x' }] }));
  assert.equal(p.ok, true); assert.equal(p.legs[0].leg !== null, true); assert.equal(p.legs[1].leg, null); assert.equal(p.legs[1].reason, 'leg_max_timeout');
});

test('classifyLeg is descriptive only: placeholder-urn / address-valued / other, plus the token fact', () => {
  const [a, b] = observed.decoded.accepts;
  assert.deepEqual(classifyLeg(a), { kind: 'address-valued', hasQuoteToken: false });
  assert.deepEqual(classifyLeg(b), { kind: 'placeholder-urn', hasQuoteToken: true });
  assert.deepEqual(classifyLeg({ ...b, payTo: 'urn:example:other-rail' }), { kind: 'other', hasQuoteToken: true });
  assert.deepEqual(classifyLeg({ ...b, extra: { tier: 'x' } }), { kind: 'placeholder-urn', hasQuoteToken: false });
  assert.deepEqual(classifyLeg({ ...b, extra: { quoteToken: 5 } }), { kind: 'placeholder-urn', hasQuoteToken: false });
  assert.deepEqual(classifyLeg({ ...a, payTo: '0x' + 'A'.repeat(40) }), { kind: 'address-valued', hasQuoteToken: false });
  assert.equal(PLACEHOLDER_URN, 'urn:x402:agent-pay:see-quote');
});

test('defaultPayeeMatch is byte equality', () => {
  assert.equal(defaultPayeeMatch('0xabc', '0xabc'), true);
  assert.equal(defaultPayeeMatch('0xABC', '0xabc'), false);
  assert.equal(defaultPayeeMatch(undefined, '0xabc'), false);
});

test('peek then inspect: payload inspection is separate and never runs when the header peek fails', () => {
  const token = observed.decoded.accepts[1].extra.quoteToken;
  const h = peekJwsHeader(token);
  assert.deepEqual(h, { alg: 'ES384', typ: 'JWT', kid: 'tavily-agentpay-x402-signing-key' });
  const p = inspectJwsPayload(token);
  assert.equal(p.iss, 'https://x402.tavily.com'); assert.equal(p.aud, 'aws:marketplace'); assert.equal(p.payTo, 'seller');
  assert.match(tokenSha256(token), /^[0-9a-f]{64}$/);
  // bad header, fine payload: peek throws; inspect still refuses because the header part is unusable
  const bad = 'x.' + token.split('.')[1] + '.c';
  assert.throws(() => peekJwsHeader(bad), (e) => e.reason === 'base64url' || e.reason === 'header_object');
  assert.throws(() => inspectJwsPayload(bad), (e) => typeof e.reason === 'string');
  // good header, bad payload: peek ok, inspect throws payload_object / base64url
  const badPayload = token.split('.')[0] + '.' + b64u('[1]') + '.c';
  assert.deepEqual(peekJwsHeader(badPayload), h);
  assert.throws(() => inspectJwsPayload(badPayload), (e) => e.reason === 'payload_object');
});

test('caps: 64 KiB + 1 header and depth 33 are malformed_input before parsing', () => {
  const big = encode({ ...observed.decoded, pad: 'x'.repeat(64 * 1024) });
  assert.ok(big.length > LIMITS.MAX_PAYMENT_REQUIRED_CHARS);
  assert.deepEqual(parseChallenge(big), { ok: false, code: 'malformed_input', reason: 'header_size' });
  const deep = encode(JSON.parse('['.repeat(33) + ']'.repeat(33)));
  const r = parseChallenge(deep);
  assert.equal(r.ok, false); assert.equal(r.code, 'malformed_input');
});

test('strict base64 decoders: canonical only', () => {
  assert.equal(decodeBase64Strict('aGk=') !== null, true);
  assert.equal(decodeBase64Strict('aGk'), null);
  assert.equal(decodeBase64Strict('aGk= '), null);
  assert.equal(decodeBase64UrlStrict('aGk') !== null, true);
  assert.equal(decodeBase64UrlStrict('aGk='), null);
  assert.equal(decodeBase64UrlStrict('aGl'), null); // non-canonical trailing bits
});
