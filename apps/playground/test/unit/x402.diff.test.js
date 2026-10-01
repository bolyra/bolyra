/**
 * Differential test: the playground's browser port of the x402 PAYMENT-REQUIRED
 * header/leg parser and the JWS protected-header peek versus the PUBLISHED
 * `@bolyra/payment-protocols` (pinned in package.json config.paymentProtocolsVersion).
 *
 * Claim this file substantiates, and nothing wider: the port matches the pinned
 * package on this corpus (the package's own local-challenge test cases, copied
 * verbatim, plus compound-invalid inputs fixing first-failure precedence).
 *
 * The oracle is the normally resolved published dependency tree (no overrides).
 * Its engines are `^20.19.0 || ^22.12.0 || >=23.0.0`; that range is enforced
 * BEFORE the oracle loads and a mismatch FAILS (never skips) this suite.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { parseChallenge, selectLeg, peekJwsHeader, isUnixSeconds, LIMITS } from '../../src/core/x402.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(here, '../..');
const ROOT = path.resolve(APP, '../..');
const pkg = JSON.parse(fs.readFileSync(path.join(APP, 'package.json'), 'utf8'));
const require = createRequire(import.meta.url);

// --- engine range gate (hard failure) --------------------------------------
function satisfiesEngines(version) {
  const [maj, min] = version.split('.').map(Number);
  return (maj === 20 && min >= 19) || (maj === 22 && min >= 12) || maj >= 23;
}
test(`Node ${process.versions.node} satisfies the oracle's engines ^20.19.0 || ^22.12.0 || >=23.0.0`, () => {
  assert.ok(satisfiesEngines(process.versions.node), `run this suite on Node ^20.19.0 || ^22.12.0 || >=23.0.0 (got ${process.versions.node}); the published oracle requires require(esm) for jose`);
});
const oraclePkg = require('@bolyra/payment-protocols/package.json');
test('installed oracle version equals config.paymentProtocolsVersion', () => {
  assert.equal(oraclePkg.version, pkg.config.paymentProtocolsVersion);
});
const { x402LocalChallenge } = require('@bolyra/payment-protocols/dist/x402-local-challenge.js');
const { peekHeader } = require('@bolyra/payment-protocols/dist/x402-issuer-quote/jws.js');

// --- corpus (verbatim from integrations/payment-protocols/test/x402-local-challenge.test.ts) ---
const observed = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations/payment-protocols/test/fixtures/x402-issuer-quote/tavily-challenge-observed.json'), 'utf8'));
const NOW = 1_790_697_736;
const RESOURCE = 'https://x402.tavily.com/search';
const header = observed.paymentRequiredHeader;
const base = observed.decoded;
const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

function both(fn, input) {
  let ours, theirs;
  try { ours = { ok: true, value: fn.port(input) }; } catch (e) { ours = { ok: false, code: e.code, reason: e.detail?.reason }; }
  try { theirs = { ok: true, value: fn.oracle(input) }; } catch (e) { theirs = { ok: false, code: e.code, reason: e.detail?.reason }; }
  return { ours, theirs };
}
const select = { port: selectLeg, oracle: x402LocalChallenge };

test('valid selections are byte-identical (JSON) to the oracle across legs, caps and clocks', () => {
  for (const legIndex of [0, 1]) for (const maxSeconds of [900, 120, 1]) for (const now of [NOW, 1790697716.5]) {
    const { ours, theirs } = both(select, { headerValue: header, resource: RESOURCE, legIndex, now, maxSeconds });
    assert.equal(ours.ok, true); assert.equal(theirs.ok, true);
    assert.equal(JSON.stringify(ours.value), JSON.stringify(theirs.value), `leg ${legIndex} cap ${maxSeconds} now ${now}`);
    assert.equal(ours.value.headerSha256, sha(header));
    assert.equal(ours.value.context.expiresAt, now + Math.min(base.accepts[legIndex].maxTimeoutSeconds, maxSeconds));
    assert.ok(Object.isFrozen(ours.value.selectedLeg) && Object.isFrozen(ours.value.selectedLeg.extra));
  }
});

const malformedHeaders = [
  ['trailing whitespace on the header value', `${header} `],
  ['not base64', '!!!not-base64!!!'],
  ['base64 but not JSON', Buffer.from('nope').toString('base64')],
  ['JSON array', encode([1, 2])],
  ['wrong x402Version', encode({ ...base, x402Version: 1 })],
  ['missing accepts', encode({ x402Version: 2 })],
  ['empty accepts', encode({ ...base, accepts: [] })],
  ['accepts entry not an object', encode({ ...base, accepts: ['x'] })],
  ['own __proto__ member', Buffer.from(JSON.stringify(base).replace('{"', '{"__proto__":{"a":1},"')).toString('base64')],
  ['header over 64 KiB', encode({ ...base, pad: 'x'.repeat(70_000) })],
  // compound-invalid: first-failure precedence
  ['non-canonical base64 (bad padding bits) AND bad version', encode({ ...base, x402Version: 1 }).slice(0, -1) + '='],
  ['invalid UTF-8 bytes', Buffer.from([0xff, 0xfe, 0x7b]).toString('base64')],
  ['header is a number', 42],
  ['own constructor member', Buffer.from(JSON.stringify(base).replace('{"', '{"constructor":1,"')).toString('base64')],
  ['leg missing scheme', encode({ ...base, accepts: [{ ...base.accepts[0], scheme: undefined }] })],
  ['leg empty payTo', encode({ ...base, accepts: [{ ...base.accepts[0], payTo: '' }] })],
  ['leg amount number', encode({ ...base, accepts: [{ ...base.accepts[0], amount: 10000 }] })],
  ['leg extra is an array', encode({ ...base, accepts: [{ ...base.accepts[0], extra: [1] }] })],
  ['leg extra with __proto__ nested', Buffer.from(JSON.stringify({ ...base, accepts: [{ ...base.accepts[0], extra: { a: 1 } }] }).replace('"extra":{"', '"extra":{"__proto__":{},"')).toString('base64')],
  ['leg extra with non-JSON value type via NaN string trick', encode({ ...base, accepts: [{ ...base.accepts[0], extra: { a: null, b: [1, { c: true }] } }] })],
];
test('malformed headers: same code and reason as the oracle', () => {
  for (const [label, headerValue] of malformedHeaders) {
    const { ours, theirs } = both(select, { headerValue, resource: RESOURCE, legIndex: 0, now: NOW, maxSeconds: 900 });
    assert.equal(ours.ok, theirs.ok, label);
    if (!ours.ok) { assert.equal(ours.code, theirs.code, label); assert.equal(ours.reason, theirs.reason, label); }
    else assert.equal(JSON.stringify(ours.value), JSON.stringify(theirs.value), label);
  }
});

test('legIndex, maxTimeoutSeconds and host-input cases: same code and reason as the oracle', () => {
  for (const [label, legIndex] of [['negative legIndex', -1], ['non-integer legIndex', 0.5], ['out-of-range legIndex', 2], ['NaN legIndex', Number.NaN], ['string legIndex', '1']]) {
    const { ours, theirs } = both(select, { headerValue: header, resource: RESOURCE, legIndex, now: NOW, maxSeconds: 900 });
    assert.deepEqual([ours.ok, ours.code, ours.reason], [theirs.ok, theirs.code, theirs.reason], label);
  }
  for (const [label, maxTimeoutSeconds] of [['missing', undefined], ['zero', 0], ['negative', -5], ['non-integer', 1.5], ['non-finite', Number.POSITIVE_INFINITY], ['string', '300']]) {
    const leg = { ...base.accepts[1], maxTimeoutSeconds };
    const headerValue = encode({ ...base, accepts: [base.accepts[0], leg] });
    const { ours, theirs } = both(select, { headerValue, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    assert.deepEqual([ours.ok, ours.code, ours.reason], [theirs.ok, theirs.code, theirs.reason], `maxTimeoutSeconds ${label}`);
  }
  for (const [label, override] of [['maxSeconds above 900', { maxSeconds: 901 }], ['maxSeconds zero', { maxSeconds: 0 }], ['maxSeconds fractional', { maxSeconds: 1.5 }], ['NaN now', { now: Number.NaN }], ['negative now', { now: -1 }], ['huge now', { now: 2 ** 41 }], ['empty resource', { resource: '' }], ['resource not a string', { resource: 5 }],
    ['bad host input AND bad header (host fault wins)', { resource: '', headerValue: 'not base64' }]]) {
    const { ours, theirs } = both(select, { headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900, ...override });
    assert.deepEqual([ours.ok, ours.code, ours.reason], [theirs.ok, theirs.code, theirs.reason], label);
  }
});

test('parseChallenge agrees with the oracle on which headers are usable and mirrors its reasons', () => {
  for (const [label, headerValue] of [['observed', header], ...malformedHeaders]) {
    const parsed = parseChallenge(headerValue);
    const { theirs } = both(select, { headerValue, resource: RESOURCE, legIndex: 0, now: NOW, maxSeconds: 900 });
    if (!parsed.ok) { assert.equal(theirs.ok, false, label); assert.equal(parsed.reason, theirs.reason, label); }
    else {
      // header-level ok; per-leg problems (if any) must match the oracle's per-leg reason
      for (const entry of parsed.legs) {
        const r = both(select, { headerValue, resource: RESOURCE, legIndex: entry.index, now: NOW, maxSeconds: 900 }).theirs;
        if (entry.leg) assert.equal(r.ok, true, `${label} leg ${entry.index}`); else assert.equal(entry.reason, r.reason, `${label} leg ${entry.index}`);
      }
    }
  }
});

test('peekJwsHeader matches peekHeader (header or reason) on the JWS corpus', () => {
  const token = base.accepts[1].extra.quoteToken;
  const b64u = (s) => Buffer.from(s).toString('base64url');
  const cases = [
    ['observed token', token], ['two parts', 'a.b'], ['empty middle', 'a..c'], ['single part', 'x'],
    ['oversize', 'x'.repeat(9000)], ['non-canonical base64url header', 'eyJhbGciOiJFUzI1NiJ9' + 'Q' + '.b.c'],
    ['invalid utf8 header', Buffer.from([0xff, 0xfe]).toString('base64url') + '.b.c'],
    ['header not json', b64u('nope') + '.b.c'], ['header array', b64u('[1]') + '.b.c'],
    ['header with __proto__', b64u('{"__proto__":{}}') + '.b.c'], ['header with constructor', b64u('{"constructor":1}') + '.b.c'],
    ['plus in base64url', 'ab+c.b.c'], ['not a string', 5],
  ];
  for (const [label, compact] of cases) {
    let ours, theirs;
    try { ours = { ok: true, value: peekJwsHeader(compact) }; } catch (e) { ours = { ok: false, reason: e.reason }; }
    try { theirs = { ok: true, value: peekHeader(compact) }; } catch (e) { theirs = { ok: false, reason: e.reason }; }
    assert.equal(ours.ok, theirs.ok, label);
    if (ours.ok) assert.deepEqual(ours.value, theirs.value, label); else assert.equal(ours.reason, theirs.reason, label);
  }
});

test('isUnixSeconds and LIMITS mirror the package constants', () => {
  for (const v of [0, 1, 1790697716.5, 2 ** 40]) assert.equal(isUnixSeconds(v), true, String(v));
  for (const v of [-1, 2 ** 40 + 1, Number.NaN, Number.POSITIVE_INFINITY, '1', null]) assert.equal(isUnixSeconds(v), false, String(v));
  assert.equal(LIMITS.MAX_PAYMENT_REQUIRED_CHARS, 64 * 1024);
  assert.equal(LIMITS.MAX_LOCAL_CHALLENGE_SECONDS, 900);
  assert.equal(LIMITS.MAX_COMPACT_JWS_CHARS, 8 * 1024);
});
