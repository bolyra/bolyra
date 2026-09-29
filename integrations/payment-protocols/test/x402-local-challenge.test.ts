/**
 * Agent-side host local challenge context (spec §4.2 / plan §B): build the
 * profile's challenge context from a raw x402 v2 PAYMENT-REQUIRED header when
 * the resource server does not participate in the profile.
 */
import { createHash } from 'node:crypto';

import { x402LocalChallenge } from '../src/x402-local-challenge';
import observed from './fixtures/x402-issuer-quote/tavily-challenge-observed.json';

const NOW = 1_790_697_736; // inside the observed token's window
const RESOURCE = 'https://x402.tavily.com/search';
const header = observed.paymentRequiredHeader;
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');
const encode = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64');

describe('x402LocalChallenge', () => {
  test('selects the agent-pay leg and maps it to profile requirements', () => {
    const lc = x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    expect(lc.mode).toBe('local');
    expect(lc.receivedAt).toBe(NOW);
    expect(lc.headerSha256).toBe(sha(header));
    expect(lc.context.nonce).toBe(sha(header));
    expect(lc.context.resource).toBe(RESOURCE);
    expect(lc.requirements).toMatchObject({
      scheme: 'agent-pay', network: 'aws:base', asset: 'iso4217:USD', amount: '0.016',
      payTo: 'urn:x402:agent-pay:see-quote',
    });
    expect(typeof (lc.requirements.extra as { quoteToken: string }).quoteToken).toBe('string');
  });

  test('the provisional deadline is receivedAt + min(maxTimeoutSeconds, maxSeconds)', () => {
    expect(x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 }).context.expiresAt).toBe(NOW + 300);
    expect(x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 120 }).context.expiresAt).toBe(NOW + 120);
    expect(x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 0, now: NOW, maxSeconds: 900 }).context.expiresAt).toBe(NOW + 60);
  });

  test('the selected leg is a deep-frozen copy, detached from the parsed input', () => {
    const lc = x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    expect(Object.isFrozen(lc.selectedLeg)).toBe(true);
    expect(Object.isFrozen(lc.selectedLeg.extra)).toBe(true);
    expect(Object.isFrozen((lc.selectedLeg.extra as { settlement: object }).settlement)).toBe(true);
    expect(() => { (lc.selectedLeg as { payTo: string }).payTo = 'x'; }).toThrow();
  });

  test('two distinct valid headers hash to distinct nonces', () => {
    const decoded = observed.decoded as { accepts: unknown[] };
    const other = encode({ ...decoded, resource: { url: 'https://other.example/x' } });
    const a = x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const b = x402LocalChallenge({ headerValue: other, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    expect(a.context.nonce).not.toBe(b.context.nonce);
    expect(b.context.nonce).toBe(sha(other));
  });

  const base = observed.decoded as { x402Version: number; accepts: Array<Record<string, unknown>> };
  test.each([
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
  ])('rejects a malformed header: %s', (_label, headerValue) => {
    expect(() => x402LocalChallenge({ headerValue, resource: RESOURCE, legIndex: 0, now: NOW, maxSeconds: 900 }))
      .toThrow(expect.objectContaining({ code: 'malformed_input' }));
  });

  test.each([
    ['negative legIndex', -1], ['non-integer legIndex', 0.5], ['out-of-range legIndex', 2], ['NaN legIndex', Number.NaN],
  ])('rejects %s', (_label, legIndex) => {
    expect(() => x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex, now: NOW, maxSeconds: 900 }))
      .toThrow(expect.objectContaining({ code: 'malformed_input' }));
  });

  test.each([
    ['missing', undefined], ['zero', 0], ['negative', -5], ['non-integer', 1.5], ['non-finite', Number.POSITIVE_INFINITY], ['string', '300'],
  ])('rejects a leg whose maxTimeoutSeconds is %s', (_label, maxTimeoutSeconds) => {
    const leg = { ...base.accepts[1], maxTimeoutSeconds };
    const headerValue = encode({ ...base, accepts: [base.accepts[0], leg] });
    expect(() => x402LocalChallenge({ headerValue, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 }))
      .toThrow(expect.objectContaining({ code: 'malformed_input' }));
  });

  test.each([
    ['maxSeconds above 900', { maxSeconds: 901 }], ['maxSeconds zero', { maxSeconds: 0 }],
    ['NaN now', { now: Number.NaN }], ['empty resource', { resource: '' }],
  ])('rejects bad host input: %s (internal_error)', (_label, override) => {
    expect(() => x402LocalChallenge({ headerValue: header, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900, ...override }))
      .toThrow(expect.objectContaining({ code: 'internal_error' }));
  });
});
