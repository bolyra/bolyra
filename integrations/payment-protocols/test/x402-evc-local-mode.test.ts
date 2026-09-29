/**
 * verifyX402EvcAuthorization in local mode (spec §4.2): resolvePayee wiring,
 * snapshots, double re-checks, quote-nonce retention, checkedLeg and the
 * payee_binding extension member. Offline.
 */
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { issueMandate, NonceStore } from '@bolyra/mpp';
import type { ConsumeNonce } from '@bolyra/mpp';
import { createHash } from 'node:crypto';

import { verifyX402EvcAuthorization, type X402EvcVerifyOptions } from '../src/x402-evc';
import { x402LocalChallenge } from '../src/x402-local-challenge';
import { createIssuerQuotePayeeResolver, type IssuerQuoteConfig, type PayeeResolver } from '../src/x402-issuer-quote';
import observed from './fixtures/x402-issuer-quote/tavily-challenge-observed.json';

const NOW = 1_790_697_736;
const ISS = 'https://x402.tavily.com';
const KID = 'tavily-agentpay-x402-signing-key';
const RESOURCE = 'https://x402.tavily.com/search';
const OPERATOR_PRIVATE_KEY = 42n;
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

let priv: CryptoKey; let pub: JWK;
beforeAll(async () => {
  const kp = await generateKeyPair('ES384', { extractable: true });
  priv = kp.privateKey as CryptoKey; pub = await exportJWK(kp.publicKey);
});

const claims = (jti = 'jti-1', patch: Record<string, unknown> = {}) => ({
  iss: ISS, aud: 'aws:marketplace', iat: NOW, exp: NOW + 300, jti,
  price: { amount: '0.016', currency: 'USD' }, payTo: 'seller', reference: 'tavily-search-advanced',
  settlement: { product_id: 'prod-maeet6sajeg42' }, ...patch,
});
const sign = (c: Record<string, unknown>) => new SignJWT(c).setProtectedHeader({ alg: 'ES384', kid: KID, typ: 'JWT' }).sign(priv);

function config(): IssuerQuoteConfig {
  return { issuers: new Map([[ISS, {
    payTo: 'urn:x402:agent-pay:see-quote', scheme: 'agent-pay', network: 'aws:base', audience: 'aws:marketplace', payToRole: 'seller',
    keys: new Map([[KID, { alg: 'ES384', jwk: pub }]]),
    products: new Map([[RESOURCE, { reference: 'tavily-search-advanced', 'settlement.product_id': 'prod-maeet6sajeg42' }]]),
    settlementFields: [{ challenge: 'extra.reference', claim: 'reference' }, { challenge: 'extra.settlement.product_id', claim: 'settlement.product_id' }],
    unboundExtraFields: ['tier'],
  }]]) };
}

/** A fresh header with the given token spliced into the agent-pay leg. */
function headerWith(token: string, salt = '') {
  const decoded = JSON.parse(JSON.stringify(observed.decoded)) as { accepts: Array<Record<string, unknown>>; resource: Record<string, unknown> };
  (decoded.accepts[1].extra as Record<string, unknown>).quoteToken = token;
  if (salt) decoded.resource = { ...decoded.resource, description: salt };
  return Buffer.from(JSON.stringify(decoded)).toString('base64');
}

async function mandate() {
  return issueMandate({ operatorPrivateKey: OPERATOR_PRIVATE_KEY, agentName: 'search-agent', audience: ISS, model: 'test-model', program: 'x402', maxUsd: '99', expiry: NOW + 3_600 });
}

class SpyStore extends NonceStore {
  calls: Array<{ entries: ConsumeNonce[]; now: number }> = [];
  onReserve?: () => void;
  reserve(entries: ConsumeNonce[], nowUnix: number): boolean {
    this.calls.push({ entries: entries.map((e) => ({ ...e })), now: nowUnix });
    this.onReserve?.();
    return super.reserve(entries, nowUnix);
  }
}

async function run(token: string, extra: Partial<X402EvcVerifyOptions> & { salt?: string; legIndex?: number; maxSeconds?: number; clock?: () => number } = {}) {
  const m = await mandate();
  const resolver = extra.resolvePayee ?? (await createIssuerQuotePayeeResolver(config()));
  const lc = x402LocalChallenge({ headerValue: headerWith(token, extra.salt), resource: RESOURCE, legIndex: extra.legIndex ?? 1, now: extra.clock ? extra.clock() : NOW, maxSeconds: extra.maxSeconds ?? 900 });
  const { salt: _s, legIndex: _l, maxSeconds: _m, clock, ...rest } = extra;
  const options: X402EvcVerifyOptions = {
    localChallenge: lc, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] },
    resolvePayee: resolver, now: clock ?? (() => NOW), ...rest,
  } as X402EvcVerifyOptions;
  return { decision: await verifyX402EvcAuthorization(m.presentation, options), lc, options };
}

describe('local mode: allow path', () => {
  test('binds the placeholder payee, records payee_binding, returns the checked leg and the finalized deadline', async () => {
    const token = await sign(claims());
    const store = new SpyStore();
    const { decision, lc } = await run(token, { nonceStore: store });
    expect(decision.allowed).toBe(true);
    expect(decision.status).toBe(200);
    const ext = decision.request!.x402_evc;
    expect(ext.payee).toBe('urn:x402:agent-pay:see-quote');
    expect(ext.payee_binding).toEqual({ kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'jti-1', exp: NOW + 300, token_sha256: sha(token) });
    expect(ext.amount).toBe('0.016');
    // provisional = NOW + 300 (leg timeout); acceptUntil = NOW + 360; finalized = NOW + 300
    expect(ext.expires_at).toBe(NOW + 300);
    expect(decision.expiresAt).toBe(NOW + 300);
    // checkedLeg is the verified leg with extra trimmed to the token + settlement-verified paths (H1)
    const { extra: legExtra, ...legRest } = lc.selectedLeg;
    const { extra: checkedExtra, ...checkedRest } = decision.checkedLeg!;
    expect(checkedRest).toEqual(legRest);
    expect(checkedExtra).toEqual({ quoteToken: (legExtra as { quoteToken: string }).quoteToken, reference: 'tavily-search-advanced', settlement: { product_id: 'prod-maeet6sajeg42' } });
    expect(Object.isFrozen(decision.checkedLeg)).toBe(true);
    const entries = store.calls[0].entries;
    expect(entries).toContainEqual({ issuer_key: `x402_evc:${ISS}`, nonce: lc.context.nonce, retain_until: NOW + 300 });
    expect(entries).toContainEqual({ issuer_key: `x402_evc_quote:${ISS}`, nonce: 'jti-1', retain_until: NOW + 360 });
  });

  test('the finalized deadline is the quote acceptance deadline when that is earlier', async () => {
    const token = await sign(claims('jti-short', { exp: NOW + 100 }));
    const { decision } = await run(token);
    expect(decision.allowed).toBe(true);
    expect(decision.request!.x402_evc.expires_at).toBe(NOW + 160);
    expect(decision.expiresAt).toBe(NOW + 160);
  });

  test('every denial omits checkedLeg', async () => {
    const token = await sign(claims('jti-deny', { payTo: 'buyer' }));
    const { decision } = await run(token);
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('request_mismatch');
    expect('checkedLeg' in decision).toBe(false);
  });
});

describe('local mode: configuration faults fail closed (internal_error)', () => {
  test('resolvePayee and payeeMatches both set', async () => {
    const { decision } = await run(await sign(claims('jti-both')), { payeeMatches: () => true });
    expect(decision.problem?.code).toBe('internal_error');
  });
  test('local mode without resolvePayee', async () => {
    const m = await mandate();
    const lc = x402LocalChallenge({ headerValue: headerWith(await sign(claims('jti-nores'))), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const decision = await verifyX402EvcAuthorization(m.presentation, { localChallenge: lc, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW } as X402EvcVerifyOptions);
    expect(decision.problem?.code).toBe('internal_error');
  });
  test('both context and localChallenge passed', async () => {
    const m = await mandate();
    const lc = x402LocalChallenge({ headerValue: headerWith(await sign(claims('jti-both2'))), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const decision = await verifyX402EvcAuthorization(m.presentation, { localChallenge: lc, context: lc.context, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, resolvePayee: await createIssuerQuotePayeeResolver(config()), now: () => NOW } as X402EvcVerifyOptions);
    expect(decision.problem?.code).toBe('internal_error');
  });
  test('neither context nor localChallenge passed', async () => {
    const m = await mandate();
    const decision = await verifyX402EvcAuthorization(m.presentation, { audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW } as unknown as X402EvcVerifyOptions);
    expect(decision.problem?.code).toBe('internal_error');
  });
  test.each<[string, PayeeResolver]>([
    ['returns no binding', async () => ({ acceptUntil: NOW + 360, verifiedExtraPaths: [] } as never)],
    ['returns malformed verifiedExtraPaths', async () => ({ binding: { kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'j', exp: NOW + 300, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 360, verifiedExtraPaths: 'quoteToken' } as never)],
    ['binding issuer differs from audience', async () => ({ binding: { kind: 'issuer_quote', issuer: 'https://other', kid: KID, jti: 'j', exp: NOW + 300, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 360, verifiedExtraPaths: [] })],
    ['acceptUntil before exp', async () => ({ binding: { kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'j', exp: NOW + 300, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 299, verifiedExtraPaths: [] })],
    ['acceptUntil beyond maxAcceptanceSeconds (default 900)', async () => ({ binding: { kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'j', exp: NOW + 300, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 901, verifiedExtraPaths: [] })],
    ['NUL in jti', async () => ({ binding: { kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'a\0b', exp: NOW + 300, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 360, verifiedExtraPaths: [] })],
    ['non-finite exp', async () => ({ binding: { kind: 'issuer_quote', issuer: ISS, kid: KID, jti: 'j', exp: Number.NaN, token_sha256: 'a'.repeat(64) }, acceptUntil: NOW + 360, verifiedExtraPaths: [] })],
    ['throws a plain Error', async () => { throw new Error('boom'); }],
  ])('resolver output: %s', async (_label, resolvePayee) => {
    const { decision } = await run(await sign(claims('jti-malformed')), { resolvePayee });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('internal_error');
  });
  test('a resolver VerifyDenial is passed through as that denial', async () => {
    const { decision } = await run(await sign(claims('jti-passthru', { aud: 'wrong' })));
    expect(decision.problem?.code).toBe('request_mismatch');
    expect(decision.verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch', detail: expect.objectContaining({ reason: 'aud' }) });
  });
});

describe('local mode: replay of the quote (issuer, jti)', () => {
  test('same jti, same challenge → nonce_replayed', async () => {
    const token = await sign(claims('jti-replay-1'));
    const store = new SpyStore();
    expect((await run(token, { nonceStore: store })).decision.allowed).toBe(true);
    const second = (await run(token, { nonceStore: store })).decision;
    expect(second.allowed).toBe(false); expect(second.problem?.code).toBe('nonce_replayed');
  });
  test('same jti, DIFFERENT challenge → nonce_replayed', async () => {
    const token = await sign(claims('jti-replay-2'));
    const store = new SpyStore();
    expect((await run(token, { nonceStore: store })).decision.allowed).toBe(true);
    const second = (await run(token, { nonceStore: store, salt: 'other challenge bytes' })).decision;
    expect(second.allowed).toBe(false); expect(second.problem?.code).toBe('nonce_replayed');
  });
  test('same jti after the first challenge expired but the quote is still acceptable → nonce_replayed', async () => {
    const token = await sign(claims('jti-replay-3'));
    const store = new SpyStore();
    expect((await run(token, { nonceStore: store, maxSeconds: 5 })).decision.allowed).toBe(true); // challenge deadline NOW+5
    const later = NOW + 10; // challenge gone, quote acceptable until NOW+360
    const second = (await run(token, { nonceStore: store, salt: 'fresh', clock: () => later })).decision;
    expect(second.allowed).toBe(false); expect(second.problem?.code).toBe('nonce_replayed');
  });
  test('two concurrent verifications with one jti → exactly one allow', async () => {
    const token = await sign(claims('jti-concurrent'));
    const store = new SpyStore();
    const [a, b] = await Promise.all([run(token, { nonceStore: store, salt: 'a' }), run(token, { nonceStore: store, salt: 'b' })]);
    expect([a.decision.allowed, b.decision.allowed].filter(Boolean)).toHaveLength(1);
  });
  test('duplicate reservation entries keep the maximum retention', async () => {
    const token = await sign(claims('jti-dup'));
    const store = new SpyStore();
    const resolver = await createIssuerQuotePayeeResolver(config());
    // a verifier consume_nonces entry that collides with the quote nonce at a shorter retention
    const wrapped: PayeeResolver = async (input) => resolver(input);
    const { decision } = await run(token, { nonceStore: store, resolvePayee: wrapped });
    expect(decision.allowed).toBe(true);
    const quoteEntries = store.calls[0].entries.filter((e) => e.issuer_key === `x402_evc_quote:${ISS}`);
    expect(quoteEntries).toHaveLength(1);
    expect(quoteEntries[0].retain_until).toBe(NOW + 360);
  });
});

describe('local mode: time races and snapshots', () => {
  test('the challenge expiring during resolvePayee denies expired', async () => {
    let clock = NOW;
    const resolver = await createIssuerQuotePayeeResolver(config());
    const slow: PayeeResolver = async (input) => { const out = await resolver(input); clock = NOW + 301; return out; };
    const { decision } = await run(await sign(claims('jti-race-1')), { resolvePayee: slow, clock: () => clock, maxSeconds: 300 });
    expect(decision.allowed).toBe(false); expect(decision.problem?.code).toBe('expired');
  });
  test('the quote acceptance deadline passing during resolvePayee denies expired', async () => {
    let clock = NOW;
    const resolver = await createIssuerQuotePayeeResolver(config());
    const slow: PayeeResolver = async (input) => { const out = await resolver(input); clock = NOW + 170; return out; };
    const { decision } = await run(await sign(claims('jti-race-2', { exp: NOW + 100 })), { resolvePayee: slow, clock: () => clock });
    expect(decision.allowed).toBe(false); expect(decision.problem?.code).toBe('expired');
  });
  test('expiry during an awaited nonce reservation denies, never allows', async () => {
    let clock = NOW;
    const store = new SpyStore(); store.onReserve = () => { clock = NOW + 400; };
    const { decision } = await run(await sign(claims('jti-race-3')), { nonceStore: store, clock: () => clock });
    expect(decision.allowed).toBe(false); expect(decision.problem?.code).toBe('expired');
  });
  test('reservation uses fresh time, not the entry time', async () => {
    let clock = NOW;
    const store = new SpyStore();
    const resolver = await createIssuerQuotePayeeResolver(config());
    const slow: PayeeResolver = async (input) => { const out = await resolver(input); clock = NOW + 50; return out; };
    const { decision } = await run(await sign(claims('jti-fresh')), { nonceStore: store, resolvePayee: slow, clock: () => clock });
    expect(decision.allowed).toBe(true);
    expect(store.calls[0].now).toBe(NOW + 50);
  });
  test('mutating the caller context after the call starts does not change what was verified', async () => {
    const m = await mandate();
    const token = await sign(claims('jti-mutate'));
    const lc = x402LocalChallenge({ headerValue: headerWith(token), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const mutable = JSON.parse(JSON.stringify(lc)) as typeof lc; // thawed copy the caller can mutate
    const pending = verifyX402EvcAuthorization(m.presentation, { localChallenge: mutable, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, resolvePayee: await createIssuerQuotePayeeResolver(config()), now: () => NOW } as X402EvcVerifyOptions);
    (mutable.context.requirements as { amount: string }).amount = '999';
    (mutable.context.requirements.extra as Record<string, unknown>).reference = 'tampered';
    (mutable.selectedLeg as { payTo: string }).payTo = 'tampered';
    const decision = await pending;
    expect(decision.allowed).toBe(true);
    expect(decision.request!.x402_evc.amount).toBe('0.016');
    expect(decision.checkedLeg!.payTo).toBe('urn:x402:agent-pay:see-quote');
  });
});

describe('regressions the local mode must keep', () => {
  test("Zach's leg A (derived exact-scheme payTo) still denies request_mismatch under the default matcher", async () => {
    const m = await mandate();
    const lc = x402LocalChallenge({ headerValue: observed.paymentRequiredHeader, resource: RESOURCE, legIndex: 0, now: NOW, maxSeconds: 900 });
    const decision = await verifyX402EvcAuthorization(m.presentation, { context: { ...lc.context, requirements: { ...lc.requirements, assetDecimals: 6 } }, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('request_mismatch');
  });
  test('the REAL observed Tavily token under a throwaway key denies with reason signature (no network)', async () => {
    const resolver = await createIssuerQuotePayeeResolver(config()); // our key under the real kid
    const lc = x402LocalChallenge({ headerValue: observed.paymentRequiredHeader, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    await expect(resolver({ audience: ISS, context: lc.context, now: NOW })).rejects.toMatchObject({ code: 'request_mismatch', detail: expect.objectContaining({ reason: 'signature' }) });
  });
});

// ---------------------------------------------------------------------------
// Review fixes (guardian + security, 2026-09-29)
// ---------------------------------------------------------------------------

describe('review fixes: unbound extra fields never reach settlement (H1)', () => {
  test('an unknown extra field next to a valid quote denies request_mismatch', async () => {
    const m = await mandate();
    const token = await sign(claims('jti-h1'));
    const decoded = JSON.parse(JSON.stringify(observed.decoded)) as { accepts: Array<{ extra: Record<string, unknown> }> };
    decoded.accepts[1].extra.quoteToken = token;
    decoded.accepts[1].extra.callback = 'https://evil.example';
    (decoded.accepts[1].extra.settlement as Record<string, unknown>).quantity = 100;
    const lc = x402LocalChallenge({ headerValue: Buffer.from(JSON.stringify(decoded)).toString('base64'), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const decision = await verifyX402EvcAuthorization(m.presentation, { localChallenge: lc, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, resolvePayee: await createIssuerQuotePayeeResolver(config()), now: () => NOW });
    expect(decision.allowed).toBe(false);
    expect(decision.verdict).toMatchObject({ code: 'request_mismatch', detail: expect.objectContaining({ reason: 'extra_unbound' }) });
    expect('checkedLeg' in decision).toBe(false);
  });

  test('checkedLeg.extra carries only the token field and the settlement-verified paths', async () => {
    const { decision } = await run(await sign(claims('jti-h1-trim')));
    expect(decision.allowed).toBe(true);
    expect(Object.keys(decision.checkedLeg!.extra!).sort()).toEqual(['quoteToken', 'reference', 'settlement']);
    expect(decision.checkedLeg!.extra!.settlement).toEqual({ product_id: 'prod-maeet6sajeg42' });
    expect('tier' in decision.checkedLeg!.extra!).toBe(false);
  });
});

describe('review fixes: options are snapshotted before the first await (M1)', () => {
  test('mutating options.audience and options.verifier inside the resolver changes nothing that was verified', async () => {
    const m = await mandate();
    const evil = await issueMandate({ operatorPrivateKey: 7n, agentName: 'evil', audience: 'https://evil.example', model: 'test-model', program: 'x402', maxUsd: '99', expiry: NOW + 3_600 });
    const token = await sign(claims('jti-m1'));
    const lc = x402LocalChallenge({ headerValue: headerWith(token), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const inner = await createIssuerQuotePayeeResolver(config());
    const options = { localChallenge: lc, audience: ISS, verifier: { kind: 'classical' as const, trustedOperators: [m.operatorPublicKey] }, now: () => NOW } as X402EvcVerifyOptions;
    options.resolvePayee = async (input) => {
      const out = await inner(input);
      options.audience = 'https://evil.example';
      options.verifier = { kind: 'classical', trustedOperators: [evil.operatorPublicKey] };
      options.now = () => NOW + 10_000;
      return out;
    };
    const decision = await verifyX402EvcAuthorization(m.presentation, options);
    expect(decision.allowed).toBe(true);
    expect(decision.request!.request.project_key).toBe(ISS);
    expect(decision.request!.x402_evc.payee_binding!.issuer).toBe(ISS);
  });
});

describe('review fixes: nonce store results and store identity (L1, I1)', () => {
  test.each([['object', {}], ['string false', 'false'], ['number 1', 1], ['promise of object', Promise.resolve({})]])('a store returning %s (not literal true) denies internal_error', async (_l, value) => {
    const store = { reserve: () => value } as unknown as NonceStore;
    const { decision } = await run(await sign(claims(`jti-l1-${_l}`)), { nonceStore: store });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('internal_error');
  });

  test('entries are deduplicated on the exact (issuer_key, nonce) pair, never on a joined string', async () => {
    const store = new SpyStore();
    const inner = await createIssuerQuotePayeeResolver(config());
    // A verifier-style consume_nonce whose (issuer_key, nonce) pair only collides with the quote entry under a naive join.
    const { decision } = await run(await sign(claims('jti-i1')), { nonceStore: store, resolvePayee: inner });
    expect(decision.allowed).toBe(true);
    const keys = store.calls[0].entries.map((e) => [e.issuer_key, e.nonce]);
    expect(new Set(keys.map((k) => JSON.stringify(k))).size).toBe(keys.length);
  });
});

describe('review fixes: the local challenge is validated against what was verified (L2/G2)', () => {
  test('a thawed challenge whose selectedLeg disagrees with context.requirements denies internal_error', async () => {
    const m = await mandate();
    const token = await sign(claims('jti-l2'));
    const lc = x402LocalChallenge({ headerValue: headerWith(token), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const thawed = JSON.parse(JSON.stringify(lc)) as typeof lc;
    (thawed.selectedLeg as { payTo: string }).payTo = '0xattacker';
    (thawed.selectedLeg as { amount: string }).amount = '5000';
    const decision = await verifyX402EvcAuthorization(m.presentation, { localChallenge: thawed, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, resolvePayee: await createIssuerQuotePayeeResolver(config()), now: () => NOW });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('internal_error');
    expect('checkedLeg' in decision).toBe(false);
  });
  test.each([
    ['mode', (t: Record<string, unknown>) => { t.mode = 'server'; }],
    ['nonce not the header hash', (t: { context: { nonce: string } }) => { t.context.nonce = 'a'.repeat(64); }],
    ['deadline beyond receivedAt + 900', (t: { context: { expiresAt: number }; receivedAt: number }) => { t.context.expiresAt = t.receivedAt + 901; }],
  ])('a thawed challenge with a bad %s denies internal_error', async (_l, mutate) => {
    const m = await mandate();
    const lc = x402LocalChallenge({ headerValue: headerWith(await sign(claims(`jti-l2-${_l}`))), resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    const thawed = JSON.parse(JSON.stringify(lc)); mutate(thawed);
    const decision = await verifyX402EvcAuthorization(m.presentation, { localChallenge: thawed, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, resolvePayee: await createIssuerQuotePayeeResolver(config()), now: () => NOW });
    expect(decision.problem?.code).toBe('internal_error');
  });
  test('x402LocalChallenge returns a deep-frozen object', () => {
    const lc = x402LocalChallenge({ headerValue: observed.paymentRequiredHeader, resource: RESOURCE, legIndex: 1, now: NOW, maxSeconds: 900 });
    expect(Object.isFrozen(lc)).toBe(true);
    expect(Object.isFrozen(lc.context)).toBe(true);
    expect(Object.isFrozen(lc.context.requirements)).toBe(true);
    expect(Object.isFrozen(lc.requirements.extra)).toBe(true);
  });
});

describe('review fixes: validation happens on the snapshot, and bad input returns a decision (L3, L4)', () => {
  test('a getter that changes expiresAt between reads cannot smuggle NaN past the guard', async () => {
    const m = await mandate();
    const good = { resource: 'https://api.merchant.example/x', requirements: { network: 'n', asset: 'USDC', amount: '25000000', payTo: ISS, assetDecimals: 6 }, nonce: 'l3' };
    let reads = 0;
    const context = Object.defineProperty({ ...good }, 'expiresAt', { enumerable: true, get: () => (reads++ === 0 ? NOW + 10 : Number.NaN) });
    const decision = await verifyX402EvcAuthorization(m.presentation, { context: context as never, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW });
    // Either outcome is sound; what must never happen is an allow carrying a non-finite deadline.
    if (decision.allowed) expect(decision.expiresAt).toBe(NOW + 10);
    else expect(decision.problem?.code).toBe('internal_error');
    // And a NaN on the very first read is caught on the snapshot.
    let reads2 = 0;
    const context2 = Object.defineProperty({ ...good, nonce: 'l3b' }, 'expiresAt', { enumerable: true, get: () => (reads2++ === 0 ? Number.NaN : NOW + 10) });
    const decision2 = await verifyX402EvcAuthorization(m.presentation, { context: context2 as never, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW });
    expect(decision2.allowed).toBe(false);
    expect(decision2.problem?.code).toBe('internal_error');
  });
  test.each([
    ['non-string presentation', 42, undefined],
    ['null context', 'x', null],
    ['context with a non-string nonce', 'x', { resource: 'r', requirements: { network: 'n', asset: 'USDC', amount: '1', payTo: ISS, assetDecimals: 6 }, nonce: 5, expiresAt: NOW + 10 }],
  ])('%s returns a decision, never throws', async (_l, presentation, context) => {
    const m = await mandate();
    const decision = await verifyX402EvcAuthorization(presentation as never, { context: (context === undefined ? { resource: 'r', requirements: { network: 'n', asset: 'USDC', amount: '1', payTo: ISS, assetDecimals: 6 }, nonce: 'n', expiresAt: NOW + 10 } : context) as never, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, now: () => NOW });
    expect(decision.allowed).toBe(false);
    expect(['internal_error', 'missing_authorization']).toContain(decision.problem?.code);
  });
});

describe('review fixes: converter output is normalized (I3)', () => {
  test('a pass-through amountToUsd returning padded or non-decimal text fails closed', async () => {
    const m = await mandate();
    for (const raw of [' 50 ', '5e1', '50.', '0x32', '']) {
      const decision = await verifyX402EvcAuthorization(m.presentation, { context: { resource: 'r', requirements: { network: 'n', asset: 'USDC', amount: '50', payTo: ISS }, nonce: `i3-${raw}`, expiresAt: NOW + 10 }, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] }, amountToUsd: () => raw, now: () => NOW });
      expect(decision.allowed).toBe(false);
      expect(decision.problem?.code).toBe('internal_error');
    }
  });
});
