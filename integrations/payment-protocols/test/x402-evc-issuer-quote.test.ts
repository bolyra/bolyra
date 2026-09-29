/**
 * Issuer-quoted payee binding resolver (spec §4.2). Offline: keys are
 * generated in-process, quotes are signed here, and no network is reachable
 * (see the isolation gate in the plan). The Tavily agent-pay shape observed
 * 2026-09-29 is the reference configuration.
 */
import { SignJWT, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { createHash } from 'node:crypto';

import { createIssuerQuotePayeeResolver, type IssuerQuoteConfig, type PayeeResolver } from '../src/x402-issuer-quote';
import type { X402EvcContext, X402EvcRequirements } from '../src/x402-evc';

const NOW = 1_790_697_736;
const ISS = 'https://x402.tavily.com';
const KID = 'tavily-agentpay-x402-signing-key';
const RESOURCE = 'https://x402.tavily.com/search';
const PLACEHOLDER = 'urn:x402:agent-pay:see-quote';
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

let es384: { privateKey: CryptoKey; publicJwk: JWK };
let es256: { privateKey: CryptoKey; publicJwk: JWK };
let other384: { privateKey: CryptoKey; publicJwk: JWK };

// In-process network sanity spies: the resolver must never reach for a key
// or anything else over the network. The authoritative isolation gate is the
// --network none container run (see the plan's Verification section).
/* eslint-disable @typescript-eslint/no-var-requires */
const nodeHttp = require('node:http') as typeof import('node:http');
const nodeHttps = require('node:https') as typeof import('node:https');
const nodeNet = require('node:net') as typeof import('node:net');
const nodeTls = require('node:tls') as typeof import('node:tls');
const nodeDns = require('node:dns') as typeof import('node:dns');
/* eslint-enable @typescript-eslint/no-var-requires */
const networkCalls: string[] = [];
const blocked = (name: string) => (...args: unknown[]): never => { networkCalls.push(`${name}(${String(args[0]).slice(0, 40)})`); throw new Error(`network call attempted: ${name}`); };
const originalFetch = globalThis.fetch;
beforeAll(() => {
  (globalThis as { fetch: unknown }).fetch = blocked('fetch');
  jest.spyOn(nodeHttp, 'request').mockImplementation(blocked('http.request') as never);
  jest.spyOn(nodeHttp, 'get').mockImplementation(blocked('http.get') as never);
  jest.spyOn(nodeHttps, 'request').mockImplementation(blocked('https.request') as never);
  jest.spyOn(nodeHttps, 'get').mockImplementation(blocked('https.get') as never);
  jest.spyOn(nodeNet, 'connect').mockImplementation(blocked('net.connect') as never);
  jest.spyOn(nodeNet, 'createConnection').mockImplementation(blocked('net.createConnection') as never);
  jest.spyOn(nodeTls, 'connect').mockImplementation(blocked('tls.connect') as never);
  jest.spyOn(nodeDns, 'lookup').mockImplementation(blocked('dns.lookup') as never);
});
afterAll(() => {
  (globalThis as { fetch: unknown }).fetch = originalFetch;
  jest.restoreAllMocks();
  expect(networkCalls).toEqual([]);
});

beforeAll(async () => {
  const mk = async (alg: 'ES256' | 'ES384') => {
    const kp = await generateKeyPair(alg, { extractable: true });
    return { privateKey: kp.privateKey as CryptoKey, publicJwk: await exportJWK(kp.publicKey) };
  };
  es384 = await mk('ES384');
  es256 = await mk('ES256');
  other384 = await mk('ES384');
});

const baseClaims = () => ({
  iss: ISS, aud: 'aws:marketplace', iat: NOW, exp: NOW + 300, jti: 'c75e4e72-0fa1-4be0-97d3-d00b6b9fc156',
  price: { amount: '0.016', currency: 'USD' }, payTo: 'seller', reference: 'tavily-search-advanced',
  settlement: { product_id: 'prod-maeet6sajeg42' },
});

async function sign(claims: Record<string, unknown>, opts: { alg?: 'ES256' | 'ES384'; kid?: string; key?: CryptoKey; typ?: string | null } = {}) {
  const alg = opts.alg ?? 'ES384';
  const header: Record<string, unknown> = { alg, kid: opts.kid ?? KID };
  if (opts.typ !== null) header.typ = opts.typ ?? 'JWT';
  return new SignJWT(claims as Record<string, unknown>).setProtectedHeader(header as { alg: string }).sign(opts.key ?? es384.privateKey);
}

function issuerConfig(overrides: Partial<IssuerQuoteConfig['issuers'] extends Map<string, infer V> ? V : never> = {}) {
  return {
    payTo: PLACEHOLDER, scheme: 'agent-pay', network: 'aws:base', audience: 'aws:marketplace', payToRole: 'seller',
    keys: new Map([[KID, { alg: 'ES384' as const, jwk: es384.publicJwk }]]),
    products: new Map([[RESOURCE, { reference: 'tavily-search-advanced', 'settlement.product_id': 'prod-maeet6sajeg42' }]]),
    settlementFields: [
      { challenge: 'extra.reference', claim: 'reference' },
      { challenge: 'extra.settlement.product_id', claim: 'settlement.product_id' },
    ],
    ...overrides,
  };
}

function config(overrides: Partial<IssuerQuoteConfig> = {}, issuerOverrides = {}): IssuerQuoteConfig {
  return { issuers: new Map([[ISS, issuerConfig(issuerOverrides)]]), ...overrides };
}

function requirements(token: string, overrides: Partial<X402EvcRequirements> = {}, extraOverrides: Record<string, unknown> = {}): X402EvcRequirements {
  return {
    scheme: 'agent-pay', network: 'aws:base', asset: 'iso4217:USD', amount: '0.016', payTo: PLACEHOLDER,
    extra: { reference: 'tavily-search-advanced', settlement: { product_id: 'prod-maeet6sajeg42' }, tier: 'advanced', quoteToken: token, ...extraOverrides },
    ...overrides,
  };
}

function context(reqs: X402EvcRequirements, overrides: Partial<X402EvcContext> = {}): X402EvcContext {
  return { resource: RESOURCE, requirements: reqs, nonce: 'local-nonce', expiresAt: NOW + 300, ...overrides };
}

async function resolve(resolver: PayeeResolver, reqs: X402EvcRequirements, opts: { audience?: string; now?: number; context?: Partial<X402EvcContext> } = {}) {
  return resolver({ audience: opts.audience ?? ISS, context: context(reqs, opts.context), now: opts.now ?? NOW });
}

const denies = (p: Promise<unknown>, reason: string) =>
  expect(p).rejects.toMatchObject({ code: 'request_mismatch', detail: expect.objectContaining({ reason }) });

describe('createIssuerQuotePayeeResolver: allow path', () => {
  test('a valid ES384 quote binds the placeholder payee to its issuer', async () => {
    const resolver = await createIssuerQuotePayeeResolver(config());
    const token = await sign(baseClaims());
    const out = await resolve(resolver, requirements(token));
    expect(out.binding).toEqual({ kind: 'issuer_quote', issuer: ISS, kid: KID, jti: baseClaims().jti, exp: NOW + 300, token_sha256: sha(token) });
    expect(out.acceptUntil).toBe(NOW + 300 + 60);
  });

  test('a valid ES256 quote against an ES256 key also binds', async () => {
    const resolver = await createIssuerQuotePayeeResolver(config({}, { keys: new Map([[KID, { alg: 'ES256', jwk: es256.publicJwk }]]) }));
    const out = await resolve(resolver, requirements(await sign(baseClaims(), { alg: 'ES256', key: es256.privateKey })));
    expect(out.binding.kind).toBe('issuer_quote');
  });

  test('clockSkewSeconds widens acceptUntil and exp tolerance exactly', async () => {
    const resolver = await createIssuerQuotePayeeResolver(config({ clockSkewSeconds: 10 }));
    const token = await sign(baseClaims());
    expect((await resolve(resolver, requirements(token), { now: NOW + 309 })).acceptUntil).toBe(NOW + 310);
    await denies(resolve(resolver, requirements(token), { now: NOW + 311 }), 'exp');
  });

  test('typ absent is accepted; typ JWT is accepted', async () => {
    const resolver = await createIssuerQuotePayeeResolver(config());
    await expect(resolve(resolver, requirements(await sign(baseClaims(), { typ: null })))).resolves.toBeDefined();
  });
});

describe('createIssuerQuotePayeeResolver: creation rejects bad configuration', () => {
  const rejects = (cfg: IssuerQuoteConfig, reason: string) =>
    expect(createIssuerQuotePayeeResolver(cfg)).rejects.toMatchObject({ code: 'internal_error', detail: expect.objectContaining({ reason }) });

  test('private key material in a JWK', async () => {
    const kp = await generateKeyPair('ES384', { extractable: true });
    const priv = await exportJWK(kp.privateKey);
    await rejects(config({}, { keys: new Map([[KID, { alg: 'ES384', jwk: priv }]]) }), 'jwk_private');
  });
  test('curve and alg disagree', () => rejects(config({}, { keys: new Map([[KID, { alg: 'ES384', jwk: es256.publicJwk }]]) }), 'jwk_curve'));
  test('conflicting jwk.alg metadata', () => rejects(config({}, { keys: new Map([[KID, { alg: 'ES384', jwk: { ...es384.publicJwk, alg: 'ES256' } }]]) }), 'jwk_alg'));
  test('jwk use other than sig', () => rejects(config({}, { keys: new Map([[KID, { alg: 'ES384', jwk: { ...es384.publicJwk, use: 'enc' } }]]) }), 'jwk_use'));
  test('jwk key_ops without verify', () => rejects(config({}, { keys: new Map([[KID, { alg: 'ES384', jwk: { ...es384.publicJwk, key_ops: ['sign'] } }]]) }), 'jwk_key_ops'));
  test('no keys', () => rejects(config({}, { keys: new Map() }), 'keys'));
  test('empty products', () => rejects(config({}, { products: new Map() }), 'products'));
  test('empty product record', () => rejects(config({}, { products: new Map([[RESOURCE, {}]]) }), 'products'));
  test('non-primitive product expectation', () => rejects(config({}, { products: new Map([[RESOURCE, { reference: { a: 1 } as unknown as string }]]) }), 'products'));
  test('prototype segment in a product path', () => rejects(config({}, { products: new Map([[RESOURCE, { '__proto__.x': 'y' }]]) }), 'products'));
  test('missing settlementFields', () => rejects(config({}, { settlementFields: undefined as unknown as [] }), 'settlement_fields'));
  test('empty settlementFields', () => rejects(config({}, { settlementFields: [] }), 'settlement_fields'));
  test('duplicate settlementFields', () => rejects(config({}, { settlementFields: [{ challenge: 'extra.reference', claim: 'reference' }, { challenge: 'extra.reference', claim: 'reference' }] }), 'settlement_fields'));
  test('prototype segment in a settlement path', () => rejects(config({}, { settlementFields: [{ challenge: 'extra.constructor', claim: 'reference' }] }), 'settlement_fields'));
  test('NUL in an identifier', () => rejects(config({}, { payToRole: 'sel\0ler' }), 'identifier'));
  test('oversized identifier', () => rejects(config({}, { audience: 'a'.repeat(257) }), 'identifier'));
  test('empty payToRole', () => rejects(config({}, { payToRole: '' }), 'identifier'));
  test('missing token audience', () => rejects(config({}, { audience: undefined as unknown as string }), 'identifier'));
  test('clockSkewSeconds out of range', () => rejects(config({ clockSkewSeconds: 301 }), 'clock_skew'));
  test('non-finite clockSkewSeconds', () => rejects(config({ clockSkewSeconds: Number.NaN }), 'clock_skew'));
  test('maxLifetimeSeconds above 900', () => rejects(config({}, { maxLifetimeSeconds: 901 }), 'max_lifetime'));
  test('empty issuers map', () => rejects({ issuers: new Map() }, 'issuers'));
  test('issuer key that is not a string', () => rejects({ issuers: new Map([[5 as unknown as string, issuerConfig()]]) }, 'identifier'));
});

describe('createIssuerQuotePayeeResolver: rail, placeholder, resource', () => {
  let resolver: PayeeResolver; let token: string;
  beforeAll(async () => { resolver = await createIssuerQuotePayeeResolver(config()); token = await sign(baseClaims()); });

  test('audience not configured as an issuer', () => denies(resolve(resolver, requirements(token), { audience: 'https://other.example' }), 'issuer_unknown'));
  test('payTo is not the configured placeholder', () => denies(resolve(resolver, requirements(token, { payTo: '0xabc' })), 'pay_to'));
  test('scheme mismatch', () => denies(resolve(resolver, requirements(token, { scheme: 'exact' })), 'scheme'));
  test('scheme missing', () => denies(resolve(resolver, requirements(token, { scheme: undefined })), 'scheme'));
  test('network mismatch', () => denies(resolve(resolver, requirements(token, { network: 'eip155:8453' })), 'network'));
  test('resource not in products', () => denies(resolve(resolver, requirements(token), { context: { resource: 'https://x402.tavily.com/other' } }), 'resource'));
  test('non-ISO asset', () => denies(resolve(resolver, requirements(token, { asset: '0x8335…' })), 'asset'));
});

describe('createIssuerQuotePayeeResolver: token presence and JWS-layer rejections', () => {
  let resolver: PayeeResolver;
  beforeAll(async () => { resolver = await createIssuerQuotePayeeResolver(config()); });

  test('no extra at all', () => denies(resolve(resolver, requirements('x', { extra: undefined })), 'token_missing'));
  test('token missing from extra', () => denies(resolve(resolver, { ...requirements('x'), extra: { reference: 'tavily-search-advanced' } }), 'token_missing'));
  test('token not a string', () => denies(resolve(resolver, requirements(42 as unknown as string)), 'token_missing'));
  test('custom tokenField is honoured', async () => {
    const r = await createIssuerQuotePayeeResolver(config({ tokenField: 'quote' }));
    const token = await sign(baseClaims());
    const reqs = requirements('ignored'); delete (reqs.extra as Record<string, unknown>).quoteToken; (reqs.extra as Record<string, unknown>).quote = token;
    await expect(resolve(r, reqs)).resolves.toBeDefined();
  });
  test('alg none', () => denies(resolve(resolver, requirements(`${Buffer.from('{"alg":"none","kid":"k"}').toString('base64url')}.e30.AA`)), 'jws_alg'));
  test('unknown kid', async () => denies(resolve(resolver, requirements(await sign(baseClaims(), { kid: 'other-key' }))), 'kid'));
  test('kid belonging to another issuer', async () => {
    const two = config(); two.issuers.set('https://issuer-two.example', issuerConfig({ keys: new Map([['two-key', { alg: 'ES384', jwk: other384.publicJwk }]]) }));
    const r = await createIssuerQuotePayeeResolver(two);
    await denies(resolve(r, requirements(await sign(baseClaims(), { kid: 'two-key', key: other384.privateKey }))), 'kid');
  });
  test('ES256-signed token against an ES384 key', async () => denies(resolve(resolver, requirements(await sign(baseClaims(), { alg: 'ES256', key: es256.privateKey }))), 'jws_alg'));
  test('signature by a different key', async () => denies(resolve(resolver, requirements(await sign(baseClaims(), { key: other384.privateKey }))), 'signature'));
  test('tampered payload', async () => {
    const [h, , s] = (await sign(baseClaims())).split('.');
    const p = Buffer.from(JSON.stringify({ ...baseClaims(), price: { amount: '0.001', currency: 'USD' } })).toString('base64url');
    await denies(resolve(resolver, requirements(`${h}.${p}.${s}`)), 'signature');
  });
  test('crit header', async () => {
    const token = await new SignJWT(baseClaims()).setProtectedHeader({ alg: 'ES384', kid: KID, crit: ['exp'], exp: true } as never).sign(es384.privateKey).catch(() => null);
    if (token) await denies(resolve(resolver, requirements(token)), 'jws_crit');
  });
});

describe('createIssuerQuotePayeeResolver: claims policy', () => {
  let resolver: PayeeResolver;
  beforeAll(async () => { resolver = await createIssuerQuotePayeeResolver(config()); });
  const withClaims = async (patch: Record<string, unknown>) => requirements(await sign({ ...baseClaims(), ...patch }));
  const without = async (name: string) => { const c: Record<string, unknown> = baseClaims(); delete c[name]; return requirements(await sign(c)); };

  test('iss differs from the host audience', async () => denies(resolve(resolver, await withClaims({ iss: 'https://evil.example' })), 'iss'));
  test('aud mismatch', async () => denies(resolve(resolver, await withClaims({ aud: 'other-rail' })), 'aud'));
  test('aud missing', async () => denies(resolve(resolver, await without('aud')), 'aud'));
  test('expired beyond skew', async () => denies(resolve(resolver, await withClaims({ exp: NOW - 61 })), 'exp'));
  test('nbf in the future beyond skew', async () => denies(resolve(resolver, await withClaims({ nbf: NOW + 61 })), 'nbf'));
  test('nbf within skew is accepted', async () => expect(resolve(resolver, await withClaims({ nbf: NOW + 59 }))).resolves.toBeDefined());
  test('iat in the future beyond skew', async () => denies(resolve(resolver, await withClaims({ iat: NOW + 61, exp: NOW + 361 })), 'iat'));
  test('iat within skew is accepted', async () => expect(resolve(resolver, await withClaims({ iat: NOW + 59, exp: NOW + 359 }))).resolves.toBeDefined());
  test('iat equal to exp', async () => denies(resolve(resolver, await withClaims({ iat: NOW, exp: NOW })), 'lifetime'));
  test('iat after exp', async () => denies(resolve(resolver, await withClaims({ iat: NOW + 10, exp: NOW })), 'lifetime'));
  test('lifetime over the default 300 s max', async () => denies(resolve(resolver, await withClaims({ iat: NOW - 10, exp: NOW + 291 })), 'lifetime'));
  test('lifetime up to a configured max is accepted', async () => {
    const r = await createIssuerQuotePayeeResolver(config({}, { maxLifetimeSeconds: 600 }));
    await expect(resolve(r, await withClaims({ iat: NOW, exp: NOW + 600 }))).resolves.toBeDefined();
  });
  test.each(['iat', 'exp', 'jti', 'price', 'payTo'])('missing %s', async (name) => denies(resolve(resolver, await without(name)), 'claims'));
  test('iat not a number', async () => denies(resolve(resolver, await withClaims({ iat: String(NOW) })), 'claims'));
  test('exp not representable', async () => denies(resolve(resolver, await withClaims({ exp: 1e300 })), 'claims'));
  test('jti empty', async () => denies(resolve(resolver, await withClaims({ jti: '' })), 'jti'));
  test('jti oversized', async () => denies(resolve(resolver, await withClaims({ jti: 'j'.repeat(257) })), 'jti'));
  test('jti containing NUL', async () => denies(resolve(resolver, await withClaims({ jti: 'a\0b' })), 'jti'));
  test('jti not a string', async () => denies(resolve(resolver, await withClaims({ jti: 12 })), 'jti'));
  test('payTo role mismatch', async () => denies(resolve(resolver, await withClaims({ payTo: 'buyer' })), 'pay_to_role'));
  test('price.amount mismatch', async () => denies(resolve(resolver, await withClaims({ price: { amount: '0.017', currency: 'USD' } })), 'price'));
  test('price.currency mismatch', async () => denies(resolve(resolver, await withClaims({ price: { amount: '0.016', currency: 'EUR' } })), 'price'));
  test('price not an object', async () => denies(resolve(resolver, await withClaims({ price: '0.016' })), 'claims'));
  test('product claim missing', async () => denies(resolve(resolver, await without('reference')), 'product'));
  test('product claim wrong type', async () => denies(resolve(resolver, await withClaims({ reference: 7 })), 'product'));
  test('product claim unequal', async () => denies(resolve(resolver, await withClaims({ reference: 'tavily-search-basic' })), 'product'));
  test('nested product claim unequal', async () => denies(resolve(resolver, await withClaims({ settlement: { product_id: 'prod-other' } })), 'product'));
});

describe('createIssuerQuotePayeeResolver: settlementFields bind the challenge to the authenticated claims', () => {
  let resolver: PayeeResolver; let token: string;
  beforeAll(async () => { resolver = await createIssuerQuotePayeeResolver(config()); token = await sign(baseClaims()); });

  test('altered extra.reference with a valid quote', () => denies(resolve(resolver, requirements(token, {}, { reference: 'tavily-search-basic' })), 'settlement'));
  test('altered extra.settlement.product_id with a valid quote', () => denies(resolve(resolver, requirements(token, {}, { settlement: { product_id: 'prod-other' } })), 'settlement'));
  test('challenge-side field missing', () => denies(resolve(resolver, requirements(token, {}, { settlement: {} })), 'settlement'));
  test('challenge-side field of the wrong type', () => denies(resolve(resolver, requirements(token, {}, { reference: ['tavily-search-advanced'] })), 'settlement'));
});
