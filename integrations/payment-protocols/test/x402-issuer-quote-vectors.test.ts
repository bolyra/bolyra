/**
 * Full-profile fixtures signed INDEPENDENTLY by OpenSSL (scripts/gen-issuer-
 * quote-vectors.sh), one ES256 and one ES384. Each must allow through the
 * resolver AND through the full local-mode verify.
 */
import { issueMandate } from '@bolyra/mpp';

import { verifyX402EvcAuthorization } from '../src/x402-evc';
import { x402LocalChallenge } from '../src/x402-local-challenge';
import { createIssuerQuotePayeeResolver, type IssuerQuoteConfig, type JwsAlg } from '../src/x402-issuer-quote';
import observed from './fixtures/x402-issuer-quote/tavily-challenge-observed.json';
import es256 from './fixtures/x402-issuer-quote/openssl-ES256.json';
import es384 from './fixtures/x402-issuer-quote/openssl-ES384.json';

const ISS = 'https://x402.tavily.com';
const RESOURCE = 'https://x402.tavily.com/search';

function configFor(f: typeof es256): IssuerQuoteConfig {
  return { issuers: new Map([[ISS, {
    payTo: 'urn:x402:agent-pay:see-quote', scheme: 'agent-pay', network: 'aws:base', audience: 'aws:marketplace', payToRole: 'seller',
    keys: new Map([[f.kid, { alg: f.alg as JwsAlg, jwk: f.publicJwk }]]),
    products: new Map([[RESOURCE, { reference: 'tavily-search-advanced', 'settlement.product_id': 'prod-maeet6sajeg42' }]]),
    settlementFields: [{ challenge: 'extra.reference', claim: 'reference' }, { challenge: 'extra.settlement.product_id', claim: 'settlement.product_id' }],
  }]]) };
}

function headerWith(token: string) {
  const decoded = JSON.parse(JSON.stringify(observed.decoded)) as { accepts: Array<Record<string, unknown>> };
  (decoded.accepts[1].extra as Record<string, unknown>).quoteToken = token;
  return Buffer.from(JSON.stringify(decoded)).toString('base64');
}

describe.each([['ES256', es256], ['ES384', es384]] as const)('openssl-signed %s fixture', (_alg, fixture) => {
  test('the resolver binds it', async () => {
    const resolver = await createIssuerQuotePayeeResolver(configFor(fixture));
    const lc = x402LocalChallenge({ headerValue: headerWith(fixture.compact), resource: RESOURCE, legIndex: 1, now: fixture.now, maxSeconds: 900 });
    const out = await resolver({ audience: ISS, context: lc.context, now: fixture.now });
    expect(out.binding).toMatchObject({ kind: 'issuer_quote', issuer: ISS, kid: fixture.kid, jti: fixture.claims.jti, exp: fixture.claims.exp });
  });

  test('the full local-mode verify allows it', async () => {
    const m = await issueMandate({ operatorPrivateKey: 42n, agentName: 'search-agent', audience: ISS, model: 'test-model', program: 'x402', maxUsd: '99', expiry: fixture.now + 3_600 });
    const lc = x402LocalChallenge({ headerValue: headerWith(fixture.compact), resource: RESOURCE, legIndex: 1, now: fixture.now, maxSeconds: 900 });
    const decision = await verifyX402EvcAuthorization(m.presentation, {
      localChallenge: lc, audience: ISS, verifier: { kind: 'classical', trustedOperators: [m.operatorPublicKey] },
      resolvePayee: await createIssuerQuotePayeeResolver(configFor(fixture)), now: () => fixture.now,
    });
    expect(decision.allowed).toBe(true);
    expect(decision.request!.x402_evc.payee_binding?.kid).toBe(fixture.kid);
    expect(decision.checkedLeg?.payTo).toBe('urn:x402:agent-pay:see-quote');
  });
});
