import test from 'node:test';
import assert from 'node:assert/strict';
import { Challenge, Credential, Receipt } from 'mppx';
import { BOLYRA_AUTHORIZATION_HEADER, issueMandate, parseBundle } from '@bolyra/mpp';
import { AUDIENCE, MODEL, PAYMENT_TOKEN, chargeMethod, createServer } from '../src/server.js';

const OPERATOR_PRIVATE_KEY = 42n; // test-only scalar, never a real key
const EXPIRY = Math.floor(Date.now() / 1000) + 3600;
const VERIFIER = { url: 'https://verify.test', token: 'verifier-token-0000000000000000000000' };
const ROUTE = `https://${AUDIENCE}/api/report`;
const NOT_ACTIVE_ID = 'ab'.repeat(32);

const issue = () =>
  issueMandate({ operatorPrivateKey: OPERATOR_PRIVATE_KEY, agentName: 'unit-agent', audience: AUDIENCE, model: MODEL, tier: 'small', expiry: EXPIRY });

/**
 * Stand in for the hosted verifier: answer POST …/v1/verify the way hosted-verify does —
 * an allow whose consume_nonces come from the presented bundle, or the not-active deny.
 */
function stubVerifier(mode: 'active' | 'not_active'): { calls: number; restore: () => void } {
  const real = globalThis.fetch;
  const stub = { calls: 0, restore: () => { globalThis.fetch = real; } };
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url !== `${VERIFIER.url}/v1/verify`) throw new Error(`unexpected fetch ${url}`);
    stub.calls += 1;
    const body = JSON.parse(String(init?.body)) as { bundle: string };
    const p = parseBundle(body.bundle);
    if (mode === 'not_active') {
      return Response.json({
        verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active',
        detail: { reason: 'credential_not_active', credential_id: NOT_ACTIVE_ID },
      });
    }
    const { x, y } = p.agent.credential.operator_pubkey;
    return Response.json({
      verdict: 'allow', kind: 'classical',
      consume_nonces: [{ issuer_key: `${x}:${y}`, nonce: p.agent.envelope.publicSignals[1], retain_until: p.binding.expiry }],
    });
  }) as typeof fetch;
  return stub;
}

function discovery(presentation: string): Request {
  return new Request(ROUTE, { headers: { [BOLYRA_AUTHORIZATION_HEADER]: presentation } });
}

function paidRetry(challenge402: Response, presentation: string): Request {
  const challenge = Challenge.fromResponse(challenge402, { methods: [chargeMethod] });
  const credential = Credential.from({ challenge, payload: { token: PAYMENT_TOKEN } });
  return new Request(ROUTE, {
    headers: { [BOLYRA_AUTHORIZATION_HEADER]: presentation, authorization: Credential.serialize(credential) },
  });
}

test('a 402→pay handshake with two fresh presentations runs the action once; the paid receipt names the url verifier', async () => {
  const stub = stubVerifier('active');
  try {
    const server = createServer(VERIFIER);
    const a = await issue();
    const b = await issue();

    const first = await server.handler(discovery(a.presentation));
    assert.equal(first.status, 402);
    assert.equal(server.state.counter, 0);
    assert.equal(stub.calls, 1, 'the discovery attempt already ran the gate');

    const paid = await server.handler(paidRetry(first, b.presentation));
    assert.equal(paid.status, 200);
    assert.equal(server.state.counter, 1);
    assert.equal(stub.calls, 2);
    const receipt = Receipt.deserialize(paid.headers.get('Payment-Receipt') ?? '') as {
      bolyraAuthorization?: { verifier?: string; tier?: string };
    };
    assert.equal(receipt.bolyraAuthorization?.verifier, 'url');
    assert.equal(receipt.bolyraAuthorization?.tier, 'small');
  } finally {
    stub.restore();
  }
});

test('re-sending the discovery presentation on the paid retry is a replay: 403 nonce_replayed, the action never runs', async () => {
  const stub = stubVerifier('active');
  try {
    const server = createServer(VERIFIER);
    const a = await issue();
    const first = await server.handler(discovery(a.presentation));
    assert.equal(first.status, 402);
    const replay = await server.handler(paidRetry(first, a.presentation));
    assert.equal(replay.status, 403);
    assert.equal(((await replay.json()) as { code?: string }).code, 'nonce_replayed');
    assert.equal(server.state.counter, 0);
    assert.equal(server.state.lastDenial?.code, 'nonce_replayed');
  } finally {
    stub.restore();
  }
});

test('a not-active verdict denies before any 402: 401 untrusted_root, counter 0, and the structured detail is kept in-process', async () => {
  const stub = stubVerifier('not_active');
  try {
    const server = createServer(VERIFIER);
    const a = await issue();
    const res = await server.handler(discovery(a.presentation));
    assert.equal(res.status, 401);
    assert.match(res.headers.get('content-type') ?? '', /^application\/problem\+json/);
    const problem = (await res.json()) as { code?: string; detail?: unknown };
    assert.equal(problem.code, 'untrusted_root');
    assert.equal(typeof problem.detail, 'string', 'the HTTP body carries the verdict message, not the structured detail');
    assert.equal(server.state.counter, 0);
    assert.equal(stub.calls, 1);
    assert.deepEqual(server.state.lastDenial?.detail, { reason: 'credential_not_active', credential_id: NOT_ACTIVE_ID });
  } finally {
    stub.restore();
  }
});
