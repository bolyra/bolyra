import test from 'node:test';
import assert from 'node:assert/strict';
import { Receipt } from 'mppx';
import { issueMandate, parseBundle } from '@bolyra/mpp';
import { AUDIENCE, MODEL, createServer } from '../src/server.js';
import { ROUTE, discoveryRequest, paidRetryRequest } from '../src/client.js';

const OPERATOR_PRIVATE_KEY = 42n; // test-only scalar, never a real key
const EXPIRY = Math.floor(Date.now() / 1000) + 3600;
const VERIFIER = { url: 'https://verify.test', token: 'verifier-token-0000000000000000000000' };
const NOT_ACTIVE_ID = 'ab'.repeat(32);
const NOT_ACTIVE_MESSAGE = "the presented binding is not an active credential in this tenant's registry";

const issue = () =>
  issueMandate({ operatorPrivateKey: OPERATOR_PRIVATE_KEY, agentName: 'unit-agent', audience: AUDIENCE, model: MODEL, tier: 'small', expiry: EXPIRY });

/** One captured POST to the stub — enough to assert the VerifierRequest the gate sends. */
interface VerifierCall {
  authorization: string | null;
  body: { version?: unknown; bundle: string; request?: Record<string, unknown>; now_unix?: unknown };
}

/**
 * Stand in for the hosted verifier: answer POST …/v1/verify the way hosted-verify does —
 * an allow whose consume_nonces come from the presented bundle's revealed credential, or
 * the not-active deny — and record every call.
 */
function stubVerifier(mode: 'active' | 'not_active'): { calls: VerifierCall[]; restore: () => void } {
  const real = globalThis.fetch;
  const calls: VerifierCall[] = [];
  const stub: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (url !== `${VERIFIER.url}/v1/verify`) throw new Error(`unexpected fetch ${url}`);
    const body = JSON.parse(String(init?.body)) as VerifierCall['body'];
    calls.push({ authorization: new Headers(init?.headers).get('authorization'), body });
    const p = parseBundle(body.bundle);
    if (mode === 'not_active') {
      return Response.json({
        verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: NOT_ACTIVE_MESSAGE,
        detail: { reason: 'credential_not_active', credential_id: NOT_ACTIVE_ID },
      });
    }
    const { operator_pubkey: { x, y }, expiry } = p.agent.credential;
    return Response.json({
      verdict: 'allow', kind: 'classical',
      consume_nonces: [{ issuer_key: `${x}:${y}`, nonce: p.agent.envelope.publicSignals[1], retain_until: expiry }],
    });
  };
  globalThis.fetch = stub;
  return { calls, restore: () => { globalThis.fetch = real; } };
}

test('a 402→pay handshake with two fresh presentations runs the action once; the paid receipt names the url verifier', async () => {
  const stub = stubVerifier('active');
  try {
    const server = createServer(VERIFIER);
    const a = await issue();
    const b = await issue();

    const first = await server.handler(discoveryRequest(a.presentation));
    assert.equal(first.status, 402);
    assert.equal(server.state.counter, 0);
    assert.equal(stub.calls.length, 1, 'the discovery attempt already ran the gate');
    assert.equal(stub.calls[0]?.authorization, `Bearer ${VERIFIER.token}`, 'the hosted verifier gets its tenant token');
    assert.equal(stub.calls[0]?.body.version, 1);
    assert.equal(typeof stub.calls[0]?.body.now_unix, 'number');
    assert.deepEqual(stub.calls[0]?.body.request, {
      agent_name: 'unit-agent',
      project_key: AUDIENCE,
      program: 'mpp',
      model: MODEL,
      granted_capabilities: ['mpp:financial:small'],
    });

    const paid = await server.handler(paidRetryRequest(first, b.presentation));
    assert.equal(paid.status, 200);
    assert.equal(server.state.counter, 1);
    assert.equal(server.state.lastDenial, undefined);
    assert.equal(stub.calls.length, 2);
    const encoded = paid.headers.get('Payment-Receipt');
    assert.ok(encoded, 'the paid response carries a Payment-Receipt header');
    const receipt = Receipt.deserialize(encoded) as {
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
    const first = await server.handler(discoveryRequest(a.presentation));
    assert.equal(first.status, 402);
    const replay = await server.handler(paidRetryRequest(first, a.presentation));
    assert.equal(replay.status, 403);
    assert.equal(stub.calls.length, 2, 'the replay reached the verifier; the gate, not the stub, denied it');
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
    const res = await server.handler(discoveryRequest(a.presentation));
    assert.equal(res.status, 401);
    assert.match(res.headers.get('content-type') ?? '', /^application\/problem\+json/);
    const problem = (await res.json()) as { code?: string; detail?: unknown; reason?: unknown; credential_id?: unknown };
    assert.equal(problem.code, 'untrusted_root');
    assert.equal(problem.detail, NOT_ACTIVE_MESSAGE, 'the HTTP body carries the verdict message, not the structured detail');
    assert.equal(problem.reason, 'credential_not_active', '0.7.0 copies an identifier-shaped reason into the body');
    assert.equal(problem.credential_id, NOT_ACTIVE_ID);
    assert.equal(server.state.counter, 0);
    assert.equal(stub.calls.length, 1);
    assert.deepEqual(server.state.lastDenial?.detail, { reason: 'credential_not_active', credential_id: NOT_ACTIVE_ID });
    const decision = server.state.lastDecision;
    assert.equal(decision?.outcome, 'deny', 'onDecision recorded the deny');
    if (decision?.outcome !== 'deny') return;
    assert.equal(decision.code, 'untrusted_root');
    assert.equal(decision.status, 401);
    assert.equal(decision.reason, 'credential_not_active');
    assert.equal(decision.credentialId, NOT_ACTIVE_ID);
  } finally {
    stub.restore();
  }
});

test('no presentation at all denies before any 402: 401 missing_authorization, the verifier is never called', async () => {
  const stub = stubVerifier('active');
  try {
    const server = createServer(VERIFIER);
    const res = await server.handler(new Request(ROUTE));
    assert.equal(res.status, 401);
    assert.equal(((await res.json()) as { code?: string }).code, 'missing_authorization');
    assert.equal(server.state.counter, 0);
    assert.equal(stub.calls.length, 0, "enforce:'always' denies before the verifier round-trip");
  } finally {
    stub.restore();
  }
});

test('onDecision records an allow, and the recorded decision is cleared at the start of the next request', async () => {
  const stub = stubVerifier('active');
  try {
    const server = createServer(VERIFIER);
    // Read through a function so each read sees the state after the request, not a narrowed copy.
    const recorded = () => server.state.lastDecision;
    const first = await server.handler(discoveryRequest((await issue()).presentation));
    assert.equal(first.status, 402);
    assert.equal(recorded()?.outcome, 'allow', 'the discovery attempt ran the gate and allowed');
    const none = await server.handler(new Request(ROUTE));
    assert.equal(none.status, 401);
    // A credential-less request under enforce:'always' is a gate deny, so the slot holds
    // THIS request's decision, not the previous allow.
    const denied = recorded();
    assert.ok(denied?.outcome === 'deny', 'the credential-less request recorded a deny');
    assert.equal(denied.code, 'missing_authorization');
    // Observe the slot from inside the verifier round-trip of the next request: the gate has
    // not decided yet, so a cleared slot reads undefined, not the previous request's deny.
    const stubbed = globalThis.fetch;
    let seenDuringVerify: unknown = 'not called';
    globalThis.fetch = async (input, init) => {
      seenDuringVerify = recorded();
      return stubbed(input, init);
    };
    const paid = await server.handler(paidRetryRequest(first, (await issue()).presentation));
    globalThis.fetch = stubbed;
    assert.equal(seenDuringVerify, undefined, 'cleared at the start of the request');
    assert.equal(paid.status, 200);
    assert.equal(recorded()?.outcome, 'allow');
  } finally {
    stub.restore();
  }
});

for (const url of [`${VERIFIER.url}/`, `${VERIFIER.url}/v1/verify`]) {
  test(`verifier url ${url} reaches the verifier at /v1/verify exactly once`, async () => {
    const stub = stubVerifier('active');
    try {
      const server = createServer({ url, token: VERIFIER.token });
      const res = await server.handler(discoveryRequest((await issue()).presentation));
      assert.equal(stub.calls.length, 1, 'one call, to the path the stub accepts');
      assert.equal(res.status, 402, 'the gate allowed, so mppx answered the discovery with its challenge');
    } finally {
      stub.restore();
    }
  });
}
