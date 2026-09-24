// Error recognition goes through the package's structural guards, never `instanceof`: this .mts
// suite `import`s ../src/errors.js while src/gate.ts `require`s ./errors, and whether those resolve
// to one class object depends on the loader (tsx on Node 20 yields two instances, so `instanceof`
// is false even though the caught error is the right one; Node 22.12+/24 share the CJS cache). The
// guards are also what a consumer with two hoisted copies of @bolyra/mpp relies on.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildApp, paymentHeader, requestWith, serverMethod, gate,
  classicalGateOptions, stubVerifierFetch,
} from './harness.mjs';
import { isBolyraDeniedError, isBolyraGateConfigError } from '../src/errors.js';
import { handleDenials } from '../src/handle-denials.js';
import type { Decision, DenyCode } from '../src/types.js';
import { makeBundle, AUDIENCE, NOW_UNIX } from '../test/helpers.js';
import { Challenge, Credential } from 'mppx';
import { testCharge } from './harness.mjs';

/** What a client does with a 402: parse the WWW-Authenticate challenge and mint the Payment credential from it. */
function credentialFrom402(res: Response): string {
  const challenge = Challenge.fromResponse(res, { methods: [testCharge] });
  const credential = Credential.from({ challenge, payload: { token: 'ok' } });
  assert.equal(credential.challenge.id, challenge.id, 'the credential is minted from THIS 402\'s challenge');
  return Credential.serialize(credential);
}

// stubVerifierFetch returns { verifier, calls, restore }; every test that stubs must restore.
let restoreFetch: (() => void) | undefined;
afterEach(() => { restoreFetch?.(); restoreFetch = undefined; });

test('allow: the protected action runs exactly once and the receipt carries bolyraAuthorization', async () => {
  const gated = gate(serverMethod(), await classicalGateOptions());
  const { mppx, state, handler } = buildApp(gated);
  const res = await handler(await requestWith({ payment: await paymentHeader(mppx) }));
  assert.equal(res.status, 200);
  assert.equal(state.lastResultStatus, 200);
  assert.equal(state.counter, 1);
  const receiptHeader = res.headers.get('payment-receipt');
  assert.ok(receiptHeader, 'Payment-Receipt header present');
  const receipt = JSON.parse(Buffer.from(receiptHeader, 'base64url').toString('utf8'));
  assert.equal(receipt.bolyraAuthorization?.decision, 'allow');
  // The receipt carries THIS request's stashed decision, not a placeholder.
  assert.equal(receipt.bolyraAuthorization.tier, 'small');
  assert.equal(receipt.bolyraAuthorization.amountUsd, '25');
  assert.equal(receipt.bolyraAuthorization.audience, AUDIENCE);
  assert.equal(receipt.bolyraAuthorization.verifier, 'classical');
  assert.equal(typeof receipt.bolyraAuthorization.receipt.payloadHash, 'string');
});

// Each case asserts its SPECIFIC code and HTTP status (DENY_STATUS in src/deny.ts):
// a loose "any BolyraDeniedError" would pass even if every case failed on an unrelated internal_error.
type Stub = ReturnType<typeof stubVerifierFetch>;
const denyCases: Array<[string, () => Promise<{ bundle: string | null | undefined; stub?: Stub }>, string, number]> = [
  ['missing Bolyra header', async () => ({ bundle: null }), 'missing_authorization', 401],
  ['revoked (verifier: untrusted_root / credential_not_active)', async () => ({
    bundle: undefined, stub: stubVerifierFetch({ status: 200, body: { verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active', detail: { reason: 'credential_not_active', credential_id: 'ab'.repeat(32) } } }),
  }), 'untrusted_root', 401],
  ['unregistered (same verifier-visible reason)', async () => ({
    bundle: undefined, stub: stubVerifierFetch({ status: 200, body: { verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active', detail: { reason: 'credential_not_active', credential_id: 'cd'.repeat(32) } } }),
  }), 'untrusted_root', 401],
  ['verifier internal_error 500', async () => ({
    bundle: undefined, stub: stubVerifierFetch({ status: 500, body: { verdict: 'deny', kind: 'classical', code: 'internal_error', message: 'storage unavailable' } }),
  }), 'internal_error', 500],
  ['verifier unreachable', async () => ({ bundle: undefined, stub: stubVerifierFetch({ unreachable: true }) }), 'internal_error', 500],
];

for (const [name, mk, code, status] of denyCases) {
  test(`deny (${name}) => ${code}/${status}: the protected action never runs; handleDenials returns Problem Details; without it the handler rejects`, async () => {
    const { bundle, stub } = await mk();
    restoreFetch = stub?.restore;
    const opts = await classicalGateOptions(stub ? { verifier: stub.verifier } : {});
    const gated = gate(serverMethod(), opts);
    const { mppx, state, handler } = buildApp(gated);
    const payment = await paymentHeader(mppx);
    const req = () => requestWith({ payment, bundle });

    await assert.rejects(handler(await req()), (e: unknown) => isBolyraDeniedError(e) && e.verdict.code === code);
    assert.equal(state.counter, 0, 'no side effect without handleDenials');
    if (stub) assert.equal(stub.calls.length, 1, 'one verifier call per request');

    const safe = handleDenials(handler);
    const res = await safe(await req());
    assert.equal(res.headers.get('content-type'), 'application/problem+json');
    assert.equal(res.status, status);
    assert.equal((await res.json() as { code: string }).code, code);
    assert.equal(state.counter, 0, 'no side effect with handleDenials');
    if (stub) assert.equal(stub.calls.length, 2, 'the url verifier was consulted once per request');
  });
}

test('replay: an allow that consumes a nonce denies nonce_replayed on the second presentation; counter stays 1', async () => {
  // The in-process classical verifier NEVER emits consume_nonces (a classical mandate is a standing
  // authorization, src/classical.ts:40) — so replay is exercised exactly as the existing jest test
  // (test/gate.test.ts:324-356) does: a `url` verifier whose allow carries a fixed nonce, returned
  // identically on both calls, so the gate's own reserve-before-act (step 6) rejects the second.
  const stub = stubVerifierFetch({ status: 200, body: {
    verdict: 'allow', kind: 'classical',
    consume_nonces: [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
  } });
  restoreFetch = stub.restore;
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier }));
  const { mppx, state, handler } = buildApp(gated);
  const bundle = await makeBundle();
  assert.equal((await handler(await requestWith({ payment: await paymentHeader(mppx), bundle }))).status, 200);
  await assert.rejects(handler(await requestWith({ payment: await paymentHeader(mppx), bundle })), (e: unknown) =>
    isBolyraDeniedError(e) && e.verdict.code === 'nonce_replayed');
  assert.equal(state.counter, 1);
  assert.equal(stub.calls.length, 2, 'both presentations reached the verifier; the gate (not the stub) denied the replay');
  assert.deepEqual(Object.keys(stub.calls[0]!.body as object).sort(), ['bundle', 'now_unix', 'request', 'version']);
});

test('standing mandate: two fresh presentations of the SAME binding through one gate allow twice (counter 0→1→2); an unrelated mandate from the same operator still allows', async () => {
  // A hosted verifier returns the presentation's publicSignals[1] as the one-time nullifier and the
  // gate reserves it before acting (issuer_key = operator key, retained until expiry). Each issuance
  // must therefore carry a fresh nullifier: a constant would make the FIRST allow reserve it for the
  // whole operator and every later presentation from that operator deny nonce_replayed until expiry.
  const stub = stubVerifierFetch({ allowFromBundle: true });
  restoreFetch = stub.restore;
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier }));
  const { mppx, state, handler } = buildApp(gated);

  // Same binding, minted twice = two presentations of one standing mandate.
  const firstBundle = await makeBundle();
  const first = await handler(await requestWith({ payment: await paymentHeader(mppx), bundle: firstBundle }));
  assert.equal(first.status, 200);
  assert.equal(state.counter, 1);
  const second = await handler(await requestWith({ payment: await paymentHeader(mppx), bundle: await makeBundle() }));
  assert.equal(second.status, 200, 'a second fresh presentation of the same standing mandate allows');
  assert.equal(state.counter, 2);

  // Re-presenting the FIRST bundle unmodified is a replay: the gate reserved its nullifier on the
  // first allow (it reserved each distinct nullifier, not nothing), so the same string denies.
  await assert.rejects(
    handler(await requestWith({ payment: await paymentHeader(mppx), bundle: firstBundle })),
    (e: unknown) => isBolyraDeniedError(e) && e.verdict.code === 'nonce_replayed',
  );
  assert.equal(state.counter, 2, 'the replayed presentation never reached the protected action');

  // An unrelated mandate from the SAME operator (different agent binding) is not blocked either.
  const other = await makeBundle({ binding: { agent_name: 'auditor-bot' } });
  const third = await handler(await requestWith({ payment: await paymentHeader(mppx), bundle: other }));
  assert.equal(third.status, 200, 'an unrelated mandate from the same operator still allows');
  assert.equal(state.counter, 3);

  // The stub derived a DIFFERENT nullifier from each fresh presentation (no fixed nonce in play);
  // the replayed call reached the verifier too (the gate, not the stub, denied it) and repeats the first.
  assert.equal(stub.calls.length, 4);
  const nullifiers = stub.calls.map((c) => JSON.parse((c.body as { bundle: string }).bundle).agent.envelope.publicSignals[1] as string);
  assert.equal(new Set(nullifiers).size, 3, `expected 3 distinct nullifiers across 4 calls, got ${JSON.stringify(nullifiers)}`);
  assert.equal(nullifiers[2], nullifiers[0], 'the replay presented the first nullifier again');
});

test("handshake under enforce:'always' (host-nonce verifier): discovery reserves bundle A's nullifier; paying with A replays; paying with fresh B allows", async () => {
  // The discovery attempt (no Payment credential yet) already runs the gate: allow, nullifier
  // reserved, THEN mppx issues the 402. The payment retry is a second gated attempt and needs a
  // fresh presentation; re-sending A is an unmodified re-send and denies nonce_replayed.
  const stub = stubVerifierFetch({ allowFromBundle: true });
  restoreFetch = stub.restore;
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier }));
  const { state, handler } = buildApp(gated);
  const bundleA = await makeBundle();

  // 1. Discovery with A and no Authorization header => 402 via result.challenge; gate ran once.
  const discovery = await handler(await requestWith({ bundle: bundleA }));
  assert.equal(discovery.status, 402);
  assert.equal(state.lastResultStatus, 402);
  assert.equal(state.counter, 0);
  assert.equal(stub.calls.length, 1, "the discovery attempt ran the gate (nullifier A reserved)");

  // 2. Pay with the credential minted from THAT 402's challenge, re-sending A => nonce_replayed.
  const payment = credentialFrom402(discovery);
  await assert.rejects(handler(await requestWith({ payment, bundle: bundleA })), (e: unknown) =>
    isBolyraDeniedError(e) && e.verdict.code === 'nonce_replayed' && e.response.status === 403);
  assert.equal(state.counter, 0);
  assert.equal(stub.calls.length, 2, 'the replay reached the verifier; the gate (not the stub) denied it');

  // 3. Same credential, fresh presentation B => 200, the action runs once.
  const paid = await handler(await requestWith({ payment, bundle: await makeBundle() }));
  assert.equal(paid.status, 200);
  assert.equal(state.counter, 1);
  assert.equal(stub.calls.length, 3);
});

test("handshake under enforce:'payment': discovery with bundle A skips the gate (zero verifier calls); paying with A allows", async () => {
  const stub = stubVerifierFetch({ allowFromBundle: true });
  restoreFetch = stub.restore;
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier, enforce: 'payment' }));
  const { state, handler } = buildApp(gated);
  const bundleA = await makeBundle();

  const discovery = await handler(await requestWith({ bundle: bundleA }));
  assert.equal(discovery.status, 402);
  assert.equal(state.counter, 0);
  assert.equal(stub.calls.length, 0, 'ungated discovery: the verifier was never consulted');

  // The gate first runs on the credentialed attempt, so A's nullifier is fresh here.
  const paid = await handler(await requestWith({ payment: credentialFrom402(discovery), bundle: bundleA }));
  assert.equal(paid.status, 200);
  assert.equal(state.counter, 1);
  assert.equal(stub.calls.length, 1);
});

test("discovery: enforce:'payment' + no Payment credential => 402, counter 0", async () => {
  const gated = gate(serverMethod(), await classicalGateOptions({ enforce: 'payment' }));
  const { state, handler } = buildApp(gated);
  const res = await handler(await requestWith({ bundle: null }));
  assert.equal(res.status, 402);
  assert.equal(state.counter, 0);
});

test("counterexample A: enforce:'payment' + original preflight returning 403 on a credential-less request => fail closed, counter 0", async () => {
  const gated = gate(serverMethod({ preflight: () => new Response('nope', { status: 403 }) }), await classicalGateOptions({ enforce: 'payment' }));
  const { state, handler } = buildApp(gated);
  await assert.rejects(handler(await requestWith({ bundle: null })), (e: unknown) =>
    isBolyraDeniedError(e) && e.verdict.code === 'internal_error' && e.response.status === 500);
  assert.equal(state.counter, 0);
});

test("counterexample B: enforce:'payment' + authorize hook => refused at construction", async () => {
  await assert.rejects(
    (async () => gate(serverMethod({ authorize: async () => undefined }), await classicalGateOptions({ enforce: 'payment' })))(),
    (e: unknown) => isBolyraGateConfigError(e),
  );
});

test("onDecision under real mppx, enforce:'always': discovery reports allow, paid retry reports allow — exactly one Decision per HTTP request", async () => {
  const stub = stubVerifierFetch({ allowFromBundle: true });
  restoreFetch = stub.restore;
  const decisions: Array<{ outcome: string; code?: string; status?: number }> = [];
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier, onDecision: (d) => { decisions.push(d); } }));
  const { state, handler } = buildApp(gated);

  const discovery = await handler(await requestWith({ bundle: await makeBundle() }));
  assert.equal(discovery.status, 402);
  assert.equal(decisions.length, 1, 'the discovery request is its own gate invocation');

  const paid = await handler(await requestWith({ payment: credentialFrom402(discovery), bundle: await makeBundle() }));
  assert.equal(paid.status, 200);
  assert.equal(state.counter, 1);
  assert.deepEqual(decisions.map((d) => d.outcome), ['allow', 'allow'], 'mppx presenting the paid request twice to the gate (preflight + verify) still reports once');
});

test("onDecision under real mppx, enforce:'payment': discovery reports nothing, paid request reports once", async () => {
  const stub = stubVerifierFetch({ allowFromBundle: true });
  restoreFetch = stub.restore;
  const decisions: Array<{ outcome: string }> = [];
  const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier, enforce: 'payment', onDecision: (d) => { decisions.push(d); } }));
  const { state, handler } = buildApp(gated);
  const discovery = await handler(await requestWith({ bundle: await makeBundle() }));
  assert.equal(discovery.status, 402);
  assert.equal(decisions.length, 0);
  const paid = await handler(await requestWith({ payment: credentialFrom402(discovery), bundle: await makeBundle() }));
  assert.equal(paid.status, 200);
  assert.equal(state.counter, 1);
  assert.deepEqual(decisions.map((d) => d.outcome), ['allow']);
});

test('onDecision under real mppx: a throwing observer and a throwing logger change nothing (the deny keeps its code, status, reason, credential_id)', async () => {
  const stub = stubVerifierFetch({ status: 200, body: { verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active', detail: { reason: 'credential_not_active', credential_id: 'ab'.repeat(32) } } });
  restoreFetch = stub.restore;
  const originalError = console.error;
  console.error = () => { throw new Error('logger down'); };
  let seen: { code?: string; reason?: string; credentialId?: string } | undefined;
  try {
    const gated = gate(serverMethod(), await classicalGateOptions({ verifier: stub.verifier, onDecision: (d) => { seen = d; throw new Error('observer threw'); } }));
    const { mppx, state, handler } = buildApp(gated);
    const res = await handleDenials(handler)(await requestWith({ payment: await paymentHeader(mppx) }));
    assert.equal(res.status, 401);
    const body = await res.json() as { code: string; reason?: string; credential_id?: string };
    assert.equal(body.code, 'untrusted_root');
    assert.equal(body.reason, 'credential_not_active');
    assert.equal(body.credential_id, 'ab'.repeat(32));
    assert.equal(state.counter, 0);
    assert.equal(seen?.code, 'untrusted_root');
    assert.equal(seen?.reason, 'credential_not_active');
    assert.equal(seen?.credentialId, 'ab'.repeat(32));
  } finally {
    console.error = originalError;
  }
});

test('Decision is a discriminated union: consumers narrow on outcome (compile-time contract)', () => {
  const describe = (d: Decision): string => {
    if (d.outcome === 'deny') {
      const code: DenyCode = d.code; // required on deny
      const status: number = d.status; // required on deny
      return `${code}/${status}/${d.reason ?? ''}`;
    }
    // @ts-expect-error — an allow Decision has no `code`
    void d.code;
    // @ts-expect-error — an allow Decision has no `status`
    void d.status;
    return `allow/${d.credentialId ?? ''}/${d.receipt ?? ''}`;
  };
  const request = { agent_name: '', project_key: 'p', program: 'mpp', model: '', granted_capabilities: [] };
  assert.equal(describe({ outcome: 'deny', code: 'expired', status: 403, request }), 'expired/403/');
  assert.equal(describe({ outcome: 'allow', receipt: 'r', request }), 'allow//r');
});
