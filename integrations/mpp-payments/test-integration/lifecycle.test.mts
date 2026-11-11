// The gate across mppx's server lifecycles, driven through real mppx with stub payment rails:
//   legacy          — one deprecated `verify` hook
//   modern          — non-mutating `validate` + terminal `broadcast`
//   broadcast-only  — terminal `broadcast`, no `validate`
// mppx's HTTP dispatch calls `validate({ operation: 'broadcast' })` (when both exist) and then
// `broadcast ?? verify`, so a gate that guards only `verify` is never consulted for a modern method.
//
// Error recognition uses the package's structural guards, never `instanceof` (see
// action-counter.test.mts for why).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Challenge, Credential, Method } from 'mppx';
import {
  buildApp, paymentHeader, requestWith, gate, classicalGateOptions,
  serverMethod, modernMethod, broadcastOnlyMethod, newRail,
  REALM, ROUTE_URL, SECRET_KEY, STUB_PAYER, testCharge,
  type ServerHooks,
} from './harness.mjs';
import { isBolyraDeniedError } from '../src/errors.js';

/** A denial raised by the gate's own lifecycle guards (not an upstream or rail error). */
const gateDenial = (pattern: RegExp) => (e: unknown): boolean =>
  isBolyraDeniedError(e) && e.verdict.code === 'internal_error' && pattern.test(e.verdict.message);
const NO_DECISION = /without an authorization decision/;
const STANDALONE_VALIDATION = /standalone credential validation/;

const receiptOf = (res: Response) =>
  JSON.parse(Buffer.from(res.headers.get('payment-receipt') ?? '', 'base64url').toString('utf8'));

/**
 * How mppx 0.18 surfaces a non-PaymentError thrown by a lifecycle hook inside HTTP dispatch: the
 * handler is told 402 (so it never proceeds), and the response mppx built is an HTTP 500
 * "Internal Payment Error" problem that carries a fresh challenge. Nothing of the gate's own
 * Problem Details is exposed there.
 */
async function assertInternalChallenge(res: Response, outerStatus: number | undefined): Promise<void> {
  assert.equal(outerStatus, 402, 'mppx tells the handler not to proceed');
  assert.equal(res.status, 500);
  assert.ok(res.headers.get('www-authenticate')?.startsWith('Payment '), 'a fresh challenge is attached');
  const problem = await res.json() as { type: string; detail: string };
  assert.equal(problem.type, 'https://paymentauth.org/problems/internal-payment-error');
  assert.doesNotMatch(JSON.stringify(problem), /bolyra|authorization decision/i);
}

const forms = [
  ['legacy', serverMethod],
  ['modern', modernMethod],
  ['broadcast-only', broadcastOnlyMethod],
] as const;

async function setup(make: (typeof forms)[number][1], hooks: ServerHooks = {}) {
  const rail = newRail();
  const gated = gate(make(hooks, rail), await classicalGateOptions());
  return { rail, gated, ...buildApp(gated) };
}

/** A fresh captured-request snapshot, as an mppx transport would produce one. */
const snapshot = () => ({ headers: new Headers(), method: 'GET', url: new URL(ROUTE_URL) });

/** A valid credential for the route plus the hook context mppx would build for `capturedRequest`. */
async function hookContext(mppx: Awaited<ReturnType<typeof setup>>['mppx'], capturedRequest = snapshot()) {
  const issued = await mppx.challenge.test.charge({ amount: '25' });
  // Narrow the issued challenge to this method's own challenge type (what mppx's dispatch hands a hook).
  const challenge = Challenge.from(issued, { methods: [testCharge] });
  const credential = Credential.from({ challenge, payload: { token: 'ok' } });
  const request = { amount: '25' };
  return { capturedRequest, credential, ctx: { credential, envelope: { capturedRequest, challenge, credential, request }, request } };
}

/** Run ONLY the gate's request authorization (preflight) for a snapshot, leaving an unconsumed allow. */
async function authorize(s: Awaited<ReturnType<typeof setup>>, capturedRequest = snapshot()) {
  const h = await hookContext(s.mppx, capturedRequest);
  const input = await requestWith({ payment: Credential.serialize(h.credential) });
  assert.ok(s.gated.preflight, 'the gate always installs preflight');
  const out = await s.gated.preflight({
    capturedRequest, credential: h.credential, input, options: { amount: '25' }, realm: REALM, secretKey: SECRET_KEY,
  });
  assert.equal(out, undefined, 'allow: preflight handles nothing itself');
  return h;
}

// ---------------------------------------------------------------------------------------------
// HTTP flow, every form
// ---------------------------------------------------------------------------------------------

for (const [name, make] of forms) {
  test(`${name} / HTTP allow: action 1, terminal 1, receipt carries bolyraAuthorization`, async () => {
    const s = await setup(make);
    const res = await s.handler(await requestWith({ payment: await paymentHeader(s.mppx) }));
    assert.equal(res.status, 200);
    assert.equal(s.state.counter, 1);
    assert.equal(s.rail.terminal, 1);
    assert.equal(s.rail.validate, name === 'modern' ? 1 : 0);
    const receipt = receiptOf(res);
    assert.equal(receipt.bolyraAuthorization?.decision, 'allow');
    assert.equal(receipt.bolyraAuthorization.amountUsd, '25');
  });

  test(`${name} / HTTP preflight deny: action 0, validate 0, terminal 0`, async () => {
    const s = await setup(make);
    await assert.rejects(
      s.handler(await requestWith({ payment: await paymentHeader(s.mppx), bundle: null })),
      (e: unknown) => isBolyraDeniedError(e) && e.verdict.code === 'missing_authorization',
    );
    assert.deepEqual([s.state.counter, s.rail.validate, s.rail.terminal], [0, 0, 0]);
  });

  test(`${name} / HTTP with preflight bypassed: the lifecycle guard denies, mppx withholds success (outer 402), action 0, rail untouched`, async () => {
    const rail = newRail();
    const gated = gate(make({}, rail), await classicalGateOptions());
    // A host that drops the gate's preflight (so no decision is ever stashed) but keeps its lifecycle hooks.
    const { mppx, state, handler } = buildApp({ ...gated, preflight: undefined });
    const res = await handler(await requestWith({ payment: await paymentHeader(mppx) }));
    await assertInternalChallenge(res, state.lastResultStatus);
    assert.deepEqual([state.counter, rail.validate, rail.terminal], [0, 0, 0]);
  });

  test(`${name} / the decision is consumed by the HTTP terminal hook: every terminal entry point then denies`, async () => {
    const captured: object[] = [];
    // Observe the snapshot mppx passed; the gate runs the method's own preflight after stashing.
    const seen = await setup(make, { preflight: ({ capturedRequest }) => { if (capturedRequest) captured.push(capturedRequest); return undefined; } });
    const res = await seen.handler(await requestWith({ payment: await paymentHeader(seen.mppx) }));
    assert.equal(res.status, 200);
    assert.equal(captured.length, 1);
    const h = await hookContext(seen.mppx, captured[0] as ReturnType<typeof snapshot>);
    await assert.rejects(seen.gated.verify(h.ctx), gateDenial(NO_DECISION));
    if (seen.gated.broadcast) await assert.rejects(seen.gated.broadcast(h.ctx), gateDenial(NO_DECISION));
    if (seen.gated.validate) await assert.rejects(seen.gated.validate({ ...h.ctx, operation: 'broadcast' }), gateDenial(NO_DECISION));
    assert.equal(seen.rail.terminal, 1, 'only the HTTP flow reached the rail');
  });

  test(`${name} / terminal failure consumes the decision: the retry denies without reaching the rail again`, async () => {
    const s = await setup(make);
    const h = await authorize(s);
    s.rail.failTerminal = true;
    const terminal = s.gated.broadcast ?? s.gated.verify;
    await assert.rejects(terminal(h.ctx), /rail: terminal failure/);
    s.rail.failTerminal = false;
    await assert.rejects(terminal(h.ctx), gateDenial(NO_DECISION));
    await assert.rejects(s.gated.verify(h.ctx), gateDenial(NO_DECISION));
    assert.equal(s.rail.terminal, 1);
  });

  test(`${name} / concurrent terminal attempts on one decision: exactly one reaches the rail`, async () => {
    const s = await setup(make);
    const h = await authorize(s);
    const terminal = s.gated.broadcast ?? s.gated.verify;
    // Mixed entry points where the form has both: `broadcast` and the (synthesized) `verify`.
    const results = await Promise.allSettled([terminal(h.ctx), s.gated.verify(h.ctx), terminal(h.ctx)]);
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    for (const r of results) if (r.status === 'rejected') assert.ok(gateDenial(NO_DECISION)(r.reason));
    assert.equal(s.rail.terminal, 1);
  });

  test(`${name} / a decision for request A does not satisfy request B`, async () => {
    const s = await setup(make);
    await authorize(s); // allow stashed for snapshot A
    const b = await hookContext(s.mppx); // same route, valid credential, different snapshot
    await assert.rejects((s.gated.broadcast ?? s.gated.verify)(b.ctx), gateDenial(NO_DECISION));
    if (s.gated.validate) await assert.rejects(s.gated.validate({ ...b.ctx, operation: 'broadcast' }), gateDenial(NO_DECISION));
    assert.deepEqual([s.rail.validate, s.rail.terminal], [0, 0]);
  });

  test(`${name} / each lifecycle wrapper denies on its own without a decision`, async () => {
    const s = await setup(make);
    const h = await hookContext(s.mppx);
    await assert.rejects(s.gated.verify(h.ctx), gateDenial(NO_DECISION));
    if (s.gated.broadcast) await assert.rejects(s.gated.broadcast(h.ctx), gateDenial(NO_DECISION));
    if (s.gated.validate) await assert.rejects(s.gated.validate({ ...h.ctx, operation: 'broadcast' }), gateDenial(NO_DECISION));
    // No envelope at all (non-HTTP transport, lower-level helpers).
    const bare = { credential: h.credential, request: h.ctx.request };
    await assert.rejects(s.gated.verify(bare), gateDenial(NO_DECISION));
    if (s.gated.broadcast) await assert.rejects(s.gated.broadcast(bare), gateDenial(NO_DECISION));
    assert.deepEqual([s.rail.validate, s.rail.terminal], [0, 0]);
  });

  test(`${name} / standalone mppx.broadcastCredential and verifyCredential reject with the gate's denial; rail untouched`, async () => {
    const s = await setup(make);
    const payment = await paymentHeader(s.mppx);
    const expected = gateDenial(NO_DECISION);
    await assert.rejects(s.mppx.broadcastCredential(payment), expected);
    await assert.rejects(s.mppx.verifyCredential(payment), expected);
    // A caller-supplied snapshot (so mppx builds an envelope) that was never authorized.
    const routed = { capturedRequest: snapshot(), request: { amount: '25' } };
    await assert.rejects(s.mppx.broadcastCredential(payment, routed), expected);
    await assert.rejects(s.mppx.verifyCredential(payment, routed), expected);
    assert.deepEqual([s.state.counter, s.rail.validate, s.rail.terminal], [0, 0, 0]);
  });

  test(`${name} / lower-level Method.broadcastCredential against the wrapped method rejects with the gate's denial`, async () => {
    const s = await setup(make);
    const payment = await paymentHeader(s.mppx);
    await assert.rejects(Method.broadcastCredential([s.gated], payment), gateDenial(NO_DECISION));
    assert.deepEqual([s.rail.validate, s.rail.terminal], [0, 0]);
  });
}

// ---------------------------------------------------------------------------------------------
// Hooks are wrapped only where the method supplies them
// ---------------------------------------------------------------------------------------------

test('no manufactured hooks: legacy has no callable validate/broadcast; broadcast-only has no callable validate', async () => {
  const legacy = await setup(serverMethod);
  assert.notEqual(typeof legacy.gated.validate, 'function');
  assert.notEqual(typeof legacy.gated.broadcast, 'function');
  const only = await setup(broadcastOnlyMethod);
  assert.notEqual(typeof only.gated.validate, 'function');
  assert.equal(typeof only.gated.broadcast, 'function');
  const modern = await setup(modernMethod);
  assert.equal(typeof modern.gated.validate, 'function');
  assert.equal(typeof modern.gated.broadcast, 'function');
});

for (const [name, make] of [forms[0], forms[2]] as const) {
  test(`${name} / standalone validation is unsupported upstream (no validate hook); the rail is untouched`, async () => {
    const s = await setup(make);
    const payment = await paymentHeader(s.mppx);
    const unsupported = /does not support non-mutating credential validation/;
    await assert.rejects(s.mppx.validateCredential(payment), unsupported);
    await assert.rejects(Method.validateCredential([s.gated], payment), unsupported);
    assert.equal(s.rail.terminal, 0);
  });
}

// ---------------------------------------------------------------------------------------------
// Modern form: validation policy
// ---------------------------------------------------------------------------------------------

test('modern / validate(operation: broadcast) with a decision: returns the original result unchanged and keeps the decision', async () => {
  const s = await setup(modernMethod);
  const h = await authorize(s);
  assert.ok(s.gated.validate && s.gated.broadcast);
  const validation = await s.gated.validate({ ...h.ctx, operation: 'broadcast' });
  assert.equal(validation.payer, STUB_PAYER);
  assert.deepEqual(validation.details, { checked: true });
  assert.strictEqual(validation, s.rail.lastValidation, 'the original return value itself, not a copy');
  assert.equal(s.rail.validate, 1);
  // Still available: validation again, then the terminal hook, succeed on the same decision.
  await s.gated.validate({ ...h.ctx, operation: 'broadcast' });
  const receipt = await s.gated.broadcast(h.ctx);
  assert.equal((receipt as { bolyraAuthorization?: { decision: string } }).bolyraAuthorization?.decision, 'allow');
  assert.deepEqual([s.rail.validate, s.rail.terminal], [2, 1]);
});

for (const operation of ['validate', undefined, 'settle'] as const) {
  test(`modern / validate(operation: ${String(operation)}) is denied even WITH an authorized decision; the decision survives`, async () => {
    const s = await setup(modernMethod);
    const h = await authorize(s);
    assert.ok(s.gated.validate && s.gated.broadcast);
    // 'settle' stands for any value mppx may add later; the cast is the point of the test.
    const params = { ...h.ctx, operation: operation as 'validate' | undefined };
    await assert.rejects(s.gated.validate(params), gateDenial(STANDALONE_VALIDATION));
    assert.equal(s.rail.validate, 0, 'the original validate was never called');
    await s.gated.broadcast(h.ctx); // a refused standalone validation does not spend the decision
    assert.equal(s.rail.terminal, 1);
  });
}

test('modern / validation failure invalidates the decision: the terminal hooks then deny, rail terminal 0', async () => {
  const s = await setup(modernMethod);
  const h = await authorize(s);
  assert.ok(s.gated.validate && s.gated.broadcast);
  s.rail.failValidate = true;
  await assert.rejects(s.gated.validate({ ...h.ctx, operation: 'broadcast' }), /rail: validation failure/);
  s.rail.failValidate = false;
  await assert.rejects(s.gated.broadcast(h.ctx), gateDenial(NO_DECISION));
  await assert.rejects(s.gated.verify(h.ctx), gateDenial(NO_DECISION));
  await assert.rejects(s.gated.validate({ ...h.ctx, operation: 'broadcast' }), gateDenial(NO_DECISION));
  assert.deepEqual([s.rail.validate, s.rail.terminal], [1, 0]);
});

test('modern / HTTP validation failure: mppx withholds success (outer 402), action 0, terminal 0', async () => {
  const s = await setup(modernMethod);
  s.rail.failValidate = true;
  const res = await s.handler(await requestWith({ payment: await paymentHeader(s.mppx) }));
  await assertInternalChallenge(res, s.state.lastResultStatus);
  assert.deepEqual([s.state.counter, s.rail.validate, s.rail.terminal], [0, 1, 0]);
});

test('modern / standalone mppx.validateCredential and Method.validateCredential reject with the gate\'s policy denial', async () => {
  const s = await setup(modernMethod);
  const payment = await paymentHeader(s.mppx);
  await assert.rejects(s.mppx.validateCredential(payment), gateDenial(STANDALONE_VALIDATION));
  await assert.rejects(
    s.mppx.validateCredential(payment, { capturedRequest: snapshot(), request: { amount: '25' } }),
    gateDenial(STANDALONE_VALIDATION),
  );
  await assert.rejects(Method.validateCredential([s.gated], payment), gateDenial(STANDALONE_VALIDATION));
  assert.deepEqual([s.rail.validate, s.rail.terminal], [0, 0]);
});

// ---------------------------------------------------------------------------------------------
// Modern form: the synthesized `verify` (HTTP and mppx.verifyCredential select `broadcast`, so
// only a direct call exercises it)
// ---------------------------------------------------------------------------------------------

test('modern / wrapped verify after a fresh authorization: one original validate, one original broadcast, enriched receipt, consumed once', async () => {
  const s = await setup(modernMethod);
  const h = await authorize(s);
  const receipt = await s.gated.verify(h.ctx);
  assert.deepEqual([s.rail.validate, s.rail.terminal], [1, 1]);
  assert.equal((receipt as { bolyraAuthorization?: { decision: string } }).bolyraAuthorization?.decision, 'allow');
  await assert.rejects(s.gated.verify(h.ctx), gateDenial(NO_DECISION));
  assert.ok(s.gated.broadcast);
  await assert.rejects(s.gated.broadcast(h.ctx), gateDenial(NO_DECISION));
  assert.deepEqual([s.rail.validate, s.rail.terminal], [1, 1]);
});

test('modern / wrapped verify whose inner validation fails: decision consumed, terminal 0', async () => {
  const s = await setup(modernMethod);
  const h = await authorize(s);
  s.rail.failValidate = true;
  await assert.rejects(s.gated.verify(h.ctx), /rail: validation failure/);
  s.rail.failValidate = false;
  await assert.rejects(s.gated.verify(h.ctx), gateDenial(NO_DECISION));
  assert.deepEqual([s.rail.validate, s.rail.terminal], [1, 0]);
});

// ---------------------------------------------------------------------------------------------
// onPaymentSuccess (mppx swallows errors thrown inside it, so capture and assert afterwards)
// ---------------------------------------------------------------------------------------------

for (const [name, make] of forms) {
  test(`${name} / onPaymentSuccess receives the enriched receipt${name === 'modern' ? ' and the validated payer' : ''}`, async () => {
    const calls: Array<{ payer?: string | undefined; receipt: unknown }> = [];
    const s = await setup(make, { onPaymentSuccess: ({ payer, receipt }) => { calls.push({ payer, receipt }); } });
    const res = await s.handler(await requestWith({ payment: await paymentHeader(s.mppx) }));
    assert.equal(res.status, 200);
    assert.equal(calls.length, 1);
    assert.equal((calls[0]!.receipt as { bolyraAuthorization?: { decision: string } }).bolyraAuthorization?.decision, 'allow');
    assert.equal(calls[0]!.payer, name === 'modern' ? STUB_PAYER : undefined);
  });
}


// ---------------------------------------------------------------------------------------------
// The boundary of the standalone guarantee: it is the DECISION that admits a terminal hook
// ---------------------------------------------------------------------------------------------

test('modern / standalone broadcastCredential with the identical authorized, unconsumed snapshot is admitted once; a look-alike snapshot is not', async () => {
  const s = await setup(modernMethod);
  const h = await authorize(s);
  const payment = Credential.serialize(h.credential);
  const lookAlike = { capturedRequest: snapshot(), request: { amount: '25' } };
  await assert.rejects(s.mppx.broadcastCredential(payment, lookAlike), gateDenial(NO_DECISION));
  const receipt = await s.mppx.broadcastCredential(payment, { capturedRequest: h.capturedRequest, request: { amount: '25' } });
  assert.equal((receipt as { bolyraAuthorization?: { decision: string } }).bolyraAuthorization?.decision, 'allow');
  assert.deepEqual([s.rail.validate, s.rail.terminal], [1, 1]);
  await assert.rejects(
    s.mppx.broadcastCredential(payment, { capturedRequest: h.capturedRequest, request: { amount: '25' } }),
    gateDenial(NO_DECISION),
  );
  assert.equal(s.rail.terminal, 1);
});
