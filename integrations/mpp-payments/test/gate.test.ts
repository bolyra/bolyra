/**
 * bolyraGate contract, driven through the mppx `Method.Server` hook seam the
 * wrapper composes into (`preflight` runs before the challenge/verification
 * path; a returned Response fully handles the request; `verify` runs only on
 * the credential-bearing payment path). The runnable example under
 * `examples/mandate-demo` exercises the same wrapper through the real
 * `Mppx.create()` request lifecycle.
 */

import { verifyReceipt, type SignedReceipt } from '@bolyra/receipts';
import { BolyraDeniedError, BolyraGateConfigError } from '../src/errors';
import { bolyraGate, BOLYRA_AUTHORIZATION_HEADER } from '../src/gate';
import type { BolyraGateOptions, OperatorKey } from '../src/types';
import { AUDIENCE, EXPIRY, NOW_UNIX, makeBundle, operatorKey } from './helpers';
import * as receiptsModule from '../src/receipts';

/** A minimal mock mppx server method (the shape `Method.toServer` returns). */
function mockMethod() {
  const verifySpy = jest.fn(async () => ({
    method: 'mock',
    reference: 'tx-ref',
    status: 'success' as const,
    timestamp: new Date(0).toISOString(),
  }));
  const preflightSpy = jest.fn(() => undefined);
  return {
    method: {
      name: 'mock',
      intent: 'charge',
      schema: {
        credential: { payload: {} },
        request: {},
      },
      preflight: preflightSpy,
      verify: verifySpy,
    },
    verifySpy,
    preflightSpy,
  };
}

/**
 * Drive one HTTP request through the wrapped method the way Mppx.create()'s
 * handler does: capture the request, run preflight (a Response return fully
 * handles the request), then — on the credential-bearing path — run verify
 * with the same captured-request snapshot in the envelope.
 */
async function drive(
  wrapped: ReturnType<typeof bolyraGate<ReturnType<typeof mockMethod>['method']>>,
  input: Request,
  options: Record<string, unknown>,
  { credential = { challenge: {}, payload: {} } as unknown }: { credential?: unknown } = {},
) {
  const capturedRequest = Object.freeze({
    headers: new Headers(input.headers),
    method: input.method,
    url: new URL(input.url),
  });
  let preflightResult: unknown;
  try {
    preflightResult = await wrapped.preflight?.({
      capturedRequest,
      credential,
      input,
      options,
      realm: 'api.merchant.example',
      secretKey: 'test-secret-key-test-secret-key-32',
    });
  } catch (err) {
    if (err instanceof BolyraDeniedError) return { denied: err.response, receipt: undefined };
    throw err;
  }
  if (preflightResult instanceof Response) {
    throw new Error('drive(): preflight returned a Response — the gate must THROW on deny');
  }
  const receipt = await wrapped.verify({
    credential,
    envelope: { capturedRequest, challenge: {}, credential, request: options },
    request: options,
  });
  return { denied: undefined, receipt };
}

/**
 * Drive only the preflight hook, passing `credential` through untouched (null
 * exercises the credential-less branch). Denials propagate as thrown errors.
 */
async function drivePreflight(
  wrapped: ReturnType<typeof bolyraGate<ReturnType<typeof mockMethod>['method']>>,
  input: Request,
  options: Record<string, unknown>,
  { credential }: { credential: unknown },
) {
  const capturedRequest = Object.freeze({ headers: new Headers(input.headers), method: input.method, url: new URL(input.url) });
  return wrapped.preflight?.({ capturedRequest, credential, input, options, realm: 'api.merchant.example', secretKey: 'test-secret-key-test-secret-key-32' });
}

async function gateOptions(overrides: Partial<BolyraGateOptions> = {}): Promise<BolyraGateOptions> {
  return {
    audience: AUDIENCE,
    verifier: { kind: 'classical', trustedOperators: [await operatorKey()] },
    now: () => NOW_UNIX,
    ...overrides,
  };
}

function requestWithBundle(bundle?: string): Request {
  return new Request('https://api.merchant.example/paid', {
    headers: bundle !== undefined ? { [BOLYRA_AUTHORIZATION_HEADER]: bundle } : {},
  });
}

async function readProblem(response: Response) {
  expect(response.headers.get('content-type')).toBe('application/problem+json');
  return response.json() as Promise<Record<string, unknown>>;
}

describe('bolyraGate', () => {
  test('allows a spend within the delegated tier and attaches receipt metadata', async () => {
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const bundle = await makeBundle(); // mandate: mpp:financial:small

    const { denied, receipt } = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });

    expect(denied).toBeUndefined();
    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect(receipt).toMatchObject({
      method: 'mock',
      status: 'success',
      bolyraAuthorization: {
        decision: 'allow',
        tier: 'small',
        capability: 'mpp:financial:small',
        amountUsd: '25',
        verifier: 'classical',
        audience: AUDIENCE,
      },
    });
    const field = (receipt as Record<string, any>).bolyraAuthorization;
    expect(field.receipt.payloadHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(field.receipt.signer).toMatch(/^0x/);
  });

  test('denies a spend over the delegated tier BEFORE any payment logic runs', async () => {
    const { method, verifySpy, preflightSpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const bundle = await makeBundle(); // small tier only

    const { denied } = await drive(wrapped, requestWithBundle(bundle), { amount: '500' });

    expect(denied).toBeDefined();
    expect(denied!.status).toBe(403);
    const problem = await readProblem(denied!);
    expect(problem).toMatchObject({
      code: 'request_mismatch',
      status: 403,
      type: 'https://bolyra.ai/problems/mpp/request-mismatch',
    });
    // Fail-closed ordering: neither payment verify nor the method's own
    // preflight ever ran.
    expect(verifySpy).not.toHaveBeenCalled();
    expect(preflightSpy).not.toHaveBeenCalled();
  });

  test('denies an expired mandate', async () => {
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ now: () => EXPIRY + 1 }));
    const bundle = await makeBundle();

    const { denied } = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(denied!.status).toBe(403);
    expect(await readProblem(denied!)).toMatchObject({ code: 'expired' });
    expect(verifySpy).not.toHaveBeenCalled();
  });

  test('denies a mandate signed for a different audience', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ audience: 'api.other.example' }));
    const bundle = await makeBundle(); // signed for AUDIENCE

    const { denied } = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(denied!.status).toBe(403);
    expect(await readProblem(denied!)).toMatchObject({ code: 'request_mismatch' });
  });

  test('denies a missing authorization header with 401 missing_authorization', async () => {
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());

    const { denied } = await drive(wrapped, requestWithBundle(undefined), { amount: '25' });
    expect(denied!.status).toBe(401);
    expect(await readProblem(denied!)).toMatchObject({ code: 'missing_authorization' });
    expect(verifySpy).not.toHaveBeenCalled();
  });

  test('denies a malformed presentation with 401 invalid_bundle', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());

    const { denied } = await drive(wrapped, requestWithBundle('not-a-bundle'), { amount: '25' });
    expect(denied!.status).toBe(401);
    expect(await readProblem(denied!)).toMatchObject({ code: 'invalid_bundle' });
  });

  test('fails closed (500 internal_error) when the verifier errors', async () => {
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(
      method,
      await gateOptions({
        verifier: { kind: 'command', command: '/nonexistent/verifier', timeoutMs: 1000 },
      }),
    );
    const bundle = await makeBundle();

    const { denied } = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(denied!.status).toBe(500);
    expect(await readProblem(denied!)).toMatchObject({ code: 'internal_error' });
    expect(verifySpy).not.toHaveBeenCalled();
  });

  test('fails closed when the route amount cannot be resolved', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const bundle = await makeBundle();

    const { denied } = await drive(wrapped, requestWithBundle(bundle), {});
    expect(denied!.status).toBe(500);
    expect(await readProblem(denied!)).toMatchObject({ code: 'internal_error' });
  });

  test('verify fails closed when reached without a gate decision', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());

    // Standalone verifyCredential()-style call: no preflight, no stash.
    await expect(
      wrapped.verify({
        credential: {},
        envelope: { capturedRequest: Object.freeze({}) },
        request: { amount: '1' },
      }),
    ).rejects.toThrow(/without an authorization decision/);

    // No envelope at all (non-HTTP transport).
    await expect(
      wrapped.verify({ credential: {}, request: { amount: '1' } }),
    ).rejects.toThrow(/without an authorization decision/);
  });

  test('emits signed, chained, verifiable receipts for allow AND deny decisions', async () => {
    const receipts: SignedReceipt[] = [];
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onReceipt: (r) => receipts.push(r) }));
    const bundle = await makeBundle();

    await drive(wrapped, requestWithBundle(bundle), { amount: '25' }); // allow
    await drive(wrapped, requestWithBundle(bundle), { amount: '500' }); // deny

    expect(receipts).toHaveLength(2);
    const [allowReceipt, denyReceipt] = receipts;

    expect(allowReceipt.payload.kind).toBe('bolyra.commerce');
    expect(allowReceipt.payload.decision.allowed).toBe(true);
    expect(allowReceipt.payload.commerce).toMatchObject({
      rail: 'mpp',
      amount: 25,
      currency: 'USD',
      merchant: AUDIENCE,
    });
    expect(denyReceipt.payload.decision.allowed).toBe(false);
    expect(denyReceipt.payload.decision.reasonCode).toBe('request_mismatch');

    // ES256K signatures verify independently, and the chain advances.
    expect(verifyReceipt(allowReceipt)).toBe(true);
    expect(verifyReceipt(denyReceipt)).toBe(true);
    expect(allowReceipt.payload.chain?.seq).toBe(0);
    expect(denyReceipt.payload.chain?.seq).toBe(1);
    expect(allowReceipt.signature.signer).toBe(denyReceipt.signature.signer);
  });

  test('enforce: "payment" lets credential-less challenge requests through ungated', async () => {
    const { method, preflightSpy, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ enforce: 'payment' }));

    // Challenge probe: no payment credential, no bolyra header — not gated;
    // the method's own preflight still runs.
    const probe = await wrapped.preflight?.({
      capturedRequest: Object.freeze({}),
      credential: null,
      input: requestWithBundle(undefined),
      options: { amount: '25' },
    });
    expect(probe).toBeUndefined();
    expect(preflightSpy).toHaveBeenCalledTimes(1);

    // The credential-bearing retry IS gated.
    const { denied } = await drive(wrapped, requestWithBundle(undefined), { amount: '25' });
    expect(denied!.status).toBe(401);
    expect(verifySpy).not.toHaveBeenCalled();
  });

  test('enforce: "always" (default) gates challenge issuance too', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());

    await expect(
      wrapped.preflight?.({
        capturedRequest: Object.freeze({}),
        credential: null,
        input: requestWithBundle(undefined),
        options: { amount: '25' },
      }),
    ).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'missing_authorization' } });
  });

  test('the method\'s own preflight still runs after an allow', async () => {
    const { method, preflightSpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const bundle = await makeBundle();

    await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(preflightSpy).toHaveBeenCalledTimes(1);
  });

  test('amountToUsd override maps token base units to USD for tier mapping', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(
      method,
      await gateOptions({
        // amount is USDC base units (6 decimals)
        amountToUsd: ({ amount }) => Number(amount as string) / 1_000_000,
      }),
    );
    const bundle = await makeBundle();

    // 250 USDC = $250 → medium tier → mandate (small) does not cover it.
    const { denied } = await drive(wrapped, requestWithBundle(bundle), { amount: '250000000' });
    expect(await readProblem(denied!)).toMatchObject({ code: 'request_mismatch' });

    // 25 USDC = $25 → small tier → allowed.
    const ok = await drive(wrapped, requestWithBundle(bundle), { amount: '25000000' });
    expect(ok.denied).toBeUndefined();
  });

  test('nonce-consuming allow verdicts make presentations one-shot (host nonce mode)', async () => {
    const { method } = mockMethod();
    const originalFetch = global.fetch;
    let calls = 0;
    global.fetch = jest.fn(async () => {
      calls += 1;
      return new Response(
        JSON.stringify({
          verdict: 'allow',
          kind: 'classical',
          consume_nonces: [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as unknown as typeof fetch;
    try {
      const wrapped = bolyraGate(
        method,
        await gateOptions({ verifier: { kind: 'url', url: 'https://verify.example' } }),
      );
      const bundle = await makeBundle();

      const first = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
      expect(first.denied).toBeUndefined();

      const second = await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
      expect(second.denied!.status).toBe(403);
      expect(await readProblem(second.denied!)).toMatchObject({ code: 'nonce_replayed' });
      expect(calls).toBe(2);
    } finally {
      global.fetch = originalFetch;
    }
  });

  test('a verifier deny detail surfaces reason + credential_id in the Problem Details (T8)', async () => {
    const { method } = mockMethod();
    const originalFetch = global.fetch;
    const id = 'ab'.repeat(32);
    global.fetch = jest.fn(async () =>
      new Response(
        JSON.stringify({
          verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active',
          detail: { reason: 'credential_not_active', credential_id: id, backend: 'secret' },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;
    try {
      const wrapped = bolyraGate(
        method,
        await gateOptions({ verifier: { kind: 'url', url: 'https://verify.example' } }),
      );
      const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
      const problem = await readProblem(denied!);
      expect(problem).toMatchObject({ code: 'untrusted_root', reason: 'credential_not_active', credential_id: id });
      expect(problem).not.toHaveProperty('backend');
    } finally {
      global.fetch = originalFetch;
    }
  });

  test('a custom nonceStore is used for reserve-before-act', async () => {
    const { method } = mockMethod();
    const originalFetch = global.fetch;
    global.fetch = jest.fn(async () =>
      new Response(
        JSON.stringify({
          verdict: 'allow',
          kind: 'classical',
          consume_nonces: [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;
    try {
      const reserve = jest.fn(async () => false); // shared store says: replayed
      const wrapped = bolyraGate(
        method,
        await gateOptions({
          verifier: { kind: 'url', url: 'https://verify.example' },
          nonceStore: { reserve },
        }),
      );
      const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), {
        amount: '25',
      });
      expect(reserve).toHaveBeenCalledWith(
        [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
        NOW_UNIX,
      );
      expect(await readProblem(denied!)).toMatchObject({ code: 'nonce_replayed' });
    } finally {
      global.fetch = originalFetch;
    }
  });

  test('rejects header: "Authorization" (collides with the MPP payment credential)', async () => {
    const { method } = mockMethod();
    const trusted = [await operatorKey()];
    expect(() =>
      bolyraGate(method, {
        audience: AUDIENCE,
        verifier: { kind: 'classical', trustedOperators: trusted },
        header: 'Authorization',
      }),
    ).toThrow(/Authorization/);
  });

  test('construction fails fast without an audience or a usable verifier', async () => {
    const { method } = mockMethod();
    const trusted: OperatorKey[] = [await operatorKey()];
    expect(() =>
      bolyraGate(method, { verifier: { kind: 'classical', trustedOperators: trusted } } as never),
    ).toThrow(/audience/);
    expect(() =>
      bolyraGate(method, {
        audience: AUDIENCE,
        verifier: { kind: 'classical', trustedOperators: [] },
      }),
    ).toThrow(/trustedOperators/);
    expect(() => bolyraGate(method, { audience: AUDIENCE } as never)).toThrow(/verifier/);
  });

  test('wrapping preserves the method identity fields (name/intent/schema)', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    expect(wrapped.name).toBe('mock');
    expect(wrapped.intent).toBe('charge');
    expect(wrapped.schema).toBe(method.schema);
  });
});

describe('receipt sink failure (fail closed, sink called once)', () => {
  const throwingSink = () => jest.fn(() => { throw new Error('sink down'); });
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('allow path: an otherwise-valid request denies 500 internal_error', async () => {
    const onReceipt = throwingSink();
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onReceipt }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied?.status).toBe(500);
    const problem = await denied!.json();
    expect(problem.code).toBe('internal_error');
    expect(problem.detail).toBe('authorization receipt sink failed');
    expect(onReceipt).toHaveBeenCalledTimes(1);
    expect(verifySpy).not.toHaveBeenCalled();
  });

  test('ordinary deny path: the original code is replaced by internal_error', async () => {
    const onReceipt = throwingSink();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onReceipt }));
    const { denied } = await drive(wrapped, requestWithBundle(undefined), { amount: '25' }); // missing_authorization
    expect(denied?.status).toBe(500);
    expect((await denied!.json()).code).toBe('internal_error');
    expect(onReceipt).toHaveBeenCalledTimes(1);
  });

  test('first emission inside the outer catch: nothing escapes', async () => {
    const onReceipt = throwingSink();
    const { method } = mockMethod();
    const reserve = jest.fn(async () => { throw new Error('store down'); });
    const nonceStore = { reserve };
    const verifier = { kind: 'url' as const, url: 'https://verify.test/v1/verify' };
    const fetchStub = jest.fn(async () => new Response(JSON.stringify({
      verdict: 'allow', kind: 'classical',
      consume_nonces: [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    global.fetch = fetchStub as unknown as typeof fetch;
    const wrapped = bolyraGate(method, await gateOptions({ onReceipt, verifier, nonceStore }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied?.status).toBe(500);
    const problem = await denied!.json();
    expect(problem.code).toBe('internal_error');
    expect(problem.detail).toBe('authorization receipt sink failed');
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(reserve).toHaveBeenCalledTimes(1);
    expect(onReceipt).toHaveBeenCalledTimes(1);
  });

  test('an async sink (returned Promise) is a sink failure: denied 500, no unhandled rejection', async () => {
    let unhandled = 0;
    const onUnhandled = () => { unhandled += 1; };
    process.on('unhandledRejection', onUnhandled);
    try {
      const onReceipt = jest.fn(async () => { throw new Error('x'); });
      const { method, verifySpy } = mockMethod();
      const wrapped = bolyraGate(method, await gateOptions({ onReceipt }));
      const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
      expect(denied?.status).toBe(500);
      const problem = await denied!.json();
      expect(problem.code).toBe('internal_error');
      expect(problem.detail).toMatch(/synchronous/);
      expect(onReceipt).toHaveBeenCalledTimes(1);
      expect(verifySpy).not.toHaveBeenCalled();
      // Let the sink's rejected promise settle: the gate attached a handler,
      // so the host sees no unhandled rejection.
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandled).toBe(0);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});

describe('credential-less passthrough', () => {
  test("enforce:'payment' + a method with an authorize hook is refused at construction", async () => {
    const { method } = mockMethod();
    const withAuthorize = { ...method, authorize: async () => undefined };
    await expect(async () =>
      bolyraGate(withAuthorize, await gateOptions({ enforce: 'payment' })),
    ).rejects.toBeInstanceOf(BolyraGateConfigError);
  });

  test("enforce:'payment' + credential-less request + original preflight returning 402 passes through", async () => {
    const { method } = mockMethod();
    const challenge = new Response(null, { status: 402 });
    const m = { ...method, preflight: jest.fn(() => challenge) };
    const wrapped = bolyraGate(m, await gateOptions({ enforce: 'payment' }));
    const out = await drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null });
    expect(out).toBe(challenge);
    expect(m.preflight).toHaveBeenCalledTimes(1);
  });

  test("enforce:'payment' + credential-less request + original preflight returning undefined passes through as undefined", async () => {
    const { method, preflightSpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ enforce: 'payment' }));
    const out = await drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null });
    expect(out).toBeUndefined();
    expect(preflightSpy).toHaveBeenCalledTimes(1);
  });

  test("enforce:'payment' + credential-less request + a method with NO original preflight yields undefined", async () => {
    const { method } = mockMethod();
    const { preflight: _omitted, ...withoutPreflight } = method;
    const wrapped = bolyraGate(withoutPreflight, await gateOptions({ enforce: 'payment' }));
    const out = await drivePreflight(
      wrapped as ReturnType<typeof bolyraGate<typeof method>>,
      requestWithBundle(undefined),
      { amount: '25' },
      { credential: null },
    );
    expect(out).toBeUndefined();
  });

  test("enforce:'payment' + credential-less request + a REJECTING original preflight propagates its own error", async () => {
    const { method } = mockMethod();
    const boom = new Error('original preflight exploded');
    const m = { ...method, preflight: jest.fn(async () => { throw boom; }) };
    const wrapped = bolyraGate(m, await gateOptions({ enforce: 'payment' }));
    let caught: unknown;
    try {
      await drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBe(boom);
    expect(caught).not.toBeInstanceOf(BolyraDeniedError);
  });

  test("enforce:'payment' + an authorize hook attached AFTER bolyraGate() is denied internal_error at request time", async () => {
    const { method, preflightSpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ enforce: 'payment' }));
    (wrapped as any).authorize = async () => undefined;
    await expect(
      drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null }),
    ).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'internal_error' } });
    expect(preflightSpy).not.toHaveBeenCalled();
  });

  test("enforce:'payment' + credential-less request + original preflight returning a NON-402 Response fails closed", async () => {
    const { method } = mockMethod();
    const m = { ...method, preflight: jest.fn(() => new Response('nope', { status: 403 })) };
    const wrapped = bolyraGate(m, await gateOptions({ enforce: 'payment' }));
    await expect(
      drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null }),
    ).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'internal_error' } });
  });

  test("enforce:'always' (default) gates credential-less requests too", async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    await expect(
      drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null }),
    ).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'missing_authorization' } });
  });
});

describe('one-use stash', () => {
  test('a second verify against the same captured request fails closed', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const input = requestWithBundle(await makeBundle());
    const capturedRequest = Object.freeze({ headers: new Headers(input.headers), method: input.method, url: new URL(input.url) });
    const credential = { challenge: {}, payload: {} } as unknown;
    await wrapped.preflight?.({ capturedRequest, credential, input, options: { amount: '25' }, realm: 'api.merchant.example', secretKey: 'test-secret-key-test-secret-key-32' });
    const envelope = { capturedRequest, challenge: {}, credential, request: { amount: '25' } };
    await expect(wrapped.verify({ credential, envelope, request: { amount: '25' } })).resolves.toMatchObject({ bolyraAuthorization: { decision: 'allow' } });
    await expect(wrapped.verify({ credential, envelope, request: { amount: '25' } })).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'internal_error' } });
  });

  test('verify without a prior decision throws BolyraDeniedError', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions());
    const rejection = wrapped.verify({ credential: {}, envelope: undefined, request: { amount: '25' } } as never);
    await expect(rejection).rejects.toBeInstanceOf(BolyraDeniedError);
    await expect(rejection).rejects.toMatchObject({ verdict: { code: 'internal_error' } });
  });

  test('a payment-rail failure consumes the decision; the retry must re-preflight, not re-verify', async () => {
    const { method, verifySpy } = mockMethod();
    const railError = new Error('rail down');
    verifySpy.mockRejectedValueOnce(railError);
    const wrapped = bolyraGate(method, await gateOptions());
    const input = requestWithBundle(await makeBundle());
    const capturedRequest = Object.freeze({ headers: new Headers(input.headers), method: input.method, url: new URL(input.url) });
    const credential = { challenge: {}, payload: {} } as unknown;
    await wrapped.preflight?.({ capturedRequest, credential, input, options: { amount: '25' }, realm: 'api.merchant.example', secretKey: 'test-secret-key-test-secret-key-32' });
    const envelope = { capturedRequest, challenge: {}, credential, request: { amount: '25' } };
    await expect(wrapped.verify({ credential, envelope, request: { amount: '25' } })).rejects.toBe(railError);
    await expect(wrapped.verify({ credential, envelope, request: { amount: '25' } })).rejects.toMatchObject({ name: 'BolyraDeniedError', verdict: { code: 'internal_error' } });
  });
});

describe('onDecision (TD-2)', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });
  const ID = 'ab'.repeat(32);

  function stubVerifier(body: unknown, headers: Record<string, string> = {}, status = 200) {
    global.fetch = jest.fn(async () =>
      new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } }),
    ) as unknown as typeof fetch;
    return { kind: 'url' as const, url: 'https://verify.example' };
  }
  const NONCE_ALLOW = {
    verdict: 'allow', kind: 'classical',
    consume_nonces: [{ issuer_key: 'op', nonce: 'n-1', retain_until: NOW_UNIX + 60 }],
  };

  /** Count unhandled rejections across `fn` plus a couple of macrotask turns. */
  async function withUnhandledCount(fn: () => Promise<void>): Promise<number> {
    let unhandled = 0;
    const onUnhandled = () => { unhandled += 1; };
    process.on('unhandledRejection', onUnhandled);
    try {
      await fn();
      for (let i = 0; i < 3; i += 1) await new Promise((resolve) => setImmediate(resolve));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
    return unhandled;
  }

  test('allow (classical): exactly one Decision, outcome allow, no code/status/evidence, request = the gate request context', async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied).toBeUndefined();
    expect(onDecision).toHaveBeenCalledTimes(1);
    expect(onDecision.mock.calls[0][0]).toEqual({
      outcome: 'allow',
      request: {
        agent_name: 'shopper-bot',
        project_key: AUDIENCE,
        program: 'mpp',
        model: 'opus-4.1',
        granted_capabilities: ['mpp:financial:small'],
      },
    });
  });

  test('allow (url): credentialId and receipt are the raw hosted-verifier headers', async () => {
    const onDecision = jest.fn();
    const verifier = stubVerifier({ verdict: 'allow', kind: 'classical' }, {
      'x-bolyra-credential-id': ID, 'x-bolyra-receipt': 'raw.receipt.value',
    });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, verifier }));
    await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(1);
    expect(onDecision.mock.calls[0][0]).toMatchObject({
      outcome: 'allow', credentialId: ID, receipt: 'raw.receipt.value',
    });
    expect(onDecision.mock.calls[0][0]).not.toHaveProperty('status');
    expect(onDecision.mock.calls[0][0]).not.toHaveProperty('code');
  });

  test('verifier deny: code, mapped status, reason and credentialId from verdict.detail', async () => {
    const onDecision = jest.fn();
    const verifier = stubVerifier({
      verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'not active',
      detail: { reason: 'credential_not_active', credential_id: ID },
    }, { 'x-bolyra-receipt': 'should-not-surface-on-deny' });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, verifier }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied!.status).toBe(401);
    expect(onDecision).toHaveBeenCalledTimes(1);
    const d = onDecision.mock.calls[0][0];
    expect(d).toMatchObject({
      outcome: 'deny', code: 'untrusted_root', status: 401,
      reason: 'credential_not_active', credentialId: ID,
    });
    expect(d).not.toHaveProperty('receipt');
    expect(d.request.project_key).toBe(AUDIENCE);
  });

  test('a free-text verifier reason is dropped from the HTTP body AND the Decision', async () => {
    const onDecision = jest.fn();
    const verifier = stubVerifier({
      verdict: 'deny', kind: 'classical', code: 'invalid_proof', message: 'bad envelope',
      detail: { reason: 'Invalid circuit.name: x', credential_id: ID },
    });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, verifier }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    const problem = await readProblem(denied!);
    expect(problem).not.toHaveProperty('reason');
    expect(problem.credential_id).toBe(ID);
    const d = onDecision.mock.calls[0][0];
    expect(d).not.toHaveProperty('reason');
    expect(d.credentialId).toBe(ID);
  });

  test('classical in-process free-text reason (proof-envelope validator message) is dropped from both surfaces', async () => {
    const onDecision = jest.fn();
    const bundle = JSON.parse(await makeBundle());
    bundle.agent.envelope = { circuit: 'not-an-object' };
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    const { denied } = await drive(wrapped, requestWithBundle(JSON.stringify(bundle)), { amount: '25' });
    const problem = await readProblem(denied!);
    expect(problem.code).toBe('invalid_proof');
    expect(problem).not.toHaveProperty('reason');
    expect(onDecision.mock.calls[0][0]).toMatchObject({ outcome: 'deny', code: 'invalid_proof' });
    expect(onDecision.mock.calls[0][0]).not.toHaveProperty('reason');
  });

  test('decide() itself throwing (receipt signer throws inside denyWith) → one deny/internal_error/500 Decision and a BolyraDeniedError', async () => {
    const real = receiptsModule.createGateReceiptSigner;
    jest.spyOn(receiptsModule, 'createGateReceiptSigner').mockImplementation((config) => ({
      ...real(config),
      sign: () => { throw new Error('signer exploded'); },
    }));
    const onDecision = jest.fn();
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    for (const bundle of [undefined, await makeBundle()]) {
      let caught: unknown;
      try {
        await drivePreflight(wrapped, requestWithBundle(bundle), { amount: '25' }, { credential: {} });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(BolyraDeniedError);
      const err = caught as BolyraDeniedError;
      expect(err.verdict).toMatchObject({ code: 'internal_error', message: 'authorization gate failed' });
      expect(err.response.status).toBe(500);
    }
    expect(verifySpy).not.toHaveBeenCalled();
    expect(onDecision).toHaveBeenCalledTimes(2);
    for (const [d] of onDecision.mock.calls) {
      expect(d).toEqual({
        outcome: 'deny', code: 'internal_error', status: 500,
        request: { agent_name: '', project_key: AUDIENCE, program: 'mpp', model: '', granted_capabilities: [] },
      });
    }
  });

  test('Decision.credentialId is capped at 256 chars on both allow (header) and deny (detail)', async () => {
    const onDecision = jest.fn();
    const long = 'c'.repeat(257);
    stubVerifier({ verdict: 'allow', kind: 'classical' }, { 'x-bolyra-credential-id': long });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, verifier: { kind: 'url', url: 'https://verify.example' } }));
    await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    stubVerifier({ verdict: 'deny', kind: 'classical', code: 'untrusted_root', message: 'x', detail: { credential_id: long, reason: 'tier_2_exceeded' } });
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(await readProblem(denied!)).not.toHaveProperty('credential_id');
    expect(onDecision).toHaveBeenCalledTimes(2);
    expect(onDecision.mock.calls[0][0]).not.toHaveProperty('credentialId');
    expect(onDecision.mock.calls[1][0]).not.toHaveProperty('credentialId');
    expect(onDecision.mock.calls[1][0].reason).toBe('tier_2_exceeded');
  });

  test('an onDecision GETTER that throws is contained: allow unchanged, deny and B11 still BolyraDeniedError, logged once per request', async () => {
    const logged: unknown[] = [];
    jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => { logged.push(args); });
    const hostile = await gateOptions();
    Object.defineProperty(hostile, 'onDecision', { get() { throw new Error('getter exploded'); }, enumerable: true });
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, hostile);

    const ok = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(ok.denied).toBeUndefined();
    expect(verifySpy).toHaveBeenCalledTimes(1);
    expect((ok.receipt as any).bolyraAuthorization.decision).toBe('allow');

    await expect(
      drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: {} }),
    ).rejects.toBeInstanceOf(BolyraDeniedError);
    expect(logged).toHaveLength(2);

    // B11 (decide() itself throws) with the same hostile getter.
    const real = receiptsModule.createGateReceiptSigner;
    jest.spyOn(receiptsModule, 'createGateReceiptSigner').mockImplementation((config) => ({
      ...real(config),
      sign: () => { throw new Error('signer exploded'); },
    }));
    const b11 = bolyraGate(mockMethod().method, hostile);
    let caught: unknown;
    try {
      await drivePreflight(b11, requestWithBundle(undefined), { amount: '25' }, { credential: {} });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(BolyraDeniedError);
    expect((caught as BolyraDeniedError).verdict.code).toBe('internal_error');
    expect(logged).toHaveLength(3);
  });

  // The tampered-native-Promise boundary is pinned in test-integration (child
  // process), because jest intercepts unhandled rejections itself.

  test('missing_authorization deny: one Decision, 401, no reason', async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    await drive(wrapped, requestWithBundle(undefined), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(1);
    expect(onDecision.mock.calls[0][0]).toMatchObject({ outcome: 'deny', code: 'missing_authorization', status: 401 });
    expect(onDecision.mock.calls[0][0]).not.toHaveProperty('reason');
  });

  test('replay deny: allow then nonce_replayed/403, one Decision per request', async () => {
    const onDecision = jest.fn();
    const verifier = stubVerifier(NONCE_ALLOW);
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, verifier }));
    const bundle = await makeBundle();
    await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(1);
    await drive(wrapped, requestWithBundle(bundle), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(2);
    expect(onDecision.mock.calls.map((c) => [c[0].outcome, c[0].code, c[0].status])).toEqual([
      ['allow', undefined, undefined],
      ['deny', 'nonce_replayed', 403],
    ]);
  });

  test('sink failure turning an allow into a 500 reports deny internal_error/500, after the sink ran', async () => {
    const order: string[] = [];
    const onReceipt = jest.fn(() => { order.push('sink'); throw new Error('sink down'); });
    const onDecision = jest.fn(() => { order.push('decision'); });
    const { method, verifySpy } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, onReceipt }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied!.status).toBe(500);
    expect(verifySpy).not.toHaveBeenCalled();
    expect(onDecision).toHaveBeenCalledTimes(1);
    expect(onDecision.mock.calls[0][0]).toMatchObject({ outcome: 'deny', code: 'internal_error', status: 500 });
    expect(order).toEqual(['sink', 'decision']);
  });

  test('an allow reports after the sink accepted the receipt', async () => {
    const order: string[] = [];
    const onReceipt = jest.fn(() => { order.push('sink'); });
    const onDecision = jest.fn(() => { order.push('decision'); });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, onReceipt }));
    await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(order).toEqual(['sink', 'decision']);
  });

  test("credential-less passthrough under enforce:'payment' (undefined or 402) fires nothing", async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, enforce: 'payment' }));
    await drivePreflight(wrapped, requestWithBundle(undefined), { amount: '25' }, { credential: null });
    const challenge = new Response(null, { status: 402 });
    const m402 = { ...mockMethod().method, preflight: jest.fn(() => challenge) };
    const wrapped402 = bolyraGate(m402, await gateOptions({ onDecision, enforce: 'payment' }));
    expect(await drivePreflight(wrapped402, requestWithBundle(undefined), { amount: '25' }, { credential: null })).toBe(challenge);
    expect(onDecision).not.toHaveBeenCalled();
  });

  test("credential-less refusals under enforce:'payment' (late authorize hook, non-402 preflight) report deny internal_error/500", async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const late = bolyraGate(method, await gateOptions({ onDecision, enforce: 'payment' }));
    (late as any).authorize = async () => undefined;
    await expect(drivePreflight(late, requestWithBundle(undefined), { amount: '25' }, { credential: null })).rejects.toMatchObject({ name: 'BolyraDeniedError' });
    const m403 = { ...mockMethod().method, preflight: jest.fn(() => new Response('nope', { status: 403 })) };
    const non402 = bolyraGate(m403, await gateOptions({ onDecision, enforce: 'payment' }));
    await expect(drivePreflight(non402, requestWithBundle(undefined), { amount: '25' }, { credential: null })).rejects.toMatchObject({ name: 'BolyraDeniedError' });
    expect(onDecision).toHaveBeenCalledTimes(2);
    for (const [d] of onDecision.mock.calls) {
      expect(d).toMatchObject({ outcome: 'deny', code: 'internal_error', status: 500, request: { project_key: AUDIENCE } });
    }
  });

  test('the verify hook never fires (fail-closed verify without a stashed decision)', async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    await expect(wrapped.verify({ credential: {}, envelope: undefined, request: { amount: '25' } } as never)).rejects.toBeInstanceOf(BolyraDeniedError);
    expect(onDecision).not.toHaveBeenCalled();
  });

  test("402 then pay under enforce:'always': two gate invocations, two Decisions (discovery allow + paid allow)", async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    await drivePreflight(wrapped, requestWithBundle(await makeBundle()), { amount: '25' }, { credential: null });
    expect(onDecision).toHaveBeenCalledTimes(1);
    await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(2);
    expect(onDecision.mock.calls.map((c) => c[0].outcome)).toEqual(['allow', 'allow']);
  });

  test("402 then pay under enforce:'payment': discovery fires nothing, the paid request fires once", async () => {
    const onDecision = jest.fn();
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision, enforce: 'payment' }));
    await drivePreflight(wrapped, requestWithBundle(await makeBundle()), { amount: '25' }, { credential: null });
    expect(onDecision).not.toHaveBeenCalled();
    await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(onDecision).toHaveBeenCalledTimes(1);
  });

  test('an observer mutating the Decision cannot change the stashed authorization', async () => {
    const onDecision = jest.fn((d: any) => {
      d.request.project_key = 'attacker.example';
      d.request.granted_capabilities.push('mpp:financial:unlimited');
      d.outcome = 'deny';
    });
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
    const { denied, receipt } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied).toBeUndefined();
    expect((receipt as any).bolyraAuthorization).toMatchObject({ audience: AUDIENCE, capability: 'mpp:financial:small' });
  });

  // Observer failure containment: authorization and response unchanged, the failure is logged,
  // nothing becomes an unhandled rejection — including when the logger itself throws.
  const failingObservers: Array<[string, () => (d: unknown) => unknown]> = [
    ['sync throw', () => () => { throw new Error('observer threw'); }],
    ['async rejection', () => async () => { throw new Error('observer rejected'); }],
    ['thenable whose then throws', () => () => ({ then() { throw new Error('then threw'); } })],
  ];
  for (const loggerThrows of [false, true]) {
    for (const [name, make] of failingObservers) {
      test(`${name}${loggerThrows ? ' + a THROWING logger' : ''}: allow and deny unchanged, no unhandled rejection`, async () => {
        const logged: unknown[] = [];
        jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
          logged.push(args);
          if (loggerThrows) throw new Error('logger down');
        });
        const onDecision = jest.fn(make());
        const unhandled = await withUnhandledCount(async () => {
          const { method, verifySpy } = mockMethod();
          const wrapped = bolyraGate(method, await gateOptions({ onDecision }));
          const ok = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
          expect(ok.denied).toBeUndefined();
          expect(verifySpy).toHaveBeenCalledTimes(1);
          expect((ok.receipt as any).bolyraAuthorization.decision).toBe('allow');

          const no = await drive(wrapped, requestWithBundle(undefined), { amount: '25' });
          expect(no.denied!.status).toBe(401);
          expect(await readProblem(no.denied!)).toMatchObject({ code: 'missing_authorization' });
        });
        expect(unhandled).toBe(0);
        expect(onDecision).toHaveBeenCalledTimes(2);
        expect(logged.length).toBe(2); // one containment log per failing observation
      });
    }
  }
});

describe('verifier URL normalization (TD-1)', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  test.each([
    ['https://verify.example', 'https://verify.example/v1/verify'],
    ['https://verify.example/', 'https://verify.example/v1/verify'],
    ['https://verify.test/v1/verify', 'https://verify.test/v1/verify'],
    ['https://verify.example/custom/', 'https://verify.example/custom/'],
    ['https://verify.example/custom/?x=1', 'https://verify.example/custom/?x=1'],
    ['https://verify.example?x=1', 'https://verify.example/v1/verify?x=1'],
  ])('verifier url %s is POSTed to %s', async (url, expected) => {
    const spy = jest.fn(async () =>
      new Response(JSON.stringify({ verdict: 'allow', kind: 'classical' }), { status: 200, headers: { 'content-type': 'application/json' } }),
    );
    global.fetch = spy as unknown as typeof fetch;
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ verifier: { kind: 'url', url } }));
    const { denied } = await drive(wrapped, requestWithBundle(await makeBundle()), { amount: '25' });
    expect(denied).toBeUndefined();
    expect((spy.mock.calls[0] as unknown[])[0]).toBe(expected);
  });

  test.each(['https://verify.example ', 'https://verify.example/ '])(
    'a whitespace-padded verifier url %p is refused at construction',
    async (url) => {
      const { method } = mockMethod();
      const options = await gateOptions({ verifier: { kind: 'url', url } });
      expect(() => bolyraGate(method, options)).toThrow(TypeError);
    },
  );

  test('an invalid verifier url is refused at construction', async () => {
    const { method } = mockMethod();
    const options = await gateOptions({ verifier: { kind: 'url', url: 'verify.example/v1/verify' } });
    expect(() => bolyraGate(method, options)).toThrow(TypeError);
    expect(() => bolyraGate(method, options)).toThrow(/url/);
  });
});
