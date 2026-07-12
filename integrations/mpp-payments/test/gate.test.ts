/**
 * bolyraGate contract, driven through the mppx `Method.Server` hook seam the
 * wrapper composes into (`preflight` runs before the challenge/verification
 * path; a returned Response fully handles the request; `verify` runs only on
 * the credential-bearing payment path). The runnable example under
 * `examples/mandate-demo` exercises the same wrapper through the real
 * `Mppx.create()` request lifecycle.
 */

import { verifyReceipt, type SignedReceipt } from '@bolyra/receipts';
import { bolyraGate, BOLYRA_AUTHORIZATION_HEADER } from '../src/gate';
import type { BolyraGateOptions, OperatorKey } from '../src/types';
import { AUDIENCE, EXPIRY, NOW_UNIX, makeBundle, operatorKey } from './helpers';

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
  const preflightResult = await wrapped.preflight?.({
    capturedRequest,
    credential,
    input,
    options,
    realm: 'api.merchant.example',
    secretKey: 'test-secret-key-test-secret-key-32',
  });
  if (preflightResult instanceof Response) {
    return { denied: preflightResult, receipt: undefined };
  }
  const receipt = await wrapped.verify({
    credential,
    envelope: { capturedRequest, challenge: {}, credential, request: options },
    request: options,
  });
  return { denied: undefined, receipt };
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

    const result = await wrapped.preflight?.({
      capturedRequest: Object.freeze({}),
      credential: null,
      input: requestWithBundle(undefined),
      options: { amount: '25' },
    });
    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(401);
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
