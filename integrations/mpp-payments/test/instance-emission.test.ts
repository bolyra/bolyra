/**
 * Wiring tests for receipt instance binding (spec/receipt-instance-binding-v1.md
 * §4): the gate computes `decisionAt` once per decision from an injectable
 * millisecond clock, every emitted commerce receipt carries a semantically
 * valid `instance` block, and the §3.1.1 audience identifier syntax is
 * enforced at gate construction and mandate issuance (entry-side), not only
 * at verification.
 */
import { computeInstanceRef, verifyInstanceBinding, verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import {
  bolyraGate,
  buildDecisionInstance,
  issueMandate,
  type BolyraGateOptions,
  type DecisionFacts,
} from '../src/index';
import { AUDIENCE, EXPIRY, NOW_UNIX, OPERATOR_PRIV, makeBundle, operatorKey } from './helpers';

/** Millisecond clock with a non-zero ms component, to prove ms precision. */
const NOW_MS = NOW_UNIX * 1000 + 123;

function mockMethod() {
  return {
    method: {
      name: 'mock',
      preflight: undefined,
      verify: async () => ({ method: 'mock', status: 'success' }),
    } as never,
  };
}

async function gateOptions(overrides: Partial<BolyraGateOptions> = {}): Promise<BolyraGateOptions> {
  return {
    audience: AUDIENCE,
    verifier: { kind: 'classical', trustedOperators: [await operatorKey()] },
    ...overrides,
  } as BolyraGateOptions;
}

/** Drive preflight only — receipts are emitted at decision time. */
async function preflight(
  wrapped: ReturnType<typeof bolyraGate>,
  bundle: string | undefined,
  options: Record<string, unknown>,
) {
  const input = new Request('https://api.merchant.example/paid', {
    headers: bundle !== undefined ? { 'x-bolyra-authorization': bundle } : {},
  });
  return wrapped.preflight?.({
    capturedRequest: Object.freeze({
      headers: new Headers(input.headers),
      method: input.method,
      url: new URL(input.url),
    }),
    credential: { challenge: {}, payload: {} } as unknown,
    input,
    options,
    realm: 'api.merchant.example',
    secretKey: 'test-secret-key-test-secret-key-32',
  });
}

describe('clock injection (exactly one of now / nowMs)', () => {
  test('passing both now and nowMs is a construction-time TypeError', async () => {
    const { method } = mockMethod();
    const options = await gateOptions({ now: () => NOW_UNIX, nowMs: () => NOW_MS });
    expect(() => bolyraGate(method, options)).toThrow(/exactly one clock|not both/i);
  });

  test('nowMs alone constructs and drives expiry checks', async () => {
    const { method } = mockMethod();
    const wrapped = bolyraGate(method, await gateOptions({ nowMs: () => NOW_MS }));
    const result = await preflight(wrapped, await makeBundle(), { amount: '25' });
    expect(result).not.toBeInstanceOf(Response); // allow → preflight passes through
  });
});

describe('emitted receipts carry a valid instance block', () => {
  async function captureReceipt(
    overrides: Partial<BolyraGateOptions>,
    amount: string,
  ): Promise<{ receipt: SignedReceipt; denied: boolean }> {
    const receipts: SignedReceipt[] = [];
    const { method } = mockMethod();
    const wrapped = bolyraGate(
      method,
      await gateOptions({ ...overrides, onReceipt: (r) => receipts.push(r) }),
    );
    const result = await preflight(wrapped, await makeBundle(), { amount });
    expect(receipts).toHaveLength(1);
    return { receipt: receipts[0], denied: result instanceof Response };
  }

  test('allow: instance present, semantically valid, ms-precise decisionAt', async () => {
    const { receipt, denied } = await captureReceipt({ nowMs: () => NOW_MS }, '25');
    expect(denied).toBe(false);
    expect(verifyReceipt(receipt)).toBe(true);
    expect(verifyInstanceBinding(receipt)).toEqual({ ok: true, present: true, code: 'ok' });
    const preimage = receipt.payload.instance!.preimage;
    expect(preimage.decisionAt).toBe(new Date(NOW_MS).toISOString());
    expect(preimage.audience).toBe(AUDIENCE);
    expect(preimage.program).toBe('mpp');
    expect(preimage.amountUsd).toBe('25');
    expect(preimage.requestNonce).toBeUndefined(); // MPP has no pre-decision challenge nonce
  });

  test('seconds-resolution now injector yields .000Z decisionAt (non-breaking path)', async () => {
    const { receipt } = await captureReceipt({ now: () => NOW_UNIX }, '25');
    expect(receipt.payload.instance!.preimage.decisionAt).toBe(
      new Date(NOW_UNIX * 1000).toISOString(),
    );
    expect(receipt.payload.instance!.preimage.decisionAt).toMatch(/\.000Z$/);
  });

  test('deny receipts carry the instance block too', async () => {
    // Mandate covers financial:small (< $100); $250 exceeds it → deny.
    const { receipt, denied } = await captureReceipt({ nowMs: () => NOW_MS }, '250');
    expect(denied).toBe(true);
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(verifyInstanceBinding(receipt)).toEqual({ ok: true, present: true, code: 'ok' });
  });
});

describe('fail-closed emission (instance construction must never throw out of the gate)', () => {
  async function captureWithResult(
    overrides: Partial<BolyraGateOptions>,
    amount: string,
    bundle?: string,
  ) {
    const receipts: SignedReceipt[] = [];
    const { method } = mockMethod();
    const wrapped = bolyraGate(
      method,
      await gateOptions({ ...overrides, onReceipt: (r) => receipts.push(r) }),
    );
    const result = await preflight(wrapped, bundle ?? (await makeBundle()), { amount });
    return { receipts, result };
  }

  test.each([
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['negative', -1000],
    ['zero', 0],
    ['sub-second epoch (floors to now_unix 0)', 500],
  ])('a clock returning %s denies internal_error (invalid sample, fail closed)', async (_n, value) => {
    const { receipts, result } = await captureWithResult({ nowMs: () => value }, '25');
    expect(result).toBeInstanceOf(Response);
    const problem = await (result as Response).json();
    expect(problem.code).toBe('internal_error');
    expect(receipts).toHaveLength(1);
    expect(receipts[0].payload.instance).toBeUndefined();
  });

  test('a throwing clock denies internal_error instead of escaping', async () => {
    const { receipts, result } = await captureWithResult(
      { nowMs: () => { throw new Error('clock boom'); } },
      '25',
    );
    expect(result).toBeInstanceOf(Response);
    const problem = await (result as Response).json();
    expect(problem.code).toBe('internal_error');
    expect(receipts).toHaveLength(1);
    expect(receipts[0].payload.instance).toBeUndefined();
  });

  test('missing_authorization (pre-amount facts unknown at header time) carries NO instance', async () => {
    const receipts: SignedReceipt[] = [];
    const { method } = mockMethod();
    const wrapped = bolyraGate(
      method,
      await gateOptions({ nowMs: () => NOW_MS, onReceipt: (r) => receipts.push(r) }),
    );
    const result = await preflight(wrapped, undefined, { amount: '25' });
    expect(result).toBeInstanceOf(Response);
    expect(receipts).toHaveLength(1);
    expect(receipts[0].payload.decision.reasonCode).toBe('missing_authorization');
    expect(receipts[0].payload.instance).toBeUndefined();
  });

  test('an out-of-domain amountUsd (non-ASCII) denies internal_error, receipt without instance', async () => {
    const { receipts, result } = await captureWithResult(
      {
        nowMs: () => NOW_MS,
        // Fullwidth "25" — numeric-looking, but outside the §3.1 ASCII domain.
        amountToUsd: () => '２５',
      },
      '25',
    );
    expect(result).toBeInstanceOf(Response);
    const problem = await (result as Response).json();
    expect(problem.code).toBe('internal_error');
    expect(receipts.length).toBeGreaterThanOrEqual(1);
    for (const r of receipts) expect(r.payload.instance).toBeUndefined();
  });

  test('a non-ASCII program is rejected at gate construction', async () => {
    const { method } = mockMethod();
    const options = await gateOptions({ program: 'paiements—x402' });
    expect(() => bolyraGate(method, options)).toThrow(/ASCII/);
  });
});

describe('buildDecisionInstance', () => {
  const facts: DecisionFacts = {
    request: {
      agent_name: 'shopper-bot',
      project_key: AUDIENCE,
      program: 'mpp',
      model: 'demo-model',
      granted_capabilities: ['mpp:financial:small'],
    } as DecisionFacts['request'],
    tier: 'small',
    amountUsd: '25',
    decisionAt: '2026-08-25T03:00:00.123Z',
  };

  test('ref recomputes from the preimage', () => {
    const instance = buildDecisionInstance(facts);
    expect(instance.ref).toBe(computeInstanceRef(instance.preimage));
    expect(instance.preimage.decisionAt).toBe('2026-08-25T03:00:00.123Z');
  });

  test('requestNonce is included exactly when the facts carry one', () => {
    const withNonce = buildDecisionInstance({ ...facts, requestNonce: 'challenge-abc' });
    expect(withNonce.preimage.requestNonce).toBe('challenge-abc');
    expect(withNonce.ref).not.toBe(buildDecisionInstance(facts).ref);
    expect(buildDecisionInstance(facts).preimage).not.toHaveProperty('requestNonce');
  });
});

describe('§3.1.1 audience enforcement at the entry points', () => {
  test('bolyraGate rejects a display-name audience at construction', async () => {
    const { method } = mockMethod();
    const options = await gateOptions({ audience: 'Acme Corp' });
    expect(() => bolyraGate(method, options)).toThrow(/identifier|3\.1\.1|printable ASCII/i);
  });

  test('issueMandate rejects a display-name audience', async () => {
    await expect(
      issueMandate({
        operatorPrivateKey: OPERATOR_PRIV,
        agentName: 'shopper-bot',
        audience: 'Acme Corp',
        model: 'demo-model',
        tier: 'small',
        expiry: EXPIRY,
      }),
    ).rejects.toThrow(/identifier|3\.1\.1|printable ASCII/i);
  });
});
