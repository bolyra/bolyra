/**
 * Asserts the demo's allow / deny / receipt outcomes:
 *   - $25 spend is AUTHORIZED and reaches the (mock) Stripe tool
 *   - $500 spend is DENIED by the real mandate verifier BEFORE any Stripe call
 *   - $100 boundary spend is DENIED (small tier is strict `< $100`)
 *   - non-USD spend is DENIED by the real Stripe ACP currency check
 *   - an untrusted operator's mandate is DENIED
 *   - every decision emits a signed, independently verifiable, hash-chained
 *     receipt
 */

import { derivePublicKey } from '@bolyra/sdk';
import { createGateReceiptSigner, issueMandate } from '@bolyra/mpp';
import type { IssuedMandate, OperatorKey } from '@bolyra/mpp';
import { verifyReceipt } from '@bolyra/receipts';

import { guardSpendTool, centsToUsdString, SpendToolExecutionError } from '../src/guard';
import type { GuardedSpendTool } from '../src/guard';
import { createStripeSpendToolStub } from '../src/stripe-toolkit-stub';
import type { StripeSpendToolStub } from '../src/stripe-toolkit-stub';

const OPERATOR_PRIVATE_KEY = 42n; // test fixture — never a real key
const AGENT_NAME = 'shopper-bot';
const AUDIENCE = 'acct_demo_merchant';
const MODEL = 'opus-4.1';

let trustedOperators: OperatorKey[];
let mandate: IssuedMandate;

beforeAll(async () => {
  const pub = await derivePublicKey(OPERATOR_PRIVATE_KEY);
  trustedOperators = [{ x: pub.x.toString(), y: pub.y.toString() }];
  mandate = await issueMandate({
    operatorPrivateKey: OPERATOR_PRIVATE_KEY,
    agentName: AGENT_NAME,
    audience: AUDIENCE,
    model: MODEL,
    tier: 'small', // < $100
    expiry: Math.floor(Date.now() / 1000) + 3600,
  });
});

function makeGuard(overrides: { trustedOperators?: OperatorKey[] } = {}): {
  guarded: GuardedSpendTool<StripeSpendToolStub>;
  stub: StripeSpendToolStub;
} {
  const stub = createStripeSpendToolStub();
  const guarded = guardSpendTool(stub, {
    mandate: mandate.presentation,
    trustedOperators: overrides.trustedOperators ?? trustedOperators,
    agentName: AGENT_NAME,
    audience: AUDIENCE,
    model: MODEL,
    receiptSigner: createGateReceiptSigner({ issuer: 'stripe-ai-mandate-demo-test' }),
    merchant: AUDIENCE,
  });
  return { guarded, stub };
}

describe('centsToUsdString', () => {
  it('converts minor units exactly, without floats', () => {
    expect(centsToUsdString(2500)).toBe('25.00');
    expect(centsToUsdString(50000)).toBe('500.00');
    expect(centsToUsdString(9999)).toBe('99.99');
    expect(centsToUsdString(1)).toBe('0.01');
  });

  it('rejects non-integer and negative amounts', () => {
    expect(() => centsToUsdString(25.5)).toThrow(TypeError);
    expect(() => centsToUsdString(-1)).toThrow(TypeError);
  });
});

describe('guarded spend tool', () => {
  it('authorizes a $25 spend within the small tier and calls the stub', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 2500, currency: 'usd' });

    expect(result.authorized).toBe(true);
    if (!result.authorized) return; // type narrowing
    expect(result.tier).toBe('small');
    expect(result.capChecked).toBe(10_000); // $100 in cents
    expect(result.paymentIntent.simulated).toBe(true);
    expect(result.paymentIntent.amount).toBe(2500);
    expect(stub.calls).toHaveLength(1);

    // Signed allow receipt, independently verifiable. intentHash is the
    // bare 64-hex sha256 the receipts verify CLI requires.
    expect(result.receipt.payload.decision.allowed).toBe(true);
    expect(result.receipt.payload.commerce?.rail).toBe('stripe-acp');
    expect(result.receipt.payload.commerce?.intentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyReceipt(result.receipt)).toBe(true);
  });

  it('canonicalizes a mixed-case currency before it reaches the tool', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 2500, currency: 'USD' });

    expect(result.authorized).toBe(true);
    expect(stub.calls).toHaveLength(1);
    expect(stub.calls[0].currency).toBe('usd'); // canonical form, not the raw input
  });

  it('preserves extra tool fields through the wrapper (framework registration)', async () => {
    const stub = createStripeSpendToolStub();
    const withParams = { ...stub, parameters: { type: 'object' as const } };
    const guarded = guardSpendTool(withParams, {
      mandate: mandate.presentation,
      trustedOperators,
      agentName: AGENT_NAME,
      audience: AUDIENCE,
      model: MODEL,
      receiptSigner: createGateReceiptSigner({ issuer: 'stripe-ai-mandate-demo-test' }),
      merchant: AUDIENCE,
    });

    expect(guarded.name).toBe('create_payment_intent');
    expect(guarded.parameters).toEqual({ type: 'object' });
    expect(guarded.description).toContain('guarded by a Bolyra spend mandate');
  });

  it('attaches the signed allow receipt when the tool fails AFTER authorization', async () => {
    const stub = createStripeSpendToolStub();
    const failing = {
      ...stub,
      execute: async () => {
        throw new Error('stripe is down');
      },
    };
    const guarded = guardSpendTool(failing, {
      mandate: mandate.presentation,
      trustedOperators,
      agentName: AGENT_NAME,
      audience: AUDIENCE,
      model: MODEL,
      receiptSigner: createGateReceiptSigner({ issuer: 'stripe-ai-mandate-demo-test' }),
      merchant: AUDIENCE,
    });

    const err = await guarded.execute({ amount: 2500, currency: 'usd' }).catch((e) => e);
    expect(err).toBeInstanceOf(SpendToolExecutionError);
    // The authorization decision survives the downstream failure.
    expect(err.receipt.payload.decision.allowed).toBe(true);
    expect(verifyReceipt(err.receipt)).toBe(true);
  });

  it('denies a $500 spend BEFORE the Stripe tool is ever called', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 50_000, currency: 'usd' });

    expect(result.authorized).toBe(false);
    if (result.authorized) return;
    expect(result.deniedBy).toBe('mandate');
    // $500 needs the medium tier; the mandate only signs small.
    expect(result.reason).toContain('mpp:financial:medium');
    expect(stub.calls).toHaveLength(0); // the mock Stripe tool never ran

    // Denials get signed receipts too.
    expect(result.receipt.payload.decision.allowed).toBe(false);
    expect(result.receipt.payload.decision.reasonCode).toBe('request_mismatch');
    expect(verifyReceipt(result.receipt)).toBe(true);
  });

  it('denies exactly $100 — the small tier cap is strict (< $100)', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 10_000, currency: 'usd' });

    expect(result.authorized).toBe(false);
    expect(stub.calls).toHaveLength(0);
  });

  it('denies a non-USD spend via the real ACP currency check', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 2500, currency: 'eur' });

    expect(result.authorized).toBe(false);
    if (result.authorized) return;
    expect(result.deniedBy).toBe('stripe-acp');
    expect(result.reason).toContain('Currency mismatch');
    expect(stub.calls).toHaveLength(0);
    expect(verifyReceipt(result.receipt)).toBe(true);
  });

  it('fails closed WITH a signed receipt on malformed currency input', async () => {
    const { guarded, stub } = makeGuard();
    // Runtime tool-call JSON can carry anything; the guard must deny, not throw.
    const result = await guarded.execute({ amount: 2500, currency: undefined as unknown as string });

    expect(result.authorized).toBe(false);
    if (result.authorized) return;
    expect(result.deniedBy).toBe('stripe-acp');
    expect(result.reason).toContain('invalid currency');
    expect(result.receipt.payload.decision.reasonCode).toBe('invalid_currency');
    expect(verifyReceipt(result.receipt)).toBe(true);
    expect(stub.calls).toHaveLength(0);
  });

  it('fails closed WITH a signed receipt on a non-integer amount', async () => {
    const { guarded, stub } = makeGuard();
    const result = await guarded.execute({ amount: 25.5, currency: 'usd' });

    expect(result.authorized).toBe(false);
    if (result.authorized) return;
    expect(result.receipt.payload.decision.reasonCode).toBe('invalid_amount');
    expect(verifyReceipt(result.receipt)).toBe(true);
    expect(stub.calls).toHaveLength(0);
  });

  it('denies a mandate from an operator that is not a trusted issuer', async () => {
    const otherPub = await derivePublicKey(7n);
    const { guarded, stub } = makeGuard({
      trustedOperators: [{ x: otherPub.x.toString(), y: otherPub.y.toString() }],
    });
    const result = await guarded.execute({ amount: 2500, currency: 'usd' });

    expect(result.authorized).toBe(false);
    if (result.authorized) return;
    expect(result.deniedBy).toBe('mandate');
    expect(result.reason).toContain('untrusted_root');
    expect(stub.calls).toHaveLength(0);
  });

  it('hash-chains consecutive receipts from the same signer', async () => {
    const { guarded } = makeGuard();
    const first = await guarded.execute({ amount: 2500, currency: 'usd' });
    const second = await guarded.execute({ amount: 50_000, currency: 'usd' });

    expect(first.receipt.payload.chain?.seq).toBe(0);
    expect(second.receipt.payload.chain?.seq).toBe(1);
    expect(second.receipt.payload.chain?.prevReceiptHash).toBe(first.receipt.receiptHash);
  });
});
