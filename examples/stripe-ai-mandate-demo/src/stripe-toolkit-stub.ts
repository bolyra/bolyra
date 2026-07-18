/**
 * STUB — a mock of a Stripe agent-toolkit spend tool. NOT the real thing.
 *
 * Stripe's agent toolkit (github.com/stripe/ai, `@stripe/agent-toolkit`)
 * hands an LLM agent Stripe API capabilities as framework tools: you build a
 * `StripeAgentToolkit` with a restricted API key and `getTools()` returns
 * tool definitions ({ description, parameters, execute }) for the Vercel AI
 * SDK, LangChain, or OpenAI function calling. When the model calls a payment
 * tool, `execute` hits the live Stripe API.
 *
 * This file stands in for exactly that surface so the demo runs with ZERO
 * setup and ZERO network: same `{ description, execute }` tool shape, but
 * `execute` fabricates a `pi_test_*` PaymentIntent object locally instead of
 * calling Stripe. Nothing here talks to Stripe, needs an API key, or moves
 * money. Every place the demo prints a PaymentIntent it is labeled SIMULATED.
 *
 * The point of the demo is what happens BEFORE this tool runs — the Bolyra
 * authorization path in `guard.ts` is real shipped code; only this Stripe
 * call is mocked.
 */

import * as crypto from 'crypto';

import type { SpendToolInput, SpendToolLike } from './guard';

export type { SpendToolInput } from './guard';

/** A locally fabricated PaymentIntent-shaped object. Never touched Stripe. */
export interface SimulatedPaymentIntent {
  id: string;
  object: 'payment_intent';
  amount: number;
  currency: string;
  status: 'requires_confirmation';
  /** Honest marker so no consumer can mistake this for a live object. */
  simulated: true;
}

/**
 * The stub tool, implementing the guard's minimal `SpendToolLike` seam (the
 * `@stripe/agent-toolkit` tool shape: `description` + `execute`), plus a
 * demo-only call log so the demo and tests can PROVE the tool was never
 * invoked on a denied spend. A real toolkit tool satisfies `SpendToolLike`
 * without the log.
 */
export interface StripeSpendToolStub extends SpendToolLike<SimulatedPaymentIntent> {
  name: 'create_payment_intent';
  /** Every invocation that reached the (mock) Stripe call. */
  readonly calls: ReadonlyArray<SpendToolInput>;
}

/** Create a fresh stub spend tool with an empty call log. */
export function createStripeSpendToolStub(): StripeSpendToolStub {
  const calls: SpendToolInput[] = [];
  return {
    name: 'create_payment_intent',
    description:
      '[MOCK] Create a Stripe PaymentIntent for the given amount/currency. ' +
      'Stands in for the @stripe/agent-toolkit payment tool; no network call.',
    async execute(input: SpendToolInput): Promise<SimulatedPaymentIntent> {
      calls.push({ ...input });
      return {
        id: `pi_test_${crypto.randomBytes(8).toString('hex')}`,
        object: 'payment_intent',
        amount: input.amount,
        currency: input.currency,
        status: 'requires_confirmation',
        simulated: true,
      };
    },
    calls,
  };
}
