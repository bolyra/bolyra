# Bolyra x Stripe agent-toolkit: verified agent spend

**Stripe's toolkit lets the agent spend; Bolyra proves it was authorized to.**

Stripe's agent toolkit ([github.com/stripe/ai](https://github.com/stripe/ai),
`@stripe/agent-toolkit`) hands an LLM agent Stripe API capabilities as
framework tools — `getTools()` returns `{ description, execute }` definitions
for the Vercel AI SDK, LangChain, or OpenAI function calling, and `execute`
goes straight to the Stripe API. There is no pre-spend authorization hook.
This demo shows the missing piece: an operator-signed **Bolyra spend mandate**
verified in front of the spend tool, so an over-mandate spend is denied
**before any Stripe call**, and every decision — allow and deny — emits a
signed, hash-chained authorization receipt.

## What it shows

1. **Operator issues a spend mandate** — `issueMandate` (`@bolyra/mpp`) signs
   an EdDSA-Poseidon binding delegating the `small` tier (< $100 per
   transaction) to agent `shopper-bot` for one audience, with an expiry.
2. **$25 spend → AUTHORIZED** — the guard verifies the mandate with
   `verifyClassical` (`@bolyra/mpp`: operator signature, trust anchor, expiry,
   audience/model binding, tier capability), then enforces the Stripe ACP
   per-transaction cap with `verifyStripeACPSpend`
   (`@bolyra/payment-protocols`). Both pass; the (mock) PaymentIntent tool
   runs; a signed allow receipt is written.
3. **$500 spend → DENIED before the Stripe call** — $500 requires the
   `medium` tier; the mandate only signs `small`. The real verifier denies
   (`request_mismatch`), the spend tool is never invoked (the demo proves the
   call count), and a signed deny receipt is written.
4. **Receipts verify independently** — `verifyReceipt` (`@bolyra/receipts`)
   validates both ES256K receipts; they are hash-chained (seq 0 → 1).

## Run it

```bash
npm install && npm run demo
```

Zero setup: no Stripe account, no API keys, no network, no circuit artifacts.
Tests: `npm test` (jest, 13 tests over the allow / deny / boundary / malformed-input / receipt paths).

## Honesty note: real authorization, stubbed Stripe call

- **Real shipped Bolyra code:** mandate issuance (`issueMandate`),
  cryptographic verification (`verifyClassical` — the same verifier the
  shipped `bolyraGate` uses), tier mapping (`requiredTierForUsdAmount`),
  the Stripe ACP spend decision (`verifyStripeACPSpend`), and receipt
  signing/verification (`createGateReceiptSigner`, `verifyReceipt`).
- **Mock:** the Stripe tool itself. `src/stripe-toolkit-stub.ts` is a
  clearly-labeled stand-in for `@stripe/agent-toolkit`'s create-PaymentIntent
  tool — same `{ description, execute }` shape, but it fabricates a
  `pi_test_*` object locally. No real PaymentIntent is ever created.
- **Composition seam:** Stripe's toolkit has no pre-execution hook, so
  `src/guard.ts` wraps the tool — the guarded `execute` runs the Bolyra
  authorization pipeline and only delegates to the Stripe tool on an allow.
  Swapping the stub for the real toolkit tool is a one-line change; the
  authorization path is unchanged.

## Files

| File | Role |
|---|---|
| `src/demo.ts` | The narrated end-to-end flow |
| `src/guard.ts` | The seam: Bolyra authorization wrapped around the spend tool |
| `src/stripe-toolkit-stub.ts` | **Mock** Stripe agent-toolkit spend tool (labeled) |
| `test/guard.test.ts` | Jest assertions: allow / deny / boundary / receipts |

## Classical trust boundary

This demo runs the classical (non-ZK) verifier: the operator's EdDSA
signature over the binding is the load-bearing authorization, covering the
tier capabilities and expiry. Sound permission-bitmask enforcement under an
adversarial presenter additionally needs the zk-class verifier
(`bolyra verify`) — see `@bolyra/mpp`'s README for the full trust model.
