# Stripe ACP End-to-End Demo — Design Spec

**Date:** 2026-06-19
**Pipeline:** pdlc-2026-06-19-stripe-acp-demo
**Author:** Viswa + Claude Opus 4.6
**Status:** Draft (pending Gate 1)

## Overview

A standalone, runnable demo at `examples/stripe-acp-demo/` that shows the full Bolyra + Stripe Agent Commerce Protocol flow. A human delegates `FINANCIAL_SMALL` (< $100) authority to an agent via SD-JWT receipt, then the agent attempts four operations — two of which succeed and two of which are correctly rejected. Every decision produces a signed audit receipt that can be independently verified with `bolyra receipt verify`.

The demo runs entirely in Stripe test mode with no real charges, requires no circuit artifacts (dev mode), and produces colored terminal output showing each step of the authorization flow.

## Goals

1. **Demonstrate the Bolyra value proposition in 30 seconds of terminal output.** A prospect runs `npm run demo:stripe-acp` and sees delegation, authorization, rejection, and audit — the full loop.
2. **Exercise the real package APIs.** No mocks of Bolyra internals — uses `@bolyra/sdk`, `@bolyra/payment-protocols`, and `@bolyra/receipts` as published.
3. **Produce verifiable artifacts.** Every decision writes a receipt JSON to `examples/stripe-acp-demo/receipts/`, and the demo ends by verifying them all.

## Non-Goals

- No Stripe SDK integration (no `stripe` npm package). The demo simulates PaymentIntent creation to keep it zero-config. Real Stripe integration is a separate feature.
- No on-chain verification. Everything runs off-chain in dev mode.
- No MCP server/client. This is a direct-invocation demo, not an MCP tool-call flow.

## Architecture

```
examples/stripe-acp-demo/
├── package.json          # workspace package, depends on @bolyra/sdk, @bolyra/payment-protocols, @bolyra/receipts
├── tsconfig.json         # strict mode, extends root
├── src/
│   ├── demo.ts           # main entry point — orchestrates all 4 scenarios
│   ├── setup.ts          # creates human identity, agent credential, delegation receipt
│   ├── scenarios.ts      # the 4 scenario functions
│   ├── stripe-sim.ts     # simulated Stripe PaymentIntent creation (no real Stripe SDK)
│   ├── receipt-writer.ts # writes + verifies signed receipts to disk
│   └── colors.ts         # ANSI color helpers for terminal output
└── receipts/             # .gitignored — written at runtime
```

### Flow

```
1. SETUP
   ├── Create human identity (dev mode, no circuit artifacts)
   ├── Create agent credential with FINANCIAL_SMALL scope (bitmask = 0b00000111 = bits 0,1,2)
   │   Note: FINANCIAL_SMALL is bit 2, cumulative with READ_DATA (0) + WRITE_DATA (1)
   └── Generate delegation SD-JWT receipt (human → agent)

2. SCENARIO A: $25 charge — ALLOWED
   ├── Build BolyraVerifiedContext (verified=true, bitmask=0b00000111, chainDepth=1)
   ├── authContextToStripeACPContext() → StripeACPContext with tier=small, cap=10000 cents
   ├── verifyStripeACPSpend(ctx, 2500, 'usd') → { allowed: true }
   ├── Simulate PaymentIntent creation (pi_test_xxx)
   └── Sign commerce receipt → receipts/scenario-a-allowed.json

3. SCENARIO B: $480 charge — REJECTED (amount_exceeds_cap)
   ├── Same StripeACPContext as Scenario A
   ├── verifyStripeACPSpend(ctx, 48000, 'usd') → { allowed: false, reason: "Amount 48000 meets or exceeds small-tier cap..." }
   ├── No PaymentIntent created
   └── Sign commerce receipt with allowed=false → receipts/scenario-b-rejected.json

4. SCENARIO C: Confirm payment without SIGN_ON_BEHALF — REJECTED (fails closed)
   ├── Same StripeACPContext (bitmask has no bit 5)
   ├── verifyStripeACPSpend(ctx, 2500, 'usd', 'confirm') → { allowed: false, reason: "Confirm operation requires SIGN_ON_BEHALF..." }
   ├── No PaymentIntent confirmation
   └── Sign commerce receipt with allowed=false → receipts/scenario-c-rejected.json

5. SCENARIO D: Verify all receipts
   ├── Read all 3 receipt files from receipts/
   ├── verifyReceipt() on each → all PASS
   └── Print summary table
```

### Identity Setup

The demo creates identities using the same pattern as `examples/mcp-demo/src/shared.ts`:

- **Human:** `createHumanIdentity(DEMO_SECRET)` — stable demo secret, dev mode (no circuit artifacts needed)
- **Agent:** `createAgentCredential(modelHash, operatorKey, [READ_DATA, WRITE_DATA, FINANCIAL_SMALL], expiry)` — the key detail is that FINANCIAL_SMALL (bit 2) is present, but FINANCIAL_MEDIUM (bit 3), FINANCIAL_UNLIMITED (bit 4), and SIGN_ON_BEHALF (bit 5) are absent
- **Delegation:** The demo constructs a `BolyraVerifiedContext` directly (simulating what `verifyBundle` would return after a real handshake + delegation chain verification), with `chainDepth: 1` to represent one delegation hop

This approach keeps the demo fast (<1s total) and zero-config. A real integration would use `attachDelegatedBolyraProof` + `verifyBundle` from `@bolyra/mcp`.

### Receipt Signing

Each scenario signs a receipt using `@bolyra/receipts`:

1. Build a `CommerceReceiptInput` (or `AuthReceiptInput` for the confirm scenario) with the decision outcome
2. `createCommerceReceipt(input, config)` produces the `ReceiptPayload`
3. `signReceipt(payload, signerConfig)` produces the `SignedReceipt` with ES256K signature
4. Write JSON to `receipts/scenario-{letter}-{outcome}.json`

The final verification step reads them back and runs `verifyReceipt()` on each, proving the audit trail is cryptographically sound.

### Stripe Simulation

`stripe-sim.ts` provides a `simulatePaymentIntent()` function that returns a mock PaymentIntent object matching Stripe's shape:

```typescript
interface SimulatedPaymentIntent {
  id: string;           // "pi_test_" + random hex
  amount: number;       // minor units
  currency: string;
  status: 'requires_confirmation' | 'succeeded';
  metadata: {
    bolyra_acting_did: string;
    bolyra_root_did: string;
    bolyra_receipt_id: string;
  };
}
```

This is clearly labeled as simulated — the demo prints "SIMULATED" in the output and the README explains that real Stripe integration requires the `stripe` npm package + API keys.

### Terminal Output

The demo uses ANSI escape codes for colored output:

- Green checkmark + "ALLOWED" for approved scenarios
- Red X + "REJECTED" for denied scenarios
- Yellow for warnings
- Cyan for receipt IDs and file paths
- Dim for metadata

Example output structure:
```
=== Bolyra x Stripe ACP Demo ===

Setting up identities...
  Human identity:  created (dev mode)
  Agent credential: FINANCIAL_SMALL (bitmask: 0b00000111)
  Delegation:      human → agent (1 hop, SD-JWT receipt)

─── Scenario A: $25 charge ───
  Spend check:     ALLOWED (tier=small, cap=$100)
  PaymentIntent:   pi_test_a1b2c3d4 (SIMULATED)
  Receipt:         receipts/scenario-a-allowed.json
  ✓ $25.00 authorized

─── Scenario B: $480 charge ───
  Spend check:     REJECTED
  Reason:          Amount 48000 meets or exceeds small-tier cap of 10000 usd
  Receipt:         receipts/scenario-b-rejected.json
  ✗ $480.00 correctly rejected

─── Scenario C: Confirm without SIGN_ON_BEHALF ───
  Spend check:     REJECTED
  Reason:          Confirm operation requires SIGN_ON_BEHALF (bit 5)
  Receipt:         receipts/scenario-c-rejected.json
  ✗ Confirm correctly rejected

─── Receipt Verification ───
  scenario-a-allowed.json:   VALID ✓
  scenario-b-rejected.json:  VALID ✓
  scenario-c-rejected.json:  VALID ✓

All 3 receipts verified. Audit trail intact.
```

### Package Configuration

`examples/stripe-acp-demo/package.json`:
- Name: `@bolyra/stripe-acp-demo` (private, not published)
- Dependencies: workspace references to `@bolyra/sdk`, `@bolyra/payment-protocols`, `@bolyra/receipts`
- Scripts: `demo` → `npx tsx src/demo.ts`

Root `package.json` gets a new script:
- `demo:stripe-acp` → `cd examples/stripe-acp-demo && npx tsx src/demo.ts`

### Dev Mode

The demo sets `process.env.BOLYRA_DEV_MODE = '1'` before importing `@bolyra/sdk` to skip circuit artifact loading. The `BolyraVerifiedContext` is constructed directly rather than through proof generation, so no `.zkey`, `.vkey`, or `.ptau` files are needed.

## Security Considerations

- **No real credentials.** Demo uses hardcoded secrets that are clearly labeled as demo-only.
- **No real Stripe calls.** The `stripe-sim.ts` module never touches the network.
- **Receipt signing key is ephemeral.** Generated at demo start, not persisted.
- **Receipts directory is .gitignored.** Runtime artifacts stay local.

## Dependencies (new)

No new npm dependencies. The demo uses only existing workspace packages:
- `@bolyra/sdk` — identity creation
- `@bolyra/payment-protocols` — `authContextToStripeACPContext`, `verifyStripeACPSpend`
- `@bolyra/receipts` — `createCommerceReceipt`, `signReceipt`, `verifyReceipt`
- `tsx` — already a dev dependency in the monorepo

## Testing

The demo is its own test: if it runs to completion and all receipt verifications pass, it works. The root script `npm run demo:stripe-acp` exits 0 on success, non-zero on any failure.

Additionally, a lightweight test file `src/demo.test.ts` will run the scenarios programmatically (no terminal output) and assert on the decision outcomes, ensuring CI catches regressions in the underlying packages.

## Scope & Effort

- **Size:** Small (S). All APIs already exist. This is a composition + presentation layer.
- **Estimated files:** 7-8 new files in `examples/stripe-acp-demo/`
- **Estimated LOC:** ~400 TypeScript
- **Risk:** Low. No new APIs, no protocol changes, no circuit changes.
