# Bolyra x Stripe ACP Demo

End-to-end demo of Bolyra's delegation + Stripe Agent Commerce Protocol (ACP) spend authorization with signed audit receipts.

## What This Shows

A human delegates **FINANCIAL_SMALL** (< $100) authority to an AI agent. The agent then attempts four operations:

| # | Scenario | Result | Why |
|---|----------|--------|-----|
| 1 | `charge($25)` | AUTHORIZED | Amount is within the $100 small-tier cap |
| 2 | `charge($480)` | REJECTED | Amount exceeds the small-tier cap |
| 3 | `confirm($25)` | REJECTED | `confirm` requires SIGN_ON_BEHALF (bit 5), which the agent lacks |
| 4 | Verify receipts | 3/3 VALID | All decisions produce signed, verifiable audit receipts |

Every decision (allow or deny) generates a signed receipt using secp256k1/ES256K. The demo ends by independently verifying all receipts, proving the audit trail is cryptographically sound.

## Run

From the repo root:

```bash
npm run demo:stripe-acp
```

Or from this directory:

```bash
npm install
npx tsx src/demo.ts
```

## No Real Stripe Calls

This demo simulates PaymentIntent creation. No `stripe` npm package is needed, no API keys are required, and no real charges are made. Real Stripe integration requires the Stripe SDK and API keys -- see the [Stripe Agent Toolkit](https://github.com/stripe/agent-toolkit) for details.

## Packages Used

- **@bolyra/sdk** -- `createDevIdentities()` for demo identities
- **@bolyra/payment-protocols** -- `authContextToStripeACPContext()`, `verifyStripeACPSpend()`
- **@bolyra/receipts** -- `createCommerceReceipt()`, `signReceipt()`, `verifyReceipt()`

## Receipt Files

Running the demo writes receipt JSON files to `receipts/` (gitignored). Each file contains the full `SignedReceipt` object with an ES256K signature that can be verified with:

```bash
npx bolyra-receipt-verify receipts/scenario-1-allowed.json
```
