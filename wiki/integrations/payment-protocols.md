---
title: Payment Protocols
visibility: public
sources:
  - integrations/payment-protocols/README.md
  - integrations/payment-protocols/package.json
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [payment, visa-tap, google-ap2, stripe-acp, zkp, commerce]
---

ZKP privacy layer for agentic commerce payment protocols. Maps Bolyra's proof system onto Visa TAP, Google AP2, and Stripe ACP so merchants learn only "authorized: yes/no" and a trust score -- never the human's identity, exact budget, or delegation structure.

## Overview

`@bolyra/payment-protocols` (v0.7.0) is open-source protocol research (not production software). It provides adapters that translate Bolyra ZKP proofs into the data structures expected by three major agentic payment protocols.

- **npm:** `@bolyra/payment-protocols`
- **Deps:** `@bolyra/sdk >=0.5.1`, `@bolyra/receipts ^0.7.0`
- **Peer dep:** `@bolyra/sdk >=0.4.0`
- **License:** Apache-2.0

## Key Concepts

### The privacy problem

When AI agents make purchases, payment networks need to verify identity, policy, and consent. Existing protocols (Visa TAP, Google AP2) use centralized registries and plain-text mandates -- the merchant sees everything. Bolyra replaces that with ZKPs: the merchant learns only authorization status, policy sufficiency, and a trust score (0-100).

### Protocol mapping

**Visa TAP:** Agent registry lookup becomes ZKP proof of human authorization. HTTP Message Signatures become scope commitments. Payment Signals become scope commitment + agent nullifier. Trust tiers become score-based grading (A/B/C/D/F).

**Google AP2:** Intent/Cart/Payment Mandates become Bolyra handshake proofs and spend policy ZKPs. Agent-to-agent delegation maps to Bolyra delegation chains with hop tracking.

**Stripe ACP:** The acting agent is the leaf delegatee in the v=2 bundle. Spending cap is collapsed from cumulative `FINANCIAL_*` bits on the leaf scope. The "narrowing wedge" means a root with `FINANCIAL_UNLIMITED` can delegate down to `FINANCIAL_SMALL` ($100 cap); Stripe sees only the leaf's cap.

## How It Works

### Visa TAP

```ts
const result = await createVisaTAPVerification(human, agent, spendPolicy, transaction);
// result.verified, result.score, result.grade, result.paymentSignal
```

### Google AP2

```ts
const credential = await createAP2AgentCredential(human, agent, mandates);
const verification = await verifyAP2AgentCredential(credential);
```

### Stripe ACP

```ts
const ctx = await verifyBundle(bundle, mcpConfig);
const acp = authContextToStripeACPContext(ctx, 'base-sepolia', 'usd');
const decision = verifyStripeACPSpend(acp, 5_000, 'USD');
```

### Spend policy encoding

Spend policies (max transaction amount, cumulative limits, time windows, MCC category restrictions) are encoded into bitmasks for the ZKP circuit. Merchant-side verification checks public signals only.

## Current Status

v0.7.0 on npm. All three protocol adapters (Visa TAP, Google AP2, Stripe ACP) implemented. The Stripe ACP narrowing wedge was the most recent addition. This is protocol research -- not production commerce infrastructure.

## See Also

- [Gateway](gateway.md) -- reverse proxy where these adapters could sit
- [MCP](mcp.md) -- `verifyBundle` used by the Stripe ACP adapter
