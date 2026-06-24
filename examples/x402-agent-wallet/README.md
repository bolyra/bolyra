# x402 Agent Wallet Guard

Human-capped x402 spending for agent wallets on Base.

An agent wallet is not just a key — it's a policy-enforced spender. Every payment decision gets a signed receipt with agent DID, amount, and reason.

## What This Shows

| Scenario | Endpoint | Price | Policy Check | Result |
|----------|----------|-------|-------------|--------|
| 1. NVDA research | `/research/nvda` | $0.50 | Under $2.00/request, under $2.00/day | Allowed |
| 2. BTC summary | `/research/btc` | $0.25 | Under caps | Allowed |
| 3. GPU inference | `/compute/gpu-hour` | $1.00 | Under caps | Allowed |
| 4. Premium report | `/premium/report` | $5.00 | Exceeds $2.00/request cap | **Denied** |
| 5. Market feed | `/data/market-feed` | $0.10 | Under caps ($1.85 daily) | Allowed |
| 6. More research | `/research/nvda` | $0.50 | Would exceed $2.00/day cap | **Denied** |

## Quick Start

```bash
cd examples/x402-agent-wallet
npm install
npm run demo
```

## How It Works

```
Agent calls paid API
    │
    │ GET /research/nvda
    ▼
API returns 402 + x402 requirements
    │ {"scheme":"x402", "amount":"50", "asset":"USDC", "network":"base-sepolia"}
    ▼
Bolyra Agent Wallet checks policy
    │ ✓ Asset allowed (USDC)
    │ ✓ Network allowed (base-sepolia)
    │ ✓ Amount $0.50 ≤ $2.00/request cap
    │ ✓ Daily total $0.50 ≤ $2.00/day cap
    │ ✓ Nonce fresh
    ▼
Payment attached + request retried → 200 + data
    │
    ▼
Signed receipt emitted
    {"decision":"allow", "amount":50, "asset":"USDC", "agentDid":"did:bolyra:..."}
```

## Agent Wallet Policy

```typescript
const wallet = new BolyraAgentWallet({
  maxPerRequest: 200,     // $2.00 in cents
  dailyCap: 200,          // $2.00/day
  allowedAssets: ['USDC'],
  allowedNetworks: ['base-sepolia'],
  agentDid: 'did:bolyra:base-sepolia:0x742d...bDe7',
});

const { status, data, receipt } = await wallet.fetch('https://api.example.com/paid-endpoint');
```

## Links

- [Agent Spend demo](https://bolyra.ai/agent-spend)
- [Benchmark](https://bolyra.ai/benchmark)
- [@bolyra/payment-protocols](https://www.npmjs.com/package/@bolyra/payment-protocols) — x402 + Stripe ACP
