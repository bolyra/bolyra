# @bolyra/base-agent-wallet

Human-gated spending for AI agents on Base. ZKP-enforced wallet delegation.

## Quick Start

```bash
cd examples/base-agent-wallet
npm install
npm run demo
```

## What It Does

A human delegates a Base wallet to an AI agent with:
- **ZK identity** — agent proves who it is without revealing its controller
- **Scoped permissions** — READ_DATA + FINANCIAL_SMALL (< $100)
- **Spend limits** — $2.00/request, $2.00/day
- **Audit trail** — signed receipt for every decision

The agent transacts autonomously within these limits. When it tries to
exceed them, the wallet blocks the transaction and records why.

## Demo Scenarios

| # | Request | Amount | Result |
|---|---------|--------|--------|
| 1 | NVDA research | $0.50 | ALLOW |
| 2 | BTC summary | $0.25 | ALLOW |
| 3 | GPU inference | $1.00 | ALLOW |
| 4 | Premium report | $5.00 | DENY (exceeds $2.00/request cap) |
| 5 | Market feed | $0.10 | ALLOW |
| 6 | More research | $0.50 | DENY (daily cap exceeded) |

## Interactive Demo

See it in your browser: [bolyra.ai/playground](https://bolyra.ai/playground) — Base Wallet tab
