# Coinbase Agent Account × Bolyra Gateway Demo

Coinbase gives AI agents accounts. Bolyra gives those accounts enforceable delegated authority, spend limits, replay protection, and audit receipts.

## What This Shows

| Scenario | Agent | Tool | Permission | Result |
|----------|-------|------|-----------|--------|
| 1. Read portfolio | READ_DATA | `get_portfolio` | Has READ_DATA | Allowed + receipt |
| 2. Transfer USDC | FINANCIAL_SMALL | `transfer_token` | Has FINANCIAL_SMALL | Allowed + receipt |
| 3. Unauthorized transfer | READ_DATA only | `transfer_token` | Missing FINANCIAL_SMALL | Blocked |
| 4. x402 paid API | FINANCIAL_SMALL | `pay_for_api` | Has FINANCIAL_SMALL | Allowed + receipt |
| 5. Deploy contract | FINANCIAL_SMALL | `deploy_contract` | Missing FINANCIAL_UNLIMITED | Blocked |
| 6. Replay attack | Reused proof | `get_portfolio` | Nonce already seen | Blocked |

## Quick Start

```bash
cd examples/coinbase-agent-demo
npm install

# Build the gateway (if not already built)
cd ../../integrations/gateway && npm run build && cd ../../examples/coinbase-agent-demo

# Run the demo
npm run demo
```

No Coinbase API keys needed. Mock server with realistic responses.

## Architecture

```
AI Agent (Claude, ChatGPT, custom)
    │
    │ Authorization: Bolyra <proof>
    ▼
Bolyra Gateway (:4200)
    │ ✓ Credential check
    │ ✓ Tool policy (transfer needs FINANCIAL_SMALL)
    │ ✓ Replay protection
    │ ✓ Receipt issuance
    ▼
Mock Coinbase AgentKit MCP (:3200)
    • Wallet balance, portfolio
    • Token transfers (ETH, USDC)
    • Token swaps (Uniswap)
    • x402 paid API calls
    • Contract deployment
```

## Tool → Permission Mapping

| Permission | Bitmask | Tools |
|-----------|---------|-------|
| READ_DATA | 1 | `get_wallet_balance`, `get_portfolio`, `get_wallet_address`, `get_token_price`, `get_transaction_history` |
| FINANCIAL_SMALL | 4 | `transfer_token`, `swap_tokens`, `pay_for_api` |
| FINANCIAL_UNLIMITED | 16 | `deploy_contract` |

## Why This Matters

Brian Armstrong (June 22, 2026): "Coinbase is an AI enabled financial account."

When AI agents manage real money, you need:
- **Who is this agent?** Verified identity, not just an API key
- **What can it do?** Per-tool permissions, not blanket access
- **Has this been seen before?** Replay protection
- **Can you prove what happened?** Signed audit receipts

Bolyra adds all four without changing the Coinbase MCP server.

## Links

- [Bolyra playground](https://bolyra.ai/playground)
- [Robinhood demo](../robinhood-demo/)
- [@bolyra/gateway on npm](https://www.npmjs.com/package/@bolyra/gateway)
- [Blog: credential lifecycle](https://bolyra.ai/blog-5)
