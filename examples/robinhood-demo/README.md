# Robinhood Agentic Trading × Bolyra Gateway Demo

Demonstrates how [@bolyra/gateway](https://www.npmjs.com/package/@bolyra/gateway) protects an MCP server modeled after [robinhood-for-agents](https://github.com/kevin1chun/robinhood-for-agents) — the community MCP server for Robinhood's Agentic Trading platform.

## What This Shows

| Scenario | Agent | Tool | Permission | Result |
|----------|-------|------|-----------|--------|
| 1. Portfolio read | Trader (READ_DATA) | `robinhood_get_portfolio` | Has READ_DATA | Allowed + receipt |
| 2. Stock order | Trader (FINANCIAL_SMALL) | `robinhood_place_stock_order` | Has FINANCIAL_SMALL | Allowed + receipt |
| 3. Unauthorized trade | Reader (READ_DATA only) | `robinhood_place_stock_order` | Missing FINANCIAL_SMALL | Blocked + denial receipt |
| 4. Replay attack | Trader (reused proof) | `robinhood_get_portfolio` | Nonce already seen | Blocked |

## Quick Start

```bash
# From repo root
cd examples/robinhood-demo
npm install

# Build the gateway (if not already built)
cd ../../integrations/gateway && npm run build && cd ../../examples/robinhood-demo

# Run the demo
npm run demo
```

## Architecture

```
Agent A (Trader) ─────────────┐
  READ_DATA + FINANCIAL_SMALL │
                              ▼
                    Bolyra Gateway (:4100)
Agent B (Reader) ─────────────┤  • Verify ZKP proof bundle
  READ_DATA only              │  • Check per-tool permission policy
                              │  • Block replay (nonce store)
                              │  • Generate signed receipt
                              ▼
                    Mock Robinhood MCP (:3100)
                      18 tools (portfolio, orders, quotes, etc.)
```

## Tool → Permission Mapping

| Permission Tier | Bitmask | Tools |
|----------------|---------|-------|
| READ_DATA | `0x01` | All `get_*`, `search`, `check_session` |
| WRITE_DATA | `0x02` | `cancel_order` |
| FINANCIAL_SMALL | `0x04` | `place_stock_order` |
| FINANCIAL_MEDIUM | `0x08` | `place_option_order`, `place_crypto_order` |
| BLOCKED | `0xFF` | `browser_login` (no agent should trigger this) |

## How It Works

1. **Mock server** implements robinhood-for-agents' 18 tools as HTTP JSON-RPC with realistic fake data
2. **Bolyra gateway** (dev mode) sits in front, verifying proof bundles and enforcing `gateway.yaml` tool policies
3. **Demo script** creates two agents with different permissions and runs 4 scenarios
4. Each request generates a **signed receipt** proving the auth decision (allow or deny)

## No Robinhood Account Needed

This demo uses a mock MCP server. No real Robinhood account, OAuth tokens, or trading is involved. The mock returns realistic but fake portfolio data and order confirmations.

## Next Steps

- Try the [interactive playground](https://bolyra.ai/playground) for delegation chains and receipt inspection
- See the [gateway quickstart](../../integrations/gateway/README.md) for production setup
- Read the [Bolyra docs](https://bolyra.ai) for the full protocol
