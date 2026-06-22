# Protecting Robinhood's Agentic Trading MCP with Verifiable Agent Identity

Robinhood launched Agentic Trading on May 27, 2026. Any MCP-compatible agent can connect, call tools, and place trades. The question nobody's answering: how do you verify which agent is trading?

## The gap

OAuth identifies the user. Nothing identifies the agent. A legitimate Claude instance and a modified fork present the same OAuth token. From the server's perspective they are identical. No cryptographic attribution survives an audit. When a regulator asks "which software placed this trade at 14:32 on Tuesday," the answer today is "something with a valid user token."

## What we built

We put `@bolyra/gateway` in front of a mock Robinhood MCP server modeled after [kevin1chun/robinhood-for-agents](https://github.com/kevin1chun/robinhood-for-agents). The gateway sits between the agent and the MCP server. It verifies ZKP proof bundles before any tool call reaches the backend. It enforces per-tool permission policies, blocks proof replays via a nonce store, and generates signed audit receipts for every decision (allow or deny).

The demo runs four scenarios:

1. **Verified read.** Agent with `READ_DATA` permission calls `get_stock_quote`. Gateway verifies proof, forwards call, returns receipt.
2. **Verified trade.** Agent with `FINANCIAL_SMALL` permission calls `place_stock_order`. Gateway checks the permission tier matches the tool, forwards call.
3. **Unauthorized agent blocked.** Agent with `READ_DATA` only tries `place_stock_order`. Gateway rejects before the call reaches the server. Receipt logs the denial.
4. **Replay attack blocked.** Agent replays a previously used proof bundle. Nonce store catches it. Request rejected.

## Tool permission mapping

This is the part that matters for engineers integrating with Robinhood's tool surface:

| Tool | Permission tier | Bit |
|---|---|---|
| `get_stock_quote` | `READ_DATA` | 0 |
| `get_account_info` | `READ_DATA` | 0 |
| `get_portfolio` | `READ_DATA` | 0 |
| `place_stock_order` | `FINANCIAL_SMALL` | 2 |
| `place_options_order` | `FINANCIAL_MEDIUM` | 3 |
| `place_crypto_order` | `FINANCIAL_MEDIUM` | 3 |
| `browser_login` | `BLOCKED` | n/a |

Cumulative bit encoding means `FINANCIAL_MEDIUM` (bit 3) implies `FINANCIAL_SMALL` (bit 2) implies `READ_DATA` (bit 0). An agent credentialed at tier 3 can read quotes and place stock orders without separate grants. An agent credentialed at tier 0 cannot trade. The delegation circuit enforces this on-chain, not just in the gateway config.

## How to run it

```bash
cd examples/robinhood-demo
npm install
npm run demo
```

No Robinhood account needed. The demo uses a mock server with deterministic responses.

## What this means

Robinhood's beta covers equities only. When it expands to crypto, options, and futures, the agent identity gap widens. More tool surface, more permission tiers, more regulatory scrutiny. Bolyra adds verifiable agent attribution without changing the MCP protocol. The gateway is self-hosted, fail-closed, and generates SOC 2-ready audit receipts with cryptographic proof of every allow/deny decision.

## Links

- [GitHub repo](https://github.com/bolyra/bolyra)
- [`@bolyra/gateway` on npm](https://www.npmjs.com/package/@bolyra/gateway)
- [`@bolyra/sdk` on npm](https://www.npmjs.com/package/@bolyra/sdk)
- [Interactive playground](https://bolyra.ai/playground)
- [Demo source](https://github.com/bolyra/bolyra/tree/main/examples/robinhood-demo)
