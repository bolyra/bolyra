# X Thread: Robinhood Agentic Trading Demo

Post from @viswaprak. 6 tweets. Attach playground screenshot to tweet 1.

---

## Tweet 1 (hook + playground)

Robinhood opened trading to AI agents last month. OAuth identifies the user. Nothing identifies the agent.

Try the problem and the fix in your browser. No install, no backend, no keys:

https://bolyra.ai/playground

Click "Gateway Simulation" → run all 4 scenarios. 🧵

[attach /tmp/playground-gateway.png]

---

## Tweet 2 (the problem)

A legitimate Claude instance and a modified fork present the same OAuth token. The MCP server can't tell them apart.

No per-tool permissions. No replay protection. No record of which software placed the trade.

As agentic trading scales to crypto, options, and futures, this gap gets worse.

---

## Tweet 3 (what the playground shows)

The playground simulates a gateway sitting in front of an MCP server:

✅ Valid Agent → credential verified, tool policy checked, receipt issued
🚫 Expired Credential → rejected before reaching the server
🚫 Insufficient Permissions → read-only agent blocked from placing trades
🚫 Replay Attack → reused proof bundle rejected

Each decision generates a signed receipt you can inspect in the Receipt Inspector tab.

---

## Tweet 4 (tool mapping)

The demo maps Robinhood's 18 MCP tools to permission tiers:

READ_DATA → quotes, portfolio, account info
WRITE_DATA → cancel orders
FINANCIAL_SMALL → stock orders
FINANCIAL_MEDIUM → options, crypto orders
BLOCKED → browser_login

An agent with READ_DATA cannot place trades. Enforced at the gateway, not the application.

---

## Tweet 5 (deeper dive)

Want to run it locally? 4 scenarios, mock Robinhood MCP server, no account needed:

git clone https://github.com/bolyra/bolyra.git
cd bolyra/examples/robinhood-demo
npm install
npm run demo

Full writeup: https://bolyra.ai/blog-4

Also opened a docs PR on robinhood-for-agents with a vendor-neutral agent identity guide:
https://github.com/kevin1chun/robinhood-for-agents/pull/17

---

## Tweet 6 (CTA)

Building Bolyra: verifiable agent identity for MCP servers. Gateway verifies credentials, enforces per-tool permissions, blocks replays, generates signed receipts. Self-hosted, fail-closed.

If you're building agent trading tools or thinking about MCP auth, I want to hear what you're running into.

https://bolyra.ai
