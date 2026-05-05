# Outreach Plan — `@bolyra/delegation` v0.1.0

Goal: validate "AI agent framework teams" as the integrator wedge by getting 3 framework adapters into real users' pipelines this week.

**Asset:** `demo/demo.gif` (1100×720, 23s, 120 KB) — embedded in the package README via `raw.githubusercontent.com`. Attach the GIF directly to DMs and posts (don't link — links lose ~70% of clicks).

---

## Cold DM template

**Use this for:** LinkedIn / X DMs to engineers and PMs at agent framework teams (LangChain, LangGraph, Mastra, AutoGen, CrewAI, AgentScript, Inngest, Restack, Letta, Smyth, etc.) and at companies shipping agent-driven products (Sierra, Decagon, Cresta, Lindy, Brex agents team, Ramp agents team, Stripe agent team, Coinbase Agent Kit, Anthropic Computer Use partners, OpenAI Agents launch partners).

> Hey {name} — saw your work on {specific thing they shipped}.
>
> Building a small open-source primitive for agent tool authorization — the human signs a scoped receipt (action, audience, amount cap, expiry) and middleware verifies it before `tool.call()` runs. Kills the "agent ran the right tool with the wrong scope" failure mode without any custom auth code per integration.
>
> 30-line wrapper for {their framework}. Demo: \[attach demo.gif]. Apache-2.0, on npm: `@bolyra/delegation`.
>
> Would love 5 min of your read on whether this matches a real pain you've hit. No ask beyond that.
>
> {your name}, {company} ({why-you're-credible — solo founder building Bolyra, prior X, etc.})

**Variants by recipient:**

- **Framework maintainer** → "30-line wrapper for {framework}" (point at the matching adapter in `integrations/`).
- **Agent product team** → "drops in front of any tool call. Per-tool agent + action + amount-cap + audience checks. No code changes to the tools themselves."
- **Wallet / payments team** (Skyfire, Coinbase Agent Kit, Privy) → "interop layer above your wallet — receipts ride on top of the spend rail you already have, audit log is portable across wallets."

**Send mechanics:**
- LinkedIn for senior people, X DMs for IC engineers (faster reply rate)
- Send 5/day max. More than that and you stop being able to handle the replies.
- One follow-up after 5 business days if no reply. Single bump only.
- Track in a doc: name, company, sent date, reply, outcome.

---

## Community posts

### 1. LangChain Discord — `#sharing-is-caring` channel

> **`@bolyra/delegation` v0.1.0 — middleware-style receipt auth for LangChain tools**
>
> Open-sourced a tiny package that gates `DynamicTool.func` on a signed delegation receipt. The human (or upstream agent) signs a scoped receipt (`agent + action + audience + amount cap + expiry`); a `withDelegation()` wrapper verifies it before the tool runs. Rejects mismatched audience, missing receipt, expired receipt, or amount-over-cap before any side effect.
>
> Apache-2.0. One dep (`jose`). Roadmap: SD-JWT in v0.2, ZK-wrapped receipts in v0.3.
>
> ```
> npm install @bolyra/delegation
> ```
>
> Adapter: https://github.com/bolyra/bolyra/tree/main/integrations/langchain/typescript
>
> [attach demo.gif]
>
> Would love feedback on the wire format before SD-JWT lands.

### 2. MCP / Model Context Protocol Discord — `#showcase` or `#general`

> **MCP `_meta.delegation`: signed receipts for tool authorization**
>
> Open-sourced a small package that uses MCP's `_meta` channel to carry delegation receipts on `CallTool` requests. A `gateMcpTool()` wrapper verifies the receipt (`agent + action + audience + cap + expiry`) before forwarding to the underlying handler. Returns `isError: true` on rejection — MCP-native.
>
> The receipt format is independent of MCP — same primitive works for OpenAI Agents SDK and LangChain — but `_meta` was the right channel for MCP because it doesn't require schema changes to existing tools.
>
> Apache-2.0, single dep (`jose`).
>
> ```
> npm install @bolyra/delegation
> ```
>
> Example: https://github.com/bolyra/bolyra/tree/main/integrations/mcp/examples
>
> [attach demo.gif]
>
> Open question for the community: should `_meta.delegation` standardize? Happy to draft an MCP RFC if there's interest.

### 3. OpenAI Developer Forum — Agents SDK category

> **`@bolyra/delegation`: scoped delegation receipts for OpenAI Agents SDK tool calls**
>
> The agentic-commerce announcements (Stripe Agent Toolkit, Visa Intelligent Commerce, the OpenAI checkout demo) all sketch the same primitive: a human-signed authorization that scopes what the agent can actually do. Each one ships its own bespoke version.
>
> I wrote a small open-source package that's framework-agnostic. A `withDelegation()` wrapper sits in front of any tool handler and verifies a signed receipt (action, audience, amount cap, expiry) before the handler runs.
>
> 30 lines of integration code per framework. Adapter for the OpenAI Agents SDK (TypeScript) is in the repo.
>
> Apache-2.0. One dep (`jose`). Roadmap: SD-JWT, then ZK-wrapped receipts.
>
> ```
> npm install @bolyra/delegation
> ```
>
> Repo: https://github.com/bolyra/bolyra
> Agents SDK adapter: https://github.com/bolyra/bolyra/tree/main/integrations/openai-agents
>
> [attach demo.gif]
>
> Curious whether anyone has hit this in production yet — would love war stories about the failure modes you actually saw.

---

## What "success" looks like this week

- ✅ Package on npm, install verified
- ✅ Demo GIF recorded
- 🔲 15 cold DMs sent (5/day × 3 days)
- 🔲 3 community posts live
- 🔲 ≥3 reply conversations going (any sentiment — even rejection is signal)
- 🔲 ≥1 person willing to take a 30-min call about their actual use case

The signal you're looking for: **someone tries the package and reports back what they want changed.** That person is your design partner. One real partner > 50 vague upvotes.

If after a week the only reply is "cool, starred" with no install attempts: the wedge is wrong. Pivot to a different integrator profile (try framework *users* instead of framework *teams*, or try wallet/payments teams instead of agent teams).

---

## Tracking

Keep a simple table somewhere (Notion, Airtable, a markdown file):

| Date | Channel | Recipient/Venue | Outcome | Notes |
|------|---------|-----------------|---------|-------|
| | DM-LinkedIn | | sent / replied / installed / call | |

Don't let "they didn't reply" feel personal. Rule of thumb: 1/5 replies, 1/3 of those goes anywhere. Plan for that math, not for "everyone will love it."
