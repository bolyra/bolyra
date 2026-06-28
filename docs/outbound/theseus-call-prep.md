# Theseus Network — Call Prep (Sunday June 29, 4pm ET)

Codex-reviewed. First potential design partner call.

## Who they are

- L1 chain for autonomous AI agents — "Agency for Agents"
- Agents own keys, hold balances, persist autonomously
- Powered by SHIP DSL, executed/verified on Theseus Chain
- Early stage (like us). Don't cite their funding or location — unverified.
- Website: https://www.theseuschain.com/

## The one-line thesis

**Theseus agents can own money. Bolyra can prove what that agent was allowed to do with that money.**

## Integration angles (ranked)

1. **x402 gateway (STRONGEST)** — Theseus agent pays an x402 API, Bolyra checks permission/replay/expiry and emits a signed receipt. Clean demo wedge.
2. **Bolyra credentials for Theseus agents** — for policy-gated actions or high-value spends (not every action — too heavy).
3. **Delegation flow** — human delegates spending authority with permission bitmasks + expiry. But ask first if humans are even in their model.
4. ~~On-chain verification on Base Sepolia~~ — DROP this. Too forced for call one. Ask where verification should live first.

## Questions (discovery-first, not solution-shaped)

1. "When a Theseus agent spends or calls a paid service today, what determines whether that action is allowed?"
2. "Is key-holder = full authority currently, or do you already have policy constraints?"
3. "Who creates, funds, and limits an agent: a human, app developer, DAO, another agent?"
4. "What action would be dangerous if an agent could do it with unconstrained wallet authority?"
5. "Are you more focused on agent-to-agent transactions, API payments like x402, or developer demos?"
6. "What would make an integration useful to you in the next 2-4 weeks: demo, SDK, verifier, gateway, or co-marketing?"
7. "If we built one joint demo, who would you want it to impress: developers, investors, ecosystem partners?"

## Demo (only after discovery)

Don't lead with a product tour. If they want to see it:

> "I have a 90-second demo: an agent tries to pay for an API through x402, Bolyra checks its credential and policy, then either allows or blocks. The useful artifact is the receipt showing what the agent was authorized to do versus what happened."

Show: valid pass + one blocked overreach + receipt. Skip the full 4-scenario walkthrough unless they ask.

URL: https://bolyra.ai/playground (x402 Agent Wallet preset, Gateway Simulation tab)

## Your ask (if there's fit)

> "I'd like to define a 2-week joint demo: one Theseus agent, one paid API, one policy credential, one receipt."

**Fallback:** "Could Bolyra issue credentials to Theseus agents for off-chain services first?"

## What NOT to do

- Don't pitch hard — they came to you
- Don't say "ZKP identity protocol." Say "authorization, spending limits, and receipts"
- Don't mention Base Sepolia — that's your implementation detail
- Don't imply Bolyra checks every action — start with high-value or externally visible actions
- Don't "push for design partner language" — earn it
- Don't assume one demo = endorsement
- Listen more than talk
- "Interesting integration" ≠ design partner intent. They may just be exploring. Qualify.

---

## Post-Call Plan (if they say yes)

### Call Goal

Agree on **one narrow demo** and **one acceptable public outcome** if it works.

### On the call, nail down:

- What exact agent flow matters to them?
- Who owns which integration pieces?
- What chain/testnet/API?
- What does "done" look like?
- Can their name/logo be used if it works?
- Who posts first, what date?

### Week 1: Build the smallest credible joint prototype

`Theseus agent DID → Bolyra credential → policy check → x402 request → signed receipt`

- Define the exact agent flow on the call (what action, what API, what chain/testnet)
- Agree who owns which pieces
- Keep it sandbox/testnet. Don't overbuild.

### Week 2: Ship proof, then ask for calibrated language

- **Best case:** "Theseus is using Bolyra for agent authorization"
- **More realistic:** "Theseus and Bolyra built a joint prototype for verifiable agent authorization and x402 payments"
- **Minimum useful:** "Exploring agent authorization with Bolyra"

Ask what language they're comfortable with. Don't push.

### Fallback

If integration slips, have a public artifact that doesn't depend on full production readiness (e.g., a joint blog post or architecture diagram).
