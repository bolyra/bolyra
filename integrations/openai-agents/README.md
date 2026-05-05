# Bolyra Delegation × OpenAI Agents SDK

Example: gate an OpenAI Agents SDK tool call with a `@bolyra/delegation` receipt. The human signs a scoped receipt (e.g. "agent_alice may purchase up to $50 from example.com for the next hour"); a middleware-style wrapper verifies the receipt before the tool runs.

## Run

```bash
npm install @bolyra/delegation @openai/agents zod
npx ts-node delegation-example.ts
```

## What it shows

1. Human generates a keypair and issues a delegation receipt for a specific agent + action + audience.
2. The agent presents the receipt when invoking a tool wrapped by `withDelegation`.
3. The wrapper rejects mismatched audience, missing receipt, expired receipt, or amount-over-cap calls before any side effect runs.

The wrapper is ~30 lines and is the entire integration surface. Copy it into your own agent service or import it directly.
