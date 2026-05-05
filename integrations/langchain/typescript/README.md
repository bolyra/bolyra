# Bolyra Delegation × LangChain.js

Example: gate a LangChain.js `DynamicTool` with a `@bolyra/delegation` receipt. The human signs a scoped receipt; a middleware-style wrapper verifies the receipt before the tool runs.

> Note: The Python adapter for the existing `@bolyra/sdk` lives in `../bolyra_delegate_tool.py`. This TypeScript adapter is the lightweight entry point using `@bolyra/delegation` (no ZK dependencies).

## Run

```bash
npm install @bolyra/delegation @langchain/core
npx ts-node delegation-example.ts
```

## What it shows

1. Human issues a scoped receipt for an agent + action + tool target.
2. A `withDelegation` wrapper inspects the LangChain tool input for a `_receipt` field and verifies it.
3. The wrapper rejects calls whose receipt is missing, expired, audience-mismatched, or over-cap before the underlying tool body runs.
