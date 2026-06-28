# Session Token Integration Guide

This guide shows how to integrate Bolyra's off-chain session tokens with
LangChain, CrewAI, and other multi-step agent frameworks.

## Why Session Tokens?

Agent chains make 10–50 tool calls per task. An on-chain `verifyHandshake()` per
call costs ~2s and ~$0.05 on L2. Session tokens amortize that cost:

1. **One** on-chain `verifyHandshake()` at the start of a session.
2. **Mint** a session token (JWT) from the verified result.
3. **Verify** the session token off-chain for every subsequent tool call (~0.1ms).
4. **Checkpoint** periodically to anchor an audit trail on-chain.

## Quick Start (3 Lines)

```typescript
import {
  verifyHandshake,
  mintSessionToken,
  verifySessionToken,
} from '@bolyra/sdk';

// Step 1: One-time on-chain verification
const result = await verifyHandshake(humanProof, agentProof, nonce);

// Step 2: Mint session token (off-chain JWT)
const sessionToken = mintSessionToken(
  humanProof,
  agentProof,
  result,
  { expirySeconds: 1800 }, // 30 minutes
);

// Step 3: Verify per tool call (off-chain, ~0.1ms)
const payload = verifySessionToken(sessionToken, requiredScopeBits);
```

## LangChain Integration

### Tool Handler Pattern

```typescript
import { DynamicTool } from 'langchain/tools';
import { verifySessionToken } from '@bolyra/sdk';

// Permissions: bit 0 = READ_DATA, bit 1 = WRITE_DATA
const READ_DATA = 0b00000001;
const WRITE_DATA = 0b00000010;

const lookupTool = new DynamicTool({
  name: 'member_lookup',
  description: 'Look up credit union member info',
  func: async (input: string) => {
    // Session token passed via tool-call context
    const token = getSessionTokenFromContext();
    const payload = verifySessionToken(token, READ_DATA);

    // payload.humanNullifier identifies the session owner
    return await memberService.lookup(input, payload.humanNullifier);
  },
});
```

### Agent Executor Setup

```typescript
import { AgentExecutor } from 'langchain/agents';
import { mintSessionToken, verifyHandshake } from '@bolyra/sdk';

async function createAuthenticatedAgent(humanProof, agentProof, nonce) {
  const result = await verifyHandshake(humanProof, agentProof, nonce);
  const sessionToken = mintSessionToken(humanProof, agentProof, result, {
    expirySeconds: 1800,
    scopeOverride: 0b00000011, // READ + WRITE only
  });

  // Inject token into agent context for all tool calls
  const agent = await createAgent({ sessionToken });
  return AgentExecutor.fromAgentAndTools({
    agent,
    tools: [lookupTool, updateTool],
  });
}
```

## CrewAI Integration

```python
from crewai import Agent, Task, Crew
import bolyra

# After handshake verification (Python SDK wraps the JS subprocess)
result = bolyra.verify_handshake(human_proof, agent_proof, nonce)
session_token = bolyra.mint_session_token(
    human_proof, agent_proof, result,
    expiry_seconds=1800,
)

# Pass token to crew context
crew = Crew(
    agents=[analyst_agent],
    tasks=[analysis_task],
    context={"bolyra_session_token": session_token},
)
crew.kickoff()
```

## Checkpoint Anchoring

Periodic on-chain checkpoints create a tamper-evident audit trail.

### Recommended Cadence

- **Every 10 tool calls**, or
- **Every 60 seconds**, whichever comes first.

```typescript
import { computeSessionRoot } from '@bolyra/sdk';

let callCount = 0;
let lastCheckpoint = Date.now();
const activeTokens: string[] = [];

async function maybeCheckpoint(contract: BolyraSessionAnchor, epoch: number) {
  callCount++;
  const elapsed = Date.now() - lastCheckpoint;

  if (callCount >= 10 || elapsed >= 60_000) {
    const root = computeSessionRoot(activeTokens);
    await contract.batchCheckpoint(root, epoch);
    callCount = 0;
    lastCheckpoint = Date.now();
  }
}
```

## Handling Expiry Mid-Chain

If a session token expires during a long chain, re-handshake and re-mint:

```typescript
import { BolyraSessionError } from '@bolyra/sdk';

async function withSessionRetry(token, scope, action) {
  try {
    verifySessionToken(token, scope);
    return await action();
  } catch (err) {
    if (err instanceof BolyraSessionError && err.code === 'TOKEN_EXPIRED') {
      // Re-handshake and re-mint
      const result = await verifyHandshake(humanProof, agentProof, newNonce);
      const newToken = mintSessionToken(humanProof, agentProof, result);
      verifySessionToken(newToken, scope);
      return await action();
    }
    throw err;
  }
}
```

## Scope Narrowing

Session tokens support **one-way scope narrowing** at mint time. This follows
the same cumulative-bit implication rules as the `Delegation` circuit:

```typescript
// Full handshake scope: READ + WRITE + FINANCIAL_SMALL + FINANCIAL_MEDIUM
const fullScope = 0b00001111;

// Narrow to READ + WRITE only for a read/write agent
const rwToken = mintSessionToken(hp, ap, result, {
  scopeOverride: 0b00000011,
});

// This would throw — can't elevate beyond handshake scope
mintSessionToken(hp, ap, result, {
  scopeOverride: 0b11111111, // BolyraSessionError: SCOPE_VIOLATION
});
```

## Migration from Per-Call On-Chain Verify

If you're currently calling `verifyHandshake()` on every tool call:

1. **Keep** your initial `verifyHandshake()` call unchanged.
2. **Add** `mintSessionToken()` immediately after.
3. **Replace** subsequent `verifyHandshake()` calls with `verifySessionToken()`.
4. **Add** periodic `batchCheckpoint()` for audit trail (optional but recommended).

This is a backwards-compatible change — the on-chain verification still happens
once, and all existing verification logic remains valid.

## Security Notes

- **Signing key is ephemeral** — generated per process, never persisted. Process
  restart invalidates all tokens (fail-safe).
- **Revocation is process-local** — `revokeSessionToken()` only affects the
  current process. Use short expiry (5–30 min) for distributed deployments.
- **No ZK in session flow** — the session token trusts the initial handshake
  verification. It does not re-prove anything.
- **Scope can only narrow** — `scopeOverride` is enforced as a bitwise subset
  and must satisfy cumulative-bit implication rules.
