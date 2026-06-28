# Off-Chain Session Token for Multi-Step Agent Chains

**Experiment:** `framework_integrator_session_token_offchain`  
**Dimension:** Adoption  
**Priority:** Critical  
**Status:** Implementation

## Problem

LangChain/CrewAI agent chains make 10–50 tool calls per task. Requiring an
on-chain `verifyHandshake()` per call is prohibitively slow (~2s) and expensive
(~$0.05 per verification on L2). This is the single biggest adoption blocker
for framework users.

## Solution

A three-layer session token architecture:

1. **SDK Session Module** (`sdk/src/session.ts`) — `mintSessionToken()`,
   `verifySessionToken()`, `revokeSessionToken()` using signed JWTs with
   ephemeral ECDSA P-256 keys.

2. **Anchor Contract** (`contracts/src/BolyraSessionAnchor.sol`) — Minimal
   Solidity contract for periodic `batchCheckpoint()` calls. Stores
   `sessionRoot → timestamp` for audit trails. No ZK verification.

3. **Protocol Spec** (`spec/session-token-offchain.md`) — JWT payload schema,
   signing key lifecycle, verification algorithm, replay prevention, checkpoint
   cadence, revocation surface.

## Artifacts

| File | Type | Description |
|------|------|-------------|
| `spec/session-token-offchain.md` | Spec | Protocol specification |
| `sdk/src/session.ts` | SDK | Core session token module |
| `sdk/src/index.ts.patch` | SDK | Export additions for public API |
| `contracts/src/BolyraSessionAnchor.sol` | Contract | On-chain checkpoint anchor |
| `sdk/test/session.test.ts` | Test | SDK unit tests |
| `contracts/test/BolyraSessionAnchor.test.ts` | Test | Hardhat contract tests |
| `docs/session-token-guide.md` | Docs | LangChain/CrewAI integration guide |

## Usage

```typescript
import {
  verifyHandshake,
  mintSessionToken,
  verifySessionToken,
} from '@bolyra/sdk';

// 1. One-time on-chain verification
const result = await verifyHandshake(humanProof, agentProof, nonce);

// 2. Mint session token (off-chain JWT, ~0.5ms)
const token = mintSessionToken(humanProof, agentProof, result, {
  expirySeconds: 1800,
});

// 3. Verify per tool call (off-chain, ~0.1ms)
const payload = verifySessionToken(token, READ_DATA | WRITE_DATA);
```

## Testing

```bash
# SDK tests
cd sdk && npm run build && npm test

# Contract tests
npm run test:contracts
```

## Key Design Decisions

- **Ephemeral signing keys** — P-256 key pair generated per SDK instance, never
  persisted. Process restart invalidates all tokens (fail-safe).
- **Process-local revocation** — `revokeSessionToken()` uses an in-memory Set.
  Distributed revocation is application-layer responsibility.
- **Scope narrowing only** — `scopeOverride` must be a bitwise subset of
  handshake scope and satisfy cumulative-bit implication rules.
- **Checkpoint anchoring** — periodic, not per-call. Recommended: every 10 calls
  or 60 seconds.
