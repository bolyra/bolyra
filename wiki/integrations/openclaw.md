---
title: OpenClaw Integration
visibility: public
sources:
  - integrations/openclaw/README.md
  - integrations/openclaw/package.json
last-updated: 2026-06-28
staleness-threshold: 14d
tags: [openclaw, trust-verification, zkp, scoring]
---

OpenClaw trust verification adapter that maps Bolyra's mutual ZKP handshake to OpenClaw's `TrustVerificationResult` interface.

## Overview

`@bolyra/openclaw` (v0.3.2) provides a plugin for [OpenClaw](https://github.com/openclaw) that runs a full Groth16 + PLONK ZKP handshake when OpenClaw requests agent verification, then returns a scored result (0-100) with a grade (A-F) and a Bolyra DID.

- **npm:** `@bolyra/openclaw`
- **Dep:** `@bolyra/sdk >=0.5.1`
- **Peer dep:** `@bolyra/sdk >=0.4.0`
- **License:** Apache-2.0

## Key Concepts

### Scoring dimensions

| Dimension | Points | Checks |
|-----------|--------|--------|
| Proof validity | 40 | Both ZKP proofs verify |
| Credential expiry | 20 | Agent credential not expired |
| Permission coverage | 20 | Agent has read/write permissions |
| Nonce freshness | 10 | Session nonce within `maxProofAge` |
| Scope commitment | 10 | Delegation chain initialized |

A score of 70+ (configurable via `minScore`) yields `verified: true`.

### Plugin pattern

The plugin follows OpenClaw's `onAgentVerify(agentId)` hook. It resolves the agent's credential from a user-provided store, runs the handshake, scores it, and returns a `TrustVerificationResult`.

## How It Works

```ts
import { createBolyraPlugin } from '@bolyra/openclaw';

const plugin = createBolyraPlugin(
  humanIdentity,
  async (agentId) => credentialStore.get(agentId),
  { network: 'base-sepolia', minScore: 70, maxProofAge: 300 }
);

openclaw.use(plugin);
```

### Standalone verification

For use outside of OpenClaw:

```ts
import { verifyAgent, computeTrustScore } from '@bolyra/openclaw';

const result = await verifyAgent(human, agentCredential, { network: 'base' });
// { verified: true, score: 100, grade: 'A', did: 'did:bolyra:base:...', warnings: undefined }
```

### Config

```ts
createBolyraPlugin(human, resolver, {
  network: 'base-sepolia',     // DID network identifier
  minScore: 70,                // Minimum score for verified=true
  maxProofAge: 300,            // Cache TTL in seconds
  sdkConfig: { ... },         // Passthrough to @bolyra/sdk
});
```

## Current Status

v0.3.2 on npm. Stable. Score-based result pattern is reused by the payment-protocols package.

## See Also

- [MCP](mcp.md) -- server-side auth middleware
- [Payment Protocols](payment-protocols.md) -- uses the same score-based result pattern
