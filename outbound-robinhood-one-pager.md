---
type: concept
title: Bolyra × Robinhood Partnership One-Pager
status: ready-for-warm-intro
created: '2026-06-21T00:00:00.000Z'
version: v3
ingested_via: 'mcp:put_page'
ingested_at: '2026-06-22T03:12:57.285Z'
source_kind: 'mcp:put_page'
tags:
  - agentic-trading
  - bolyra
  - mcp
  - outbound
  - partnership
  - robinhood
---

# Adding Verifiable Agent Identity to Robinhood's Agentic Trading MCP

**Bolyra** | bolyra.ai | Viswanadha Pratap Kondoju | kondojuviswanadha@gmail.com

---

## The Gap

Robinhood's Agentic Trading launched with strong user-level controls: dedicated agent accounts, pre-loaded budgets, optional trade approvals. OAuth handles user authentication well.

What's missing is a layer below that: cryptographic attribution to a specific agent build, operator, and delegated policy. Today, if an agent's OAuth token is compromised or an agent is modified, there is no protocol-level mechanism to:

- **Distinguish agents.** Nothing in the MCP handshake differentiates a legitimate Claude instance from a modified fork claiming to be Claude.
- **Attribute trades to agent identity.** OAuth logs show which user authorized trading, but not which agent build executed it, who operates that agent, or what policy it was running under.
- **Enforce granular scope cryptographically.** Permissions like "equities only, max $500/day, no options" are enforced via UI toggles, not verifiable proofs that survive an audit.

These gaps widen as Agentic Trading moves beyond beta equities into crypto, options, futures, and event contracts.

## What Bolyra Adds

Bolyra is an attestation gateway for AI agents. Before an agent executes a trade, it presents a zero-knowledge proof of its properties: operator-attested model hash, permission bitmask, and delegation chain. The gateway verifies the proof, enforces tool-level policy, blocks replays, and generates a signed audit receipt.

ZK is the mechanism, not the product. The product is provable agent attribution, delegated policy enforcement, and auditable receipts.

**Trust roots for agent claims:** Agent credentials are bound to operator-signed manifests (model hash, build version, deployment ID). The protocol also supports TEE attestations and reproducible build hashes as stronger trust anchors when runtime integrity guarantees are required.

**Gateway integration:**

```typescript
import { createGatewayProxy } from '@bolyra/gateway';

const proxy = createGatewayProxy({
  target: 'http://internal-trading-mcp:3000',
  toolPolicy: {
    place_order:    0x04n,  // FINANCIAL_SMALL (< $100)
    get_positions:  0x01n,  // READ_DATA only
    get_account:    0x01n,  // READ_DATA only
  },
});
```

No core MCP protocol rewrite. Production deployment needs header validation, logging integration, and policy mapping on Robinhood's side.

## What Changes

| Today | With Bolyra Gateway |
|-------|---------------------|
| OAuth identifies the user session | Gateway adds cryptographic agent-build attribution (operator, model hash, permissions) on top of existing OAuth |
| Permissions set by UI toggle | Permissions encoded in a verifiable bitmask, enforced per-tool at the gateway before requests reach your MCP |
| Agent scope within dedicated account is coarse | Gateway enforces tool-level policy: which tools this agent can call, with what permission tier |
| Post-trade fraud review by human team | Every auth decision (allow/deny) generates a signed JWS receipt with agent DID, permissions, scope, and delegation chain depth |
| Audit trail shows user + timestamp | Audit trail adds: agent X (model Y, operator Z) placed trade W via delegation chain D |

## Threat Model

Protects against: stolen OAuth token reuse by unregistered agents, operator-attested agent builds being impersonated by unsigned ones, delegated-scope escalation (scope can only narrow, never expand), replay of previous proof bundles, and weak post-trade attribution.

Does not replace: user-level OAuth, account-level funding limits, or Robinhood's existing fraud detection. Bolyra sits alongside these, adding agent-layer attestation.

## Why Now

1. **Beta is the window.** Equities-only beta is the right time to add the identity layer, before crypto/options/futures raise the stakes and the attack surface.
2. **27M funded customers.** As Agentic Trading scales beyond beta, agent-level attribution becomes a regulatory expectation, not a nice-to-have.
3. **Regulatory gap.** SEC, CFTC, and FINRA haven't issued agent-specific trading rules yet. Building the attribution layer now means shaping the standard, not reacting to it.
4. **Standards alignment.** An IETF individual Internet-Draft on AI agent authentication (draft-klrc-aiagent-auth-01, authored by engineers from AWS, Zscaler, Ping Identity, and OpenAI) is defining how agents prove identity to services. Bolyra implements the privacy-preserving layer that standard leaves open.

## How It Works

Agent presents ZKP proof bundle → Bolyra Gateway verifies (< 200ms p95), checks tool policy, rejects replay, generates signed receipt → Robinhood Trading MCP executes with agent identity + audit trail. Self-hosted, fail-closed, no external Bolyra service dependency.

## Proposed Pilot

Protect one non-production MCP endpoint with two tools and two registered agent identities. Success: < 200ms p95 verification, fail-closed replay rejection, signed receipts in Robinhood logs, no change to OAuth flow. Timeline: 2 weeks.

## The Ask

30 minutes with the owner of Agentic Trading MCP auth/security. Live demo of gateway protecting an MCP endpoint with receipts in under 5 minutes.

## Codex Review Summary

Reviewed through 3 iterations by OpenAI Codex (gpt-5.5). Final grades: Tone FIXED, Ask FIXED, Positioning FIXED (v3), Credibility/Technical Accuracy/Missing/Killer Question PARTIALLY FIXED (diminishing returns — remaining items are conversation-stage topics). Verdict: ready as leave-behind after warm intro.

## Key Contacts at Robinhood

- Deepak Rao — VP/GM Robinhood Money (agentic credit card)
- Abhishek Fatehpuria — VP Product (agentic trading launch spokesperson)
- Johann Kerbrat — GM Robinhood Crypto (agentic expansion to crypto)
