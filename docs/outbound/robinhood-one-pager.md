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

4. **Standards alignment.** An IETF individual Internet-Draft on AI agent authentication (draft-klrc-aiagent-auth-01, authored by engineers from AWS, Zscaler, Ping Identity, and OpenAI) is defining how agents prove identity to services.[^1] Bolyra implements the privacy-preserving layer that standard leaves open.

[^1]: Individual Internet-Draft, not yet adopted by an IETF working group. Published on Datatracker.

## How It Works

```
User's Agent (Claude, ChatGPT, custom)
    |
    | 1. Agent presents ZKP proof bundle
    |    (operator-attested model hash, permission bitmask, nonce)
    v
Bolyra Gateway (self-hosted reverse proxy)
    |
    | 2. Verify proof (< 200ms p95 on commodity hardware)
    | 3. Check tool policy (place_order requires FINANCIAL_SMALL)
    | 4. Reject replay (nonce already seen? blocked)
    | 5. Generate signed receipt (JWS)
    | 6. Fail-closed on proof failure (no silent pass-through)
    |
    v
Robinhood Trading MCP
    |
    | X-Bolyra-DID: did:bolyra:agent:0x7f3a...
    | X-Bolyra-Permissions: 0x04
    | X-Bolyra-Receipt-ID: rec_2026-06-21_...
    v
Trade executes with agent identity + audit trail
```

**Deployment model:** Self-hosted gateway. Robinhood controls keys, log retention, and receipt storage. No external Bolyra service dependency. Fail-closed: if proof verification fails or the gateway is down, no agent requests pass through.

## What's Live Today

- **@bolyra/gateway** (v0.2.0, npm + Docker) ... reverse proxy, nonce replay protection, signed receipts
- **@bolyra/sdk** (v0.5.1, npm) ... mutual ZKP handshake, delegation, scope narrowing
- **@bolyra/mcp** (v0.6.3, npm) ... MCP middleware for per-tool ZKP auth
- **Playground** at bolyra.ai/playground ... interactive demo

385 tests. 11 packages (npm + PyPI). Patent pending. Apache 2.0.

## Proposed Pilot

**Scope:** Protect one non-production MCP endpoint with two tools (one read, one simulated trade) and two registered agent identities. Receipt export to Robinhood's existing logging infrastructure.

**Success criteria:**
- Proof verification < 200ms p95 (M1 Mac baseline, adaptable to your infra)
- Fail-closed replay rejection (reused nonce blocked, no silent pass-through)
- Signed receipts visible in Robinhood logs with agent DID, permissions, and delegation chain
- No change to client OAuth flow
- Gateway self-hosted, no external service dependency

**Timeline:** 2 weeks from kickoff to demo.

## The Ask

30 minutes with the owner of Agentic Trading MCP auth/security to validate whether agent-build attestation and receipt signing belong in the gateway, MCP middleware, or OAuth layer. We can show a live demo of the gateway protecting an MCP endpoint, with receipts, in under 5 minutes.

## FAQ: Why ZK Instead of mTLS + Signed Manifests?

OAuth identifies the user session. mTLS authenticates the transport. Signed manifests can attest operator and build metadata. These are necessary and Bolyra works alongside all of them.

ZK adds three things they can't:

1. **Selective disclosure of delegation.** A delegated agent proves it has FINANCIAL_SMALL permission without revealing the full delegation chain, the delegator's identity, or the original scope it was narrowed from. Signed manifests would require exposing the entire chain to every verifier.

2. **Non-revealing scope verification.** The verifier confirms "this agent's permissions are a valid subset of its parent's" without seeing either set of permissions in the clear. With signed manifests, the verifier must see the parent's full permission set to check containment.

3. **Third-party verifiability without secret exposure.** An auditor or regulator can verify a receipt's proof independently without the operator sharing private keys, internal delegation policies, or credential material. Signed manifests require the verifier to trust the signer's key or access the signing infrastructure.

Where these properties aren't needed, signed manifests are sufficient. Bolyra enforces ZK only at the boundaries where privacy or delegation depth matters.

---

**Bolyra** | bolyra.ai | github.com/bolyra/bolyra (open source, Apache 2.0)
