# Extending Zero Trust to AI Agents on the Rippling Platform

**Bolyra** | bolyra.ai | viswa@bolyra.ai

---

## The Gap

Rippling's zero trust controls verify humans and devices before they touch workforce data. Role-based MFA, device trust certificates, conditional access, SCIM-driven lifecycle management.

Third-party agent access creates a new workload identity boundary. Based on publicly available Rippling API and MCP integrations, AI agents authenticate with Bearer tokens. A valid token lets an agent query employee PII, salary data, and device inventory. Standard bearer-token deployments don't bind authorization to an attested agent runtime:

- **Which agent is connecting.** Bearer tokens identify the OAuth client, not the specific agent build or runtime configuration behind it.
- **Whether the agent has been modified.** A certified App Shop integration and a modified fork present the same token.
- **What the agent should actually access.** Token scopes are static. There's no cryptographic enforcement of "this agent can read org structure but not salary data" that survives an audit.

This matters most for third-party App Shop agents. The partner controls the agent. Rippling needs to verify the agent's properties without trusting self-reported claims. The partner doesn't want to expose internal delegation structure to Rippling.

The data at stake is PII and payroll records. The regulatory framework is SOC 2 and GDPR, where the compliance pressure is already here.

## What Bolyra Adds

An attestation gateway for AI agents. Before an agent queries workforce data, it presents a zero-knowledge proof of its properties: operator-attested build hash, permission bitmask, and delegation chain. The gateway verifies the proof, enforces tool-level policy, blocks replays, and generates a signed audit receipt.

ZK is the mechanism. The product is verifiable agent attribution, delegated policy enforcement, and SOC 2-ready audit receipts.

**Concrete example:** AcmeHR builds a headcount planning agent on the App Shop. It needs read access to org structure and salary bands, but not individual SSNs or tax IDs. Today, AcmeHR's agent authenticates with a Bearer token scoped to "employees" — which grants access to everything in that scope, including PII. With Bolyra, AcmeHR's agent presents a ZKP proving it has READ_DATA permission (bit 0) but not ACCESS_PII (bit 7). The gateway lets `list_employees` through but blocks `get_employee` with a signed denial receipt. Rippling never sees AcmeHR's internal delegation chain. AcmeHR never gets PII it didn't need.

**Why ZK for this:** Signed manifests alone would require AcmeHR to expose its full permission grant and delegation structure to every verifier. ZK lets Rippling verify "this agent's permissions are a valid subset of what AcmeHR was granted" without either side revealing their internals.

No core MCP protocol rewrite. Production deployment needs header validation on the MCP server side and mapping from Rippling's existing RBAC rules to gateway tool policies. Integration details (code samples, gateway config) available at [bolyra.ai](https://bolyra.ai).

## Threat Model

Protects against: stolen Bearer token reuse by unregistered agents, certified App Shop integrations being impersonated by modified forks, third-party agents exceeding their delegated scope (scope can only narrow, never expand), replay of previous proof bundles, and weak post-incident attribution for PII access.

Does not replace: Rippling's existing IAM, device trust, SCIM lifecycle management, or conditional access rules. Bolyra is an enforcement and attestation layer that feeds into Rippling's IAM, audit logs, and App Shop certification.

**Guarantees:** The proof attests an approved build artifact, declared permissions, and delegation chain validity. It does not attest model behavior, prompt integrity, or runtime state beyond what the operator's signature covers.

**Data isolation:** The gateway is self-hosted. Bolyra never sees PII. Rippling controls keys, log retention, and receipt storage.

## Why This Fits Rippling

1. **Identity is already your product.** Rippling manages the full identity lifecycle for humans and devices. AI agents are the next identity class. Bolyra adds the attestation layer for agents the same way device trust certificates added it for hardware.

2. **App Shop is the use case.** Third-party developers building on the Rippling platform need to prove their agents are authorized without exposing internal delegation structure. ZK delegation chains handle this at the trust boundary where Rippling and partners meet.

3. **You'd be the operator for internal agents.** Rippling runs its own AI for access certifications and workflow automation. You sign your own agent manifests, control the trust root, and verify third-party agents against it.

4. **Fail-closed is the right default.** If the attestation layer is down, agents don't access employee PII. That's the compliance-correct behavior for workforce data.

## How It Works

```
App Shop Partner's AI Agent (or Rippling's internal AI)
    |
    | 1. Agent presents ZKP proof bundle
    |    (operator-attested build hash, permission bitmask, nonce)
    v
Bolyra Gateway (self-hosted reverse proxy)
    |
    | 2. Verify proof (< 200ms p95)
    | 3. Check tool policy (get_employee requires ACCESS_PII)
    | 4. Reject replay (nonce already seen? blocked)
    | 5. Generate signed receipt (JWS)
    | 6. Fail-closed on proof failure — denial includes a
    |    signed receipt proving which policy check failed
    |
    v
Rippling MCP Server (unchanged)
    |
    | X-Bolyra-DID: did:bolyra:agent:0x7f3a...
    | X-Bolyra-Permissions: 0x01 (READ_DATA)
    | X-Bolyra-Receipt-ID: rec_2026-06-21_...
    v
Query executes with agent identity + audit receipt
```

## What's Live

- **@bolyra/gateway** (v0.2.0, npm + Docker) — [npmjs.com/package/@bolyra/gateway](https://www.npmjs.com/package/@bolyra/gateway)
- **@bolyra/sdk** (v0.5.1, npm) — [npmjs.com/package/@bolyra/sdk](https://www.npmjs.com/package/@bolyra/sdk)
- **@bolyra/mcp** (v0.6.3, npm) — [npmjs.com/package/@bolyra/mcp](https://www.npmjs.com/package/@bolyra/mcp)
- **Interactive demo** — [bolyra.ai/playground](https://bolyra.ai/playground)
- **Source** — [github.com/bolyra/bolyra](https://github.com/bolyra/bolyra) (Apache 2.0)

## Proposed Pilot

**Scope:** Protect one non-production MCP endpoint with three tools: `list_employees` (READ_DATA), `get_employee` (ACCESS_PII), and `approve_leave` (WRITE_DATA). Two registered agent identities: one internal, one simulating a third-party App Shop partner with a delegation chain. Receipt export to Rippling's existing audit log infrastructure.

**Success criteria:**
- Proof verification < 200ms p95
- Fail-closed replay rejection
- ACCESS_PII tool gated: agent without PII permission gets a signed denial receipt proving which check failed
- Delegation chain verified: third-party agent proves narrowed scope without exposing partner's full grant
- Signed receipts visible in Rippling's audit logs
- No change to existing Bearer token auth flow

**Timeline:** 2 weeks from kickoff to demo.

## The Ask

30 minutes with the MCP or App Shop security owner to test one question: should third-party App Shop agents carry verifiable agent identity and delegated scope at the MCP boundary? We'll bring a 5-minute demo and a proposed pilot architecture.

## FAQ: Why ZK Instead of Extending Existing IAM?

Rippling's IAM verifies humans and devices using SCIM, SSO, device certificates, and conditional access. These work because Rippling controls both sides of the identity relationship.

Third-party AI agents break that model. The partner controls the agent. OAuth token exchange, DPoP-bound tokens, and signed partner manifests can authenticate the transport and attest operator metadata. ZK is justified at the trust boundary where these fall short:

1. **Delegation without exposure.** The partner proves their agent has READ_DATA permission without revealing the full delegation chain or the original grant they were narrowing from. Signed manifests require exposing the chain to every verifier.

2. **Scope containment without visibility.** Rippling confirms "this agent's permissions are a valid subset of the partner's grant" without seeing the partner's full permission set. SCIM and RBAC require visibility into both sides.

3. **Independent audit verification.** A SOC 2 auditor can verify a receipt's proof without Rippling sharing IAM configurations or the partner sharing credential material. The proof is self-contained.

For internal agents where Rippling controls both sides, existing IAM and signed attestations may be sufficient. ZK adds value specifically at the boundary where Rippling and third-party partners meet and neither side wants full transparency into the other's internals.

---

**Bolyra** | bolyra.ai | [github.com/bolyra/bolyra](https://github.com/bolyra/bolyra) (Apache 2.0)
