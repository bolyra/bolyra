---
type: concept
title: Bolyra × Rippling Partnership One-Pager
status: ready-for-warm-intro
created: '2026-06-21T00:00:00.000Z'
version: v3
ingested_via: 'mcp:put_page'
ingested_at: '2026-06-22T03:13:29.954Z'
source_kind: 'mcp:put_page'
tags:
  - app-shop
  - bolyra
  - iam
  - mcp
  - outbound
  - partnership
  - rippling
  - zero-trust
---

# Extending Zero Trust to AI Agents on the Rippling Platform

**Bolyra** | bolyra.ai | viswa@bolyra.ai

---

## The Gap

Rippling's zero trust controls verify humans and devices before they touch workforce data. Role-based MFA, device trust certificates, conditional access, SCIM-driven lifecycle management.

Third-party agent access creates a new workload identity boundary. Based on publicly available Rippling API and MCP integrations, AI agents authenticate with Bearer tokens. Standard bearer-token deployments don't bind authorization to an attested agent runtime: which agent is connecting, whether it's been modified, what it should actually access.

This matters most for third-party App Shop agents. The partner controls the agent. Rippling needs to verify the agent's properties without trusting self-reported claims. The partner doesn't want to expose internal delegation structure to Rippling.

The data at stake is PII and payroll records. The regulatory framework is SOC 2 and GDPR.

## What Bolyra Adds

An attestation gateway for AI agents. ZK is the mechanism. The product is verifiable agent attribution, delegated policy enforcement, and SOC 2-ready audit receipts.

**Concrete example:** AcmeHR builds a headcount planning agent on the App Shop. It needs read access to org structure and salary bands, but not individual SSNs or tax IDs. Today, AcmeHR's agent authenticates with a Bearer token scoped to "employees" — which grants access to everything in that scope, including PII. With Bolyra, AcmeHR's agent presents a ZKP proving it has READ_DATA permission (bit 0) but not ACCESS_PII (bit 7). The gateway lets `list_employees` through but blocks `get_employee` with a signed denial receipt. Rippling never sees AcmeHR's internal delegation chain. AcmeHR never gets PII it didn't need.

**Why ZK for this:** Signed manifests alone would require AcmeHR to expose its full permission grant and delegation structure to every verifier. ZK lets Rippling verify "this agent's permissions are a valid subset of what AcmeHR was granted" without either side revealing their internals.

## Threat Model

Protects against: stolen Bearer token reuse by unregistered agents, certified App Shop integrations being impersonated by modified forks, third-party agents exceeding their delegated scope (scope can only narrow, never expand), replay of previous proof bundles, and weak post-incident attribution for PII access.

Does not replace: Rippling's existing IAM, device trust, SCIM lifecycle management, or conditional access rules. Bolyra is an enforcement and attestation layer that feeds into Rippling's IAM, audit logs, and App Shop certification.

**Guarantees:** The proof attests an approved build artifact, declared permissions, and delegation chain validity. It does not attest model behavior, prompt integrity, or runtime state beyond what the operator's signature covers.

**Data isolation:** The gateway is self-hosted. Bolyra never sees PII. Rippling controls keys, log retention, and receipt storage.

## Why This Fits Rippling

1. **Identity is already your product.** AI agents are the next identity class after humans and devices.
2. **App Shop is the use case.** Third-party agents need to prove authorization without exposing internal delegation structure. ZK delegation chains handle this at the trust boundary.
3. **You'd be the operator for internal agents.** Rippling signs its own agent manifests, controls the trust root, verifies third-party agents against it.
4. **Fail-closed is the right default.** If attestation is down, agents don't access PII. Compliance-correct for workforce data.

## Proposed Pilot

Protect one non-production MCP endpoint with three tools (`list_employees`, `get_employee`, `approve_leave`). Two agent identities: one internal, one simulating App Shop partner with delegation chain. Success: < 200ms p95 verification, fail-closed replay rejection, PII gating with signed denial receipts, delegation chain verified without exposing partner's full grant. Timeline: 2 weeks.

## The Ask

30 minutes with the MCP or App Shop security owner to test one question: should third-party App Shop agents carry verifiable agent identity and delegated scope at the MCP boundary? 5-minute demo + proposed pilot architecture.

## FAQ: Why ZK Instead of Extending Existing IAM?

OAuth token exchange, DPoP-bound tokens, and signed partner manifests can authenticate transport and attest operator metadata. ZK is justified at the trust boundary where these fall short: (1) delegation without exposure, (2) scope containment without visibility into the partner's full permission set, (3) independent SOC 2 audit verification without sharing IAM configs or credential material. For internal agents where Rippling controls both sides, existing IAM may be sufficient.

## Codex Review Summary

Reviewed through 3 iterations by OpenAI Codex (gpt-5.5). Final grades: PHI/HIPAA overclaim FIXED, concrete App Shop scenario FIXED, pilot/ask FIXED, ZK justification/bearer-token assumptions/permission model/threat model PARTIALLY FIXED (remaining items are conversation-stage topics). Permission-bit bug caught and fixed in v3. Verdict: ready as leave-behind after warm intro.

## Strategic Notes

- Rippling may be a stronger fit than Robinhood because: (1) IAM is a core product — they understand identity, (2) PII/payroll data regulated by SOC 2/GDPR today (not speculative like SEC agent rules), (3) App Shop third-party delegation is the killer ZK use case, (4) they'd be the operator — clean trust root answer, (5) fail-closed is a feature not a liability.
- Rippling is $13.5B valuation, 4.8/5 on G2 (12,900 reviews), ISO 42001 AI certified.
- The Rippling MCP server details (18 tools, Bearer auth) come from community MCP integrations, not official Rippling docs. Soften claims accordingly in conversation.
