---
title: Competitive Landscape
visibility: internal
sources:
  - strategy/codex-challenge-strategy.md
  - strategy/codex-pushback-round2.md
  - strategy/zk-vs-rfc7662-differentiation.md
  - differentiation-autoresearch/history/convergence_report.md
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [strategy, competition, positioning]
---

Bolyra operates in the AI agent identity and authorization space. The competitive landscape is dominated by established identity vendors solving the general case, leaving Bolyra a narrow but defensible wedge in regulated-deployment agent authorization.

## Overview

The agent identity market is converging on standard OAuth 2.1 infrastructure. MCP auth is specified as OAuth 2.1 + PRM (RFC 9728) + PKCE + resource indicators. Vendors already selling MCP auth include Auth0, WorkOS, Stytch, and Cloudflare Access. Bolyra does not compete on the general case -- it competes on privacy and cryptographic assurance properties that OAuth cannot deliver.

## Key Competitors

| Competitor | Positioning | Bolyra Advantage |
|---|---|---|
| **Auth0 / Okta** | General MCP auth, OAuth 2.1 AS, enterprise IAM | Cannot provide AS-blind unlinkability or model-instance binding |
| **WorkOS** | Developer-friendly MCP auth | Same OAuth structural limitations |
| **Stytch** | Connected apps, MCP auth | Same OAuth structural limitations |
| **Cloudflare Access** | Remote MCP deployment, auth, governance, DLP, shadow-MCP detection | Best positioned for enterprise MCP; Bolyra's regulated-privacy wedge is complementary, not competitive |
| **World (Worldcoin)** | Human uniqueness proofs at scale ($250M+) | Bolyra binds human + agent identity with delegation; World does human-only |
| **Privy / Lit Protocol / Turnkey** | Wallet infra, agent wallets | Not solving agent authorization; wallet identity is secp256k1 keypairs, not capability proofs |
| **SPIFFE / WIMSE** | Workload identity, machine-to-machine | Hides attributes from verifiers but not from issuers; no provider anonymity |
| **W3C VC + BBS+** | Verifiable credentials with selective disclosure | Overlaps with Bolyra on issuer-blind predicates; does not address model-instance binding |

## Where Bolyra Wins (Data-Driven)

Two properties confirmed under 5-persona adversarial scrutiny (differentiation-autoresearch, April 2026):

1. **C7 -- Cryptographic model-instance binding (9/10).** Binds `(modelHash, operator_pk, permission_bitmask, messageHash)` per RS invocation. No OAuth/MCP configuration can deliver per-call payload binding + provider anonymity + runtime-model identity simultaneously. RFC 7662 signed introspection cannot bind per-call payloads without re-introducing AS participation; DPoP binds to URI not payload; PPIDs cannot provide provider anonymity.

2. **C2 -- AS-blind cross-scope unlinkability (8/10).** Post-enrollment agent-side proof generation keeps the AS off the per-scope authorization path. OAuth/OIDC structurally requires AS participation at token issuance.

## Where Bolyra Loses

- **General MCP auth.** Auth0/WorkOS/Stytch/Cloudflare win on ecosystem integrations, simplicity, and time-to-integrate. Operators who do not need privacy properties will never choose Bolyra.
- **Anthropic-side infrastructure.** Anthropic runs centralized services; AS-surveillance concern does not apply inside their own boundary.
- **Agent-only ecosystems without regulation.** If no regulatory requirement drives privacy, simpler tools suffice.

## Recommended Partnership Target

Cloudflare over Anthropic. Cloudflare publicly owns remote MCP deployment, auth, portals, governance, and DLP. That is where auth budget and operational pain live.

## Current Status

Zero users. 11+ packages shipped. Positioning pivoted (June 2026) to "authorization layer for AI-agent payments" in the x402/Base ecosystem, focusing on finding one builder with an actual paid endpoint.

## See Also

- `strategy/zk-vs-rfc7662-differentiation.md` -- full ZK vs RFC 7662 analysis
- `strategy/codex-challenge-strategy.md` -- Codex adversarial review of partnership strategy
- `strategy/codex-pushback-round2.md` -- revised strategy after pushback
- `wiki/strategy/differentiation.md` -- technical differentiation details
