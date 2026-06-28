---
title: Go-to-Market Strategy
visibility: internal
sources:
  - strategy/2026-06-27-gtm-codex-final.md
  - strategy/codex-pushback-round2.md
  - strategy/codex-challenge-strategy.md
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [strategy, gtm, outreach, x402]
---

Bolyra's GTM strategy was Codex-reviewed (gpt-5.5, high reasoning effort) on 2026-06-27. The strategy is founder-driven, focused on one narrow wedge: x402/Base agent payments authorization.

## Overview

The current positioning:

> Bolyra is the authorization layer for AI-agent payments. It lets x402/Base apps verify which agent is making a paid request, check what it is allowed to access, and approve or reject the request before serving the endpoint.

Do not lead with ZKPs, identity protocol, or privacy. Lead with: "Can this agent be trusted, authorized, and rate-limited before I serve a paid API request?"

## Key Findings

### What Died

- **Anthropic partnership strategy** -- dead on arrival (Codex Pass 1). MCP auth is already OAuth 2.1. Anthropic lost the standards chokepoint to AAIF/Linux Foundation. ZKP in the auth hot path is disqualifying for interactive agent auth.
- **"Bolyra as MCP auth, generally"** -- the general case is already taken by Auth0/WorkOS/Stytch/Cloudflare.
- **Standards-first approach** -- customer proof must come before standards work; one real regulated deployment outweighs ten RFC issues.

### What Survived (Codex Round 2)

A narrower strategy with six load-bearing components:
1. Bolyra = regulated-deployment OAuth 2.1 AS for MCP (not a new protocol)
2. Standard bearer tokens on the wire (no custom handshake)
3. Opaque tokens + minimal RFC 7662 introspection by default
4. ZK only if it proves concrete privacy/compliance advantage
5. ext-auth path only if protocol-visible capability metadata is needed
6. AAIF engagement through standards/security/privacy channels

### Current GTM Plan (45-Day Sprint)

**Days 1-2:** Turn the Jesse Pollak/Base/x402 Twitter attention into conversations. Post follow-up, quote-post the authorization angle, DM relevant builders. Success metric: 3 real conversations.

**Days 3-7:** Narrow outbound to 40 highly relevant people -- x402 builders, Base app developers, AI agent framework builders, paid API developers. Daily: 8 DMs, 2 public replies, 1 founder post, 1 demo improvement. Primary ask: "Can I see how your paid agent/API request flow works and tell you where authorization breaks?"

**Days 8-21:** Build for one user. If one builder shows real pain, stop all broad product work and integrate with them. Build only: agent registration, auth check before paid endpoint, simple allow/deny policy, dev-readable logs.

**Days 22-45:** Decide based on pull. 1+ integration = case study + intros + repeat. No integration = change wedge. No calls = kill this wedge.

### Kill Criteria

| Day | Trigger | Action |
|---|---|---|
| 7 | < 3 meaningful replies from 40 contacts | Kill the current MESSAGE |
| 21 | No technical walkthrough or integration attempt | Change wedge |
| 45 | No integration, no active builders, no partner | Stop or radically reposition |

### Alternate Wedges (if x402 fails)

- API abuse/rate-limit identity for AI agents
- Verified agent access for paid data APIs
- Compliance/privacy credentialing for agent transactions

## Current Status

- Zero users as of 2026-06-28
- 11+ packages shipped (npm + PyPI)
- Demo live at bolyra.ai/playground
- x402 Agent Wallet preset shipped
- shafu0x (x402 creator, 16.4K followers) joined AgentCash Telegram
- Outbound started: X thread + replies, Coinbase CDP Discord posts

### The Founder's Rule

> No feature, site, package, SDK, or side project gets built unless it helps one specific x402/Base builder authorize AI-agent access to a paid endpoint.

## See Also

- `strategy/2026-06-27-gtm-codex-final.md` -- full Codex-reviewed GTM plan
- `strategy/codex-challenge-strategy.md` -- why Anthropic partnership died
- `wiki/strategy/competitive-landscape.md` -- who else is in the space
