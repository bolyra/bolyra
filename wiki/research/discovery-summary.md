---
title: Discovery Autoresearch Summary
visibility: internal
sources:
  - discovery-autoresearch/program.md
  - discovery-autoresearch/reports/discovery-r1.md
  - discovery-autoresearch/reports/discovery-r2.md
  - discovery-autoresearch/reports/discovery-r3.md
  - discovery-autoresearch/reports/discovery-r4.md
  - discovery-autoresearch/history/opportunity_trajectory.jsonl
  - discovery-autoresearch/output/opportunity_board.json
last-updated: 2026-06-28
staleness-threshold: 7d
tags: [research, discovery, market, opportunities]
---

The discovery autoresearch loop systematically searched for market opportunities where Bolyra's ZKP identity primitives solve real problems. The result was sobering: zero opportunities survived adversarial scrutiny across 4 iterations.

## Overview

The discovery loop is a Karpathy-style autoresearch program focused on demand discovery, not protocol improvement. It scores opportunities on 4 dimensions (Demand, Timing, Fit, Feasibility -- 25 points each) and subjects survivors to 5-axis adversarial challenge by a skeptical-investor persona.

The loop ran 4 iterations (June 19-21, 2026), scanning 156 signal sources total, discovering 35 raw opportunities, validating 22 through Tier 2, challenging 18 in Tier 3 -- and approving zero.

## Key Findings

### Iteration Summary

| Iter | Date | Sources | Found | Tier 2 | Tier 3 | Approved | Board Size |
|---|---|---|---|---|---|---|---|
| 1 | 2026-06-21 | 105 | 9 | 7 | 7 | 0 | 0 |
| 2 | 2026-06-21 | 26 | 8 | 4 | 4 | 0 | 0 |
| 3 | 2026-06-21 | 18 | 9 | 5 | 5 | 0 | 0 |
| 4 | 2026-06-19 | 7 | 9 | 6 | 6 | 0 | 0 |

The opportunity board is empty (`opportunity_board.json = []`).

### Recurring Rejection Patterns

The adversarial reviewer (skeptical investor persona) consistently rejected opportunities for three reasons:

1. **Phantom demand.** Nearly every opportunity card admitted "Web search evidence returned zero results" or "demand_strength: none" in its own metadata. Demand scores of 8/25 were awarded against zero evidence -- the reviewer correctly flagged these as fabricated.

2. **Platform risk / incumbent advantage.** For framework integrations (LangChain, CrewAI, AutoGen), the platform owner can ship native auth in a single sprint. For enterprise identity (Okta, Auth0, Microsoft Entra), incumbents have distribution, budgets, and existing customer relationships that a pre-revenue startup cannot match.

3. **ZKP is overengineered.** For most use cases examined, simpler solutions (OAuth scopes, API keys, policy engines like OPA/Cedar, short-lived JWTs) solve the problem adequately. The privacy properties ZKP provides are features nobody has asked for in the examined contexts.

### Opportunities Examined (All Rejected)

Across all 4 iterations, tested opportunities included:
- ZKP-based agent auth for CI/CD pipelines
- Mutual ZKP authentication for human-agent interactions
- One-way scope narrowing for multi-agent delegation chains
- Privacy-preserving agent identity vs transparent DID/signature schemes
- Cumulative-bit permission encoding as a standard
- ZKP alternative to OAuth-like Agent Passport flows
- LangChain/CrewAI agent auth middleware
- Bolyra DID method as reference implementation
- Privacy-preserving agent identity layer for enterprise IdPs
- EU AI Act Article 50 compliance via ZKP
- On-chain spend policy enforcement
- Agent identity as VC-fundable primitive
- ZKP handshake for agent-native payment authorization
- AutoGen multi-agent role verification
- DID-native ZKP credentials for zero-trust agent frameworks
- Cross-app agent access (XAA alternative)
- Agentic wallet identity layer

## Current Status

The discovery loop is considered stalled (3 consecutive iterations with zero approvals meets the drought exit condition). The opportunity board remains empty. This informed the June 2026 pivot to the x402/Base agent payments wedge (see `wiki/strategy/gtm.md`), which was selected outside the autoresearch loop based on real-time social signal (Jesse Pollak/Base engagement) rather than systematic search.

## See Also

- `discovery-autoresearch/program.md` -- master specification
- `discovery-autoresearch/reports/` -- per-iteration reports with full rejection rationales
- `wiki/strategy/gtm.md` -- current GTM strategy (post-discovery pivot)
- `wiki/strategy/competitive-landscape.md` -- competitive context
