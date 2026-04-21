# Strategy Priors — Cross-Model Adversarial Review Summary

Synthesized from Claude (Opus 4) and Codex (GPT-5.4) adversarial review of Bolyra positioning.

## Market Wedge: Agentic Commerce

Both models converge: **agentic commerce** is the right entry point. AI agents spending money on behalf of humans/orgs is the near-term use case where ZKP identity solves a real, painful problem — not abstract "decentralized identity" or "self-sovereign credentials."

## Framing: Delegated Spend-Policy Verification

The winning pitch is **"delegated spend-policy verification"**, not "cryptographic spending limits." The distinction matters:

- "Cryptographic spending limits" sounds like a feature (rate-limiting with math). Incumbents can bolt this on.
- "Delegated spend-policy verification" frames the *principal-agent problem*: proving an agent is authorized to spend within a policy, without revealing the policy itself. This is structurally new.

## Beachhead Markets

Three segments where the pain is immediate and the willingness to integrate is high:

1. **B2B procurement** — Agents purchasing on behalf of orgs need verifiable authorization. Current flow is broken (shared credentials, approval chains that don't translate to API calls).
2. **Enterprise travel** — Travel agents (AI) booking within policy constraints. Hotels, airlines, and TMCs already deal with complex authorization. ZKP policy proofs compress this.
3. **High-value marketplaces** — Platforms where agent-to-agent transactions require trust without full identity disclosure. Think wholesale, industrial supply, specialized services.

## Positioning: Privacy Layer, Not Competing Platform

Critical strategic insight: Bolyra must be the **privacy layer underneath incumbents** (Visa, Microsoft, Okta), not a competing platform.

- Visa wants agent commerce to flow through its rails. Bolyra makes that possible without exposing cardholder policy details.
- Microsoft wants Entra to manage agent identities. Bolyra adds ZKP attestations to Entra tokens.
- Okta wants to be the agent auth provider. Bolyra provides the privacy-preserving credential layer Okta can't build fast enough.

**Be plumbing, not a destination.** The incumbents are the distribution channel.

## Standards Opportunity: IETF draft-klrc-aiagent-auth-01

The IETF draft on AI agent authentication (draft-klrc-aiagent-auth-01) is an opening. If Bolyra positions as the **privacy extension** to this draft — adding ZKP-based policy attestations to the authentication framework — it becomes a standards-track component rather than a proprietary solution.

Action: monitor the draft, contribute if/when appropriate, ensure Bolyra's protocol is compatible.

## Consensus: Stop Building, Start Validating

Both Claude and Codex independently reached the same conclusion: **the technical primitives are sufficient. The risk is not "can we build it" but "does anyone want it."**

Priority must shift from protocol development to demand validation:
- Find 3-5 teams actually building agent commerce systems
- Show them the delegated spend-policy verification concept
- Measure reaction: indifference, curiosity, or "when can I use this?"

## Key Risk: Timing

The market for agent spending authorization is **6-18 months early**. Agents browsing, summarizing, and coding are mainstream. Agents autonomously spending money are not — yet.

This is a feature, not a bug, IF the time is used for:
- Open-source ecosystem building (SDK, docs, reference implementations)
- Standards participation
- Community cultivation

It becomes a fatal risk if the time is spent on premature go-to-market.

## PMF Signal

Real product-market fit will not come from surveys or interviews. It will come from:
> **Someone opens a GitHub issue for a feature you didn't plan.**

That is the signal. Everything before that is hypothesis.
