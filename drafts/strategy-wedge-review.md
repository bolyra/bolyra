# Wedge Strategy Adversarial Review — Cross-Model Synthesis
Reviewed: 2026-04-21
Sources: Codex (gpt-5.4) + Claude Opus (independent parallel reviews)

## Consensus: The Wedge

"Agentic commerce" is the right market. "Cryptographic spending limits" is NOT the right framing.

**Codex framing:** "Delegated spend-policy verification for agent-initiated transactions — prove this agent is allowed to spend up to $X, with vendor/category/time limits, without exposing the full identity or policy graph."

**Claude framing:** "Zero-knowledge delegation proofs for agent transactions — cryptographic delegation receipts that prove a specific human authorized a specific scope of action for a specific agent."

**Best beachhead:** B2B procurement, enterprise travel booking, high-value marketplace purchases.

**NOT:** Generic consumer checkout (Visa TAP already there).

## Consensus: Competitive Position

Be the privacy LAYER underneath incumbents, not a competing platform.

- Visa's Trusted Agent Protocol needs privacy → Bolyra is the ZK layer
- Microsoft's Governance Toolkit needs audit trails without vendor access → Bolyra
- Okta's OAuth is plaintext delegation → Bolyra adds selective disclosure

**Pitch:** "Add privacy-preserving delegated authorization to existing flows."

## Consensus: IETF Strategy

The existing draft-klrc-aiagent-auth-01 (backed by AWS, Zscaler, Ping Identity, OpenAI) is a THREAT if Bolyra stays standalone. It becomes an OPPORTUNITY if Bolyra positions as the privacy extension.

**Action:** Email draft authors this week. Offer to co-author privacy extension or contribute ZK scope-narrowing section.

## Consensus: Stop Building, Start Validating

Both reviewers agree: the next move is NOT more code. It's finding ONE design partner for ONE painful workflow.

## Key Risk: Timing

Claude raised the existential question: "Are there actual humans today authorizing AI agents to spend money and worried about the authorization trail? If 'not yet, but soon' — you're 6-18 months early."

Codex's counter: Visa, Mastercard, Microsoft, and Okta are all building solutions NOW. The market is real. The question is whether a solo founder can win a piece of it.

## Action Plan (Next 7 Days)

1. Email IETF draft-klrc-aiagent-auth authors (Day 1)
2. Write "How Bolyra maps to IETF agent auth" 1-pager (Day 1)
3. Build ONE B2B procurement demo with existing SDK (Day 2-3)
4. Rewrite bolyra.ai hero for delegated spend-policy use case (Day 3)
5. 20 targeted outreaches to procurement/payments/risk leads (Day 4-7)
6. Build thin OpenClaw adapter (Day 5, max 1 day)

## What NOT To Do (Next 30 Days)

- No more framework integrations
- No circuit optimization or gas cost work
- No crypto Twitter thread (wrong audience for B2B)
- No ZKP blog posts (buyer doesn't read ZKP blogs)
- No crypto conferences
- No broad platform building
- No commercial activity (EAD still pending)
