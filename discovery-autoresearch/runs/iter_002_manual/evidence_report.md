# Iteration 002 (Manual) -- Evidence Report

**Date:** 2026-04-21
**Method:** Manual web search seeding (15 searches)
**Purpose:** Seed autoresearch loop with real demand evidence after iter_001 returned zero URLs

---

## Executive Summary

The demand signal for agent identity is **overwhelmingly strong** and **accelerating faster than expected**. This is not a speculative market -- it is an active, multi-front buildout happening simultaneously across standards bodies (IETF, NIST, OWASP, FIDO), payment networks (Visa, Mastercard, Google AP2), enterprise platforms (Microsoft Entra Agent ID, WorkOS FGA), and open-source projects (7+ GitHub repos with distinct approaches). ZKP-based agent identity is explicitly called out by CoinDesk, academic papers, and the World/Coinbase collaboration.

## Signal Strength by Topic

### 1. Verifiable AI Agent Identity (CRITICAL -- highest evidence density)

**Standards activity:**
- **NIST** published a concept paper on AI agent identity and authorization (2026-02-05), comment period already closed. Standards under consideration: MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC. [Source](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- **IETF** has at minimum 4 active drafts: `draft-klrc-aiagent-auth` (OpenAI co-authored), `draft-hartman-credential-broker-4-agents`, `draft-yao-agent-auth-considerations`, `draft-ni-a2a-ai-agent-security-requirements`. Plus a chartered Web Bot Auth Working Group (Cloudflare + Google).
- **OWASP** published the Agentic Top 10 (2026 edition). 3 of the top 4 risks are identity-related (ASI02, ASI03, ASI04). [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

**Enterprise products shipped:**
- **Microsoft Entra Agent ID** -- first-class identity for AI agents, OAuth 2.0/OIDC based. Copilot Studio auto-creates Entra agent identities. Governance framework for inventorying, owning, auditing agents. [Source](https://learn.microsoft.com/en-us/entra/agent-id/what-is-agent-id-platform)
- **WorkOS FGA** -- resource-scoped authorization layer for AI agents, launched April 2026. Millions of authz requests/sec, explicit agent credentials, least-privilege. [Source](https://workos.com/blog/agents-need-authorization-not-just-authentication)

**Open-source ecosystem (GitHub):**
- Microsoft Agent Governance Toolkit (covers full OWASP Agentic Top 10)
- Agent Identity Protocol (AIP) -- zero-trust MCP proxy with HITL
- ZeroID -- cryptographic verifiable credentials + delegated authority chains
- Open Agent Passport (OAP) -- real-time enforcement at point of action
- Agent Integrity Protocol -- supply chain security for agentic web
- better-auth/agent-auth-protocol -- capability-based authz + service discovery
- Verified Agent Identity (Billions Network) -- DID-based

### 2. Payment Network Agent Identity (CRITICAL -- massive capital commitment)

**Visa:**
- Trusted Agent Protocol (TAP) launched Oct 2025 with 10+ partners including Cloudflare, Shopify, Stripe, Microsoft, Coinbase. [Source](https://investor.visa.com/news/news-details/2025/Visa-Introduces-Trusted-Agent-Protocol-An-Ecosystem-Led-Framework-for-AI-Commerce/default.aspx)
- Hundreds of agent-initiated transactions completed. 100+ partners, 30+ building in sandbox, 20+ integrating directly.
- 2026 mainstream adoption: pilot programs in APAC and Europe.

**Mastercard:**
- Agent Pay: registered/verified agents required for payments. Strong consumer auth via on-device biometrics. [Source](https://www.mastercard.com/global/en/news-and-trends/press/2025/april/mastercard-unveils-agent-pay-pioneering-agentic-payments-technology-to-power-commerce-in-the-age-of-ai.html)
- Verifiable Intent: open-source standards-based framework for agentic commerce (2026).
- Contributing to **FIDO Payments Working Group** for verifiable credentials in agent auth. [Source](https://www.mastercard.com/us/en/news-and-trends/stories/2026/agentic-commerce-rules-of-the-road.html)
- Partnered with PayPal (Oct 2025) for secure global agentic commerce.

**Google:**
- Agent Payments Protocol (AP2): 60+ partners including Mastercard, AmEx, UnionPay. Extension of A2A and MCP. [Source](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
- A2A Protocol: 150+ organizations at one-year mark. Production deployments in financial services, supply chain, insurance. Hosted by Linux Foundation.

### 3. ZKP for Agent Identity (HIGH -- explicit demand + academic validation)

- **CoinDesk opinion piece** (Nov 2025): "AI Agents Need Identity and Zero-Knowledge Proofs Are the Solution." ZKPs allow verification without surveillance. [Source](https://www.coindesk.com/opinion/2025/11/19/ai-agents-need-identity-and-zero-knowledge-proofs-are-the-solution)
- **World (Worldcoin) + Coinbase x402** (Mar 2026): Verify human identity behind AI agents using ZKPs. Platforms verify agent represents a real person without collecting personal data. [Source](https://www.coindesk.com/tech/2026/03/17/sam-altman-s-world-teams-up-with-coinbase-to-prove-there-is-a-real-person-behind-every-ai-transaction)
- **ZK-ACE** (arXiv): Identity-centric ZK authorization for post-quantum blockchain systems.
- **Zero-Trust Identity Framework for Agentic AI** (arXiv): Decentralized authentication + fine-grained access control.
- **Know Your Agent (KYA)**: Emerging paradigm combining AI identity verification with crypto commerce.
- **ISACA (2025):** "63% of organizations cannot enforce purpose limitations on their AI agents." [Source](https://www.isaca.org/resources/news-and-trends/industry-news/2025/the-looming-authorization-crisis-why-traditional-iam-fails-agentic-ai)

### 4. Delegated Spending / Agent Authorization (HIGH -- enterprise budget signal)

- **Delegated economies**: Authorization becomes policy -- users approve a decision space, not individual transactions. [Source](https://argozconsultants.com/delegated-economies-ai-payments/)
- **Coinbase Agentic Wallets** (Feb 2026): First wallet infra for AI agents. x402 protocol with 50M+ transactions. Programmable spending caps per session + per transaction. [Source](https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets)
- **Privacy.com** published an agent payment solutions comparison for 2026.
- **KPMG**: 67% of leaders maintain AI spending even in recession. $124M projected per-company deployment. Agentic AI = 10-15% of IT spending in 2026.

### 5. Machine Identity Market (HIGH -- addressable market validated)

- **Market size**: $21.39B in 2026 (machine identity management). [Source](https://www.businessresearchinsights.com/market-reports/machine-identity-management-market-102859)
- Non-human identities outnumber human users 3:1 in most enterprises.
- 60% of cybersecurity experts consider machine identities higher security risk than human identities.
- **Gartner IAM Summit 2026** theme: "Identity expanded faster than most programs did." [Source](https://blog.gitguardian.com/gartner-iam-summit-2026-identity-expanded-faster-than-most-programs-did/)
- **Strata**: AI agents require a new identity playbook -- they are not just non-human identities. [Source](https://www.strata.io/blog/agentic-identity/new-identity-playbook-ai-agents-not-nhi-8b/)

---

## Key Takeaways for Bolyra

1. **Timing is perfect.** The market is in early buildout phase (standards being drafted, first products shipping, pilots running). A ZKP-native approach is differentiated.

2. **ZKP is explicitly called out** as a solution by CoinDesk, World/Coinbase, academic researchers, and industry analysts. Bolyra's ZKP-first position is not a stretch -- it is the direction the market is moving.

3. **The gap Bolyra fills**: Existing solutions (Microsoft Entra Agent ID, WorkOS FGA) are centralized, OAuth-based, enterprise-walled. The ZKP angle enables privacy-preserving, portable, cross-platform agent identity that no incumbent currently offers.

4. **Immediate competitive landscape**: ZeroID, Agent Identity Protocol, Open Agent Passport are open-source attempts. None appear to combine ZKPs with production-grade DID infrastructure the way Bolyra could.

5. **Standards engagement is a moat**: NIST comment period just closed. IETF drafts are active. FIDO Payments Working Group is forming. Bolyra should aim to be at these tables.

6. **Payment networks as distribution**: Visa TAP, Mastercard Agent Pay, and Google AP2 all need agent identity verification layers. A ZKP-based verification layer could plug into any of these as a trust primitive.

---

## Recommended Next Steps

- Feed this evidence into the autoresearch loop as `tier_1_validated` signals
- Deep-dive the IETF drafts (especially `draft-klrc-aiagent-auth` where OpenAI is co-author)
- Read the NIST concept paper PDF for specific technology gaps Bolyra could address
- Map Bolyra's architecture against OWASP Agentic Top 10 risks ASI02/ASI03/ASI04
- Evaluate World/Coinbase x402 as a potential integration partner
