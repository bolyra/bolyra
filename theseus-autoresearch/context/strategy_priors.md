# Strategic Priors — Bolyra x Theseus

## 1. Theseus Is Pre-Launch — Architecture Decisions Still Fluid

Theseus has $100K seed from Orange DAO and is building toward launch. Identity layer design is not finalized. Bolyra can influence foundational architecture decisions rather than retrofit into an existing system. This is the ideal integration window.

## 2. "No Human Key Path" Is Structurally New

Most identity systems assume a human in the loop — OAuth, SAML, WebAuthn, even W3C DIDs center around a human holder. Theseus explicitly removes the human key path. Bolyra's delegation circuit currently assumes human-rooted trust. An agent-rooted variant (where the L1 genesis or agent birth transaction is the root of trust) is the key architectural extension.

## 3. Bolyra's Existing Moat

What we ship today:
- 3 Circom circuits (HumanUniqueness, AgentPolicy, Delegation)
- 8-bit cumulative permission model with on-circuit enforcement
- IdentityRegistry smart contract (Base Sepolia)
- 12 published packages (npm + PyPI)
- IETF draft (draft-bolyra-mutual-zkp-auth-01)
- 67 conformance test vectors
- CrewAI + LangChain + MCP integrations

No competitor has ZKP-based authorization with on-chain delegation enforcement.

## 4. The "Agent-Only" Gap

Current architecture: Human creates identity -> delegates to agent -> agent acts within scoped permissions. For Theseus: Agent IS the root identity. Agent-to-agent delegation with L1 genesis as root of trust is the key missing piece. The Delegation circuit needs an agent-rooted variant where the "delegator" can be another agent, not just a human.

## 5. x402 Bridges

The `@bolyra/payment-protocols` package already implements x402 (HTTP 402 payment-required flows). Theseus agents that need to pay for services on other chains can use Bolyra's payment-protocols as a bridge. Natural integration for autonomous agent spending.

## 6. Competitors

| Competitor | Funding | Gap |
|---|---|---|
| Lit Protocol | $3.6M | Programmable key pairs, no ZKP auth or delegation chains |
| Turnkey | Well-funded | Embedded wallets, enterprise focus, no agent-native identity |
| Privy | Well-funded | Embedded wallets, human-centric, no delegation circuits |
| World ID | Massive | Human-only biometric, explicitly excludes agents |
| SPIFFE/WIMSE | Standards | Enterprise service mesh identity, no crypto/ZKP layer |

None have: ZKP-based auth + delegation chains + on-chain enforcement + agent-native design.

## 7. Orange DAO Context

Orange DAO is crypto-native (YC alumni). They value decentralization, open source, and composability. Bolyra's Apache 2.0 license and open protocol approach aligns with their investment thesis. A partnership with a portfolio company strengthens the DAO relationship.

## 8. Verifiable AI Execution Complement

Theseus advertises "verifiable AI execution." But verifiable execution without verifiable authorization is incomplete — you can prove WHAT an agent did, but not WHETHER it was authorized to do it. Bolyra provides the missing authorization proof layer: not just "this agent ran this model" but "this agent was authorized to spend up to $100 on behalf of entity X with permission bits 0b00000111."
