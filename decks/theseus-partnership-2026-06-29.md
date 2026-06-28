# Bolyra x Theseus: Identity for Autonomous Agents

---

## The Problem

Theseus agents hold their own keys, manage their own balances, and persist autonomously.

But who verifies an agent before it gets that power?

- How does Agent A trust Agent B before transacting?
- How do you enforce spending limits without a human in the loop?
- How does an agent prove what it's allowed to do without exposing its full control graph?

---

## Existing Identity Systems Don't Fit Autonomous Agents

Most identity and wallet systems were built for humans, apps, or organizations. Theseus needs identity for agents that act independently, delegate authority, enforce limits, and prove permissions on-chain.

Bolyra is designed for that model: agent-native credentials, ZK permission proofs, scoped delegation, and signed receipts for every action.

| Need | Typical Identity / Wallet Stack | Bolyra |
|------|--------------------------------|--------|
| Agent can prove permissions | Partial / app-specific | Yes |
| Delegation narrows but never expands | Usually off-chain | Enforced in circuit |
| Spending caps can be privately proven | No | Yes |
| Agent-to-agent trust handshake | No | Yes |
| On-chain verifier support | Limited | Yes |
| Human root required | Usually yes | Optional |

---

## What Bolyra Gives Theseus

Bolyra lets a Theseus agent prove:

- who issued or created it
- what actions it is allowed to perform
- what spending limits apply
- whether it can delegate to another agent
- and that every action produced a signed receipt

The agent does this without exposing its full permission set, upstream controller, or total balance.

---

## Core Mechanism

Theseus genesis or an approved agent factory issues an agent birth credential. From there, agents can delegate scoped authority to other agents.

Each delegation can only narrow permissions, never expand them. The ZK circuit checks that the child agent's authority is a valid subset of the parent's authority, including spend limits and delegation rights.

```
Theseus L1 Genesis / Agent Factory
    |
    v
  Agent Birth Credential (PLONK proof, no per-agent setup)
    |
    v
  Agent A (holds credential, proves identity on-chain)
    |
    v
  Scoped Delegation (narrower permissions, ZK enforced)
    |
    v
  Agent B (proves to services, pays via x402)
```

Permissions are represented as a compact bitmask with circuit-enforced subset checks. Details in the appendix.

---

## What Already Works

Bolyra has working proof generation, verifier contracts, TypeScript and Python SDKs, a gateway, CLI, x402 payment flow, MCP integration, and Base Sepolia deployments.

| Component | Status |
|-----------|--------|
| ZKP Circuits (Groth16 + PLONK) | Shipped |
| TypeScript SDK | v0.5.2 on npm |
| Python SDK | v0.5.0 on PyPI |
| Gateway (reverse proxy) | v0.2.1 on npm |
| x402 Payment Protocols | v0.7.0 on npm |
| MCP Auth Middleware | 6 packages on npm |
| CLI | v0.3.1 on npm |
| Base Sepolia Contracts | Deployed (IdentityRegistry + 3 Verifiers) |
| CrewAI Integration | v0.2.0 on PyPI |
| Conformance Vectors | 67 vectors, v3 |

Current demos support agent credential verification, spend-cap receipts, and mutual agent handshakes. Proofs complete in under 200ms.

Live demo: **bolyra.ai/playground** -> Base Wallet tab

---

## The Theseus Integration

### Already Built (demo today)

**1. Agent credential verification**
AgentPolicy circuit proves an agent's identity and permissions via Groth16 proof. Verifier contract deployed on Base Sepolia, portable to Theseus L1.

**2. Spending caps with receipts**
Agent auto-pays x402 APIs within policy limits. Blocked when it exceeds caps. Every decision has a signed receipt.

**3. Mutual agent handshake**
Two agents verify each other's identity and permissions in a single ZK exchange before transacting. Replay-protected via nonce binding.

### New Theseus-Specific Layer

For Theseus, we would add agent-rooted delegation: the L1 or an approved agent factory becomes the root of trust instead of a human wallet.

This makes identity native to the chain's agent lifecycle: agent creation, delegation, handshake, spend authorization, and receipts all become verifiable primitives.

No other project has this capability.

---

## Proposed Pilot

| Week | Deliverable |
|------|------------|
| 1 | Deploy AgentPolicy verifier on Theseus testnet + define agent birth credential |
| 2 | Integrate mutual agent handshake + private spend-cap proofs |
| 3 | Ship public testnet demo: Agent A verifies Agent B, delegates limited authority, executes x402 payment with signed receipt |

**Ask from Theseus:** one technical contact, testnet integration guidance, and agreement to co-demo if the pilot works.

---

## Why This Partnership

Theseus makes agents autonomous economic actors.
Bolyra gives those agents verifiable identity, scoped authority, and private policy enforcement.

Together, the demo shows more than agents transacting. It shows agents that can prove they are allowed to transact.

---

## About

**Viswa Kondoju** -- Solo founder, ZKProva Inc.
- Apache 2.0 open source
- Provisional patent filed (April 2026)
- IETF draft: draft-bolyra-mutual-zkp-auth-01

bolyra.ai | github.com/bolyra/bolyra | viswa@bolyra.ai

---

## Appendix: Permission Bitmask

8-bit cumulative encoding. Higher tiers imply lower.

| Bit | Permission | Scope |
|-----|-----------|-------|
| 0 | READ_DATA | |
| 1 | WRITE_DATA | |
| 2 | FINANCIAL_SMALL | < $100 |
| 3 | FINANCIAL_MEDIUM | < $10K (implies bit 2) |
| 4 | FINANCIAL_UNLIMITED | (implies bits 2+3) |
| 5 | SIGN_ON_BEHALF | |
| 6 | SUB_DELEGATE | |
| 7 | ACCESS_PII | |

Cumulative encoding and subset checks are enforced in the Circom circuit, not middleware. The Delegation circuit verifies that a child credential's bitmask is a valid subset of the parent's.
