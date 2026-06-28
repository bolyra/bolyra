# Teach: Bolyra Protocol Overview

## Status: COMPLETE (18/18 mastered)

---

## 1. The Problem — Why Bolyra Exists
- [x] 1.1 What gap in the market does Bolyra fill? (humans + agents, no single protocol does both)
- [x] 1.2 Why ZKPs specifically? Why not just sign things with keys?
- [x] 1.3 What's wrong with existing approaches? (World = Orbs hardware, Didit = govt ID, Indicio = VCs without privacy)
- [x] 1.4 What is draft-klrc-aiagent-auth-01 and why does Bolyra position against it?

## 2. The Protocol — How It Works
- [x] 2.1 The two sides: HumanUniqueness circuit (Semaphore v4 reuse) vs AgentPolicy circuit
- [x] 2.2 What is a handshake? (mutual auth binding human proof + agent proof to a session nonce)
- [x] 2.3 The permissions model — 8-bit cumulative encoding, implication rules
- [x] 2.4 Delegation circuit — one-way scope narrowing, why it's enforced at the circuit level
- [x] 2.5 Nonce binding — why replay attacks fail by design

## 3. The Architecture — How It Fits Together
- [x] 3.1 Circom circuits → Solidity verifiers → on-chain registry (the proving pipeline)
- [x] 3.2 Groth16 vs PLONK — why both, when each is used, trusted setup implications
- [x] 3.3 Semaphore v4 ceremony reuse — why HumanUniqueness doesn't need its own ceremony
- [x] 3.4 SDK surface area — createHumanIdentity, createAgentCredential, proveHandshake, verifyHandshake
- [x] 3.5 Python SDK as a thin shell — subprocess bridge, not reimplementation
- [x] 3.6 Integrations layer — MCP, LangChain, CrewAI, payment-protocols, OpenClaw (high-level purpose)

## 4. The Broader Context — Why This Matters
- [x] 4.1 How Bolyra relates to ZKProva and GeniusComply (same company, different customers)
- [x] 4.2 The IETF play — privacy companion spec to draft-klrc
- [x] 4.3 Patent strategy — provisional #64/043,898, non-provisional deadline
- [x] 4.4 What "Phase 1 — Proof of Enrollment" means and what comes next
