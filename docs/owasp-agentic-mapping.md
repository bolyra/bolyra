# Bolyra Protocol: OWASP Agentic Top 10 (2026) Security Mapping

**Version**: 1.0
**Date**: 2026-04-21
**Status**: Open-source security research artifact
**Protocol version**: Bolyra Phase 1 (Proof of Enrollment)
**OWASP reference**: [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

---

## Executive Summary

The OWASP Top 10 for Agentic Applications (2026) identifies ten critical security risks facing autonomous AI agent systems, from goal hijacking to rogue agent behavior. Bolyra's zero-knowledge proof protocol provides cryptographic mitigations for **6 of the 10 risks** at the identity and authorization layer, with full coverage on 3 risks and partial coverage on 3 others.

Bolyra's approach is distinctive because its mitigations are **mathematically enforced in-circuit** rather than implemented as runtime policy checks. Scope narrowing, delegation chain integrity, credential expiry, and sybil resistance are all guaranteed by ZKP soundness properties — an attacker cannot bypass them without breaking the underlying cryptographic assumptions (discrete log on Baby Jubjub, Poseidon collision resistance, Groth16/PLONK soundness).

The remaining 4 risks (ASI01 Goal Hijacking, ASI05 Code Execution, ASI06 Memory Poisoning, ASI09 Trust Exploitation) operate at the LLM reasoning and prompt-processing layer, which is outside the scope of an identity/authorization protocol. This is expected — Bolyra is a cryptographic identity primitive, not an LLM guardrail system. These risks require complementary solutions at the inference layer.

---

## Risk-by-Risk Analysis

### ASI01: Agent Goal Hijacking

**Risk description**: Attackers manipulate an agent's objectives, task selection, or decision pathways through prompt injection (direct or indirect), deceptive tool outputs, malicious artifacts, forged agent-to-agent messages, or poisoned external data. The agent pursues unintended or malicious objectives while appearing to function normally. Real-world example: EchoLeak (CVE-2025-32711, CVSS 9.3) demonstrated zero-click prompt injection in Microsoft 365 Copilot.

**Bolyra mitigation**: NOT ADDRESSED

**Coverage**: `NOT ADDRESSED`

**Analysis**: Goal hijacking operates at the LLM reasoning layer — it exploits how natural-language instructions are processed, not how identity or authorization is managed. Bolyra can constrain *what an agent is authorized to do* (via `AgentPolicy.circom` permission bitmasks and scope commitments), but it cannot prevent the agent's underlying LLM from being tricked into *wanting* to do something unauthorized. Even with Bolyra's scope enforcement, a goal-hijacked agent could still misuse its legitimately-granted permissions.

**Additional work needed**: Complement Bolyra with inference-layer guardrails (input/output classifiers, instruction hierarchy enforcement). Bolyra's permission bitmask acts as a hard ceiling on damage even when goal hijacking succeeds.

---

### ASI02: Tool Misuse and Exploitation

**Risk description**: Agents misuse legitimate tools (APIs, CLI, databases) in risky ways — often staying within granted permissions but performing destructive actions. This includes tool poisoning, tool shadowing, and manipulation through indirect prompt injection that causes agents to call tools with harmful parameters.

**Bolyra mitigation**: PARTIAL — scope-bounded authorization prevents unconstrained tool access.

**Coverage**: `PARTIAL`

**Relevant primitives**:
- **`AgentPolicy.circom`** — Permission bitmask with cumulative bit encoding enforces capability tiers. An agent with `FINANCIAL_SMALL` (bit 2) cannot prove it holds `FINANCIAL_UNLIMITED` (bit 4) because the ZKP soundness property S2.3 enforces `requiredScopeMask & ~permissionBitmask = 0`. Tool integrations can require specific scope masks before executing.
- **`Delegation.circom`** — Scope narrowing (S3.2: `delegateeScope ⊆ delegatorScope`) ensures sub-agents can only access a subset of the delegator's tools. Monotone attenuation across the full chain (CC3) prevents privilege accumulation.
- **`IdentityRegistry.sol`** — Atomic handshake verification binds tool authorization to a verified identity in a single transaction.
- **SDK**: `permissionsToBitmask()` and `validateCumulativeBitEncoding()` enforce correct permission encoding client-side.

**What is not covered**: Bolyra constrains *which categories* of tools an agent can access, but does not inspect *how* the agent uses a specific tool (e.g., SQL injection through a legitimately-accessed database). Parameter-level validation remains an application-layer concern.

---

### ASI03: Agent Identity and Privilege Abuse

**Risk description**: Attackers exploit inherited or cached credentials, delegated permissions, over-provisioned access, or agent-to-agent trust to perform unauthorized actions. A single agent effectively merges multiple permissions into one execution point, creating a dynamic identity surface. Risks include credential theft, privilege escalation through delegation, and confused deputy attacks.

**Bolyra mitigation**: FULL — this is Bolyra's core design target.

**Coverage**: `FULL`

**Relevant primitives**:
- **`HumanUniqueness.circom`** — Establishes sybil-resistant human identity via Semaphore v4 nullifiers. Property S1.2 guarantees nullifier determinism: `nullifierHash = Poseidon(scope, secret)`. One human, one identity per scope.
- **`AgentPolicy.circom`** — Agent credentials are operator-signed (S2.1: EdDSA verification over credential commitment), enrolled in a separate Merkle tree (S2.2), and time-bounded (S2.4: `currentTimestamp < expiryTimestamp`). Privilege is explicitly encoded in a 64-bit bitmask with cumulative hierarchy enforcement (S2.7).
- **`Delegation.circom`** — Delegation chains (max 3 hops, enforced on-chain) with monotone scope attenuation (S3.2) and expiry narrowing (S3.3). Delegatees cannot escalate privileges. Chain integrity is cryptographically guaranteed: `P(delegatorScope, delegatorCredCommitment) = previousScopeCommitment` (S3.1). The UC3.1 fix binds the delegator's signing key to their credential commitment, preventing key substitution attacks.
- **`IdentityRegistry.sol`** — Dual LeanIMT trees (humanTree + agentTree) maintain separate identity registries. Delegation nullifier replay protection prevents credential reuse. Hop count enforcement (max 3) limits delegation chain depth on-chain.
- **SDK**: `createAgentCredential()` binds model hash, operator key, permissions, and expiry into a single commitment. `proveHandshake()` produces mutual ZKPs — both human and agent prove identity simultaneously.

**Why ZKP matters here**: Unlike centralized credential stores, Bolyra credentials cannot be "stolen" in the traditional sense. The secret scalar never leaves the proving device. An attacker who compromises a server does not obtain reusable credentials — only ZKP artifacts that are bound to specific scopes and sessions via nullifiers and nonce bindings.

---

### ASI04: Agentic Supply Chain Compromise

**Risk description**: Malicious or compromised models, tools, plugins, MCP servers, or prompt templates introduce hidden instructions and backdoors at runtime. Unlike traditional supply chain risks (pre-deployment), agentic supply chain attacks occur during dynamic runtime composition — agents discover and integrate components during execution. Includes rug pulls, typosquatting, and hallucinated dependency installation.

**Bolyra mitigation**: PARTIAL — model binding and operator attestation provide provenance verification.

**Coverage**: `PARTIAL`

**Relevant primitives**:
- **`AgentPolicy.circom`** — The credential commitment includes `modelHash` as a first-class component: `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)`. A verifier can require that the agent's credential was issued for a specific model hash, preventing model substitution attacks. Property P2.1 (model hiding) means the model identity is private to the prover but committed to cryptographically.
- **`IdentityRegistry.sol`** — Enrollment in the agent Merkle tree is a gatekeeping function. Only operator-enrolled agents are verifiable. This creates a supply chain checkpoint: agents must be registered before they can participate.
- **SDK**: `createAgentCredential(modelHash, operatorKey, permissions, expiry)` requires explicit model hash binding at credential creation time.

**What is not covered**: Bolyra verifies that an agent's credential was issued for a specific model by a specific operator, but does not inspect the model itself for backdoors or verify plugin/tool integrity at runtime. MCP server compromise and dependency poisoning are outside scope. A compromised operator could issue valid credentials for a malicious model.

---

### ASI05: Unexpected Code Execution

**Risk description**: Agents generate, modify, or execute code or commands that create security or operational risk. Natural-language execution paths unlock dangerous new avenues for remote code execution, including sandbox escapes and unsanctioned package installs.

**Bolyra mitigation**: NOT ADDRESSED

**Coverage**: `NOT ADDRESSED`

**Analysis**: Code execution risks occur at the agent runtime and sandbox layer, which is entirely outside the scope of a cryptographic identity protocol. Bolyra does not inspect, generate, or constrain code execution. However, Bolyra's permission bitmask (specifically the `WRITE_DATA` and `SIGN_ON_BEHALF` bits in the `Permission` enum) can serve as a prerequisite gate — an agent without `WRITE_DATA` permission could be denied access to code execution environments.

**Additional work needed**: Combine Bolyra scope verification with sandboxed execution environments. A `langchain-bolyra-tool` or `crewai-bolyra-tool` integration (currently stubs) could enforce scope checks before tool invocation.

---

### ASI06: Memory and Context Poisoning

**Risk description**: Retrieved or stored context (memory, embeddings, RAG stores) is poisoned, stale, or tampered with, influencing future agent behavior. Memory poisoning corrupts an agent's long-term memory, causing consistently flawed decisions over time.

**Bolyra mitigation**: NOT ADDRESSED

**Coverage**: `NOT ADDRESSED`

**Analysis**: Memory and context poisoning targets the data layer feeding into LLM reasoning. Bolyra's Merkle trees store identity commitments, not agent memory or context. The protocol has no mechanism to verify the integrity of RAG stores, embedding databases, or conversation history.

**Additional work needed**: A potential extension would use Bolyra's commitment scheme to create verifiable memory stores — Poseidon-hashed context entries in a Merkle tree with inclusion proofs — but this is speculative and not part of the current protocol.

---

### ASI07: Insecure Inter-Agent Communication

**Risk description**: Agents exchange messages without sufficient authentication, integrity, or policy controls. Spoofed inter-agent messages can misdirect entire clusters. Includes man-in-the-middle attacks on agent-to-agent channels, impersonation of trusted agents, and unauthorized message injection.

**Bolyra mitigation**: FULL — mutual ZKP authentication with scope-bound delegation chains.

**Coverage**: `FULL`

**Relevant primitives**:
- **`proveHandshake(human, agent, options)`** — The mutual handshake protocol requires both parties to generate ZKPs simultaneously. The shared `sessionNonce` (property S1.3: `nonceBinding = Poseidon(nullifierHash, sessionNonce)`) binds both proofs to the same session, preventing relay attacks.
- **`Delegation.circom`** — Inter-agent delegation is cryptographically authenticated: the delegator must produce an EdDSA signature over `Poseidon(previousScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` (S3.4). The delegatee must prove enrollment via Merkle inclusion (S3.5, CIP-1). A spoofed agent cannot produce a valid delegation proof.
- **`IdentityRegistry.sol`** — Nonce equality enforcement ensures both parties in a handshake use the same session nonce. On-chain verification of Groth16 + PLONK proofs in a single atomic transaction prevents partial verification attacks.
- **Scope commitment chaining** (CC1, CC2): `AgentPolicy.scopeCommitment` flows into `Delegation.previousScopeCommitment`, creating a cryptographically-linked chain. Each hop's output is the next hop's input. An attacker cannot insert a fabricated hop.

**Why ZKP matters here**: In centralized systems, inter-agent authentication depends on a trusted authority (IdP, message broker). If that authority is compromised, all inter-agent trust collapses. Bolyra's proofs are self-verifiable — any party can verify a ZKP without contacting a central server. There is no single point of compromise for inter-agent authentication.

---

### ASI08: Cascading Agent Failures

**Risk description**: A single error, compromise, or bad decision propagates across connected agents, tools, and workflows into system-wide impact. Symptoms include rapid fan-out, cross-domain spread, oscillating retries, and downstream queue storms.

**Bolyra mitigation**: PARTIAL — scope attenuation and delegation depth limits bound the blast radius.

**Coverage**: `PARTIAL`

**Relevant primitives**:
- **`Delegation.circom`** — Monotone scope attenuation (CC3: `finalScope ⊆ ... ⊆ scope_1 ⊆ originalScope`) ensures each hop in a delegation chain has *equal or fewer* permissions than its parent. A compromised sub-agent cannot escalate to affect resources beyond its attenuated scope.
- **`IdentityRegistry.sol`** — Hop count enforcement (max 3 hops) places a hard upper bound on delegation chain depth. A cascade cannot propagate beyond 3 levels of delegation.
- **Expiry narrowing** (CC4: `delegateeExpiry_k ≤ ... ≤ originalExpiry`) ensures deeper delegation hops have shorter lifetimes, automatically limiting the temporal window for cascading failures.
- **Delegation nullifier replay protection** prevents a single compromised delegation token from being reused across sessions.

**What is not covered**: Bolyra limits the *authorization scope* of cascading failures but does not prevent cascades at the operational layer (retry storms, fan-out of valid-but-wrong decisions, resource exhaustion). Circuit breaker patterns, rate limiting, and orchestration-level safeguards remain necessary.

---

### ASI09: Human-Agent Trust Exploitation

**Risk description**: Agents use persuasive or misleading outputs (confident explanations, authority bias, social engineering) to influence human operators into approving unsafe actions or divulging sensitive information.

**Bolyra mitigation**: NOT ADDRESSED

**Coverage**: `NOT ADDRESSED`

**Analysis**: Trust exploitation is a UX and cognitive security problem that operates at the human-AI interaction layer. Bolyra authenticates *who* is interacting but does not evaluate *what* an agent says to a human or whether the human's approval was informed. The `Permission.SIGN_ON_BEHALF` bit (bit 5) could serve as an indicator that an agent has authority to act without human approval, but this does not prevent the agent from manipulating the approval process itself.

**Additional work needed**: Bolyra's handshake result (`HandshakeResult.verified`) provides cryptographic proof that the agent is who it claims to be, which mitigates impersonation-based trust exploitation. Full mitigation requires UI-layer transparency controls showing the agent's verified permission scope to the human approver.

---

### ASI10: Rogue Agents

**Risk description**: Agents drift or are actively compromised in ways that cause harmful behavior beyond their intended scope. This includes misalignment, concealment of actions, and self-directed behavior. Rogue agents may be difficult to detect because they can appear to function normally while pursuing unauthorized objectives.

**Bolyra mitigation**: FULL — cryptographic scope enforcement makes unauthorized actions provably detectable.

**Coverage**: `FULL`

**Relevant primitives**:
- **`AgentPolicy.circom`** — An agent's permission bitmask is cryptographically committed at credential issuance time (S2.1). The agent cannot prove it holds permissions beyond what the operator signed. A rogue agent attempting to exceed its scope will fail the ZKP verification (S2.3: `requiredScopeMask & ~permissionBitmask = 0`).
- **`AgentPolicy.circom` expiry enforcement** (S2.4) — Credentials have hard expiry. A rogue agent cannot continue operating after its credential expires without obtaining a new operator-signed credential.
- **`Delegation.circom` scope narrowing** (S3.2) — A rogue sub-agent cannot escalate beyond its delegated scope. The bitwise subset constraint is enforced in-circuit.
- **`IdentityRegistry.sol`** — Root history buffers (30 entries) combined with Merkle tree removal provide a revocation mechanism. An operator who detects rogue behavior can remove the agent's credential commitment from the tree, invalidating all future proofs.
- **Nullifiers** — Per-scope nullifiers (`HumanUniqueness.circom`) and per-session nullifiers (`AgentPolicy.circom`) create an audit trail. A rogue agent's actions are linked to its credential commitment within a scope, enabling post-hoc detection.

**Why ZKP matters here**: Centralized authorization systems can be bypassed if the policy engine is compromised. Bolyra's constraints are embedded in arithmetic circuits — a rogue agent cannot "convince" the verifier to accept a proof for permissions it does not hold. The soundness property of the proving system (Groth16/PLONK) provides a mathematical guarantee, not a software policy check.

---

## Coverage Summary

| Risk ID | Risk Name | Coverage | Key Bolyra Primitive |
|---------|-----------|----------|---------------------|
| ASI01 | Agent Goal Hijacking | NOT ADDRESSED | — (LLM reasoning layer) |
| ASI02 | Tool Misuse & Exploitation | PARTIAL | `AgentPolicy.circom` permission bitmask, `Delegation.circom` scope narrowing |
| ASI03 | Identity & Privilege Abuse | FULL | All three circuits + `IdentityRegistry.sol` + SDK handshake |
| ASI04 | Supply Chain Compromise | PARTIAL | `AgentPolicy.circom` modelHash binding, operator-signed credentials |
| ASI05 | Unexpected Code Execution | NOT ADDRESSED | — (runtime sandbox layer) |
| ASI06 | Memory & Context Poisoning | NOT ADDRESSED | — (data/RAG layer) |
| ASI07 | Insecure Inter-Agent Comms | FULL | `proveHandshake()`, delegation chain linking, nonce binding |
| ASI08 | Cascading Agent Failures | PARTIAL | Delegation depth limit (3 hops), scope/expiry attenuation |
| ASI09 | Human-Agent Trust Exploitation | NOT ADDRESSED | — (UX/cognitive layer) |
| ASI10 | Rogue Agents | FULL | Permission bitmask, expiry enforcement, Merkle revocation, nullifier audit trail |

**Summary**: 3 FULL, 3 PARTIAL, 4 NOT ADDRESSED

---

## Comparison: Centralized Approaches vs. Bolyra's ZKP Approach

| Risk | Microsoft Entra Agent ID | WorkOS FGA | Bolyra (ZKP) |
|------|-------------------------|------------|---------------|
| **ASI01** Goal Hijacking | Runtime guardrails via Agent Governance Toolkit; policy enforcement at inference layer | Not addressed (authorization layer only) | Not addressed (identity layer only) |
| **ASI02** Tool Misuse | Role-based access control; Copilot Studio connector permissions | Fine-grained authorization on resource subtrees; relationship-based access control (ReBAC) | Permission bitmask with cumulative encoding; scope narrowing in delegation — enforcement is in-circuit, not policy-engine dependent |
| **ASI03** Identity & Privilege | First-class agent identity type in Entra; OAuth 2.0 token issuance; centralized lifecycle management | IdP group-to-FGA role mapping; authorization checks on every resource access | ZKP-based: no credential server to compromise; secret never leaves proving device; sybil-resistant nullifiers; formally-verified scope attenuation |
| **ASI04** Supply Chain | Azure-managed trust chain; signed tool manifests | Not directly addressed | modelHash commitment in credential; operator-signed attestation — but no runtime plugin verification |
| **ASI05** Code Execution | Agent Governance Toolkit sandboxing; execution policy enforcement | Not addressed | Not addressed |
| **ASI06** Memory Poisoning | Content Safety integration; grounding detection | Not addressed | Not addressed |
| **ASI07** Inter-Agent Comms | Entra-issued tokens for agent-to-agent auth; centralized trust broker | Not directly addressed (authorization, not inter-agent auth) | Mutual ZKP handshake; self-verifiable proofs without central authority; scope commitment chaining across delegation hops |
| **ASI08** Cascading Failures | Agent Governance Toolkit circuit breakers; orchestration-level controls | Not addressed | Hard delegation depth limit (3 hops); monotone scope/expiry attenuation bounds blast radius |
| **ASI09** Trust Exploitation | Copilot Studio transparency features; human-in-the-loop controls | Not addressed | Not addressed |
| **ASI10** Rogue Agents | Continuous monitoring via Entra Permissions Management; token revocation | Authorization checks prevent scope creep if policy engine is intact | Mathematical guarantee: rogue agent cannot prove permissions it does not hold; credential expiry + Merkle revocation |

### Key Architectural Differences

**Centralized approaches** (Entra, WorkOS) provide comprehensive coverage through runtime policy enforcement, but their security depends on the integrity of the policy engine and token infrastructure. If the IdP, policy engine, or token store is compromised, all downstream authorization decisions are affected.

**Bolyra's ZKP approach** provides narrower but mathematically-guaranteed coverage. The security properties are embedded in arithmetic circuits and hold regardless of infrastructure compromise. However, Bolyra does not address risks at the LLM reasoning layer (ASI01, ASI06, ASI09) or runtime execution layer (ASI05) because these are outside the scope of identity and authorization.

**Complementary deployment**: The strongest posture combines both approaches — Bolyra for cryptographic identity and authorization guarantees, centralized tooling for runtime monitoring, guardrails, and the LLM-layer risks that ZKPs cannot address.

---

## References

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-identities)
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [WorkOS FGA: Authorization for AI Agents](https://workos.com/blog/agents-need-authorization-not-just-authentication)
- [Palo Alto Networks: OWASP Agentic AI Security](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)
- Bolyra formal properties: `circuits/FORMAL-PROPERTIES.md`
- Bolyra primitives: `discovery-autoresearch/primitives.json`
- Bolyra SDK types: `sdk/src/types.ts`
- IETF internet-draft: `draft-bolyra-mutual-zkp-auth-01`
