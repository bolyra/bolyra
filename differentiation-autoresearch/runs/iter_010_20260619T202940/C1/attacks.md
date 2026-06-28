# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Constant-Time Discipline Is a Latency Floor, Not a Feature

- **Attack:** Section 2 (Agent-side response discipline) explicitly states: "If proving succeeds before `T_prove`, the agent pads with a `sleep(T_prove - elapsed)`." This means every legitimate scope check takes at least `T_prove = 500ms` (rapidsnark) or `T_prove = 3s` (snarkjs) — not as a worst case, but as the *guaranteed minimum*. The construction converts proving speed into a floor to enforce constant-time discipline. WorkOS and Auth0 issue tokens in <100ms. An MCP agent making 20 resource-access calls per user turn adds 10 seconds of pure auth latency (rapidsnark) or 60 seconds (snarkjs) — before the actual work starts. No enterprise operator accepts a 10-60x latency regression on their agentic product's hot path.

- **Why it works / why it fails against the construction:** The construction defends the constant-time budget only against the bit-extraction threat in the `mqSE-IND` game (Section 3). It does not address operator SLAs or the compounding effect of per-call proving in multi-step agentic workflows. The latency floor is a deliberate design choice — and it's the right choice *for security* — but the construction never argues why operators should accept it. Section 6's "< 500 ms" target is the proving time before padding, not after. There is no mitigation offered for high-frequency access patterns.

- **In-threat-model?** No — construction must address. Mitigation candidate: credential caching (prove once, present token for N minutes), but this reintroduces the AS-like pattern the construction claims to eliminate. A concrete deployment answer is required.

---

### Attack 2: Revocation Is Now On-Chain and Slower Than a Phone Call

- **Attack:** The construction's "adversarial-AS resilience" eliminates the AS from the verification path — but revocation requires modifying the on-chain Merkle tree. When Columbia CU needs to revoke a compromised agent *immediately* (think: credential exfiltration, a rogue model deployment, a fired operator), the flow is: (1) submit an on-chain transaction to remove the credential commitment, (2) wait for block confirmation on Base L2 (~2 seconds for inclusion, 7 days for full L1 finality under the Optimistic rollup model), (3) wait for the RS's cached `onChainAgentRoot` to expire. The 30-entry root history buffer in `contracts/BolyraRegistry` explicitly allows proofs against any of the 30 most recent roots — meaning a revoked credential remains valid against stale RS caches for however long those 30 roots span. RFC 7662 introspection revokes access in under 100ms — the AS simply returns `{"active": false}` on the next introspection call. The construction's Section 7 scenario mentions a "CrowdStrike-style AS outage" as an argument for AS-blind verification, but never addresses the opposite scenario: an operator-side incident requiring instant revocation. That scenario is far more common.

- **Why it works / why it fails against the construction:** The construction never mentions revocation. Section 4 (adversarial-AS resilience) argues the AS cannot inflate or suppress permissions — correct — but says nothing about the operator's ability to revoke enrolled credentials faster than block time. The 30-entry root history buffer is presented without a time-to-expiry bound. If the RS caches roots for 10 minutes and there are 30 roots, a revoked credential may remain valid for hours.

- **In-threat-model?** No — construction must address. This is likely the first question from any CISO reviewing the spec. A concrete answer (e.g., emergency revocation via root history buffer flush, maximum cache TTL enforcement at the RS) is required before enterprise adoption.

---

### Attack 3: Enrollment Is a Blockchain Transaction, Not a POST Request

- **Attack:** Section 7 describes the deployment as: "Columbia CU enrolls the agent's credential commitment (`Poseidon5(modelHash, opAx, opAy, 0b10010111, expiry)`) into the on-chain Bolyra agent Merkle tree." This single sentence hides the actual operator workflow: generate an EdDSA Baby Jubjub keypair, hash the model identifier (what exactly? a model version string? a binary hash? — the construction doesn't specify how `modelHash` is computed in practice), compute the Poseidon5 commitment, submit a gas-bearing on-chain transaction, wait for inclusion, distribute the PLONK circuit artifacts (`pot16.ptau`, `.zkey`, `.vkey`) to the agent runtime, configure the SDK. Compare this to Auth0's DCR (RFC 7591): `POST /oidc/register` with a JSON body, receive `client_id` and `client_secret`. Stytch's MCP auth is a browser-based OAuth flow. Cloudflare Access is a DNS CNAME change. The construction's onboarding requires running a ZK toolchain, holding crypto (gas), and understanding Merkle tree membership — all before a single API call is authenticated. The CLAUDE.md itself notes that verification must prove the onboarding is not worse than paste-an-API-key. This fails that test by a wide margin.

- **Why it works / why it fails against the construction:** The construction is silent on the operator enrollment UX. Section 7 presents the deployment scenario from the RS's perspective (proving is seamless) but not the operator's perspective (enrollment requires blockchain access). The security argument in Section 4 is rigorous, but it assumes enrollment has already happened. The path from "I have an AI agent" to "my agent can make its first verified API call" is the product, and it is not described.

- **In-threat-model?** No — construction must address. A comparison of time-to-first-verified-call (Bolyra vs. Auth0/WorkOS) is a required addition to the deployment scenario.

---

### Attack 4: The Five-Property Uniqueness Claim Answers Cryptographers, Not Buyers

- **Attack:** Section 8 organizes the construction's differentiation around six properties: adversarial-AS soundness, ZK predicate evaluation, AS-blind presentation, constant-size proof, model identity binding, and SE-NIZK. Every one of these properties is a cryptographic or systems property. None of them map to a line item in a credit union's vendor evaluation checklist. NCUA Letter 24-CU-03 (cited in Section 7) focuses on vendor concentration risk, incident response SLAs, and third-party due diligence — it does not require "cryptographic binding to the agent's runtime model identity." A procurement officer at a 12-CU consortium will ask: Does the vendor have SOC 2 Type II? What's the uptime SLA? Who do we call at 2am during an incident? Who owns liability if a proof verification bug allows unauthorized access? The construction's threat model explicitly includes a "solo founder" adversary question (in the attack_prompts) but never addresses it. A solo-founder ZK protocol with no SOC 2, no incident response team, no liability coverage, and no enterprise support contract will not survive a single round of FFIEC-mandated third-party vendor due diligence — regardless of how elegant the R1CS constraints are.

- **Why it works / why it fails against the construction:** The construction is technically sound but GTM-incomplete. The differentiation argument (Section 8) is written for a peer-reviewed workshop, not for a VP of Engineering at a credit union technology consortium. The concrete deployment scenario in Section 7 describes cryptographic properties the RS learns — but the RS's CISO doesn't care about simulation-extractable zero-knowledge. They care about: can we audit this, can we turn it off, who do we call when it breaks, and what is the vendor's financial viability. These are not addressed anywhere in the construction.

- **In-threat-model?** No — construction must address. A buyer-level argument section is required: specifically, how a CISO at a regulated institution justifies adopting a solo-founder protocol over WorkOS (SOC 2, 24/7 support, existing IdP integrations) or Cloudflare Access (incumbent infrastructure, zero new vendor risk). The cryptographic uniqueness is real but insufficient as a standalone GTM argument.


## Persona: cryptographer

Applied cryptographer. I've reviewed constructions like this for CRYPTO/EUROCRYPT. The circuit gadgets are competently assembled. The formal claims, however, have four structural problems. I'll work through each with a concrete break or gap.

---

### Attack 1: Subverted Trusted Setup — The Construction's Actual Trust Root

**Attack:** The adversary participates in (or obtains the toxic waste τ from) the `pot16.ptau` powers-of-tau ceremony. With τ known, the adversary constructs a PLONK proof for a circuit relation that is **not satisfied** — specifically, they forge a valid `SelectiveScopeProof` where `permissionBitmask & requiredScopeMask ≠ requiredScopeMask` (G5 constraint violated in the witness, but the proof verifies under the subverted SRS).

**Why it works:** PLONK knowledge soundness holds in the Algebraic Group Model + ROM. Under AGM, the extractor uses the fact that adversary group elements are algebraic combinations of the SRS elements. If the adversary **knows τ**, they're not algebraically constrained — they can construct the Kate polynomial commitment openings for any claimed evaluation, including ones corresponding to an unsatisfied circuit. The toxic waste τ breaks the AGM assumption at its root.

**Construction's handling:** Section 3 game definition step 1: *"Run trusted setup for SelectiveScopeProof circuit → (pk, vk)"* — this is a single black-box line. The threat model enumerates what the adversary controls: the AS, the network, N-1 agents. It does **not** model the setup as adversarial. Section 4 names knowledge soundness of PLONK as Assumption 1, but the assumption's precondition (honest SRS generation) is never justified. The construction asserts "No new cryptographic building blocks" but the `pot16.ptau` ceremony is not described — who ran it, how many participants, what transcript verification was performed.

**Compounding issue:** The construction specifically claims *adversarial-AS resilience* as a differentiator. But the AS (or any party who participated in the SRS ceremony) remains a trust anchor. A colluding AS + ceremony participant defeats the entire adversarial-AS threat model. This is not a corner case — it's the exact scenario the construction's Section 7 "concrete deployment" uses (consortium of credit unions with an adversarial Columbia CU AS).

**In-threat-model?** **No — construction must address.** Either (a) describe the ceremony, prove it was multi-party with sufficient honest participants, and bound the subversion probability; or (b) prove the construction is secure under *subverted SRS* (which PLONK is not, without additional structure like updatable SRS with transparent setup). The adversarial-AS claim is undermined if the AS could have participated in the SRS ceremony.

---

### Attack 2: mqSE-IND Game is Vacuous After 64 Chosen-Predicate Queries

**Attack:** The adversary A uses Phase 1 to query all 64 single-bit predicates: `requiredScopeMask ∈ {0x01, 0x02, 0x04, ..., 0x80_00_00_00_00_00_00_00}`. For each query, A observes a binary outcome: proof returned (bit set in `permissionBitmask`) or `{"error": "scope_insufficient"}` (bit not set). After 64 queries, A has fully reconstructed `permissionBitmask = B*`.

**Why the construction's response fails:** Section 2 argues:

> "A 64-query sweep where each query sets a single bit yields at most 64 binary outcomes — but these match exactly the outcomes the adversary would see if the agent had ANY subset of permissions."

This is false as stated. 64 binary outcomes over 64 single-bit predicates uniquely determine a 64-bit string. The adversary has extracted `B*` exactly.

**Why the game definition doesn't capture this:** The mqSE-IND game (Section 3) requires at step 4: *"A chooses two bitmasks B0, B1 such that for every predicate R queried in Phase 1, B0 satisfies R iff B1 satisfies R."* After 64 single-bit queries, A is forced to choose B0, B1 that agree on all 64 bits — meaning B0 = B1 = B*. The challenge phase produces identical transcripts for both. A cannot win above 1/2. The game records this as "A failed to distinguish" — **but A has already extracted the full bitmask**.

**The definitional gap:** The mqSE-IND game measures indistinguishability between two pre-committed bitmasks after Phase 1 constraints are applied. Full bitmask extraction via Phase 1 queries is not a "winning condition" under this definition — it just collapses the challenge to a coin flip. The relevant privacy property ("the adversary learns only the boolean satisfaction outcome for each queried predicate, and nothing else about `permissionBitmask`") is not the same property the game proves. The game proves something weaker: "you can't distinguish transcripts for two bitmasks that agree on all queried predicates."

**Concrete impact on the credit union scenario:** The malicious partner CU uses 64 sequential queries to reconstruct Columbia CU's full bitmask. Constant-time discipline prevents timing leakage but does **not** prevent information-theoretic leakage via the binary proof/error response. The 64-query attack is precisely the "bit extraction via chosen predicates" scenario described in Section 7, and the construction's only defense is constant-time budgeting — which addresses *timing* not *content*.

**What a correct game would say:** The winning condition should be: *A outputs a bit b' and wins if b' = b AND b' could not have been determined from the binary outcomes of Phase 1 queries.* Or alternatively, define the privacy property directly as: *"for any two bitmasks B0, B1 consistent with all Phase 1 query outcomes, the joint distribution of (Phase 1 proofs, challenge transcripts) is computationally indistinguishable."* The current formulation is necessary but not sufficient for the claimed "scope privacy."

**In-threat-model?** **No — construction must address.** The game definition does not capture full bitmask extraction as an attack. Section 3 must either (a) explicitly acknowledge that chosen-predicate queries leak one bit per query (fine — this is information-theoretically unavoidable and the correct design), and update the privacy claim accordingly, or (b) define a game where full bitmask extraction is a winning condition and prove it is hard (which it isn't — it's trivially achievable in 64 queries). The gap is definitional, not in the circuit.

---

### Attack 3: Blinded Nullifier Renders Rate-Limiting Incoherent

**Attack:** The adversary (or honest agent) makes N sequential requests to the same RS, each time generating a fresh `blindingNonce ← Rnd`. Each presentation produces a fresh `agentNullifier = Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)`. The RS records each nullifier. None repeat. The RS cannot correlate any two presentations to the same agent. The adversary bypasses rate-limiting by generating fresh proofs without bound.

**Why it works against the stated design:** Section 2, G9 description: *"agentNullifier ... blinded per presentation, enables rate-limiting without cross-session linkage."* These two properties are in direct tension:

- **Rate-limiting** requires the RS to correlate N requests from the same agent across sessions, so it can count and enforce a budget.
- **No cross-session linkage** means no two nullifiers reveal they came from the same credential.

A nullifier that is `Poseidon3(C*, R, r)` with fresh uniform `r` is identically distributed to a uniform random field element (given Poseidon PRF security). The RS receives a stream of independent uniform values — it cannot enforce "agent A has made k requests this hour" because it cannot identify which nullifiers belong to agent A.

The nullifier achieves only **proof-level replay prevention** (the RS rejects a re-presented *identical* proof `pi` with the same nullifier) — not rate-limiting in any meaningful sense. An adversary generating a fresh proof (new `blindingNonce`) per request faces zero rate-limiting enforcement from the nullifier mechanism.

**What would actually work:** A rate-limiting nullifier for a temporal window requires something like `Poseidon3(credentialCommitment, requiredScopeMask, epoch)` where `epoch = floor(currentTimestamp / windowSize)` — linkable within a window but unlinkable across windows. This is a deliberate design choice with a concrete privacy/rate-limiting tradeoff that the construction neither makes nor acknowledges.

**In-threat-model?** **No — construction must address.** The rate-limiting claim in Section 2 is incorrect as implemented. Either the nullifier scheme must be redesigned to provide the stated property, or the claim must be downgraded to "proof-level replay prevention." This is not a circuit flaw — it's a protocol-layer design inconsistency.

---

### Attack 4: Root History Buffer Creates an Unmodeled Revocation Window

**Attack:** Agent A holds a credential commitment `C* = Poseidon5(modelHash, opAx, opAy, 0xFF, expiry)` (all permissions). The operator decides to revoke A's access — removes `C*` from the Merkle tree, producing a new root `R_{t+1}` that does not contain `C*`. The on-chain registry updates its 30-entry root history buffer. For the next 30 root updates (which may span hours or days depending on enrollment activity), the buffer still contains root `R_t` (the pre-revocation root). Agent A generates a `SelectiveScopeProof` with `onChainAgentRoot = R_t` as a public input. The RS verifies this against its root history buffer — `R_t` is present, proof verifies. Revocation is ineffective for the duration of the buffer window.

**Construction's handling:** Section 2 verification step 1: *"RS reads onChainAgentRoot from the Bolyra on-chain registry (cached, no AS contact)"* — the 30-entry buffer is mentioned in Section 5 (`contracts/` description) but no revocation game is defined. Section 3's adversarial-AS model states: *"It cannot suppress an agent's permissions (the agent holds its own secret inputs and generates the proof autonomously)."* This framing treats AS-side suppression as an attack. But **operator-side revocation** is the same mechanism, and the buffer makes it ineffective for a window. There is no revocation sub-game in Section 3.

**Why this matters formally:** The `SelectiveScopeForgery` game (Section 3) defines the honest agent's `permissionBitmask` as fixed. The game doesn't model the case where the credential has been legitimately revoked and the operator expects the agent to lose access. This is a gap in the threat model — not a game the adversary breaks, but a property the deployment scenario requires (Columbia CU revoking a compromised agent's access) that the formal model doesn't address.

**Concrete bound missing:** How long is the revocation window? It depends on how frequently the Merkle tree is updated. If new enrollments happen once per week, the 30-entry buffer represents 30 weeks of revocation lag. The construction provides no bound on this window and no protocol for operators to force immediate revocation (e.g., by advancing the root faster or by nullifying the credential commitment separately).

**In-threat-model?** **No — construction must address.** Define a revocation game, bound the revocation window explicitly, and either (a) reduce buffer size with a documented tradeoff, (b) add an emergency revocation mechanism that pushes a new root immediately (with proof of operator authorization), or (c) explicitly scope the construction to non-revocable credentials and document this as a limitation. The current text implies revocation is possible (Section 3: "enrolled on-chain") but provides no mechanism or bound.


## Persona: cu_ciso

---

### Attack 1: The Examiner Can't Read a Poseidon Hash — NCUA Part 748 Appendix A §I.B

- **Attack:** I pull up the NCUA Part 748 Appendix A security program checklist. Section I.B requires the institution to maintain "audit trails designed to detect and respond to security incidents." My examiner asks me to produce the audit trail for Agent X's access to member loan files on March 14. I hand them `agentNullifier = 0x1a4f...c83b` and `scopePredicateHash = 0x9d2e...77f1`. These are Poseidon field elements over BN254. The examiner closes their laptop and marks a finding. The construction (Section 2, G8/G9) explicitly makes the nullifier and predicate hash *blinded per presentation* and unlinkable across sessions by design. That's the ZK privacy property. It also means I cannot reconstruct who accessed what, when, under what permission context, from a human-readable log. "Cryptographically proven minimum-necessary permissions" (Section 7) is not an audit trail — it is a mathematical fact inaccessible to my compliance team, my internal auditor, and my NCUA examiner.

- **Why it works / why it fails against the construction:** The construction's privacy guarantees are the attack surface. The blinding nonce (private input) randomizes each transcript so proofs are unlinkable. This is a *feature* for ZK unlinkability and a *failure* for NCUA audit defensibility. The construction does not address how an institution reconstructs a human-readable access log. The Section 7 regulatory alignment claim cites Letter 24-CU-03 but does not describe what artifact an examiner actually inspects.

- **In-threat-model?** No. The threat model (Section 3) defines adversaries as cryptographic attackers. NCUA examiners are not in the threat model. The construction must address this or the "regulatory alignment" claim in Section 7 is marketing, not defensibility. Minimum fix: the agent SDK must maintain a plaintext local audit log (timestamp, RS identifier, `requiredScopeMask` in human-readable form, proof accept/reject, agent identifier) stored separately from the ZK layer, with retention policy meeting NCUA Part 748 and GLBA requirements. This log lives outside the proof — it is the institution's operational record. The ZK proof is not a substitute for it.

---

### Attack 2: The On-Chain Registry Is an Unvetted Fourth Party — NCUA Part 748 Appendix B, GLBA §501(b)

- **Attack:** I open my Vendor Management Policy (required under GLBA Safeguards Rule 16 CFR §314.4(f) and NCUA Part 748 Appendix B). The RS verification path (Section 2, Verification Protocol step 1) reads `onChainAgentRoot` from the Bolyra on-chain registry — a smart contract on Base (an L2 Ethereum chain). I need the following from Bolyra before my board approves this: SOC 2 Type II report, SSAE 18 / AT-C 320 attestation, SLA with financial penalty for downtime, incident notification timelines, and a business continuity plan. None of these exist for a blockchain registry. Base L2 has experienced sequencer outages. The 30-entry root history buffer (Section 5) means credentials enrolled more than 30 root updates ago are unverifiable — what is the rotation frequency? If the registry updates every block (~2 seconds on Base), my credential history window is 60 seconds. If agents are offline for longer than the buffer window, they cannot be re-verified without re-enrollment. The SLA for my core processor (FiServ/Jack Henry) is 99.9% with contractual recourse. What is the SLA for the Bolyra registry? 

- **Why it works / why it fails against the construction:** The construction explicitly positions the on-chain registry as the alternative to AS trust. Section 8 states: "trust = on-chain root + proof soundness." This makes the chain the trust root. Blockchain nodes are not GLBA-covered entities, do not sign BAAs, and have no regulatory accountability. The construction does not address vendor management, chain availability SLAs, or what the RS does when the chain is unreachable (sequencer outage, RPC provider failure, network partition). Caching `onChainAgentRoot` locally (step 1) defers the problem — stale roots accept revoked credentials.

- **In-threat-model?** No. The threat model assumes "on-chain registry (Ethereum/Base L2 consensus assumptions)" as a given (Section 3, "The adversary does NOT control"). My vendor management examination does not accept "consensus assumptions" as a third-party risk control. The construction must define: root cache TTL with security justification, fallback behavior on registry unavailability, the buffer window in calendar time not block count, and what contractual instrument governs the registry's availability obligations.

---

### Attack 3: Operator Key Compromise Is a Systemic Meltdown With No NCUA-Reportable Revocation Path — NCUA Part 748 §748.1(b), GLBA §314.4(c)

- **Attack:** The credential commitment is `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` signed by the operator's Baby Jubjub private key (Section 2, G3). Every agent credential issued by Columbia CU's operator is cryptographically bound to that one key pair. I ask: where does the operator private key live? The construction is silent. If the answer is "an HSM" — which HSM, with what FIPS 140-2 Level certification, managed by whom, with what key rotation schedule? If the answer is "a server" — that server is now my most critical cryptographic asset and is not mentioned anywhere in the construction. GLBA Safeguards Rule 16 CFR §314.4(c) requires encryption and access controls for customer information. The operator key controls all agent authorizations touching member data. Now I compromise the operator key. I can issue valid credentials for any `modelHash`, any `permissionBitmask`, signed with the legitimate operator key, enrolled into the Merkle tree. Every RS in the consortium accepts my agent proofs as cryptographically valid. The construction's G3 (EdDSA signature verification) is the security-critical control and the entire burden falls on key custody infrastructure the construction does not specify. NCUA Part 748 §748.1(b) requires notification within 36 hours of a "notification event." Under key compromise, which credentials are affected, how do I identify them, and what is the revocation mechanism? The construction has a Merkle tree but no revocation primitive beyond expiry.

- **Why it works / why it fails against the construction:** This attack is partially in-threat-model (the adversary controls the AS, not the operator key) but the construction conflates "AS not in the trust path" with "operator key is safe." The AS is replaced by the operator. The operator key is now the AS. The construction moves the single point of failure from the AS to the operator key without specifying key custody. The 30-entry root history buffer provides no revocation — it provides recency. An enrolled credential with a compromised operator key remains valid until expiry (`expiryTimestamp`). If expiry is 90 days (reasonable for agent credentials), the breach window is 90 days.

- **In-threat-model?** Partially. The threat model explicitly excludes the operator key from adversary control. But "does not control" is a model assumption, not a real-world control. The construction must specify: required key custody standard (FIPS 140-2 Level 2 minimum for anything touching member data), key rotation policy and procedure, emergency revocation path (not just expiry-waiting), and the audit trail for operator key usage. Without these, the construction cannot survive a NCUA examination of the third-party AI program.

---

### Attack 4: The Constant-Time Rejection Protocol Disables My SOC 2 CC6.6 Anomaly Detection

- **Attack:** Section 2 ("Agent-side response discipline") mandates that the agent return `{"error": "scope_insufficient"}` for expired credentials, revoked credentials, stale Merkle roots, AND unsatisfied predicates — all after the same `T_prove` wall-clock delay. By design, "the RS cannot distinguish unsatisfied-predicate from any other proof failure." My SIEM (Splunk, Sentinel — pick one) is configured to alert on authentication anomalies per FFIEC CAT (Maturity Level 3, Domain 2: Threat Intelligence). I need to distinguish: (a) a legitimate agent that lacks a scope — operational noise, (b) a probe attack from a malicious consortium partner sweeping permission bits — active threat, (c) an agent whose credential expired — operational issue needing re-enrollment, (d) a revoked credential from a compromised agent — incident requiring NCUA 36-hour notification. The construction collapses all four into a single opaque `scope_insufficient` error. My Tier 1 SOC analyst at 2am cannot tell an expired credential from an adversarial probe sweep. My incident response playbook requires I escalate (b) and (d) immediately and log them differently. The construction explicitly prevents this distinction as a privacy feature.

- **Why it works / why it fails against the construction:** The construction's constant-time discipline is cryptographically sound for privacy (Section 3, mqSE-IND game). It is operationally incompatible with FFIEC CAT Domain 2 (Threat Intelligence and Collaboration) requirements for anomalous authentication detection, SOC 2 Type II CC6.6 (logical access restriction with monitoring), and any SIEM-based threat detection that relies on distinguishing error subtypes. The construction cannot simultaneously provide indistinguishable errors to the RS (privacy) and distinguishable error codes to the SIEM (detection). These requirements are in direct tension.

- **In-threat-model?** No. The construction's threat model considers privacy against an adversarial RS. My SIEM is not an adversarial RS — it is a required security control. The construction must address this tension explicitly. One path: a separate, institution-internal audit channel (not visible to the RS) where the agent logs error subtype to a local audit sink controlled by the CU's security team, with access controls preventing the RS from querying it. This preserves RS-facing privacy while enabling institution-side incident detection. Without this, deploying the construction puts me in a position where I must choose between ZK privacy and FFIEC CAT compliance — and my examiner chooses for me.


## Persona: rfc7662_advocate

*OAuth Working Group veteran, 10 years shipping production introspection, armed with RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + RFC 9449.*

---

### Attack 1: The Enrollment Authority Paradox — "Adversarial-AS" Is Relocated, Not Eliminated

**Attack:**

Section 8, Property 1 claims the construction achieves "Adversarial-AS soundness" because "the AS never appears in the verification path." But the verification path is only half the protocol. The construction requires someone to call the on-chain registry and insert `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` as a leaf. That party is the **operator**, identified by `(operatorPubkeyAx, operatorPubkeyAy)` — who signs over the commitment in G3.

In Section 7 (the Columbia CU scenario), the operator **is** Columbia CU — the exact party whose trustworthiness the partner RSes distrust. A compromised operator can:

1. Generate a new keypair `(opAx', opAy')`.
2. Enroll `Poseidon5(modelHash, opAx', opAy', 0xFF, expiry)` — all 64 bits set — into the on-chain registry.
3. Distribute the corresponding agent credential with the inflated bitmask.
4. The proof verifies: G4 (Merkle membership) passes against the on-chain root; G3 (EdDSA) passes because the operator signed it honestly; G5 and G6 pass because `0xFF & requiredMask == requiredMask` for any mask.

The RS learns from the chain only that *some* commitment is enrolled — it cannot read back the bitmask from the on-chain leaf (the leaf is a hash). The construction has moved trust from "AS at verification time" to "operator at enrollment time." For consortium partners who distrust Columbia CU's AS, they have equal reason to distrust Columbia CU's enrollment. The trust root is the same entity, at a different phase.

**Why it works/fails against the construction:**

The construction does not address governance of the enrollment authority. The threat model (Section 3) says the adversary controls the AS and "up to N−1 of N enrolled agents" — but it does not model a compromised *enrollment operator*. This is a gap in the threat model, not the circuit.

The construction is also silent on whether the operator key is the same as the AS's signing key. In every real deployment I've seen, they would be — the same organizational key signs both tokens and credentials.

**In-threat-model?** No — the construction must address enrollment authority trust. Suggested fix: require a multi-party threshold for enrollment (e.g., 2-of-3 among consortium members), or tie the operator key to a hardware root (TPM/HSM) whose attestation is verifiable on-chain. Without this, "adversarial-AS" becomes "adversarial-but-only-at-query-time AS" — a weaker claim than stated.

---

### Attack 2: Boolean-Return RFC 7662 + Offline JWT Introspection Achieves Information-Disclosure Parity; Implication Closure Is a Policy Invariant, Not a Category Difference

**Attack:**

Section 7 ("Why boolean-return RFC 7662 does NOT close the gap") concedes that a boolean-return AS limits the RS to one bit per query — matching the construction's information leakage. The author then pivots to two remaining gaps: (a) adversarial-AS soundness (addressed in Attack 1 above) and (b) implication closure enforcement.

On implication closure: the construction claims that G6 (`permBits[4] * (1 - permBits[3]) === 0`, etc.) is an "R1CS constraint" that "no baseline variant even attempts." This is true as a *mechanical* claim. But consider the threat scenario:

> *A malicious AS issues an RFC 7662-style token with `FINANCIAL_UNLIMITED` (bit 4) but without `FINANCIAL_SMALL` (bit 2).*

Under what conditions does this happen? Either the AS has a **bug** (violated its own invariant) or the AS is **malicious** (deliberately issuing structurally invalid tokens). In the malicious case, the AS is already adversarial — covered by Attack 1's enrollment authority argument. In the bug case, the RFC 7662 advocate responds: Circom has bugs too. CVE-2023-33252 (circom-ecdsa underconstrained signals), the Tornado Cash nullifier bug, and the Semaphore v4 depth-20 configuration subtleties all demonstrate that ZK circuits are at least as prone to implementation errors as AS policy code. The construction's G6 covers exactly 3 financial-tier implications — it does not enforce that `ACCESS_PII` (bit 7) implies anything, that `SUB_DELEGATE` (bit 6) requires `SIGN_ON_BEHALF` (bit 5), or any novel implication structure added in future permission revisions.

A well-implemented AS with policy-as-code (OPA, Cedar) can enforce implication closure with unit tests, formal verification, and peer review. A circuit with G6 hard-coded to 3 constraints cannot be updated without re-running trusted setup (see Attack 4).

Furthermore, `jwt-introspection-response` (draft-ietf-oauth-jwt-introspection-response) allows the AS to sign a per-RS filtered response that the RS caches and verifies offline — eliminating the AS from the hot path. Combine with RFC 8707 (`resource` parameter) for audience binding and RFC 9449 DPoP for sender constraint, and the remaining gap is: *who evaluates the predicate?* The answer is: "the AS, whose correctness is assumed." The construction reframes this as a category difference ("R1CS constraint vs. assertion") — but the practical security reduction is: PLONK knowledge soundness under the algebraic group model and ROM, vs. TLS+HMAC for the signed introspection response plus correct AS implementation. Both are formal assumptions; neither is categorically superior.

**Why it works/fails against the construction:**

The construction wins on the *formal* separation between circuit-enforced invariants and policy-code invariants. For a mathematically rigorous deployed system where the operator and AS are distinct, adversarial parties, this matters. For the credit union consortium scenario where Columbia CU operates both the AS and the enrollment authority, the formal gap is smaller than advertised.

**In-threat-model?** Partially — the construction survives if the threat model is scoped to the adversarial-AS case with separate enrollment authority. The construction must strengthen its argument that implication closure enforcement in R1CS is practically superior to formally verified policy code, not just structurally different.

---

### Attack 3: The Constant-Time Budget Does Not Achieve `SD(D_accept, D_reject) = 0` in the snarkjs/WASM Runtime

**Attack:**

Section 2 (agent-side rejection discipline) and Section 4 (timing side-channel closure) claim: "The constant-time budget `T_prove` ensures `SD(D_accept, D_reject) = 0`. Timing is not an additional distinguishing channel."

This claim is an idealization that fails against a network-capable adversary (explicitly in-scope per Section 3: "Network position — can observe all RS-agent traffic, including timing").

The construction's constant-time mechanism is: run the WASM prover; if it fails (no valid assignment), catch the failure and `sleep(T_prove - elapsed)`. But there are at least three distinguishing channels below `T_prove` granularity:

1. **WASM heap allocation pattern.** snarkjs allocates FFT buffers, witness vectors, and polynomial coefficient arrays during proving. A failed witness (G5 unsatisfied) causes the prover to exit the constraint-check loop early — allocating less memory before exiting than a successful proof that proceeds through polynomial commitment, multi-scalar multiplication, and Fiat-Shamir transcript construction. A co-resident or cloud hypervisor adversary observing memory balloon/pressure signals can distinguish "2 GB peak allocation during MSM" from "10 MB peak allocation during early constraint check."

2. **JIT tier-up variability in Node.js/V8.** snarkjs runs in Node.js. The first few proving calls trigger V8 JIT tier-up (interpreter → Sparkplug → Maglev → Turbofan). A cold reject (before JIT warmup) takes measurably longer than a warm reject — creating a JIT-warmup distinguisher during the first N calls after process startup. For N=5–10 calls, `T_prove=3s` does not conceal this.

3. **Network RTT jitter is not `SD=0` — it is `SD = f(jitter_distribution)`**. The construction claims `SD(D_accept, D_reject) = 0` but this requires identical wall-clock response times at the NETWORK level, not the agent level. OS scheduler preemption, TCP retransmission, and congestion on the agent→RS path add ±5–50ms of RTT jitter per request. For `T_prove=500ms` (rapidsnark), a network adversary measuring 8 sequential single-bit probe responses with 10ms RTT precision has `SNR = 500ms / 10ms = 50` — each sample provides ~5.6 bits of distinguishing power. After 20 probes, the adversary can construct a histogram and detect if response times are bimodal (success cluster vs. failure cluster) even with T_prove padding, because T_prove padding only controls the agent-side budget, not the network jitter.

The formal bound in Section 4 states `|Pr[A wins] - 1/2| <= Adv_PLONK_SE_ZK + 4q * Adv_Poseidon_PRF`. This bound applies to the **idealized** game where timing is perfectly controlled. The construction has not shown that the implementation achieves the idealized game's timing assumptions — it has mandated that implementations *try* to achieve them (Section 2's "MUST" language), but has not provided a reduction from the real execution model to the ideal.

**Why it works/fails against the construction:**

This attack is valid at the implementation level, not the protocol level. The construction's formal security argument is sound in the ROM model. The question is whether `T_prove` padding achieves the claimed `SD=0` in deployed snarkjs on commodity hardware — and the answer is provably "no" in the presence of the three channels above.

**In-threat-model?** Yes — the adversary explicitly has network position and can observe traffic. The construction must either: (a) bound `SD(D_accept, D_reject)` under realistic network/runtime assumptions and incorporate that into the mqSE-IND bound, or (b) require rapidsnark + a fixed-throughput network tunnel (e.g., QUIC with padding to fixed MTU) and document the residual. Stating `SD=0` in the security argument while deploying in snarkjs+Node.js is a gap between the formal claim and the implementation.

---

### Attack 4: The `pot16.ptau` Trusted Setup Is a Single Point of Failure with Permanent, Undetectable Blast Radius — Worse Than a Federated AS

**Attack:**

Section 5 maps the construction to `pot16.ptau` as the universal SRS for PLONK. The CLAUDE.md notes: "Project-specific keys (Agent/Delegation) use `pot16.ptau`." This ceremony is not identified as a multi-party computation (MPC) ceremony with published transcripts — it appears to be a locally generated powers-of-tau file.

PLONK's soundness requires that no party knows the "toxic waste" — the secret scalar `τ` used to compute the SRS `([τ^0]₁, [τ^1]₁, ..., [τ^{n-1}]₁)`. If any party knows `τ`:

1. They can compute a valid polynomial `p(X)` such that `p(τ) = 0` for any arbitrary witness `w*`, even one that fails G5 or G6.
2. They can construct a valid PLONK proof that the RS's verifier accepts with probability 1.
3. This enables universal forgery: prove any permission predicate satisfied for any enrolled credential, regardless of the actual bitmask.
4. The RS has no mechanism to detect this — the proof is indistinguishable from a legitimate proof.
5. The compromise is **permanent** and **retroactive** — all past and future proofs can be forged.

Compare to a compromised AS: an AS compromise is detectable (audit logs, anomalous token issuance patterns, revoked signing keys), bounded in time (re-key terminates the attack), and subject to governance (CU regulators can require AS audit). A `pot16.ptau` toxic waste leak is none of these. The toxic waste holder can forge proofs silently, forever, with no observable signal.

The construction's security argument in Section 4 assumes the trusted setup is clean and reduces soundness to PLONK knowledge soundness. This reduction is valid *given the assumption* — but the assumption is load-bearing. The RFC 7662 advocate's objection: you've replaced "trust an AS that is auditable, re-keyable, and governed" with "trust that a ptau file was generated correctly, by a process that is none of those things."

For the credit union regulatory context (NCUA Letter 24-CU-03 cited in Section 7), a `pot16.ptau` whose provenance cannot be verified by an NCUA examiner is a compliance liability, not an improvement over a federally chartered AS.

The construction's only mitigation path is a publicly verifiable MPC ceremony with ≥1 honest participant (e.g., Hermez, Semaphore, or Ethereum KZG ceremony). `HumanUniqueness` inherits the Semaphore v4 ceremony (correct). `AgentPolicy` and `Delegation` do not — they use `pot16.ptau`. Until these circuits have a comparable public ceremony, the "adversarial AS is not in the trust model" claim is offset by "non-auditable ceremony IS in the trust model."

**Why it works/fails against the construction:**

This attack does not break the circuit construction — it breaks the deployment security argument. The formal reduction in Section 4 is correct under the named assumptions. The issue is that Assumption 1 (PLONK knowledge soundness) is conditioned on a clean SRS, and the construction provides no evidence the SRS meets this condition.

**In-threat-model?** Partially — the construction's threat model (Section 3) does not list "compromised trusted setup" as an adversary capability, which means the construction correctly excludes it from scope. However, Section 8 ("Why the baseline cannot match") makes the positive claim that the construction's trust model is *superior* to an AS-based model. This claim requires addressing the trusted setup provenance, because "trust a ptau file of unknown MPC origin" is not obviously superior to "trust a federally audited AS."

---

### Summary Table

| Attack | Section Targeted | In-Threat-Model? | Disposition |
|---|---|---|---|
| 1: Enrollment Authority Paradox | §3 Threat Model, §8 Prop 1 | No — must address | Construction must scope enrollment authority separately from AS |
| 2: Boolean RFC 7662 + Offline JWT Achieves Disclosure Parity; Implication Closure Is Policy Bug, Not Category Gap | §7 "Why boolean-return RFC 7662 does NOT close the gap", §8 Prop 1 | Partially | Construction survives on formal grounds; must strengthen practical argument vs. formally verified AS policy |
| 3: Constant-Time Budget Does Not Achieve `SD=0` in snarkjs/WASM | §2 Agent-Side Discipline, §4 Timing Side-Channel Closure | Yes — construction survives formally but must quantify residual `SD` | Replace `SD=0` claim with `SD <= f(jitter)` bound under realistic runtime |
| 4: `pot16.ptau` Trusted Setup Is Single Point of Failure | §4 Named Assumptions, §8 "cannot match" claim | Partially (excluded from threat model but undermines superiority claim) | Require public MPC ceremony for AgentPolicy/Delegation or explicitly bound residual trust |


## Persona: spiffe_engineer

I run SPIRE at scale — 40,000 workloads across 12 trust domains, sub-second SVID renewal, OPA sidecar on every pod. I co-authored the WIMSE S2S protocol sections on workload proof-of-possession. Let me tell you exactly where your construction does not close the loop.

---

### Attack 1: You built a SPIRE plugin, not a protocol

**Attack:**
SPIRE has a plugin API at three layers: node attestors, workload attestors, and the Workload API gRPC surface. Your `SelectiveScopeProof` circuit is exactly what a SPIRE workload attestor plugin would look like if someone added a ZK prover step.

Concretely: the SPIRE agent already holds the workload's identity material after node attestation (TPM PCR binding, AWS IID, k8s SAT). A plugin extending the Workload API could:
1. Receive the workload's `permissionBitmask` and `modelHash` from the attestation metadata.
2. Run the `SelectiveScopeProof` prover locally (same binary, same `pot16.ptau`).
3. Return an X.509-SVID *plus* a ZK proof attachment in the Workload API response.

The RS then verifies both the SVID (existing SPIFFE toolchain) and the ZK proof (your circuit). All five properties you claim — adversarial-AS independence, zero-knowledge predicate, AS-blind presentation, constant-size proof, model-hash binding — are achieved inside the SPIFFE trust model without a new protocol.

Your Section 7 comparison table ("Why Client Attestation, WIMSE WPoP, and hardware-attested SPIRE do not close the gap") dismisses SPIRE on the grounds that "SPIRE's SVID carries no permission bitmask." That is a SPIRE *deployment* choice, not an architectural constraint. SPIRE custom attestors can attest arbitrary metadata. The failure mode you cite is a configuration gap, not a protocol gap.

**Why it works / why it fails:**
The construction never models what a ZK-extended SPIRE attestor looks like. It compares against vanilla SPIRE (identity only) and vanilla token exchange (AS-mediated). It does not compare against "SPIRE + ZK prover plugin." This means the claim in Section 1 — "No composition of RFC 7662 … can simultaneously achieve all five properties" — is formally incomplete because SPIFFE is not in the enumerated baseline set, and the comparison table in Section 7 assumes a static SPIRE deployment rather than a plugin-extended one.

**In-threat-model?** No. The construction must address why a SPIRE ZK attestor plugin is architecturally insufficient and not merely a re-implementation of itself inside an existing trust framework.

---

### Attack 2: Your "no AS roundtrip" claim trades AS for L2 RPC — same dependency class

**Attack:**
Section 3 ("Adversarial-AS resilience") asserts: "The AS never appears in the verification path. The RS verifies the proof against the on-chain Merkle root."

Step 1 of the RS-side verification protocol (Section 2): "RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact)."

This is not AS-independence — it is AS *replacement*. The RS now depends on:
- A Base L2 RPC endpoint (availability, correct block data, MEV/sequencer trust)
- The `BolyraRegistry` contract (upgradeability, governance, admin key compromise)
- L2 finality guarantees (optimistic fraud window on Base: 7 days; ZK rollup proof publication lag)

Compare to SPIFFE: the RS caches the SPIFFE bundle (a signed JSON document containing trust domain public keys). Bundle refresh happens over HTTPS to the SPIRE server's bundle endpoint. The RS can verify SVIDs fully offline with the cached bundle — same "no AS roundtrip at presentation time" property, but backed by a replicated, air-gappable bundle store rather than a live L2 RPC.

The threat model in Section 3 states the adversary "does NOT control the on-chain registry (Ethereum/Base L2 consensus assumptions)" — but this simply *names* the assumption without modeling it. Assumptions not modeled:
- The L2 RPC provider (Alchemy, Infura, or custom node) is a trusted third party whose compromise is equivalent to AS compromise for Merkle root freshness.
- The `BolyraRegistry` contract upgrade path: if the contract is upgradeable (proxy pattern), the contract admin key is an AS-equivalent.
- Sequencer censorship: a censoring sequencer can prevent new enrollments from appearing in the Merkle tree, equivalent to an AS refusing to issue tokens.

Your "adversarial-AS" game in Section 3 models a compromised or offline AS. The same game applies to a compromised or unavailable L2 RPC — and you have not bounded that adversary's power.

**Why it works / why it fails:**
The construction's adversarial-AS argument is structurally sound for the *predicate evaluation* (G5/G6 are R1CS constraints, AS cannot lie about those). But the *enrollment integrity* depends on the on-chain registry, and the on-chain registry is not a credible improvement over a replicated SPIRE server bundle endpoint in availability, upgrade safety, or Byzantine fault model. The construction is trading one trusted third party (AS) for another (L2 + RPC + contract admin).

**In-threat-model?** No. Section 3 asserts "Ethereum/Base L2 consensus assumptions" without modeling sequencer trust, contract upgradeability, or RPC provider adversaries. The construction must bound these or acknowledge them as residual trust assumptions equivalent to the AS trust it claims to eliminate.

---

### Attack 3: Constant-time budget `T_prove` does not hold in Node.js — the mqSE-IND proof is vacuous in practice

**Attack:**
Section 2 ("Agent-side response discipline") specifies a constant-time budget `T_prove` to close the timing side-channel. Section 3 (mqSE-IND game) claims "SD(D_accept, D_reject) = 0" as a result. Section 4 ("Timing side-channel closure") states this "ensures" indistinguishability.

This is false for the snarkjs deployment path (Section 6: "PLONK (snarkjs): < 3 seconds on commodity hardware").

Node.js is not a real-time runtime:
- V8 garbage collection introduces unpredictable pauses (major GC: 50–200 ms; minor GC: 1–5 ms), correlated with heap pressure during prover witness expansion.
- `setTimeout(fn, T_prove - elapsed)` has ~1 ms timer resolution but is subject to Node.js event loop scheduling — the actual sleep duration is `T_prove - elapsed + δ` where `δ` is event loop delay, observable to a network adversary measuring response time.
- CPU frequency scaling (Intel SpeedStep, ARM big.LITTLE) causes proving time to vary by 2–3× depending on thermal state. A fresh prover run is faster than a run after sustained load.

The adversary's bit-extraction attack (Section 7, "Chosen-predicate attack in the consortium setting") requires distinguishing "proof generated" from "proof generation failed." With variable snarkjs timing under load, `D_accept` (proof succeeds at time `t_actual ± δ_gc`) and `D_reject` (proof fails at time `ε ± δ_init`, where `ε` is the near-zero time before constraint failure) are distinguishable through second-order variance, not just mean response time. An adversary running 1,000 probe queries per predicate can extract variance signatures that distinguish the two distributions even under `T_prove` padding.

The rapidsnark path (Section 6: "< 500 ms") is a native binary invoked via subprocess (`sdk-python` already uses subprocess bridge; the TS SDK shells out similarly). Subprocess spawn time is variable (5–50 ms), process scheduling is non-deterministic, and the shared library loader's timing leaks on first invocation.

The formal game in Section 3 states the constant-time guarantee as an *axiom* ("The constant-time budget `T_prove` ensures `SD(D_accept, D_reject) = 0`") rather than a proved property. There is no reduction to a real-time execution model. The mqSE-IND proof is therefore a proof under an assumption that does not hold in any of the named deployment paths.

**Why it works / why it fails:**
The ZK proof itself is perfectly zero-knowledge — the circuit outputs reveal nothing. But the *generation* of that proof creates a side channel that the construction acknowledges and then claims to close via `T_prove` padding. The padding argument requires a constant-time prover, which snarkjs is not. The construction must either: (a) prove the implementation provides statistical indistinguishability under a concrete execution model, or (b) restrict the security claim to the rapidsnark deployment path and provide a formal bound on subprocess variance.

**In-threat-model?** No. Section 4 claims timing closure as a proved property but provides no reduction to an execution model. The implementation section (Section 6) names two provers with known variable timing. The gap between the formal claim and the stated implementation is unaddressed.

---

### Attack 4: The 30-entry Merkle root history buffer creates a revocation window the construction does not bound

**Attack:**
Section 5 (Bolyra primitive mapping) states the RS uses "Agent Merkle root from `BolyraRegistry` with 30-entry root history buffer." The security game in Section 3 specifies that the adversary wins if the `onChainAgentRoot` in the forged proof "is a valid root from the registry's root history buffer."

This means: a proof generated against root `R_N` remains verifiable at the RS until root `R_{N+30}` displaces it from the history buffer. Revocation of an agent credential requires removing its commitment from the Merkle tree, but proofs generated *before revocation* against historical roots *within the buffer window* remain valid.

The construction does not specify:
- The rate at which the Merkle root is updated (block time? enrollment events? fixed schedule?)
- The maximum age of a root in the 30-entry buffer (30 blocks ≈ 60 seconds on Base; 30 enrollment events = unbounded wall-clock time if enrollments are sparse)
- Whether the RS is required to purge historical roots upon detecting a revocation event

Concretely: an agent is compromised at time `T`. The operator revokes the credential by removing the commitment from the Merkle tree. A proof generated at `T - 1 second` against root `R_N` is still valid against the RS until `R_{N+30}` is produced and the RS's cached root history ages out `R_N`. In a sparse enrollment environment (one new agent enrolled per week), `R_{N+30}` may not appear for 30 weeks. The revocation window is unbounded.

SPIRE's approach: X.509-SVID TTL defaults to 1 hour. A revoked workload fails to renew its SVID — the next SVID request is denied by SPIRE, and the old SVID expires within 1 TTL. The revocation window is at most 1 TTL, configurable down to minutes. There is no analog of a "30-entry history buffer" that extends validity for an attacker-controlled duration.

**Why it works / why it fails:**
The 30-entry history buffer is motivated by a legitimate engineering concern: preventing proof invalidity due to Merkle root churn during proof generation latency. But it introduces a revocation window whose maximum duration depends on an unspecified root update rate. The security game's winning condition explicitly allows proofs against historical roots, acknowledging this window exists without bounding it.

**In-threat-model?** No. The construction models credential forgery (Section 3, SelectiveScopeForgery) but not credential revocation window exploitation. The 30-entry buffer's interaction with revocation is unaddressed. The construction must either specify a mandatory root rotation interval (bounding the revocation window to `30 × interval`) or replace the history buffer with a revocation accumulator or nullifier set that the RS can check at presentation time without an AS roundtrip.
