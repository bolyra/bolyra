# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: scopeId is public — behavioral fingerprinting survives the cryptography

**Attack:** The circuit outputs `scopeId` as a public signal (Section 2, Index 4 of the on-chain signal layout). The construction acknowledges this directly: "Cascade FCU sees `scopeId_pharmacy` and `scopeId_grocery` on-chain but **cannot associate either with the member's agent**." The defense is that N agents share the same `agentMerkleRoot`, so the AS can't identify *which* agent accessed the pharmacy.

But the IND-UNL-AS game (Section 3) is defined for a **single challenge pair of proofs**. In production, a credit union sees *thousands* of proof submissions over weeks. An adversarial AS applies behavioral fingerprinting: time-of-day patterns, inter-request delays, scope co-occurrence sequences, and request frequency. In a CU with 500 enrolled agents and 10 popular scopes, agents with distinctive patterns (the only one accessing both a specialty pharmacy and an auto dealer within 40 minutes on weekday afternoons) achieve k=1 anonymity despite cryptographically unlinkable nullifiers.

The construction's defense is "request batching via a relay/mixer" — but Section 4 explicitly classifies this as "an operational recommendation, not a circuit-level property." That means it's opt-in, enterprise teams won't deploy it, and the construction's formal game doesn't cover it.

**Why it works:** The IND-UNL-AS game is defined for a single-shot challenge (two proofs, two scopes). It says nothing about temporal or frequency metadata accumulated over thousands of real-world requests. The security proof in Section 4 only considers what A learns from `(π_A, pubSignals_A, π_B, pubSignals_B)` — it does not model a sequence of proofs over time.

**In-threat-model?** No. The construction must extend the game to an adaptive multi-query setting and either (a) provide circuit-level batching with dummy proof injection, or (b) explicitly scope the claim to single-shot linkability and disclaim temporal correlation.

---

### Attack 2: scopeNullifier is a permanent pseudonym — RS collusion reconstructs the agent's profile anyway

**Attack:** `scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)` is **deterministic and permanent** per `(agent, scope)`. Every time the same agent accesses the same RS, they present the identical `scopeNullifier`. This is intentional for Sybil detection.

The threat model (Section 3) explicitly allows A to "collude with any subset of RSes." RS-Pharmacy receives `(proof, scopeNullifier_pharmacy)` on every visit. RS-Pharmacy knows nothing about the agent's identity — but it maintains a complete timestamped access log keyed on `scopeNullifier_pharmacy`. When RS-Pharmacy hands this log to Cascade FCU (permitted by the threat model), the AS has a permanent pseudonymous identifier for this specific agent at this scope, including visit frequency, timing, and any application-layer payload (e.g., prescription amount) that RS-Pharmacy observed independently.

If *any* colluding RS has an off-chain means to identify the member — a payment amount that matches a bank record, a device fingerprint on the agent's HTTP call — they can resolve `scopeNullifier_pharmacy` to a real identity and hand that resolution to the AS. From that point, the AS can link every subsequent pharmacy visit without breaking any cryptographic primitive.

The construction's Section 7 scenario says RS-Pharmacy "does NOT learn the agent's identity." True — in isolation. But the threat model allows RS-AS collusion, and the combination of a permanent nullifier plus off-chain RS knowledge breaks the claimed privacy at the RS-AS boundary.

**Why it works:** The construction provides cross-scope unlinkability (different scopes → different nullifiers). It provides zero within-scope unlinkability by design (same scope → same nullifier, intentionally). Under RS-AS collusion with off-chain signal, within-scope permanence becomes a cross-session tracking vector that the formal game doesn't address, because the game doesn't model off-chain RS observations.

**In-threat-model?** No. The IND-UNL-AS game requires A to distinguish *across scopes*. The game has no oracle for within-scope repeated access. The construction must either (a) add per-session nullifiers within a scope (and use a separate Sybil-detection mechanism) or (b) explicitly bound the claim: unlinkability holds across scopes but not across sessions within a scope.

---

### Attack 3: Groth16 trusted setup is a procurement kill switch for every named target customer

**Attack:** The construction uses a project-specific Groth16 trusted setup (`pot16.ptau`) for `ScopeSeparatedAgentPolicy` and `Delegation`. Section 5 notes `HumanUniqueness` reuses the public Semaphore v4 ceremony — but Agent and Delegation circuits use Bolyra's own ceremony. The construction contains zero mention of: a multi-party ceremony, a public transcript, third-party audit of the ceremony record, or continuity guarantees if Bolyra (a solo founder) becomes unavailable.

Section 7 names Intermountain Health (33 hospitals, HIPAA-regulated) and a Pacific Northwest Credit Union Association (NCUA-supervised). These entities have procurement checklists. For cryptographic infrastructure handling PHI or member financial data, those checklists include: SOC 2 Type II report, HIPAA Business Associate Agreement, evidence of the trusted setup ceremony (who ran it, what hardware, what software, what the output hash is), and a Big 4 or equivalent cryptographic audit.

Auth0 ships a HIPAA BAA. WorkOS is SOC 2 Type II. Stytch has enterprise SLAs with named uptime commitments. All three have legal entities with D&O insurance that procurement can attach liability to. Bolyra's construction provides a cryptographic proof that the *circuits* are sound — it provides nothing about the *ceremony* being uncompromised. If the ceremony trapdoor was retained, any party holding it can forge arbitrary proofs, including false authorization grants at every enrolled RS.

**Why it works:** Procurement at a 33-hospital health system doesn't evaluate BN254 scalar field security margins. They run a vendor risk questionnaire. "Solo founder ran the trusted setup" is an automatic red flag under any HIPAA security risk analysis. The construction's cryptographic strength is irrelevant if the deployment never clears procurement.

**In-threat-model?** No — this is outside the formal threat model by design. But it is entirely within the buyer's threat model. The construction needs a public MPC ceremony transcript, independent attestation, and an answer to "what happens to credential verification if Bolyra shuts down tomorrow?"

---

### Attack 4: The AS is in the hot path for root updates — the anonymity set collapses to ~1 during sparse enrollment windows

**Attack:** The construction's central claim against AS-level linkability is that `agentMerkleRoot` is "identical for both agents (same tree)" — the anonymity set is all N enrolled agents. Section 7 states the AS "can verify that *some* enrolled agent accessed the pharmacy... but cannot determine that it was the same agent."

But who updates the root history buffer? Section 7 says "Cascade FCU stores the commitment in the tree" during enrollment. The on-chain registry verifies that `agentMerkleRoot is in the agent root history buffer`. Someone must publish new roots when agents enroll or are revoked — and that entity is the AS (Cascade FCU) or an operator with equivalent access.

Consider a sparse enrollment window: Cascade FCU processes a batch of new agent enrollments at 2:00 PM and publishes root R_47. Only 3 new agents were added in that batch. Proofs submitted between 2:00 PM and the next root update use R_47. The AS, which *published* R_47 and knows exactly which 3 agents were added, observes proof submissions in that window. The effective anonymity set is 3, not N — the "large tree" defense only holds when the root history buffer is long and roots change infrequently relative to proof submission rate.

Worse: if the AS deliberately staggers enrollment to create singleton root windows ("enroll agent X, publish root, observe proofs for 60 seconds, enroll next agent"), they can de-anonymize every agent trivially — no cryptographic primitive is broken.

The IND-UNL-AS game (Section 3) fixes the setup as "Challenger C enrolls n agents into the Merkle tree" and gives A "the full tree and all credential commitments" — but doesn't model the *sequence* of root publications or the AS's ability to control enrollment timing to isolate agents.

**Why it works:** The security argument in Section 4, Step 2 asserts that `agentMerkleRoot` is "identical for both agents (same tree)" as a given. In practice, the AS controls when roots change. Sparse trees or deliberate enrollment timing let the AS collapse the anonymity set to 1 without breaking any cryptographic primitive listed in Section 4.

**In-threat-model?** No. The construction must either (a) require that the Merkle tree operator be a distinct, non-colluding party from the AS, contradicting the Section 7 CU deployment scenario where "Cascade FCU operates the AS and enrollment infrastructure," or (b) add a minimum anonymity set requirement (k-anonymity on root membership) and a mandatory root publication cadence that prevents singleton windows.


## Persona: cryptographer

---

### Attack 1: The IND-UNL-AS Game Understates Adversary Power — Nonce Issuance Is an AS Capability

**Attack**: In the IND-UNL-AS game (Section 3, Challenge phase), the Challenger C generates `sessionNonce_A` and `sessionNonce_B` independently. But the adversary A *controls the Authorization Server*, which in every realistic deployment issues session nonces. If A issues the nonces, A retains the mapping `(sessionNonce, agent_session_context, timestamp)` before the proof is ever constructed. When A subsequently observes on-chain transactions containing those nonces as public signals, A trivially wins: it looks up which agent session it issued `sessionNonce_A` to and outputs `b' = b` with probability 1.

**Why it works / why it fails**: The construction does not specify who generates session nonces. Section 4 says agents "SHOULD verify nonce freshness against the on-chain used-nonce set **or generate their own nonces when the protocol permits**." "When the protocol permits" is undefined. In the standard OAuth pattern that Bolyra is replacing, the AS issues state/nonce values. If the AS retains that issuance record, the entire ZK stack is irrelevant — the adversary wins by the nonce provenance lookup alone, not by any cryptographic attack.

The game definition insulates C from this by having C pick nonces. That exclusion must be stated as a *protocol assumption* (client-generated nonces, MUST, not SHOULD), not buried in an operational note. Without that assumption baked into the formal model, the game definition does not capture the real adversary.

**In-threat-model?** No. Section 3 lists A's capabilities as "full access to the enrollment records" and "on-chain observation" but never grants A nonce issuance capability, even though AS nonce issuance is standard behavior. The game must either (a) grant A the ability to choose `sessionNonce_i` and prove the bound still holds, or (b) state as a hard protocol requirement that nonces are always client-generated (and circuit-enforce it by committing to a client-provided randomness component). Currently neither is done.

---

### Attack 2: Groth16's ZK Is HVZK, Not Simulation-Extractable — The Reduction Is Under-Specified

**Attack**: The reduction sketch (Section 4, Step 1) asserts: "By the Groth16 zero-knowledge property, we can replace both real proofs `(π_A, π_B)` with simulated proofs that are computationally indistinguishable." This hybridization argument is standard — but it silently assumes the AS is an *honest verifier*. The AS in this construction is explicitly adversarial. Honest-verifier ZK (HVZK) does not guarantee indistinguishability against a verifier that (a) chooses verification keys adversarially or (b) runs adaptive queries outside the protocol. Groth16 achieves HVZK under the CRS model; it achieves simulation-extractable ZK only in the algebraic group model (AGM) + random oracle model (ROM), which is not stated.

**Why it works / why it fails**: The reduction omits the model. "Computationally indistinguishable" requires a home — standard model, ROM, AGM, or generic group model. Groth16's ZK theorem (Groth 2016, Theorem 1) is proven in the CRS model assuming the σ-DLOG assumption and requires the simulator to hold the simulation trapdoor. Section 3 says "The adversary does NOT control: The Groth16 trusted setup (simulation trapdoor)" — fine, but the reduction must then explicitly invoke the CRS-model simulator and state the underlying assumption (σ-DLOG on BN254). It does not. Additionally, if this construction is ever composed with other protocols (UC framework), HVZK is insufficient; you need simulation-extractability. The PLONK alternative (Section 2, "MAY") does not resolve this because standard PLONK also achieves HVZK, not SE-ZK, without Fiat-Shamir in ROM.

**In-threat-model?** Partially. The claim "π reveals nothing about the witness beyond public signals" is not wrong for Groth16 in isolation under honest verification, but the reduction as written would not survive a referee at CRYPTO. The fix is straightforward: state "we work in the AGM+ROM" (or CRS model under σ-DLOG), cite the relevant Groth16 ZK theorem precisely, and note that UC composition would require upgrading to an SE-SNARK. The current sketch is hand-waving at the exact point the persona's heuristic triggers.

---

### Attack 3: Delegation Chain Linkability — `previousBlindedScopeCommitment` Is a Public Beacon

**Attack**: The modified Delegation circuit (Section 2) proves:

```
Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder) == previousBlindedScopeCommitment
```

The `previousBlindedScopeCommitment` is a **public input** to the delegation circuit, and therefore appears on-chain. In a two-hop delegation A→B→C:

- A's proof at RS-A produces `blindedScopeCommitment_A` (public, on-chain, indexed by block).
- B's delegation proof at RS-B takes `previousBlindedScopeCommitment = blindedScopeCommitment_A` as a public input — on-chain.
- C's delegation proof at RS-C takes `previousBlindedScopeCommitment = blindedScopeCommitment_B` — on-chain.

The AS (or any on-chain observer) follows the chain: find all proofs where `previousBlindedScopeCommitment = X`; that gives the next hop. The full delegation graph is publicly reconstructible by graph traversal.

**Why it works / why it fails**: The IND-UNL-AS game (Section 3) only models single-level proofs — no delegation. The game does not address this attack surface. But the concrete deployment scenario in Section 7 explicitly claims: "The delegation circuit's blinded chain linking ensures that even the delegation path (PCP → Specialist) is hidden from the AS." This is false. The blinded commitment hides *who* the delegator is (you cannot invert `Poseidon3` to recover `delegatorCredCommitment`), but the *existence and structure of the delegation link* is fully visible on-chain. The AS traces the chain without inverting anything — it just matches public output values.

**In-threat-model?** No. The IND-UNL-AS game does not model delegation, so the game technically does not break. But the Section 7 claim is a false guarantee. The construction must either (a) drop the delegation privacy claim from the deployment scenarios or (b) extend the IND-UNL-AS game to delegation chains and redesign the linkage so `previousBlindedScopeCommitment` is also unlinkable (e.g., re-blind at each hop with a fresh blinder that the verifier cannot trace, using an auxiliary ZK proof of chain consistency that doesn't reveal the link value).

---

### Attack 4: Single-Game Bound Does Not Compose — Multi-Scope Behavioral Fingerprinting Is Outside the Reduction

**Attack**: The advantage bound in Section 4 is `Adv_A ≤ 2·Adv_Groth16-ZK + 2·Adv_Poseidon-PRF`. This bound applies to the IND-UNL-AS game with a **single challenge pair** `(π_A, π_B)`. Real deployment (Section 7) involves an agent repeatedly accessing many scopes over days. The AS observes a time-series of on-chain proofs. Even if each individual pair is unlinkable, the joint distribution may leak:

1. **Temporal pattern attack**: Agent X always submits a pharmacy-scope proof within 30 seconds of a grocery-scope proof. The `scopeId` values are PUBLIC signals. The AS observes `(scopeId_pharmacy, t₁)` and `(scopeId_grocery, t₁+28s)` repeatedly. The correlation is a side channel orthogonal to any cryptographic primitive — it is a behavioral fingerprint exploitable by an AS with time-series data.

2. **Merkle root history timing**: Section 2 states the registry checks "`agentMerkleRoot` is in the agent root history buffer." If the AS controls Merkle tree updates (it does — it controls enrollment), it can issue a targeted update between two agent enrollments, then ask: "Which proofs appearing after update epoch k use a root from before epoch k?" This narrows the anonymity set to agents enrolled before the update, progressively de-anonymizing via root timing.

3. **Multi-query distinguisher**: The IND-UNL-AS game gives A a single challenge. A PPT adversary with polynomial query access to the on-chain proof stream can use a distinguisher over k proofs that is negligible per-query but polynomially amplified. The bound does not compose to multi-query without an explicit hybrid argument over k rounds. The construction provides no such argument.

**Why it works / why it fails**: The reduction is tight for the single-pair game. It does not imply anything about the multi-proof setting. The deployment scenarios describe sustained operation, not one-shot protocols. The claim "Bolyra provides ~128 bits of security under the Poseidon PRF assumption" (Section 8) is the per-query bound; the system's actual unlinkability in deployment degrades with the number of observations the AS accumulates. The bound overstates security for the scenarios actually described.

**In-threat-model?** Partially. Items (1) and (3) are outside the formal game as defined — but that is the critique: the game is too narrow. Item (2) uses the AS's Merkle control, which IS within A's stated capabilities. The construction must either extend the game to multi-query adaptive adversaries and bound the advantage per-query × number-of-queries, or add an operational requirement (mixing, batching, minimum cohort size before root publication) that the formal model then accounts for. The current Section 4 timing treatment only addresses proof-generation time variance, not the multi-session behavioral graph that a real AS accumulates.


## Persona: cu_ciso

### Attack 1: The Audit Trail Paradox — NCUA Part 748 §748.2(c)

- **Attack**: The construction's core privacy guarantee is that the AS cannot link `scopeNullifier_pharmacy` to any specific member's agent. I invoke NCUA Part 748 §748.2(c) (Safeguards for Member Information): my security program must include controls for "monitoring and detecting actual and attempted attacks" and producing audit trails for examiner review. When an NCUA examiner walks in after a suspected breach and asks "which member's agent accessed RS-Pharmacy on June 14th between 2–4pm?" — I cannot answer. Section 7 of the construction explicitly celebrates this: "The member's merchant graph is cryptographically hidden from their own credit union." That is not a feature I can sell to an examiner. It is a documented control deficiency. The very PRF-based unlinkability that closes the IND-UNL-AS game destroys my ability to fulfill mandatory suspicious activity monitoring obligations under §748.1(c)(2) and my BSA/AML transaction monitoring requirements under 31 U.S.C. §5318.
- **Why it works / why it fails**: The construction provides no dual-mode path — no privacy-preserving audit logging, no selective disclosure mechanism, no "audit oracle" that can de-anonymize under court order without compromising all agents. Section 7 describes what Cascade FCU *cannot* see; it says nothing about what a compliance officer *can* see. The threat model (Section 3) explicitly excludes "the agent's local proving environment" from adversary control, but the legitimate compliance use case requires exactly that access under lawful process.
- **In-threat-model?** No — construction must address. Needs a selective audit disclosure mechanism (e.g., escrow of `operatorPrivateKey` with a regulated key custodian, or a ZK proof of audit compliance that reveals identity only to an authorized auditor) with explicit NCUA Part 748 §748.2 mapping.

---

### Attack 2: Operator Private Key Custody — GLBA Safeguards §314.4(f) and FFIEC Third-Party Risk

- **Attack**: Section 4 (security argument, revised nullifier) and Section 5 reduce the entire construction's unlinkability to the secrecy of `operatorPrivateKey` — the Baby Jubjub EdDSA scalar. The construction says this is "the operator's EdDSA private key scalar" but never specifies where this key lives, how it is generated, how it is rotated, or what happens when it is compromised. I invoke GLBA Safeguards Rule §314.4(f): my security program must include controls over "access to customer information systems." I also invoke NCUA's Third-Party Vendor Management guidance (Letter to Credit Unions 07-CU-13): I must assess vendor controls over sensitive data. If `operatorPrivateKey` is held in a browser key store (WebCrypto) or a mobile app, it is outside my control posture entirely. If it is held by an "AI agent operator" (a fintech), that operator is a critical third party for whom I have no SOC 2 Type II, no right-to-audit clause, and no contract requiring NIST SP 800-57 key management practices. A compromised `operatorPrivateKey` does not just compromise one session — it allows the attacker to compute `Poseidon2(scopeId, sk)` for any scope and forge or replay scope nullifiers undetected.
- **Why it works / why it fails**: Section 3 threat model says the adversary "does NOT control the agent's local proving environment" and "cannot extract private inputs." For enterprise agents running in controlled infrastructure this is defensible. For consumer-facing CU members whose AI agents run in browsers or third-party app sandboxes, this assumption collapses in practice. The construction provides no key rotation circuit — once `operatorPrivateKey` is enrolled, the `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, ...)` is fixed in the Merkle tree. Key compromise requires re-enrollment. The revocation mechanism (Section 2, on-chain `scopeNullifier` revocation mapping) is per-scope — does my Tier 1 ops team know which of 50 scopes to revoke when a member's phone is stolen at 2am?
- **In-threat-model?** No — construction must address. Needs: (1) explicit key custody options with regulatory mapping; (2) key rotation circuit or re-enrollment protocol; (3) emergency revocation workflow that a Tier 1 ops team can execute without knowing the full scope list.

---

### Attack 3: On-Chain Registry Availability vs. Core Processor SLA — NCUA Part 748 Business Continuity

- **Attack**: Every agent authentication in this construction requires on-chain verification: the registry checks `sessionNonce` freshness, `scopeNullifier` revocation status, and `agentMerkleRoot` membership (Section 2, modified on-chain verification). The construction deploys to Base Sepolia → production Base mainnet. I ask the question directly: what is your SLA? My core processor (FiServ/Jack Henry) contractually commits to 99.9% uptime (~8.7 hours downtime/year). The Base network has no SLA guarantee. During the March 2024 Optimism sequencer outage (Base shares the OP Stack), Base was degraded for ~4 hours. When the chain is congested or the bridge is unavailable, `currentTimestamp` verification fails, nonce submission fails, and agents cannot authenticate to *any* RS. NCUA Part 748 requires business continuity and disaster recovery planning for critical systems. An authentication system with no offline fallback is a critical dependency I cannot accept. Section 7 "deployment scenario" mentions no fallback path; Section 6 proving time targets assume the on-chain call succeeds.
- **Why it works / why it fails**: The construction has no degraded-mode operation. The `agentMerkleRoot` history buffer (Section 2) requires an on-chain read for every verification. The nonce-used set is on-chain state. A Layer 2 rollup that processes sequencer blocks in batches introduces non-deterministic finality latency that could cause legitimate proofs to fail `currentTimestamp < expiryTimestamp` if finality is delayed while the credential expires. The construction says "The registry stores `blindedScopeCommitment` as the delegation chain seed" — this means the delegation chain itself cannot advance during a chain outage.
- **In-threat-model?** No — construction must address. Needs: (1) a fallback verification path (e.g., optimistic offline verification with on-chain settlement when available, or a secondary RPC provider failover); (2) explicit SLA commitment or acknowledgment that availability is bounded by L2 sequencer uptime; (3) business continuity design section with NCUA-defensible recovery time objective.

---

### Attack 4: Anonymity Set Collapse via `requiredScopeMask` Fingerprinting

- **Attack**: Section 2 lists `requiredScopeMask` as a **public input** — it appears in every on-chain verification transaction. The IND-UNL-AS game (Section 3) stipulates that A selects "two enrolled agents with identical `permissionBitmask` and `expiryTimestamp`" — the strongest case *for* the adversary. But in practice, a mid-size CU ($2B–$10B AUM) might have 500–5,000 AI agents enrolled, with a highly non-uniform permission distribution. If only 3 agents in the entire tree hold `requiredScopeMask = 0b00110101` (READ_DATA + FINANCIAL_SMALL + SIGN_ON_BEHALF), the `requiredScopeMask` value on-chain reduces the anonymity set to 3 agents. Cross-referencing with `scopeId` (also a public input) and `currentTimestamp` (block time, publicly visible) may uniquely identify the transaction to a specific member. The construction celebrates that `agentMerkleRoot` is "identical for both agents (same tree)" — but this works against it: a small CU with a sparse permission distribution cannot hide behind a tree of 2^20 leaves when only 3 leaves carry the distinguishing bitmask combination.
- **Why it works / why it fails**: The construction's Section 4 reduction sketch correctly notes that the *blinded scope commitments* are indistinguishable. But the reduction assumes the adversary cannot extract information from public inputs outside the commitment. `requiredScopeMask` is a public input *chosen by the RS*, not by the agent — the agent cannot randomize it. An adversarial AS that also controls or observes the RS's required policy (trivially: the AS issues policy documents to RSes) knows exactly which `requiredScopeMask` corresponds to which RS type (pharmacy RS always requires `FINANCIAL_SMALL`). Combined with timing, this provides a side channel entirely outside the IND-UNL-AS game definition, which does not bound information from public inputs. Section 4 side-channel treatment covers timing and nonce freshness but omits public-input enumeration attacks.
- **In-threat-model?** No — construction must address. The IND-UNL-AS game should be extended to account for information leaked by `requiredScopeMask` and `scopeId` public inputs, or the construction should include a minimum anonymity set requirement (e.g., k-anonymity bound on active proofs per `(requiredScopeMask, scopeId)` pair) with operational guidance for small CUs where k < threshold.


## Persona: rfc7662_advocate

---

### Attack 1: scopeId Is Public — The Merchant Graph Is Not Hidden

**Attack:**
The construction places `scopeId` as a **public input** (Table 2, on-chain layout index 4). An adversarial AS observing the blockchain sees every `(scopeId, timestamp)` pair in every verification transaction. Section 7's deployment scenario claims "the member's merchant graph is cryptographically hidden from their own credit union," but the construction itself publishes `scopeId_pharmacy` and `scopeId_grocery` on-chain for every proof. The blinded scope commitment hides the *permission bitmask*, not the scope identity. The AS doesn't need the nullifier to reconstruct the merchant graph — it reads `scopeId` directly from the calldata.

**Why it matters against the construction:**
Section 8 point 3 states "Bolyra's `blindedScopeCommitment` commits to the permission bitmask without revealing it to the on-chain observer or the AS." True for the bitmask. But this is a different property from merchant-graph privacy. The RFC 7662 baseline provides exactly the same information to the AS: it learns which RS is being accessed at what time. In RFC 7662, the RS calls the introspection endpoint, and the AS sees `(resource_id, timestamp)`. In Bolyra, the AS reads `(scopeId, timestamp)` from on-chain calldata. The information content is identical. The construction's stated advantage in the deployment scenario (Section 7) is not supported by the circuit's public signal layout.

**In-threat-model?** Yes — this is within the adversary capabilities (on-chain observation). The construction must either (a) make `scopeId` a private input with a public commitment, (b) route proofs through a mixer before on-chain submission, or (c) revise the merchant-graph-privacy claim to accurately state only *agent unlinkability*, not *scope unlinkability*.

---

### Attack 2: Adversarial Tree Management Collapses the Anonymity Set

**Attack:**
The adversary A controls the Merkle tree (threat model, Section 3). A can:
1. Perform a targeted enrollment: add only two dummy agents alongside the victim, anchor a tree root, and present this 3-leaf root as valid in the history buffer.
2. Instruct the victim agent to use the freshly anchored root by making it the most recent valid entry in the history buffer.
3. Observe a proof against the 3-leaf root. The anonymity set is now exactly 3 agents, two of which are A's own dummies.

The IND-UNL-AS game (Section 3) assumes A "enrolls n agents" but never specifies a minimum n or any mechanism preventing the AS from engineering sparse roots targeting a specific agent epoch. The circuit check `agentMerkleRoot in history buffer` enforces only freshness, not set size. The construction provides no lower bound on the anonymity set. A proof that is cryptographically sound against a 2-element tree provides approximately 1 bit of anonymity — the ZK argument and the unlinkability game both hold, but the real-world guarantee is vacuous.

RFC 7662 baseline comparison: RFC 7662 is honest about this — the AS always knows the exact principal. Bolyra's construction implies a meaningful anonymity set but provides no protocol mechanism to enforce one. A well-specified RFC 7662 extension (e.g., token binding to a blinded identifier issued by a privacy proxy) could be paired with an honest AS and would have the same or stronger properties under the "AS is honest" assumption that the anonymity set argument effectively requires.

**In-threat-model?** Yes. The adversary A controls the Merkle tree, and controlling tree update timing is within those capabilities. The construction must specify a minimum anonymity set size, an epoch policy with a mandatory hold period (e.g., no root valid until it contains ≥ K enrollments), and a mechanism for agents to verify the set size before proving.

---

### Attack 3: Nonce Issuance Timing Is a Protocol-Layer Deanonymization Channel

**Attack:**
The `sessionNonce` is a public input supplied by the RS in a challenge-response flow. The threat model permits A to collude with any subset of RSes. A colluding RS does not merely forward the nonce — it timestamps the nonce issuance event and reports it to A: `"nonce n1 issued to IP/agent-context X at t1"`. A receives:

- `(n1, t1)` from RS-Pharmacy's nonce log
- `(n2, t2)` from RS-Grocery's nonce log

Both `n1` and `n2` appear on-chain at approximately `t1+Δproof` and `t2+Δproof`. If an AI agent operating in batch mode contacts multiple RSes within a short window (standard agentic behavior: plan → fanout to N services in parallel), the temporal clustering of nonce requests and subsequent on-chain submissions allows A to correlate the proofs with non-negligible probability — entirely bypassing the ZK unlinkability property, which is a cryptographic guarantee about the *proof content*, not the *protocol flow*.

Section 3's side-channel treatment covers timing of proof generation (constant-time Poseidon) and recommends a relay at the network layer. It does not address the nonce issuance timing channel, which is distinct: it occurs at the *protocol layer* between the agent and the RS, observable by the AS through legitimate RS collusion. The relay recommendation is labeled "operational," not "required for IND-UNL-AS security."

**In-threat-model?** Yes. AS–RS collusion is explicitly permitted. The construction needs to either (a) specify that nonces MUST be agent-generated and merely countersigned by the RS, with the AS blind to nonce request timing, or (b) include nonce issuance timing in the formal side-channel treatment and define a mandatory blinding delay or batching protocol.

---

### Attack 4: `operatorPrivateKey` Is an Undeclared Signal — Nullifier Binding Is Underconstrained

**Attack:**
The security argument in Section 4 resolves the nullifier linkage problem by redefining the scope nullifier as:

```
scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)
```

But `operatorPrivateKey` does not appear in the private inputs table (Section 2). The circuit specifies `sigR8x, sigR8y, sigS` (EdDSA signature components) and `operatorPubkeyAx, operatorPubkeyAy`, but no private key signal. The `EdDSAPoseidonVerifier` gadget verifies `(R, S, A, M)` — it checks that a given signature is valid under the given public key, but it does NOT accept or constrain a separate `operatorPrivateKey` signal as an input. The public key and the private key are mathematically related but that relationship is NOT enforced by the EdDSA verifier gadget — it's established by the key generation procedure outside the circuit.

Without an explicit circuit constraint `operatorPrivateKey * G = (operatorPubkeyAx, operatorPubkeyAy)`, a malicious prover can:
1. Use a legitimate `credentialCommitment` (obtained from the on-chain tree) with a real operator public key
2. Supply an arbitrary field element `sk'` as `operatorPrivateKey` to compute `scopeNullifier = Poseidon2(scopeId, sk')`
3. The EdDSA signature check passes (it doesn't involve `sk'`)
4. The Merkle membership check passes (uses `credentialCommitment`, not `sk'`)
5. The circuit produces a valid proof with a prover-chosen nullifier

This breaks Sybil resistance entirely: a single enrolled credential can generate unlimited distinct nullifiers by varying `sk'`, one per proof, rendering the per-scope revocation mapping useless.

The constraint to fix this — a BabyJubjub scalar multiplication — costs approximately 3,200 additional constraints, which is absent from the Section 6 cost estimate (`~12,750` total). The real cost is `~15,950` constraints. This still fits under `pot16.ptau`, but the omission indicates the resolution in Section 4 was written as prose without being reflected back into the circuit spec.

**In-threat-model?** Yes — this is a soundness failure, not a side channel. Any prover with read access to the on-chain tree can exploit it. The construction must add `operatorPrivateKey` to the private inputs, add the Baby Jubjub scalar multiplication constraint, and revise the circuit cost estimate accordingly.


## Persona: spiffe_engineer

*Staff engineer who runs SPIFFE/SPIRE in production for a Fortune 500, co-author of WIMSE drafts. Stance: workload identity is a solved problem at the right layer.*

---

### Attack 1: scopeNullifier is a permanent stable identifier — your "unlinkable" construction creates a worse tracking vector than rotating SVIDs

**Attack:** The SPIFFE engineer observes that `scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)` (Section 2, constraint 8; Section 4 revised construction) is **deterministic and permanent** for a given `(agent, scope)` pair. `operatorPrivateKey` is fixed for the credential's lifetime; `scopeId` is fixed per RS. Every time the same agent accesses RS-Pharmacy, the on-chain registry records the identical `scopeNullifier`. RS-Pharmacy accumulates a permanent, stable pseudonym for this agent — frequency of visits, session timing, basket size correlations, whatever metadata RS-Pharmacy attaches to that identifier. Now the engineer points to the colluding RS capability in the threat model (Section 3): A colludes with *any subset* of RSes. If A colludes with RS-Pharmacy, A receives `(nullifier_pharmacy, T1, T2, T3, ...)` — a longitudinal behavioral log under a stable identifier. In SPIFFE, X.509 SVIDs rotate every hour by default via the Workload API. A compromised SPIRE server gets `(sub, T1)` and `(sub, T2)`, but after the next rotation the correlation window closes. The Bolyra construction provides **zero temporal unlinkability within a scope**: the nullifier never rotates unless the operator re-enrolls with a new key pair, which is not modeled or required by the protocol.

**Why it fails / works against the construction:** The IND-UNL-AS game (Section 3) is defined as a *cross-scope* distinguishing game — agent `b` at `scope_A` vs. agent `1-b` at `scope_B`. It says nothing about the longitudinal, *within-scope* attack. The construction survives the game as stated. But the deployment scenario (Section 7, Step 4) claims "RS-Pharmacy does NOT learn the agent's identity" — this is only true for the first visit. After `k` visits, RS-Pharmacy holds a behavioral profile indexed by the permanent `scopeNullifier`. If A colluded with RS-Pharmacy from the start, A has a fully deanonymized longitudinal record before any cross-scope correlation is attempted. The construction addresses unlinkability *between* scopes but explicitly creates *linkability within* a scope for Sybil prevention, without bounding the exposure this creates to a colluding RS.

**In-threat-model?** No — the threat model explicitly permits RS collusion but the IND-UNL-AS game does not define an advantage for the within-scope longitudinal attack. The construction must either (a) define and bound this exposure formally, (b) introduce nullifier rotation (e.g., `Poseidon3(scopeId, operatorPrivateKey, epoch)`) with an epoch committed on-chain, or (c) explicitly exclude within-scope longitudinal RS adversaries and state the residual risk.

---

### Attack 2: The IND-UNL-AS game excludes multi-session queries — a stronger game trivially breaks the scopeNullifier

**Attack:** The WIMSE engineer reads Section 3 carefully. The challenge phase grants A exactly **two proofs** (`π_A` at `scope_A`, `π_B` at `scope_B`), one per scope, one query each. The adversary A does not get an oracle for additional proofs. But the actual deployment scenario (Section 7) has the agent accessing RS-Pharmacy and RS-Grocery *repeatedly* across sessions. The engineer constructs a stronger game: A is an adaptive chosen-scope adversary who submits `q` scope queries before the challenge. Concretely, A submits `(scope_A, agent_0)` as a legitimate request and receives the resulting on-chain `scopeNullifier_A0 = Poseidon2(scope_A, sk_0)`. A also knows `credentialCommitment_0` from the Merkle tree. Now in the challenge phase, A receives `π_A` containing `scopeNullifier` and compares: if `scopeNullifier == scopeNullifier_A0`, then `b = 0`. The game collapses because A pre-queried the same scope. The construction's Step 3 reduction (Section 4) explicitly notes that "A knows both `cc_0` and `cc_1` (they are in the Merkle tree)" and resolves this by using `operatorPrivateKey` as the PRF key. But the game definition does not model adaptive pre-queries. A proper IND-UNL-AS game requires an oracle `OProve(agent, scope)` callable before the challenge, with a restriction that `(agent_b, scope_A)` is never queried — and the proof that the oracle doesn't help must be explicit. The WIMSE architecture draft (Section 5, draft-ietf-wimse-arch) defines workload token proofs in a multi-session model with per-session token binding; this construction's single-shot game is weaker by construction.

**Why it fails / works:** The reduction sketch in Section 4 argues that A's view of the nullifiers is PRF-indistinguishable *without* the pre-query capability. This is correct for the single-shot game. But the real protocol runs in a multi-session, multi-agent environment where A (the AS) observes every enrollment and every on-chain verification across all sessions. The single-shot game doesn't capture this. The argument that `scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)` is PRF-secure holds when `operatorPrivateKey` is secret — but A observes `scopeNullifier` values on-chain across many proofs and can build a lookup table `{(scope, nullifier) → agent}` by correlating enrollment timestamps, permission bit patterns, and the fact that the same `scopeNullifier` recurs for repeat visits (see Attack 1). The game definition doesn't prohibit A from building this table.

**In-threat-model?** No — the IND-UNL-AS game as defined is single-shot and non-adaptive. The construction must upgrade to a multi-session adaptive game (game with `OProve` oracle, standard restriction on challenge queries) and prove security in that model, or explicitly bound the adversary's advantage to the single-shot scenario and argue why real deployments don't enable adaptive queries.

---

### Attack 3: scopeId is a public input on-chain — global traffic analysis breaks the merchant-graph privacy claim without touching the cryptography

**Attack:** The SPIFFE engineer ignores the ZK proof entirely and looks at what's on-chain. `scopeId` is listed as a **public input** in Section 2 (Public inputs table, row 1) and appears in the registry's public signal layout (Section 2, index 4). In the deployment scenario (Section 7, Step 4), the engineer reads: "Cascade FCU sees `scopeId_pharmacy` and `scopeId_grocery` on-chain." This is treated as a non-issue because "Cascade FCU cannot associate either with the member's agent." But the engineer asks a different question: *the global traffic graph of* `(scopeId, timestamp, agentMerkleRoot)` tuples *is publicly visible to any on-chain observer, not just Cascade FCU.* In the cross-credit-union scenario, there are 5 member CUs sharing one Merkle tree. An external analyst (or a colluding RS that participates in multiple industry networks) observes:

```
T=09:23:01  scopeId=Poseidon("pharmacy.rx-network.org")  root=0xabc
T=09:23:47  scopeId=Poseidon("grocery.freshmart.com")    root=0xabc
T=09:24:02  scopeId=Poseidon("pharmacy.rx-network.org")  root=0xabc
```

Two pharmacy hits bookending one grocery hit, in 61 seconds, same root. Without breaking any cryptography, this is a behavioral fingerprint. The `agentMerkleRoot` is identical for all agents in the same tree — the construction correctly notes this in Step 4 ("shared across all agents"). But the temporal clustering of `scopeId` values across on-chain events is exploitable. With `K` total agents in the tree and `M` scopes, an analyst correlates temporal clusters to infer that the same agent produced the clustered events. In SPIFFE, SVIDs are presented to RSes directly over mTLS — no on-chain broadcast, no global traffic graph, no external observer.

**Why it fails / works:** Section 4 under "Timing" says: "agents SHOULD submit proofs for multiple scopes in a single batched transaction or use a relay/mixer." This is explicitly an operational recommendation, not a circuit-level property. The formal IND-UNL-AS game gives A "timing metadata" capability (Section 3, adversary capabilities). But the game's challenge phase produces exactly two proofs at two scopes simultaneously — there is no temporal clustering to exploit in the game. Real deployments produce proofs sequentially over minutes or hours, creating exactly the clustering this attack exploits. The construction acknowledges the gap but defers it to operational recommendations without modeling it in the security proof.

**In-threat-model?** Partially — timing is listed as an adversary capability but the IND-UNL-AS game does not model sequential, temporally-correlated proof submission. The construction should either (a) include a relay/mixer as a required protocol component (not a SHOULD), (b) model timing correlation formally in the game, or (c) explicitly bound the anonymity set size and the timing correlation risk as out-of-scope with a citation to a separate network-layer privacy mechanism.

---

### Attack 4: "Extend SPIFFE with a ZK attestor" — the claimed AS-removal property is already provided by the SPIRE Workload API

**Attack:** The engineer fires the sharpest SPIFFE objection at Section 8, item 1: *"The AS is in the issuance hot path — Bolyra removes it entirely."* The SPIFFE engineer responds: this is precisely what the SPIRE Workload API already does. The SPIRE agent runs as a daemonset colocated with the workload. The workload calls the Workload API over a local Unix domain socket to obtain an X.509 SVID or JWT-SVID without any per-request contact with the SPIRE server. The SPIRE server is only involved during **SVID rotation** (default: 1-hour TTL, rotation at 50% lifetime). A workload making 1,000 scoped requests per hour contacts the SPIRE server exactly twice — at rotation boundaries. The AS is not in the hot path. The SPIFFE engineer then points at the WIMSE architecture draft (draft-ietf-wimse-arch, Section 4.2, Workload Token): a JWT-SVID with audience restriction (`aud: pharmacy.rx-network.org`) is issued by the SPIRE agent locally and verified by RS-Pharmacy directly. The SPIRE server never sees the per-scope request. The construction's key differentiation claim in Section 8 item 1 does not distinguish Bolyra from a correctly deployed SPIFFE/WIMSE stack. The *actual* differentiation is that Bolyra provides cryptographic unlinkability across scopes even when the operator's identity is known to the SPIRE server — but this is never stated as the core claim in Section 8.

**Why it fails / works:** The engineer is correct that the AS-removal argument does not differentiate Bolyra from SPIFFE in terms of per-request AS involvement. Where the construction's argument is valid but understated: in SPIFFE, the SPIRE server at enrollment time knows exactly which workload (by SPIFFE ID) has which capabilities, and can correlate `(workload_id, scope)` at any SVID rotation. In Bolyra, the AS enrolls `credentialCommitment = Poseidon5(...)` and never learns which scope the agent later proves against — the Merkle root is public but the leaf-to-agent mapping requires the private key. **This is the genuine gap**, but the construction's Section 8 argues it poorly: item 1 conflates "AS not in per-request hot path" (which SPIFFE matches) with "AS cannot correlate per-scope accesses" (which SPIFFE cannot match and Bolyra can). The SPIFFE ZK-attestor extension the engineer proposes would add a ZK attestor plugin to SPIRE that issues anonymous Merkle membership proofs instead of signed SVIDs — this is architecturally cleaner than a standalone protocol and would inherit SPIFFE's federation model, WIMSE's token binding, and the existing ecosystem. The construction must argue why this extension path is insufficient (likely: SPIRE's attestor model requires the SPIRE server to attest the workload at enrollment, reintroducing the AS-knows-identity problem), but it does not make this argument.

**In-threat-model?** The attack on the AS-removal claim is valid: the construction overstates differentiation from SPIFFE. The actual differentiation is **AS-level unlinkability post-enrollment**, not AS removal from the hot path. The construction survives if it reframes Section 8 item 1 to the correct claim: "The AS enrolls a cryptographic commitment, not an identity. Post-enrollment, the AS cannot learn which scopes the agent accesses because the ZK proof reveals only Merkle membership, not the leaf. SPIFFE's SVID issuance at rotation reveals `(SPIFFE-ID, audience)` to the SPIRE server at each rotation boundary." This is falsifiable and accurate; the current framing is not.
