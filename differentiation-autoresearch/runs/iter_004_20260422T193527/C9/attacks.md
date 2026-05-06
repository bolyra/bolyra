# Tier 3 Adversarial — C9 Forward-secure agent delegation

## Persona: auth0_pm

---

### Attack 1: The r_T Fiction — Your Game Excludes the Realistic Compromise Vector

- **Attack:** Section 3 explicitly excludes `r_T` from the adversary's compromise package: *"Adversary does NOT receive `r_T` (modeling immediate rotation or secure enclave isolation of blinding factors)."* But the scenarios the construction advertises — a 30-day lending agent whose key leaks on Day 31, a whistleblower agent that gets seized — are **memory compromise events**. In every realistic credential theft scenario (malware, memory forensics, compromised secure enclave firmware), `s_T` and `r_T` are co-located in the same process heap. They're both live. The game games this away by definitional fiat.

  The construction admits the degradation in plain text (Section 3, "Residual"): *"If the adversary also obtains `(s_T, r_T)`, the claim degrades to requiring relayer-mediated rotation transactions (operational mitigation) rather than a pure cryptographic guarantee."* That's not a hedge — that's the main threat model for the exact scenarios you're selling.

- **Why it works / why it fails:** The IND-FS-AGENT game is correctly specified for the case where `r_T` is isolated (HSM, TEE). But the claimed differentiator over DPoP — *"compromise of the key retroactively reveals the agent's prior activity graph"* — requires that the adversary gets `s_T` without `r_T`. If they co-reside (which they do in any software agent), the construction falls back to an operational mitigation (relayer + archive-node archaeology difficulty) that WorkOS already handles equivalently via short-lived token TTLs and access log segmentation.

- **In-threat-model?** **No — construction must address.** The game should either (a) prove security under `(s_T, r_T)` compromise with a Merkle anonymity set construction (deferred per Section 3) or (b) bound the claim precisely: *"forward secrecy holds iff `r_T` is HSM-isolated,"* and then justify that credit union agent deployments will actually do this.

---

### Attack 2: EpochCommitment Is a Public Input to Session Proofs — Chain Traversal Survives r_T Compromise

- **Attack:** Section 2.5 lists `epochCommitment` as a **public input** to `ForwardSecureAgentSession`. Every tool-call proof the agent emits is permanently tagged with `epochCommitment_e = Poseidon2(s_e, r_e)`. If the adversary recovers `(s_T, r_T)` — see Attack 1 — they compute `epochCommitment_T` and can grep every session proof ever submitted for that value. That reveals the full tool-call log for epoch T. The `previousEpochCommitment` chain then exposes epoch T-1, T-2, and so on via archive node traversal.

  Section 3 admits this: *"If the adversary recovers `(s_T, r_T)` AND has archive node access AND `epochCommitment` appears as a public input in session proofs, the adversary can correlate sessions to epochs."* The mitigation — *"a structural change deferred to a future iteration"* — means the construction does not currently deliver forward secrecy in the `(s_T, r_T)` case, which is the realistic case.

- **Why it works / why it fails:** The construction correctly identifies this gap and correctly defers it. The problem is the **main claim** — *"sessions executed before T remain cryptographically unlinkable and non-replayable"* — is stated unconditionally in Section 1 and then conditionally qualified in Section 3. A buyer reading the abstract gets a different promise than a buyer reading the threat model. Auth0's product team will surface exactly this inconsistency in a security review.

- **In-threat-model?** **No — construction must address.** The fix (Merkle tree of epoch commitments, inside-proof membership) is known. Until it's shipped, the claim should be scoped: *"forward secrecy holds assuming `r_T` is not recoverable at compromise time."*

---

### Attack 3: The Latency Tax Kills Interactive Agent Deployments

- **Attack:** Section 6 estimates `ForwardSecureAgentSession` at ~5 seconds proving time. In an MCP context, a "session" is underspecified — is it one proof per conversation turn? Per tool call? Per OAuth token issuance? If it's per tool call, a Claude agent making 20 tool calls in a loan-origination workflow generates 100 seconds of proving overhead per user interaction. If it's per token issuance (more likely), what's the token TTL and reuse model?

  WorkOS issues MCP auth tokens in under 100ms. Auth0 AI's MCP integration (cited in toolbox) uses standard OAuth 2.1 with DPoP — sub-10ms per operation after initial token grant. The construction's Section 8 argues DPoP is inferior on *linkability after compromise*, but doesn't argue on *latency*, and credit union procurement will weight latency at least as heavily as post-compromise unlinkability for a lending agent.

  More precisely: the construction doesn't specify whether `ForwardSecureAgentSession` is generated once per OAuth token grant or once per tool call. The claim "sessions and delegations executed before T remain unlinkable" suggests session-level granularity — but if sessions map to token grants with 1-hour TTLs, then epoch boundaries need to be sub-hour, and the EpochRotation circuit (~<1s) runs hourly, which is fine. But then all tool calls within an hour are linkable to each other — the session proof for each tool call uses the same `epochCommitment`. That's a much weaker guarantee than the abstract implies.

- **Why it works / why it fails:** The latency argument partially fails if sessions = token grants (standard OAuth model). But the linkability argument still applies within an epoch: all tool calls in epoch T share the same `epochCommitment` public input, making them linkable to each other (though not to prior epochs). The construction needs to state whether intra-epoch linkability is in or out of scope.

- **In-threat-model?** **Partially.** Latency is not a cryptographic concern, but the session definition gap — what granularity generates a proof — is a correctness concern for the unlinkability claim.

---

### Attack 4: The Buyer Question — What Does This Solve That My Vendor Risk Team Will Approve?

- **Attack:** Your three deployment scenarios are: a 30-day autonomous lending agent, a CFPB whistleblower relay, and a model rotation compliance use case. Two of three are edge cases no credit union compliance officer has ever written a control for. The third (model rotation) is addressed by standard key rotation + short-lived tokens in every OAuth library.

  When SECU's CISO asks *"why Bolyra instead of WorkOS?"*, the answer requires explaining IND-FS-AGENT games, Poseidon PRFs, and epoch secret derivation. That's a failed sales motion. WorkOS has SOC 2 Type II, a shared responsibility model, a 99.9% SLA, and existing credit union references. Bolyra has a solo founder and a PLONK circuit.

  More specifically: the threat the construction defends against — *"adversary obtains the signing key and reconstructs the prior activity graph"* — requires the adversary to have already compromised the agent. At that point, SECU has bigger problems (the adversary can observe real-time tool calls regardless of forward secrecy). The construction is solving for the forensic-analysis-after-exfiltration case, which is a real but narrow threat. No enterprise buyer has "post-compromise activity graph unlinkability" in their vendor questionnaire.

- **Why it works / why it fails:** This is a genuine GTM gap, not a cryptographic one. The construction is technically interesting. The question is whether any credit union procurement process will approve a novel ZK protocol from a solo founder when WorkOS exists and covers the 95th-percentile MCP auth use case. The scenarios need to be re-cast in NCUA examination language, not cryptography-paper language, to land with the actual buyer.

- **In-threat-model?** **No — construction must address at the GTM layer.** The construction needs a buyer-level threat narrative: *"Your agent's activity log is subpoenaed or leaked. Here's what happens with WorkOS (full history exposed) vs. Bolyra (nothing recoverable)."* That's the sentence that clears procurement. Without it, the technical correctness of IND-FS-AGENT is irrelevant.


## Persona: cryptographer

Applied cryptographer. My standard: if the threat model has an assumption that conveniently rules out the hardest case, that assumption IS the attack surface. Let me work through this construction.

---

### Attack 1: The IND-FS-AGENT Game Is Rigged — r_T Exclusion Is an Operational Assumption Dressed as a Cryptographic One

**Attack:**
The adversary's capability in the game (§3) is defined as: receives `s_T` and credential key material, but explicitly does **not** receive `r_T`. The justification is "modeling immediate rotation or secure enclave isolation of blinding factors."

But the construction's top-level claim (§1) says: *"If an agent's signing key is compromised at time T, sessions and delegations executed before T remain cryptographically unlinkable."* No mention of `r_T`. The claim is unconditional on signing key compromise; the game is conditional on `r_T` also being safe.

The attacker who can read `s_T` from process memory or a leaked keystore almost certainly reads `r_T` from the same allocation. Both are field elements; both live in the same secure enclave or the same memory region. Requiring them to be independently managed and independently destroyed is **doubling the key-management burden** while presenting the scheme as a single-secret solution.

Under the more natural game where the adversary receives `(s_T, r_T)` — the full runtime state at compromise time — the construction's own §3 ("Residual: chain traversal via previousEpochCommitment") concedes the attack works: adversary computes `epochCommitment_T = Poseidon2(s_T, r_T)`, identifies the rotation transaction on-chain, and walks the `previousEpochCommitment` linked list backward through the archive node. The mitigation is then relayer obfuscation — an **operational** control, not a cryptographic guarantee.

**Why it matters:**
The construction degrades exactly to the baseline in the natural compromise scenario. DPoP also fails on key compromise; Bolyra also fails on `(s_T, r_T)` compromise, just with an extra step of archive-node traversal. The gap is an operational assumption, not a reduction.

**In-threat-model?** No — the game definition excludes the natural adversary. The construction must either (a) prove security when `r_T` is also compromised (requires anonymity-set construction, deferred), or (b) explicitly restate the claim as conditional on `r_T` being independently hardware-isolated, which is a much weaker product claim than §1 makes.

---

### Attack 2: Intra-Epoch Sessions Are Trivially Linked — The Epoch Commitment Is a Public Correlator

**Attack:**
`ForwardSecureAgentSession` (§2.5) exposes `epochCommitment` as a **public input** to every session proof. All sessions within epoch `e` share `epochCommitment_e = Poseidon2(s_e, r_e)` as an identical public value. An adversary observing two on-chain session proofs with the same `epochCommitment` value trivially knows they came from the same agent in the same epoch.

The IND-FS-AGENT game (§3) picks challenge transcript `τ_b` from **two transcripts from the same epoch** `e*`. By the circuit structure, both transcripts carry the identical `epochCommitment_{e*}` public input. The distinguishing advantage is 1, not negligible — the adversary just checks whether both transcripts' `epochCommitment` fields match and, if so, they are linked.

The reduction in §4 (Case 2) claims commitments are hiding by A5. But A5 says `Poseidon2(s, r)` with unknown `r` is indistinguishable from random — this says an *external party* who doesn't know `s` or `r` can't learn `s`. It does **not** say two transcripts bearing the same value can't be correlated. Hiding protects the *preimage*; it says nothing about *value equality* as a correlator.

**Why it matters:**
For the 30-day lending agent scenario (§7): 30 epochs × however many daily tool calls, all calls on day `e` carry `epochCommitment_e`. A passive observer (including the AS, RS, or on-chain analytics) trivially clusters sessions by epoch. Intra-epoch activity graph is fully exposed. The claim of "sessions remain cryptographically unlinkable" (§1) is false within an epoch. The construction provides inter-epoch forward secrecy but zero intra-epoch privacy.

**In-threat-model?** No — the construction makes no statement about intra-epoch unlinkability and the game's challenge transcripts being from the same epoch `e*` renders the game trivially winnable by value equality. Either the epoch commitment must not appear as a cleartext public input (e.g., prove membership in a Merkle root of all agent commitments without revealing which one), or the security claim must be scoped to cross-epoch linkability only.

---

### Attack 3: The On-Chain Commitment Graph Is a Public Linked List — Archive Node Traversal Requires Only One Anchor Point

**Attack:**
`EpochRotation` (§2.4) emits `previousEpochCommitment` as a **public input** and `newEpochCommitment` as a **public output**. On-chain, every rotation transaction has the form `(prev_C, new_C)` in the clear. This is a **publicly traversable linked list**: given any single commitment value `C` in the list, every predecessor commitment is readable from archive-node history by following `prev_C` pointers.

The construction defends against an attacker entering the chain at `epochCommitment_T` because that requires `r_T`. But there are other entry points:

1. **Enrollment transaction.** The agent's first enrollment presumably registers `epochCommitment_0 = Poseidon2(s_0, r_0)`. If enrollment transactions are identifiable (e.g., a specific registry method, or they carry an operator signature that reveals the agent slot), an adversary can anchor to `epochCommitment_0` and traverse forward — no `s_T` or `r_T` needed.

2. **Session proof anchor.** An adversary who can correlate even one session proof to a known agent (e.g., via application-layer metadata, timing, or a coercion order to the operator) learns one `epochCommitment_e`. From there, the entire chain backward and forward is readable.

3. **Relayer deanonymization.** §3's mitigation suggests using a relayer (Tornado Cash pattern) to prevent linking the sender of the rotation transaction to the agent. But the relayer only hides the transaction sender — not the `previousEpochCommitment` value, which remains in calldata. Any two rotation transactions sharing a `previousEpochCommitment / newEpochCommitment` chain are publicly linked regardless of sender.

The reduction in §4 (Case 5) argues that without `r_T`, the adversary "cannot initiate" chain traversal. This is correct only if all entry points are blocked. The construction secures one entry point (`epochCommitment_T`) but leaves enrollment and session-anchor entry points open.

**In-threat-model?** Partially. The game as written delivers `s_T` (not `r_T`) and asks about pre-T sessions. The commitment-chain traversal via `previousEpochCommitment` is acknowledged as a residual (§3). But the construction's threat model does not include an adversary who obtains one `epochCommitment_e` value by non-key-material means (application-layer coercion, timing attack on session proofs, enrollment transaction identification). That is a material gap for the whistleblower scenario (§7).

---

### Attack 4: The ZK Simulator Is Invoked but Never Constructed — HVZK Does Not Imply Session Proof Privacy Against the On-Chain Verifier

**Attack:**
§4 Case 4 states: *"PLONK proof. Zero-knowledge simulator exists in ROM."* This is an assertion without a simulator description. Two problems:

**4a. PLONK's ZK is honest-verifier ZK (HVZK).** Standard PLONK achieves HVZK: the simulator works when the verifier's random challenges are drawn honestly. The on-chain verifier is deterministic — it evaluates a fixed verification equation. Whether the PLONK instantiation used here achieves *simulation-extractable* ZK (SE-ZK, required for non-malleable composability under UC) is not stated. SE-ZK requires the prover's randomness to be used in a specific way that prevents an adversary from re-randomizing a proof to produce a new valid proof for a different statement. Without SE-ZK, an adversary who sees a valid `ForwardSecureAgentSession` proof can potentially produce a new proof for a different `epochNullifier` paired with the same `epochCommitment`, enabling a linkage attack outside the standard nullifier-reuse check.

**4b. The session public transcript leaks structure.** The public outputs of `ForwardSecureAgentSession` include `epochNullifier`, `scopeCommitment`, and `epochCommitment`. Even if the PLONK proof itself is ZK, these public I/O values are in the clear. An adversary who does not know `s_e` can still compute the set of *consistent* `(epochCommitment, scopeCommitment, epochNullifier)` tuples across all observed transcripts and check for structural patterns (same scopeCommitment = same policy, same epochCommitment = same epoch, etc.). The ZK property of the proof doesn't protect public signals — it only protects the witness. The privacy claim requires those public signals to be pseudorandom, which is A2+A5, but the simulator argument is irrelevant to them.

**Why it matters:**
If PLONK is only HVZK here, then in a multi-verifier setting (e.g., multiple resource servers each verify the proof), an adversary controlling one verifier can use non-standard challenges to extract witness information. The construction should specify which PLONK variant is used, whether it achieves simulation-extractability, and give an actual simulator description for the specific circuits, not a generic appeal to "ROM."

**In-threat-model?** The game as stated does not model a malicious verifier. But the scenarios in §7 involve a resource server that is a distinct party from the operator — a colluding RS could run the PLONK verifier with chosen challenges. The construction's ZK claim needs to specify HVZK vs. malicious-verifier ZK vs. SE-ZK, since the application threat model arguably includes a malicious RS.


## Persona: cu_ciso

---

### Attack 1: The Secure Deletion Assumption Is Not a Control — It's a Gap

**Attack:** I pull out NCUA Part 748, Appendix A, §II.B and GLBA Safeguards Rule 16 CFR §314.4(f)(2), which both require documented controls for the *destruction* of sensitive information. I then ask the construction author to show me their deletion log.

The construction's entire forward-secrecy guarantee rests on the phrase "secure deletion assumption" in §3: *"Does NOT have deleted epoch secrets s_e for e < T or blinding factors r_e for e < T (secure deletion assumption)."* That sentence is doing enormous work. The IND-FS-AGENT game simply *stipulates* the adversary doesn't hold the deleted values — it does not provide a mechanism to prove deletion occurred. §8.3 even acknowledges the problem ("Memory forensics can recover 'deleted' keys") and then waves it away by saying the construction is "a property of Poseidon preimage resistance + hiding commitments, not runtime hygiene." But in my NCUA exam, I can't hand the examiner a Poseidon preimage resistance reduction. I need a control.

Where is the key ceremony record? Who witnessed the epoch rotation and confirmed deletion? What HSM, TEE, or secure enclave enforces `r_e` destruction? What is the retention schedule for the deletion audit log? The construction specifies none of this. It names the assumption but does not close it.

**Why it works / why it fails against the construction:** The construction *names* the gap in §3 (the "honest limitation" paragraph) but defers the fix. The IND-FS-AGENT game excludes `r_T` from the adversary model by definition, not by a deployed control. An NCUA examiner doesn't accept game definitions as evidence of control implementation. This attack lands.

**In-threat-model?** No — the construction must address this. Required additions: a concrete key custody architecture (HSM key slot erasure, TEE ephemeral memory, or at minimum a tamper-evident deletion log), and a mapping from that architecture to NCUA Part 748 Appendix A §II.B and GLBA §314.4(f)(2).

---

### Attack 2: The Construction Destroys the Audit Trail NCUA Requires Me to Maintain

**Attack:** I cite NCUA Part 749 (Records Preservation), BSA/AML recordkeeping requirements (31 CFR §1020.410), and CFPB UDAAP supervision expectations. Then I read the construction's own value proposition back to the author:

*"30 on-chain commitments Poseidon2(s_e, r_e) are indistinguishable from those of every other enrolled agent."*

That sentence is catastrophic for my exam. The construction is designed so that a compromised key cannot be linked to prior sessions. That is *also* a description of a system where I, the credit union, cannot link prior sessions to member accounts in response to a regulator subpoena.

Section 7 describes "30 days of loan processing" — but NCUA expects me to produce, on demand, a complete audit trail of every agent decision that affected a member's loan file. The ZK session proofs prove policy compliance to the verifier, but the *content* of what the agent did (which member, which loan, which decision, which dollar amount) is not in the proof — it's in application logs that are entirely external to this construction. The construction says nothing about how those logs are keyed, retained, or correlated back to an epoch. If the construction is actually *achieving* unlinkability end-to-end, I've just built a system that is audit-proof against my own regulators.

**Why it works / why it fails against the construction:** This is a design-level gap, not a cryptographic one. The construction achieves unlinkability at the ZK layer but is silent on whether the application layer maintains the NCUA-required audit trail separately. If it does, the ZK unlinkability is partially illusory (a subpoena hits the application log). If it doesn't, the credit union is non-compliant. Neither answer is in the spec.

**In-threat-model?** No — the construction must address this. It needs a section explicitly mapping: (a) what records the credit union retains in a separate audit log, (b) how those records are keyed to members (not to ZK nullifiers), and (c) how that log survives without undermining the forward-secrecy claim at the ZK layer.

---

### Attack 3: "As in Tornado Cash" Is a Board-Level Career Event

**Attack:** I read §3 aloud to my board: *"rotation transactions SHOULD be submitted via a relayer (standard ZK pattern, as in Tornado Cash)."*

Tornado Cash was sanctioned by OFAC in August 2022 under 31 CFR §598. FinCEN issued guidance in 2023 on virtual currency mixing services. Any credit union CTO who puts "Tornado Cash architecture pattern" in a system design document has just created an exhibit for the next BSA/AML examination. I don't care that the construction is citing a *technical pattern* — the examiner reading the vendor assessment document will not parse that distinction. The compliance and reputational blast radius of that citation is larger than the security benefit of the relayer pattern.

Beyond the citation problem: the relayer is presented as the *primary* operational mitigation for the residual chain-traversal attack (§3, "mitigable by registry design"). That means the forward-secrecy guarantee in a deployed credit union environment degrades from a cryptographic property to "trust your relayer operator." Who runs the relayer? What is their BSA/AML program? What happens when they go offline during an epoch rotation window? The construction doesn't answer these questions.

**Why it works / why it fails against the construction:** The construction correctly identifies the relayer as a defense-in-depth measure, not the primary security mechanism. But the Tornado Cash reference will trigger an immediate compliance review at every regulated institution. Separately, the relayer introduces a third-party dependency with no SLA, no SOC 2 mapping, and no NCUA vendor management assessment path — all required under NCUA Letter 07-CU-13 and the 2023 NCUA third-party risk guidance.

**In-threat-model?** No — the construction must address this. Replace the Tornado Cash reference with a neutral technical description. Add a relayer vendor management requirement section mapping to NCUA 07-CU-13: contractual SLA, SOC 2 Type II or equivalent, business continuity provisions, and a BSA/AML attestation.

---

### Attack 4: The On-Chain Registry Has No SLA and Cannot Be in My Core-Processor Failover Plan

**Attack:** I open the FFIEC CAT and turn to the Business Continuity domain. Then I ask: what is the availability SLA of the on-chain registry, and what happens to agent sessions if the registry is unavailable during an epoch rotation?

Section 2.4 says the registry "MUST atomically set `consumedEpochCommitment[previousEpochCommitment] = true` and update `currentEpochCommitment[agentSlot] = newEpochCommitment`." This is a hard dependency on a blockchain write achieving finality before the agent can operate in the new epoch. No blockchain — public or permissioned — offers the five-nines availability my core processor contract requires. Ethereum mainnet has had multiple multi-hour degraded periods. Permissioned chains (Hyperledger, Besu) require their own infrastructure with their own DR plans.

More operationally: the epoch rotation window is unbounded in the construction. If the agent needs to rotate at midnight (daily rotation in the SECU scenario, §7) and the registry is congested or offline, what happens? Does the agent operate on a stale epoch commitment? Does it halt? The construction says nothing about the failure mode, which means my Tier 1 ops team at 2am is looking at a ZK circuit error with no runbook.

**Why it works / why it fails against the construction:** The construction specifies the registry's *correctness* requirements (atomic write, consumption map) but not its *availability* architecture. For a credit union, availability is a regulatory requirement, not a preference — NCUA examines Business Impact Analyses and RTO/RPO for critical systems. A ZK registry with undefined failover behavior cannot be classified as anything other than a critical third-party dependency with a missing vendor assessment.

**In-threat-model?** No — the construction must address this. Required: a deployment section specifying (a) acceptable registry substrates with their availability profiles, (b) the epoch rotation failure mode and whether graceful degradation to the prior epoch is safe under the forward-secrecy model, and (c) an RTO/RPO statement that can be inserted into the credit union's BIA and reviewed by NCUA under the IT examination handbook's Business Continuity module.


## Persona: rfc7662_advocate

### Attack 1: epochCommitment Is a Persistent Correlator Requiring Zero Key Material

- **Attack:** `ForwardSecureAgentSession` (§2.5) lists `epochCommitment` as a **public input** to every session proof. `EpochRotation` (§2.4) emits `previousEpochCommitment` and `newEpochCommitment` as public I/O, permanently linking the commitment chain on-chain. An adversary who can attribute *any single session proof* to the target agent — by scope content, timing, operator credential, or external correlation — immediately recovers that epoch's `epochCommitment`. They then traverse the EpochRotation chain in either direction via archive node to recover every prior epoch commitment, and match all remaining session proofs to the agent. No key material required. `s_T` is irrelevant. RFC 9449 DPoP has no analogous public correlator chain: there is no on-chain structure linking DPoP proofs across sessions.

- **Why it fails against the construction / Why the construction hasn't addressed it:** The construction openly concedes this in §3 ("Honest Limitation"): "the adversary can correlate sessions to epochs and thus to the agent" and "Full mitigation of this residual would require an anonymity-set construction… a structural change deferred to a future iteration." Yet §1 states flatly that pre-T sessions "remain cryptographically unlinkable." The claim is unconditional; the security argument is conditional on an anonymity set that doesn't exist yet.

- **In-threat-model?** **No — construction must address.** The claim in §1 overstates what the current circuits provide. The correct claim is: *sessions remain unlinkable provided no session proof's `epochCommitment` is attributable to the agent through any auxiliary channel.* That is a much weaker, operationally-contingent statement.

---

### Attack 2: The IND-FS-AGENT Game Excludes r_T Without Cryptographic Justification

- **Attack:** The game (§3) awards the adversary `s_T` but stipulates they do NOT receive `r_T`, justified as "modeling immediate rotation or secure enclave isolation of blinding factors." But `s_T` and `r_T` are both field elements residing in the same process heap at epoch T. A memory-forensics adversary who recovers `s_T` via a key leak (the stated scenario: leaked agent key in a public repo) almost certainly recovers the co-resident `r_T` as well — they're sampled in the same code path before `s_T` is handed off. The construction itself acknowledges in §3: "The claim degrades to requiring relayer-mediated rotation transactions (operational mitigation) rather than a pure cryptographic guarantee" when `r_T` is available. Contrast §8.3, which dismisses the RFC baseline: "No proof of deletion exists in any RFC. Memory forensics can recover 'deleted' keys." This critique applies symmetrically to `r_T` inside the Bolyra agent process.

- **Why it works:** The construction's security proof is purchased by excluding `r_T` from the compromise model. That exclusion is an *operational* assumption (secure enclave, immediate zeroization) dressed up as a game parameter. The RFC 7662 baseline can make exactly the same move: "assume the AS's session log is zeroized immediately after token issuance." Neither side has a *cryptographic* separation between the two values — both rely on runtime hygiene. The IND-FS-AGENT game is not a stronger model than the baseline; it simply moves the operational assumption from "AS deletes logs" to "enclave zeroizes r_T."

- **In-threat-model?** **No — construction must address.** The game definition should either (a) include `r_T` in the compromise material and prove security anyway, or (b) explicitly bound the security claim to a hardware-attested enclave that cryptographically proves `r_T` destruction, referencing a concrete attestation scheme. As written, the game parameter is question-begging.

---

### Attack 3: DPoP Per-Session Ephemeral Keys Achieves Equivalent Post-Compromise Unlinkability

- **Attack (RFC 9449 §11.1):** The claim (§8.1) says the baseline fails because "AS logs `sub + jkt` per session." But nothing in RFC 9449 mandates permanent AS-side jkt logging. Consider: agent generates a fresh DPoP key pair `(sk_session, pk_session)` per session, deletes `sk_session` after token use, and the AS issues a token bound to `jkt_session = SHA-256(JWK_session)` but stores only the token hash, not the jkt, post-issuance. Combine with OIDC PPID (`sub` is pairwise per RS, RFC 8176). Now: compromise of the agent's *long-term* credential at T reveals the long-term key, but every prior session used an independent ephemeral key. The adversary cannot link sessions across different `jkt_session` values because the ephemeral private keys are gone. The construction's counter (§8.1) relies entirely on AS logging behavior — an operational choice, not a cryptographic inevitability.

- **Why it partially fails:** The ZK construction does have one genuine advantage: the AS is *not on the path at all* for session verification — the on-chain verifier is trustless. A DPoP solution with a non-logging AS still requires trusting that the AS doesn't log, doesn't get subpoenaed, and correctly implements PPID. Bolyra's unlinkability is AS-independent. But the claim that "no bearer-token or DPoP-bound construction achieves this" is too strong. The correct claim is: *no construction achieves this without trusting the AS's logging policy*, which is a meaningful but narrower statement.

- **In-threat-model?** **Partially.** The construction survives if the claim is reframed as "AS-trust-independent forward secrecy." The current §8.1 argument is too dismissive — it defeats a strawman (logging AS) rather than the strongest RFC 9449 configuration. The differentiation section must engage with per-session ephemeral DPoP keys + PPID explicitly, or the comparative claim is vulnerable.

---

### Attack 4: The Relayer Mitigates Transaction Sender, Not Public Circuit Inputs — Chain Is Always Visible

- **Attack:** §3 cites "relayer-mediated rotation transactions (standard ZK pattern, as in Tornado Cash)" as mitigating chain traversal by forcing "archive-node archaeology." This is wrong about what relayers do. A relayer hides the *Ethereum sender address* (`msg.sender`) of the rotation transaction. It does not hide the **public inputs and outputs of the PLONK proof**, which are emitted as calldata or event logs. Every `EpochRotation` transaction on-chain exposes `(previousEpochCommitment, newEpochCommitment)` regardless of who submitted it. The Tornado Cash analogy is inapt: Tornado Cash's security model relies on a *single, fungible anonymity pool* where all notes of the same denomination are indistinguishable — there is no per-user chain structure. Here, each `EpochRotation` explicitly chains two commitment values that are unique to one agent slot (`currentEpochCommitment[agentSlot]`). Any full node sees the complete directed graph of commitment pairs the moment they appear in a block. Archive-node archaeology is not required; a live node suffices.

- **Why it works:** The relayer defense is referenced twice (§3, §7) as a mitigation for chain traversal, but it addresses the wrong threat surface. The threat is not "who submitted the tx" but "what are the public PLONK inputs." The `agentSlot` mapping in the registry (`currentEpochCommitment[agentSlot]`) further anchors each commitment to a specific slot, making the chain trivially reconstructible by slot index without any archive archaeology at all.

- **In-threat-model?** **No — construction must address.** The relayer mitigation should either be dropped as a defense (it doesn't do what the text claims) or replaced with a genuine mitigation: verifying epochCommitment membership in a Merkle tree of *all agents' current commitments* as a public input, hiding which slot is being rotated. This is the same anonymity-set fix deferred in §3 — the relayer claim is a false proxy for that real fix.


## Persona: spiffe_engineer

Staff engineer running SPIFFE/SPIRE in production across 200k+ workloads. Co-author on WIMSE architecture drafts. My prior: workload identity problems get solved at the workload identity layer, not by bolting ZK gadgets onto application-layer session protocols.

---

### Attack 1: SPIRE Continuous Rotation Already Beats Your Epoch Claim On the Metric That Matters

**Attack:** Section 7 grounds the forward-secrecy claim in a SECU 30-day lending agent with *daily* epoch rotation. SPIRE's default SVID TTL is 1 hour, configurable to 5 minutes. With hourly SVIDs, key compromise at day 31 exposes at most 1 hour of sessions — not 30 days. Bolyra's forward-secrecy *advantage* over the baseline shrinks to exactly the ratio `epoch_length / SPIRE_TTL`. With daily epochs and hourly SVIDs, SPIRE already contains the blast radius to 1/24th of a day. The ZK construction only wins when epoch length approaches "the whole session," which is an operational choice the deployment controls. The construction never argues why a 24-hour epoch is operationally necessary rather than, say, 1 hour — which would reduce it to SVID parity with zero ZK overhead.

**Why it partially lands:** The construction conflates *forward secrecy* (limiting exposure window) with *unlinkability* (preventing retroactive graph reconstruction). SPIRE short-TTL rotation achieves the former; it does not achieve the latter because SVIDs contain a stable `spiffe://trust-domain/agent/foo` subject. The ZK layer's real claim is unlinkability, not just forward secrecy. The construction should lead with unlinkability as the *distinct* property rather than burying it.

**In-threat-model?** Partially. The construction survives on unlinkability, but must clarify that the claim is specifically unlinkability-after-compromise, not forward secrecy in the textbook session-key sense. Section 1 and Section 8 conflate the two throughout. A reader familiar with SPIRE will reject "no RFC construction achieves this" because they will interpret the claim as "limits compromise exposure window" — which SPIRE does achieve.

---

### Attack 2: Your r_T Exclusion Is an Enclave Assumption Wearing a Game Definition

**Attack:** The IND-FS-AGENT game (Section 3) excludes `r_T` from the adversary with the parenthetical: *"modeling immediate rotation or secure enclave isolation of blinding factors."* But the realistic threat model for "key is compromised at time T" is memory forensics, container escape, or kernel exploit — all of which yield a full process memory dump. That dump contains `s_T`, the current epoch's `r_T` (it must be in memory to compute `epochCommitment_T = Poseidon2(s_T, r_T)` at next session), and — critically — `s_{T-1}` if the deletion is software-level rather than hardware-enforced. Section 3's "honest limitation" acknowledges this degrades to an *operational mitigation* (relayer pattern) rather than a cryptographic guarantee. Compare SPIRE's architecture: the Workload API holds private key material in the SPIRE *agent* process, not the workload process. The workload receives short-lived JWTs signed by SPIRE. Full workload-process compromise does not yield the signing key. Bolyra hands epoch secrets (`s_e`, `r_e`) directly to the agent process, which is structurally weaker isolation than SPIRE's key-out-of-workload design. The ZK proof provides mathematical guarantees only to the extent the delete is hardware-enforced (TPM/HSM), which the construction never requires and the deployment scenarios in Section 7 never provision.

**Why it lands:** Section 3's game is the security claim. If the game excludes `r_T` only by analogy to "secure enclave isolation," the construction needs to either (a) require an enclave as a deployment precondition, or (b) prove security when `r_T` is also compromised. The construction explicitly says it degrades in that case. This makes the claim conditional on an infrastructure assumption that isn't named in the claim statement.

**In-threat-model?** No — the construction must address this. Either add "requires secure enclave for `r_e` isolation" as an explicit precondition in Section 1 and Section 7, or prove a weaker guarantee under `r_T` compromise. The current framing of Section 3 as a cryptographic game while smuggling in an operational assumption as a parenthetical is not acceptable for a security argument.

---

### Attack 3: agentSlot Is a Stable Correlator the Construction Never Closes

**Attack:** The on-chain registry uses `currentEpochCommitment[agentSlot]` and `consumedEpochCommitment[hash]` (Section 2.4). The `agentSlot` is the lookup key — any verifier calling `ForwardSecureAgentSession` must know which `agentSlot` to check the epoch commitment against. That means `agentSlot` is either (a) included in the session proof's public inputs, making it a stable identity correlator visible to every verifier, or (b) derived inside the ZK circuit from something the verifier knows — which requires the verifier to hold a stable identifier for the agent anyway. The construction nowhere specifies how verifiers discover `agentSlot` without having a stable per-agent identifier. An adversary who observes *any* session proof can record the `agentSlot`, then query an archive node for all `currentEpochCommitment[agentSlot]` state transitions. This reconstructs the complete epoch rotation timeline — dates, frequencies, total session count — without breaking Poseidon, obtaining `r_T`, or using the removed `epochTransitionNullifier`. This is a timing side-channel that the construction's security argument in Section 4 never addresses; Cases 1–5 of the IND-FS-AGENT reduction are all nullifier/commitment-based and none touch the `agentSlot` linkage.

In SPIFFE terms: `agentSlot` is structurally equivalent to a SPIFFE ID — the stable workload identifier that the construction's Section 8.2 criticizes SPIFFE for exposing. The construction has the same exposure at the registry layer.

**Why it lands:** Section 3's adversary has "full on-chain registry read access including archive node history." Combined with a known `agentSlot`, the adversary reconstructs the epoch rotation graph without any cryptographic attack. The construction's forward secrecy claim holds for *session contents* but not for the *activity graph* (how many sessions, when rotations occurred, which epochs were active) — which is precisely what the whistleblower scenario in Section 7 requires to be hidden.

**In-threat-model?** No — the construction must address how `agentSlot` is either (a) hidden inside the session proof using a Merkle set membership construction (deferred in Section 3 as "a future iteration"), or (b) acknowledged as a structural linkage that limits the unlinkability claim to session-content rather than activity-graph privacy.

---

### Attack 4: WIMSE SD-JWT Token Exchange Covers Your Delegation Critique and You Haven't Read the Current Drafts

**Attack:** Section 8.2 dismisses WIMSE with: *"SPIFFE IDs are stable; SVID certificate chains contain issuer DNs in plaintext. Delegation graph is structural and key-independent."* This is accurate for X.509 SVIDs — but the WIMSE architecture (draft-ietf-wimse-arch, current revision) explicitly supports JWT-based workload tokens with SD-JWT selective disclosure. A WIMSE deployment using JWT SVIDs + SD-JWT can: (1) derive a per-hop ephemeral public key as the token's `cnf` (holder-of-key), (2) selectively disclose only the claims necessary for each downstream service, and (3) use RFC 8693 token exchange to mint a new token at each delegation hop with a fresh ephemeral key binding — no stable SPIFFE ID in the disclosed payload. The `iss` (issuer) remains, but the WIMSE working group has active discussion on trust-domain pseudonymization. The construction's baseline comparison in Section 8 is accurate against X.509 SVIDs circa 2021, not against current WIMSE JWT token flows. If the contribution is "ZK proofs for delegation unlinkability," it must show that WIMSE SD-JWT + ephemeral holder-of-key fails the IND-FS-AGENT game specifically, not that SPIFFE X.509 SVIDs fail it — those are different constructions. The right framing is a contribution *on top of* WIMSE, not as a replacement, or a proof that WIMSE SD-JWT cannot achieve the unlinkability game even in principle.

**Why it lands:** Section 8 is the "why we can't use existing standards" argument. If the baseline is outdated, the claim "no RFC/draft construction achieves this" is vulnerable to being falsified by a WIMSE implementer who points to the SD-JWT flow. This doesn't break the ZK construction's correctness, but it breaks the construction's *motivation* — which is the primary thing a standards-body reviewer or a security architect will attack.

**In-threat-model?** Partially. The ZK construction likely does achieve strictly stronger unlinkability than WIMSE SD-JWT (no `iss` in zero-knowledge is genuinely hard with JWT semantics). But the claim must be grounded in a concrete comparison against WIMSE JWT SVIDs + SD-JWT, not X.509 SVIDs. The construction should either (a) extend the comparison in Section 8.2 to WIMSE JWT flows and prove the gap, or (b) position as a ZK attestor plugin for WIMSE rather than a competing protocol — which would also answer Attack 1 by making the "wrong layer" objection moot.
