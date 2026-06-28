# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0\_pm

---

### Attack 1: The Privacy Feature Is a Regulatory Liability

- **Attack**: The entire construction is built around hiding intermediate scopes and participant identities from the auditor. But NCUA examiners and SOC 2 auditors don't *want* scope values hidden — they want to see them. The FFIEC SR 11-7 analogue the deployment scenario cites (Section 7) requires model risk management documentation including the *specific* permissions granted to third-party AI agents. An examiner who receives `narrowingValid=1` and `policyOk=1` has proof of a structural property but has not satisfied the substantive audit requirement: "Show me what TransUnion's agent could actually do with member PII." The construction's privacy guarantee, which hides intermediate scopes, is architecturally incompatible with what the examiner is legally required to confirm. WorkOS and Auth0 give examiners a scoped audit-log dashboard where the examiner can read the exact permission grants. That's what passes a NCUA exam. A ZK proof that the examiner cannot interpret passes nothing.

- **Why it works**: The construction conflates *cryptographic* privacy with *regulatory* privacy. The NCUA scenario is chosen to make ZK sound valuable, but examiners have subpoena power and confidentiality agreements — they don't need the scopes hidden from *themselves*. The construction never defines who the auditor's adversary is. If the auditor is the examiner, hiding data from them is counterproductive. If the auditor is a public observer, the examiner scenario is the wrong example. The gap-to-close in the candidate card ("broaden to chain-of-custody proofs for AI agent pipelines") doesn't fix this — it's a use-case expansion over a flawed premise.

- **In-threat-model?** No. The construction must add a section distinguishing auditors who should NOT see intermediate data (e.g., the journalist/source case) from auditors who ARE entitled to see it (NCUA examiners). The Navy Federal deployment scenario as written has the wrong auditor for the privacy guarantee being provided.

---

### Attack 2: On-Chain Anchoring Requires Infrastructure Enterprises Won't Deploy

- **Attack**: The soundness argument in Section 4 depends entirely on the auditor cross-referencing `chainAnchor` against on-chain `DelegationVerified` events (constraint 8, steps 5–6 of the reduction). Remove the blockchain and the reduction collapses: a prover with fabricated witness data produces a valid PLONK proof with a non-matching `chainAnchor`, but there's no canonical on-chain record to compare against. The entire privacy-without-disclosure guarantee is therefore conditional on the enterprise deploying delegation events to a public or consortium chain. Navy Federal Credit Union, with $176B in assets and NCUA oversight, will not emit member loan origination events — even as opaque commitments — to Base Sepolia or any other public chain. Their information security policy, member data governance obligations, and vendor risk program will block it at procurement. WorkOS runs on your existing AWS/GCP infrastructure, zero blockchain. The construction's soundness requires the blockchain; the enterprise's security policy prohibits it.

- **Why it works**: Section 7 states "NCUA examiner requests proof" and walks through a deployment scenario without mentioning that Base Sepolia must be involved. The Bolyra primitive mapping table (Section 5) lists `HandshakeVerified` and `DelegationVerified` events as required, but the deployment scenario buries this dependency. An enterprise buyer reading Section 7 will only discover the blockchain requirement when implementation starts. This is a procurement blocker that WorkOS, Auth0, and Stytch — all pure SaaS — never trigger.

- **In-threat-model?** No. The construction must either (a) specify a private/permissioned chain option and prove the soundness argument still holds when the chain operator is semi-trusted, or (b) define an off-chain append-only log alternative and prove the cross-reference step remains binding. Neither is present.

---

### Attack 3: The Construction Is Post-Hoc Audit, Not Real-Time Enforcement — and Admits It

- **Attack**: Section 7 step 1 says "NFCU's compliance agent generates a PLONK proof." This happens *after* the pipeline executes. The construction is an audit artifact, not an enforcement mechanism. WorkOS enforces narrowing *synchronously* at delegation issuance — a scope that violates the parent's bitmask is rejected at token-mint time, in <100ms, before any tool call reaches a downstream agent. The Bolyra circuit proves that the scopes *were* monotonically narrowing *if the prover used the real on-chain witnesses* — but a pipeline that violated least-privilege has already executed by the time the audit proof is generated. The nullifier-scope binding (constraint 8) ensures the proof is anchored to actual on-chain state, but on-chain state was written by the per-hop `Delegation` circuit at delegation time — *not* at enforcement time. A pipeline operator who controls all hops can issue delegation proofs that technically narrow (e.g., drop `ACCESS_PII` at hop 1) but exfiltrate PII at hop 1 before delegating. The audit proof proves the scope was narrowed; it proves nothing about what the agent *did* within that scope. WorkOS would ask: what does your proof prevent that my synchronous scope check doesn't?

- **Why it works**: Section 8 claims "In-circuit enforcement at presentation" as a differentiator. But the DelegationChainAudit circuit is an *audit* circuit, not a presentation circuit. It runs after the fact, not at each tool call. The construction conflates "proven at audit time" with "enforced at execution time." The comparison row in Section 8 says "The proof IS the enforcement" — but the proof is generated by "NFCU's compliance agent" post-hoc. That is not enforcement; it is attestation. Auth0 Actions and WorkOS webhook policies are synchronous enforcement.

- **In-threat-model?** No. The construction should clearly state this is a post-hoc audit primitive, not a real-time enforcement mechanism, and separately specify how it composes with a runtime enforcement layer (e.g., the gateway that verifies the per-hop Delegation proof before each tool call executes). Without that composition, the claim that ZK provides enforcement that the baseline lacks is false for the primary attack surface: misbehavior within an authorized scope.

---

### Attack 4: The Verifier Is a Person Who Cannot Verify PLONK Proofs

- **Attack**: Section 7 step 3 says "Examiner verifies: PLONK proof checks out." This requires the examiner to run a PLONK verifier, reconstruct `PoseidonN(hopDigest[0..7])`, and cross-reference indexed `DelegationVerified` events from a blockchain node. NCUA examiners use spreadsheets and vendor-provided portals. They do not have PLONK verifier infrastructure, do not know what BN254 is, and cannot interpret a `chainAnchor` value without significant tooling investment. The construction entirely delegates the tooling problem to the consumer: "Examiner verifies." WorkOS gives examiners a web dashboard with a timeline of delegation events, exportable to CSV, integrated with their existing SIEM via webhooks. Stytch's audit log ships with pre-built Splunk and Datadog integrations. The construction's verifier is a cryptographic primitive; the baseline's verifier is a product. Enterprises buy products.

- **Why it works**: The candidate card's gap-to-close says the construction must be "in a form usable beyond narrow regulatory niches." A verification step that requires a PLONK verifier binary, a blockchain RPC endpoint, and Poseidon hash tooling is maximally narrow. The entire Section 7 deployment scenario assumes a technically sophisticated compliance agent that generates the proof AND an examiner with verification infrastructure — neither of which exists in the market segment (credit unions) being targeted. This is the "worse than paste-an-API-key" failure mode from the attack prompts: the onboarding flow for the *auditor* alone requires more integration work than standing up WorkOS.

- **In-threat-model?** No. The construction must specify a hosted verification service (e.g., a Bolyra-operated or self-hosted verifier endpoint that accepts a proof and returns a human-readable audit report) and acknowledge that this reintroduces an operator trust assumption that the construction otherwise eliminates. The tension between "no trusted third party" and "examiner-accessible verification" needs to be resolved explicitly, not papered over with "examiner verifies."


## Persona: cryptographer

*Applied cryptographer. IACR publications. Reviews for CRYPTO/EUROCRYPT/S&P. My prior: if you can't state the threat model as a game and sketch a reduction, you have marketing. Let's see what we have here.*

---

### Attack 1: Scope-Space Enumeration Breaks the Privacy Claim

**Attack:**
The `AuditPrivacy` game claims an adversary cannot distinguish two chains C₀, C₁ with "different intermediate scope VALUES." But the 8-bit permission model (bits 0–7 active, bits 8–63 reserved per `CLAUDE.md`) gives at most 2⁸ = 256 distinct meaningful scope values. The on-chain `DelegationVerified` events emit `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])` as a public indexed field. An adversary who resolves `credCommitment[i]` — which may be recoverable from the originating `HandshakeVerified` event that stores `agentPubSignals[2]` (the root scope commitment from which credential commitments are derivable) — can enumerate all 256 candidate scopes and compute `Poseidon2(scope_candidate, credCommitment_known)` until it matches the on-chain commitment. Cost: 256 Poseidon2 evaluations per hop.

**Why it works / why it fails:**
The construction correctly notes that Poseidon preimage resistance protects `scope[i]`. But preimage resistance assumes the preimage has sufficient entropy. With only 8 meaningful bits, the combinatorial space is trivially enumerable. The privacy argument implicitly assumes `credCommitment[i]` is unknown to the adversary — but credential commitments appear in the original per-hop `Delegation` circuit's public outputs, which are emitted on-chain at delegation time. A persistent adversary watching chain state can correlate. The privacy game as stated does NOT bound the adversary's ability to use auxiliary on-chain data to resolve credential identities.

**In-threat-model?** **No** — the construction must address this. The fix requires either: (a) salting `scope[i]` with a high-entropy blinding factor before hashing (adding ~300 constraints per hop for a Poseidon3 call), or (b) explicitly restricting the privacy game adversary from querying on-chain credential commitment registrations. As written, the zero-knowledge claim is computationally vacuous for any adversary who observes chain state and knows which agents were delegated to.

---

### Attack 2: Chain-Stitching — Assembling a Fictional Pipeline from Real Events

**Attack:**
The `NarrowingAuditSoundness` game condition (c) requires that each `hopDigest[i]` matches a legitimate on-chain `DelegationVerified` event. Constraint 8 (nullifier-scope binding) ensures the in-circuit `(delegationNullifier[i], scopeCommit[i])` pairs match real on-chain events. But the circuit does NOT enforce that these events are **connected** — i.e., that hop `i`'s original delegation proof used `scopeCommit[i-1]` as its `previousScopeCommitment`.

Concretely: suppose two entirely unrelated delegation chains exist on-chain:
- Chain A: Root→Agent₁ (scope `0x07`), Agent₁→Agent₂ (scope `0x03`)
- Chain B: Root'→Agent₃ (scope `0x03`), Agent₃→Agent₄ (scope `0x01`)

An adversary constructs a "stitched" audit proof using:
- Hop 0: nullifier and `scopeCommit` from Chain A, hop 0
- Hop 1: nullifier and `scopeCommit` from Chain A, hop 1 (scope `0x03`)
- Hop 2: nullifier and `scopeCommit` from Chain B, hop 1 (scope `0x01`)

Each `hopDigest[i]` matches a real `DelegationVerified` event. Constraint 5 (monotonic narrowing) is satisfied: `0x07 ⊇ 0x03 ⊇ 0x01`. Constraint 4 (chain linking) enforces `scopeCommit[i-1]` equals the previous expected value within the witness — but it does NOT verify that the on-chain `DelegationVerified` event for `nullifier_2` recorded `Chain A hop 1's scopeCommit` as its predecessor. These are never cross-referenced.

**Why it works / why it fails:**
The reduction sketch (steps 5–7) shows that `scopeCommit[i]` matches the on-chain commitment paired with `nullifier_i`. It does NOT show that the on-chain delegation event for `nullifier_i` listed `scopeCommit_{i-1}` as its `previousScopeCommitment`. This is a genuine gap in the chain linkage argument. The `DelegationVerified` event presumably emits `(nullifier, newScopeCommitment)` — but NOT `previousScopeCommitment`. If it did emit the predecessor, the auditor could verify chain connectivity off-circuit. If it does not, the stitching attack succeeds.

The consequence: the proof certifies "these 8 on-chain events, taken in this order, exhibit monotonic narrowing" — not "a single connected delegation chain with these participants exhibited monotonic narrowing." The semantic gap between these two statements is exactly the thing the construction needs to close for the NFCU/examiner scenario to be meaningful.

**In-threat-model?** **No** — the construction must address this. The fix is one of: (a) require `DelegationVerified` to also emit `previousScopeCommitment` as an indexed field, and have the audit circuit verify `scopeCommit[i-1] == previousScopeCommit_i^{chain}` (adds 7 public input pairs and ~7 equality constraints), or (b) make the chain anchor commit to a linked-list hash that chains each `hopDigest[i]` through its predecessor.

---

### Attack 3: "Universal Setup" Does Not Mean Trustless — SRS Subversion Collapses Everything

**Attack:**
Section 2 states PLONK is chosen because it uses "universal setup, no per-circuit ceremony — auditors can verify without trusting a circuit-specific ceremony." This framing is dangerously misleading. PLONK (KZG variant) requires a **universal Structured Reference String** generated by a powers-of-tau ceremony over BN254 with toxic randomness `τ`. An adversary who controls the ceremony — or who exfiltrates `τ` from a participant — can:

1. **Forge proofs** (soundness collapse): Construct an accepting PLONK proof for ANY witness, including witnesses where `narrowingValid = 1` but actual on-chain scopes did not narrow monotonically.
2. **Extract private inputs** (zero-knowledge collapse): From any honestly-generated proof transcript, recover all private inputs — intermediate scopes, credential commitments, delegation nullifiers — defeating the `AuditPrivacy` claim entirely.

The construction does not name which PLONK SRS is used, cite a ceremony transcript, specify the number of participants, or reference a subversion-resistant variant (e.g., transparent STARKs, Halo2 with IPA, or a sufficiently large multi-party ceremony with at least one honest participant).

**Why it works / why it fails:**
Under the stated adversary model ("does NOT control the BN128 pairing"), this attack is out-of-scope if the SRS ceremony is trusted. But the claim "auditors can verify without trusting a circuit-specific ceremony" will be read by deployment engineers as "no ceremony required at all." This is false. Every PLONK deployment on BN254/BN128 requires ceremony trust — the only question is whether it is per-circuit or universal. The construction silently moves ceremony trust from the circuit to the SRS while framing this as eliminating ceremony trust entirely.

For the journalist/source scenario specifically: if a state actor participated in (or compromised) the powers-of-tau ceremony, they can extract source identities from every audit proof generated using that SRS — the exact deanonymization the construction is designed to prevent.

**In-threat-model?** **Partially** — as written, the adversary model excludes SRS subversion. But the construction **must address** this by: (a) citing a specific ceremony with a verifiable transcript (e.g., Hermez Phase 1, Zcash Powers of Tau), (b) specifying the minimum number of ceremony participants required, and (c) acknowledging that SRS subversion is outside the model and documenting the consequence. The current framing actively misleads auditors about the trust assumptions.

---

### Attack 4: The `AuditPrivacy` Game Is Circular — On-Chain Scope Commitments Are Already Public

**Attack:**
The `AuditPrivacy` game (Section 3) requires that C₀ and C₁ have:
> "Same set of on-chain (nullifier, scopeCommitment) pairs (hence same chainAnchor)"

But `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])` is emitted by every `DelegationVerified` event as a public indexed field (Section 5, "On-chain registry requirement"). The privacy game parameterizes privacy as: "the adversary cannot distinguish chains with different `scope[i]` values when the `Poseidon2(scope[i], credCommitment[i])` commitments are identical."

This reduces the game to: **can the adversary find two distinct `(scope, credCommitment)` pairs with the same Poseidon2 hash?** That is trivially Poseidon collision resistance — which is assumed. The game proves nothing about the construction; it is a restatement of an assumption.

The privacy claim the construction actually wants to make is: "given `scopeCommit[i]`, the adversary cannot learn `scope[i]`" — which is Poseidon preimage resistance. But the game as written conflates collision resistance (same commitment → indistinguishable chains) with preimage resistance (from commitment → cannot recover input). These are different properties, and neither implies what the construction needs: that `scope[i]` values are protected against a chain-watching adversary who accumulates many `(nullifier, scopeCommit)` pairs over time and uses correlation with external information to deanonymize.

**Why it works / why it fails:**
The zero-knowledge privacy argument (Section 4, "Reduction sketch (privacy)") says: "by the HVZK property of PLONK, the proof transcript is simulatable given only public inputs/outputs." This is correct for the proof transcript — PLONK's HVZK means the proof itself leaks nothing beyond its public inputs. But the public inputs/outputs include `chainAnchor`, which commits to `(nullifier_i, scopeCommit_i)` pairs that are already on-chain. The privacy of `scope[i]` is therefore NOT a property of the ZK proof system at all — it is a property of Poseidon preimage resistance applied to a 8-bit input space.

Formally: let `F(x) = Poseidon2(x, c)` for fixed `c = credCommitment[i]`. Privacy of `scope[i]` given `scopeCommit[i]` requires that `F` is a one-way function over the domain {0, 1}^8. One-wayness over a 256-element domain is not the same as one-wayness over the full field — the latter is what Poseidon's security proof guarantees.

**In-threat-model?** **No** — the construction must state a tighter privacy game that: (a) explicitly bounds the adversary to not knowing `credCommitment[i]` values, (b) accounts for the low-entropy of `scope[i]`, and (c) separates ZK transcript privacy (which PLONK provides) from on-chain commitment privacy (which Poseidon preimage resistance over a small domain does NOT provide). A formal fix requires adding a high-entropy salt `r[i]` to each scope commitment: `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], r[i])` where `r[i]` is an ephemeral blinding factor — at the cost of one additional private input and ~100 constraints per hop.


## Persona: cu_ciso

---

### Attack 1: Privacy-as-Liability — GLBA §314.4(f) Vendor Management Collision

- **Attack**: The construction's headline privacy property — "Examiner does NOT learn: who the intermediate agents are" (§7) — directly conflicts with the GLBA Safeguards Rule §314.4(f), which requires the institution to **identify and oversee service providers who have access to member information**. In the NFCU scenario, TransUnion is hop 2 and handles member credit data. NCUA examiners reviewing third-party risk will ask for the full vendor inventory, a copy of the service agreement, evidence of due diligence, and an assessment of TransUnion's access to member PII. The proof tells the examiner `narrowingValid=1`. It does **not** tell the examiner who handled the member's data. The CISO cannot file a compliant vendor management dossier on an entity the proof is designed to conceal. Worse: if the construction is used precisely to hide that TransUnion (or a cheaper, unapproved substitute) handled member data, the examiner will view ZK as an obstruction, not a control.

- **Why it works against the construction**: The construction frames intermediate-participant hiding as a feature (§8, "Journalist/source anonymity"). From a GLBA/NCUA lens, this is a liability. The ZK proof proves structural integrity of the permission graph but says nothing about whether each participant is an approved vendor under §314.4(f). There is no output signal that maps to "all intermediate participants appear in the institution's approved vendor list." The construction is silent on this.

- **In-threat-model?** No. The construction's threat model (§3) defines adversaries as parties trying to forge narrowing proofs — not as institutions using ZK to obscure a non-compliant vendor relationship from examiners. This attack lives outside the cryptographic threat model and inside the regulatory compliance model. **Construction must address**: either expose a certified-vendor attestation (out-of-band) that the examiner can cross-reference with the `credCommitment` set, or explicitly disclaim that participant-hiding is unsuitable for regulated pipelines where GLBA vendor disclosure is required.

---

### Attack 2: Incident Response Black Box — NCUA Part 748 Appendix B Notification Failure

- **Attack**: At 2:47 AM, NFCU's SOC gets an alert: unauthorized read of 14,000 member loan files. The incident response team opens the Bolyra delegation chain for the loan origination pipeline. They have: `narrowingValid=1`, `policyOk=1`, `chainAnchor`, `terminalScopeCommitment`, `chainLength=4`. They do **not** have: which hop accessed what records, when, which agent instance (credential commitment) was involved at hop 2, or whether the scope narrowing held at the hop where the breach occurred. NCUA Part 748 Appendix B requires the institution to notify NCUA within 72 hours of discovering a reportable cyber incident, including a description of the nature of the incident. The CISO must answer: *what data was accessed, by whom, through which system?* The ZK audit proof answers *"did the permission graph narrow?"* — a structural question, not a data-access question. The proof's privacy property is specifically designed to prevent reconstruction of intermediate participants and their scopes, which are exactly what incident response requires.

- **Why it works against the construction**: The construction conflates **permission-graph integrity** (what the circuit proves) with **access auditability** (what the regulator needs post-incident). These are orthogonal properties. `narrowingValid=1` proves no hop exceeded its mandate at delegation time. It does not prove what data the hop actually touched, does not log which credential was presented at the terminal RS, and does not provide a timeline of accesses. The construction has no access log component — by design.

- **In-threat-model?** No. The threat model defines privacy as hiding intermediate scope values and participant identities from the auditor (§3, AuditPrivacy game). This privacy property directly impedes the post-breach forensics the same auditor is legally required to conduct. The construction does not reconcile ZK privacy with incident-response disclosure obligations. **Construction must address**: define the boundary between "audit-time ZK proof" (pre-incident, structural) and "incident-response disclosure" (post-incident, selective deanonymization). A break-glass mechanism that reveals participants under a court order or regulatory examination — without invalidating routine audit privacy — is absent and necessary.

---

### Attack 3: Self-Attestation Without Independent Witness Generation — FFIEC CAT "Detect and Respond" Gap

- **Attack**: Section 7 states: *"NFCU's compliance agent generates a PLONK proof."* The private inputs — `scope[i]`, `credCommitment[i]`, `delegationNullifier[i]` for all four hops — are supplied by NFCU's own systems. The nullifier-scope binding (constraint 8) ensures the in-circuit scopes match the on-chain `DelegationVerified` events. But NFCU also controls the systems that **wrote** those `DelegationVerified` events in the first place. If a misconfigured or compromised pipeline at NFCU writes incorrect `newScopeCommitment` values to the registry at delegation time, the proof will faithfully prove that the chain narrowed monotonically — because it did, as recorded on-chain — even if the actual runtime permission enforcement was absent or bypassed. The examiner's cross-reference of `hopDigest[i]` against on-chain events confirms the proof used the correct on-chain data. It does not confirm the on-chain data reflected runtime enforcement. The chain anchor is only as trustworthy as the entity that emitted the `DelegationVerified` events.

- **Why it works against the construction**: The security argument (§4, reduction sketch step 5) states: *"the auditor has verified that each `hopDigest[i]` matches the on-chain pair from `DelegationVerified` events."* This is correct but assumes the on-chain events were written by an honest registry. The construction's deployment section (§5) notes the registry is a Solidity contract — but does not address who has write access to it, whether NFCU's own systems are the sole writers, or whether a privileged NFCU operator could re-emit events with scope commitments of their choosing. The FFIEC CAT "Detect and Respond" domain requires independent detection of control failures — not self-reported control evidence. An institution generating its own compliance proof from its own on-chain state is self-attestation, not independent audit.

- **In-threat-model?** Partially. The adversary model (§3) excludes the case where the institution itself is the adversary who manipulates the on-chain record. The game definition's condition (d) refers to *"the ACTUAL on-chain scope"* — but actual on-chain scope is what the institution's contract wrote, not necessarily what the runtime enforced. **Construction must address**: the trust model for the on-chain registry. Options include: (a) the registry contract is permissionless and each participant's delegation proof is submitted independently, so no single party controls all `DelegationVerified` events; (b) a neutral third party submits events; (c) the audit circuit is extended to re-verify per-hop delegation proofs inline, removing the relay on self-reported on-chain state. The current construction's §5 ("The only new requirement is that the event log includes both values") leaves this unresolved.

---

### Attack 4: Bolyra-as-Vendor SLA and Business Continuity — NCUA Part 748 §1 and FFIEC BCP

- **Attack**: The construction requires the examiner to cross-reference `hopDigest[i]` values against on-chain `DelegationVerified` events in real time (or near real time) at audit time (§7, step 3). This means the Base Sepolia chain (or whatever L1/L2 hosts the Bolyra registry) is in the critical path for regulatory compliance demonstrations. The construction does not specify: what is the availability SLA of the on-chain registry? What happens if the chain is reorging, the RPC endpoint is down, or the `DelegationVerified` event logs are pruned by a node operator? Separately, Bolyra itself — as the provider of the PLONK verifier, the registry contract, and the SDK — becomes a **critical third-party vendor** under NCUA Regulation Part 748 and the GLBA Safeguards Rule. NFCU would need to conduct vendor due diligence on Bolyra, obtain a SOC 2 Type II report, review Bolyra's BCP/DR plan, and include Bolyra in its TPRM program. None of this is addressed. The construction presents the on-chain anchor as a *trust-reduction* feature ("no real-time API calls to any authority" — §8). But verifying that on-chain events exist requires querying a node, which is itself an availability dependency and a vendor relationship.

- **Why it works against the construction**: The baseline comparison table (§8) correctly notes RFC 7662 introspection requires live AS queries. The construction claims PLONK proof + on-chain event cross-reference as an advantage. But querying a blockchain for indexed events is not offline — it requires an RPC endpoint, an archive node (events may require `eth_getLogs` over a historical range), and confidence that the chain hasn't had a deep reorg that invalidated the events. Archive nodes are not universally available and have their own SLA profiles. For a credit union's NCUA examiner conducting a compliance review, "check the blockchain" is not an operationally understood procedure, and "the chain was down" is not an acceptable gap in compliance evidence.

- **In-threat-model?** No. The threat model assumes a functioning on-chain registry as a given. Availability, vendor risk, and BCP are operational properties outside the cryptographic game definition. **Construction must address**: specify the expected RPC infrastructure, availability SLA, archive node requirement, event retention window, fallback procedure if on-chain state is unavailable at audit time, and the vendor classification (critical vs. non-critical) of the Bolyra registry operator under NCUA TPRM guidance. Without this, the construction is a cryptographic primitive, not a deployable compliance control.


## Persona: rfc7662_advocate

---

### Attack 1: AS-Side Boolean Narrowing Attestation Collapses the "No Trusted Third Party" Claim

- **Attack**: draft-ietf-oauth-jwt-introspection-response already enables an AS to pre-compute `∀i: scope[i] ⊆ scope[i-1]` server-side and issue a signed JWT response containing only `{"narrowing_valid": true, "policy_ok": true, "session_nonce": ..., "chain_length": 4}` — with zero intermediate scope values in the payload. Per-RS introspection policy (RFC 9728 §4) lets the AS filter what each caller receives. The auditor verifies a standard JWT signature — offline, no live query, no scope disclosed. The construction's §8 dismisses this category ("AS is the anchor, AS compromise breaks the chain") but then accepts an on-chain smart contract as an equivalent anchor. A PLONK verifier contract on a permissioned chain (e.g., NFCU's internal Besu deployment) is operated by a single organization — structurally identical to a single-operator AS. The claim "no trusted third party" holds only for a sufficiently decentralized public chain; on any network where NFCU controls ≥1/3 of validators, the trust assumption for the smart contract is weaker than a well-audited AS run by a regulated financial institution with SOC 2 Type II, HSM-backed signing keys, and NCUA examination.

- **Why it works / why it fails**: It works as an equivalence attack for the concrete deployment scenario in §7 (NFCU, a permissioned enterprise context). It fails against a public Ethereum mainnet or Base deployment where the construction genuinely decentralizes trust. The construction must explicitly state that the "no trusted third party" claim requires a sufficiently decentralized chain, and must quantify what "sufficiently decentralized" means — otherwise the NFCU scenario it chooses as its primary deployment example undermines the baseline comparison in §8.

- **In-threat-model?** No — the construction must address this. §3's adversary model does not specify chain decentralization requirements. §8's comparison is framed as categorical ("AS is the anchor") but the same critique applies to permissioned smart contracts. The construction needs to either restrict the claim to decentralized chains or argue why a smart contract under NFCU's operational control is a stronger trust anchor than NFCU's own AS.

---

### Attack 2: TEE-Attested Narrowing Computation Is an Unaddressed Alternative

- **Attack**: An AS running inside a TEE (AWS Nitro Enclave, Intel TDX, AMD SEV-SNP) can compute the narrowing check over plaintext scope values without the AS operator seeing them. The enclave produces a remote attestation quote (signed by the hardware root of trust) that asserts: "I computed `∀i: scope[i] ⊆ scope[i-1]` over the following session's token chain and the result is TRUE." The auditor verifies the attestation against the vendor's root certificate — no ZK, no on-chain state, no circuit. The scope values never leave the enclave in plaintext. This satisfies the construction's headline claim ("auditor verifies monotonic narrowing without reconstructing intermediate scopes") using hardware-attested computation rather than cryptographic proof.

- **Why it works / why it fails**: The attack is technically viable for §7's NFCU scenario today using AWS Nitro, which is already in NFCU's cloud stack. It fails on threat model grounds: TEE attestation requires trusting the silicon vendor (Intel/AMD/AWS), assumes no microarchitectural side-channels (Spectre/Meltdown class), and provides no guarantee if the attestation key is compromised or the enclave binary is malicious. ZK provides purely algebraic guarantees that survive hardware-level adversaries — no vendor trust required. The construction does not articulate this distinction. §3's threat model describes the adversary's capabilities but says nothing about hardware trust assumptions or why the BN254 pairing is preferable to hardware attestation for regulatory compliance contexts.

- **In-threat-model?** No — the construction must address this. §8's "Why the baseline cannot match" table omits TEE entirely, treating the choice as ZK vs. RFC 8693 bearer tokens. A complete comparison must include TEE-attested computation and argue why PLONK's algebraic trust model is preferable to Intel TDX's hardware trust model for the specific deployment scenarios claimed. For a journalist/whistleblower scenario (§7 variant), TEE attestation from a well-known vendor may be a stronger practical guarantee than an unaudited PLONK circuit — or weaker, depending on the attacker. The construction must take a position.

- **In-threat-model?** No — construction must address.

---

### Attack 3: The AuditPrivacy Game Is Vacuously Trivial Under Its Own Constraints

- **Attack**: The AuditPrivacy game (§3) requires C₀ and C₁ to simultaneously satisfy: (a) "Same set of on-chain (nullifier, scopeCommitment) pairs (hence same chainAnchor)" and (b) "Different intermediate scope VALUES and/or different intermediate participants." These two conditions are contradictory under the construction's own Assumption 2. Scope commitments are defined as `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])`. If scope values or credential commitments differ between C₀ and C₁, then `scopeCommit[i]` differs by Poseidon collision resistance. But condition (a) requires identical on-chain scope commitments. Therefore no valid (C₀, C₁) pair satisfying all game conditions exists, and the adversary's advantage is exactly 0 — not because of ZK, but because the game state space is empty. The privacy claim is vacuously true and provides no information about what the construction actually protects.

  The real privacy question for this construction is: **given on-chain public events `(nullifier_i, scopeCommit_i)` and an audit proof `π`, can an adversary recover `scope[i]` or `credCommitment[i]`?** This is the preimage resistance question for Poseidon, answerable without invoking ZK at all. ZK's contribution to privacy is that the proof transcript itself reveals no additional information beyond the public inputs/outputs — which is correct and valuable, but not what the AuditPrivacy game formalizes.

- **Why it works / why it fails**: The attack exposes a formalization gap, not a cryptographic break. The actual privacy guarantee is real: the PLONK proof transcript leaks nothing beyond what's already on-chain, and Poseidon preimage resistance protects scope values from recovery. But the game as written does not demonstrate this — it proves something trivially true under collision resistance. The construction claims this as a formal ZK privacy argument when it is, at best, a preimage resistance argument. This matters for standards review: a formal verifier (IETF CFRG, peer reviewer) will correctly identify the game as vacuous and dismiss the privacy claim as unsubstantiated.

- **In-threat-model?** Yes — the construction survives a practical privacy attack (scope values are genuinely protected), but the formal argument must be fixed. Replace the AuditPrivacy game with one that asks: "given all on-chain public data and an audit proof, can the adversary distinguish `scope[i] = 0x07` from `scope[i] = 0x0F` at any hop?" Answer this via ZK + preimage resistance jointly, not via a vacuous indistinguishability game.

---

### Attack 4: `chainLength` as a Public Input Leaks Pipeline Topology Beyond What the Privacy Game Bounds

- **Attack**: `chainLength` is a public input (not just a public output derived from private data — it is asserted directly by the prover). Combined with on-chain `DelegationVerified` event timestamps and the deterministic zero-padding structure (`hopDigest[i] = Poseidon2(0, 0) = CONST` for inactive hops), the following is globally observable without the auditor's cooperation: (1) how many delegation hops occurred in the pipeline; (2) the exact block numbers of each hop's registration (from event timestamps); (3) that a 4-hop pipeline was audited at a specific session nonce. For the journalist/source scenario (§7 variant), the number of relay agents in a protection chain is itself sensitive — a 3-hop chain is a different operational security posture than a 7-hop chain, and timing correlation of the `DelegationVerified` events against known journalist activity patterns is a real deanonymization vector.

  RFC 8693 token exchange, by contrast, can be batched and pre-provisioned: an AS can issue the full chain at enrollment time, before any live session, producing no timing signal correlated with the actual communication event. On-chain event emission is live and unforgeable — exactly the properties that make the construction auditable also make it a timing oracle.

- **Why it works / why it fails**: This is a traffic analysis attack outside the formal AuditPrivacy game's scope — the game doesn't model timing adversaries or chain-length inference. The attack fails to break the ZK guarantees (scopes and participants remain hidden) but does break the practical anonymity claim for the journalist/source scenario. The construction should note: `chainLength` is the minimum necessary leakage for the audit to be meaningful (the auditor must know how many hops to cross-reference), but the on-chain event timing leaks chain length independently. Mitigation: off-chain event commitment with batch on-chain finalization, or a range proof `chainLength ∈ [1, 8]` that hides the exact count. Neither is addressed in the current construction.

- **In-threat-model?** No — the threat model in §3 explicitly excludes timing adversaries. For the journalist/source scenario to be a credible use case, the construction must either scope out the timing attack (documenting it as out-of-scope with operational mitigations) or extend the threat model to cover it. As written, the §7 journalist scenario is overclaimed: the construction hides *who* the participants are but cannot hide *when* or *how many* there are, which is sufficient to narrow suspicion in a targeted surveillance context.


## Persona: spiffe_engineer

---

### Attack 1: ScopeCommitment Linkability — No Blinding Salt Breaks Session Unlinkability

**Attack:**
Constraint 3 in the construction defines `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])`. There is no blinding factor (randomness) in this commitment. The construction also requires that on-chain `DelegationVerified` events emit `newScopeCommitment` as an indexed field (Section 5, registry requirement).

Result: for any agent with a fixed identity (`credCommitment`) operating at a fixed scope (`scope`), the emitted `scopeCommit` is *identical across every session*. An observer watching the chain does not need to break Poseidon — they observe that the same `newScopeCommitment` value appears in `DelegationVerified` events for session nonces S₁, S₂, S₃… and conclude that the same (agent, scope) pair participated at that hop across all three sessions.

In the NFCU scenario (Section 7), TransUnion's credit scoring agent at hop 2 produces a fixed `scopeCommit` every time it accepts a READ_DATA delegation. A chain-watching adversary learns the cardinality and structure of NFCU's loan pipeline across thousands of applications, even though they learn none of the scope *values*.

**Why it works:** The AuditPrivacy game (Section 3) papers over this by requiring that C₀ and C₁ "use the same on-chain delegation events" — i.e., the game artificially requires the same nullifier-scope pairs. But in practice, repeated invocations of the same pipeline produce the same `scopeCommit` sequence, violating the spirit of the unlinkability claim in the scenario text.

Compare to Semaphore v4's nullifier design: `nullifier = Poseidon(identitySecret, externalNullifier)`, which binds to a *per-invocation* external nullifier. The Bolyra scope commitment binds to no per-session entropy.

**In-threat-model?** No — the construction does not address this. The privacy game is defined over a single pair of chains, not over repeated invocations with the same participants. A blinding salt `r ← Fₚ` must be added: `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], r[i])`, with `r[i]` committed on-chain at delegation time (as Semaphore does with the identity trapdoor). The chain anchor and on-chain event schema must be updated to bind the salt.

---

### Attack 2: Workload Identity Gap — EdDSA `credCommitment` is Self-Issued, Not Attested

**Attack:**
Section 5 (Bolyra primitive mapping) identifies the credential root as "Baby Jubjub EdDSA — Operator signature scheme." The `credCommitment[i]` at each hop is a commitment to the operator's EdDSA public key. The audit circuit explicitly "does NOT re-verify EdDSA signatures" (Section 2, audit circuit description) — it trusts that the per-hop `Delegation` proofs were verified on-chain.

But what attests that `credCommitment[i]` corresponds to an *actual deployed workload* rather than a key generated by an adversary? In SPIFFE/SPIRE, this is solved by node attestation: the SPIRE agent running on a workload host attests its identity to the SPIRE server via TPM measurement, cloud instance metadata (AWS IMDSv2, GCP instance identity tokens), or hardware attestation. The SVID issued by SPIRE is therefore hardware-rooted — forging it requires compromising the TPM or the cloud provider's attestation service.

Bolyra's `credCommitment` is operator-issued: an operator generates an EdDSA keypair, signs an agent credential, and the commitment is `Poseidon(modelHash, operatorPubKey, permissions, expiry)`. There is no mechanism in the construction for a *verifier* to confirm that the operator's keypair was generated inside a TEE, that the modelHash corresponds to a specific deployed artifact hash, or that the operator is who they claim to be. The `DelegationChainAudit` circuit proves monotonic narrowing over credential commitments whose *binding to real infrastructure* it explicitly cannot verify.

In the NFCU scenario (Section 7), the examiner verifies that narrowing held. But they cannot verify that the TransUnion agent at hop 2 is actually a TransUnion-deployed workload — only that *someone* holding an EdDSA key with a particular `modelHash` participated. A compromised NFCU compliance team could insert a phantom hop with a self-generated `credCommitment` that satisfies narrowing, producing a proof of narrowing over a fabricated pipeline.

**Why it works:** The audit circuit's security argument (Section 4) reduces to PLONK soundness + Poseidon collision resistance. Both hold. But neither assumption says anything about the mapping between `credCommitment[i]` and real-world workload identity. The entire trust chain for workload authenticity sits *below* the circuit, in the issuance process for operator credentials — which the construction does not specify or bound.

SPIFFE solves this at the infrastructure layer by making SPIRE server the attestation authority with cryptographic node-attestation flows. Bolyra needs an equivalent — a TEE-rooted credential issuance process, or integration with SPIRE's Workload API — or the construction must explicitly scope its claims to "proving narrowing over whatever credentials participants chose to issue themselves."

**In-threat-model?** No — the construction defines `credCommitment` as a private input and explicitly punts on EdDSA verification. The claim in Section 1 ("anchored to on-chain state so the auditor cannot be fed a fabricated chain") is true for the *scope* values (via constraint 8) but does not extend to the authenticity of the *participants* those scope values are attributed to.

---

### Attack 3: On-Chain Event Completeness — Participants Control Transaction Submission

**Attack:**
The chain anchor verification (Section 3, game condition (c), and Section 9 of the reduction) requires the auditor to reconstruct each `hopDigest[i]` from on-chain `DelegationVerified` events. The reduction sketch (steps 5–7) assumes the auditor has a *complete and authentic* event log: "the auditor has verified that each `hopDigest[i]` matches the on-chain pair `(nullifier_i^{chain}, scopeCommit_i^{chain})` from `DelegationVerified` events."

But the `DelegationVerified` event is emitted by the contract *only when a transaction is submitted*. The adversary model (Section 3) allows the adversary to control "any subset of participants." A participant who controls a hop can:

1. Execute the delegation off-chain (generate the EdDSA signature and delegation proof).
2. Withhold the on-chain transaction, so no `DelegationVerified` event appears for that hop.
3. Later, submit a *different* `DelegationVerified` transaction with altered parameters (different `newScopeCommitment` or nullifier), then construct an audit proof using the fraudulent event.

This is not a Poseidon collision — it is an event *substitution* attack. The adversary does not need to break any cryptographic primitive. They simply choose *which* events to publish and when.

In SPIFFE/SPIRE, equivalent state (the SPIFFE ID ↔ workload binding) is maintained by the SPIRE server, which is operated by the infrastructure owner and not by individual workload participants. Participants cannot unilaterally publish or withhold SPIRE identity assertions.

The construction's Section 5 says the registry requirement is "already the case in the current registry design" but provides no mechanism to force transaction submission, detect omitted hops, or prevent event replay from a prior session. The `sessionNonce` binding ties the proof to a specific session but does not prevent a participant from publishing a stale event from a previous session with a matching nonce.

**Why it works:** Game condition (c) cross-references on-chain events, but the game does not model the adversary's ability to control which events appear. This is not captured by PLONK soundness or Poseidon collision resistance. It is a completeness and liveness property of the on-chain event log that the construction assumes but does not enforce.

**In-threat-model?** No — the construction must either (a) define a commit-then-reveal scheme that prevents event omission (e.g., requiring the session nonce to appear as a commitment at session initiation before any delegation proofs are accepted), or (b) restrict the adversary model to exclude participants who control their own transaction submission. Neither is currently present.

---

### Attack 4: Wrong Abstraction Layer — WIMSE Solves the Stated Problem Without ZK

**Attack:**
The "structural impossibility" argument in Section 8 claims: "No composition of BBS+ derived proofs, RFC 8693 token exchanges, or WIMSE attestations can produce a self-verifiable proof of a relational invariant over hidden multi-credential state… without introducing a trusted aggregator."

This is only true if hiding intermediate scope *values from the auditor* is a hard requirement. But in every regulated deployment cited — NCUA examination, FFIEC guidance, AI model risk management (Section 7) — the examiner is the auditor, and examiners have subpoena authority. The NFCU scenario does not establish a legal basis for withholding intermediate permission bitmasks from an NCUA examiner; it assumes one.

WIMSE (draft-ietf-wimse-arch) addresses the actual threat: workload-to-workload token binding with delegation attestation, across organizational trust domains using SPIFFE federation. The Authorization Server in a WIMSE deployment is the trust anchor, not a single-point-of-failure — it is federated. An NFCU AS and a TransUnion AS can federate their SPIFFE trust bundles, and the resulting delegation token chain is auditable by any party the SPIFFE trust domain permits. The AS sees the scopes because it enforces them; the auditor queries the AS.

The construction's privacy claim — "examiner does NOT learn: who the intermediate agents are, what specific permissions each had, or the pipeline architecture" (Section 7) — solves a problem that WIMSE does not claim to solve because it assumes regulators should not have AS-level access. That assumption needs explicit justification, not assertion.

Further: for the journalist/source scenario (Section 7 variant), WIMSE and SPIFFE offer no mechanism for participant anonymity — the SPIFFE engineer concedes this is a genuine gap. But this scenario is presented as co-equal with the regulatory scenario, and the construction does not establish that the ZK machinery required for journalist anonymity is the right price to pay for the regulatory use case where it is unnecessary.

**Why it works:** The comparison table in Section 8 accurately lists WIMSE's limitations for the *privacy* use case. But it does not address whether the privacy requirement is justified for the regulatory use case, or whether the ZK complexity is proportionate. The construction is conflating "can prove narrowing without revealing scopes" (a capability) with "must prove narrowing without revealing scopes" (a requirement). WIMSE satisfies the stated deployment scenario — NFCU NCUA audit — without ZK, by granting the auditor AS query access. The ZK circuit is necessary only if the privacy requirement holds; the construction does not establish that it does.

**In-threat-model?** Partially. The journalist/source scenario (Section 7) is genuinely in-threat-model for participant anonymity — WIMSE cannot satisfy it, and the ZK construction can. But the regulatory scenario (Section 7, NFCU) is not established as requiring scope hiding from the examiner. The construction must cleanly separate these two use cases and provide a justification for why the regulatory examiner is adversarial with respect to intermediate scopes, or narrow the claim to the journalist/anonymity-class scenarios where ZK is demonstrably necessary.
