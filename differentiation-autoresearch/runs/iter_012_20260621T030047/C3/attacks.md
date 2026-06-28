# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Latency Kills Real-Time Agent Pipelines

- **Attack:** The construction's §6 estimates `< 5s` per `DelegationHopAccumulator` prove and `< 3s` for `ChainAuditProof`. A 4-hop pipeline (the NFCU scenario in §7) runs **four sequential on-chain transactions** before the pipeline is trusted to execute business logic. At minimum that's 20s of ZK proving, plus L2 finality, plus the audit proof. WorkOS issues a scoped token in `< 100ms`. Stytch M2M tokens are `< 50ms`. Any real-time AI agent loop — tool calls averaging 200-500ms — cannot absorb a 20s synchronous ZK tax per session. The construction does not address whether proving runs **before** the delegation (blocking) or **after** (which means the agent acts under unproven scope and the audit is retroactive).

- **Why it works / fails:** The construction is silent on whether `DelegationHopAccumulator` proofs are generated inline (blocking the pipeline) or batched post-hoc. If retroactive, the "in-circuit enforcement at presentation time" claim in §8 is false — an agent acts under unproven scope, and the "proof IS the enforcement" framing collapses to "proof IS the audit log," which is weaker than claimed. If synchronous, the 20s latency is a product-ending defect for the AI agent use case the construction explicitly targets.

- **In-threat-model?** No. The construction's threat model (§3) covers soundness and privacy, not latency or execution ordering. This is a product correctness gap disguised as a performance issue.

---

### Attack 2: On-Chain Accumulator = Blockchain Dependency at Every Hop

- **Attack:** `BolyraAuditRegistry.sol` (§2, on-chain components) requires calling `submitDelegationHop(...)` per hop — a live blockchain write that updates `chainAccumulators[sessionNonce]`. For the NFCU scenario (§7), this means **four L2 transactions during a member loan processing session**, each requiring gas, Base Sepolia (or mainnet) availability, and sub-second finality. The construction names Base Sepolia as the deploy target (CLAUDE.md). At Navy Federal's scale — 13M members, thousands of concurrent loan applications — gas costs and chain liveness become existential. More critically, **NCUA examination procedures do not recognize smart contract state as an authoritative audit artifact**. The examiner in §7 would require an export to a recognized format (CSV, PDF, JSON against a known schema), not a call to `verifyChainAudit()` on a Solidity contract.

- **Why it works / fails:** The §8 comparison table claims "verification is O(1) — ~300K gas on EVM." That 300K gas is **per audit query**, not per hop — and it assumes the NCUA examiner is equipped to call an EVM contract. They are not. The construction provides no off-chain alternative to the on-chain accumulator state that preserves the soundness argument. Removing the on-chain anchor breaks constraint 1 (`chainSeed === onChainChainSeed`) — the proof loses its binding to the actual executed chain and becomes a proof about arbitrary inputs.

- **In-threat-model?** No. The threat model (§3) treats the on-chain registry as a trusted component outside the game definition. An adversary who controls the L2 (or whose transactions are censored) can decouple the on-chain accumulator from the actual delegation chain — a gap the construction does not close.

---

### Attack 3: Enrollment Requires a Centralized Authority — Which Is Us

- **Attack:** Every `DelegationHopAccumulator` constraint 8 verifies `BinaryMerkleRoot(20)` — the delegatee must be enrolled in the Bolyra agent Merkle tree. The cross-org scenario (§8: "OpenAI agent → Anthropic agent → Mistral agent requires only that each agent is enrolled in the shared Bolyra Merkle tree") assumes a **shared global enrollment tree** across organizations. Who controls that tree? Who adds leaves? Who revokes? Who runs the enrollment API? That is an identity provider. It is Auth0. It is WorkOS. The construction calls it a "Merkle tree" but enrollment governance is identical to what any OAuth AS already provides — with the addition that Bolyra's enrollment authority, if compromised, lets an attacker enroll rogue agents whose credentials pass the ZK check. The `delegateeMerkleRoot` in per-hop public outputs (§2) is static per epoch — a rogue enrolled agent leaks nothing specific, but the enrollment root itself is a single point of failure the construction treats as external to its trust model.

- **Why it works / fails:** The §8 "no trusted third party" claim is accurate for the *verification* path (PLONK against a public vkey) but false for the *enrollment* path. The construction conflates "no authorization server at presentation time" with "no trusted third party," which are different claims. The k-anonymity argument ("tree contains thousands of agents, providing k-anonymity") is only true at scale — in an early-stage Bolyra deployment, the tree is small and the anonymity set collapses. The construction provides no analysis of anonymity as a function of enrollment tree size.

- **In-threat-model?** Partially. The `IntermediateAnonymity` game (§3) models `A` receiving on-chain per-hop outputs. But it does not model an adversary who **controls the enrollment tree** or who observes **which leaves are freshly added** around a delegation event (timing correlation). The privacy reduction (§4) is valid only for a fully-populated tree; the sparse-tree case is unaddressed.

---

### Attack 4: The NCUA Examiner Cannot Use This

- **Attack:** The headline scenario in §7 is an NCUA examination at Navy Federal. The examiner "verifies the PLONK proof on-chain (or off-chain against the verification key)." NCUA examination procedures (NCUA Letter to Credit Unions 01-CU-20, FFIEC IT Examination Handbook) require audit evidence in recognized, examiner-interpretable formats. A PLONK verification key and a 1.1 KB proof blob are not in the NCUA's toolkit. The examiner cannot independently audit what `pot16.ptau` is, whether the circuit constraints in §2 correctly implement narrowing, or whether the `BN254` curve parameters match the claimed security level. In practice, the examiner calls their standard vendor — Protiviti, Crowe, RSM — who have no Circom/PLONK expertise. The result: NFCU's compliance team must hire a ZK auditor ($300K+), produce a written attestation that the circuit constraints correctly implement monotonic narrowing, and get that attestation blessed by the NCUA. This is a multi-year adoption cycle. WorkOS ships a SOC 2 Type II report and an NCUA-recognized OAuth 2.0 audit log export today.

- **Why it works / fails:** The construction's §8 "why the baseline cannot match" table compares cryptographic properties — not procurement properties. The column headers are chosen to favor ZK (constant-size artifact, in-circuit enforcement). But the NCUA examiner's decision criteria are: (1) recognized standard (OAuth 2.0 / OIDC is RFC-backed; PLONK is an academic paper), (2) auditable by known vendors, (3) examiner-producible evidence trail. The construction claims to be "usable beyond narrow regulatory niches" in its gap statement, but the only deployment scenario given (§7) is the narrowest possible regulatory niche — an NCUA examination of a credit union AI pipeline.

- **In-threat-model?** No. The construction has no model for regulatory acceptance or examiner capability. This is not a cryptographic attack — it is the correct observation that the auditor in §7 is not the cryptographic verifier modeled in the `DelegationAuditSoundness` game. The real auditor is a human examiner whose threat model is "can I present this to my supervisor and the credit union's board."


## Persona: cryptographer

Applied cryptographer. Groth16/PLONK provenance: reviewed for CRYPTO and S&P. Reading §1–§6 of this construction.

---

### Attack 1: Phantom Chain Attack — `ChainAuditProof` is not bound to on-chain accumulator state

**Attack:** The `ChainAuditProof` circuit takes `finalAccumulator` as a **private input** (§2, Circuit 2 private inputs). The circuit verifies internal consistency of the accumulator trace starting from `onChainChainSeed` (Constraint 3–5). But the only public output linking to `finalAccumulator` is `chainDigest = Poseidon2(finalAccumulator, sessionNonce)` (Constraint 10). The on-chain registry stores `chainAccumulators[sessionNonce]` — the true final accumulator built from legitimately-submitted hop proofs. For the audit to be sound, the contract's `verifyChainAudit` must check:

```
chainDigest == Poseidon2(chainAccumulators[sessionNonce], sessionNonce)
```

The construction never states this check. The `verifyChainAudit` spec (§2, On-chain components) says only "verifies `ChainAuditProof` PLONK proof, emits `ChainAudited(...)`." No linkage to the stored accumulator.

**Exploit:** An adversary who controls the prover (e.g., the regulated entity under audit) runs a DIFFERENT accumulator trace — one where every hop passes the circuit's internal constraints but corresponds to fabricated `scopeCommitmentTrace` values, not to any proofs submitted via `submitDelegationHop`. The adversary chooses a `finalAccumulator` for this phantom chain, generates a valid PLONK proof for it, and presents `auditResult = 1`. The auditor verifies the PLONK proof and sees `chainLength = 4` — but the underlying chain never executed; no on-chain state was ever updated for it.

**Why it works:** The circuit enforces *internal* consistency of the accumulator trace starting from `onChainChainSeed`. It does not recursively verify the per-hop PLONK proofs (that would require recursive composition, which is absent from the construction). The chain seed is public and anchors the start, but nothing anchors the *end* to the on-chain `chainAccumulators[sessionNonce]` unless the contract performs the `chainDigest` check explicitly.

**Security argument gap (§4, Soundness sketch, step 5):** The argument claims "Each `scopeCommitmentTrace[i]` was a public output of a previously verified `DelegationHopAccumulator` proof." This is an *assertion*, not a constraint enforced by either circuit or the contract as specified. Without the contract-level binding, the reduction breaks at this step.

**In-threat-model?** YES — construction must address. Required fix: `verifyChainAudit` must revert unless `chainDigest == Poseidon2(chainAccumulators[sessionNonce], sessionNonce)`. This must be a stated circuit public input or a contract-level pre-check, not an implementation detail left to the reader.

---

### Attack 2: Scope Commitment Precomputation — `newScopeCommitment` is a deterministic fingerprint over a small input space

**Attack:** Each `DelegationHopAccumulator` proof emits `newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment)` as a **public output** (§2, Circuit 1). The adversary (auditor, AS, or any chain observer) receives this value for every submitted hop.

The input space is:
- `delegateeScope`: 64-bit bitmask, but with cumulative bit constraints (bits 4→3→2 implication, §CLAUDE.md permissions model) the valid set is far smaller — at most a few hundred distinct valid bitmasks under the 8-bit permission scheme described.
- `delegateeCredCommitment`: Stored as Merkle tree leaves in `BolyraAuditRegistry`. All enrolled agent credential commitments are enumerable from on-chain state (every leaf was submitted during enrollment).

A precomputation adversary:
1. Enumerates all enrolled credential commitments `C_1, ..., C_N` from the Merkle tree.
2. Enumerates all valid scope bitmasks `S_1, ..., S_k` (small: at most 256, practically much fewer).
3. Builds table `T[(S_j, C_i)] = Poseidon2(S_j, C_i)`.
4. For any observed `newScopeCommitment`, looks it up in `T` to recover `(scope, agent)`.

**Why it works:** The construction's privacy argument (§4, Privacy reduction) states: "recovering the scope or credential from the commitment requires inverting Poseidon (breaks A1)." This is true for arbitrary inputs. But Poseidon preimage resistance is for *random* preimages. When the input domain is polynomial-size (N enrolled agents × ~100 valid scopes = O(100N) entries), precomputation is O(100N) hash evaluations — not a preimage inversion. This is a dictionary attack, not a preimage attack.

The `IntermediateAnonymity` game (§3) is broken: the adversary recovers `(delegateeScope, delegateeCredCommitment)` for each hop from the per-hop public outputs, without ever touching the `ChainAuditProof`.

**In-threat-model?** NO — construction must address. The fix requires a hiding commitment: `newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment, r)` where `r` is a fresh random blinding factor kept private by the prover. Without this, the "anonymity set = all enrolled agents" claim in §4 (Privacy reduction, last paragraph) is vacuous.

---

### Attack 3: Cross-Session Correlation via Stable Commitment Tags

**Attack:** Even with blinding (fixing Attack 2), consider the following. The `newScopeCommitment` is derived from `(delegateeScope, delegateeCredCommitment)`. If the same agent participates with the same scope in two different delegation chains (two different `sessionNonce` values), they produce **the same `newScopeCommitment`** in both, since neither input is session-specific.

An observer who sees on-chain accumulator submissions across sessions maintains a ledger of `(sessionNonce, newScopeCommitment)` pairs. Two entries with matching `newScopeCommitment` across different `sessionNonce` values reveal: the same (agent, scope) pair appeared in both chains. In the whistleblower scenario (§2, Deployment scenario), even if the auditor cannot learn *who* the source is from a single chain, observing that the same `newScopeCommitment` appears in multiple chains — across the source's leak history — correlates them.

This is the **cross-session linkability** problem (§3 attack_prompts: "nullifier cross-session linkability"). The construction emits a `delegationNullifier = Poseidon2(delegationTokenHash, sessionNonce)` which IS session-specific — but the `newScopeCommitment` is NOT. The nullifier prevents double-spend per session; it does not prevent session linkability from the scope commitment.

The `DelegationAuditPrivacy` game (§3) compares two chains with "identical (auditPolicyMask, chainLength, sessionNonce)" — same session nonce by construction of the game. But a real adversary operates across sessions.

**Why it works against the stated game:** The stated privacy game (§3) artificially restricts both chains to the same `sessionNonce`. A stronger game — where the adversary sees proofs across different sessions — is not covered. The privacy reduction in §4 never addresses multi-session composition.

**In-threat-model?** NO — construction must address. The game definition is weaker than the deployment threat. Fix: either (a) make `newScopeCommitment` session-specific by binding a session-specific nonce into the commitment, or (b) explicitly tighten the privacy game to cover multi-session adversaries and argue unlinkability across sessions.

---

### Attack 4: HVZK Is Insufficient for Multi-Proof Composition — Simulation Extractability Gap

**Attack:** The security argument (§4, Assumption A4) invokes "Honest-Verifier Zero-Knowledge of PLONK." In the audit setting, the adversary simultaneously observes:
- All submitted `DelegationHopAccumulator` PLONK proofs (public, on-chain, adversary-accessible).
- The `ChainAuditProof` PLONK proof (presented to auditor).
- All corresponding public inputs and outputs.

HVZK guarantees that *each individual proof* is simulatable given public signals. It does **not** guarantee that the joint distribution of multiple proofs — with correlated witnesses — is simulatable. Composing multiple HVZK proofs under a *single shared witness* (e.g., the same `delegateeCredCommitment` appears in multiple per-hop proofs and in the audit proof's `scopeCommitmentTrace`) requires **simulation extractability (SE-NIZK)** or at minimum a UC composition argument in the random oracle model.

PLONK with Fiat-Shamir in the ROM *does* achieve simulation extractability under standard assumptions (Fischlin et al.; also Ganesh et al. 2022 for "straight-line simulation extractability"). But the construction does not cite this. It cites only HVZK (A4), which is the weaker property. A reviewer at CRYPTO/S&P would reject a proof that uses HVZK in a multi-proof setting without arguing composability.

Concretely: the `IntermediateAnonymity` adversary (§3) sees per-hop proofs AND the audit proof. The HVZK simulator for the audit proof operates independently of the per-hop proof transcripts. If there is any leakage from the joint distribution that cannot be explained by the per-hop simulators and audit simulator running independently (e.g., correlated challenges due to shared Fiat-Shamir hash inputs), the privacy claim is unproven.

**In-threat-model?** YES — construction survives in practice if the authors replace A4 with the SE-NIZK property of PLONK in ROM (citing the appropriate theorem), but as stated the security argument has a formal gap. The reduction sketch at §4 ("Privacy reduction") must be rewritten to invoke simulation extractability and argue joint simulatability of the full transcript `(π_hop_1, ..., π_hop_n, π_audit)`.


## Persona: cu_ciso

### Attack 1: Third-Party Risk Management Inversion

- **Attack:** Section 7 of the construction explicitly advertises that the NCUA examiner "does **not** learn: which vendors NFCU uses (Experian, SendGrid)." The CISO presents this as a feature. The NCUA examiner flags it as a control failure.

  NCUA Part 748, Appendix B, and the FFIEC IT Examination Handbook on Outsourcing Technology Services both require the CU to maintain a complete, auditable inventory of third-party service providers with access to member data. GLBA Safeguards Rule (16 CFR § 314.4(f)) mandates that the CU oversee service provider arrangements, including contractual controls and annual reviews. The CU's own Vendor Management Policy — required by NCUA examiners as a governance artifact — must list every entity that touches member NPI.

  The construction's privacy guarantee (hiding intermediate participants via `delegateeMerkleRoot` anonymity set) directly conflicts with the CU's obligation to *know and document* its vendor relationships. Hiding Experian and SendGrid from the audit trail is not a competitive advantage — it is a gap in the required third-party risk program. The examiner will cite the missing vendor inventory regardless of what the ZK proof says.

- **Why it works / why it fails:** The construction never addresses this conflict. It treats auditor privacy as uniformly desirable. For the journalist/whistleblower scenario (Section 7, variant 2), anonymity is the point. For the NFCU loan pipeline scenario (Section 7, primary), it inverts the regulatory requirement. The examiner's job is precisely to verify that NFCU *knows* who Experian and SendGrid are and has contracts with them. Showing the examiner a proof that hides those names fails the exam.

- **In-threat-model?** No. The construction must address the dual-mode problem: the same construction that is privacy-preserving for whistleblower chains is compliance-violating for regulated vendor chains. Selective disclosure — where NFCU can prove scope narrowing to the examiner AND separately produce the vendor inventory through conventional means — needs to be explicitly specified. The current construction provides no mechanism for the CU to "opt out" of intermediate anonymity when disclosure is legally required.

---

### Attack 2: Incident Response Forensic Nullity

- **Attack:** At 2am, an alert fires: the Experian API agent made 47,000 credit report pulls in 90 seconds. The CISO opens an incident. The construction can prove the agent had `READ_DATA` scope. It cannot prove what the agent read, when, or from which member records.

  NCUA Part 748 requires a response program for security incidents involving member data. GLBA's Safeguards Rule (amended 2021) mandates notifying NCUA within 30 days of discovering a notification event. The FTC's Safeguards Rule requires the CU to preserve forensic evidence for regulatory review. FFIEC CAT Domain 3 (Cybersecurity Controls) requires logging and monitoring of all access to sensitive systems.

  The `ChainAuditProof` reveals `auditResult = 1`, `chainLength = 4`, and `chainDigest`. It proves that the Experian agent had `READ_DATA` and not more. It proves nothing about *what data was actually accessed during the session*. The scope proof and the access log are orthogonal artifacts. After the incident, the examiner asks: "Show me the access log for the Experian agent during sessionNonce `0xabc...`." The on-chain `chainAccumulators[sessionNonce]` and `delegationNullifier` are present. None of them are an access log.

  The construction provides a scope-narrowing proof. It does not provide a data-access audit trail. These are different controls. The NCUA examiner needs both.

- **Why it works / why it fails:** The construction conflates "scope was valid" with "access was auditable." Section 7 describes the NCUA examiner verifying "that no agent in the loan pipeline exceeded its mandate." Mandate verification ≠ access logging. NCUA Part 748.1(b) defines "security program" to include detection AND response — detection requires logs of actual access events, not proofs that authorized scope was properly delegated. The construction is silent on this gap.

- **In-threat-model?** No. The construction must either (a) explicitly scope itself as a delegation audit tool only and document what complementary controls (SIEM, access logs) are required, or (b) extend the construction to include a data-access commitment at each hop — a Poseidon commitment over accessed record hashes that the audit proof can bind to — so the scope proof and the access trail are cryptographically linked.

---

### Attack 3: Examiner Interpretability and SOC 2 Evidence Mapping

- **Attack:** The NCUA examiner arrives with the IT Examination Handbook and a questionnaire. One line asks: "Provide evidence that third-party API integrations operate within authorized permission scopes." The CISO hands the examiner a PLONK proof — a ~1.1 KB binary blob and an Ethereum transaction hash showing `auditResult = 1`.

  The examiner is not a ZK cryptographer. The examiner's evidence standard is: a human-readable document, a SOC 2 Type II report, a log extract, or a policy attestation. A PLONK proof is none of these. The CU's internal audit team, its external auditors (likely a regional CPA firm), and the NCUA examiner all need to evaluate this control. None of them will run a PLONK verifier.

  FFIEC CAT Maturity Level 3 ("Intermediate") requires that the institution be able to explain its security controls in plain language to examiners. SOC 2 Type II requires that controls be documented, tested, and reported by a qualified auditor over a 6-12 month period. A ZK proof generated on-demand does not constitute a SOC 2 tested control — it is an output of a control, not the control itself.

  The board narrative is also broken. Section 7 claims the CISO can tell the board "the chain narrowed monotonically." What the board actually needs is: who authorized what, where is the paper trail, and what would we say to a plaintiff's attorney if the Experian agent caused a FCRA violation.

- **Why it works / why it fails:** The construction provides a cryptographic object, not a regulatory artifact. It is necessary but not sufficient for an NCUA examination. The claim that "The NCUA examiner verifies the PLONK proof on-chain (or off-chain against the verification key)" (Section 7, step 3) is operationally fantasy for 2026 credit union examinations. No NCUA examiner has a PLONK verifier in their toolkit.

- **In-threat-model?** No. The construction must specify the human-readable evidence layer that wraps the cryptographic proof — a standardized attestation document that a CPA firm or examiner can sign off on, referencing the on-chain transaction hash and verification key, translated into plain-language control language that maps to NCUA Part 748 sections. The ZK proof is the machine-verifiable substrate; the construction must also define the human-verifiable surface.

---

### Attack 4: On-Chain Dependency Creates BCP / Availability Risk

- **Attack:** Section 2's `BolyraAuditRegistry.sol` and `submitDelegationHop(...)` require that every delegation hop submit a verified PLONK proof to an EVM chain before the next hop can proceed. The on-chain `chainAccumulators[sessionNonce]` and `lastScopeCommitment[sessionNonce]` are updated per hop and read by the next hop's `previousScopeCommitment` public input.

  The NFCU loan pipeline (Section 7) has 4 hops. Each hop submission costs ~300K gas (Section 8, comparison table). At current Base Sepolia / Base mainnet congestion, each on-chain submission introduces latency and a dependency on L2 block finality. If Base experiences degraded throughput — as happened during NFT mint events in 2023 — the loan pipeline stalls mid-chain. The `submitDelegationHop` transaction fails to confirm, and the next hop cannot proceed because its `previousScopeCommitment` is not yet on-chain.

  NCUA examiners assess Business Continuity Plans under Part 748 and the FFIEC BCP booklet. A core loan-processing pipeline that blocks on an L2 blockchain transaction is a single point of failure that a BCP reviewer will flag immediately. The CU's core processor (FIS, Fiserv, Jack Henry) guarantees 99.9%+ uptime. Base Sepolia has no SLA. Base mainnet has no contractual SLA with the CU.

  The CISO's question from the attack prompts applies directly: "If your on-chain registry has a 1% outage budget, that's more than my core processor."

- **Why it works / why it fails:** The construction's security model requires on-chain state (`chainAccumulators`, `lastScopeCommitment`) to be the chain-of-custody anchor. Without per-hop on-chain submission, the `ChainAuditProof` cannot bind to publicly auditable state — the whole "no trusted third party" claim collapses if the accumulator is stored off-chain by NFCU itself. The tension is structural: the trustlessness guarantee requires on-chain state; on-chain state introduces availability risk that conflicts with BCP requirements.

- **In-threat-model?** No. The construction must specify a degraded-mode path: either (a) an off-chain accumulator with a designated custodian (reintroducing a trusted party) and a reconciliation protocol that batches on-chain settlement after the fact, or (b) a rollup/blob-submission mechanism with defined finality guarantees and a measurable SLA the CU can include in its BCP documentation. As written, the construction provides no answer to "what happens to an in-flight loan application when the L2 is congested."


## Persona: rfc7662_advocate

---

### Attack 1: BBS+ + Sigma Protocols DO Prove Hidden Bitmask Subset Relations — §8 Comparison Table Is Factually Wrong

**Attack:** The construction's §8 table claims "BBS+ can hide individual claims but cannot prove ordering relationships (⊆) over hidden bitmasks — no native set-containment predicate." This is false, and I can cite the literature that disproves it.

BBS+ (in the Camenisch-Lysyanskaya lineage) supports commit-and-prove extensions. A scope bitmask is a 64-bit integer. To prove `childBits ⊆ parentBits` over *hidden* values, you need:

1. A commitment to both bitmasks (BBS+ blind signing gives you this)
2. A sigma protocol proving `∀i: (1 - childBits[i]) OR parentBits[i] = 1`

This is a conjunction of linear constraints over {0,1}-committed values — solvable by Bulletproofs inner product argument or standard CDS composition. Hyperledger AnonCreds has done this since 2002 (Camenisch-Lysyanskaya "A Signature Scheme with Efficient Protocols," SCN 2002). The W3C VC 2.0 spec's BBS Appendix explicitly describes "predicate proofs" including range proofs and set membership over committed attributes.

The construction has *not* shown that the baseline cannot achieve hidden-bitmask subset proofs — it has only shown that *vanilla* BBS+ lacks this. A well-equipped RS-side verifier using BBS+ + Bulletproofs produces the same monotonic narrowing proof without a ZK trusted setup ceremony.

**Why it matters:** This collapses the "Monotonic narrowing proof without scope disclosure" row in §8 — the table's strongest comparative claim. The construction must either (a) cite a formal impossibility result for BBS+ set containment proofs, or (b) acknowledge the baseline can achieve this property and reframe the differentiator.

**In-threat-model?** No — the construction must address this. The §8 baseline comparison is the paper's load-bearing differentiation argument.

---

### Attack 2: The PLONK Trusted Setup IS a Trusted Third Party — "No Trusted Authority" Is Circular

**Attack:** Section 8 claims: "Proof is self-verifying: PLONK verification against a public verification key. No AS, no federation authority, no trust anchor beyond the cryptographic setup."

That final clause does all the work, and it contains the concession. `pot16.ptau` — the universal SRS used for both `DelegationHopAccumulator` and `ChainAuditProof` — is a *multi-party computation ceremony*. Its security guarantee is "at least one participant was honest." The construction inherits this trust assumption without acknowledging it.

Now compare: RFC 8693 + draft-ietf-oauth-jwt-introspection-response. The AS signs an introspection JWT at issuance. The auditor verifies the AS's signature offline using the AS's published JWK Set (RFC 7517). The trust model is: trust the AS signing key.

Both models require trusting an external ceremony:
- **Bolyra:** Trust that at least one of ~1000 ceremony participants was honest; trust that the circuit source is the one that produced the proving/verification keys; trust the Poseidon MDS constants over BN254.
- **RFC 8693:** Trust the AS's ECDSA-P256 key, which can be rotated, revoked, and monitored via Certificate Transparency.

The AS signing key is actually *more auditable* — it has a known identity, appears in OIDC discovery metadata (RFC 8414), and can be placed under hardware security module attestation (FIPS 140-3). The `pot16.ptau` MPC ceremony happened once and cannot be revoked if a participant later proves dishonest.

**DPoP analogy (attack_prompt seed):** "Name the property DPoP cannot provide." DPoP cannot provide monotonic narrowing proofs across anonymous multi-hop chains. But that is a *specific* property, not "no trusted third party." The construction is overclaiming "no trusted authority" when it has merely *relocated* the trust anchor from a live AS to a one-time MPC ceremony.

**In-threat-model?** Yes and no — the construction survives for the specific property of *cross-org delegation without a shared live authority*. But the blanket "no trusted third party" framing in §8 is false and must be corrected to "no shared live authorization server," which is a weaker but still genuine claim.

---

### Attack 3: On-Chain Per-Hop Public Outputs Break Participant Anonymity in Sparse Trees — Whistleblower Scenario Fails

**Attack:** Every `DelegationHopAccumulator` proof is submitted on-chain *as the pipeline executes*. The public outputs committed to the blockchain are:

- `newScopeCommitment` — `Poseidon2(delegateeScope, delegateeCredCommitment)`
- `delegateeMerkleRoot` — the Merkle root of the enrollment tree at that moment
- `delegationNullifier` — `Poseidon2(delegationTokenHash, sessionNonce)`
- **Submission timestamp** (block timestamp — not in the threat model)

For the whistleblower scenario (§7): the construction claims "the tree contains thousands of agents, providing k-anonymity." But:

1. **Sparse tree attack:** If the agent tree at time T has only 12 enrolled agents, `delegateeMerkleRoot` is consistent with a tree of 12 leaves. An adversary monitoring the chain knows the tree state at each block. If the whistleblower source enrolled recently and is leaf index 11 of 12, the root combined with the submission timestamp narrows the anonymity set to ~1.

2. **Timing correlation:** The `IntermediateAnonymity` game (§3) gives the adversary the per-hop public signals. In the game, the adversary knows the *timing* of each `submitDelegationHop` call. In the whistleblower scenario, the leak event is observable externally (the journalist publishes the document). An adversary who timestamps both the on-chain hop submissions and the publish event has a traffic-analysis oracle that the game definition explicitly excludes from the adversary's view — but that an NCUA examiner or a subpoena plainly provides.

3. **`newScopeCommitment` reuse across sessions:** The same delegatee with the same scope generates the same `newScopeCommitment = Poseidon2(scope, credCommitment)` across different sessions unless `credCommitment` is session-specific. The circuit definition shows `delegateeCredCommitment` as private input with no freshness mechanism — it is the agent's stable credential commitment. Two sessions involving the same agent at the same scope produce the same `newScopeCommitment`, enabling cross-session linkability that the `IntermediateAnonymity` game (which is single-session) does not model.

**In-threat-model?** No — both the sparse-tree anonymity collapse and the `newScopeCommitment` cross-session linkability are out-of-scope in the formal game definitions. The construction's on-chain architecture directly undermines the whistleblower-safety claim in §1 and §7. Fix required: add a session-scoped blinding factor to `credCommitment` for the per-hop proof, and add a minimum-anonymity-set precondition to the whistleblower deployment scenario.

---

### Attack 4: Audience-Bound Tokens + PPIDs Eliminate Cross-RS Linkability Without ZK — The Residual Gap Is Narrower Than Claimed

**Attack (seeds: attack_prompts 3 and 4):** The construction's §8 row "Intermediate participant anonymity" claims PPIDs are insufficient because "the AS and any auditor with `act` chain access can correlate." True — but this sets up a strawman. The actual RFC 7662 + extensions comparison should be:

**RFC 9449 DPoP + RFC 8707 Resource Indicators + OIDC PPID, with per-RS filtered introspection (draft-ietf-oauth-jwt-introspection-response §5 "claims filtering"):**

- DPoP sender-constrains each token to a per-session proof-of-possession key. A compromised token is useless without the DPoP private key (RFC 9449 §9).
- RFC 8707 audience-binds the token to a specific RS, so forwarding to a different RS (hop widening) fails at the RS level without AS involvement.
- OIDC PPIDs generate distinct `sub` values per (user, RS) pair — cross-RS correlation requires AS-level collusion, not just RS-level observation.
- The AS's per-RS introspection policy (RFC 7662 §2.2 "resource server policy") can be configured to return only the claims relevant to that RS — the AS acts as a selective disclosure filter without exposing intermediate scopes to any RS.

**What DPoP cannot provide:** A proof to a third-party auditor that monotonic narrowing held across hops *where the auditor does not trust any single party in the chain* and *where intermediate participants must be anonymous*. DPoP sender-constrains each individual token but produces no cross-hop narrowing artifact. A NFCU auditor who trusts NFCU's AS logs can verify narrowing trivially — but a *distrusting* cross-org auditor cannot, because the AS logs are NFCU-controlled.

**The real residual gap — precisely stated:** The irreducible advantage of `ChainAuditProof` is: *a cross-organizational, distrusting auditor who trusts no single party in the chain can verify monotonic narrowing without any party disclosing intermediate scopes or identities.* This is a real and meaningful property. But it is *much narrower* than the §8 table claims. The NFCU examiner scenario (§7) uses NCUA — a *trusted regulator* — as the auditor. An NCUA examiner who can subpoena AS logs does not need Bolyra for this audit; the ZK construction is only load-bearing when the auditor is *adversarial* or *distrusted*.

The construction must clarify: in the §7 scenario, is NCUA a trusted or distrusted auditor? If trusted, RFC 7662 + signed JWT introspection suffices. If distrusted, the construction is correct but the scenario description is misleading (regulators typically have subpoena power that supersedes cryptographic privacy).

**In-threat-model?** Partially — the construction survives for the *genuinely adversarial cross-org auditor* case. But the framing of §8 as a categorical defeat of the RFC 7662 baseline is overstated. The paper needs to scope its claim precisely to: "auditor who is distrusted by all participants and lacks out-of-band access to AS logs or delegation tokens." That is the irreducible niche, and it should be stated as such rather than as a broad defeat of OAuth/OIDC.


## Persona: spiffe_engineer

### Attack 1: The Enrollment Tree Is a Shared Authority in Disguise

- **Attack:** Section 8 claims "No trusted third party — proof is self-verifying … no AS, no federation authority, no trust anchor beyond the cryptographic setup." But Circuit 1 (`DelegationHopAccumulator`) Constraint 8 requires `BinaryMerkleRoot(20)` against the agent tree, and `BolyraAuditRegistry.sol` stores `chainAccumulators` keyed by session. *Someone* controls agent enrollment — who publishes the Merkle root, who can insert or remove leaves, who governs the registry contract? In SPIFFE, the SPIRE server is the explicit authority, its key material is attested by infrastructure (TPM, k8s node attestor), and trust-domain federation is governed by explicit policy bundles. Bolyra replaces the SPIRE server with an unnamed enrollment oracle and a smart contract owner. The security of every `delegateeMerkleRoot` check — and therefore the `IntermediateAnonymity` game — reduces to "trust whoever controls that contract." The claim of no trusted third party is simply false; the party is just implicit and harder to audit.

- **Why it works / fails:** The construction has no section addressing enrollment authority governance, key rotation for the Merkle tree, or what happens when the registry contract admin key is compromised. SPIFFE explicitly specifies SPIRE server HA, node attestor trust chain, and key rotation. Bolyra leaves the hardest part unstated.

- **In-threat-model?** No — the adversary model in §3 only bounds adversaries controlling "up to n-1 of n delegation participants." A malicious enrollment authority is entirely outside the game definition. The construction must address it.

---

### Attack 2: Per-Hop On-Chain Submissions Leak Chain Topology and Timing

- **Attack:** `submitDelegationHop(...)` is called once per hop against `BolyraAuditRegistry.sol`. Each call updates `chainAccumulators[sessionNonce]` and `lastScopeCommitment[sessionNonce]` on a public ledger. The public outputs of each `DelegationHopAccumulator` proof include `newScopeCommitment`, `delegationNullifier`, `delegateeMerkleRoot`, and `newAccumulator` — all emitted as calldata or logs. An adversary watching the chain learns:

  1. Exact chain length and hop timing (number of `submitDelegationHop` calls per `sessionNonce`).
  2. The `newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment)` at every hop. For common enterprise permission profiles, `delegateeScope` lives in a small set (e.g., `0b00000001`, `0b00000011`, `0b00001011`). Brute-forcing the 64-bit bitmask over a realistic population of issued credentials is feasible — the anonymity set for `delegateeScope` is tiny, not 2^64.
  3. The `delegateeMerkleRoot` per hop — which, contrary to the anonymity claim in §3, is not a fixed global root. If the per-hop verifier circuit outputs a *specific* root (e.g., after a recent enrollment batch added only 3 agents), the root fingerprints a small sub-population.

  The `IntermediateAnonymity` game in §3 grants the adversary "on-chain state (including per-hop DelegationHopAccumulator public outputs)" — meaning the construction's own game allows this attack. The SPIFFE comparison is instructive: the Workload API is a local Unix socket call; SVIDs are never broadcast to a public ledger. There is no per-hop on-chain footprint in SPIFFE/WIMSE.

- **Why it works / fails:** The privacy argument in §4 says `newScopeCommitment` "reveals nothing about intermediates under A1 (Poseidon is a one-way function in ROM)." This is correct for the preimage, but the scope bitmask is not a high-entropy secret — it's drawn from a small named vocabulary. Poseidon being one-way doesn't help when the preimage space has cardinality ~8.

- **In-threat-model?** Partially. The game bounds the adversary to guessing a 1-of-2 participant (`a₀` vs `a₁`). But the real threat is an adversary who correlates `newScopeCommitment` across sessions to build a probability distribution over participants — a traffic-analysis attack the game explicitly excludes. The construction must address this, either by proving the scope commitment hides the bitmask against a small-domain adversary, or by committing to additional blinding randomness in the scope commitment (currently absent from `Poseidon2(delegateeScope, delegateeCredCommitment)`).

---

### Attack 3: WIMSE Token Exchange Already Handles the Cross-Org Audit Case — The Comparison Is a Strawman

- **Attack:** Table 8 claims "Cross-org delegation requires either a shared AS or WIMSE federation with mutual trust. Neither produces a single auditable artifact proving cross-org narrowing without a common authority." This mischaracterizes the WIMSE architecture (draft-ietf-wimse-arch §5, workload-to-workload token exchange). WIMSE separates the *issuance* authority (SPIRE per domain) from the *audit* authority: each domain signs its own delegation token using its SVID key material, producing a chain of JWT-SVIDs where each carries `act` claims. An auditor in WIMSE does not need a shared AS — they need each domain's JWKS endpoint (public, federated via SPIFFE bundle endpoint). The audit artifact is a chain of signed JWTs, each verifiable against a public key with no common authority. The construction's Table 8 baseline column is wrong on this point.

  More importantly: the `ChainAuditProof` (§2, Circuit 2) proves the *delegation structure* narrowed monotonically, but it does not prove that the *actual runtime behavior* of the tool call used the delegated credential. Constraint 7 verifies `finalScope` satisfies `auditPolicyMask`, where `finalScope` is a private input asserted by the proof generator. A malicious NFCU pipeline could: (a) generate a valid delegation chain proving scope narrowed to `READ_DATA` at the terminal, (b) have the Experian agent actually call the tool with a separate, broader credential obtained out of band. The `ChainAuditProof` verifies credential structure, not credential use. In SPIFFE/WIMSE, the SPIRE agent *controls* the Workload API call — it enforces at the socket level that only the attested SVID is presented. There is no equivalent enforcement binding in Bolyra.

- **Why it works / fails:** The construction's audit guarantee is "the chain as structured was correctly delegated." It makes no claim about binding credential presentation to the ZK proof at runtime. The NCUA examiner scenario in §7 is therefore weaker than stated — a sophisticated operator can satisfy the ZK proof while bypassing it in practice.

- **In-threat-model?** No. The threat model in §3 defines soundness as "some hop violated *bitwise subset*" in the chain. Runtime credential use outside the proven chain is not modeled. This is a gap the construction must close, either by binding the handshake nonce to an on-chain transaction that actually invokes the tool, or by acknowledging the audit scope is limited to delegation structure only.

---

### Attack 4: MAX_HOPS=16 and hopIndex Are Circuit Constants — Operational Inflexibility SPIFFE Does Not Have

- **Attack:** §2 sets `MAX_HOPS = 16` as a compile-time constant in `ChainAuditProof`. The circuit instantiates `accumulatorTrace[MAX_HOPS]` and `scopeCommitmentTrace[MAX_HOPS]` as fixed-width arrays. Changing the maximum chain depth requires circuit recompilation, a new `pot16.ptau` ceremony (or verification that the new constraint count still fits), regeneration of PLONK keys, redeployment of the `BolyraAuditRegistry.sol` verifier contract, and migration of any active sessions. In production SPIFFE/SPIRE, delegation depth is a runtime policy parameter in the SPIRE server config (`max_workload_ttl`, trust propagation rules) — changing it is a config reload, not a cryptographic ceremony.

  The `hopIndex` in `DelegationHopAccumulator` is an 8-bit signal (§2, Table 1) allowing up to 255 hops per-hop — but `ChainAuditProof` only verifies up to `MAX_HOPS=16`. These two limits are silently inconsistent. A chain with 17 hops can be individually proven via `DelegationHopAccumulator` and submitted on-chain successfully, but `ChainAuditProof` cannot audit it — the multiplexer for unused hops (§2, Constraint 12) has no mechanism to handle `hopCount > MAX_HOPS`. The construction does not specify what happens in this case: does proof generation fail silently, does the circuit output `auditResult = 0`, or is there an underconstraint that allows `hopCount = 3` to be asserted against a 17-hop on-chain accumulator?

- **Why it works / fails:** The `ChainAuditProof` Constraint 4 iterates `i` in `[1, hopCount)` over the fixed `accumulatorTrace[MAX_HOPS]` array. If `hopCount` is a private input and there is no range-check enforcing `hopCount ≤ MAX_HOPS` as a circuit constraint (it is not listed in §2's constraint enumeration), a prover could supply `hopCount = 3` against a 17-hop on-chain chain, and the proof would verify correctly while `chainLength = 3` is reported to the NCUA examiner — underreporting the actual chain depth. This is a concrete soundness gap, not just an operational concern.

- **In-threat-model?** Yes (the soundness game covers forged `auditResult = 1`) — but the specific vector of `hopCount` underreporting is not addressed in the security argument in §4, which only sketches the case where a hop violates bitwise subset. The construction survives if `Num2Bits(8)` on `hopCount` is constrained AND an explicit `hopCount ≤ MAX_HOPS` constraint is added, and the paragraph in §4 step 4 is extended to cover this. As written, it does not.
