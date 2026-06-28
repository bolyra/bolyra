# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The Enrollment Blind Spot — AS Correlation Before the "Hot Path" Begins

- **Attack:** The construction claims the AS is "removed from the per-RS authorization hot path entirely." But the IND-UNL-AS game only applies *post-enrollment*. The one-time enrollment requires the AS to bind a `credCommit` to an agent identity. An adversarial AS operating at enrollment time sees: (a) the agent's identity, (b) the credential commitment, and (c) the timing of enrollment relative to subsequent RS access patterns. The nullifier `Poseidon2(rsScopeId, credCommit)` is scope-specific, but `credCommit` itself is issued *by the AS* and is constant across scopes. If the AS logs enrollment timestamps and the RS logs first-access timestamps, the AS+RS colluding variant must account for this enrollment-time linkage — but the construction only defines the colluding game for *post-enrollment* interactions. The gap is real: enrollment leaks a timing anchor.
- **Why it works:** Section 3 (IND-UNL-AS-RS colluding variant) does not include the enrollment event in the adversary's oracle. A colluding AS+RS can intersect `{enrollment_time, agent_id}` with `{first_proof_submission_time, rsScopeId}` without breaking Poseidon at all.
- **In-threat-model?** No — the construction must address enrollment-phase leakage, either via anonymous enrollment (Semaphore group join without AS knowing which leaf corresponds to which agent) or by explicitly bounding what the game assumes the adversary knows at enrollment.

---

### Attack 2: Epoch Batching Compounds the Latency Problem Into a Product Non-Starter

- **Attack:** The construction cites "epoch batching + `epochSalt`" as the timing side-channel mitigation. But epoch batching *adds latency on top of already-slow proof generation*. PLONK at ~16,300 constraints on client hardware takes 8–15 seconds. If you batch releases to a 30-second or 60-second epoch window to hide timing, your p99 latency for an agent authorization is 60s + 15s = 75 seconds. For Kaiser Permanente's referral scenario: a physician's agent waiting 75 seconds for an authorization to go through is dead on arrival in any EHR integration. WorkOS issues a token in <100ms with zero batching needed. The construction presents epoch batching as a *mitigation* but it's actually a product tax that hits hardest in the exact healthcare scenario the construction uses as a flagship.
- **Why it works:** The construction acknowledges the timing side channel but frames epoch batching as a solution without quantifying the latency budget. Enterprises evaluate this at integration time, not at paper-review time.
- **In-threat-model?** No — the construction must either (a) show proof generation can reach <500ms on target hardware (e.g., with rapidsnark on mobile/edge), or (b) redesign the epoch window to be small enough that latency is acceptable *and* large enough that timing correlation is broken. These two constraints may be in tension and need an explicit tradeoff analysis.

---

### Attack 3: BSA/AML Makes the CU Privacy Guarantee a Compliance Liability, Not a Feature

- **Attack:** The Navy Federal CU scenario is framed as: "CU-as-AS must not see member merchant graph." But for a federally-chartered credit union under BSA/AML (31 U.S.C. § 5318), the CU is a *covered financial institution* legally required to monitor transaction patterns for suspicious activity reporting (SARs). If Bolyra's cross-scope unlinkability *prevents the CU from seeing the member's merchant access graph*, the CU cannot fulfill its SAR obligations. The construction's flagship CU scenario is not a feature to the CU's compliance officer — it's a regulatory liability. Auth0 + WorkOS deliberately *preserve* AS-level visibility precisely because enterprise compliance teams require it. Bolyra's strongest technical claim is directly opposed to what the CU buyer needs to stay in regulatory compliance.
- **Why it works:** This is a buyer-level objection, not a cryptography-level one. The compliance officer will veto the deployment before it reaches the engineering team. The construction needs to address how BSA/AML audit requirements coexist with cross-scope unlinkability — a selective disclosure or audit-log escrow mechanism is not mentioned anywhere.
- **In-threat-model?** No — the construction must define a compliance mode where a designated auditor (distinct from the operational AS) can de-anonymize on court order or SAR trigger, without giving the AS real-time correlation capability. Selective disclosure proofs or escrow keys would address this but are absent.

---

### Attack 4: Poseidon PRF Reduction Is a Procurement Blocker at Regulated Institutions

- **Attack:** The security reduction chains to the Poseidon PRF assumption. Poseidon is a ZK-friendly hash designed for arithmetic circuits — it is not a NIST-approved cryptographic primitive. NCUA-regulated credit unions and HIPAA-covered healthcare entities procuring cryptographic infrastructure are subject to guidance from NIST SP 800-57 and, increasingly, NIST SP 800-208. Their procurement checklists ask: "Is this built on NIST-approved algorithms?" The answer for Bolyra's core unlinkability guarantee is no — it rests on a non-standardized algebraic hash. WorkOS/Auth0 issue tokens using RS256/ES256 (NIST P-256), which passes any procurement checklist by default. Bolyra will be blocked at the vendor security questionnaire stage at the exact institutions — CUs and health systems — named in the construction's flagship scenarios.
- **Why it works:** This is purely a procurement/sales-cycle attack, not a cryptographic one. The construction does not address NIST alignment or provide a migration path to standardized primitives. Even a paragraph acknowledging NIST PQC (ML-KEM, ML-DSA) alignment would help.
- **In-threat-model?** No — the construction should acknowledge the NIST-alignment gap and either (a) propose a hybrid construction pairing Poseidon with SHA-3 for the portions that face compliance review, or (b) explicitly scope the target market to institutions where Poseidon is acceptable (DeFi, crypto-native operators) and stop using CU/healthcare as flagship scenarios until standardization catches up.


## Persona: cryptographer

---

### Attack 1: AS-Controlled Nullifier Precomputation (Nullifier Domain Collapse)

- **Attack:** The nullifier is defined as `Poseidon2(rsScopeId, credCommit)`. The AS issued the credential — it therefore knows or can reconstruct `credCommit` (it signed the commitment, or the commitment appears on-chain in the enrollment registry the AS manages). RS instances must register their `rsScopeId` with *some* authority to be accepted by the verifier circuit; if the AS operates or observes that registry, it learns the full `(rsScopeId, credCommit)` table and can precompute every nullifier for every enrolled agent × every RS. The adversary then watches nullifiers appear during proof verification and reads the agent-RS graph directly from the nullifier store — *without breaking Poseidon*.

- **Why it works / why it fails:** It works because the PRF argument (`Poseidon2` is a PRF ↔ breaks Poseidon) is only valid when the adversary does *not* control both inputs. The reduction sketch presumably holds `credCommit` as a secret witness. But the AS, as credential issuer, has out-of-band access to `credCommit` through the issuance transcript. The construction removes the AS from the *authorization hot path* but does not remove AS knowledge of *credential material*. The reduction therefore does not go through against a credential-issuing AS.

- **In-threat-model?** **No.** The IND-UNL-AS game must explicitly bound what the adversary learns during credential issuance (the "setup phase" of the game). If the game allows the AS to see `credCommit` at enrollment time (which it must, since the AS signs it), the reduction to Poseidon PRF has a trivial break. The game definition or the nullifier derivation must be revised — e.g., derive `credCommit` from a blinded commitment the AS never sees in cleartext, or use a second secret (`blindingSalt`) the agent samples post-issuance: `Poseidon2(rsScopeId, Poseidon(credSecret, blindingSalt))` where `blindingSalt` never leaves the agent.

---

### Attack 2: Honest-Verifier vs. Malicious-Verifier Zero-Knowledge Gap

- **Attack:** Standard PLONK achieves *honest-verifier* zero-knowledge (HVZK): the simulator works when the verifier's challenges are honestly sampled. The IND-UNL-AS game places an *adaptive*, *potentially malicious* adversary in the role of the AS/verifier. A malicious verifier can choose verification challenges (in an interactive variant) or, in the Fiat-Shamir setting, craft public inputs adversarially to probe the witness. Without a formal proof that the PLONK instantiation used here achieves *simulation-extractable ZK* (SE-ZK) or at minimum *malicious-verifier ZK*, the "unlinkability under adversarial AS" claim is unsubstantiated. Concretely: the adversary submits two honestly-generated proofs `(π₁, π₂)` from the same agent to different RS instances, then queries the "real-or-simulated" oracle with crafted public inputs that cause transcript overlap detectable by a distinguisher.

- **Why it works / why it fails:** PLONK (KZG variant) achieves simulation-extractability in the algebraic group model + ROM, but this requires the full proof of Theorem 1 in Fuchsbauer-Kiltz-Loss (2018) and is not automatic from "we use PLONK." The construction's claim of ZK against an adaptive AS requires citing this result explicitly and verifying that the circuit's public input structure does not introduce distinguishing information beyond what HVZK tolerates. Without the simulator construction for the malicious-verifier case written down, this is hand-waving.

- **In-threat-model?** **No** (construction must address). The security reduction must specify: (a) which ZK flavor is achieved, (b) cite the concrete result for PLONK in the relevant model (AGM+ROM), (c) show the simulator works even when the adversary adaptively chooses public inputs. The IND-UNL-AS game definition should include a "ZK oracle" query that the simulator must answer — and the reduction must use it.

---

### Attack 3: `credCommit` as a Cross-Scope Public Correlator

- **Attack:** The PLONK circuit proves knowledge of a witness `(credSecret, credCommit, ...)` such that `credCommit` is consistent with a public on-chain enrollment root. For this Merkle membership proof to be publicly verifiable, the circuit must expose *some* public output tying the proof to a specific enrolled identity — otherwise any agent could present any valid proof for any scope. The minimal public output is the `humanMerkleRoot` (enrollment tree root) plus the scope-specific nullifier. But if the prover also outputs a `credentialEpochHash` or any deterministic function of the underlying credential (common in constructions that want cross-epoch freshness), that output is the same across all RS interactions by the same agent and serves as a direct correlation handle. Even without an explicit correlator: if the Merkle path depth or the sibling positions in the sparse Merkle tree are observable (e.g., as auxiliary proof metadata or through verification cost timing), a statistical adversary correlates proofs sharing the same Merkle path prefix.

- **Why it works / why it fails:** This is a *public-input linkage* attack orthogonal to the PRF security of the nullifier. The construction addresses nullifier separation but does not specify *all* public outputs of the circuit. Any deterministic, agent-specific value in the proof transcript (proof size is fixed in PLONK, but KZG commitments to witness polynomials leak structure if the same witness is reused across proofs) is a correlation handle. The reduction to Poseidon PRF covers the nullifier; it says nothing about other public outputs.

- **In-threat-model?** **No** (construction must address). The IND-UNL-AS game needs a *complete* public transcript model: enumerate every bit the adversary sees per interaction, prove each is either (a) perfectly simulatable independently per session, or (b) explicitly shown to carry no cross-session mutual information. A full transcript audit of the circuit's public output vector is required before the claim holds.

---

### Attack 4: `epochSalt` as a Cross-RS Correlation Handle + Intra-Epoch Traffic Analysis

- **Attack:** Epoch batching releases proofs at synchronized epoch boundaries, using a shared `epochSalt` to prevent inter-epoch timing linkage. But `epochSalt` is a *public* value (it must be, for any RS to verify `nonceBinding = Poseidon(sessionNonce, epochSalt)`). If `epochSalt` is the same across all RS instances in an epoch (by design — that's how batching works), then every proof submitted in epoch *e* carries the same `epochSalt`. A colluding AS+RS pair with synchronized clocks observes: (1) agent A submits to RS1 with `epochSalt = e`, (2) simultaneously, a proof with `epochSalt = e` arrives at RS2. Even without linking the nullifiers, the *temporal co-occurrence within an epoch* is a side channel. For low-traffic RS instances (e.g., a single CU serving 500 members), the anonymity set per epoch is small and the adversary's distinguishing advantage is non-negligible.

- **Why it works / why it fails:** The construction reduces timing linkage to "within-epoch granularity" but does not bound the anonymity set size. If the anonymity set in a given epoch has only *k* members (e.g., *k* = 10 agents accessing a specialty provider in the Kaiser Permanente scenario), the adversary's advantage is 1/*k* — not negligible for small *k*. The `epochSalt` also creates a new attack surface: if an adversary can manipulate epoch boundary timing (e.g., by inducing latency at one RS), it can force a proof to appear in a different epoch than intended, reducing anonymity set size or creating epoch-mismatch fingerprints.

- **In-threat-model?** **Partially** — the construction acknowledges timing side channels and proposes epoch batching, but the IND-UNL-AS game does not formalize the adversary's power over epoch parameters or the anonymity set lower bound. A concrete security statement requires either (a) a minimum anonymity set assumption baked into the game (e.g., "at least *k* agents per epoch per RS"), or (b) a dummy-traffic protocol that pads each epoch to a fixed rate — with the associated bandwidth cost analyzed. Neither appears in the stated gap-to-close items.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Inversion — NCUA Part 748.0(a)(2) and GLBA Safeguards §314.4(f)

- **Attack:** The construction's key architectural claim is that "the AS is removed from the per-RS authorization hot path entirely." From my exam desk, that sentence just deleted my centralized audit log. NCUA Part 748 Appendix A requires a security program with audit trails sufficient to detect and reconstruct unauthorized access. GLBA §314.4(f) mandates monitoring of activity on all systems that access member information. If the AS never sees the per-RS authorization event, *who writes the authoritative access log*? The RS? The agent itself? An agent-generated log is self-attested and worthless to an examiner. When my NCUA examiner asks "show me every system that touched member John Doe's account data in Q3," I cannot hand them a Poseidon PRF reduction. I need a signed, tamper-evident, centrally-anchored log entry. The construction conflates *cryptographic unlinkability* with *operational auditability* — they are in direct tension here.
- **Why it works / fails:** The construction has no answer because it explicitly removes the AS from the hot path as a *feature*. Section 1 of the construction (`ScopedAgentPresentation` circuit) achieves unlinkability precisely by eliminating the AS observation point. There is no described compensating control — no RS-side audit relay, no out-of-band audit beacon, no zk-audit-log primitive.
- **In-threat-model?** No — the construction must address this. Proposed path: a separate `AuditCommitment` output in the PLONK proof that the RS can write to a regulator-accessible log without breaking cross-RS unlinkability (selective disclosure, not full deanonymization). This is not described anywhere in the construction.

---

### Attack 2: Key Custody Silence — FFIEC CAT Baseline Domain 3 (Cybersecurity Controls) + Vendor Management Policy

- **Attack:** The nullifier is `Poseidon2(rsScopeId, credCommit)`. `credCommit` is a commitment to the agent credential, which in turn commits to the operator private key or a derived secret. My attack prompt is literal: *where does that secret live?* The construction lists "agents self-generate PLONK proofs locally" but never specifies the key custody model. If the generating process runs in a browser JS context, the `credCommit` preimage is exposed to the browser heap, XSS, extension compromise, and memory scraping. FFIEC CAT Baseline Domain 3, Control 3.1.1 requires documented key management procedures including generation, storage, distribution, and destruction. My vendor management policy requires any third-party handling member credentials to demonstrate HSM-backed key storage or equivalent. The construction's security reduction ("breaking the Poseidon PRF assumption") is perfectly valid in the ROM — and completely irrelevant if the input secret leaks via a side channel before it reaches the PRF.
- **Why it works / fails:** The formal IND-UNL-AS game assumes the adversary cannot observe the agent's local state. That assumption collapses in a browser or unmanaged endpoint. The construction describes the *cryptographic* layer in detail but is silent on the *operational* key lifecycle. "Locally" is not a custody model.
- **In-threat-model?** No — the construction must address this. The Navy Federal CU scenario in particular involves member agents, which means member-controlled devices. A construction that requires HSM custody to be secure is not deployable in that scenario without significant additional infrastructure.

---

### Attack 3: Epoch Batching vs. Core Processor SLA — FFIEC BCP + NCUA Examiner Questionnaire Q4.3

- **Attack:** The construction mitigates timing side channels via "epoch batching — timing side-channel mitigation via `epochSalt` + batched release." My core processor (FiServ DNA or Jack Henry Symitar) authorizes transactions in under 200ms. My NCUA examiner's third-party questionnaire (Q4.3) asks me to document the RTO/RPO for every authentication dependency in the transaction path. What is the epoch duration? 1 second? 10 seconds? If an agent authorization is held until epoch boundary before release, I have introduced latency that either (a) breaks my core SLA or (b) forces the epoch to be so short it provides negligible timing privacy. This is not a theoretical concern — the construction explicitly lists this as the timing side-channel mitigation. The tradeoff is not quantified. Additionally, if the epoch salt source (on-chain or off-chain?) is unavailable, does the authorization path fail closed or open? Neither is described.
- **Why it works / fails:** The construction acknowledges the timing side channel exists (good) and proposes epoch batching (reasonable in theory) but provides no latency bound, no epoch duration parameter, and no failure mode analysis. From my FFIEC BCP standpoint, an unquantified latency dependency in the auth path is an unacceptable risk.
- **In-threat-model?** Partially — the construction acknowledges the timing channel but the mitigation is underspecified. This needs: (1) concrete epoch duration with latency impact analysis, (2) failure mode behavior, (3) SLA table comparable to OAuth/OIDC baseline.

---

### Attack 4: Breach Scope Assessment Collapse — GLBA Breach Notification + State Privacy Laws (NYDFS 500.16, CCPA)

- **Attack:** This is my most dangerous attack. The privacy guarantee the construction provides to members — cross-RS unlinkability even under colluding AS+RS — is *identical* to the property that makes post-breach forensics impossible. Under GLBA §314.4(h) and NYDFS 500.16, when I have a breach I must determine: which member data was accessed, the scope of exposure, and notify affected members within required windows. If an agent accessed five RS instances (payment processor, insurance portal, mortgage servicer, investment account, medical FSA) and the AS+RS cannot reconstruct the cross-RS graph by design, then after a breach involving one of those RS instances, I cannot determine whether the same agent credential was used to access the other four. I cannot scope my breach notification. My board narrative becomes "we don't know how many members were affected because we built a system that prevents us from knowing." The healthcare scenario (Kaiser Permanente) makes this acute — HIPAA breach notification has a 60-day clock and requires precise affected-population enumeration.
- **Why it works / fails:** The IND-UNL-AS-RS colluding variant specifically protects against the colluding case. That means even if I *want* to reconstruct the access graph post-incident with RS cooperation, the cryptographic guarantees prevent it. This is not a gap the construction can patch with a configuration option — it is the core claim. A construction that achieves IND-UNL-AS-RS necessarily prevents breach scope reconstruction by the credential issuer.
- **In-threat-model?** No — this is a fundamental tension the construction does not address. The likely resolution is a **selective deanonymization** mechanism: a regulator-held decryption key or a threshold ceremony that can reconstruct the cross-RS graph only under a documented legal/compliance trigger, without routine AS visibility. This is architecturally non-trivial and absent from the current construction.


## Persona: rfc7662_advocate

### Attack 1: Signed JWT Introspection Already Removes the AS from the Hot Path

- **Attack:** The construction's architectural headline — "AS is removed from the per-RS authorization hot path entirely" — is also achieved by `draft-ietf-oauth-jwt-introspection-response`. The AS issues a signed, cacheable JWT introspection response. The RS validates it offline using the AS's public key with no per-request AS callout. Combined with short-lived tokens and RS-local caching, the AS is just as absent from the per-RS hot path as in the ZK construction. The construction's claim needs to be more precise or it is indistinguishable from a cached JWT.

- **Why it works / fails:** It *partially* works as a challenge. The construction needs to clarify what "off hot path" means operationally. The genuine differentiation is not latency or AS availability — it is *what the AS learns at issuance time*. In OAuth, even if the AS is offline at RS evaluation time, the AS **saw** the resource indicator (`RFC 8707`) at token-request time. An adversarial AS can log `(agent_id, aud=RS_scope_id, timestamp)` at issuance and reconstruct the traffic graph post-hoc. The ZK path breaks this because the agent generates the PLONK proof locally with no per-RS issuance call. The construction should make this the central claim, not "AS removed from hot path."

- **In-threat-model?** Partially. The construction survives if it tightens the claim to: *"AS learns nothing about which RS the agent contacts at any time, including at issuance."* The current framing ("removed from hot path") is underspecified and invites this confusion.

---

### Attack 2: credCommit Precomputation Nullifies the Nullifier

- **Attack:** The nullifier is defined as `Poseidon2(rsScopeId, credCommit)`. If the adversarial AS issued the credential, it knows `credCommit` — or can enumerate it, since it is a commitment over agent attributes the AS approved. `rsScopeId` is public (it identifies the RS). Therefore, an adversarial AS can precompute the nullifier for every `(credCommit, rsScopeId)` pair across all registered RSes. When the AS or a colluding RS observes nullifiers in presented proofs, it can invert the traffic graph directly — no PRF inversion required.

- **Why it works / fails:** This is a **real gap** unless `credCommit` contains a secret blinding factor that is generated client-side and never transmitted to the AS (i.e., the AS signs a commitment it cannot open). The construction must explicitly state whether the AS knows `credCommit` or only a binding over it that hides the blinding factor. If the AS issues `credCommit = Poseidon2(attrs, AS_secret)` and knows both inputs, the nullifier scheme provides zero unlinkability against the AS. The construction needs a section establishing that `credCommit` is a *hiding* commitment with a holder-side randomness that the AS never sees.

- **In-threat-model?** **Yes — this is unaddressed.** The IND-UNL-AS game sketch does not specify the credential issuance sub-protocol or the information the AS retains post-issuance. This is a gap the construction must close before claiming strength 10.

---

### Attack 3: Audience-Bound PPIDs + RFC 8707 Already Break RS-Level Cross-Correlation

- **Attack:** RFC 8707 Resource Indicators bind a token to a specific audience. OIDC Pairwise Pseudonymous Identifiers (PPIDs, Section 8.1 of OIDC Core) give each RS a different `sub` for the same user. The RS sees `(aud=self, sub=pairwise_id)` — it cannot correlate the agent across RSes. From the RS's perspective this is identical to the ZK construction's unlinkability guarantee. The construction must show a property the PPID+audience scheme cannot match.

- **Why it works / fails:** It *fails against the construction's adversary model* — but the construction does not say so loudly enough. The PPID mapping lives in the AS. An adversarial AS can trivially invert `(RS_id → pairwise_sub)` to recover the real agent identity and reconstruct the full cross-RS graph. The PPID scheme provides RS-to-RS unlinkability, not AS-to-RS unlinkability. The construction's adversary is explicitly the AS itself. **The construction survives this attack** but only if its threat model section explicitly names the AS as the adversary and explains why PPID gives no protection there. Without that framing, reviewers will dismiss the contribution as reinventing PPIDs.

- **In-threat-model?** Yes — construction survives, but must call this out explicitly in the differentiation section. Currently missing from the candidate description.

---

### Attack 4: Epoch Batching Fails Under Small Cohort Size

- **Attack:** The construction mitigates timing side channels via `epochSalt + batched release`. But the AS controls enrollment and therefore knows the set of agents enrolled in each epoch. If epoch `E` contains `k` agents and the AS observes `m` nullifier presentations to RS `R` during epoch `E`, basic intersection: the AS knows the presentation came from one of the `k` enrolled agents. For small `k` (a single credit union branch, a small healthcare practice), this is a deanonymization attack — the AS narrows the agent identity to a tiny anonymity set, without breaking Poseidon. The construction claims empirical testing but does not specify minimum cohort size or degradation curve for the timing guarantee.

- **Why it works / fails:** This is a **partial gap**. The epoch batching does eliminate precise timestamps, reducing the adversary to set membership, not timing. But the construction's Navy Federal CU and Kaiser Permanente scenarios may have small per-epoch cohorts. The IND-UNL-AS-RS colluding variant must account for this: if the AS knows epoch membership and the RS knows which epochs received nullifiers, the colluding pair can intersect. The construction needs either: (a) a minimum anonymity set size `k_min` and a refusal to present proofs below threshold, or (b) dummy/cover traffic to pad epochs, or (c) a formal proof that epoch-set membership leakage is within the IND-UNL-AS game's allowed leakage budget.

- **In-threat-model?** **Yes — partially unaddressed.** The construction acknowledges timing side channels but the batching mitigation as described is insufficient against a colluding AS+RS with enrollment knowledge. The IND-UNL-AS-RS variant must be extended to model epoch membership leakage explicitly.


## Persona: spiffe_engineer

---

### Attack 1: The "AS Removed from Hot Path" Claim Is Not Novel — SPIRE Already Does This

- **Attack:** The construction's headline insight — *"the AS is removed from the per-RS authorization hot path entirely"* — is presented as differentiating. It is not. SPIRE agents deliver X.509-SVIDs and JWT-SVIDs to workloads via the local Workload API socket without any network call to the SPIRE server on the critical path. The SPIRE agent handles rotation and caching locally; the SPIRE server is only contacted on rotation or initial node attestation. An agent presenting a JWT-SVID to an RS today achieves "no AS involvement per request" already. The construction has not cleared the novelty bar it claims.

- **Why it works / fails:** The construction *does* add something SPIFFE doesn't — the scope-specific nullifier prevents cross-RS correlation even between colluding RS instances, which JWT-SVID `sub` claims cannot. But this is a much narrower claim than "AS removed from hot path." The construction needs to restate its differentiator precisely: not *hotpath removal* but *credential-holder unlinkability under colluding verifiers*, which is a strictly stronger property than what SPIFFE provides.

- **In-threat-model?** No — the construction overclaims the baseline gap. It must either (a) reframe its differentiator to the colluding-verifier unlinkability property specifically, or (b) show that SPIFFE's baseline allows cross-RS correlation and prove the construction closes that gap. The current framing conflates latency decoupling with cryptographic unlinkability.

---

### Attack 2: Stable Public Inputs Are a Correlation Oracle for Colluding RS Instances

- **Attack:** The `ScopedAgentPresentation` circuit produces PLONK proofs with public inputs that the RS must inspect to verify. At minimum, the RS needs to validate: (1) the operator's public key (so it knows who issued the credential), (2) the permission bits in scope, and (3) the credential expiry. These fields are *stable across all RS visits for the same credential issuance*. A set of colluding RS instances — no Poseidon PRF break required — can intersect on `(operatorPubKey, permissionMask, expiryEpoch)` to build a per-credential traffic graph. The nullifier `Poseidon2(rsScopeId, credCommit)` is scope-specific, yes — but `operatorPubKey` is not a PRF output. It is a cleartext field that the RS must see to verify the credential chain. The IND-UNL-AS-RS game in the construction needs to account for this or it is proving security against a weaker adversary than it claims.

- **Why it works / fails:** The construction's reduction to Poseidon PRF is only valid if *all* cross-RS correlation vectors reduce to inverting the PRF. Stable public inputs are a side channel that is entirely orthogonal to the PRF assumption. This attack succeeds unless the circuit hides operator identity behind a group membership proof (e.g., proving operator ∈ approved-operator-set without revealing which one) — which is not described in the construction.

- **In-threat-model?** No — the IND-UNL-AS-RS game as described does not explicitly bound what public inputs the RS sees. The construction must either (a) enumerate all public circuit outputs and prove none are stable across scopes, or (b) add a layer of operator anonymity (e.g., a Merkle membership proof over a registry of approved operators, revealing only the root). This is a real gap in the security argument, not a framing issue.

---

### Attack 3: WIMSE Token Exchange Already Covers This — Why a Parallel Protocol?

- **Attack:** `draft-ietf-wimse-arch` (WIMSE working group, IETF) explicitly scopes workload-to-workload authentication, token exchange, and is tracking selective disclosure as a future mechanism. RFC 8693 (Token Exchange) already handles cross-service credential narrowing. Contributing a ZK attestor plugin to SPIRE and a selective-disclosure token type to WIMSE would achieve the stated privacy goal while remaining interoperable with every enterprise that already runs SPIRE. Instead, the construction defines a new wire format, a new DID method, and a new handshake protocol — creating an adoption cliff that no Fortune 500 CISO will clear without an RFC track. The construction is solving a standards problem with a cryptography solution.

- **Why it works / fails:** This is an adoption/interoperability objection, not a cryptographic break. The construction *is* technically sound in isolation. The attack lands because the gap analysis never explains why the WIMSE selective-disclosure roadmap cannot absorb this work. If the answer is "WIMSE won't add ZK for 5+ years," that should be stated and defended. If the answer is "we need human-root enrollment which WIMSE doesn't model," that needs to be explicit.

- **In-threat-model?** No — the construction does not address the standards-layer alternative. It needs a section explaining why WIMSE extension is insufficient (not just slower), covering: (a) WIMSE's token exchange requires AS involvement per exchange by design, (b) WIMSE does not model a human enrollment root binding agent credentials to a unique human, (c) WIMSE's selective disclosure roadmap is advisory, not committed. Without this, the construction reads as NIH.

---

### Attack 4: Epoch Batching Creates a Temporal Correlation Window, Not Mitigation

- **Attack:** The epoch batching mechanism — releasing proofs only at epoch boundaries with a shared `epochSalt` — is described as a timing side-channel mitigation. It is actually a *temporal linkage enabler*. All proofs released in the same epoch share the same `epochSalt` as a public input (or it is derivable from the epoch boundary timestamp, which is public). A colluding AS + RS set that sees proofs from RS-A and RS-B within epoch *t* can assert: these two authorizations came from agents active in epoch *t*, narrowing the anonymity set from "all agents ever" to "all agents active in this epoch." In a sparse deployment (e.g., 12 agents with access to Kaiser's referral network in a given hour), this is a de-anonymization. The construction's healthcare scenario is precisely the high-risk, low-cardinality case where epoch batching provides the weakest protection.

- **Why it works / fails:** The construction does not bound the anonymity set size as a function of epoch length and deployment cardinality. For high-cardinality deployments (thousands of agents), epoch batching is reasonable. For the stated scenarios — one credit union's member agents, one healthcare network's referral agents — the anonymity set may be small enough that epoch correlation is a practical attack without any cryptographic break.

- **In-threat-model?** Partially — the construction acknowledges timing side channels but does not provide a formal bound on anonymity set size per epoch. It must add: (a) a minimum anonymity set threshold below which epoch batching is insufficient and dummy traffic or k-anonymity padding is required, (b) explicit guidance that the healthcare and CU scenarios require deployment-specific epoch calibration, and (c) acknowledgment that `epochSalt` as a shared public input is itself a partial correlation signal, not a neutral parameter.
