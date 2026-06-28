# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: Your Threat Model Assumes the AS is Adversarial — But the AS *Is* the Credit Union

- **Attack:** Section 7's CU deployment scenario says "CU-as-AS must not see member merchant graph." But the credit union *is* the AS. Under BSA/AML, OFAC, and SAR obligations, the CU has a **legal duty** to surveil exactly that graph. The IND-UNL-AS game formalizes protection against adversarial AS — but the AS isn't adversarial here, it's *compliant*. Privacy from your own compliance officer is a regulatory liability, not a feature. A procurement officer at any federally-chartered CU will hand this document to their BSA officer, who will kill the deal in 10 minutes.

- **Why it works / why it fails:** The construction proves unlinkability against AS collusion, which is technically sound. But the scenario is self-defeating: if the AS is the CU, unlinkability from AS is unlinkability from the CU's own AML monitoring. The construction does not distinguish between *privacy from AS as a surveillance actor* vs. *privacy from AS as a compliance actor*. These are not the same adversary.

- **In-threat-model?** No — construction must address. Section 7 needs a revised CU threat model that separates (a) the CU's internal compliance function from (b) cross-CU or merchant correlation. The `scopeBlindingSecret` may still be valuable for the cross-CU case, but the current framing conflates them and will fail procurement review.

---

### Attack 2: The Baseline You Beat Doesn't Exist in Production

- **Attack:** Section 3 defines Mode B as "BBS+ offline presentation + PPID + RFC 8707 + DPoP." But *no incumbent ships this.* Auth0, WorkOS, Stytch, and Cloudflare Access all issue short-lived, audience-restricted JWT tokens (`aud` claim per RS, TTL ≤ 15 min) with DPoP sender-binding. That's the real baseline. Corollary 4.7's summary table has two columns — Mode A and Mode B — but the column that matters to any buyer is "what WorkOS ships today," which is neither. The five structural impossibilities in Section 8 are devastating against BBS+ Mode B, which has zero market share, while leaving the actual incumbent's architecture (short-TTL aud-restricted tokens) unaddressed. The quasi-identifier attack (B3) and PPID mapping table (B1) don't apply to a system that never issues persistent pseudonyms at all — just ephemeral, audience-scoped tokens.

- **Why it works / why it fails:** The construction correctly identifies that BBS+ Mode B cannot achieve full AS-opaque unlinkability. But a WorkOS PM's response is: "We never claimed unlinkability — we claimed a 15-minute blast radius per token, per RS. If you want unlinkability, reduce TTL to 1 minute and rotate." The construction has no section benchmarking against this defense. Theorem 4.6 doesn't cover it.

- **In-threat-model?** No — construction must address. Add a Mode C: ephemeral aud-restricted tokens with aggressive TTL. Formally show why this fails the cross-scope unlinkability game. (Hint: the AS still observes the refresh cadence per RS, which leaks the traffic graph — this is actually winnable, but the construction doesn't make the argument.)

---

### Attack 3: `scopeBlindingSecret` is a New Key Management Primitive with No Enterprise Story

- **Attack:** The core primitive that closes the gap is a locally-generated `scopeBlindingSecret` that is never part of the issued credential. Section 4 and Section 8 both rely on this. But: who manages it? What happens when a cloud-hosted agent container restarts and the secret is lost? How does a CU's SOC 2 auditor verify that this secret isn't exfiltrated? What's the rotation policy? Auth0 Machines, WorkOS Bot Users, and Stytch M2M tokens are all centrally managed — key revocation is an API call. The `scopeBlindingSecret` has no centralized revocation path by design (that's what makes it AS-opaque), which means a compromised agent cannot be cleanly revoked without leaking the correlation the construction is trying to prevent.

- **Why it works / why it fails:** The construction's unlinkability guarantee is structurally sound, but it trades one problem (AS correlation) for another (unrevocable agent key). Enterprise buyers have made the opposite tradeoff deliberately: they accept that the IdP sees traffic patterns *because* it enables instant revocation. The construction offers no answer to "how do I kill a compromised agent in under 60 seconds?"

- **In-threat-model?** No — construction must address. Section 6 (or wherever operational properties are discussed) needs explicit treatment of: (a) `scopeBlindingSecret` lifecycle in ephemeral compute environments, (b) emergency revocation under unlinkability constraints (hint: this may require a nullifier-based revocation list, but that reintroduces AS visibility), (c) what a SOC 2 Type II audit looks like for this primitive.

---

### Attack 4: 15-Second Proof Time Fails the Synchronous MCP Tool-Call Budget

- **Attack:** The construction's unlinkability is per-handshake. In a real MCP deployment, an agent calls multiple tools across multiple RS instances per user turn — Auth0's MCP auth docs model 3–7 resource server hops in a single agentic chain. At ~15s per Groth16 proof (the benchmark in `circuits/scripts/`), the cross-scope scenario the construction is *designed for* — the exact scenario where unlinkability matters — produces 45–105 seconds of proof latency per user turn. The IND-UNL-AS game is won cryptographically and lost in the p99 latency histogram. WorkOS issues tokens in <100ms via a standard HTTP call. Cloudflare Access adds ~5ms at the edge. No enterprise operator will accept a 15-second blocking call in an agentic loop, regardless of the cryptographic guarantee.

- **Why it works / why it fails:** The construction does not address proof caching or pre-computation for the multi-RS case. If proofs are pre-computed per scope at agent initialization, the attack weakens — but pre-computation requires knowing the RS set upfront, which partially re-introduces the correlation the construction eliminates (the AS sees which scopes the agent pre-computed proofs for). This is a genuine tension the construction has not resolved.

- **In-threat-model?** No — construction must address. The gap-to-close section mentions "empirical test showing colluding AS+RS cannot de-anonymize" but says nothing about latency under multi-RS scenarios. A concrete proof-caching design that doesn't leak scope pre-selection to the AS is needed, or the practical deployment model is limited to single-RS use cases where unlinkability is irrelevant.


## Persona: cryptographer

The construction claims a `scopeBlindingSecret`-derived nullifier achieves `1/2 - negl(λ)` adversarial advantage in an IND-UNL-AS game against a colluding AS+RS. I find four structural problems the construction has not formally closed.

---

### Attack 1: Constant Public Input Across Scopes Trivially Links Presentations

**Attack:** In any Groth16 circuit, public inputs appear in the clear in the verification equation. The AgentPolicy circuit almost certainly includes a credential commitment `C = H(agentSecret ‖ modelHash ‖ permissions ‖ expiry)` as a **public** input — otherwise the RS cannot check revocation status or permission scope without knowing the credential's structure. This value is deterministic and constant across every scope presentation for a given credential issuance epoch.

A colluding AS+RS pair observes:
- `(nullifier₁, C, π₁)` at RS₁ with scope `s₁`
- `(nullifier₂, C, π₂)` at RS₂ with scope `s₂`

Since `nullifier_i = H(scopeBlindingSecret ‖ scope_i)` differ but `C` is identical, the adversary trivially links the two presentations by the constant public input. The `scopeBlindingSecret` nullifier separation is irrelevant — the credential commitment is the deanonymizer.

**Why it works / fails:** Works unless the construction either (a) makes `C` a private input and publishes only a per-scope commitment `C_i = H(C ‖ scope_i)`, or (b) uses a rerandomizable commitment scheme (e.g., Pedersen) so the verifier sees a fresh randomization each time while the circuit constrains the opening. Neither is described in the construction — the `scopeBlindingSecret` primitive does not address public-input leakage of the base credential.

**In-threat-model?** No — the construction must address this. Specifically, Section 4's Theorem 4.6 must include a proof that no deterministic public input persists across scope presentations. The current corollary table compares against BBS+ Mode B but says nothing about its own public-input surface.

---

### Attack 2: Groth16 Subverted Setup Breaks Unlinkability at the Root

**Attack:** The AgentPolicy and Delegation circuits use `pot16.ptau` for project-specific Groth16 keys (CLAUDE.md confirms this). If any contributor to the multi-party computation retains their τ contribution (toxic waste), they can:
1. Extract the full witness from any proof, including `scopeBlindingSecret`.
2. Compute `H(scopeBlindingSecret ‖ scope_i)` for every registered `scope_i` and build a complete agent-to-nullifier map retroactively.
3. Link all past and future presentations trivially.

More subtly, a malicious setup coordinator can embed a structured-reference string with a backdoor `[f(τ)]_1` term that encodes a trapdoor known only to them, producing proofs that appear valid to the standard verifier but leak witness information to the backdoor holder.

**Why it works / fails:** The construction's entire unlinkability claim rests on `scopeBlindingSecret` being extractable only via the knowledge-soundness extractor — but knowledge soundness assumes an *honestly generated* CRS. Under a subverted setup, the extractor in the soundness reduction is replaced by the backdoor, and the `1/2 - negl(λ)` bound collapses to `1 - negl(λ)` for the setup trapdoor holder. This is not a theoretical edge case: it is the standard criticism of single-organization Groth16 deployments.

**In-threat-model?** Depends on trust assumptions the construction has not stated. If the threat model includes the setup coordinator as a potential adversary, the claim fails. The construction should either (a) commit to a public multi-party ceremony with at minimum N≥2 independent contributors, or (b) switch AgentPolicy/Delegation to PLONK with a universal SRS (Bolyra already builds dual `.zkey` for both — but the unlinkability claim must be argued under the universal SRS, not Groth16). Section 4 contains no setup-trust assumption.

---

### Attack 3: AS-Issued Nonce Creates a Correlation Channel Outside the ZK Layer

**Attack:** The CLAUDE.md states every handshake commits to a fresh `sessionNonce` and describes the AS as an active participant (it issues credentials and is the adversary in IND-UNL-AS). If the AS is also the nonce oracle — i.e., the agent must *request* a nonce from the AS before generating a proof for RS_i — then:

1. Agent requests nonce `n₁` for RS₁, AS records: *entity E requested n₁ at time t₁*.
2. Agent requests nonce `n₂` for RS₂, AS records: *entity E requested n₂ at time t₂*.
3. Agent presents `(nullifier₁, π₁, n₁)` to RS₁ and `(nullifier₂, π₂, n₂)` to RS₂.
4. Colluding AS+RS correlates by nonce issuance: the AS *knows* it issued n₁ and n₂ to the same network endpoint / credential identity at nearly the same time.

The ZK layer is bypassed entirely — the correlation happens at the transport layer before the proof is generated.

**Why it works / fails:** Works whenever the AS functions as a nonce oracle and can correlate nonce-request metadata. Fails only if nonces are either (a) agent-generated and verifiably fresh (but then replay prevention requires AS-side nonce ledger lookup, which leaks access time), or (b) derived from a publicly verifiable randomness beacon the agent can reference without contacting the AS. The construction's Section 7 deployment scenarios say nothing about who generates session nonces or what metadata the AS retains at nonce issuance time.

**In-threat-model?** No — this is a classic "the protocol is secure but the handshake isn't." The IND-UNL-AS game must model the nonce oracle. If the AS controls nonce generation, the game must give the adversary the nonce-request transcript, and the unlinkability bound must hold even then. The current construction's gap list mentions "nonce freshness" but does not formalize whether the AS is the nonce oracle.

---

### Attack 4: scopeBlindingSecret Entropy and Nullifier Dictionary Precomputation

**Attack:** The nullifier for scope `s_i` is `nullifier_i = H(scopeBlindingSecret ‖ scope_i)`. The AS knows every registered `scope_i` (it registers RSes). If `scopeBlindingSecret` is derived from, or correlated with, anything the AS observes — credential issuance timestamp, agent model hash, operator key fingerprint — the AS can:

1. Build a candidate set `{SBS_candidate}` (e.g., if SBS is 128 bits sampled from a device with weak entropy, or derived as `H(operatorPrivKey ‖ salt)` where the salt has limited range).
2. For each candidate, precompute `H(SBS_candidate ‖ scope_i)` across all known scopes.
3. Match observed nullifiers to candidates in `O(|SBS_candidates| × |scopes|)` time.

Even absent entropy failure: upon observing nullifier `n₁ = H(SBS ‖ s₁)`, the AS gains partial information. If it then observes any side channel that bounds the entropy of SBS further (e.g., the agent's credential was issued with `expiry = T` and `SBS` is re-derived on each credential renewal using a deterministic KDF), subsequent presentations leak SBS via repeated nullifier observation + KDF inversion attempts.

**Why it works / fails:** Works whenever SBS entropy is bounded or its derivation procedure is partially observable. The construction's Section 4 Theorem 4.6 argument that "no credential-based system where the issuer signs all claims can replicate it" is true but doesn't establish a *lower bound on SBS entropy* or *a requirement on the SBS generation procedure*. Without a formal statement like "SBS ← {0,1}^λ sampled uniformly by the agent from a secure random source, never transmitted or stored outside the agent's secure enclave," the `negl(λ)` in `1/2 - negl(λ)` is not justified.

**In-threat-model?** Partially — the game definition can exclude weak-entropy adversaries, but the construction must then explicitly state the entropy assumption as a security parameter requirement and argue that practical deployments (mobile agents, embedded IoT agents, browser-based agents) meet it. The deployment scenarios in Section 7 (cross-CU, healthcare) involve agents running on potentially constrained hardware. This is not an edge case.


## Persona: cu_ciso

---

### Attack 1: The scopeBlindingSecret is Uncharted Key Custody

**Attack:** Section 4 introduces `scopeBlindingSecret` as "locally-generated, never part of the issued credential." My first question to every vendor is: *where does that secret live?* For an AI agent acting on behalf of a member, this secret must persist somewhere between sessions — device keychain, browser storage, HSM, or your cloud. You have not specified. Under **GLBA Safeguards Rule 16 CFR §314.4(c)(2)**, I must inventory all locations where member-relevant cryptographic material is stored and assess controls. Under **NCUA Part 748 Appendix A §III.B**, I need to ensure that member authentication factors are protected commensurate with sensitivity.

**Why it works against this construction:** Section 7 describes both deployment scenarios (CU cross-scope, healthcare delegation) but says nothing about `scopeBlindingSecret` lifecycle: derivation, storage, rotation, and destruction. If the secret is stored in a browser, an XSS compromises unlinkability for that member permanently — an adversary recomputes the same pseudonyms the member would have generated. If stored server-side by the agent operator, the agent operator becomes a correlated observer, defeating the entire claim. If stored in an HSM, I need HSM vendor audit artifacts. None of this is in the construction.

**In-threat-model?** No — the IND-UNL-AS game models a cryptographic adversary, not a key-custody failure. The construction must address secret storage, rotation policy, and loss/compromise recovery before a CU CISO can accept the unlinkability claim as operationally real.

---

### Attack 2: The Privacy Guarantee Is an Audit Trail Gap

**Attack:** I'll hand my NCUA examiner the following sentence from Section 8: *"the AS cannot reconstruct the member-merchant access graph."* The examiner will hand it back and cite **NCUA Part 748 §748.2(b)(3)** — my written information security program must include procedures to detect, respond to, and recover from security events, including unauthorized access to member data. **GLBA Safeguards 16 CFR §314.4(h)** requires continuous monitoring of all systems handling customer financial information. If the AS provably cannot see cross-RS access, it also provably cannot audit it.

**Why it works against this construction:** The construction frames unlinkability as a feature for the CU-as-AS scenario (Section 7, "CU must not see member merchant graph"). But that same guarantee means: if a compromised AI agent is systematically abusing member delegations across 40 merchant RS instances, my SOC cannot detect the pattern — because the pattern is cryptographically hidden from everyone including me. My **FFIEC CAT** maturity model (Innovative domain, Control Objective 3.1) requires behavioral analytics on third-party integrations. Bolyra's unlinkability makes that impossible by design.

**In-threat-model?** No — the IND-UNL-AS adversary is an *external* correlator. The construction does not address the *operator's own legitimate audit need* being in tension with the privacy guarantee. A CISO who cannot audit aggregate agent behavior across scopes cannot sign off on this deployment. The construction needs a "privacy-preserving audit" mechanism (e.g., threshold disclosure or regulator-held view key) or it will fail every NCUA examination that asks "how do you monitor third-party agent activity?"

---

### Attack 3: Timing Correlation Is Not a Cryptographic Problem

**Attack:** Section 8 acknowledges "side channels (timing, nonce freshness)" as a gap to close. I do not need to break your nullifier math. I just need to correlate HTTP timestamps. My AS receives a ZK proof submission at `T=14:23:07.442`. My colluding RS partner (same CUSO network) logs a resource access at `T=14:23:07.619`. The 177ms delta is well within a single TLS session. The IND-UNL-AS game in Theorem 4.6 assumes the adversary sees only the cryptographic output, not the network layer. Real deployments run over HTTPS with millisecond-precision server logs, which are required by **FFIEC CAT** and my SOC 2 Type II audit.

**Why it works against this construction:** The construction closes the cryptographic linkability gap (Corollary 4.7 shows `Adv = 1/2` in all functional BBS+ cases) but the formal game does not model a network-layer adversary. Two colluding RSes logging access times can reconstruct the member-merchant graph with high confidence using traffic analysis — no cryptographic break required. This is a known deanonymization technique (cf. Tor timing correlation). Section 8's five structural impossibilities for Mode B do not carry over to Bolyra because they address cryptographic linkage, not traffic analysis.

**In-threat-model?** Partially — the construction mentions this gap but does not close it. A CISO accepting this construction in production should require a concrete timing-noise specification (e.g., mandatory proof submission jitter ±500ms, decoupled submission proxy) before signing the vendor assessment. As written, the gap-to-close item in the candidate remains open.

---

### Attack 4: Third-Party Agent Operators Become Unauditable Quasi-Issuers

**Attack:** Section 7's healthcare delegation scenario has: *"agent delegation across providers without issuer learning referral network."* In my CU context, the AI agent is operated by a third-party vendor — call it ModelCo. ModelCo holds the agent's EdDSA signing key (per the `AgentPolicy` circuit). Under my **Vendor Management Policy** (required by NCUA supervisory letter 07-CU-13) and **FFIEC third-party guidance**, I must assess ModelCo's controls over the credentials it holds. Here is my problem: ModelCo's agent generates `scopeBlindingSecret`-derived pseudonyms that *even Bolyra cannot link*. ModelCo therefore has unilateral ability to correlate all member scopes (it holds both the credential key and the blinding secret), while my AS is cryptographically blinded.

**Why it works against this construction:** The construction's threat model places the AS as the adversary to blind. But in a real CU deployment, the AS is the CU (trusted), and the agent operator is the third party I actually cannot trust. The unlinkability guarantee runs in the wrong direction: it blinds the CU while leaving the agent operator with full correlation capability. A compromised ModelCo can reconstruct the member-merchant graph in full, sell it, or use it for competitive intelligence — and I have no cryptographic evidence because the construction provides no audit mechanism against a malicious agent operator who holds the `scopeBlindingSecret`. **GLBA Safeguards §314.4(f)** requires me to oversee service providers; I cannot oversee an entity that has asymmetric cryptographic advantage over me by protocol design.

**In-threat-model?** No — the IND-UNL-AS game blinds the *issuer/AS*, not the *agent operator*. The construction must either (a) define a separate adversary model for malicious agent operators, (b) require the `scopeBlindingSecret` to be member-held (not operator-held), or (c) provide a mechanism for the CU-as-AS to verify that the agent operator cannot reconstruct the cross-scope graph. Until that is addressed, no CU CISO can accept this as a privacy control under GLBA — the attack surface shifts, it does not close.


## Persona: rfc7662_advocate

---

### Attack 1: Credential Commitment as a Stable Cross-RS Identifier

- **Attack:** The IND-UNL-AS game in Theorem 4.6 shows the adversarial AS cannot link proofs *via* nullifiers, because `nullifierHash = H(nullifierSecret, scopeBlindingSecret, scope)` is scope-specific. But a ZK proof must convince the RS that the underlying credential was AS-issued and non-revoked. That requires the proof to commit to *something* the AS can later verify — a credential hash, a Merkle root, or an accumulator witness. If that commitment is a public input, it is *identical* across every proof the same agent ever generates, regardless of scope blinding. The scopeBlindingSecret only blinds the nullifier; it cannot blind the credential commitment without destroying verifiability. Concretely: adversarial AS logs the credential commitment `C` from any one proof, then asks each RS for the `C` values appearing in their proof logs. Correlation is trivial.

- **Why it works / why it fails:** The construction's Section 4 never specifies what appears in the public inputs of the scope-blinded circuit. If `C` or any deterministic function of the AS-issued credential is a public input, the construction is broken as written. The defense would require proving credential validity via a *second* ZK layer (e.g., prove "I know a preimage of a commitment that is a leaf of the AS's accumulator" without revealing which leaf) — a recursive or split-proof design not described anywhere in the current construction. This is a design gap, not a soundness gap of the abstract claim.

- **In-threat-model?** No — the construction must address this. Section 4 needs to specify the full public input vector of the scope-blinded proof and demonstrate that no stable per-credential identifier appears in it. Without this, Theorem 4.6 is vacuously correct (the *nullifier* is unlinkable) while the *credential commitment* re-links everything.

---

### Attack 2: Operational Unlinkability via AS-Side No-Log Policy Already Meets the Bar for Non-Adversarial Deployments

- **Attack:** The construction frames its advantage as defeating an *adversarial AS*. Section 8 lists five structural impossibilities all predicated on the AS being a willing correlator. But the claimed deployment scenarios — a credit union AS, a healthcare provider AS — are regulated entities operating under GLBA, HIPAA, and state privacy law. Those AS operators are *legally prohibited* from building member merchant graphs. RFC 7662 with a no-log introspection policy, per-RS scoped tokens (RFC 8707 `resource` parameter), and pairwise PPIDs is sufficient for the actual threat model these operators face. The adversarial AS is a strawman for regulated deployments. The construction provides cryptographic unlinkability where operational unlinkability + legal obligation already suffices; the marginal benefit is zero for the named scenarios.

- **Why it works / why it fails:** This doesn't break the construction's mathematics — it challenges the *deployment rationale*. The construction needs a threat model section that distinguishes: (a) regulated AS where legal compliance is the control; (b) unregulated / offshore AS where cryptographic enforcement is the only recourse; (c) compromised/subpoenaed AS where even a no-log policy fails. Only case (c) is where Bolyra's cryptographic unlinkability is strictly necessary. The current Section 7 deployment scenarios both fall squarely in case (a), which RFC 7662 + policy can handle.

- **In-threat-model?** No — the construction must sharpen its threat model. Asserting "adversarial AS" without specifying *why* the AS is adversarial (compromised, subpoenaed, insider threat, regulatory arbitrage) leaves the comparative advantage claim under-supported against a sophisticated RFC 7662 advocate.

---

### Attack 3: Nonce Freshness as a Timing Side-Channel Against an AS-Colluding-with-RS Adversary

- **Attack:** The construction explicitly lists "treatment of side channels (timing, nonce freshness)" as an unresolved gap. Here is a concrete instantiation: the `sessionNonce` in each handshake must be fresh and must be verifiably fresh (to prevent replay). If freshness is enforced by an AS-issued nonce (common in DPoP via RFC 9449 `nonce` header) or by RS-issued challenges that the AS can later see, then the *timing* of nonce issuance at AS or RS is observable even when the proof content is perfectly unlinkable. An adversarial AS that receives nonce requests at times T₁, T₂, T₃ and an RS that receives proof submissions at times T₁+δ, T₂+δ, T₃+δ can correlate traffic graphs with high confidence under even modest traffic volumes. This is the OAuth equivalent of a traffic-analysis attack against Tor: the ZK layer hides content but not timing.

- **Why it works / why it fails:** The construction's IND-UNL-AS game is purely information-theoretic over the *proof content*. It explicitly does not model timing. For the game to be meaningful in practice, either: (1) the nonce must be locally generated by the agent with no AS involvement (but then how does the RS verify freshness without a nonce oracle?), or (2) the proof submission must be batched or delayed to break timing correlation. Neither mechanism is specified. RFC 9449 DPoP at least has an explicit nonce architecture (§8) — Bolyra has a gap marker.

- **In-threat-model?** Yes and no — timing attacks are generally acknowledged as out-of-scope for cryptographic unlinkability proofs, but the construction explicitly lists this as a gap to close (the candidate's `gap_to_close` field includes "empirical test showing colluding AS+RS cannot de-anonymize"). If empirical de-anonymization via timing survives the construction, the `current_strength: 9` score is inflated.

---

### Attack 4: RFC 8693 Token Exchange Provides AS-Mediated Delegation Without the BBS+ Structural Impossibility — Delegation Gap Is Overstated

- **Attack:** Section 8 claims "delegation requires AS involvement" as a structural impossibility for BBS+ Mode B. The construction then concludes Bolyra wins on delegation. But this is not a Bolyra-vs-BBS+ comparison — it is a Bolyra-vs-RFC 8693 comparison, and the construction never runs that race. RFC 8693 Token Exchange allows: (1) the delegating principal presents their credential to the AS; (2) the AS issues a narrowed token to the delegate actor; (3) the RS sees the `act` claim with the delegate's identity; (4) scope narrowing is enforced by the AS exchange policy. The AS *does* learn the delegation relationship — but the construction claims unlinkability against the AS only for *cross-RS correlation*, not for the delegation relationship itself. A delegated agent using RFC 8693 with per-RS tokens (RFC 8707) and pairwise PPIDs for each RS produces RS-level unlinkability for all RSes that never see the original principal. The construction's Section 7 healthcare scenario fails to show why RFC 8693 + per-RS scoped issuance + PPID does not already prevent the "referral network" from being visible at individual RSes.

- **Why it works / why it fails:** The construction's Section 8 item (4) correctly identifies that BBS+ requires AS involvement for credential refresh and delegation. But "AS involvement in delegation" is different from "AS can build a delegation graph." RFC 8693 exchange with opaque subject identifiers and short-lived tokens can produce delegation that the AS processes but does not log in a way that leaks the referral graph. The construction needs to demonstrate a concrete case where RFC 8693 + privacy-preserving issuance policy fails but Bolyra succeeds — not merely assert that AS involvement is structurally problematic.

- **In-threat-model?** No — the construction must run the Bolyra-vs-RFC 8693 comparison explicitly. Defeating BBS+ Mode B (Section 8 rewrite) is necessary but not sufficient; RFC 8693 is a distinct baseline with a different trust topology that the current construction does not engage.


## Persona: spiffe_engineer

> Workload identity is a solved problem at the right layer. The `scopeBlindingSecret` is a clever trick at the credential layer, but you are running this construction on top of infrastructure that maintains identity at four other layers you haven't touched. Let me show you each one.

---

### Attack 1: Credential Issuance Correlation — The AS Has a Pre-Image Map

**Attack:**
In any real deployment, `AgentCredential` issuance is not a private event. The operator's signing key is derived from or attested by a workload identity root (SPIFFE node attestation, AWS instance identity, k8s service account JWKS, etc.). The AS sees the binding: `(workload W, time T) → credential C, modelHash H, permissionMask P, expiry E)`. The IND-UNL-AS game in Section 4 models the adversarial AS during *presentation* — but the AS already holds a complete issuance log before the game begins. Any presentation arriving within C's validity window, for a modelHash matching H, is trivially attributed to W by set intersection: `Challenger = { workloads with live credentials matching observed public signals }`. As `|Challenger|` collapses toward 1 (single-model deployments, enterprise environments), `Adv → 1`.

**Why it works / why it fails:**
The construction's `scopeBlindingSecret` is never signed by the AS, which closes the BBS+ PPID gap. But the game's `Adv = 1/2 - negl(λ)` bound implicitly assumes the AS cannot narrow the anonymity set from issuance-side data. Section 4 (Theorem 4.6) and Section 8 enumerate structural gaps in BBS+ Mode B but do not model AS-side issuance observability as a separate adversarial capability. The `scopeBlindingSecret` provides unlinkability *across presentations of the same credential*, not unlinkability *of the credential issuance event itself*.

**In-threat-model?** **No** — the IND-UNL-AS game must be extended with an `Issue(W)` oracle that the adversary queries before the challenge phase, and the proof must show that issuance-log observations don't collapse the anonymity set. If the deployment has `n` workloads issuing credentials with distinct `(modelHash, permissionMask)` tuples, the actual anonymity set shrinks dramatically below what the cryptographic bound suggests.

---

### Attack 2: Transport-Layer SPIFFE SVID Bypass — TLS Carries What ZK Hides

**Attack:**
The ZK unlinkability claim lives at the proof/token layer. But workloads in production communicate via service mesh (Envoy + SPIRE, Istio with mTLS) where the transport carries an X.509 SVID in the TLS handshake: `spiffe://cu-a.bolyra/agents/model-xyz/instance-42`. The RS sees this SVID *before* it ever evaluates the ZK proof. Section 8 claims that "AS+RS collusion cannot de-anonymize," but this addresses collusion at the *application* layer. At the *transport* layer, the RS has already received a globally unique SPIFFE ID from the TLS certificate. The ZK proof proves authorization scope; the TLS cert proves workload identity. These two channels are independent. Correlating them requires no cryptographic attack — it is a log join: `RS_tls_log.spiffe_id JOIN RS_app_log.zk_nullifier ON timestamp`.

**Why it works / why it fails:**
The construction explicitly targets the application-layer unlinkability property and doesn't claim transport-layer privacy. But the deployment scenarios in Section 7 (cross-CU member agent, healthcare delegation) implicitly assume that transport and application unlinkability compose. They don't, unless the transport is also anonymized (Tor, mix network, or unauthenticated outer TLS). WIMSE draft-ietf-wimse-arch Section 4.3 separates "workload authentication" from "request authorization" precisely because conflating them creates this gap. The construction does not address how an agent that holds a SPIFFE SVID for infrastructure auth can simultaneously be ZK-unlinkable at the application layer.

**In-threat-model?** **No** — the threat model in Sections 3–4 must scope transport identity vs. application proof identity. If the agent presents an mTLS SPIFFE SVID to the RS service mesh and separately presents a ZK proof to the RS application layer, the RS can always correlate. Mitigation requires either (a) proving that the deployment runs without transport-layer identity (unacceptable for enterprise), or (b) introducing a proxy/relay that breaks the SVID-to-proof binding — at which point the SPIFFE engineer would argue you've rebuilt Tor, not improved on SPIFFE.

---

### Attack 3: Credential Rotation Timing Side Channel — `scopeBlindingSecret` Lifecycle Creates Correlation Windows

**Attack:**
The construction closes BBS+ gap (B4) ("credential refresh timing") but does not close the equivalent gap in its own construction. `AgentCredential` has an `expiry` field (see `createAgentCredential` API). When the credential expires, a new one is issued and the agent begins generating new nullifiers. If `scopeBlindingSecret` is *per-credential* (regenerated at refresh for forward secrecy), then nullifiers are fully independent across credential epochs — but account continuity breaks: the RS cannot verify that agent-in-epoch-1 is the same as agent-in-epoch-2 without AS involvement. If `scopeBlindingSecret` is *persistent across credentials*, then `nullifier = H(scopeBlindingSecret, scope, credentialHash)` — the credentialHash changes at rotation but the unlinkability property now depends on the RS never seeing two nullifiers from the same persistent secret, which is exactly what is being claimed. **But the transition event itself is visible**: the AS sees "credential C1 for workload W expired; credential C2 issued." Any RS that received presentations in epoch C1 and then receives a new presentation in epoch C2 — from the same scope — sees a timing correlation: the presentation gap aligns precisely with the AS-observable issuance event. For short-lived credentials (SPIFFE default: 1 hour), this creates a 1-hour correlation window that repeats.

**Why it works / why it fails:**
Section 8, gap (B4) says Mode B has a credential refresh timing problem because "AS issues the new credential." Bolyra's construction has the *same* gap: the AS issues the new credential. The `scopeBlindingSecret` not being signed by the AS doesn't prevent the AS from observing the epoch boundary. For the IND-UNL-AS game to hold across credential epochs, the proof must additionally show that epoch-boundary events don't reveal inter-epoch linkage. This is not addressed in Theorem 4.6 or Corollary 4.7.

**In-threat-model?** **No** — the formal definition needs a multi-epoch variant of the IND-UNL-AS game where the adversary can observe `Issue(W, epoch_i)` and `Issue(W, epoch_{i+1})` events and then see challenge presentations. The `scopeBlindingSecret` lifecycle (per-epoch vs. persistent) must be explicitly specified, with the tradeoff between forward secrecy and epoch-boundary correlation formally modeled.

---

### Attack 4: SPIFFE Bundle Federation Reveals RS Access Topology

**Attack:**
The cross-CU scenario in Section 7 has different RS instances at different credit unions. In a SPIFFE/SPIRE federation deployment (which is the *standard* way enterprises share identity across trust domains), each trust domain publishes a JWT bundle and X.509 bundle. To accept a Bolyra credential from an agent rooted in `spiffe://cu-a.bolyra`, the RS at CU-B must fetch the trust bundle for `cu-a.bolyra`. The SPIRE federation endpoint is observable: `CU-A's SPIRE server` sees which remote trust domains have fetched its bundle. This gives CU-A (acting as AS) a map of which other trust domains are accepting credentials rooted in its attestation chain — which is precisely the RS access topology the construction claims to hide. Even without per-request correlation, the bundle refresh schedule reveals "CU-B's RS has accepted credentials from CU-A's attestation root since timestamp T" — a coarse-grained but structurally sound inference about cross-CU agent activity.

**Why it works / why it fails:**
This attack operates entirely outside the ZK layer. The IND-UNL-AS game in Section 4 models a single AS; the cross-CU scenario in Section 7 implicitly involves multiple trust domains with federation. The `scopeBlindingSecret` provides unlinkability within the ZK proof system, but SPIFFE bundle federation is a metadata channel that the construction does not model. The adversarial AS in the game needs to be extended to include a federated AS that can observe bundle refresh events from peer trust domains. The WIMSE architecture (draft-ietf-wimse-arch, Section 5.2) explicitly calls out inter-domain token propagation as a disclosure risk that implementations must address at the deployment level — Bolyra's Section 7 scenarios do not.

**In-threat-model?** **No** — the Section 7 deployment scenarios must address whether the trust root for agent credentials is federated across CU trust domains, and if so, whether bundle-level metadata creates a correlated RS-access topology. If the construction assumes a single monolithic trust domain (all CUs share one SPIFFE trust root), this must be stated explicitly and the operational implications (single point of compromise, centralized AS) addressed. If it assumes per-CU trust roots with federation, the bundle metadata channel must be modeled as an adversarial side channel and either eliminated (sealed bundle exchange) or bounded (coarse-grained disclosure acknowledged in the threat model).
