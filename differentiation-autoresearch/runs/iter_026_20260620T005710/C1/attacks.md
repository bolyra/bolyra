# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: "AS-blind is a threat model you manufactured"

- **Attack:** §3 and §7 reframe the AS as *adversarially controlled*, citing a CrowdStrike-style outage as proof the AS can't be trusted. But in every enterprise deal I've closed, the customer owns their AS. Auth0, WorkOS, Stytch — we are the AS. If your AS is compromised or lying about scopes, you have an IAM breach, not a cryptography problem. The fix is AS redundancy, token caching with a short TTL, and a SOC 2 audit — not a Groth16 circuit. The §7 "CrowdStrike outage" scenario is an *availability* failure, not a *trust* failure. AS-blindness solves neither.

- **Why it works / why it fails:** The construction's §3 explicitly says "the adversary controls the AS." That's a valid research threat model, but it's not the enterprise procurement threat model. No CISO at a credit union is signing off on "we assume our IdP is compromised." The construction survives if the target customer is a multi-party federation where the AS is operated by a third party (e.g., a correspondent bank, a network operator). It fails if the pitch is "replace Auth0 for your own AS."

- **In-threat-model?** **No** — unless §1 or a new §0 scopes the adversary model to *third-party-operated AS*, this reads as a cryptography paper solving a procurement buyer's non-problem. Must address.

---

### Attack 2: "Runtime-adaptive predicate evaluation is just ABAC — it's already solved"

- **Attack:** §3 and §8 claim "runtime-adaptive predicate evaluation" is jointly decisive because the RS decides at call time what predicate to check (e.g., FINANCIAL_SMALL based on loan amount). But this is precisely what Open Policy Agent, AWS Cedar, and SpiceDB do today. The RS receives a JWT with scopes, evaluates a policy at request time (`permit if token.scope contains FINANCIAL_SMALL and request.amount < 100`), and makes the decision. No AS roundtrip. No ZK circuit. The construction conflates *who evaluates the predicate* with *whether the predicate can be evaluated at all*. The "runtime-adaptive" property in §8 Axis 0 doesn't distinguish ZK evaluation from RS-local ABAC on a standard bearer token.

- **Why it works / why it fails:** The construction's actual differentiator is *proving the predicate is satisfied without revealing which other bits are set* — that's the ZK part. But §8 Axis 0 leads with "runtime-adaptive" as if that's the novel claim. The ABAC objection lands unless the construction clarifies that the predicate is evaluated *inside the circuit*, meaning the RS gets only a boolean (pass/fail) and zero bits about which permissions the agent holds — not even the evaluated scope. If the token carries any scope claims at all (even minimal ones), ABAC achieves the same runtime flexibility without the proof latency.

- **In-threat-model?** **Partial** — the construction survives if it tightens §3 to say the differentiator is *zero-knowledge predicate satisfaction* (RS learns nothing, not even the evaluated scope name). As written, "runtime-adaptive" reads as ABAC rebranded.

---

### Attack 3: "15-second proof latency is a product non-starter, not an engineering footnote"

- **Attack:** The construction's §1 claim and all supporting sections treat proof latency as out of scope. The attack prompts cite ~15s for circuit proving. WorkOS and Auth0 issue signed JWTs in under 100ms. In the credit union scenario (§7): a loan officer's agent calls the RS, the RS requests a proof, and the customer waits 15 seconds — for a predicate evaluation that OPA would resolve in 2ms. The construction has no latency budget analysis, no pre-computed proof strategy, and no response to "what does the UX look like while we wait for Groth16." The 2^64 permission space scenario (§1) is the only case where AS-side policy tables *might* not scale, and even there, the latency penalty likely outweighs the benefit.

- **Why it works / why it fails:** This is the most lethal GTM attack. The construction might survive it if: (a) proofs are pre-generated at credential issuance and cached by the agent, not generated per-request, or (b) the proving time drops to <500ms via rapidsnark on the agent's hardware. Neither is stated in the construction. §8 Axis 0 presents the joint property as decisive but never addresses whether the decisiveness survives a 15s wall-clock cost.

- **In-threat-model?** **No** — a construction claiming enterprise-grade differentiation over Auth0 must address latency explicitly. Silence here is a blocker, not an oversight.

---

### Attack 4: "BBS+ + token caching decomposes your joint property without ZK"

- **Attack:** §8 Axis 0 claims "every baseline mechanism achieving one property sacrifices the other" — citing BBS+ as "holder-driven but not predicate-evaluating." But consider: issue an 8-bit BBS+ credential at enrollment. The agent, at call time, selects which bit(s) to disclose to the RS (holder-driven, AS-blind after issuance). The RS receives only the disclosed bit and evaluates its own ABAC policy (`permit if disclosed_bit == FINANCIAL_SMALL`). The RS never contacts the AS. The agent never reveals the full bitmask. This composition — BBS+ selective disclosure + RS-local ABAC — achieves AS-blind presentation *and* runtime-adaptive predicate evaluation with sub-millisecond RS-side evaluation, no trusted setup, and no per-request proving. The construction's §8 dismissal of BBS+ is too thin: "not predicate-evaluating" is only true if predicate evaluation must happen inside the circuit. If it can happen at the RS on disclosed claims, BBS+ + ABAC is a credible counter-construction.

- **Why it works / why it fails:** The construction survives this only if the predicate must be evaluated *privately* — i.e., the RS cannot learn even which permission name was checked, only that "some permission in the set satisfies the predicate." That's a stronger claim than anything in §1 or §3. If the RS knowing "the agent disclosed FINANCIAL_SMALL" is acceptable, BBS+ wins on latency, simplicity, and ecosystem support.

- **In-threat-model?** **No** — §8 must close the BBS+ gap by specifying whether predicate evaluation must be *fully private to the RS* (circuit wins) or just *AS-blind* (BBS+ + ABAC is sufficient). Without that distinction, the "joint property no baseline can decompose" claim is falsified by a 10-line BBS+ composition.


## Persona: cryptographer

---

### Attack 1: Adversarial Merkle Root Substitution (§7 scenario breaks AS-blind claim)

- **Attack:** The AS-blind property is stated as "predicate evaluation moves from adversary-controlled to adversary-independent." But the circuit verifies membership against a Merkle root — *who publishes the canonical root?* In the construction, the AS enrolls agents and publishes the enrollment tree. A malicious AS can (a) publish a sparse tree with only one agent, trivially deanonymizing every proof against that root; or (b) maintain a shadow tree per RS, issuing per-RS roots so nullifiers uniquely identify the agent to each RS even without seeing the proof witness. The AS never touches the proof yet controls the anonymity set.

- **Why it fails against the construction:** The construction does not specify a root-authenticity mechanism. If the root is pinned on-chain (e.g., the `BolyraRegistry` contract) and updates are access-controlled and auditable, the attack requires on-chain collusion — a much stronger adversary. But §3 and §7 say nothing about root custody. The adversarial-AS model is invoked without bounding what the AS controls.

- **In-threat-model?** **No.** The formal game must specify: does the adversary control root publication? If yes, AS-blind is vacuous. The construction must either (i) require on-chain roots with append-only semantics, or (ii) restrict the adversarial-AS definition to exclude Merkle root manipulation. Right now the threat model is stated in prose, not as a game.

---

### Attack 2: Nullifier Scope Table Precomputation (§3 "adversary-independent" claim)

- **Attack:** The nullifier in a Semaphore-style scheme is `nullifier = H(identity_nullifier, scope_id)` where `identity_nullifier = H(secret)` is derived from the agent's secret. The AS does not know `secret` — but the AS assigns `scope_id`. If `scope_id` is a structured identifier with low entropy (e.g., a short RS identifier or a small integer bitmask position), the AS can build a lookup table: for every enrolled agent `i` with public commitment `C_i`, probe `H(·, scope_id)` exhaustively over the plausible nullifier space. More concretely: if the AS sees two proofs from the same agent to different RS endpoints and the scope_ids are predictable, the AS links them via `nullifier_A ≠ nullifier_B` but can correlate by ruling out all other commitments in the tree. This is a *traffic analysis* attack at the nullifier layer, not a break of the hash, but it collapses unlinkability when the anonymity set is small or scope_ids are guessable.

- **Why it fails / partially survives:** If `scope_id` is a fresh 128-bit random value chosen by the RS at proof time and never reused, the precomputation table is infeasible. But the construction does not specify scope_id entropy or freshness requirements. The CrowdStrike scenario (§7) has a fixed RS endpoint, implying a stable scope_id.

- **In-threat-model?** **Partially.** The construction survives if scope_id freshness is a specified protocol requirement. Currently it is not. The claim "AS cannot lie about scope membership" (gap statement) is unrelated to scope_id precomputation — the two attacks are orthogonal. The construction must add a scope_id freshness requirement and argue the nullifier scheme is domain-separated against a malicious scope_id-assigning AS.

---

### Attack 3: Groth16 Trusted Setup Under Adversarial-AS Threat Model

- **Attack:** The construction explicitly adopts an *adversarial-AS* threat model in §3 and §8 ("the adversary controls the AS"). Groth16 requires a per-circuit trusted setup — a toxic waste ceremony. The `AgentPolicy` and `Delegation` circuits use project-specific `.zkey` files generated from `pot16.ptau`. Knowledge soundness for Groth16 holds *if and only if* the SRS trapdoor is destroyed. If the AS is modeled as a computationally unbounded adversary (or the threat model does not exclude setup influence), the AS that retains the trapdoor can forge a proof of *any* NP statement — including proofs that a credential satisfies a predicate it does not satisfy. This collapses both soundness and the "AS-independent predicate evaluation" property simultaneously: the adversarial AS does not need to see the proof; it can produce one.

- **Why it works:** The adversarial-AS threat model as stated in §3 does not scope the adversary's role. A *subverted setup* adversary is strictly stronger than a *policy-lying* adversary, yet the construction is silent on setup trust. The claim that predicate evaluation is "adversary-independent" holds only against an adversary that did not participate in the trusted setup.

- **In-threat-model?** **No.** The construction must either (i) invoke a universal SRS (PLONK with a universal and updateable SRS, where one honest updater suffices), which is already available for `AgentPolicy`/`Delegation` per the CLAUDE.md table, and make PLONK the normative proving system for the adversarial-AS scenario, or (ii) explicitly restrict the adversarial-AS model to post-setup adversaries and justify this restriction. Defaulting to Groth16 in the adversarial-AS scenario and claiming adversary-independent evaluation is internally inconsistent.

---

### Attack 4: Adaptive Predicate Extraction via Repeated Querying (§8 Axis 0)

- **Attack:** §8 Axis 0 states that runtime-adaptive predicate evaluation is a jointly decisive differentiator because "RS decides it needs `FINANCIAL_SMALL` based on loan amount at call time." The RS sends the predicate to the agent, the agent generates a ZK proof. Now model the following game: an active adversary controls both the AS and the RS (the "colluding AS+RS" case, which the construction's §3 says it covers). The adversary issues a sequence of adaptive predicate queries `P_1, P_2, …, P_k` — each a different Boolean formula over the 8-bit permission bitmask — and observes accept/reject. With 8 bits, 8 linearly independent queries suffice to reconstruct the full bitmask in `GF(2)`. The agent's "selective disclosure" is thus completely negated against a colluding AS+RS that can retry with different predicates across sessions. This is a *chosen-predicate attack* and it is not addressed in §8.

- **Why it partially works:** The nullifier prevents the *same* proof from being replayed, but it does not prevent the adversary from requesting fresh proofs for fresh predicates. The construction must either (i) rate-limit predicate diversity per credential epoch, (ii) commit to the predicate at issuance time (collapsing runtime-adaptivity), or (iii) invoke a *zero-knowledge proof of predicate satisfaction* that is simulation-extractable and prove that the sequence of proofs reveals nothing about the complement of the satisfied predicate — which requires a formal simulation argument that is absent. The HVZK guarantee of Groth16 is not sufficient; the adversary here is an *adaptive* verifier across multiple protocol executions.

- **In-threat-model?** **No.** The "AS-blind" framing addresses the *single-round* case. The adversarial-AS+RS multi-round case is not modeled. The gap statement mentions "adversarial-AS model where AS cannot lie about scope membership" but says nothing about multi-round adaptive extraction. The construction must bound the information leakage across a sequence of proof verifications or explicitly restrict to a single-predicate-per-epoch protocol.


## Persona: cu_ciso

---

### Attack 1: AS-Blind Is a Compliance Liability, Not a Feature

- **Attack:** The construction's lead differentiator — §3's "AS-blind presentation" — means the CU's own authorization server has zero visibility into what scope an agent is claiming at the moment it accesses a resource. I am the CU. The AS runs on my infrastructure. You're telling me the primary security property is that *I* can't see what my agent is claiming. NCUA Part 748.0(b) requires me to document and monitor access to member information systems. My FFIEC CAT "Cyber Risk Management" domain requires detective controls on privileged access. If the AS is architecturally blind, I cannot produce an access log. When my examiner asks "show me the authorization log for the agent that executed this wire transfer," the answer is "we have a nullifier hash and a Groth16 proof blob." That is not an audit artifact. That is a finding.

- **Why it works against the construction:** §3 and §8 spend significant text explaining *why* AS-blindness is necessary (adversary-controlled AS model), but never address the case where the CU *is* the AS and *wants* visibility. The adversary model in §7 assumes a semi-trusted or hostile AS. In a credit union, the AS is operated by the CU or its core processor — it is the trusted party. Removing AS visibility from the trust model inverts the CU's own audit architecture.

- **In-threat-model?** No. The construction must address a "cooperative AS" deployment mode with a queryable, examiner-readable authorization log that does not require the AS to participate in proof verification. A nullifier registry with a CU-readable mapping layer would close this, but §3 and §8 do not propose one.

---

### Attack 2: Runtime-Adaptive Predicate Inverts Least-Privilege Issuance

- **Attack:** §7 and §8 define the runtime-adaptive property as: "RS decides it needs `FINANCIAL_SMALL` based on loan amount at call time, not at issuance." Under the GLBA Safeguards Rule (16 CFR §314.4(c)), I must implement access controls that restrict access to customer financial information to authorized personnel and systems — *based on what was authorized*. Under NCUA 748 Appendix A, least-privilege means the grant is made at authorization time and is auditable. If the RS is choosing the predicate at call time, then the access control policy is controlled by the resource consumer, not the authorizing institution. My examiner will ask: "Who authorized this scope?" The answer under this construction is "the RS chose the predicate at runtime against a pre-issued credential." That is not authorization. That is capability-based access with no issuance-time record of what was approved.

- **Why it works against the construction:** §8 "Axis 0" frames RFC 8693 as "runtime-adaptive but AS-dependent" and positions the ZK construction as superior because it's runtime-adaptive *without* AS dependency. But the AS dependency in RFC 8693 is exactly what produces the issuance-time authorization record my examiner needs. The construction trades auditability for flexibility and calls it a win. It is not a win in an NCUA examination.

- **In-threat-model?** No. The construction must define a concrete issuance record that ties a credential to a specific approved permission grant, with a timestamp and authorizing-party identity, independently of what predicate the RS selects at runtime. Without that, the runtime-adaptive property is a compliance gap dressed as a feature.

---

### Attack 3: Operator Private Key Custody Is Unaddressed Vendor Risk

- **Attack:** The `createAgentCredential` call signs with `operatorPrivKey` (EdDSA). That key is the root of trust for every agent credential your system issues. Where does it live? Who audits it? Under NCUA Part 748 Appendix B and my Vendor Management Policy, any third party that holds or generates a key material that authorizes access to member accounts is a critical service provider requiring due diligence, contract review, and incident response SLA. The construction never says where `operatorPrivKey` is stored, who rotates it, what happens when it's compromised, or how a compromised key is revoked across all issued credentials. The on-chain registry tracks nullifiers, not key revocation. If the operator key leaks, every credential issued under it is compromised and I have no revocation path that doesn't require on-chain transactions with uncertain latency.

- **Why it works against the construction:** §8's comparison axes focus entirely on what the RS sees and whether the AS is involved. No section addresses key lifecycle management, operator key revocation, or the vendor risk surface of wherever `operatorPrivKey` is generated and stored. The GLBA Safeguards Rule §314.4(f) requires me to oversee service providers that maintain safeguards for customer information — if the operator key is managed by Bolyra or a third-party HSM vendor, that's a new critical vendor relationship with no SLA defined.

- **In-threat-model?** No. The construction must specify operator key custody requirements (HSM class, FIPS 140-2 level), key rotation policy, and a revocation path that does not depend on blockchain liveness. Without this, the security property of the ZK construction rests on a key whose management model is undefined.

---

### Attack 4: On-Chain Registry SLA Fails NCUA Business Continuity Requirements

- **Attack:** §7 uses the CrowdStrike scenario (AS offline 14+ hours) to argue that AS-blind presentation keeps the system running when the AS is down. But the construction's own revocation and nullifier model depends on the on-chain registry. If Base Sepolia has a chain reorganization, an RPC provider outage, or a gas price spike that delays transaction inclusion, the CU's ability to check nullifier state is degraded. My core processor — Jack Henry, Fiserv, FIS — contractually guarantees 99.95%+ availability with regulatory backstop. The Base Sepolia network has no SLA, no contractual counterparty, and no NCUA-approved incident response procedure. FFIEC Business Continuity Planning booklet requires RTOs and RPOs for every system component supporting member transactions. The construction has no section defining what happens when the on-chain registry is unavailable: does the RS fail open (security incident) or fail closed (availability incident)?

- **Why it works against the construction:** §7 invokes the CrowdStrike outage as a reason AS-blindness helps availability, but the construction's liveness depends on a different single point of failure — blockchain RPC availability — that has worse contractual guarantees than the AS it replaces. The construction trades one liveness dependency for another with fewer operational controls and no regulatory precedent.

- **In-threat-model?** No. The construction must specify a fallback nullifier cache with a defined staleness bound, a contractual availability commitment from the RPC provider, and a documented fail-open/fail-closed policy with board-approved risk acceptance. Without these, I cannot include this system in my Business Impact Analysis and my examiner will flag it as an unmitigated third-party dependency.


## Persona: rfc7662_advocate

### Attack 1: Signed JWT Introspection Response Already Removes the AS from the Hot Path

- **Attack:** §3 claims "AS-blind presentation" as half the decisive joint property. But `draft-ietf-oauth-jwt-introspection-response` (now merged into RFC 9701) lets the AS issue a signed introspection JWT at token issuance time, bound to the RS audience via RFC 8707 `resource` indicators. The RS verifies it offline against the AS's published JWK set — no AS roundtrip, no AS availability dependency. The §7 CrowdStrike scenario (AS offline 14+ hours) is solved: the RS caches the signed introspection JWT and continues verifying during the outage. The ZK circuit is not needed for AS-blindness.

- **Why it fails against the construction:** The signed introspection JWT is *fixed at issuance time*. The RS's predicate is *not known at issuance*. If the RS decides at call time — based on the loan amount in the request body — that it needs to evaluate `FINANCIAL_SMALL` rather than `FINANCIAL_MEDIUM`, the introspection JWT cannot adapt. The JWT contains whatever scope the AS chose to serialize; the RS cannot re-evaluate a different predicate over the raw bitmask post-issuance. The construction's §3 argument holds: offline verification and runtime-adaptive predicate evaluation cannot both be achieved by signed introspection JWT because the predicate is baked into the response at AS-controlled issuance time, not chosen by the RS at verification time.

- **In-threat-model?** Yes — construction survives, but §3 should explicitly name RFC 9701 as the baseline that gets closest and explain why fixing the predicate at issuance is the decisive gap, not AS availability.

---

### Attack 2: RFC 8693 Token Exchange Achieves Runtime Predicate Selection Without ZK

- **Attack:** §8 Axis 0 claims RFC 8693 is "runtime-adaptive but AS-dependent," treating AS-dependency as fatal. But the advocate's position is: *of course* the AS is in the delegation loop — that's correct architecture, not a bug. At request time, the agent performs a token exchange (RFC 8693 `urn:ietf:params:oauth:token-type:access_token`) narrowing to only the permission predicate the RS demanded. The RS receives a downscoped token and never sees the broad credential. The predicate is chosen at runtime, after the RS signals what it needs. The ZK circuit adds no property RFC 8693 cannot express.

- **Why it fails against the construction:** RFC 8693 token exchange is synchronous and requires the AS to be live, reachable, and cooperative at the moment of the exchange. Three problems remain: (1) adversarial-AS model — if the AS is controlled by an adversary, it sees *every predicate evaluation* the agent makes across every RS, enabling behavioral fingerprinting regardless of PPID unlinkability at the RS layer; (2) the agent reveals to the AS which specific predicate it is presenting to which RS at which moment, breaking the AS-blind property even if the RS sees nothing; (3) the AS can selectively lie — returning a token that asserts a predicate the agent does not actually satisfy — and the RS has no cryptographic recourse independent of AS trust. The construction's §8 Axis 0 is correct on the decisive dimension.

- **In-threat-model?** Yes — construction survives. However: §8 should add an explicit note that the adversarial-AS behavioral fingerprinting attack (AS sees predicate + RS + timestamp on every exchange) is a *distinct* threat from "AS lies about membership," since the latter requires active malice while the former is passive surveillance by a semi-trusted AS.

---

### Attack 3: PPID + Per-RS Filtered Introspection Already Break Cross-RS Linkability at the RS Layer — the AS-Side Advantage Is Not Load-Bearing

- **Attack:** §3 and §8 frame "adversary controls the AS" as the threat model that makes the ZK construction necessary. But RFC 7662 with pairwise subject identifiers (OIDC PPID, RFC 8176 `pairwise`) gives each RS a different `sub` — cross-RS correlation requires the AS's cooperation *by design*. Per-RS filtered introspection means RS-A's response never contains permissions scoped to RS-B. The net result: RS-level linkability is already broken without ZK. The remaining gap ("AS can correlate") only matters under an explicitly adversarial-AS assumption that is not part of the standard OAuth deployment model. The construction is solving a threat model it has not proven is real.

- **Why it fails against the construction:** This is the strongest partial attack. PPIDs + filtered introspection *do* break RS-level linkability. The construction must concede this explicitly. Where it survives: PPID + per-RS filtering are AS-mediated privacy properties — the AS grants them and can revoke them unilaterally. In the scenarios the candidate lists in §1 (regulated agent, semi-trusted AS), the AS *is* the party whose honesty is in question. A semi-trusted AS can silently stop using PPIDs for a specific agent, or log which RS is querying which agent's permissions. The ZK construction moves the unlinkability guarantee from "AS policy" to "circuit soundness" — a fundamentally different trust anchor. The construction needs to make this explicit rather than treating the adversarial-AS model as a rhetorical aside.

- **In-threat-model?** Partially — the construction survives in the adversarial-AS model but the candidate (§1, §7) has not clearly justified *why that model applies* to the credit union scenario. This is a gap the construction must address, not the ZK claim itself.

---

### Attack 4: The Construction Conflates Two Separable Properties and Has Not Proven They Must Be Jointly Achieved

- **Attack:** §3 introduces "AS-blind + runtime-adaptive predicate evaluation" as the *jointly decisive* differentiator and §8 Axis 0 argues no baseline mechanism achieves both simultaneously. But the RFC 7662 advocate has a composition available that the construction has not engaged: **pre-issuance predicate negotiation via RFC 9728 Protected Resource Metadata (PRM)**. The RS publishes its required scope predicates in its PRM document (`/.well-known/oauth-protected-resource`). The AS reads PRM at token issuance time and issues a fine-grained token *already shaped* to each RS's declared predicate. No runtime exchange needed; no AS roundtrip at verification time (signed JWT introspection handles that). The predicate selection happened *before* issuance, driven by RS-published metadata. §3's framing of "RS decides at call time" assumes the RS cannot communicate its predicate requirements in advance — PRM directly addresses this.

- **Why it fails against the construction:** RFC 9728 PRM predicate negotiation is static: the RS publishes fixed predicate requirements in a well-known document. The construction's §7 credit union example is specifically a *dynamic* predicate: the RS evaluates `FINANCIAL_SMALL` vs. `FINANCIAL_MEDIUM` based on the *loan amount in the individual request*, not a fixed RS-level policy. PRM cannot encode "require FINANCIAL_SMALL if loan < $100, else require FINANCIAL_MEDIUM" as a verifiable predicate the agent satisfies at call time — that logic lives in the RS application layer and cannot be pre-published as a static OAuth scope. More precisely: PRM tells the AS what the RS *generally* requires; the ZK predicate lets the RS verify at call time against the *specific request context* without trusting the AS's pre-issuance scope assignment. §3 should explicitly address PRM and clarify that the "runtime" in "runtime-adaptive" means *per-request* context evaluation, not merely RS-level policy.

- **In-threat-model?** Yes — construction survives, but §3 has a terminology gap. "Runtime-adaptive" must be defined as *per-request predicate evaluation over request context*, not just "the RS chose the predicate at some point before the AS." PRM shows why the distinction matters.


## Persona: spiffe_engineer

---

### Attack 1: WIMSE Token Exchange Already Decomposes Your Joint Property

- **Attack**: WIMSE `draft-ietf-wimse-arch` §5 defines workload-to-workload token exchange where the calling workload presents a *subject token* (JWT SVID from SPIRE) to a *WTS (Workload Token Service)* co-located with the RS, which issues a *context token* scoped to that RS call. The critical piece: the WTS can be deployed as a sidecar — it is not the central AS. The calling workload never contacts the issuing SPIRE server at call time. The WTS validates the SVID offline (cached JWKS from SPIRE bundle endpoint, short-lived rotation). The RS then drives the predicate: "I need FINANCIAL_SMALL" → WTS checks the context token claims locally. This achieves **AS-blind at call time** (no SPIRE server roundtrip) and **runtime-adaptive** (RS-side predicate expressed as WTS policy evaluated against presented claims, not baked into the token at issuance). The construction's §8 Axis 0 claims "RFC 8693 is runtime-adaptive but AS-dependent" — that's true of the canonical RFC 8693 flow. But the WIMSE architecture explicitly separates the token exchange function from the AS and co-locates it. Your §8 table treats "AS" as monolithic; WIMSE splits it. The joint property the construction considers uniquely achievable via ZK circuit is decomposed at the infrastructure layer.

- **Why it works / why it fails**: It works because the construction's §8 analysis anchors on RFC baselines without modeling the WIMSE WTS deployment topology. It partially fails if the predicate is an *arithmetic* predicate over private inputs (e.g., "permission_bits & mask == mask without revealing permission_bits") — BBS+ selective disclosure reveals which bits are set, WTS inspection reveals the actual claim value. The ZK circuit is the only mechanism that evaluates a predicate over a *hidden* bitmask. But the construction's motivating scenario (8-bit permission field) is not a hidden-input predicate — the RS knows what permissions exist. The privacy claim evaporates for workload identity.

- **In-threat-model?** **No** — the construction must address why the WTS sidecar in WIMSE does not collapse Axis 0. Either tighten the threat model to require input-privacy (not just AS-blindness), or acknowledge this as a valid decomposition for the workload case and restrict the claim to the consumer-agent case where permission sets are genuinely private.

---

### Attack 2: The Adversarial-AS Model Is Self-Inflicted

- **Attack**: The construction's §3 states the decisive scenario is "adversary controls the AS, so moving predicate evaluation from AS to circuit moves it from adversary-controlled to adversary-independent." In SPIFFE, the SPIRE server is not a trusted-but-unverifiable software process — it is *attested*. The SPIRE server's signing key is sealed in a hardware root of trust (TPM, AWS Nitro Attestation, GCP Confidential Space). The SPIRE agent does node attestation before accepting any SVID; the join token is hardware-rooted. An "adversarial AS" in this model requires hardware compromise of the HSM or cloud attestation service, at which point you have a Tier-0 infrastructure breach that invalidates *any* cryptographic construction including the ZK circuit's verifier contract. The construction's §7 uses the CrowdStrike outage as a motivating scenario (AS offline → agent cannot present credentials). SPIRE solves this differently: SVIDs are cached by the workload API and rotated proactively. Short-lived SVIDs (1hr TTL, rotation at 50% of lifetime) mean the workload holds a valid offline-verifiable credential without any AS roundtrip for the duration. The construction's "AS-blind" property is not needed if the AS is hardware-attested and credentials are pre-cached.

- **Why it works / why it fails**: It works for the infrastructure workload case. It fails for *AI agents deployed outside controlled infrastructure* — a LLM agent running on a third-party inference provider cannot enroll in SPIRE node attestation. The SPIFFE node attestation model assumes you control the execution environment (EC2 instance, Kubernetes node). Consumer-deployed agents (laptop, phone, browser) have no SPIRE agent. This is a genuine gap in SPIFFE coverage.

- **In-threat-model?** **Yes, partially** — the construction survives for consumer/mobile agent deployments. But it must explicitly carve out the enterprise-infrastructure case and concede that the adversarial-AS framing does not apply where SPIRE node attestation is available. §3 and §7 currently present "AS may lie" as a universal threat, not a deployment-conditional one.

---

### Attack 3: The 2^64 Permission Space Scaling Argument Is Wrong

- **Attack**: The construction's candidate scenario states "regulated agent with 2^64 permission space where AS-side policy tables do not scale." In SPIFFE/SPIRE, policy is not a table enumeration — it is a *claim expression*. The SVID carries permissions as a structured JWT claim (a bitmask, a JSON array, or an OPA-evaluated policy result). The RS evaluates the predicate locally against the claim. There is no O(2^64) table on the AS side. SPIRE's OPA integration (`spire-oidc-provider` + OPA sidecar) evaluates arbitrary Rego predicates at attestation time against workload selectors. For a 64-bit permission field, the SVID carries a single 8-byte claim; the RS evaluates `(svid.permissions & required_mask) == required_mask` locally. The ZK circuit achieves a "constant-size proof regardless of bitmask width" — but the JWT SVID is also constant-size (the claim is a fixed-width integer). The construction's §8 lists "constant-size proof" as a corollary advantage; if the JWT claim is already constant-size, this corollary doesn't distinguish the construction.

- **Why it works / why it fails**: It works for the claim as currently stated. It fails if you distinguish *claim size* from *proof size* for a different reason: the ZK circuit hides the claim value entirely (only the predicate result is revealed), whereas the JWT SVID reveals the full bitmask to the RS. For a 64-bit permission field where the RS should not see which *other* permissions the agent holds (e.g., the agent has SIGN_ON_BEHALF and FINANCIAL_UNLIMITED but is only invoking FINANCIAL_SMALL), the ZK circuit provides input-hiding that JWT SVID cannot. But the construction does not clearly separate this input-privacy claim from the scaling claim. They read as the same argument in §8.

- **In-threat-model?** **No** — the construction must retire the "2^64 permission space" scaling framing, which is technically incorrect against SPIFFE. Replace it with the input-privacy framing: "the ZK circuit proves predicate satisfaction without revealing which *other* permissions the agent holds to the RS." That is the real gap.

---

### Attack 4: "Mutual ZK Handshake" Is mTLS with SVIDs Plus a Predicate Check — Name the Delta

- **Attack**: The construction's §1 title is "Selective scope proof" framed as a mutual handshake property. SPIFFE mTLS with X.509 SVIDs already gives you mutual authentication at the workload layer. The RS presents its X.509 SVID; the agent presents its X.509 SVID. Both sides attest their SPIFFE ID (`spiffe://trust-domain/agent/name`). Adding scope to this: the agent's JWT SVID carries the permission claim; the RS evaluates it. This is "mutual ZK handshake" minus the ZK — it's mutual SVID presentation plus local predicate evaluation. The construction's claim in §3 is that the "mutual" property adds *cryptographic binding of the predicate proof to the specific RS session*, preventing replay across RS endpoints. In SPIFFE mTLS, the TLS session itself provides this binding (session-specific key material, certificate pinning to SPIFFE ID). The construction's nonce-binding mechanism (§CLAUDE.md: "every handshake commits to a fresh sessionNonce") replicates what TLS session tickets already provide, but at the application layer above an unencrypted transport. The delta is only non-zero if you operate over a transport that doesn't provide session binding — which is a transport choice, not a fundamental cryptographic gap.

- **Why it works / why it fails**: It works if the construction targets non-TLS transports (e.g., agent-to-agent messaging via MCP tool calls, where there is no TLS session between the calling agent and the callee tool). The SPIFFE model assumes a TLS transport. For intra-LLM-pipeline calls (tool invocations inside a chain, browser-based agents, serverless function calls without mutual TLS), SPIFFE mTLS is operationally infeasible. The ZK handshake can work over any transport including application-layer protocols where you cannot enforce mTLS. This is a real deployment gap that the construction should call out explicitly rather than presenting nonce-binding as a novel cryptographic property.

- **In-threat-model?** **Yes, conditionally** — the construction survives if it explicitly scopes itself to non-TLS-transport environments (MCP, browser agents, serverless). It fails if it claims the nonce-binding mechanism is novel against an adversary who can deploy SPIFFE mTLS. The §CLAUDE.md spec draft (`draft-bolyra-mutual-zkp-auth-01.md`) should include a deployment-conditions section stating: "this construction is complementary to mTLS/SPIFFE for environments where mutual TLS cannot be enforced at the transport layer."
