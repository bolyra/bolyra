# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: You Strawmanned the ZK Baseline — BBS+ Signatures Close the Gap

**Attack:**
The construction's Section 7 exhaustively rebuts RFC 7662, SD-JWT (RFC 9635), Client Attestation, and WIMSE WPoP. It does not mention **BBS+ signatures** (`draft-irtf-cfrg-bbs-signature-05`, now in IETF CFRG Last Call). BBS+ lets a holder prove *predicate satisfaction over hidden attributes* — e.g., "permissions ∧ (0b00000111)" — without disclosing the full bitmask, without an AS roundtrip, and without a circuit. The proof is ~hundreds of bytes, verifies in milliseconds, and requires no trusted setup. Auth0 already ships a BBS+ prototype in its Verifiable Credentials lab; WorkOS has a roadmap item. The construction's core claim — "a property these fundamentally cannot express" — has a concrete counterexample that isn't in the paper.

**Why it works / why it fails against the construction:**
The construction's G5/G6 gadgets evaluate *implication closure* (bit 3 implies bit 2) over a hidden bitmask. BBS+ proofs are field-equality predicates, not arbitrary boolean circuits. Implication-closure verification reduces to checking `(mask & implied) == implied` — which is *not* a standard BBS+ predicate form. The construction could survive if Section 7 explicitly proves BBS+ cannot evaluate implication closure without full attribute disclosure. Currently it does not.

**In-threat-model?** No — construction must address BBS+ directly or the "fundamentally cannot express" claim is falsified by a live IETF draft.

---

### Attack 2: The Adversarial-AS Premise Has Zero Enterprise Buyers

**Attack:**
The construction's Section 1 (preserved verbatim) and the two scenarios in CANDIDATE both assume an "adversarial AS" or "semi-trusted AS." In practice, every enterprise MCP deployment has Auth0, Okta, WorkOS, or their own Entra ID as the AS — an entity they contracted with, audited, and SOC-2-certified. The RS and AS are often the *same legal entity*. The scenario where "AS cannot lie about scope membership" is not a threat to any buyer in the credit union space: they trust their identity vendor by contract. The ZK novelty only matters if you distrust your own identity provider. That is a niche academic threat model, not a procurement-level concern.

**Why it works / why it fails against the construction:**
The construction does not present a buyer-facing threat model. It presents a cryptographic threat model. A credit union CISO will ask: "Who is the AS in your model?" If the answer is "you can't trust it," the follow-up is "then why would we deploy your SDK on top of it?" The adversarial-AS scenario is only compelling in multi-party federation (e.g., a fintech using a third-party AS to issue scopes to an agent operated by a fourth party). This scenario is not described anywhere in the construction.

**In-threat-model?** No — the construction must add a concrete deployment scenario where the AS and RS are operated by *different* distrusting parties, and explain why credit unions encounter this.

---

### Attack 3: Proof Latency Invalidates the Agentic Use Case

**Attack:**
The construction's claim is targeted at agents ("agent proves it satisfies a required permission predicate"). Agentic workflows issue 10–100 API calls per task. At 15s per proof (per CLAUDE.md: `test:circuits:slow` takes ~2min for the full suite; individual Groth16 proofs are measured in `circuits/scripts/bench_rapidsnark.js`), the total proof overhead per agent task is 150s–1500s. WorkOS issues tokens in under 100ms. Even with caching (`sessionNonce` prevents replay, per CLAUDE.md "Handshake nonce binding"), proof reuse across calls is architecturally blocked by design. The construction's Section 8 property table claims "constant-size proof" but does not address *latency*. Size and time are different properties. The construction conflates them.

**Why it works / why it fails against the construction:**
The construction could respond that (a) proofs are generated once per session not per call, and (b) rapidsnark brings single-proof time to ~200ms on server hardware (benchmarks in `circuits/scripts/`). But (a) contradicts the nonce-binding security property — if you reuse a proof across calls, the nonce binding is vacuous. And (b) is a hardware requirement that adds operational complexity Auth0 does not impose. The construction must quantify proof latency *per session* and explain nonce-binding semantics across multi-call sessions.

**In-threat-model?** No — the construction must address proof reuse policy vs. nonce-binding security and provide honest latency numbers for a realistic agentic session.

---

### Attack 4: "Solo Founder" Is a Procurement Veto, Not a Sales Objection

**Attack:**
This is the attack the construction cannot answer cryptographically. Every credit union above $500M AUM has a vendor risk management policy requiring SOC 2 Type II, pen test reports, business continuity plans, and minimum revenue thresholds for critical identity infrastructure. WorkOS, Auth0, Stytch, and Cloudflare all clear this bar. A solo-founder ZK protocol — regardless of cryptographic soundness — will be vetoed at the vendor questionnaire stage before any technical evaluation occurs. The "regulated agent with 2^64 permission space" scenario in CANDIDATE is technically compelling but irrelevant if the buyer can't onboard the vendor.

**Why it works / why it fails against the construction:**
The construction is a cryptographic paper, not a GTM strategy. It has no response to this because it's out of scope by design. But from a PM perspective, the construction's viability depends entirely on whether it can (a) be embedded inside an existing certified vendor's product, (b) be standardized (IETF/W3C) so enterprises adopt the spec not the vendor, or (c) target a non-enterprise segment first. None of these paths are described. The IETF draft (`spec/draft-bolyra-mutual-zkp-auth-01.md`) is the right vector — but standardization takes 3–5 years, and the construction does not position itself as a standards contribution.

**In-threat-model?** No — the construction must explicitly state its go-to-market path: standards body first, embedded SDK, or direct enterprise sales. The cryptographic argument is complete; the adoption argument is absent.


## Persona: cryptographer

---

### Attack 1: Subverted Setup Breaks Soundness Unconditionally

- **Attack:** Groth16 achieves knowledge soundness only if the structured reference string (SRS) is honestly generated. Let the adversary control the trusted-setup ceremony (or compromise its toxic waste). They then hold a trapdoor `τ` such that for any statement `x` — including `x` where the agent does *not* hold the required permission bits — they can produce an accepting proof `π` with `Verify(vk, x, π) = 1`. Concretely: an agent with `permissionBitmask = 0b00000001` (READ_DATA only) can forge a proof claiming `FINANCIAL_MEDIUM` (bit 3). The construction's Section 3 `ImplicationClosureForgery` sub-game is vacuous here: if the prover can pick any satisfying witness after seeing the circuit, the game is trivially won.

- **Why it works / fails:** Works unconditionally given setup compromise. The construction inherits the standard Groth16 caveat but does *not* appear to bound the trust model. PLONK (used for AgentPolicy and Delegation) uses a universal SRS, which shifts but does not eliminate the problem — the universal SRS for KZG commitments has its own toxic waste. Neither proving system offers setup-free soundness.

- **In-threat-model?** No. The construction must either (a) specify a concrete ceremony with third-party attestation, (b) adopt a transparent/recursive SNARK (STARK, Halo2, Nova) that eliminates the ceremony, or (c) explicitly bound the adversary to honest-setup and state this as an assumption in the security theorem. Without one of these three, the soundness claim is conditional on an unnamed assumption.

---

### Attack 2: AS + RS Collusion Breaks the AS-Blind Claim via Proof Fingerprinting

- **Attack:** The construction's key differentiator is "AS-blind presentation" — the AS learns nothing about which predicate the agent proved to which RS. But Groth16 proofs are *not* zero-knowledge against a colluding (AS, RS) pair unless the proof is re-randomized before presentation. A standard Groth16 proof `π = (A, B, C)` is deterministic given the witness and randomness; if the prover reuses the same witness and randomness across two RS interactions (or if a deterministic prover implementation is the common case), the AS and RS can compare proof transcripts and link sessions. More dangerously: the public inputs `(permissionRoot, scopeId, predicateHash)` are the same across all presentations of the same credential — the RS can trivially correlate all sessions by the same agent credential, and the AS can re-link by matching the public input against its issuance records. This is not unlinkability; it is pseudonymity at best.

- **Why it works / fails:** The ZK property of Groth16 is honest-verifier zero-knowledge (HVZK): it hides the witness from an honest verifier who does not see other proofs. It is *not* simulation-extractable (SE-ZK) nor re-randomization-resistant by default. The construction needs to either (a) include a proof re-randomization step per presentation (possible for Groth16 by sampling fresh randomness over the same witness), or (b) use a Groth16 variant with built-in re-randomization, or (c) specify that `scopeId` is session-ephemeral and the `permissionRoot` is a per-session commitment. None of these is specified.

- **In-threat-model?** No. The "adversarial-AS model where AS cannot lie about scope membership" is advertised as a gap RFC 7662 cannot close — but the corresponding privacy game (AS cannot *track* scope usage) is never stated. A colluding AS+RS observing identical public inputs trivially wins a straightforward distinguishing game. The construction must define the linkability game and prove the scheme achieves unlinkability under it.

---

### Attack 3: ImplicationClosure Constraint Under-Specification

- **Attack:** The 8-bit cumulative encoding mandates that bit 3 (`FINANCIAL_MEDIUM`) implies bit 2 (`FINANCIAL_SMALL`), and bit 4 (`FINANCIAL_UNLIMITED`) implies bits 2 and 3. The `validateCumulativeBitEncoding()` function enforces this in the SDK, but the claim is that the `Delegation` circuit enforces it *on-chain*. The attack: supply a witness `permissionBitmask = 0b00001000` (bit 3 set, bit 2 clear). Does the `AgentPolicy` circuit reject this? If the circuit encodes the predicate as "bit `k` is set" via a single bit extraction constraint (`(bitmask >> k) & 1 = 1`) without also asserting all implied lower bits, then a prover with a malformed bitmask (one that violates implication closure but satisfies the literal predicate query) produces a valid proof. The RS accepts; the agent has a credential with an internally inconsistent permission set that the RS cannot detect because the bitmask is hidden.

- **Why it works / fails:** This is a constraint completeness failure, a known pitfall in circom circuits. The `FORMAL-PROPERTIES.md` presumably states the implication closure property, but circuit constraints must encode *every* implication as an arithmetic constraint, not merely check the high bit. A missing constraint is undetectable from the outside — tests pass because honest witnesses satisfy all constraints; malicious witnesses (bit 3 set, bit 2 clear) are never generated by the honest SDK path. Formal verification (e.g., via Ecne, Picus, or a pen-and-paper constraint analysis) is the only mitigation.

- **In-threat-model?** Conditional. If the circuit provably encodes all eight implication rules as explicit constraints, the attack fails. But the construction does not exhibit the constraint listing or a formal verification result. Until `FORMAL-PROPERTIES.md` is accompanied by a machine-checked proof of constraint completeness, this is an open soundness gap.

---

### Attack 4: Predicate Malleability — RS Cannot Bind the Proof to Its Own Predicate

- **Attack:** The RS specifies a required predicate `P` (e.g., "must have `FINANCIAL_MEDIUM`"). The agent produces a proof `π` claiming `P(bitmask) = 1`. The attack question: is `P` cryptographically bound to `π`, or can the agent present a proof generated for a *weaker* predicate `P' ⊂ P` and have the RS accept? Formally: if `P` is encoded as a public input hash `predicateHash = H(P)`, the RS must verify that `predicateHash` in the proof matches the predicate it actually requested. If the RS instead accepts any proof that merely mentions a compatible predicate hash — or if the predicate is not public-input-bound at all — the agent can present a stale proof from an earlier, weaker RS interaction. This is a credential replay attack orthogonal to the `sessionNonce` binding: nonces prevent temporal replay but do not prevent *predicate substitution* across different RS interactions occurring in the same time window.

- **Why it works / fails:** Groth16 binds public inputs to the proof cryptographically — if `predicateHash` is a public input, the RS can check it directly. But the construction must ensure (a) the predicate is fully serialized into the hash (no predicate aliasing — two distinct predicates with the same hash), and (b) the RS actually verifies `predicateHash == H(P_requested)` and not merely `π` validity. Neither the SDK API (`verifyHandshake`) nor the on-chain verifier contract is shown to perform this binding check explicitly. The construction inherits a standard "check what you verify" failure mode common in ZK application layers.

- **In-threat-model?** Conditional. If `verifyHandshake` performs an explicit `predicateHash` equality check against the RS's requested predicate, the attack is closed. If the check is absent or delegated to the caller, it is an in-threat-model vulnerability in the RS-facing API.


## Persona: cu_ciso

---

### Attack 1: "Name the Control" — Regulatory Mapping Vacuum

- **Attack:** I hand my NCUA examiner the construction's Section 7 comparison table. She looks up from it and asks: "Which Part 748 control requires this, and which SOC 2 Type II criterion does your vendor's ZK proof system satisfy?" I cannot answer. Section 7 argues cryptographic superiority over RFC 7662 — but my examiner's questionnaire does not contain the phrase "zero-knowledge proof." She uses FFIEC CAT Domain 2 (Threat Intelligence) and NCUA Part 748 Appendix B (response program). Neither maps to selective predicate disclosure. The construction's entire comparative argument is written for a cryptographer, not an examination narrative.
- **Why it works:** The construction is entirely framed as a *technical* differentiation from RFC standards. It contains no mapping to NCUA examination outcomes, GLBA Safeguards Rule §314.4(e) (access controls), or FFIEC CAT Maturity Level controls. This is not an oversight the construction can wave away — it is a structural absence. The CISO cannot adopt a novel cryptographic mechanism that has no regulatory hook without requiring board-level exception approval and NCUA pre-examination disclosure.
- **In-threat-model?** No. The construction must address this or it will not cross the procurement threshold at any federally-examined institution.

---

### Attack 2: Forensic Invisibility During Incident Response

- **Attack:** An agent accesses member PII at 3:47am. My SOC flags it at 5am. I open a GLBA breach investigation and pull the audit log. The log shows: `agent_id=X, predicate=SATISFIED, proof_valid=true`. The ZK proof — which is the entire point of Section 3's `SelectiveScopeProof` and the `AS-blind presentation` scenario — has cryptographically concealed the actual permission bitmask from the resource server. I cannot tell my NCUA examiner which bits were set. I cannot reconstruct the authorization surface of the agent during the incident window. The construction's core security property — hiding the full permission set from the RS — is directly antagonistic to GLBA Safeguards §314.4(c) (audit and monitoring) and NCUA's post-incident reconstruction requirements.
- **Why it works:** The construction correctly argues the RS learns only "predicate satisfied." That *is* the differentiating property. But that property destroys my forensic reconstruction capability. Section 3's ImplicationClosureForgery sub-game proves the cryptography is sound — it does not address what happens when law enforcement or my examiner demands the full access record. The proof is a one-way door: I can verify it was valid, I cannot invert it to recover what was authorized.
- **In-threat-model?** No. The construction must define a forensic disclosure mode — either a regulator-held escrow of the bitmask or a separate audit channel — or it is not deployable in a GLBA-regulated environment.

---

### Attack 3: AS-Blind Presentation Eliminates Real-Time Revocation

- **Attack:** Scenario 2 of the construction explicitly positions AS-blind presentation as a feature: "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." In my environment, the Authorization Server is not a threat actor — it is the revocation authority. When an employee is terminated at 2pm, my AS revokes their delegated agent credentials by 2:01pm. If the agent holds a ZK credential that proves permission predicate satisfaction *without an AS roundtrip*, that agent remains cryptographically valid until the credential expires. Depending on the `expiry` parameter in `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)`, I may have a live credential for hours or days post-termination. NCUA Part 748 and GLBA §314.4(f) (service provider oversight) require timely access termination — "timely" in exam language means minutes, not hours.
- **Why it works:** The construction trades AS liveness for AS blindness. For a threat model where the AS is adversarial, this is correct. For a credit union, the AS is your own IAM stack — not adversarial, and critically responsible for revocation. The construction's Scenario 2 is solving a problem I do not have while creating a revocation problem I cannot accept.
- **In-threat-model?** No. The construction must either (a) define a short-lived credential regime with mandatory online check that degrades gracefully when AS is unavailable, or (b) explicitly scope Scenario 2 to contexts where AS-blind operation is acceptable and exclude federally examined institutions.

---

### Attack 4: Vendor Due Diligence Under Third-Party Risk — Unauditable Stack

- **Attack:** My Vendor Management Policy (required by NCUA Part 748 Appendix B §III) requires I complete a due diligence questionnaire before onboarding any vendor with access to member-facing systems. The questionnaire asks: penetration test results, SOC 2 Type II report, DR/BCP RTO/RPO, encryption key management procedures, and audit log retention. I send this to Bolyra. The response for "encryption key management" cites `circuits/build/rapidsnark_prover`, Groth16 trusted setup ceremony, and `pot16.ptau`. My vendor risk analyst returns this to me with a sticky note: "I don't know what a `.ptau` file is or who audited the ceremony." The construction's Section on trusted setup reuse ("HumanUniqueness reuses the public Semaphore v4 ceremony") means the security root is a *community ceremony* — not a vendor-controlled, auditable key management procedure. I cannot complete my NCUA third-party risk assessment against a decentralized trusted setup.
- **Why it works:** The construction's trusted setup story is cryptographically defensible (reusing a public ceremony avoids bespoke trusted setup risk). But it is operationally opaque to every vendor risk framework in existence. My examiner will ask who controls the `pot16.ptau`, who can revoke it, and what my remediation path is if the ceremony is retroactively compromised. The honest answer — "it's a community artifact, no single party controls it" — reads as "no one is accountable," which is the worst possible answer in a third-party risk examination.
- **In-threat-model?** No. The construction must provide a vendor-auditable trust artifact — either a SOC 2 Type II covering the circuit compilation and key derivation pipeline, or an explicit ceremony audit report from a named third-party cryptographic auditor — before a federally examined institution can complete onboarding.


## Persona: rfc7662_advocate

---

### Attack 1: RFC 8693 Token Exchange Already Provides Runtime-Adaptive Scope Narrowing

- **Attack:** The construction's strongest claimed differentiator is "runtime-adaptive predicate over permissions (not fixed at issuance)." But RFC 8693 §2.1 defines exactly this: the agent presents a broad `subject_token` to the AS at moment-of-use, specifies a `scope` parameter narrowed to what the target RS requires, and receives a freshly-issued narrow token. The AS enforces the predicate (`requested_scope ⊆ granted_scope`) at exchange time. The RS receives only the narrow scope — it never sees the agent's full permission set. Combined with RFC 8707 Resource Indicators, the returned token is audience-bound to that RS and unusable elsewhere. The AS *does* see the exchange request, but the RS is fully blind to the original broad grant.

- **Why it works / why it fails:** The construction must argue that AS-roundtrip-at-use-time is a fundamental distinction, not just an operational inconvenience. Section 7 of the construction does not analyze RFC 8693 Token Exchange. It addresses per-RS *introspection policy* (static filtering), but Token Exchange is dynamic — the agent drives scope selection at the moment of use, which is precisely what the construction calls "agent-chosen disclosure." The ZK construction's claim to "AS-blind presentation" remains the only surviving differentiator: in Token Exchange, the AS observes `(agent_id, target_RS, requested_scope)` on every invocation. In the ZK construction, the AS never sees the presentation event. If the construction's threat model requires hiding invocation patterns from the AS, this must be stated explicitly as a first-class property.

- **In-threat-model?** Partially. The construction survives if and only if it explicitly claims AS-invocation-blindness (not just RS-blindness) as load-bearing. If the construction only claims RS-blindness, RFC 8693 closes the gap. **The construction must address RFC 8693 in Section 7 — it is currently absent.**

---

### Attack 2: OIDC PPID + Signed JWT Introspection Response Closes Cross-RS Linkability Without ZK

- **Attack:** The construction implies that ZK is needed to prevent cross-RS correlation of the agent's permission set. But pairwise pseudonymous identifiers (OIDC PPID, Section 8 of OIDC Core) already sever identity correlation across RSes at the identifier level. Combine this with `draft-ietf-oauth-jwt-introspection-response` (signed JWT response): each RS receives a *separately issued, RS-specific* signed JWT containing only the scopes relevant to that RS, with a pairwise subject. The RS verifies offline, the AS is not on the hot path, and cross-RS scope correlation requires compromising the AS — the same trust boundary the ZK construction relies on. The construction's Section 8, Property 2 claims the baseline "cannot enforce predicate satisfaction without revealing the full permission set" — but with per-RS introspection policy, the AS never puts the full permission set in the RS-facing JWT to begin with.

- **Why it works / why it fails:** The attack fails specifically at implication closure. Per-RS filtering returns a *curated subset* of scopes — but the RS cannot verify that the returned subset is *consistent with the implication lattice*. Example: the AS could return `{FINANCIAL_MEDIUM}` without `{FINANCIAL_SMALL}`, and the RS has no way to detect this omission. The ZK circuit's G5/G6 gates (implication closure enforcement over the hidden `permissionBitmask` witness) produce a proof that the implication invariants hold — the RS verifies this without seeing the bitmask. No JWT-based scheme can offer this because JWT verification is over disclosed claim *values*, not over hidden witnesses. **This is the construction's strongest surviving claim, but it must be foregrounded more explicitly than it currently is.**

- **In-threat-model?** Yes — the construction survives this attack on implication closure grounds. But the construction must clearly distinguish: (a) cross-RS linkability (already solvable by PPID + filtered JWT) vs. (b) implication-closure integrity over hidden witnesses (genuinely novel). Currently, the two are conflated in Section 8.

---

### Attack 3: The Adversarial-AS Model Is Non-Standard and Carries the Entire Unique Claim

- **Attack:** Strip away every property achievable by the standard OAuth toolbox. What remains is this: "the AS cannot lie about scope membership." This appears in the construction's `gap_to_close` as an afterthought — "adversarial-AS model where AS cannot lie about scope membership." But in every RFC in the toolbox, the AS is a trusted party by definition. RFC 7662 §2.2 states "the authorization server is trusted to provide accurate information." RFC 9449 DPoP adds sender-constraint but does nothing to constrain AS honesty. RFC 8707 Resource Indicators narrow audience but the AS still constructs the token. If the AS is adversarial, *all* RFC-based constructions collapse simultaneously — the threat model has departed from OAuth entirely. The ZK construction's Groth16/PLONK proof, however, shifts trust from "AS is honest" to "circuit is correct + zkey is untampered" — a cryptographic guarantee, not a policy guarantee.

- **Why it works / why it fails:** The attack surfaces a genuine underspecification. The construction mentions the adversarial-AS model in `gap_to_close` but Section 7 does not formalize *what AS adversary is contemplated*. A semi-honest AS (correct protocol, leaks observations) is different from a malicious AS (fabricates scope membership). The construction's proof system binds the agent's `permissionBitmask` to a commitment that was established at credential issuance time — if the AS issues a corrupt bitmask, the ZK proof is for a corrupt input. The construction only provides cryptographic scope-privacy relative to an *honestly-issued credential*. Against a malicious AS that issues false bitmasks at enrollment time, neither the ZK construction nor RFC 7662 provides protection. **Section 3's threat model must bound this explicitly or the adversarial-AS claim is overclaimed.**

- **In-threat-model?** Partially. The construction survives against a semi-honest AS (privacy guarantee holds). It does not survive against a credential-forging AS — and the construction does not currently state this bound. This is an **active gap that must be addressed.**

---

### Attack 4: The Constant-Size Proof Property Is Trivially Matched by Bitmask JWTs

- **Attack:** Section 8, Property 4 claims the ZK construction produces constant-size proofs regardless of bitmask width, implying this is a differentiator. But a JWT with a single `permissions` claim carrying a 64-bit integer bitmask is also constant-size. An RS evaluating `(permissions & required_mask) == required_mask` performs constant-time predicate evaluation against a constant-size claim. The construction's `scenario` of "2^64 permission space where AS-side policy tables do not scale" does not engage with bitmask JWTs at all. The scaling argument applies to *enumerated-scope lists* (e.g., `scope: "read write admin financial_small financial_medium ..."`), not to compact binary encodings. Bolyra itself uses an 8-bit cumulative bitmask (`CLAUDE.md`, Permissions Model section) — this is already the compact representation.

- **Why it works / why it fails:** The attack fails on *predicate privacy*, not on *predicate evaluation*. A bitmask JWT discloses the full 8-bit (or 64-bit) integer to the RS. The RS learns the entire permission set in order to evaluate the predicate. The ZK construction evaluates the predicate without disclosing the bitmask. For the attack to land, the construction must be claiming proof-size efficiency as a standalone property — which it should not. **Property 4 in Section 8 should be rewritten to emphasize predicate-privacy-with-constant-proof-size, not proof-size alone, since size is not a differentiator against bitmask JWTs.**

- **In-threat-model?** No — this attack exposes a **weak framing in Section 8, Property 4** that makes the construction look like it's claiming something it isn't. Constant-size is not a ZK-unique property. Constant-size-with-predicate-privacy is. Fix the framing.


## Persona: spiffe\_engineer

---

### Attack 1: The SPIRE ZK-Attestor Extension Non-Argument

- **Attack:** SPIFFE/SPIRE exposes a pluggable node attestor interface. I can write a `zk_attestor` that emits an SVID carrying an opaque proof-carrying claim — say `x-zk-scope-proof: <groth16_blob>` — inside a standard JWT-SVID. The SPIRE server issues the SVID without knowing the underlying permission set; it only verifies that the ZK blob satisfies the attestor's policy check. The Workload API delivers this SVID to the workload socket. The RS validates the embedded proof inline. This is a 500-line SPIRE plugin, not a new protocol. The construction's Section 7 compares against RFC 7662 and WIMSE WPoP but never argues why a ZK attestor shim inside SPIFFE fails the four-property test from Section 8. The omission is the attack surface.

- **Why it works / why it fails:** The construction *might* survive this if it can show that the SPIRE server, as issuer of the SVID wrapper, still learns the predicate being evaluated — reintroducing AS-side visibility even though the scope bits are hidden. But the draft does not make this argument. Section 7 argues against WIMSE WPoP specifically because the AS learns which predicate is requested (at token-exchange time). The same argument applies to the SPIRE attestor: the attestor call-site knows *what* is being attested. If this is the actual gap, Section 7 needs a "ZK attestor shim" subsection that explicitly closes it by identifying the attestor call-site as the leak point.

- **In-threat-model?** No — construction must address. Add a "ZK attestor plugin for SPIRE" subsection to Section 7 and show where attestor-call observability re-introduces AS-side leakage.

---

### Attack 2: The Adversarial-AS Threat Model Is Self-Undermining

- **Attack:** The construction's strongest differentiator (Section 8, Property 6; Section 3 adversarial-AS sub-game) is that the RS gets cryptographic assurance *independent of AS cooperation*. But consider the trust chain: the `permissionBitmask` witness comes from somewhere — a credential issuance step where *some* trusted party encoded those bits. In the Bolyra model that party is the operator who signed the `AgentPolicy` credential with their EdDSA key. In practice, the operator *is* the AS analog. The construction permits the operator to lie about the bitmask at issuance time and the ZK proof will happily prove a false predicate over a false bitmask. What the construction actually achieves is "the AS cannot lie about scope *at presentation time*" — which is a narrower and less compelling property. SPIFFE's model is equivalent: the SPIRE server cannot forge a presentation, but it controls issuance. The adversarial-AS game in Section 3 (`ImplicationClosureForgery`) targets an AS that *modifies claims in transit*, not one that issues false claims. That is a replay/tamper threat, not an adversarial-AS threat, and mTLS with SVIDs already closes it.

- **Why it works / why it fails:** The construction survives if it precisely scopes "adversarial AS" to mean "an AS that issues correct credentials but makes false claims *about which scopes were used* at audit time." ZK gives a privacy-preserving audit trail — the RS can prove post-hoc which predicate was satisfied without the operator learning which sub-permissions were exercised. That *is* a genuine gap SPIFFE doesn't close. But the draft doesn't make this the primary claim; it leads with "AS cannot lie about scope membership" which conflates issuance-time trust with presentation-time trust.

- **In-threat-model?** Partially. Construction survives the narrower claim (tamper-in-transit) but must reframe the adversarial-AS scenario more precisely or a reviewer will conflate it with issuance-time forgery, which ZK does not address.

---

### Attack 3: Hierarchical Scope Strings Collapse the Implication-Closure Gap

- **Attack:** Section 8 Property 2 claims SD-JWT cannot evaluate predicates over hidden claims and that implication closure enforcement and selective disclosure are mutually exclusive. But the construction's cumulative-bit encoding (`FINANCIAL_MEDIUM` implies `FINANCIAL_SMALL`) is structurally isomorphic to a lattice of named scopes: `financial.medium ⊇ financial.small`. A JWT carrying `scope: "financial.medium"` already implies `financial.small` under RS-side policy — the RS does not need to see a separate `financial.small` claim because the naming convention encodes the implication. No ZK required. More directly: the RS can issue an RS-specific policy document that maps scope strings to their closure, making the AS's returned scope verifiable as a *lower bound* on granted permissions. The RS presents its required predicate (`requires: financial.small`) and checks that the presented scope is in the closure of `financial.medium` by table lookup. This is exactly what RFC 8707 (`resource` indicator) combined with AS-side scope filtering is designed to enable. The construction's uniqueness claim must show why this breaks down for the 2^64-permission scenario claimed in Section 1.

- **Why it works / why it fails:** The attack fails if the permission space is not enumerable at RS-policy-definition time — i.e., the predicate is *runtime-adaptive* (e.g., `satisfies: lambda bits: bits & 0xFF > threshold(context)`). Hierarchical scope strings require a finite, pre-enumerated lattice. For the 2^64 scenario the lookup table is infeasible. But the construction's current eight-bit encoding does *not* demonstrate this — an 8-bit lattice has 256 nodes and is trivially enumerable. The draft must either (a) make the scalability argument central and cite the 8-bit encoding as a toy instantiation, or (b) define a runtime-adaptive predicate that cannot be expressed as a scope-lattice lookup, and prove it in Section 3.

- **In-threat-model?** No for the 8-bit instantiation as currently presented. Construction must either commit to the 2^64 scenario as the primary claim or formally define "runtime-adaptive predicate" and show it falls outside the scope-lattice model.

---

### Attack 4: Constant-Size Proof Is Not a Differentiating Property at This Bitmask Width

- **Attack:** Section 8 Property 4 cites constant-size proof as a meaningful advantage over SD-JWT (where size grows with disclosed claims). For an 8-bit bitmask, a standard JWT encoding of all eight scope claims is under 400 bytes. A Groth16 proof is ~256 bytes (three G1 points + one G2 point in compressed form), plus the verification key amortization. The size advantage is real but marginal at 8 bits and only becomes material above roughly 2^12 bits where bitmask-encoded JWTs become impractical. The construction does not show the crossover point, does not define the permission-space cardinality at which the property becomes load-bearing, and does not address that for the regulated-agent scenario (2^64 permissions) the circuit depth and proving time may make the latency tradeoff *worse* than a large JWT for synchronous API calls. The "constant-size" claim needs a cost model, not just a direction-of-improvement claim.

- **Why it works / why it fails:** The attack is blunted if the construction adds a concrete crossover analysis: proving time vs. JWT size vs. validation latency at N=8, N=64, N=1024, N=2^32. SPIFFE engineers will immediately ask "at what scale does this beat mTLS+SVID in p99 latency?" Without numbers, Property 4 reads as theoretical rather than operational.

- **In-threat-model?** Partially. Property 4 is not wrong, but it is undefended for the scale at which it matters. The construction should add a one-paragraph operational cost model to Section 8 Property 4, or drop the constant-size claim as a primary differentiator and let the AS-blind and predicate-evaluation properties carry the argument.
