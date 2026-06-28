# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: AS-Blind Is a Compliance Liability, Not a Feature

- **Attack:** The construction's stated differentiator — "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)" — is marketed as a privacy win. An enterprise security architect at a credit union will read it as an audit gap. SOC 2 CC6, ISO 27001 A.9, and NCUA examination guidance (relevant for Bolyra's stated credit-union target market) all require centralized, AS-side records of what access was granted and exercised. If the AS cannot see what scope predicate the agent presented at runtime, the compliance team cannot produce that record. Auth0/WorkOS provide that audit trail by design. The construction eliminates it by design.

- **Why it works / why it fails:** The construction doesn't address this. Section 8's SE-NIZK hardening closes a cryptographic attack but makes no claim about auditability. The mqSE-IND upgrade makes the proof *harder to correlate*, which further obscures what the agent disclosed. This is cryptographically desirable and compliance-operationally hostile — opposite directions.

- **In-threat-model?** No. The construction must address how an operator produces a regulatorily-acceptable audit log of runtime scope disclosures when the AS is explicitly kept blind.

---

### Attack 2: RFC 8707 + RFC 9068 Already Scope-Restricts Per-RS, Offline-Verifiable

- **Attack:** The construction claims that no combination of RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP can match selective scope proof. But RFC 8707 (Resource Indicators) combined with RFC 9068 (JWT Profile for Access Tokens) already lets the AS issue a token scoped *exclusively* to a named RS, with the scope claim reflecting only what's relevant to that RS. The RS verifies offline against the AS public key. The agent never reveals its full permission space to any RS — the AS filters at issuance time. The construction's surviving claim must be that *even the AS should not know the full permission set at presentation time*. But that requires the "adversarial AS" threat model from the gap description. Enterprise buyers do not have adversarial IdPs — they *are* the IdP operator.

- **Why it works / why it fails:** The construction partially survives on the "adversarial AS" scenario and the "2^64 permission space" scenario. But neither scenario appears in any actual enterprise MCP deployment today. The adversarial-AS scenario requires the buyer to believe their own IdP is compromised — which means they have bigger problems than scope disclosure. The 2^64 scenario is speculative; WorkOS and Auth0 permission models top out in the hundreds of scopes in practice.

- **In-threat-model?** Partial. The construction needs to explicitly delineate which specific threat model RFC 8707 + RFC 9068 cannot handle and produce a real-world deployment scenario (not a theoretical one) where that threat model applies.

---

### Attack 3: The mqSE-IND Proof Is Unaudited — and That Kills Enterprise Procurement

- **Attack:** The refinement invokes PLONK simulation-extractability per Faust et al. 2022, extends it to a q-query hybrid with a Poseidon PRF hop, and produces a new bound `|Pr[A wins] - 1/2| ≤ Adv_PLONK_SE_ZK + 4q · Adv_Poseidon_PRF`. This is a novel composition — Bolyra's specific circuit, Bolyra's blinding strategy, and Bolyra's hybrid argument — that has not been independently audited. Procurement at a financial institution will ask for: a third-party cryptographic audit, a CVE history, and a named security contact. The answer to all three is currently the same solo founder who wrote the proof. WorkOS points to SOC 2 Type II, a named security team, and years of production deployments. The mqSE-IND upgrade is technically meaningful and procurement-invisible.

- **Why it works / why it fails:** The construction survives the cryptographic challenge — the math may be sound. It fails the trust challenge. "Faust et al. 2022 says PLONK is SE" is not the same as "our specific instantiation has been reviewed by Trail of Bits." No bridge between those two claims exists in the construction.

- **In-threat-model?** No. The construction must address the trust bootstrapping problem: how does an enterprise buyer develop confidence in an unaudited novel composition before the construction has audit history?

---

### Attack 4: Proving Latency Kills the Agentic Use Case That Motivates the Construction

- **Attack:** The construction's scenario — agent proves a predicate over a large permission space at runtime — requires generating a ZK proof at the moment of resource access. The cited circuits run in the 10–30s range on commodity hardware (circuits build artifacts, `bench_rapidsnark.js` in `circuits/scripts/`). WorkOS issues a signed JWT in under 100ms. Agentic workloads make dozens to hundreds of RS calls per task (tool invocations, sub-delegations, chained MCP calls). At 15s per proof, a 10-step agent task with one scope presentation per step takes 150 seconds in ZK overhead alone — before any actual work. The construction's mqSE-IND refinement adds no performance improvement; it hardens the proof system that is already the bottleneck.

- **Why it works / why it fails:** The construction does not address latency. The `rapidsnark_prover` benchmark exists in the repo but is not cited in the construction as a bound on proof generation time, and no batching or pre-computation strategy is proposed. Proof caching could partially address this (prove once per session, reuse across RS calls with a session nonce), but that strategy has its own linkability consequences that conflict with the mqSE-IND privacy goal.

- **In-threat-model?** No. The construction must either bound proof generation time for the target permission bitmask width and demonstrate it is acceptable for agentic latency budgets, or propose a pre-computation architecture that preserves the mqSE-IND guarantee.


## Persona: cryptographer

---

### Attack 1: Nullifier Precomputation in a Bounded Permission Space

- **Attack:** The Bolyra permission model encodes an 8-bit bitmask (256 possible permission sets, per `CLAUDE.md`). At issuance time, the AS records the full bitmask for agent credential `(modelHash, operatorPrivKey, bitmask)`. Given that the RS announces its required `scope_id` in the request, a colluding AS+RS pair can precompute the Poseidon PRF output `nullifier = Poseidon(blindingNonce, scope_id, bitmask)` for all 256 bitmask values and all observed `blindingNonce` candidates. Since the blindingNonce is presumably derived from the agent's secret or a per-session value, and the AS has the issuance record, this is a brute-force enumeration of size ≤ 256 per proof transcript. Cross-referencing the presented nullifier against the precomputed table links the proof to the specific issued credential.
- **Why it works:** The construction's mqSE-IND game models the AS as honest (or at least non-colluding with RS). The 7-step hybrid argument reduces unlinkability to `Adv_Poseidon_PRF`, but this reduction assumes the PRF key (blindingNonce) is hidden from the distinguisher. If the AS issued the credential and logged the full bitmask, it functions as a PRF key-recovery oracle, collapsing the PRF advantage term.
- **In-threat-model?** **No.** The candidate's own scenario 2 explicitly states "AS is semi-trusted." The mqSE-IND game as described does not model a colluding AS+RS adversary. The construction must either (a) define a formal two-party collusion game where the adversary controls both AS and RS and show the reduction still holds, or (b) restrict the unlinkability claim to honest-AS deployments only — which contradicts scenario 2.

---

### Attack 2: PLONK Simulation-Extractability in AGM+ROM Does Not Transfer to the Standard Model Proof Claim

- **Attack:** The refinement invokes "PLONK with Fiat-Shamir in ROM is simulation-extractable (Faust et al. 2022)" to justify mqSE-IND. Faust et al.'s SE result for PLONK holds in the **Algebraic Group Model (AGM) + Random Oracle Model (ROM)** jointly. The construction's reduction bound `|Pr[A wins] - 1/2| ≤ Adv_PLONK_SE_ZK + 4q · Adv_Poseidon_PRF` implicitly treats these as independent terms, but Poseidon is an algebraically-defined permutation — its PRF security in the AGM is not established by the same techniques as e.g. AES-based PRFs. An AGM adversary can exploit the algebraic structure of Poseidon's MDS matrix to produce non-trivial linear relations between proof components and PRF outputs, potentially correlating transcripts in ways invisible to a purely ROM analysis.
- **Why it works / why it might fail:** The reduction stacks two model-dependent assumptions (AGM for PLONK SE + ROM for Fiat-Shamir + "PRF security" for Poseidon) without specifying whether Poseidon is modeled as a random oracle, a PRF in the standard model, or something else. If Poseidon is also ROM-idealized, the bound may be formally valid but vacuous — you've replaced one idealization with another. If it's claimed as a standard-model PRF, no published reduction justifies that for Poseidon in the AGM.
- **In-threat-model?** **No.** The construction must either (a) state the exact model (AGM+ROM) explicitly in the theorem statement and bound the concrete security loss through the AGM reduction, or (b) substitute a standard-model PRF (e.g., HMAC-SHA256) for blindingNonce generation and carry a separate ROM assumption only for Fiat-Shamir. Mixing Poseidon as both a hash (circuit-efficient) and PRF (security reduction term) without a clean separation is not a publishable proof strategy.

---

### Attack 3: Subverted Universal SRS Breaks the Adversarial-AS Claim Entirely

- **Attack:** The construction selects PLONK partly to avoid per-circuit trusted setup ("PLONK avoids per-circuit ceremony," per `CLAUDE.md`). But PLONK still requires a structured reference string (SRS) from a Powers of Tau ceremony. If the AS — modeled as semi-trusted in scenario 2 — contributed to or controls the SRS (e.g., is the ceremony coordinator, or ran a single-party ceremony), it knows the toxic waste `τ`. With `τ`, the AS can construct valid PLONK proofs for *any* statement, including proofs asserting permissions the agent was never granted. More critically, knowing `τ` allows the AS to extract the witness from any honest agent's proof via the algebraic extractor. This completely breaks both soundness (AS forges permission proofs) and zero-knowledge (AS extracts the full permission bitmask from presentations).
- **Why it works:** The construction's claim "RS needs cryptographic assurance independent of AS cooperation" collapses if AS controls the SRS. An adversarial AS that set up the ceremony has a trivial win: forge proofs on behalf of revoked agents, or retroactively deanonymize all presentations by extracting witnesses. The mqSE-IND game and the PLONK SE theorem both presuppose an *honestly generated* SRS. This is standard but must be an explicit axiom in the threat model, not assumed silently.
- **In-threat-model?** **No.** The construction must formally distinguish between (a) a semi-trusted AS that is adversarial at *presentation time* (post-issuance) vs. (b) one that is adversarial at *setup time*. If the claim is only "AS-blind at presentation time with honestly-generated SRS," state that. If the claim extends to adversarial AS at setup, the construction needs either a transparent/universal SRS (e.g., from a public ceremony Bolyra does not control) with a formal reference, or a subverted-setup model with explicit security degradation bounds.

---

### Attack 4: The "Constant-Size Proof Regardless of Bitmask Width" Claim Is Not a ZK Property — and the RFC 7662 Differentiation Depends on It

- **Attack:** The candidate claim states "constant-size proof regardless of bitmask width" as a differentiator from RFC 7662. PLONK does produce constant-size proofs (fixed number of group elements independent of circuit size for a fixed SRS). However, the *circuit size* for evaluating the predicate `satisfies(bitmask, required_perms)` grows with bitmask width. For an 8-bit bitmask the circuit is trivial, but the RFC 7662 comparison scenario mentions "2^64 permission space." A circuit for a 64-bit predicate over a Merkle-committed permission tree has non-trivial depth, and the SRS must be sized to accommodate it. "Constant-size proof" in PLONK means the *proof* is constant-size for a fixed circuit, not that proof generation cost is constant as the permission space scales. An adversary (or a skeptical RFC editor) correctly notes that at 2^64 permissions, the prover computation is O(n log n) in the circuit gate count — which scales with the predicate complexity — not O(1).
- **Why it works:** The differentiation claim against RFC 7662 rests on scalability to large permission spaces. If the prover cost is superlinear in predicate complexity, and the RFC 7662 alternative uses an AS-side policy lookup (O(1) DB query), the ZK construction is *slower* for large permission spaces, not faster. The proof size is constant, but proof generation is not. This doesn't break the ZK security claim, but it invalidates the stated differentiator in scenario 1 ("2^64 permission space where AS-side policy tables do not scale") — policy tables scale fine; it's the ZK circuit that doesn't.
- **In-threat-model?** **Partially.** The security claim (soundness, ZK, SE) is unaffected. But the *application claim* — that this construction is strictly superior to RFC 7662 in the large-permission-space scenario — requires a proof of concept circuit at realistic bitmask widths with benchmarked prover times vs. AS roundtrip latency. Without this, scenario 1 is marketing. The construction should either restrict the claim to the 8-bit Bolyra model (where it holds cleanly) or provide asymptotic and concrete benchmarks for the large-space case.


## Persona: cu_ciso

---

### Attack 1: The AS-Blind Presentation Destroys My Audit Trail

**Attack:** The construction's headline differentiator — "AS-blind presentation, no AS roundtrip, agent chooses what to disclose at the moment of use" — is precisely what breaks NCUA Part 748 Appendix B, Section III.C requirement for audit records. When an agent presents a selective-scope proof to an RS without an AS roundtrip, *no central authority sees the presentation event*. The RS gets a valid proof and presumably logs "proof verified: yes." The AS has no record this interaction occurred. The member's device generated the proof. Under FFIEC CAT Domain 3 (Cyber Incident Management), an incident response requires reconstructing: *who accessed what, when, with what permissions, and can I prove it to my examiner?*

During a 2am fraud incident — agent exfiltrates member data — my Tier 1 ops team calls the on-call. They pull AS logs: nothing. They pull RS logs: "proof verified." They cannot tell the examiner *which* permission bits were presented, *whether the agent disclosed more than it should have*, or *what session nonce bound this transaction*. The examiner asks for a privilege access log under GLBA Safeguards Rule §314.4(c)(3). I hand them a Poseidon hash. I fail the exam.

**Why it works against this construction:** Section 8 (the PLONK/SE-NIZK hardening) protects against proof malleation between *technical* adversaries. It does not produce a human-readable, examiner-defensible audit trail. Zero-knowledge is an *audit liability* in regulated contexts, not a feature.

**In-threat-model?** No — construction must address. The construction needs a logging layer that is cryptographically consistent with the ZK proof (e.g., a blinded log commitment the RS countersigns and reports to a designated audit endpoint), and it must name the specific FFIEC CAT control this satisfies.

---

### Attack 2: Key Custody — Where Does the Human Secret Live?

**Attack:** `createHumanIdentity(secret)` — that's the public API. Where is `secret` stored between sessions? The CLAUDE.md mentions browser-based proving. GLBA Safeguards Rule §314.4(d) requires "encryption of customer information in transit and at rest." NCUA examiners applying the FFIEC CAT "Baseline" maturity level will ask: what is the key management lifecycle for member-held secrets? Who performs rotation? What happens at device loss?

My vendor management policy requires the vendor to answer: (1) what cryptographic module holds the key (FIPS 140-2 Level 1+?), (2) what is the backup/recovery path, (3) what is the revocation mechanism. The construction claims the nullifier hash prevents replay, but it does not address what happens when a member's device is compromised and the secret is extracted — the adversary can generate valid proofs indefinitely for *any* permission predicate. There is no AS to revoke the credential because the design is AS-blind.

**Why it works against this construction:** The multi-query SE-IND hardening in the refinement proves an *external* adversary can't correlate transcripts. It does not address a *compromised key* scenario where the adversary *has* the secret and can generate fresh, valid, unlinkable proofs. RFC 7662 has a token revocation endpoint (RFC 7009). The construction has no equivalent.

**In-threat-model?** No — construction must address. Need a revocation or expiry mechanism that does not require AS cooperation but is still auditable. The current claim of "no AS roundtrip" is incompatible with centralized revocation; the construction must propose a credential expiry or on-chain revocation registry with a stated SLA.

---

### Attack 3: Regulatory Control Mapping Vacuum

**Attack:** I'll quote back the construction's claim: *"no configuration of RFC 7662 (plus jwt-introspection-response, RFC 8693, RFC 8707, DPoP) can match."* My examiner does not care. My examiner uses the FFIEC CAT and NCUA's IT examination handbook. Neither document contains the word "Groth16," "PLONK," or "simulation-extractable NIZK." 

My vendor management policy requires new technology vendors to map their controls to NIST SP 800-53 or NIST CSF. The construction maps to *neither*. It maps to academic cryptography literature (Faust et al. 2022). When I present this to my board's risk committee, they will ask: "Is this FIPS-validated?" No — snarkjs and Circom have no FIPS 140-3 validation. "Is this SOC 2 Type II audited?" No — it's an open protocol with no operating entity holding a SOC 2. "Has NCUA issued guidance permitting ZKP-based access control as a substitute for OAuth introspection?" No published guidance exists.

**Why it works against this construction:** The differentiation claim is valid *in the cryptographic threat model* but entirely absent from the *regulatory threat model*. My risk is not that an adversary breaks the ZK proof. My risk is that my examiner rates me "Baseline-Evolving" on FFIEC CAT and issues a Matter Requiring Attention on third-party risk management for deploying a non-FIPS-validated, unaudited cryptographic primitive in a member-data pathway.

**In-threat-model?** No — construction must address. Needs a section that explicitly maps the construction to FFIEC CAT domains, NCUA Part 748 sections, and proposes a path to SOC 2 Type II attestation for the proof-generation and verification infrastructure.

---

### Attack 4: On-Chain Registry Uptime vs. Core Processor SLA

**Attack:** The construction depends on an on-chain registry (Solidity verifiers, Base Sepolia → production Base mainnet). The CISO attack is mechanical: what is the SLA? Base mainnet has had outages (October 2023, ~1.5hr sequencer halt). My core processor (Fiserv, Jack Henry) contractually guarantees 99.95%+ uptime with defined RTO/RPO. My NCUA examiner expects my business continuity plan to cover all systems in the member-data pathway.

If the on-chain registry is unavailable during RS verification, what happens? The construction says proofs are verified against `humanMerkleRoot` and `nullifierHash` stored on-chain. If the chain is unavailable, can the RS cache the root? If yes, for how long? If a stale root is cached, a revoked credential (via Merkle root rotation) might still verify. If no, my member-facing services go down when Base has a sequencer outage.

GLBA Safeguards Rule §314.4(i) requires a written incident response plan that covers "service provider arrangements." My plan must document what happens when the on-chain dependency fails. The construction does not provide a fallback availability mode.

**Why it works against this construction:** The refinement (multi-query SE-IND, PLONK simulation extractability) addresses *cryptographic* adversaries. A sequencer halt is a *liveness* failure, not a *soundness* failure — and liveness failures in a regulated member-data pathway are treated as outages requiring BCP documentation. The construction's claim to be superior to RFC 7662 is undermined if RFC 7662 + a standard OAuth AS can provide 99.99% SLA via replicated infrastructure, while this construction cannot.

**In-threat-model?** No — construction must address. Needs a defined fallback mode (e.g., RS caches Merkle root with a TTL bound to the maximum revocation window), a stated maximum acceptable staleness, and a BCP section that a credit union can incorporate into its NCUA-required business continuity plan.


## Persona: rfc7662_advocate

---

### Attack 1: Per-RS Filtered JWT Introspection Achieves Selective Disclosure Without ZK

- **Attack:** RFC 7662 §2.2 lets the AS return a filtered `scope` claim per requesting RS. Combined with draft-ietf-oauth-jwt-introspection-response, the AS issues a *signed JWT introspection response* targeted at RS1 that contains only the scopes RS1 is authorized to see — RS2 never sees RS1's scope surface. The AS signs it offline; RS verifies with the AS's public key. No AS roundtrip per request after the first token fetch. The agent's full permission set never appears in any single RS-visible artifact. Where exactly does the construction (§ on AS-blind presentation) claim an advantage here?

- **Why it fails against the construction:** The AS must decide at introspection-response-issuance time which scopes to include. The *predicate* is fixed by the AS's policy table, not chosen by the agent at the moment of use. The Bolyra construction lets the agent prove "bit 3 is set AND bit 5 is set" against an arbitrary runtime-supplied predicate *without any AS involvement* — the agent selects and proves the predicate locally. Additionally, in the adversarial-AS scenario (§ "semi-trusted AS"): a malicious AS can simply lie in the JWT, including scopes the agent never had. The RS has no cryptographic assurance independent of AS cooperation; it trusts the AS's signature, not a circuit witness.

- **In-threat-model?** Yes — construction survives, but must make the adversarial-AS scenario a *named*, first-class threat model section. Currently it appears only as a parenthetical in the gap description. An RFC 7662 advocate will call this scope creep unless it's formally stated upfront.

---

### Attack 2: PPID + RFC 8707 Audience Binding Already Breaks Cross-RS Linkability at the RS Layer

- **Attack:** OIDC Pairwise Pseudonymous Identifiers give RS1 `sub=h(salt_rs1 || user_id)` and RS2 `sub=h(salt_rs2 || user_id)`. RFC 8707 resource indicators bind each token to a specific audience so a token issued for RS1 is cryptographically invalid at RS2. Neither RS sees the other's subject identifier. The construction claims ZK is needed to prevent cross-RS linkability — but this is already deployed production behavior. What property does the mqSE-IND privacy game (§ multi-query extension) provide that PPID+audience-binding does not?

- **Why it fails against the construction:** PPIDs break RS-to-RS linkability but not AS-to-RS linkability. The AS maintains the full PPID mapping and can trivially correlate all RS interactions for a given agent. In the adversarial-AS model, the AS *is* the adversary. The ZK construction achieves unlinkability from the AS itself: the agent's `blindingNonce` (now PRF-derived per the multi-query fix) means even the AS cannot link two presentations from the same agent. PPID provides unlinkability *between* resource servers; the construction provides unlinkability *including* the authorization server. That distinction must be stated explicitly or the RFC 7662 advocate will claim the construction solves a non-problem.

- **In-threat-model?** Yes — construction survives, but the threat model must clearly distinguish the "AS is honest" and "AS is adversarial" regimes. PPID wins in the former; ZK is strictly necessary in the latter.

---

### Attack 3: DPoP Already Provides Sender-Constraint — Why Is SE-NIZK Load-Bearing?

- **Attack:** RFC 9449 DPoP binds an access token to a client's ephemeral key pair. The RS verifies the DPoP proof-of-possession header on every request. Token theft or replay by a third party is prevented at the HTTP layer without any ZK machinery. The construction (§ hardened Section 8) calls out Groth16 proof malleation as a concrete attack that SE-NIZK prevents. But proof malleation is an attack on the *proof artifact*, not on the token transport. If the RS only accepts one proof per nonce (standard replay protection), malleated proofs are rejected by the nonce check before the verifier runs. What does SE-NIZK add beyond what DPoP + nonce replay protection already provides?

- **Why it works / why it fails:** DPoP operates at the bearer layer and prevents token theft, but it does *not* prevent a proof-malleating adversary who has observed a valid PLONK/Groth16 transcript from producing a fresh `(π′, x)` pair that satisfies the verifier for a *different* statement than originally proved. Groth16 malleability (linear homomorphism over the proof group elements) means an adversary can produce `π′ = π · δ` that verifies for a modified public input vector without knowing the witness. SE-NIZK (PLONK in ROM) closes this: extraction of a valid proof implies knowledge of a witness for exactly the claimed statement. Nonce replay protection catches *reuse* but not *malleation to a neighboring statement*. The construction must include a concrete example of the neighboring-statement attack to make this crisp — without it, the RFC 7662 advocate will claim Section 8's hardening is theoretical hand-waving.

- **In-threat-model?** Yes — construction survives, but requires a concrete malleation example (e.g., flipping permission bit 3→5 in the public input vector) to justify SE-NIZK over a simpler proof system + nonce defense.

---

### Attack 4: RFC 8693 Token Exchange + ABAC Renders the 2^64 Scalability Argument a Strawman

- **Attack:** The construction's "regulated agent with 2^64 permission space where AS-side policy tables do not scale" scenario (§ scenarios) assumes the AS stores a flat scope table. Modern AS deployments use attribute-based access control: the scope is a *structured claim* (JSON, XACML, Cedar) evaluated by a policy engine at token-exchange time. RFC 8693 token exchange lets an agent present a narrow `requested_token_type` with a `scope` parameter that is a runtime expression. The policy engine evaluates it against the agent's attributes and returns a token for exactly the requested predicate. The full 2^64 bitmask never appears in any issued token. Why is ZK needed when ABAC policy engines scale to arbitrary predicate spaces?

- **Why it fails against the construction:** RFC 8693 + ABAC requires a roundtrip to the AS *at proof time* — the agent cannot present a proof to an RS without first obtaining a narrowed token from the AS. In the construction, the agent proves the predicate locally using the circuit witness and presents a constant-size proof directly to the RS, with zero AS involvement. This is "AS-blind presentation" — the AS issues the credential once at enrollment; every subsequent proof is generated and verified without AS participation. Additionally, the AS must know the target RS's predicate at exchange time; if the predicate is supplied by the RS at runtime (unknown to the AS at enrollment), RFC 8693 cannot pre-issue the right token. The construction handles runtime-supplied predicates natively. The counter-argument must cite a concrete scenario where the RS's acceptance predicate is unknown at token-issuance time — that is the irreducible gap RFC 8693 cannot close.

- **In-threat-model?** Yes — construction survives, but the "2^64 permission space" framing is weak and will be dismissed as hypothetical. Replace it with "RS-supplied runtime predicate unknown to AS at issuance" as the primary scenario. That is a real deployment pattern (capability-based access in multi-tenant SaaS) and RFC 8693 provably cannot address it without a synchronous AS call.


## Persona: spiffe_engineer

---

### Attack 1: SD-JWT + WIMSE Already Delivers AS-Blind Selective Disclosure

- **Attack:** The construction's centrepiece claim — "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)" — is satisfied today by SD-JWT (RFC 7519 extension, now stabilised in the IETF OAUTH WG) composed with WIMSE token exchange. At issuance the SPIRE agent delivers a JWT-SVID containing all permissions as individually salted disclosures. At presentation the workload selects which disclosures to include and strips the rest. The RS verifies the selective SD-JWT offline against the SPIFFE bundle. No AS roundtrip, no ZK circuit, no trusted setup. The WIMSE `workload-to-workload` token exchange draft adds a one-hop narrowing step that mirrors what you are calling "delegation." Concretely: section 4's "property fundamentally unreachable by RFC 7662" list should strike AS-blind presentation, because SD-JWT + WIMSE covers it.

- **Why it works / why it fails against the construction:** It works as a gap-closer for the presentation-time disclosure property. It fails to cover zero-knowledge: SD-JWT reveals *which* claims were omitted (the RS learns the structure of undisclosed fields via salted hash placeholders). The construction can survive here only if it explicitly frames the claim as "the RS learns nothing beyond the single predicate bit" — full ZK, not selective disclosure. That is a stricter guarantee than SD-JWT gives, but the current candidate text (C1) does not name this distinction. The "AS-blind" bullet conflates two things: no-roundtrip and zero-knowledge. WIMSE closes the first; the construction must own the second as its differentiator.

- **In-threat-model?** No — the construction must tighten the claim. Replace "AS-blind presentation" with "zero-knowledge predicate evaluation: RS learns only `pred(perm_set) = 1`, not any individual bit or structural hint." SD-JWT cannot match that. WIMSE cannot match that.

---

### Attack 2: The 2^64 Permission Space Scenario Is a Strawman That Breaks the Circuit

- **Attack:** The construction's "regulated agent with 2^64 permission space" scenario is cited to justify ZK over policy tables. But the current circuit operates on an **8-bit cumulative bitmask** (bits 0–7, section on Permissions Model). A Groth16 or PLONK circuit over a 64-bit input is not what is built; it is a hypothetical. Worse, in a genuine 2^64 permission space you would use a capability token or a Cedar/OPA policy engine — not a bitmask at all. Meanwhile the SPIFFE/OPA composition is production-deployed at scale: SPIRE issues SVIDs, OPA evaluates policy against SPIFFE ID + environment attributes, RS receives an OPA decision document signed by OPA's bundle key. This handles unbounded policy predicates with no circuit constraints. The "AS-side policy tables do not scale" objection is also weakened by the fact that the construction's own circuit adds O(n) constraints per permission bit and the proving time for snarkjs (acknowledged as dev/test only) grows with constraint count.

- **Why it works / why it fails against the construction:** It works as an attack on the scenarios section. The 2^64 claim is not backed by an actual circuit that handles 64-bit inputs. The construction survives only if it scopes the claim correctly: "for the specific 8-bit cumulative encoding, a constant-size proof is achievable and covers the currently defined permission space." That is defensible. The extrapolation to 2^64 is marketing, not construction.

- **In-threat-model?** No — the construction must drop or qualify the 2^64 scenario. A tighter claim: "constant-size proof for any k-bit bitmask, where k ≤ circuit constraint budget (currently 2^16 from pot16.ptau), independent of which subset of bits is asserted."

---

### Attack 3: Adversarial-AS Is Not a Workload Identity Threat Model — It Is a PKI Failure Mode

- **Attack:** The construction's fourth differentiator — "adversarial-AS model where AS cannot lie about scope membership" — is the claim SPIFFE practitioners will reject most forcefully. In SPIRE, the SPIRE server is your PKI root. If it is compromised, it mints arbitrary SVIDs with arbitrary claims; game over. No cryptographic construction above the AS layer prevents this, because the AS is the trust anchor. Building a protocol that "survives a lying AS" is equivalent to building a TLS record-layer protocol that survives a compromised CA — you are solving the wrong threat. The correct mitigation is SPIRE HA + audit logs + short-lived SVIDs (default TTL: 3600s), not a ZK proof the AS cannot forge claim membership on. If the AS is adversarial, it generates a fresh `AgentPolicy` witness itself and issues a valid proof for any claim it wants.

- **Why it works / why it fails against the construction:** It works unless the construction can show a binding between the agent's hardware root of trust (e.g., TPM-sealed key, TEE attestation) and the ZK circuit input, such that the AS cannot generate a valid witness without access to the hardware-protected secret. The construction references `operatorPrivKey` as an EdDSA key — but if the AS holds `operatorPrivKey` (common in managed-agent scenarios), the adversarial-AS model collapses. The construction survives if and only if `operatorPrivKey` is generated and held exclusively by the agent's TEE/TPM, and the PLONK proof commits to a public output derived from that key. Neither the circuit spec nor section 8 says this.

- **In-threat-model?** No — the construction must either scope this to "semi-honest AS" (AS follows protocol but may be subpoenaed or compelled), not "adversarial AS," or add a TEE/hardware binding requirement that makes `operatorPrivKey` AS-inaccessible and document it explicitly.

---

### Attack 4: Short-Lived SVIDs Already Close the Multi-Query Attack Window

- **Attack:** The mqSE-IND hardening (the section 8 refinement) defends against an adversary who collects "polynomially many proofs from the same agent" and correlates across transcripts. In production SPIFFE deployments, SVIDs rotate every 3600 seconds by default and can be configured as low as 300 seconds. The multi-query attack requires collecting q transcripts within a single credential epoch before the key rotates. With 5-minute SVIDs (common in high-security environments), the attack window is operationally closed by key hygiene, not by SE-NIZK. The construction is paying a proving overhead (PLONK is ~3–5× slower than Groth16 for the same circuit, as the benchmarks in `circuits/scripts/bench_rapidsnark.js` would show) to prevent an attack that short-lived credentials already prevent. Meanwhile, SPIRE's automatic SVID rotation is zero-overhead: the Workload API pushes new SVIDs proactively.

- **Why it works / why it fails against the construction:** It works as a cost-justification attack: if the primary beneficiary of simulation extractability is multi-query resistance, and operational key rotation provides multi-query resistance for free, the marginal security value of SE-NIZK (at PLONK's proving cost) must come from somewhere else. The construction survives if it argues SE-NIZK prevents **proof malleation** — an adversary taking a valid proof `π` and constructing `π'` for the same statement without the witness — which short-lived SVIDs do not prevent. Section 8 does call out Groth16 malleation, which is the right argument. But that argument must be front-loaded as the *primary* motivation for SE-NIZK, not buried after the multi-query framing. As written, the construction leads with multi-query and mentions malleation second; a SPIFFE engineer reading it concludes "key rotation handles this."

- **In-threat-model?** Yes, partially — the construction survives on the malleation vector (key rotation cannot prevent π → π' without witness). But the multi-query framing is unnecessarily weak given the rotation alternative. Restructure section 8: lead with **proof malleation resistance** as the irreducible motivation for SE-NIZK, then note that multi-query resistance is a consequence, not the cause.
