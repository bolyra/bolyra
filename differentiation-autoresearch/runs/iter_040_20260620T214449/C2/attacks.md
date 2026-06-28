# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The IND-UNL-AS Game Proves Safety Against the Wrong Adversary

- **Attack:** Theorem 4.2 and Corollary 4.3 formalize the AS as the *adversary* trying to correlate agent traffic. But in every enterprise deal I close, the AS *is* the identity provider — that's us (Auth0), WorkOS, Stytch. The threat model your CISO cares about is: rogue insider at the CU, subpoena from a regulator, or breach of the CU's own audit logs. The IND-UNL-AS game assumes an *honest-but-curious AS that follows the protocol*. A subpoena against PNWCU's issuance log doesn't care what game your theorem covers — the log still exists with timestamps, IP addresses, and session metadata that sit outside the ZK circuit entirely.

- **Why it works / why it fails:** The construction's formal separation gap (`1/2 - negl(λ)`) is real within its stated model. But the model excludes the adversary that actually shows up in credit union procurement reviews. The §7 deployment scenario quantifies "PNWCU's privacy improvement" against this theorem, which means it inherits the theorem's adversary assumption. Nothing in the construction addresses OS-layer metadata, TLS session resumption fingerprinting, or legal compelled disclosure — all of which sit above the ZK layer.

- **In-threat-model?** No — construction must address. The formal game needs a companion threat model section that explicitly names what it does *not* cover and why those residual leaks are acceptable for the stated scenarios (CU-as-AS must not see member merchant graph). A procurement reviewer will ask exactly this.

---

### Attack 2: Proof Latency Collapses Unlinkability in Practice

- **Attack:** The claim requires fresh ZK proofs per authorization (nullifier separation per scope, per §4's proof-grounded argument). Your circuits take ~15s to prove. Any operator who can't wait 15s will implement proof caching or session token reuse — which collapses the unlinkability property. The formal bound `Adv_ZK ≤ negl(λ)` holds for a fresh proof per request. The moment an SDK ships a `ProofCache` for performance reasons (and it will, because 15s is unusable), the nullifier stops being fresh-per-scope and the separation theorem's premise breaks.

- **Why it works / why it fails:** The construction notes that side channels (timing, nonce freshness) are a gap but claims the formal separation theorem closes the *cryptographic* gap. It does. However, the engineering gap around latency creates pressure to cache, and caching degrades the cryptographic guarantee without the construction having a stated policy against it. WorkOS issues tokens in <100ms — the comparison isn't just UX, it's that their model is *safe by default* and yours requires operators to never optimize for latency.

- **In-threat-model?** No — construction must address. The construction needs either a stated latency budget (rapidsnark gets to ~400ms — cite that), an explicit prohibition on proof caching in the security properties section, or a nonce-freshness check that makes stale proofs fail verifiably so the SDK can't silently degrade.

---

### Attack 3: "Colluding AS+RS" Is the Wrong Threat for the Stated Scenarios

- **Attack:** The construction's §7 scenario is "CU-as-AS must not see member merchant graph." In real deployments, the merchant RS is operated by a payment network (Visa, FIS, Fiserv), not the CU. The actual correlation threat is: the *payment network* as RS correlates member agent traffic across multiple CUs (each acting as their own AS). Your IND-UNL-AS game isolates the AS as adversary. But the scenario requires protection against a *colluding RS*, not a colluding AS. RFC 8707 resource indicators already bind tokens to a single RS — WorkOS implements this today with no ZK. The formal separation theorem in §4 doesn't speak to the RS-as-correlator model at all.

- **Why it works / why it fails:** Corollary 4.3 cleanly separates Bolyra from OAuth in the IND-UNL-AS game. The formal gap is real. But the healthcare delegation scenario ("issuer learning referral network") and the merchant graph scenario both require IND-UNL-RS or a combined IND-UNL-(AS∧RS) game. Neither is defined or proved. The baseline comparison with DPoP+PPID+RFC 8707+BBS+ addresses AS-side correlation; it does not claim RS-side protection, so the "trivial 5-line adversary A_base" only wins the AS game — it might not win the RS game, making the separation theorem prove less than the scenario requires.

- **In-threat-model?** No — construction must address. Define IND-UNL-RS separately. Show that the nullifier domain separation (`H(scope ∥ secret)` per scope) protects against an RS that shares data with peer RSes. The current theorem proves the right thing for the wrong party in the stated scenarios.

---

### Attack 4: Solo-Founder Theorem vs. Enterprise Procurement Reality

- **Attack:** Even if Theorem 4.2 is correct and peer-reviewed, a credit union CISO's procurement checklist has: SOC 2 Type II, FIPS 140-2, a signed BAA, vendor financial viability, and a support SLA. Bolyra has a provisional patent and a formal proof. The 4-remark argument in §4 that BBS+/PPID/DPoP/anonymous requests can't close the gap is a *technical* argument. Procurement's counter-argument is: "We've been running Auth0 for 5 years; WorkOS is SOC 2 certified; this one-page theorem doesn't transfer risk away from us." The formal separation `1/2 - negl(λ)` doesn't appear anywhere on a vendor risk assessment form.

- **Why it works / why it fails:** The construction is technically rigorous. The gap it closes (IND-UNL-AS) is real and not addressed by incumbents. But the construction has no answer to the §1 claim's *market* burden of proof, only its *cryptographic* burden of proof. The scenarios in §7 name PNWCU specifically — credit unions are regulated entities with vendor due diligence requirements that operate entirely outside the threat model.

- **In-threat-model?** This is a GTM attack, not a cryptographic one — but it's the attack that actually kills deals. The construction should add a §8 or companion document mapping each formal claim to a regulatory artifact (NCUA guidance, SOC 2 control, FIPS module boundary) so procurement reviewers have something to check. Without it, Corollary 4.3 is a proof that exists in a document no auditor will read.


## Persona: cryptographer

> "Theorem 4.1 with a bound `Adv ≤ 2·Adv^PRF + Adv^ZK` is a good start. But three things are still hand-waving: the threat model elides AS corruption model, the PRF and ZK terms are not independent, and 'zero-knowledge' is doing very heavy lifting without naming which flavor. Let me be specific."

---

### Attack 1: Active-AS Scope-ID Collision (Nullifier Preimage Entanglement)

- **Attack:** The IND-UNL-AS game as described places the AS in a *passive observer* role — it reads its own issuance log. But the claim is against an "adversarial AS that tries to correlate per-agent traffic graphs." An active AS controls RS registration. Suppose the nullifier is computed as `null = H(secret, scope_id)` (the natural construction for domain separation). If the AS registers two resource servers with the *same* `scope_id` — or with `scope_id` values it chose to collide in a truncated hash — it receives `null₁ = null₂` for the same agent across both RS interactions. The adversary wins IND-UNL-AS trivially by comparing nullifiers.

- **Why it works / fails:** It works unless the construction enforces that `scope_id` is *externally committed and collision-resistant* before the agent generates a proof — i.e., the agent refuses to prove under an AS-supplied `scope_id` that it has not independently verified maps to a distinct RS. The construction (§4, Definition 4.2) specifies the AS issuance log but does not specify who generates or commits `scope_id`. If AS is the generator, this attack is trivially in-model.

- **In-threat-model?** **No** — the construction must either (a) add a `scope_id` binding commitment step where the agent verifies `scope_id ∈ public RS registry` before proving, or (b) reformulate the IND-UNL-AS game to give the adversary explicit `scope_id`-selection power and show the advantage remains `negl(λ)` even then.

---

### Attack 2: Non-Independence of the Two Reduction Terms (`2·Adv^PRF + Adv^ZK`)

- **Attack:** Theorem 4.1 states `Adv ≤ 2·Adv^PRF + Adv^ZK`. This union bound is only valid if the PRF and ZK security games are *independent* — i.e., an adversary breaking one does not help break the other. Both `Adv^PRF` and `Adv^ZK` depend on the same CRS (the Groth16 proving key). Under a **subverted setup** — a well-known attack vector for Groth16, which requires a per-circuit trusted setup — the trapdoor `τ` allows the setup authority to: (1) forge proofs without the witness (breaking knowledge soundness), and simultaneously (2) extract the witness from any submitted proof (breaking ZK). A single corrupted setup collapses both terms to `1` simultaneously. The union bound becomes `2·1 + 1 = 3`, which is vacuous.

- **Why it works / fails:** The bound `2·Adv^PRF + Adv^ZK` implicitly treats the CRS as a common random string trusted by all parties. Groth16 does not achieve universal composability under setup compromise. The construction (§4, Theorem 4.1, Remark following Corollary 4.3) does not specify a *setup ceremony* assumption or a fallback under subverted setup. The PLONK alternative cited for `AgentPolicy` / `Delegation` circuits has a universal SRS, but the CRS is still not subversion-resistant without additional structure (e.g., polycommit with independently verifiable randomness).

- **In-threat-model?** **No** — the security proof must either (a) add a formal "honest setup" assumption as an explicit game axiom and note it is not compositionally removable, or (b) switch to a subversion-resistant NIZK (e.g., Groth-Maller 2017, or a transparent setup like STARKs) and re-derive the bound. Omitting this leaves the main theorem meaningful only against adversaries who do not control the setup — which is a significant implicit trust assumption for a deployed system.

---

### Attack 3: HVZK is Insufficient — AS is a Malicious Verifier

- **Attack:** The corollary asserts `Adv^ZK ≤ negl(λ)`. Groth16 as a NIZK is **honest-verifier zero-knowledge** (HVZK): the simulator works because the verifier uses a honestly-generated CRS and does not adaptively choose the statement. However, in the IND-UNL-AS game, the AS is the *verifier* and is *malicious* — it chooses which nonces to include in the challenge, may reuse nonces across game queries, and sees all proofs submitted to it. HVZK guarantees that *transcripts* are simulatable when the verifier is honest. It does not guarantee zero-knowledge against a malicious verifier who can, for example: adaptively choose the statement to be proved after seeing a previous proof, or supply a maliciously generated CRS component as part of the handshake.

  More precisely: the simulation in HVZK produces `(crs, proof)` given only the statement. A malicious AS can check whether the proof it received could plausibly have been produced by a *specific* witness by running an alternative verifier check keyed on the AS's own trapdoor knowledge. This is exactly what **simulation-extractability** (SE) is designed to prevent. Groth16 achieves SE only under the knowledge-of-exponent assumption in the generic group model — a non-standard, non-falsifiable assumption that is not cited anywhere in the construction.

- **Why it works / fails:** The gap between HVZK and malicious-verifier ZK (or SE-NIZK) is real and protocol-specific. For unlinkability under active AS, the construction needs either SE-NIZK or a proof that the specific Groth16 instantiation achieves simulation-extractability under named assumptions. The current proof (§4) writes `Adv^ZK` without specifying HVZK vs. SE-NIZK — a critical omission that leaves the reduction incomplete.

- **In-threat-model?** **No** — Corollary 4.3 must explicitly name the ZK flavor. If HVZK suffices (argue why the AS cannot deviate from the NIZK verification equation), state it. If SE-NIZK is needed, cite the assumption and the specific Groth16 variant (e.g., Groth 2016 + KoE, or Lipmaa et al. 2023 SE-NIZK).

---

### Attack 4: AS-Controlled Nonce Allows Cross-Session Tagging

- **Attack:** The gap list in C2 explicitly flags "nonce freshness" as an unaddressed side channel but does not show it is closed. Suppose session nonces are supplied by the AS (a natural choice — the AS issues a challenge, the agent proves against it). The AS sends `nonce_i` to agent for session `i`. If the AS supplies the *same* nonce `n*` to two different RS-bound requests `r₁` and `r₂` — possibly through two colluding RS instances — and receives proofs `π₁(n*)` and `π₂(n*)`, the AS cannot directly extract the witness. However, if the proof system's public inputs include the nonce in a non-hiding commitment (e.g., `nonce` appears as a plaintext public signal in the Groth16 statement), the AS can construct a distinguishing test: submit `(n*, RS₁)` and `(n*, RS₂)` to the IND-UNL-AS challenger and check whether the returned proofs share any public signal. Under honest construction they should not (because nullifiers differ by scope), but the nonce itself *is* shared — and if the nonce is the only varying public input between two RS calls for the same agent, a statistical test on proof-submission timing against the nonce distribution can de-anonymize with advantage `O(1/|nonce_space|)` per query, which is non-negligible for small nonce spaces.

- **Why it works / fails:** The attack fails if the agent generates the nonce independently and commits to it before receiving the AS challenge (a commit-then-reveal pattern), or if the nonce space is at least 128 bits and AS-supplied nonces are never recycled. Neither constraint is stated in the construction. Definition 4.2 specifies a "7-step token issuance flow" but does not specify nonce generation party or nonce reuse policy.

- **In-threat-model?** **No** — the construction must either (a) specify that nonces are agent-generated with freshness enforced by a monotonic counter or randomness beacon, or (b) include a formal argument that AS-controlled nonces cannot reduce the distinguishing advantage below `negl(λ)`. The current text leaves nonce generation underspecified, making the empirical "colluding AS+RS cannot de-anonymize" claim in C2 unverifiable.


## Persona: cu_ciso

### Attack 1: The Unlinkability-AML Inversion

- **Attack:** The CISO reads §4 and immediately flags it to the BSA officer. The construction's core guarantee — that a "colluding AS+RS cannot de-anonymize" — is *identical* in effect to the threat FinCEN and NCUA examiners spend their careers hunting. If the AS cannot correlate per-agent traffic graphs, neither can my fraud analytics platform. The same nullifier separation that hides member merchant graphs from the AS hides transaction velocity patterns from my OFAC/BSA monitoring stack. The CISO submits a finding: "Vendor's privacy guarantee is structurally incompatible with 31 USC §5318(g) SAR obligations and NCUA Letter to Credit Unions 01-CU-20 (BSA program requirements)."
- **Why it works:** The construction's Theorem 4.1 bound (`Adv ≤ 2·Adv^PRF + Adv^ZK`) and Corollary 4.3 (`Adv_ZK ≤ negl(λ)`) are stated from the AS's perspective as *adversary*. The construction does not distinguish between a malicious AS trying to build a merchant graph and a *compliant* AS running legally mandated transaction monitoring. There is no selective disclosure mechanism described that would let the AS see enough to satisfy BSA while still being blind to the unlinkable pattern.
- **In-threat-model?** No. The construction must address the dual-use problem: how does a regulated AS satisfy SAR/BSA obligations without the "adversarial AS" capability the construction explicitly prevents? A §4.x exception or a compliance-disclosure sub-protocol is required.

---

### Attack 2: Incident Response Black Hole — SOC 2 CC7.2 / NCUA Part 748 Appendix B

- **Attack:** At 2am, the CISO gets paged: an agent credential was used in 47 unauthorized transactions across 6 RS instances. The IR team asks: "Show me the authorization chain." The answer, by construction, is that cross-scope authorizations are *cryptographically unlinkable* — the nullifiers are scoped, the AS issuance log contains no correlatable identifier (that's the point of Corollary 4.3). The CISO cannot produce a timeline for the NCUA examiner. NCUA Part 748 Appendix B ¶III.C requires that institutions "maintain records sufficient to reconstruct significant transactions." The FFIEC CAT Domain 3 (Cybersecurity Controls) requires audit logging that supports forensic investigation. Unlinkability-by-design fails both.
- **Why it works:** The construction's gap-closing narrative (§4, Theorem 4.2) explicitly benchmarks against the baseline's weakness (AS issuance log leaks `client_id`). It solves this by *removing* the correlatable log entry. But removing the log entry that enables de-anonymization also removes the log entry that enables post-incident forensics. The construction offers no recovery mechanism — no escrow, no threshold-reveal, no time-locked linkability. The deployment scenario (§7, PNWCU) quantifies the privacy improvement but is silent on incident reconstruction.
- **In-threat-model?** No. The construction must specify a break-glass linkability path — e.g., a threshold credential reveal triggered by a signed examiner subpoena — or it will fail SOC 2 CC7.2 audit evidence review and NCUA examination.

---

### Attack 3: "Negligible Advantage" Is Not an Examiner-Legible Control

- **Attack:** The CISO forwards Corollary 4.3 to outside counsel and the third-party risk committee. The vendor management policy requires that all cryptographic controls be mapped to a NIST SP 800-53 or FFIEC CAT control with an assessable, evidence-based test procedure. The formal separation — `Adv_baseline = 1/2` vs. `Adv_ZK ≤ negl(λ)`, gap = `1/2 - negl(λ)` — is not a test procedure. The NCUA examiner's IT questionnaire asks: "How do you validate that your access control mechanisms are functioning as intended?" The answer "we have a theorem" fails the question. SOC 2 Type II requires *operating effectiveness* evidence over a period, not a proof-of-concept IND-UNL-AS game instantiation.
- **Why it works:** The construction closes a *formal* gap but leaves the *operational evidence* gap entirely open. There is no specified audit artifact — no log format, no test vector suite, no penetration test methodology — that a SOC 2 auditor or NCUA examiner can use to validate that the deployed system matches the theorem. The empirical test mentioned in the original gap ("empirical test showing colluding AS+RS cannot de-anonymize") does not appear as a runnable artifact in the construction summary.
- **In-threat-model?** No. The construction must produce: (a) a concrete test vector suite tied to the IND-UNL-AS game instantiation, (b) a mapping table from Theorem 4.1/4.2/Corollary 4.3 to NIST 800-53 controls (at minimum AC-2, IA-8, SC-28), and (c) a SOC 2-compatible audit procedure that a Type II auditor can execute against a deployed instance.

---

### Attack 4: Side-Channel Timing Is an Ops Problem, Not a Math Problem

- **Attack:** The gap-to-close statement acknowledges "treatment of side channels (timing, nonce freshness)" but the construction summary is silent on whether §4 addresses timing. The CISO raises this at the vendor risk review: if two RS instances run by the same AS can measure latency differences in proof verification (ZK proof verification time is non-constant for malformed inputs, and on-chain verification has observable gas costs per transaction), the AS can build a probabilistic correlation graph even with `Adv_ZK ≤ negl(λ)`. The FFIEC CAT "Innovative" maturity level for threat intelligence requires that side-channel risk be assessed for new cryptographic deployments. The GLBA Safeguards Rule §314.4(c) requires the institution to assess risks not just from external attack but from operational implementation gaps.
- **Why it works:** `negl(λ)` bounds cryptographic advantage against an algorithm-level adversary. Timing channels operate below the cryptographic abstraction layer. Theorem 4.1's bound (`2·Adv^PRF + Adv^ZK`) makes no statement about the proof-generation or proof-verification *duration* as an observable side channel. The construction's empirical test scope ("colluding AS+RS cannot de-anonymize") is undefined — it is unstated whether the empirical test covers network-level timing correlation. For a credit union running this against a shared AS (e.g., a third-party identity provider serving multiple CUs), the AS operator learns proof-submission timestamps even if it learns nothing about the proof content.
- **In-threat-model?** No. The construction must either (a) specify constant-time verification requirements and benchmark them, or (b) explicitly scope the threat model to exclude network-observable side channels and document that exclusion as a residual risk item in the vendor risk register — something a CISO can sign off on and show an examiner.


## Persona: rfc7662_advocate

---

### Attack 1: The IND-UNL-AS Game Is Straw-Manned — RFC 7662 Per-RS Filtering Already Separates Adversaries

- **Attack:** Theorem 4.2 proves that the AS's own issuance log contains `client_id` and that a trivial deterministic adversary wins IND-UNL-AS with advantage 1/2. But the game is rigged: it places the AS in the adversary role and measures leakage from the *issuer's internal log*. In real OAuth deployments, the RS is the party that aggregates cross-RS behavior — not the AS. RFC 7662 §2.2 explicitly permits the AS to return a *filtered* introspection response per requesting RS, and `draft-ietf-oauth-jwt-introspection-response` (§4.1, "intended_audience") allows the AS to issue a signed JWT tailored so that the RS receives only the claims it is entitled to see. A correctly configured AS can strip all stable subject identifiers from the introspection response served to RS₂ while maintaining them internally. The adversary the construction defeats (AS correlating its own issuance log) is not the adversary that operators care about (RS₁ and RS₂ colluding on the tokens they received).

- **Why it works / fails:** The construction's Corollary 4.3 establishes `Adv_baseline = 1/2` only because it models the adversary as having direct read access to the AS issuance log. If the AS is trusted but curious — exactly the stated threat model in §7 (PNWCU-as-AS) — then the RFC 7662 defender can simply argue: per-RS filtered introspection response + audience-scoped tokens (RFC 8707) already prevents RS₁/RS₂ correlation without any ZK. The construction *does* address the AS-is-adversary case, but needs to explicitly narrow the game to that case and justify why it is the dominant threat. As currently written, the formal separation theorem proves more than it needs to while missing the RS-collusion sub-case.

- **In-threat-model?** Partial. The construction survives the AS-adversary variant but must add explicit treatment of the RS₁+RS₂ collusion adversary as a separate game variant to close the straw-man objection.

---

### Attack 2: RFC 8693 Token Exchange + RFC 8707 Audience Binding Eliminates Stable `client_id` at the RS Layer

- **Attack:** Theorem 4.2's Remark (1) dismisses BBS+ credential presentation but does not address the combined defense of RFC 8693 token exchange *plus* RFC 8707 resource indicators. The flow: agent authenticates to AS once with a primary token; for each RS access the agent calls the AS token exchange endpoint (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`) requesting a new audience-scoped token for that specific RS. The AS can issue per-RS tokens with a *derived* subject — e.g., a per-`(client_id, resource)`-scoped pseudonym using OIDC PPID semantics (RFC 8176 §2). The RS receives a token whose `sub` is unique to that RS; `client_id` need never appear in the token or the introspection response. The AS retains the correlation graph, but the AS is assumed trusted in the non-ZK baseline. Theorem 4.2's deterministic adversary A_base wins only because it reads the AS log — the same trust assumption the ZK construction relaxes.

- **Why it works / fails:** The construction's Corollary 4.3 states "no incremental RFC addition can close it (OAuth §2.3 mandates `client_id`)." But RFC 8693 token exchange requests *are permitted* to omit `client_id` for public clients (RFC 6749 §2.1), and the returned `access_token` need carry only the derived `sub`. The bound `Adv^PRF` in Theorem 4.1 would need to account for this: if the AS issues RS-scoped tokens with fresh PRF-derived subjects, the construction's advantage over baseline shrinks to the ZK-specific property that *even the AS cannot correlate*, which is a strictly stronger claim the construction should state explicitly rather than hiding in the game definition.

- **In-threat-model?** Yes, but only if the construction explicitly states that the AS-cannot-correlate property is load-bearing and that RFC 8693 token exchange with per-RS PPID is insufficient because the AS retains the linkage. That argument exists implicitly in §7 but is not surfaced in the formal theorem statement.

---

### Attack 3: Timing Observations Break IND-UNL-AS Outside the PPT Message Model

- **Attack:** The IND-UNL-AS game is a standard PPT game over message transcripts. ZK proof generation time for the nullifier-per-scope construction is a deterministic function of the circuit's constraint count and the witness (secret key, scope string, nonce). An adversarial AS+RS pair that records `(timestamp_request, timestamp_token_returned)` can use the latency delta as a side channel. If the agent uses a common hardware profile (browser WASM prover, mobile TPM), the proving time distribution has a tight mode. A colluding AS+RS observing that two requests from different nominal identities both exhibit proving-time latency in the 120–180ms band can assign a non-negligible linkability probability *without ever seeing the cryptographic identifiers*. This is entirely outside the construction's formal bound `Adv ≤ 2·Adv^PRF + Adv^ZK`.

- **Why it works / fails:** The construction's gap statement acknowledges "treatment of side channels (timing, nonce freshness)" as open. The formal theorem does not bound side-channel advantage at all — it is a pure algebraic game. RFC 7662 introspection has *no ZK proving step*: its latency is O(database lookup), with variance dominated by network RTT, making timing correlation harder not easier. The ZK construction inadvertently introduces a new correlation vector the baseline does not have. The construction must either (a) argue the timing distribution is sufficiently flat across agents on realistic hardware, or (b) bound timing side channels separately and accept the theorem applies only to the cryptographic component.

- **In-threat-model?** Yes — this is the most concrete empirical gap. Needs a separate side-channel model or a proof that the prover's timing is independent of the agent identity.

---

### Attack 4: Small OAuth Scope Space Makes `Adv^PRF` Non-Negligible, Collapsing the Formal Bound

- **Attack:** Theorem 4.1 states `Adv ≤ 2·Adv^PRF + Adv^ZK` where nullifiers are derived as a PRF over `(scope, agent_secret)`. The PRF security holds when the input space is unguessable. But OAuth scopes are human-readable, enumerable strings defined in AS metadata (RFC 9728 §3, `scopes_supported`). A production AS publishes perhaps 12–40 scope values. An adversary observing a nullifier can enumerate all `(scope_i, candidate_secret_j)` pairs where `candidate_secret_j` comes from a leaked or weak entropy source. More subtly: if the adversary knows two nullifiers `N₁ = PRF(scope_A, k)` and `N₂ = PRF(scope_B, k)` came from the same agent (e.g., from a single RS that received both), it can test all published scope pairs from the AS's `scopes_supported` list against `N₁` and `N₂` to confirm `k` without learning `k` directly. This is a chosen-input PRF distinguishing attack specific to the small scope domain — the `Adv^PRF` term is non-negligible when `|scope_space|` is polynomial in the security parameter rather than exponential.

- **Why it works / fails:** The construction's proof of Theorem 4.1 presumably treats scope as a full-entropy input to the PRF. In practice this assumption fails. The fix is standard: prepend a random per-session salt to the PRF input — `nullifier = PRF(salt || scope, k)` where `salt` is fresh and opaque to the AS. But this change must be reflected in the formal bound with an explicit entropy argument on the scope input, and the prototype must implement it. As written, the bound has a hidden assumption that the scope domain is large, which directly contradicts the deployment scenario in §7 where PNWCU has a fixed, published scope set.

- **In-threat-model?** Yes — this is a gap between the formal model and the deployment instantiation. The construction survives if it adds a salt term and re-states the PRF bound with the domain size assumption made explicit.


## Persona: spiffe_engineer

---

### Attack 1: The Baseline Strawman — You Compared Against Broken OAuth, Not WIMSE

- **Attack:** Theorem 4.2 constructs A_base that trivially wins IND-UNL-AS by reading `client_id` from the AS issuance log. The four remarks then dismiss BBS+, PPID, DPoP, and anonymous credentials as insufficient. But the relevant comparison class is **not RFC 6749 OAuth** — it is the WIMSE Workload Identity Token (WIT) architecture, where the "AS" is a SPIRE server performing node attestation. SPIRE never issues `client_id`. It issues `spiffe://trust-domain/path` SVIDs bound to node attestation selectors. The WIT subject is a SPIFFE ID, not a client registration. OAuth §2.3 mandating `client_id` is simply irrelevant to that stack.

- **Why it works / fails:** Corollary 4.3's formal gap (`Adv_baseline = 1/2` vs `Adv_ZK ≤ negl(λ)`) is only as strong as the baseline it beats. If the baseline is WIMSE+SPIRE rather than vanilla OAuth, A_base cannot compare `client_id` because none exists in the issuance log. The construction would need to re-run the IND-UNL-AS game with a WIMSE adversary that queries the SPIRE workload API, not an OAuth token endpoint. The current proof-of-separation collapses against the right baseline.

- **In-threat-model?** **No.** The construction must either (a) explicitly scope its baseline to RFC 6749 AS implementations and carve out WIMSE/SPIFFE as out-of-scope, or (b) restate Theorem 4.2 against a WIMSE-aware adversary and show the gap persists there. As written, the formal separation proves Bolyra beats something nobody serious deploys for workload-to-workload auth in 2026.

---

### Attack 2: SPIFFE Trust-Domain Federation Already Gives Per-RS Unlinkability Without ZK

- **Attack:** In production SPIFFE deployments, when workload W in `trust-domain-A` calls an RS in `trust-domain-B`, the SPIRE federation bundle exchange gives W a *separate* SVID scoped to domain B. From domain B's perspective, the workload identity is `spiffe://trust-domain-B/federated/agent-class` — not `spiffe://trust-domain-A/workload/W`. If each RS lives in its own trust domain (which is standard SPIFFE segmentation), the AS for domain B's RS never sees the same SVID the AS for domain A's RS sees. The identities are **already distinct at the attestation layer**, with no ZK nullifier required. The cross-credit-union scenario in §7 is exactly this: each CU is a SPIFFE trust domain.

- **Why it works / fails:** The Bolyra IND-UNL-AS game models a single adversarial AS that sees issuance logs across scopes. But SPIFFE federation *architecturally removes* the single AS: there is no global issuance log because each trust domain runs its own SPIRE server. An adversary would need to compromise multiple independent SPIRE servers and correlate their logs — the threat model for that is federation-bundle compromise, not AS-level correlation. The construction's unlinkability claim must specify whether it is stronger than federation-scoped SVID separation, and if so, how.

- **In-threat-model?** **No.** The construction needs a threat scenario where a *single* AS spans multiple RS scopes — which is the OAuth-AS-as-central-broker topology, not the SPIFFE-federation topology. Without specifying the deployment topology precisely, the claim "unlinkable even under adversarial AS" is vacuously true for SPIFFE-federated deployments and redundant for OAuth-brokered ones (where ZK helps). The gap-to-close in C2 should enumerate which topology this applies to.

---

### Attack 3: Network-Layer Side Channels the ZK Layer Cannot Touch

- **Attack:** The construction acknowledges "treatment of side channels (timing, nonce freshness)" as a gap to close, but Theorem 4.1's bound `Adv ≤ 2·Adv^PRF + Adv^ZK` is purely cryptographic — it says nothing about transport. In a SPIRE deployment, the Workload API delivers SVIDs over a Unix domain socket; the SPIRE agent makes outbound mTLS connections to the SPIRE server on a predictable rotation interval (default: cert TTL / 2). An adversary who is the network operator — not the AS — can correlate: (1) which SPIRE agent requested a new SVID bundle, (2) the TLS fingerprint or IP of the workload calling each RS, and (3) timing of ZK proof generation (which is non-trivial: Groth16 proving takes measurable wall-clock time for AgentPolicy). None of this is in the IND-UNL-AS game because the game gives the adversary only the AS issuance log, not the network.

- **Why it works / fails:** The construction's formal model is complete within its declared adversary class (AS with issuance log). But the candidate's own gap list calls out timing and nonce freshness as open. An adversary that is AS+network observer (realistic in a single-cloud deployment where the AS operator also controls the VPC flow logs) can de-anonymize by correlating proof-generation latency spikes with RS access timestamps. This is not addressed by nullifier separation or the PRF bound.

- **In-threat-model?** **Yes, partially — but the construction has not closed it.** The gap-to-close in C2 says "empirical test showing colluding AS+RS cannot de-anonymize" but the summary of the refinement makes no mention of timing channels being addressed. The construction survives the pure cryptographic attack but not the covert-channel attack that a SPIFFE-style infrastructure engineer would actually run in a red-team exercise.

---

### Attack 4: Nonce Freshness Cannot Be Enforced by the Client — SPIRE's Workload API Already Solves This Correctly

- **Attack:** The construction's handshake commits to a `sessionNonce` (CLAUDE.md: "Replaying `(humanProof, agentProof)` without rebinding the nonce fails verification by design"). But nonce freshness requires the AS to issue a fresh challenge *and* the client to use it exactly once. In WIMSE, nonce freshness is enforced by the resource server presenting a `WWW-Authenticate` challenge, and the client's short-lived JWT SVID (TTL: minutes) is its own replay protection — there is no separate nonce ceremony. The Bolyra construction adds a nonce-binding layer *on top of* a ZK proof, which means the nonce must be transmitted to the prover before proof generation. Under an adversarial AS, the AS can issue the *same* nonce to two different RS-bound requests and observe whether the same nullifier is reused — which would break unlinkability if the prover reuses the same credential commitment with the same nonce across sessions. The construction must prove that its nonce-to-nullifier binding prevents this, or show that the IND-UNL-AS adversary cannot issue replayed nonces.

- **Why it works / fails:** If the IND-UNL-AS game correctly models nonce freshness (i.e., the adversary is constrained to issue distinct nonces per session), the construction survives. But the refinement summary tightens Theorem 4.1 with `Adv ≤ 2·Adv^PRF + Adv^ZK` — the PRF term covers nullifier generation, but it is not clear whether a nonce-replay attack by the adversarial AS is within the PRF adversary's capabilities or is a separate attack surface. SPIFFE sidesteps this entirely by using short-lived X.509 SVIDs where the cert serial number is the replay guard.

- **In-threat-model?** **Unclear — the construction must be explicit.** The IND-UNL-AS game needs to specify whether the adversary can issue chosen nonces (chosen-nonce model) or only observe fresh nonces. If the game only models the latter, a chosen-nonce adversarial AS is an unaddressed attack that the formal separation theorem does not cover.
