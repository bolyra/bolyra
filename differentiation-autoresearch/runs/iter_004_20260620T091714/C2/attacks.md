# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The blindingSalt Creates a New Secret Management Crisis

- **Attack:** The construction closes the gap by adding `blindingSalt` — "generated once at provisioning, stored locally, never transmitted." The adversary flags this in procurement: *you just gave every operator a new secret to protect, with no key rotation story, no HSM integration, and no recovery path.* If the salt leaks, cross-scope linkability is fully restored. If the salt is lost, the agent's identity is irrecoverable — you can't regenerate the same nullifiers. Auth0 and WorkOS handle key lifecycle (rotation, revocation, HSM-backed storage) as table stakes. Bolyra is offloading that complexity to the operator with zero tooling.

- **Why it works / fails:** The construction's threat model treats `blindingSalt` as a solved premise ("stored locally, never transmitted"). It says nothing about: what "locally" means in a containerized agent fleet, whether salts survive pod restarts, how rotation works when `operatorPrivKey` is rotated, or what the recovery ceremony looks like. These aren't cryptographic questions — they're operational questions that kill enterprise deals before the proof system is even evaluated.

- **In-threat-model?** **No.** The IND-UNL-AS-DL game assumes `salt_i` is safely held. Real deployments violate this assumption routinely. Construction must address salt lifecycle: generation, storage, rotation, and disaster recovery — or the unlinkability guarantee is purely theoretical.

---

### Attack 2: Cross-Scope Unlinkability Contradicts the Buyer's Actual Compliance Posture

- **Attack:** The adversary reframes the feature as a liability. Credit unions (scenario 1) operate under BSA/AML, NCUA examination, and SAR filing obligations — they are *legally required* to link member activity across their product surface. A member agent that "must not" let the CU see a merchant graph is a **compliance red flag**, not a feature. For healthcare (scenario 2), HIPAA audit trail requirements mean the covered entity must be able to reconstruct the referral network on demand for OCR investigations. The adversary says: "You're selling privacy against the issuer. The issuer is your enterprise customer. You're pitching them a product that protects their users from *them.*"

- **Why it works / fails:** The construction's scenarios are plausible for consumer-facing privacy tools, but for regulated enterprise buyers (CUs, health systems) the AS/RS *is* the regulated entity with disclosure obligations. Unlinkability from the AS is the opposite of what the compliance team wants. Auth0 and WorkOS sell *auditability* as a feature — full event logs, SIEM integrations, compliance reports. Bolyra's strongest cryptographic property actively undermines the enterprise compliance sale.

- **In-threat-model?** **No.** The construction assumes unlinkability is universally desirable. It must scope its buyer personas to cases where the AS is genuinely adversarial to the user (B2C privacy-first contexts), and explicitly disclaim that regulated-entity operators may be prohibited from deploying unlinkability against themselves.

---

### Attack 3: 16,450 Constraints × Per-Scope × Per-Call = Unusable Agent Loops

- **Attack:** The adversary pulls up their agent telemetry. MCP tool calls in production agent loops complete in 200–800ms end-to-end. WorkOS M2M tokens: under 100ms, cached, no per-call computation. The construction now sits at 16,450 constraints after the `blindingSalt` addition. Even with rapidsnark, that's 8–15 seconds of proving time on consumer hardware, longer on cloud-native agent runtimes without GPU. Cross-scope unlinkability means a *fresh proof per scope per session* — an agent hitting five different RS instances in one task runs five sequential proof generations. The adversary asks: "What LangChain or CrewAI operator accepts a 60-second authentication overhead per multi-step task?"

- **Why it works / fails:** The construction correctly notes it stays under `pot16.ptau` capacity (constraint budget), but capacity is not latency. The cost section accounts for "+500 constraints" without benchmarking the real-world p50/p99 prove time in the target deployment environment (cloud VM without specialized hardware). There is no proof-caching story — caching by `(scopeId, sessionNonce)` would break unlinkability if nonces are reused, and fresh nonces require fresh proofs.

- **In-threat-model?** **No.** The construction treats performance as an implementation detail. The adversary correctly identifies it as a first-order adoption blocker. The construction needs either: (a) a proof-batching design that amortizes cost across scopes, (b) a delegated proving architecture where the operator pre-generates proofs on provisioning, or (c) explicit latency benchmarks proving the p99 fits inside agent orchestrator timeout budgets.

---

### Attack 4: The Formal Security Definition Is Unverifiable by Any Enterprise Security Team

- **Attack:** The adversary escalates to CISO review. The construction introduces the "IND-UNL-AS-DL variant" — a bespoke security game defined in the construction itself, with a reduction argument authored by the same party making the security claim. There is no external citation (no ePrint, no academic publication, no IETF RFC). Enterprise security teams at the credit union level run procurement through vendor security questionnaires (VSQs), require SOC 2 Type II, and for cryptographic primitives, require FIPS 140-2 validation or at minimum published peer-reviewed proofs. Auth0 can point to RFC 6749, RFC 9068, OIDC Core 1.0. Cloudflare Access can point to their published architecture reviews. The adversary says: "Your security claim is a circom file and a markdown reduction. My CISO will not approve that."

- **Why it works / fails:** The IND-UNL-AS-DL game may be technically sound — the two-layer PRF argument is plausible. But soundness is not the same as verifiability by a non-cryptographer procurement team. The construction has no path from "we wrote a security game" to "an enterprise security team can validate our claim" without either (a) external academic peer review or (b) a third-party cryptographic audit with a published report. The `blindingSalt` reduction from DL-BJJ hardness is particularly novel — novel claims require novel scrutiny.

- **In-threat-model?** **No.** The construction's threat model is purely cryptographic. Enterprise adoption requires institutional trust signals that cryptographic correctness alone cannot provide. The construction must identify which third-party audit firm will review the IND-UNL-AS-DL reduction, and when, before any enterprise procurement conversation can succeed.


## Persona: cryptographer

Stance: *Unless I see a threat model, a game definition, and a reduction sketch, it's marketing.* The blindingSalt change is progress, but the construction still has at least three unaddressed holes and one model gap that invalidates the reduction outright.

---

### Attack 1: Static `blindingSalt` as a Long-Term Correlation Handle

- **Attack:** The construction states `blindingSalt` is "generated once at provisioning, stored locally, never transmitted." This makes `blindedCredSecret = Poseidon2(operatorPrivateKey, blindingSalt)` a **fixed, lifetime constant** for the agent. A colluding `(AS_A, AS_B)` pair does not need to invert Poseidon2. Instead, they observe auxiliary credential metadata that is necessarily stable: (a) the credential epoch/version number embedded in the proof statement, (b) the certificate chain anchor (operatorPubKey is public), (c) provisioning timestamps, or (d) any credential-level revocation list entry. Because `blindedCredSecret` never rotates, any one leaked auxiliary attribute that is correlated at both scopes suffices to link the agent cross-scope — without ever touching the nullifier.

- **Why it (partially) fails against the construction:** The nullifier values themselves are scope-separated (`Poseidon2(scopeId, bcs)` differs per scope). The adversary cannot directly derive one nullifier from another.

- **Why it survives:** The construction's IND-UNL-AS-DL game only models the adversary learning private keys. It does **not** model auxiliary leakage from the credential object that is static for the agent's lifetime. The "two-layer PRF argument" holds only when the adversary's view is limited to the nullifier stream. Any out-of-band stable attribute (credential serial, epoch, pubkey fingerprint) breaks unlinkability entirely without touching DL-BJJ. This is a gap in the threat model, not the primitives. **Verdict: not in threat model — construction must address.**

---

### Attack 2: Undefined Simulator → Hand-Waving ZK Claim

- **Attack:** The construction asserts zero-knowledge but does not produce a simulator. Without one, there is no ZK claim. Specifically: what does the Groth16 prover reveal about `(operatorPrivateKey, blindingSalt)` to a malicious verifier (= adversarial AS)? Groth16 is known to be honest-verifier zero-knowledge (HVZK) but is **not** simulation-extractable in the standard model (Groth16 proofs are malleable; a simulator for an actively malicious verifier requires additional structure). An adversarial AS can issue adaptive challenges — e.g., presenting a manipulated `scopeId` to probe whether two agents share the same `blindedCredSecret` by checking whether the returned proof is consistent with a precomputed witness table.

- **Why it (partially) fails:** The Fiat-Shamir transformation in Groth16 binds the proof to the public inputs, so simple replay is caught.

- **Why it doesn't go away:** Without a formal simulator and a proof that the simulator runs in PPT, the ZK property is unproven. The construction needs to specify: HVZK only? Malicious-verifier ZK? Simulation-extractable? Each has a different bar and a different implication for what the adversarial AS learns. The cross-scope unlinkability reduction *depends on* ZK (the proof leaks nothing about the witness); without a simulator proof, that dependency is ungrounded. **Verdict: not in threat model — construction must address.**

---

### Attack 3: AS-Controlled `scopeId` Enables Differential Nullifier Analysis

- **Attack:** The construction does not specify who controls `scopeId` assignment, or whether the AS can assign distinct `scopeId` values *per interaction* rather than per RS endpoint. An adversarial AS that controls scope assignment can: (1) assign `scopeId_α` to agent X on request R₁, record the returned nullifier `N_α = Poseidon2(scopeId_α, bcs_X)`; (2) replay the same agent on request R₂ with a subtly different `scopeId_β = scopeId_α ⊕ 1`, get `N_β`; (3) test whether `N_α` and `N_β` can be jointly inverted to recover `bcs_X`. While Poseidon2 collision resistance blocks step (3) directly, the AS can instead mount a **dictionary attack**: for all enrolled agents `i`, precompute `Poseidon2(scopeId_α, bcs_i)` using provisioning-time data. The construction claims "even with DL-BJJ break, salt_i keeps bcs_i pseudorandom" — but this holds only if the AS does not know `blindingSalt`. If `blindingSalt` is derived deterministically from any provisioning artifact visible to the AS (enrollment timestamp, credential serial number, any AS-observable field), the pseudorandomness argument collapses entirely.

- **Why it fails against the construction (conditionally):** If `blindingSalt` is generated by a local CSPRNG at provisioning time and stored exclusively client-side with no AS-observable derivation, precomputation is blocked.

- **Why it requires more work:** The construction does not specify the `blindingSalt` generation procedure, its derivation path, or the storage threat model. A single sentence asserting "stored locally" does not constitute a security argument. The reduction sketch must include a formal assumption on the source of `blindingSalt` entropy and a bound on what the AS observes at provisioning. **Verdict: not in threat model — construction must formally specify the salt generation oracle and its privacy assumptions.**

---

### Attack 4: Subverted Groth16 Setup Breaks Soundness, Not Just Unlinkability

- **Attack:** The construction uses Groth16 with a project-specific trusted setup (`pot16.ptau`). The updated threat model introduces "IND-UNL-AS-DL variant where adversary has the private keys but still can't link." But this threat model is orthogonal to setup subversion. Under a subverted Groth16 CRS (Common Reference String), **soundness breaks entirely**: a setup adversary can forge arbitrary proofs — including proofs for false statements (e.g., claiming a non-enrolled agent is enrolled, or binding a nullifier to a credential it does not hold). The construction's claim survives DL-BJJ break at the `blindingSalt` layer, but it says nothing about what happens when the extractor in the Groth16 knowledge soundness argument fails — which it does under a subverted setup. The `pot16.ptau` ceremony trust assumption is never stated as a formal hardness assumption in the construction.

- **Why it (partially) fails:** The CLAUDE.md notes that `HumanUniqueness` reuses the public Semaphore v4 ceremony, providing social/audit trust. The project-specific keys for `AgentPolicy`/`Delegation` use `pot16.ptau` as a universal SRS.

- **Why it remains open:** The construction adds a soundness argument for the DL layer but removes no trust from the Groth16 setup. The correct framing is: the security of the entire construction reduces to **both** (a) Poseidon2-PRF security (addressed by the salt change) **and** (b) the Groth16 CRS being honestly generated. Neither assumption is stated as a named hardness assumption with a parameter. If the goal is "construction survives a total DL break," it must also address "construction fails under a setup compromise" — and specify whether PLONK (used for `AgentPolicy`) provides a stronger guarantee here via its universal SRS model. The current construction conflates these two independent trust axes. **Verdict: partially in threat model — construction should state the setup trust assumption explicitly and explain why PLONK's universal SRS is or is not preferred for the cross-scope unlinkability property specifically.**


## Persona: cu\_ciso

### Attack 1: blindingSalt Is a Key — Who's the Custodian?

- **Attack:** The construction states `blindingSalt` is "generated once at provisioning, stored locally, never transmitted." From a NCUA Part 748 / GLBA Safeguards Rule perspective, this *is* a cryptographic key material artifact tied to member identity. I need to ask: stored locally *where*? Browser `localStorage`? Device TPM? A wallet? The construction doesn't say. If it lives in a browser, GLBA § 314.4(c)(2) requires me to demonstrate "access controls consistent with the sensitivity of the information" — and browser storage doesn't pass a Safeguards Rule exam. My vendor management policy requires I inventory all locations where member-identifying secrets reside. This construction introduces a new secret (the salt) with no documented custody chain.

- **Why it works / fails:** The construction closes the DL-BJJ correlation attack but opens a *key custody gap*. If the salt is silently generated and stored in-browser, a device compromise exfiltrates it. An adversary with `blindingSalt` and any one `scopeNullifier` can re-derive `blindedCredSecret = Poseidon2(operatorPrivateKey, blindingSalt)` *if* they also compromise `operatorPrivateKey` — which collapses the two-layer PRF reduction back to a single-factor break. The construction's "survives DL-BJJ break" claim only holds when the salt is independently protected.

- **In-threat-model?** No — the construction specifies the nullifier derivation formula but is silent on salt custody, backup, and rotation. A lost salt means the member's identity is unrecoverable (no nullifier re-derivation = no proof). An examiner will ask for the key management procedure. There isn't one here.

---

### Attack 2: Unlinkability Directly Conflicts With BSA/AML Audit Requirements

- **Attack:** The entire value proposition of IND-UNL-AS is that a colluding AS+RS *cannot* de-anonymize member agent traffic across scopes. I'm citing FFIEC BSA/AML Examination Manual and FinCEN's 31 U.S.C. § 5318(g) SAR obligations. If my member's AI agent transacts across five merchant RS instances and I detect a suspicious pattern, I need to file a SAR that *links* those transactions to a single member. But if cross-scope nullifiers are cryptographically unlinkable — even to me, the AS — I cannot construct that linkage. I cannot produce the member activity graph my BSA officer needs. The construction's strongest security property is my biggest compliance liability.

- **Why it works / fails:** The construction doesn't distinguish between *third-party* unlinkability (good: the merchant RS can't profile the member) and *operator* unlinkability (potentially illegal: the CU itself can't link member activity for AML purposes). The IND-UNL-AS game treats the AS as fully adversarial. But I *am* the AS — and I have regulatory obligations that require me to be able to link member behavior under subpoena or SAR filing obligations. The construction offers no "audit backdoor" that satisfies regulatory disclosure while preserving unlinkability to outsiders.

- **In-threat-model?** No — the construction addresses cryptographic adversaries, not the CU's own legal disclosure obligations. This is a fundamental design gap for any financial institution deploying this as the AS. The construction must either (a) define a compliant audit layer where the CU retains a mapping table outside the ZK construction, or (b) explicitly scope unlinkability to non-operator third parties only and document what the AS is *allowed* to retain.

---

### Attack 3: Incident Response Forensics Are Impossible by Design

- **Attack:** Member calls at 2am claiming their AI agent made unauthorized purchases across three RS instances (a mortgage servicer, a retail platform, a healthcare portal). My Tier 1 ops team needs to: (1) identify what the agent did, (2) correlate across RS instances, (3) freeze further activity, (4) produce a forensic timeline for the incident report required under NCUA Part 748 Appendix B § III.C. Unlinkable nullifiers mean Step 2 is cryptographically impossible. My ops team cannot hand an examiner a coherent incident timeline because the construction *intentionally* makes cross-scope correlation infeasible.

- **Why it works / fails:** NCUA Part 748 Appendix B requires a written incident response program with "identification and analysis" capabilities. The FFIEC CAT Intermediate domain "Cyber Incident Management and Resilience" specifically requires forensic capability. This construction's security guarantee and incident response forensics are in direct opposition. The construction mentions "empirical test showing colluding AS+RS cannot de-anonymize" as a goal — but from an ops standpoint, that's exactly the capability I need during an incident.

- **In-threat-model?** No — the construction's scenarios (§ "cross-credit-union member agent") treat the CU as a *threat* to member privacy, not as a regulated entity with mandatory forensic obligations. The construction must define a recoverable audit path that the CU can activate under documented incident response procedures, without breaking unlinkability for normal operation.

---

### Attack 4: On-Chain Proof Submission Is a Public Timing Oracle

- **Attack:** The construction adds +500 constraints and places nullifier verification on-chain (Base Sepolia, with a future mainnet path). Every `proveHandshake` call that hits the on-chain registry is a public transaction with a block timestamp, gas price, and originating address. An adversarial AS doesn't need to break Poseidon2 — it watches the mempool. If the same operator submits proofs to `scope_A` and `scope_B` within the same block window using the same originating address or relayer, the *submission metadata* creates a linkage graph that the nullifier separation was designed to prevent. The construction mentions "treatment of side channels (timing, nonce freshness)" as a known gap — but doesn't close it.

- **Why it works / fails:** The gap is acknowledged in the candidate's own text: "Needs ... treatment of side channels (timing, nonce freshness)." The blinded nullifier is unlinkable at the *cryptographic* layer, but the transport and submission layer leaks correlation. A MEV searcher or a well-resourced AS with mempool access can cluster proof submissions by temporal proximity, gas patterns, and relayer identity. This is a well-understood attack on on-chain ZK systems (see Tornado Cash traffic analysis literature). The construction's SLA claim is also unaddressed: if the on-chain registry has the same 1% outage budget as Base Sepolia's historical availability, that's ~87 hours/year of member-facing downtime — more than my core processor's SLA allows under NCUA examination.

- **In-threat-model?** No — the construction closes the cryptographic correlation attack but leaves the metadata correlation attack open. For a CU operating under FFIEC CAT "External Dependency Management," I need my vendor (Bolyra) to demonstrate that the full submission stack — not just the ZK circuit — provides the claimed unlinkability. A SOC 2 Type II report on the relayer infrastructure would be the minimum bar before I'd consider this production-ready.


## Persona: rfc7662_advocate

---

### Attack 1: PPID + RFC 8707 Already Achieves the Claimed Property at the RS Layer

- **Attack:** Section claiming "unlinkable authorizations even under adversarial AS" conflates two distinct sub-properties: (a) *RS-to-RS linkability*, and (b) *AS-side traffic graph construction*. RFC 7662 with OIDC Pairwise Pseudonymous Identifiers (PPID) already eliminates (a): each RS receives a different `sub` value computed as `HMAC(RS_sector_id, user_internal_id)`. Combine with RFC 8707 `resource` indicators — each token is audience-bound to exactly one RS and introspection response is policy-filtered per RS. No RS can link sessions across other RSes. Claim (b) is where the AS is adversarial — but then the AS *issued* the tokens and the PPID mapping table *lives at the AS*. The construction also requires a provisioning step where some authority mints `operatorPrivateKey`. If that authority is the AS (or the AS has the provisioning transcript), the AS can compute `Poseidon2(operatorPrivateKey, blindingSalt)` the moment it learns `blindingSalt` — which it can demand at provisioning.
- **Why it works / fails against the construction:** This attack **partially** holds. The construction survives the RS-layer sub-claim (ZK nullifiers are cryptographically distinct per scope, not just policy-filtered). It **does not** yet survive the provisioning-oracle variant: the construction states `blindingSalt` is "generated once at provisioning, stored locally, never transmitted" but provides no formal guarantee about *who* runs the provisioning ceremony or whether the AS is excluded. If the operator self-generates `blindingSalt` without AS involvement, the claim holds. If any ceremony touches AS infrastructure, the AS has the lookup.
- **In-threat-model?** Partial. RS-layer unlinkability claim **survives**. Provisioning-oracle sub-attack is **not addressed** — construction must specify whether `blindingSalt` generation is fully offline/self-sovereign.

---

### Attack 2: JWT Introspection Response Removes AS from Hot Path — Why Is the AS-Side Advantage Load-Bearing?

- **Attack:** `draft-ietf-oauth-jwt-introspection-response` (which the construction does not cite) issues *signed JWT responses* to RSes. Once the RS caches a signed introspection response, the AS is entirely out of the verification loop — no per-request AS call, no AS-observable traffic graph at request time. Combined with short-lived audience-bound tokens (RFC 8707), the AS's view of the agent's access pattern is limited to token-issuance events, not access events. The construction's threat model targets "adversarial AS that tries to correlate per-agent traffic graphs" — but with JWT introspection caching, the AS's graph is coarse-grained (one entry per token, not per request). The construction must show that coarse-grained issuance-time correlation is still dangerous enough to require ZK.
- **Why it works / fails against the construction:** This attack **narrows the construction's claimed advantage** without fully breaking it. The construction's nullifiers are scope-separated at the *circuit level* — even issuance-time, the AS never sees which scopeId the agent will use, because the circuit proof is generated client-side and the AS verifies only the Groth16 proof output, not the preimages. JWT introspection still requires the AS to issue a token with a `sub` claim that is scope-correlated. The ZK construction genuinely hides the scope during issuance. However, the construction does not explicitly argue this distinction.
- **In-threat-model?** Yes — construction **survives**, but must add a paragraph explaining why issuance-time scope hiding matters and why JWT introspection caching doesn't close this specific gap.

---

### Attack 3: The IND-UNL-AS-DL Game Conflates Key Compromise with Local Storage Compromise

- **Attack:** The new "IND-UNL-AS-DL variant" claims the construction survives a total discrete-log break on BabyJubJub. The argument: adversary learns `operatorPrivateKey` from the public key, but still cannot compute `scopeNullifier` without `blindingSalt`. This is correct *if* `blindingSalt` remains secret. But the threat scenario that warrants a DL-hardness reduction is one where the adversary has significant cryptanalytic capability — government-level compute, quantum adversary, or supply-chain compromise of the BabyJubJub implementation. Any adversary with the resources to break DL-BJJ almost certainly has access to the device that stores `blindingSalt` (HSM compromise, endpoint exfiltration, memory scraping). The reduction treats key compromise and local storage as independent — this is not a valid independence assumption in the threat scenarios where DL breaks are realistic. RFC 9449 DPoP at least binds to an ephemeral keypair per request, limiting blast radius: a DPoP key compromise reveals one session, not all future sessions.
- **Why it works / fails against the construction:** This attack **holds as a gap**. The construction's two-layer PRF argument is mathematically correct in the abstract model but the independence assumption between `operatorPrivateKey` exfiltration and `blindingSalt` exfiltration is not argued. DPoP's blast-radius advantage under key compromise is also not addressed.
- **In-threat-model?** No — construction **must address** the dependency between key compromise and salt compromise scenarios, or scope the IND-UNL-AS-DL game to exclude full device compromise explicitly.

---

### Attack 4: Timing and Nonce Freshness Channels Are Unaddressed — DPoP Already Has a Better Story Here

- **Attack:** The construction's own gap analysis explicitly lists "side channels (timing, nonce freshness)" as unresolved. RFC 9449 DPoP requires a `nonce` issued by the RS (server-provided nonce, Section 8 of RFC 9449) with strict replay detection and freshness windows. An adversarial AS observing proof submission timestamps can build a traffic graph *without* breaking any cryptographic primitive — scope-separated nullifiers are cryptographically unlinkable, but the *timing pattern* of proof submissions to the Groth16 verifier endpoint is not. If agent A always submits proofs to RS-1 at T and RS-2 at T+Δ, an AS that logs proof submission times (not contents) can correlate across scopes. The construction achieves *cryptographic* unlinkability but claims protection against "adversarial AS that tries to correlate per-agent traffic graphs" — a traffic graph can be built from metadata alone. DPoP's nonce mechanism, combined with batch token issuance (pre-issued tokens for a session window), can at least offer timing obfuscation at lower engineering cost.
- **Why it works / fails against the construction:** This attack **holds as an unaddressed gap** — the construction itself flags it. The blinding salt change (Constraint 9) addresses cryptographic linkability only. A metadata-only adversary remains unaddressed.
- **In-threat-model?** No — the construction's own stated threat model includes timing, and the blinding salt iteration does not close it. Must either formally scope out timing attacks or add a protocol-level mitigation (e.g., proof batching, fixed submission cadence, or mixing).


## Persona: spiffe_engineer

---

### Attack 1: Why Not a SPIFFE ZK Node Attestor?

**Attack:** The SPIFFE node attestation plugin API is an open extension point. A ZK attestor plugin delivering `(proof, scopeNullifier)` to SPIRE would give you pseudonymous workload attestation inside the existing Workload API — without a new wire protocol, a new DID method, or a new trust anchor. The cross-scope unlinkability claim maps directly onto SPIRE's "different SVIDs per audience" design: each audience-scoped SVID already uses a fresh keypair, giving you independent public identifiers per RS. Where, precisely, does the construction add something a `AttestorPlugin + per-audience ephemeral SVID TTL=1h` cannot do?

**Why it works / fails:** The construction has no explicit treatment of this comparison. Its unlinkability is ZK-native, so it does handle the case where the attested identity itself must never appear in cleartext — short-lived SVIDs still carry a resolvable `spiffe://trust-domain/path` identifier that the RS sees, and the AS sees which path was requested. The construction's nullifier reveals nothing about the underlying `operatorPrivateKey`. That is a genuine gap in the SVID model.

**In-threat-model?** Partially. The construction survives if the threat is "AS sees the SVID URI and correlates it to a specific workload across RS calls." It **does not address** why a ZK attestor plugin inside SPIRE wasn't the chosen architecture — the gap is a missing section, not a cryptographic failure. **Construction must address the architectural choice.**

---

### Attack 2: `blindingSalt` Is the New Private Key — Local Storage Destroys the Argument

**Attack:** The construction claims the two-layer PRF survives a total DL-BJJ break because `blindingSalt` is "generated once at provisioning, stored locally, never transmitted." But in a workload threat model, a compromised workload process can read its own secret material. If an attacker compromises the workload and exfiltrates `blindingSalt` alongside `operatorPrivateKey`, they can recompute `blindedCredSecret = Poseidon2(operatorPrivateKey, blindingSalt)` and then enumerate `Poseidon2(scopeId_i, blindedCredSecret)` for any candidate scope set. The colluding AS holds a log of observed nullifiers per RS. Matching these is now $O(|S|)$ offline. The "survives DL-BJJ break" claim reduces to "survives simultaneous exfiltration of both secrets" — which is the same claim as before the change, just with two secrets instead of one.

**Specific construction cite:** Constraint 9 — `blindedCredSecret = Poseidon2(operatorPrivateKey, blindingSalt)`. The security argument says "even with DL-BJJ break, `salt_i` keeps `bcs_i` pseudorandom." That is true under DL break alone, but the construction never specifies the storage threat model for `blindingSalt`. Is it in a TPM? An env var? A file? SPIFFE's Workload API deliberately avoids persisting secrets on-disk exactly because workload compromise is the primary threat.

**In-threat-model?** **No — construction must address.** Either bound the `blindingSalt` to a hardware root (TPM/HSM attestation, which is exactly what SPIRE does via TPM attestation plugins), or acknowledge that workload-compromise unlinkability is not achieved. The IND-UNL-AS-DL game variant listed as a gap is the right formalism here, but it must include an adversary that reads local storage.

---

### Attack 3: AS-as-Adversary Conflicts with AS-as-Issuer in the Same Trust Model

**Attack:** The claim reads "adversarial AS that tries to correlate per-agent traffic graphs." But the construction requires the AS to issue the credential that binds `operatorPrivateKey` to the agent identity. If the AS is adversarial, it chose `operatorPrivateKey` or observed it during issuance. In the cross-credit-union scenario, "CU-as-AS must not see member merchant graph" — but the CU-AS issued the credential embedding the agent's scope permissions. The construction must define whether the adversarial AS is the *same* AS that issued the credential or a *different* one. WIMSE draft-ietf-wimse-arch separates the Workload Identity Provider (WIP) from the Authorization Server — the WIP can be blind to downstream RS interactions. The construction conflates these roles.

**In-threat-model?** **No — construction must address.** If the issuing AS is adversarial, the `operatorPrivateKey` was either chosen by the AS or witnessed during provisioning, and blind-salting after the fact does not help (the AS can brute-force `blindingSalt` given `bcs = Poseidon2(privKey, salt)` if it knows `privKey`). If only non-issuing ASes are adversarial, that must be stated explicitly as a trust assumption, and the threat model should cite WIMSE's WIP/AS separation as the structural analogy.

---

### Attack 4: `scopeId` Namespace Collision Under Colluding AS+RS

**Attack:** The nullifier is `Poseidon2(scopeId, blindedCredSecret)`. The construction does not specify who mints `scopeId`, how it is globally disambiguated, or what prevents two colluding resource servers from registering identical `scopeId` values. In SPIFFE, global uniqueness is enforced structurally: `spiffe://trust-domain/workload-path` is URI-addressed and the trust domain is anchored to a SPIRE root CA. Here, if an AS+RS pair manufactures a `scopeId` that collides with a legitimate RS's `scopeId`, the resulting nullifier is identical — the colluding pair can now detect that the same `blindedCredSecret` was used against both, reconstructing the cross-scope link the construction is designed to prevent. This is not a cryptographic break; it is a protocol governance gap that the cryptography cannot close.

**In-threat-model?** **No — construction must address.** The fix is straightforward (a registry, a domain-separated scope URI scheme, or AS-signed scope tokens), but none of this is present. The healthcare cross-provider scenario is particularly vulnerable: two provider ASes could coordinate scope ID values to detect shared agent sessions.
