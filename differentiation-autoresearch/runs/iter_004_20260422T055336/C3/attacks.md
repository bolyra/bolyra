# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Latency math kills the AI pipeline thesis

- **Attack:** The construction's flagship use case is a *multi-tool AI pipeline* where every hop in the delegation chain produces a ZK proof. At ~15s per proof (acknowledged in the persona's toolbox context), a 4-hop agentic pipeline (LLM → retrieval tool → write tool → audit log) accumulates **60s of proof latency** before the auditor sees anything. Auth0 issues an access token with scope narrowing via JWT claims in <100ms. WorkOS's MCP auth uses Dynamic Client Registration (RFC 7591) to narrow scopes at registration time — zero per-hop cost. The construction's §2.5 CT-log + §3 PLONK constraints are cryptographically sound but operationally incompatible with streaming tool calls, which are the dominant AI pipeline pattern in 2026.
- **Why it works / why it fails:** The construction addresses proof *correctness* but never addresses proof *scheduling*. It doesn't specify whether proofs are generated synchronously per hop, batched at pipeline end, or deferred to an offline auditor. If proofs are offline (post-hoc), the "no hop exceeded its mandate" guarantee arrives *after* the damage. If proofs are synchronous, the pipeline is unusable. The gap-to-close text ("formal semantics of narrowing proof and in-circuit enforcement") doesn't resolve this.
- **In-threat-model?** No — the construction must address proof generation timing, batching strategy, and whether audit guarantees are real-time or forensic-only.

---

### Attack 2: Procurement is §0 and the construction has no §0

- **Attack:** Credit union enterprise procurement asks three questions before the CISO reads any whitepaper: (1) Do you have SOC 2 Type II? (2) What's your SLA and who do I call at 2am? (3) Are you still a company in 18 months? Auth0, WorkOS, and Stytch answer all three. The construction's §3 (malicious AS argument), Game 1 reduction, and chainNullifier derivation are irrelevant to the vendor questionnaire. Solo-founder ZK protocol is not a procurement category that exists at NCUA-regulated institutions.
- **Why it works / why it fails:** The construction is entirely a cryptographic artifact. It has a gap-to-close section but no go-to-market section, no trust anchor for the verifier beyond the protocol itself, and no institutional backing. The NARROW-FORGE reduction sketch is correct by construction but the actual threat for a credit union CISO is vendor lock-in risk and regulatory audit trail — both of which WorkOS solves with a signed BAA and a compliance dashboard.
- **In-threat-model?** No — the construction must either (a) name a trust anchor institution (CUNA, NCUA, a CUSO) that backs the CT-log registry, or (b) acknowledge this is a developer-facing primitive, not an enterprise auth product.

---

### Attack 3: Client attestation (draft-ietf-oauth-attestation-based-client-auth) already covers the malicious AS case without ZK

- **Attack:** The construction's load-bearing threat in §3 is a compromised Authorization Server. The IETF draft `draft-ietf-oauth-attestation-based-client-auth` (which Auth0 is implementing in 2026) binds client identity to hardware attestation (TPM/TEE), making AS-issued tokens verifiable against device roots of trust — without ZK. Cloudflare Access + remote MCP adds mTLS at the network layer. The construction claims BBS+ collapses under AS compromise, which is correct, but the market answer is **hardware-rooted attestation + short-lived tokens + introspection**, not PLONK constraint enforcement. A buyer comparing the two sees: "attestation = uses my existing PKI and hardware; PLONK = new cryptographic dependency, new trusted setup, new toolchain."
- **Why it works / why it fails:** The construction's §3 argument is valid in the pure-software trust model but doesn't engage with hardware attestation as a competing mitigation. If an enterprise already deploys TPM-backed device auth (which most Fortune 500 and many larger credit unions do via Entra ID or Okta Device Trust), the malicious AS threat is already mitigated without any ZK machinery. The construction needs to state where hardware attestation *fails* that PLONK survives.
- **In-threat-model?** No — the construction must define the hardware attestation boundary and show a concrete scenario where TPM+short-lived-tokens fails but chainNullifier survives.

---

### Attack 4: The two scenarios address incompatible buyers, so neither converts

- **Attack:** Scenario A (multi-tool AI pipeline, enterprise buyer) and Scenario B (journalist/source agent chain, adversarial-government buyer) require opposite product properties. Enterprise AI pipeline buyers (Salesforce, ServiceNow MCP integrations) want uptime SLAs, role-based dashboards, and Okta SSO — they will not accept a cryptographic primitive that requires them to understand Poseidon2 or configure a CT-log SLA. Journalist/whistleblower buyers need *no vendor relationship at all* — a hosted CT-log registry (§2.5) is a liability because the registry operator can be subpoenaed. The construction serves neither: too complex for enterprise, too centralized for adversarial use.
- **Why it works / why it fails:** The gap-to-close says "broaden: chain-of-custody proofs for AI agent pipelines … whistleblower-safe agent delegation." Broadening to two opposed buyer profiles without a wedge market means the ICP (Ideal Customer Profile) is undefined. Auth0's PM playbook: undefined ICP = no sales motion = no pipeline = no company. The construction's cryptographic claim is coherent, but the product claim requires a single buyer type with a single deployment model.
- **In-threat-model?** No — the construction must pick one scenario as the wedge and explicitly stage the second as a future extension with a different deployment topology (e.g., self-hosted CT-log for the adversarial case, hosted + SLA for the enterprise case).


## Persona: cryptographer

---

### Attack 1: Vacuous Monotone-Narrowing — No Partial Order, No Constraint

**Attack:** The core claim is that the circuit enforces "monotonic narrowing" of scopes across hops. But §4 (gap-to-close) explicitly lists "formal semantics of narrowing proof and in-circuit enforcement" as *not yet done*. So what does the circuit actually check? If the constraint is `scope_{i+1} ⊆ scope_i` expressed as a field element inequality on opaque commitments, the prover must expose the scope preimages inside the witness — but then the circuit either (a) hides them from the auditor while the constraint is unchecked, or (b) checks them against a public partial order that leaks structure. Without a formal lattice definition — a computable `leq : ScopeCommitment × ScopeCommitment → {0,1}` with a witness that is hiding and binding — the narrowing predicate is syntactic sugar. An adversarial intermediate node commits `scopeCommitment_i` to an arbitrary value, satisfies the Poseidon binding constraint, and the monotonicity gate is vacuously satisfied because the partial order was never encoded.

**Why it works / why it fails:** The reduction in Game 1 reduces to PLONK knowledge soundness — fine, *if* the constraint polynomials actually encode narrowing. If they don't (because the partial order was left informal), the extractor recovers a valid witness for a *wrong* predicate. The reduction proves the prover knows *something*, not that it knows a narrowing chain.

**In-threat-model?** No. The construction must supply a concrete `ScopeLattice` definition, a Merkle/set-accumulator witness for `scope_{i+1} ⊆ scope_i`, and a proof that this witness is extractable under knowledge soundness. Without it, the monotonicity claim is marketing.

---

### Attack 2: HVZK Breaks Under Malicious Auditor — The Cross-Org Handoff Case

**Attack:** §4 (SE-PLONK ZK fix) explicitly restricts to honest-verifier ZK and punts malicious-auditor unlinkability to a "separate Poseidon-PRF-based unlinkability argument." But the candidate's own Scenario 2 — *journalist/source agent chain where intermediate nodes must stay hidden from auditor* — requires zero-knowledge against a **malicious** auditor who controls the challenge. In HVZK, the simulator can only simulate against uniformly random challenges. A malicious auditor sends a correlated challenge (e.g., reruns the same proof with a tweaked statement) and checks for consistency. This is exactly the standard distinguishing attack on HVZK-only systems. The Poseidon-PRF unlinkability argument is never given a game definition — what is the adversary's advantage? What is the simulator? What oracle queries does it make?

**Formal gap:** Let `A` be a malicious auditor. Define a game: `A` chooses two chains `C_0, C_1`; the challenger proves one; `A` guesses which. Under HVZK, `A` is restricted to sending random challenges — but if `A` is malicious, it sends adaptive challenges. The PRF argument needs to show that even under adaptive challenges, the view is indistinguishable. That requires **simulation-extractability** or at minimum **non-malleable ZK** — neither of which is claimed or reduced.

**In-threat-model?** No. The cross-org handoff scenario places a malicious auditor squarely in scope. The construction either needs to (a) promote to simulation-extractable PLONK (e.g., Lunar, RedShift, or Marlin with simulation-extractability), or (b) formally define the PRF-unlinkability game and provide a reduction. Current text does neither.

---

### Attack 3: chainNullifier Universe Enumeration via Correlated Commitments

**Attack:** `chainNullifier = Poseidon2(seedScopeCommitment, finalScopeCommitment)`, blinded as `Poseidon2(chainNullifier, Σblinding)`. Game 3 claims λ-bit security for `|U|=1`. But consider the AS's view: the AS issues `seedScopeCommitment` (it knows the seed scope by definition — it is the root delegator). If the AS also observes `finalScopeCommitment` at audit time (which is public — it's what the auditor verifies against), then `chainNullifier` is fully determined before blinding. The blinding factor `Σblinding` must then provide the entire security. What is `Σblinding`? The construction does not specify its derivation. If it is derived from public protocol state (e.g., a session identifier the AS can observe), the blinded nullifier is deterministic given AS's view. An AS adversary precomputes `Poseidon2(Poseidon2(seed, final), σ)` for all plausible `σ` from the session transcript.

**Why the |U|=1 proof is insufficient:** Proving λ-bit security for a universe of one agent proves nothing about linkability across sessions. The real attack is cross-session: the AS sees `(blinded_nullifier_1, blinded_nullifier_2)` for the same agent across two audit events, and asks whether they correspond to the same chain. If `Σblinding` is freshly sampled per proof, this is fine — but then the construction needs to specify *who samples it*, *how*, and *whether the prover is bound to use a fresh value*. An in-circuit freshness constraint requires a nonce the verifier can check without learning it — a standard but non-trivial commitment-in-commitment pattern not described anywhere.

**In-threat-model?** Partially. The AS-as-root-delegator knowing `seedScopeCommitment` is explicitly in the threat model (§3). The construction must formally specify `Σblinding` derivation and prove that a malicious AS who knows the seed cannot link blinded nullifiers across sessions.

---

### Attack 4: workloadNonce Deferred Substitution via MMD Window

**Attack:** `workloadNonce = Poseidon2(workloadTimestamp, Poseidon2(delegateeCredCommitment, sessionNonce))`, with timestamp signed by the execution environment and anchored to an immutable log (SLH). Game 4 bounds "deferred substitution." But the CT-log (§2.5) specifies an MMD (Maximum Merge Delay) SLA — meaning a credential submitted at time `T` may not be included in the log until `T + MMD`. During this window, a malicious delegator can:

1. Generate credential at time `T` with `workloadTimestamp = T`.
2. Present the credential to a delegatee who executes at `T + ε`.
3. At `T + MMD - ε`, decide whether to include or withhold the log entry based on observed execution outcomes.

The **equivocation attack**: the delegator retroactively decides which credential was "used" by selectively submitting to the CT-log. The SLH provides inclusion proofs but not *exclusion* proofs — an auditor cannot prove that no other credential with the same `delegateeCredCommitment` was submitted during the MMD window under a different timestamp.

**Game 4 gap:** Game 4 bounds the probability that a substituted workload passes verification, but the bound is only tight if the log is consistent *and complete* by audit time. Completeness during the MMD window is exactly what the CT-log cannot guarantee. The construction needs a **non-equivocation argument**: either require `workloadTimestamp` to be a log sequence number (LSN) from an already-included entry (eliminating the window), or add a signed promise from the log operator that no other entry with the same commitment will be accepted, backed by a transparency mechanism that penalizes equivocation.

**In-threat-model?** No. A malicious delegator in an AI pipeline (Scenario 1) who controls submission timing can exploit the MMD window to retroactively select which tool-call credential appears in the audit trail. The construction's SLH anchor does not close this gap.


## Persona: cu_ciso

---

### Attack 1: The Examiner Literacy Problem — §2.5 CT-Log Mode vs. NCUA Part 748 §748.0(b)

- **Attack:** The construction's core audit claim is that a verifier can confirm monotonic scope-narrowing *without* reconstructing intermediate scopes. But NCUA Part 748 and the FFIEC CAT "Cyber Risk Management and Oversight" domain require that examination-ready evidence be *legible to an examiner* — not just mathematically sound. During a supervisory exam, the examiner hands me a questionnaire that says "provide evidence of access control and delegation scope for Member Data System X." I hand them a PLONK proof and a CT-log inclusion witness. They stare at me. §3's claim that "C3 survives AS compromise" is a theorem, not an audit artifact. The construction nowhere specifies what the *human-readable exam deliverable* looks like — no examiner-facing attestation format, no mapping to NCUA IT examination procedures (NCUA Supervisory Letter 12-01 or equivalent), no SOC 2 Type II control narrative that maps the PLONK constraint to a control objective. The gap-to-close acknowledges the construction "must broaden" — but broadening the cryptographic scope without broadening the compliance surface makes this *harder*, not easier, to defend in an exam room.

- **Why it works:** The construction is silent on the artifact format. A ZK proof is evidence for a mathematician; it is not evidence for an NCUA field examiner. The construction's dual-mode §2.5 (on-chain + CT-log) creates two possible audit paths with no normative guidance on which one satisfies which regulatory instrument.

- **In-threat-model?** No. The construction must add an explicit "Regulatory Artifact" section specifying: (a) what document the institution hands to NCUA, (b) which Part 748 / GLBA Safeguards §314.4 sub-control it satisfies, and (c) how the CT-log's MMD SLA maps to examination timeliness requirements.

---

### Attack 2: The AI Agent Pipeline Has No Data Custodian — Scenario 1 vs. GLBA §314.4(f) Third-Party Oversight

- **Attack:** Scenario 1 ("multi-tool AI pipeline where auditor wants proof no hop exceeded its mandate") maps exactly to an AI agent vendor chain: my CU deploys an AI workflow where Agent A calls Tool B calls API C, each holding a delegated credential. Under GLBA Safeguards Rule §314.4(f), I must oversee *service provider* arrangements and ensure each provider implements appropriate safeguards. In this construction, the intermediate nodes are "hidden from auditor" by design — that is the point of the ZK proof. But §314.4(f) requires me to have *contractual* assurances from each service provider. If I cannot identify intermediate nodes (their identity is part of what the proof hides), I cannot execute vendor due diligence, I cannot include them in my Vendor Risk Register, and I cannot respond to an NCUA examiner asking "who had access to member data at hop 2?" The construction conflates cryptographic unlinkability with regulatory permissibility of unlinkability. These are different things.

- **Why it works:** The construction's "journalist/source agent chain where intermediate nodes must stay hidden" scenario is *exactly the opposite* of GLBA's service provider disclosure requirements. The gap-to-close explicitly wants "whistleblower-safe agent delegation" — but a credit union cannot adopt whistleblower-grade anonymity for *member data pipelines* without violating its GLBA obligations. The construction offers no safe harbor or carve-out distinguishing member-data pipelines from non-member-data pipelines.

- **In-threat-model?** No. The construction must specify a *data classification gate*: ZK-hidden intermediate nodes are only permissible for pipelines that carry no GLBA-covered member information. The current text makes no such restriction and the primary stated use case (credit union identity) is, by definition, GLBA-covered.

---

### Attack 3: The workloadNonce Execution Environment Is Not an Approved Control — §C12 vs. FFIEC CAT Baseline

- **Attack:** §C12 derives `workloadNonce = Poseidon2(workloadTimestamp, Poseidon2(delegateeCredCommitment, sessionNonce))` with the timestamp "signed by the execution environment and anchored to an immutable log SLH." My question: what *is* the execution environment? For an AI agent pipeline, this is a cloud Lambda, a container, a LLM inference API. None of these are FFIEC CAT Baseline-approved signing authorities. The FFIEC CAT Baseline domain "Access and Data Management" requires that time-of-access evidence come from a *system of record* — typically the core processor, the IAM system, or a SIEM. A Poseidon2-hashed timestamp from an LLM API runtime is not a system of record. If an incident occurs and I need to prove to my examiner that delegation hop #3 happened at 14:32:07 UTC and not 14:31:55 UTC (relevant for a fraud timeline), the construction gives me a cryptographic anchor but *no chain of custody back to an authoritative time source*. The SLH is append-only, but who controls the SLH? If it's the AI vendor, I have a single point of trust that is also a vendor.

- **Why it works:** The construction's Game 4 bounds deferred substitution attacks *cryptographically* but does not address the *operational provenance* of the timestamp itself. An attacker who controls the execution environment can feed a false timestamp at proof generation time; the PLONK constraint enforces internal consistency but cannot enforce fidelity to wall-clock time from a NCUA-acceptable time source.

- **In-threat-model?** Partial. Game 4 addresses substitution between valid proofs but not timestamp injection at the source. The construction must specify: the execution environment's time source must be an NTP-synchronized HSM or equivalent, and the SLH operator must be the institution or a SOC 2 Type II-certified custodian — not the AI tool vendor.

---

### Attack 4: Incident Response Leaves Me Holding a Proof I Cannot Open — §3 Survival Claim vs. NCUA 12 CFR §748.1(b) Incident Reporting

- **Attack:** NCUA 12 CFR §748.1(b) requires that I notify NCUA of a reportable cyber incident and, in follow-up, provide a *root cause analysis*. The construction's design goal is that the auditor *cannot* reconstruct intermediate scopes or participants — that is the privacy guarantee. But post-incident, my root cause analysis requires exactly that reconstruction: which agent held which scope, which hop introduced the over-privileged credential, which intermediate delegator was compromised. The construction in §3 correctly argues PLONK survives AS compromise — but surviving AS compromise means I *cannot identify the compromised AS* through the audit record. I know *that* the chain was valid when sealed; I do not know *which node went rogue afterward*. I am reporting to NCUA with evidence that says "the system worked correctly at delegation time" while my members' data was exfiltrated by a rogue intermediate agent. The ZK proof becomes my adversary in the incident postmortem.

- **Why it works:** The construction treats audit-time verification and incident-time forensics as the same problem. They are not. The privacy properties that make the construction useful for ongoing compliance are directly hostile to post-incident reconstruction. The gap-to-close's ambition to support "cross-org agent handoff" makes this worse — cross-org handoffs multiply the number of entities I cannot identify after the fact.

- **In-threat-model?** No. The construction must define a *break-glass mechanism*: a threshold-decryption or escrow path that allows the institution (but not the auditor during routine examination) to reconstruct intermediate scopes under a documented incident response procedure, with the break-glass itself logged and included in the NCUA incident report. Without this, the privacy guarantee and the regulatory incident-reporting obligation are in direct conflict.


## Persona: rfc7662_advocate

---

### Attack 1: AS-Attested Monotonic Narrowing via RFC 8693 — Circuit Enforcement Is Not Load-Bearing

- **Attack:** RFC 8693 §2.1 requires the AS to validate that each token-exchange request does not expand scope beyond the subject token. The AS therefore *already enforces* monotonic narrowing at issuance time. Combine this with a signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response §4) that carries a `narrowing_chain_digest` claim—a hash over the ordered sequence of `scope` values the AS recorded during exchange—and the auditor receives a cryptographic attestation of the narrowing property without ever seeing intermediate scopes. The AS is removed from the hot path for verification; the signed JWT is the proof artifact. Section §3 of the construction asserts "RFC 8693 + JWT introspection collapses under AS compromise," but the ZK construction itself requires a trusted party to bind `seedScopeCommitment` to a real identity credential. That party is isomorphic to the AS. The trust root is identical; the construction's "AS-side advantage" argument is circular unless it can name a property the circuit enforces that the AS *cannot* enforce by policy.

- **Why it works / fails:** It works unless the construction can demonstrate a scenario where the AS is simultaneously (a) trusted enough to anchor `seedScopeCommitment` and (b) untrusted enough that its signed narrowing attestation is worthless. §3 gestures at "constraint-level enforcement (C3) survives AS compromise" but does not show what a compromised AS *actually gains* against an auditor holding a PLONK proof—it still needs the AS's initial commitment to be valid. If the AS is corrupt, `seedScopeCommitment` is corrupt, and the entire narrowing proof proves nothing meaningful.

- **In-threat-model?** No — construction must address this directly. The "malicious AS" argument in §3 needs a concrete distinguishing attack, not an assertion.

---

### Attack 2: HVZK Restriction Collapses the Journalist/Whistleblower Scenario

- **Attack:** The construction explicitly retreats to honest-verifier ZK (§4, Game 2) and handles malicious auditors via a "separate Poseidon-PRF-based unlinkability argument." In the journalist/source scenario (Candidate scenario 2), the auditor is explicitly *adversarial*—a state actor, opposing counsel, or regulatory body that will deviate from the prescribed verification transcript. HVZK provides zero protection here. An adversarial verifier chooses challenges adaptively and can use the prover's responses to extract information about intermediate nodes. The Poseidon-PRF unlinkability argument is a separate, informal claim that is not integrated into the soundness game—it is not a simulation-based argument and does not compose with the NARROW-FORGE reduction. Contrast: RFC 9449 DPoP + pairwise subject identifiers (OIDC PPID) provide a deployment-proven, formally analyzed protection against cross-RS linkability for honest-but-curious auditors, with no restriction to honest verifiers, because the privacy property is structural (the RS never receives a linkable identifier), not proof-based.

- **Why it works / fails:** The construction's gap-to-close explicitly lists "whistleblower-safe agent delegation" as a target use case. Restricting to HVZK means the construction does *not* achieve this target for adversarial auditors. Game 3's |U|=1 security argument compounds this: when the journalist is the sole user of a delegation chain, the population size is one, and the chainNullifier reveals exactly which chain is being audited regardless of blinding, because the blinding term Σblinding appears in a public input and an adversary can simply enumerate the single population member.

- **In-threat-model?** Yes — this is an unaddressed gap. The construction must either (a) upgrade to simulation-extractable ZK (SE-PLONK or Groth16 with simulation extractability) for the whistleblower case, or (b) explicitly scope the construction to exclude adversarial auditors and remove the journalist scenario from the claim.

---

### Attack 3: chainNullifier Does Not Encode Intermediate Hops — Tree Topology Leaks

- **Attack:** `chainNullifier = Poseidon2(seedScopeCommitment, finalScopeCommitment)`. This is a two-input function of only the *endpoints* of the delegation chain. It contains no encoding of intermediate commitments, chain length, or participant count. An auditor who observes a set of nullifiers sharing the same `seedScopeCommitment` (which is a public input in the PLONK statement, per §3) can enumerate distinct `finalScopeCommitment` values and thereby learn the *branching structure* of the delegation tree—how many distinct terminal delegations originated from a single root mandate. In an AI agent pipeline (Candidate scenario 1), this reveals how many tool calls a root agent spawned, which is operationally sensitive. Furthermore, the blinding `Poseidon2(chainNullifier, Σblinding)` does not help if `Σblinding` is derived deterministically from public inputs—an adversary can recompute it. The construction does not specify the distribution or derivation of Σblinding in a way that would prevent this.

- **Why it works / fails:** RFC 8707 resource indicators + audience-bound tokens already prevent cross-RS scope correlation at the RS level. The ZK construction is supposed to provide *stronger* privacy, but the nullifier design leaks tree topology that RFC 8707 does not. This is a property the construction claims to have (§1: "without reconstructing intermediate scopes or participants") but the nullifier scheme only hides intermediate scopes, not the count or branching factor of the chain.

- **In-threat-model?** Yes — partial. The construction survives on scope content privacy but fails on structural/topological privacy. Section §3's C3 constraint claim does not address tree topology leakage. This needs either (a) a per-hop nullifier with a Merkle/accumulator structure that hides depth and branching, or (b) an explicit acknowledgment that topological leakage is out of scope.

---

### Attack 4: workloadNonce Timestamp Signing Does Not Anchor Execution Order — Replay Across Pipelines

- **Attack:** `workloadNonce = Poseidon2(workloadTimestamp, Poseidon2(delegateeCredCommitment, sessionNonce))`. The timestamp is "signed by the execution environment and anchored to an immutable log SLH" (§3, Game 4). But the SLH anchor provides *existence* proofs, not *ordering* proofs between concurrent delegations in the same pipeline. Two tool calls in a multi-hop AI pipeline that execute within the same SLH MMD window (which is typically minutes to hours) can have interchangeable `workloadTimestamp` values from the auditor's perspective—the SLH inclusion proof does not establish which came first. An adversary controlling one node in the pipeline can present a valid PLONK proof with a reordered delegation chain that still passes monotonic narrowing checks, because the narrowing constraint is on scope content (`finalScope ⊆ seedScope`), not on temporal ordering of hops. RFC 8693 token exchange, by contrast, records each exchange event as a distinct AS log entry with a server-side timestamp that is non-replayable and totally ordered by the AS's clock—a property the SLH-based construction does not provide unless the SLH is a single-writer append-only log with strict sequencing guarantees, which §2.5 does not specify.

- **Why it works / fails:** Game 4's "deferred substitution" bound addresses substituting a *later* workload for an *earlier* one, but does not address reordering attacks within the MMD window. For the AI agent pipeline scenario, execution order is semantically meaningful (tool B may depend on tool A's output), and an auditor who cannot verify order cannot verify correct delegation flow. The construction must either (a) require the SLH to be a strict total-order log (single-writer, no concurrent appends), or (b) derive `workloadNonce` from a chain of prior nonces (i.e., `workloadNonce_i = Poseidon2(workloadNonce_{i-1}, ...)`) so that ordering is enforced in-circuit.

- **In-threat-model?** Yes — construction must address this for the AI pipeline scenario to be credible. The current §3/Game 4 language treats this as an existence-anchoring problem but the actual threat is ordering, which is a distinct and harder property.


## Persona: spiffe_engineer

---

### Attack 1: The ZK Attestor Plugin You Never Wrote

- **Attack:** SPIRE's attestor plugin architecture is exactly the extension point for "execution-environment-anchored identity." C12's `workloadNonce = Poseidon2(workloadTimestamp, Poseidon2(delegateeCredCommitment, sessionNonce))` is doing what SPIRE node attestation already does — binding a workload's claim to a signed execution-environment fact (TPM, k8s token, AWS IID). A ZK attestor plugin takes that same signed fact, runs it through a Poseidon-based circuit, and issues a standard X.509 SVID whose SAN encodes the scope commitment. The delegation-chain narrowing proof becomes a SVID path check. The entire §3 threat model (A_AS compromise) is avoided because SPIRE's Workload API never hands the raw credential to the AS — it's issued on-demand to the local agent socket. Where is the construction's justification that this plugin doesn't exist, or that it can't be written, or that it produces weaker guarantees?

- **Why it works / why it fails:** The construction's Game 4 (deferred substitution bound) requires that `workloadTimestamp` be anchored to an *immutable* log SLH. SPIRE does not currently chain its node attestation receipts to an append-only log — a compromised SPIRE agent can back-date or replay attestation. So the attack partially fails: the SLH anchor is genuinely new. But §2.5's CT-log alternative and the SPIRE plugin are complementary, not competing — the construction should explain why it doesn't sit *inside* SPIRE rather than beside it.

- **In-threat-model?** Partially. The SLH anchor is in-scope and the construction survives that sub-claim. The plugin composition argument is **not addressed** — the construction must justify why this is a new protocol rather than a SPIRE plugin + CT-log sidecar.

---

### Attack 2: WIMSE Already Has Delegation Scope in Charter

- **Attack:** WIMSE draft-ietf-wimse-arch §5.3 ("Context Propagation") explicitly covers multi-hop workload token exchange where each hop attaches a `wsc` (workload security context) claim. The `gap_to_close` field names "chain-of-custody proofs for AI agent pipelines where each hop is a tool call" — that is verbatim WIMSE's design target. The selective-disclosure gap the construction is solving (auditor sees monotonic narrowing without learning intermediate scopes) is a natural extension of the WIMSE `wsc` claim: add a `zk_delegation_proof` extension claim carrying a PLONK proof blob, standardize the verifier interface, contribute to the WIMSE WG. Why is a new protocol needed instead of a two-page WIMSE extension draft?

- **Why it works / why it fails:** The construction's §3 explicitly argues that RFC 8693 (OAuth token exchange, which WIMSE builds on) collapses under A_AS compromise because the AS sees intermediate scopes in plaintext. That argument is sound — WIMSE's current charter does not require the authorization server to be excluded from scope visibility. The `chainNullifier` binding across the full chain is not expressible in a WIMSE `wsc` claim without the circuit. So the cryptographic core survives. But the construction never acknowledges WIMSE, which is a standards-process failure: an IETF reviewer will ask this question and the answer needs to be in §1.

- **In-threat-model?** Yes — the construction survives cryptographically. But the **positioning gap is not addressed**: the paper must contain an explicit "why not WIMSE extension" paragraph or it will be rejected at the WG level before the crypto is ever reviewed.

---

### Attack 3: Monotonic Narrowing Is Already SPIFFE Path Semantics

- **Attack:** `chainNullifier = Poseidon2(seedScopeCommitment, finalScopeCommitment)` is supposed to prove that each hop narrowed scope. But SPIFFE ID path hierarchy *is* monotonic narrowing: `spiffe://trust-domain/pipeline/stage1` is a strictly narrower identity than `spiffe://trust-domain/pipeline`, and SVID issuance enforces this — a child workload cannot request an SVID with a path shorter than its registered entry. The auditor check becomes: did the SVID chain from root to leaf always extend the path? That's a PKI chain verification, not a ZK proof. The construction's "formal semantics of narrowing" (named in `gap_to_close` as still missing) needs to show that path-extension semantics are *insufficient* — that there exists a narrowing predicate expressible in circuit that cannot be encoded in a URI path. Without that, the construction is a cryptographic solution to a naming problem.

- **Why it works / why it fails:** The attack holds for scope structures that are *lattice-ordered but not path-encodable* — e.g., a scope that is the intersection of two independent permission sets. A tool call that narrows `{read:*, write:logs}` to `{read:metrics, write:logs}` cannot be expressed as a SPIFFE path extension. The circuit's constraint that `finalScope ⊆ intermediateScope ⊆ seedScope` for arbitrary lattice scopes is genuinely not expressible in SPIFFE path semantics. The attack fails on the lattice-scope case. But the construction never defines what the scope lattice *is* — §3 uses "narrowing" informally. Without formal lattice semantics the circuit's `⊆` constraint is underspecified and the narrowing claim is unverifiable.

- **In-threat-model?** No — **this is a gap the construction must address.** The formal semantics of the narrowing predicate are explicitly named as missing in `gap_to_close` and the SPIFFE path attack shows exactly why informal narrowing is insufficient. The construction must define the scope lattice, prove the in-circuit `⊆` check is complete with respect to it, and show a counterexample where path semantics fail.

---

### Attack 4: The Journalist Scenario Breaks SPIFFE Federation by Design — But Federation Handles It

- **Attack:** The whistleblower scenario requires that "intermediate nodes must stay hidden from auditor." SPIFFE trust-domain federation already provides this: intermediate hops can live in a *private* trust domain (`spiffe://internal.source/`) that federates only a single endpoint (`spiffe://auditor.org/verifier`). The auditor sees: (a) the origin SVID from the journalist's trust domain, (b) the terminal SVID in the auditor's trust domain, and (c) the federation bundle proof. Intermediate SVIDs from `internal.source` are never presented to the auditor — only the federation handshake endpoint is exposed. The ZK proof of hidden intermediate nodes is unnecessary because federation trust-domain opacity already provides the property. The construction must show a scenario where a private SPIFFE trust domain is *not* available (e.g., the intermediate is a third-party SaaS that cannot run SPIRE), and argue that that scenario is the common case in AI agent pipelines.

- **Why it works / why it fails:** The attack fails when the intermediate is a stateless, third-party tool call (an LLM API, a data retrieval service) that cannot issue SVIDs and cannot run a SPIRE agent. This is precisely the AI pipeline case: `GPT-4o` cannot be a SPIFFE workload. In that regime, the ZK delegation proof is the only mechanism to prove that the tool call stayed within its mandate without exposing the mandate to the auditor or requiring the tool to participate in the identity infrastructure. The attack succeeds for *org-boundary* intermediate nodes (which could run SPIRE) but fails for *stateless-third-party* intermediate nodes. The construction should partition these cases explicitly — the claim in §1 that the construction applies to "cross-org agent handoff" conflates the two.

- **In-threat-model?** Partially. The stateless-third-party case is in-model and the construction survives. The org-boundary case is **not addressed** — the construction should concede that SPIFFE federation is preferred when both endpoints can run SPIRE, and scope its claims to the stateless-intermediate regime.
