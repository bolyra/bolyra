# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Auth0 FGA Already Solves the "Predicate Without Revealing Full Scope" Problem

- **Attack:** The construction's core claim is that "no configuration of RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP can match" predicate proof. But this ignores Auth0 Fine-Grained Authorization (FGA), Permit.io, and Google Zanzibar-style systems. In these systems, the RS never receives the full permission set. It sends a check request: `allowed(agent, READ_DATA, resource)?` → gets a boolean. The AS evaluates the predicate server-side and returns only the authorization decision — not the bitmask. This is already in production at scale. The construction's §8 "Gap 0" dismisses RFC 7662 for returning `scope` strings, but FGA-augmented introspection returns *decisions*, not scopes. The construction does not address this architecture at all.

- **Why it works against the construction:** The construction's written claim specifically targets RFC 7662 returning scope strings. It does not engage with the FGA/policy-engine tier that major identity providers already ship. Auth0 FGA, AWS Verified Permissions (Cedar), and Ory Keto all implement the `(subject, action, resource) → bool` predicate evaluation pattern the construction claims only ZK can provide — and they do it in <5ms over TLS, with existing SOC 2 coverage.

- **In-threat-model?** **No** — the construction must address the AS-side predicate evaluation architecture. As written, the claim language ("no configuration of RFC 7662 can match") is falsified by a standard FGA deployment that returns authorization decisions rather than scope lists. The construction must either (a) narrow the claim to "AS-blind, no-roundtrip predicate proof" as its *primary* differentiator, or (b) explicitly explain why FGA introspection is insufficient even when it returns only a boolean. The semi-trusted AS scenario (§3) does implicitly cover this, but it is buried and not the lead claim.

---

### Attack 2: The Semi-Trusted AS Threat Model Is Not an Enterprise Buyer's Problem

- **Attack:** The construction's most defensible scenario is "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." But no enterprise buyer has this threat model. In every Auth0, WorkOS, or Okta deployment, the AS *is* fully trusted — it is the control plane the enterprise paid for and audited. The enterprise's threat model is: *prevent unauthorized agents from accessing the RS even if agent credentials are compromised*. That is solved by short-lived tokens + DPoP + token binding, all of which ship today. The adversarial-AS model described in the construction scenarios is a crypto research problem, not a CU procurement problem.

- **Why it works against the construction:** The construction's §3 threat model formally defines the "SI game" where the AS cannot lie about scope membership. This is a valid cryptographic property. But the construction does not establish *who experiences this threat*. Credit unions (cited in the CLAUDE.md project context) operate under NCUA supervision — their AS is their own IAM system or a regulated vendor. The AS-blind property the construction targets is valuable in *multi-party data markets* and *cross-institutional agent delegation* — not in a single CU's agent-auth flow. As written, the construction proves a hard mathematical property in search of a buyer, rather than identifying a buyer with this specific pain and working backward.

- **In-threat-model?** **No** — construction must add a concrete buyer persona who *actually* distrusts their AS. Examples that would work: (1) a fintech aggregator where the operator AS and the CU RS are separate organizations with no trust relationship, (2) a cross-chain agent that must present credentials to a smart contract verifier that cannot call back to any AS. Without this, the construction's hardest property (AS-blindness) has no buyer.

---

### Attack 3: Proof Latency Is Not a Footnote — It Is a Showstopper

- **Attack:** Bolyra's CLAUDE.md acknowledges that `test:circuits:slow` takes ~2 minutes for full Groth16/PLONK proving. The attack prompt references ~15s per proof. WorkOS issues tokens in <100ms. For any agent that calls a resource server more than once per session — API pagination, batch file operations, multi-step tool chains — Bolyra's per-call proof cost is architecturally incompatible with real usage patterns. The construction's §1 claim language does not bound the proof latency anywhere. A construction that is "theoretically unbreakable but takes 15 seconds" will lose to a "good enough" 80ms JWT in every operator adoption decision.

- **Why it works against the construction:** The construction is a cryptographic claim paper. It does not engage with proof amortization, session-level caching, or batched verification. If the agent generates one proof at session start and the RS accepts it for the session duration (with nonce binding), the latency argument weakens significantly. But this session model is not described in the construction — it would need to be: (a) specify that proofs are generated once per session, not per request; (b) define what "session" means for an autonomous agent running overnight; (c) address proof staleness when permissions change mid-session.

- **In-threat-model?** **No** — the construction must add a latency/amortization section or explicitly scope the claim to "session-token issuance" rather than "per-request authorization." Without this, any operator evaluating Bolyra against WorkOS will reject it on latency grounds before the cryptographic differentiation is even read.

---

### Attack 4: The Onboarding Gap Kills Adoption Before Procurement Does

- **Attack:** Auth0 MCP auth onboarding: add SDK, paste client ID, done. WorkOS MCP auth: same. Bolyra onboarding (from CLAUDE.md): install Node 18+, compile Circom circuits (`npm run compile:circuits` → writes to `circuits/build/`), configure `BOLYRA_RAPIDSNARK` env pointing at a native binary, deploy Solidity verifier contracts to Base Sepolia, and run a subprocess bridge from Python to Node because snarkjs is JS-only. A developer who hits the Python SDK first discovers it "only ships pure-Python types/validation" and "all proving spawns Node @bolyra/sdk." That is a multi-hour integration that requires blockchain access, a compiled binary, and two runtimes. The construction's differentiation claim is irrelevant if the integration burden causes developers to abandon the evaluation within 20 minutes.

- **Why it works against the construction:** The construction document (§1 claim, §8 gap analysis) makes no mention of developer experience or integration path. From a GTM perspective, the buyer-level question is "how do I get from zero to a working agent auth check?" — not "what does the SI game prove?" The construction is evaluated by a crypto-PM reviewing it, but it will be *shipped* by an engineer who has 30 minutes to prototype. The 5-line quickstart experiment (`tier2_004_sdk_designer_five_line_quickstart`) in the autoresearch runs suggests the team knows this gap exists. If that experiment's output is not the *first thing* a developer sees, the cryptographic differentiation is permanently irrelevant.

- **In-threat-model?** **No** — the construction must either (a) add a "deployment model" section showing the zero-to-working-proof path takes fewer steps than Auth0, or (b) explicitly scope the claim to "construction-layer correctness" and acknowledge that productization is a separate work item. Leaving this implicit gives procurement reviewers — and competing PMs — a clean line of attack that cannot be answered with cryptography.


## Persona: cryptographer

I have four attacks. The file write is a separate issue I'll address after the analysis.

---

### Attack 1: Adaptive Predicate Binary-Search — Full Bitmask Reconstruction in 8 Queries

- **Attack:** The construction grants the agent *runtime-adaptive* predicate choice at presentation time. The RS chooses the challenge predicate at query time. A malicious RS issues 8 sequential queries with predicates P₀(x) = (x & 1), P₁(x) = (x >> 1 & 1), …, P₇(x) = (x >> 7 & 1). Each proof leaks exactly 1 bit by the construction's own claim. After 8 proofs under distinct nonces, the RS has reconstructed the full 8-bit bitmask completely — the same information leak as handing over the raw token.

- **Why it works:** The "1-bit leak per proof" invariant is stated per-query, not per-session. The construction's SI game (§3) must be stated as a *single-query* indistinguishability game; if it permits adaptive multi-query interaction under a session key, the adversary wins trivially via exhaustive bit extraction. The gap analysis in §8 compares Bolyra to SD-JWT on a per-disclosure basis — but the correct comparison must hold under *Q* adaptive disclosures where Q ≥ 8. Standard SD-JWT with 8 claim types is no worse in this model; both leak the full set after 8 queries.

- **In-threat-model?** **No.** The construction must either (a) bound the number of distinct predicate queries per credential issuance, (b) use a nullifier that prevents cross-query linkage (but see Attack 3), or (c) formally restrict the SI game to a single-query model and state this as a design limitation. Currently, the §3 SI game definition is not quoted in the candidate summary; if it is single-query, the adaptive attack is out-of-model, but that must be stated explicitly and the practical implications acknowledged.

---

### Attack 2: Groth16 Trusted Setup Compromise — AS-Blind Claim Collapses Under Subverted CRS

- **Attack:** Groth16's knowledge soundness holds under an *honestly-generated* CRS. If the Authorization Server participated in or influenced the circuit-specific trusted setup (per-circuit toxic waste), the AS can forge proofs for *any* witness, including fabricated permission bitmasks. The "adversarial-AS model where AS cannot lie about scope membership" scenario (candidate §2, scenario 2) explicitly positions this as a strength — but it is precisely where Groth16 fails catastrophically.

- **Why it works:** The AS-blind presentation property says the agent presents proofs without an AS roundtrip, and the RS gets cryptographic assurance independent of AS cooperation. But if the AS holds τ (the toxic waste), it can produce a valid Groth16 proof π for the statement "bitmask satisfies predicate P" with *any* bitmask, including one the agent was never issued. The RS cannot distinguish a legitimate proof from a forged one. The construction inherits the PLONK option for AgentPolicy and Delegation circuits (per `CLAUDE.md`) — PLONK uses a universal SRS (no per-circuit trusted setup), which partially mitigates this. But HumanUniqueness uses Groth16 with the Semaphore v4 ceremony. The candidate's construction description does not specify which circuit is used for the permission predicate proof; if it uses a project-specific Groth16 key, the subverted-setup attack applies directly.

- **Why it partially fails:** If the permission predicate is proven via the PLONK-based AgentPolicy circuit, the universal SRS (pot16.ptau) means no single party holds per-circuit toxic waste. But the pot16.ptau phase 1 ceremony itself must be trusted, and the construction must state explicitly that AS participation in the ceremony is excluded.

- **In-threat-model?** **No (partially).** The threat model must state: (a) which proving system is used for the predicate proof, (b) whether the AS participated in any phase of the trusted setup, and (c) what the security guarantee degrades to under AS-controlled ceremony. The current §3 expansion in the candidate addresses SD-JWT and BBS+, but says nothing about setup trust assumptions.

---

### Attack 3: Nullifier Precomputation Over Small Permission Space

- **Attack:** The construction uses an 8-bit cumulative permission space (256 possible bitmasks). The nullifier in a Semaphore-style scheme is typically H(identity_secret, scope_id) or a variant. But if the nullifier is computed over the *permission commitment* in addition to (or instead of) the identity secret — or if the nullifier scheme is H(scope_id, ek) where ek is derived deterministically from the bitmask — then an AS that knows scope_id can enumerate all 256 bitmasks, compute the expected nullifier for each, and link observed nullifiers to specific permission sets. This deanonymizes the agent's exact permissions from the nullifier alone, without breaking the ZK proof.

- **Why it works:** The `CLAUDE.md` construction assigns AgentCredential an EdDSA-signed credential containing a permissions bitmask. If the circuit computes nullifier = H(credential_hash, scope_id) and credential_hash is derived deterministically from (modelHash, operatorKey, permissions, expiry), then an AS with knowledge of (modelHash, operatorKey, expiry) can enumerate all 256 permissions values, compute credential_hash for each, and precompute the full nullifier table. The 1-bit predicate proof becomes irrelevant: the AS identifies the exact bitmask from the nullifier before even reading the proof.

- **Why it partially fails:** If the EdDSA credential uses fresh randomness (a salt/blinding factor) in the credential_hash that is not derivable by the AS, the precomputation attack fails. But the candidate's construction summary does not mention a credential blinding factor. The §8 Gap 0 focuses on SD-JWT/BBS+ information leaks, not on the nullifier leakage channel.

- **In-threat-model?** **No.** The threat model must specify the nullifier derivation function and prove that it does not leak the committed bitmask to a scope_id-knowing adversary. This is a standard pitfall for nullifier schemes over small domains.

---

### Attack 4: HVZK vs. Malicious-Verifier ZK — RS Can Break Zero-Knowledge via Non-Standard Challenges

- **Attack:** The construction's ZK claim (§3, SI game analysis) almost certainly proves *honest-verifier zero-knowledge* (HVZK) — the standard result for Groth16 and PLONK. HVZK assumes the verifier samples challenges honestly. A malicious RS (resource server) can deviate: it selects a biased or correlated challenge (e.g., a challenge derived from a hash of the proof's π_A element) to break simulation. In the non-interactive setting via Fiat-Shamir, HVZK + random oracle gives ZK, but only under the assumption that the verifier uses the same hash function and does not control the input to the hash. If the RS controls the nonce (the sessionNonce in `proveHandshake`), it can choose nonces adversarially to create distinguishing transcripts across multiple proof sessions.

- **Why it works:** The candidate's "AS-blind presentation" model requires that the RS gets cryptographic assurance *independent of AS cooperation*. But the RS is not necessarily honest. The simulation-extractable (SE-NIZK) property is required for proofs that must be ZK against malicious verifiers. Groth16 is not simulation-extractable in general (Fuchsbauer et al., 2018 showed that standard Groth16 is *malleable* — given a valid proof, an adversary can produce a new valid proof for the same or a related statement). If the RS can see multiple proofs from the same agent credential across sessions, malleability could allow transcript correlation that breaks the 1-bit leak claim.

- **Why it partially fails:** The `proveHandshake` API commits each proof to a fresh `sessionNonce`, which bounds replay. But nonce binding prevents *replay*, not *malleability-based correlation*. The construction needs either (a) a simulation-extractable variant (e.g., Groth16 with an additional commitment layer, or Plonky2/Nova with built-in SE), or (b) a formal proof that the SI game does not require malicious-verifier ZK. The candidate's §3 expansion addresses SD-JWT/BBS+ but does not state whether the claimed ZK property is HVZK or malicious-verifier ZK.

- **In-threat-model?** **No.** The §3 SI game must specify the verifier's power (honest vs. malicious). If the RS is modeled as honest-but-curious, HVZK suffices and this attack is out-of-model — but that assumption must be stated explicitly, since the "adversarial-AS model" in the candidate's scenarios suggests an adversarial environment where restricting the RS to honest-but-curious is a significant limitation.

---

**Summary table of open gaps:**

| Attack | Section that must address it | Currently addressed? |
|---|---|---|
| Adaptive predicate binary-search | §3 SI game (query bound) | No |
| Subverted trusted setup | §3 threat model (setup trust) | No |
| Nullifier precomputation over 8-bit space | §5 nullifier derivation | No |
| HVZK vs. malicious-verifier ZK | §3 SI game (verifier model) | No |

---

Regarding the blocked file write: I can't approve filesystem permissions — that requires you to accept the write prompt in your Claude Code session when it appears, or adjust your permission settings. The critique above is the full output; paste it into `differentiation-autoresearch/construction.md` directly if the write prompt doesn't appear.


## Persona: cu_ciso

---

### Attack 1: Regulatory Mapping — The §8 Gap Analysis Answers the Wrong Question

**Attack:** The entire §8 differentiation argument (Gap 0 through the summary table) benchmarks the construction against RFC 7662, SD-JWT, and BBS+ on *information-theoretic* dimensions: proof size, bit leakage, predicate vs. selective disclosure. My NCUA examiner does not carry an information theory textbook. She carries the NCUA Part 748 examination questionnaire and FFIEC CAT. I will ask the vendor: *"Name the Part 748 or FFIEC CAT control this maps to."* The construction has no answer. The §3 threat model defines the "SI game" adversary — a cryptographic abstraction. It does not map to FFIEC CAT Baseline Domain 3 (Identity and Access Management) control statements, nor to NCUA's third-party risk questionnaire under Letter 07-CU-13. An examiner finding that my CU relies on a ZKP-based access control mechanism with no mapped regulatory control family is a Material Finding under Part 748 §1.

**Why it works / why it fails:** The construction's authors are solving a real technical problem but have not performed the regulatory translation layer. The mathematical rigor of §3 and §8 is orthogonal to audit defensibility. This is not a flaw in the cryptography — it is a gap in the compliance narrative that no amount of §8 gap-closing addresses.

**In-threat-model?** No — the construction must address this. Required: a mapping table from each proof property to a specific FFIEC CAT control, NCUA Part 748 subsection, or GLBA Safeguards Rule 16 CFR Part 314.4 requirement. Without it, my board presentation and examiner response are indefensible.

---

### Attack 2: The Hiding Property Destroys the Forensic Record

**Attack:** The construction's headline property — the verifier learns exactly 1 bit (predicate satisfied or not), with the full permission bitmask hidden — is cryptographically elegant and operationally catastrophic for incident response. Scenario: an AI agent acting under a delegated credential performs a transaction that later appears in a member complaint or a BSA/AML review. My BSA officer needs to reconstruct: what permissions did this agent exercise, at what time, in what context? Under GLBA Safeguards Rule 16 CFR §314.4(h) I am required to monitor and test safeguards, which requires logs that establish *what access occurred*. Under NCUA Part 748 Appendix B, incident response requires the ability to determine scope of access. The construction's §3 SI game proves indistinguishability of the hidden bitmask — meaning by design, no log entry can reveal which permission bits were active during the session. The audit trail is a 1-bit record: "access granted."

**Why it works / why it fails:** The construction does not address this tension at all. The §3 threat model treats "hiding the bitmask from the RS" as a pure win. From a CISO perspective, the RS is not the threat — the regulator and the plaintiff's attorney are the threat. I need my RS to *have* the audit record. The "AS-blind presentation" scenario (§8 Gap analysis, adversarial-AS model) makes this worse: if the AS cannot see what the agent claimed, and the RS only receives a 1-bit outcome, the incident forensic chain is broken at both ends.

**In-threat-model?** No — the construction must address this. The authors need to specify a compliant audit channel: either the agent logs a signed, non-repudiable disclosure to a separately-controlled audit ledger at proof time, or the predicate proof must be accompanied by a regulatorily-scoped disclosure to the CU's SIEM that satisfies NCUA Part 748 §3 (audit trail requirements). This is not a minor annex — it is a load-bearing compliance requirement.

---

### Attack 3: Member Secret Custody Under NCUA Part 748 and GLBA

**Attack:** The construction references a Semaphore v4-style HumanUniqueness enrollment where the member holds a secret. I will ask: *"Where does the member secret live, and what is the documented recovery path?"* If the answer is "in the browser," I have a vendor management finding on day one — browser storage does not satisfy NCUA Part 748 Appendix A (guidelines for information security) key management requirements or NIST SP 800-57 key lifecycle controls. If the answer is "the member is solely responsible," I have an unacceptable member-facing SLA failure mode: member loses device, member loses secret, member loses access permanently. My Tier 1 ops team cannot recover it. If the answer is "there is a recovery path via the CU," then the CU holds escrow material that breaks the uniqueness guarantee in §3 — a trusted insider at the CU can synthesize enrollment proofs. The construction does not address key custody at all; the CLAUDE.md notes "Groth16 ceremony reuse" and "Semaphore v4" but nothing about member secret lifecycle.

**Why it works / why it fails:** This is a genuine threat-model gap. The cryptographic construction is sound assuming the secret remains secret. The operational environment of a credit union (call centers, device replacement programs, member-facing recovery flows) makes this assumption structurally false at scale. The §3 threat model defines the adversary as the resource server and the authorization server — not the insider at the CU's identity desk who processes a "lost phone" recovery ticket.

**In-threat-model?** No — the construction must address this. Required: a defined key custody model (HSM, MPC wallet, or hardware-bound key with attestation) with a documented recovery path that satisfies both the uniqueness guarantee and NCUA Part 748 member data protection requirements. This likely requires a separate key management specification section, not a footnote.

---

### Attack 4: On-Chain Registry SLA vs. Core Processor Uptime Requirements

**Attack:** The construction's scenarios reference an "on-chain registry" for verifying agent credentials and human enrollment roots. I will compare this to my core processor SLA. My core processor (FiServ/Jack Henry) contractually guarantees 99.95% uptime, with defined RTO/RPO in my Business Continuity Plan reviewed annually by NCUA examiners. The construction does not specify an SLA for the on-chain registry. Base Sepolia (the deployment target per CLAUDE.md) is a testnet. The production chain (Base mainnet) has had documented L2 sequencer outages. A 1% annual downtime budget on the registry means roughly 87 hours of agent authentication failures per year — during which time no agent can prove scope, all agent-mediated transactions fail, and my members experience service denial. NCUA examiners will ask for this registry in my Business Impact Analysis. I cannot include a blockchain component in my BIA without a defined operator SLA and contractual liability. The GLBA Safeguards Rule §314.4(f) requires me to oversee service providers — who is the service provider for the on-chain registry, and what is their examined security program?

**Why it works / why it fails:** The construction's "constant-size proof regardless of bitmask width" and "AS-blind presentation" properties are moot if the registry is unavailable and no proof can be verified. The construction's §8 gap analysis does not discuss availability, fallback behavior, or degraded-mode operation. RFC 7662 introspection endpoints, by contrast, can be implemented in-house with standard HA infrastructure and are covered by existing FFIEC CAT vendor assessment frameworks.

**In-threat-model?** No — the construction must address this. Required: a defined availability architecture for the registry (including read-replica caching, fallback to last-known-good root, and documented RTO), an identified legal entity responsible for registry uptime with auditable controls, and a degraded-mode specification that allows the CU to continue operating under NCUA Business Continuity Plan requirements when the registry is unreachable.


## Persona: rfc7662_advocate

*(OAuth Working Group veteran, 10 years of production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.)*

---

### Attack 1: Per-RS Filtered Introspection Defeats "Minimal Disclosure to RS"

**Attack:** RFC 7662 §2.2 says the AS "MAY include additional information" and by extension MAY *omit* it. A well-configured AS implements per-RS introspection policy: RS1 (file-reader) sends the opaque token, AS responds `{"scope":"READ_DATA","active":true}` — the full 8-bit bitmask never appears in the wire response. `draft-ietf-oauth-jwt-introspection-response` lets the AS sign that response as a JWT so RS can cache and verify offline, eliminating the live AS round-trip on hot paths. The RS gets exactly the predicate outcome (`active=true`, `scope=READ_DATA`) with nothing else disclosed.

**Why it works / why it fails:** It works for *fixed, pre-registered predicates* — RS1 is enrolled at the AS and the AS knows at policy-table time what scope to filter. It breaks for *runtime-adaptive predicates*: if the agent constructs an arbitrary Boolean function over the bitmask at the moment of use (e.g., "I satisfy FINANCIAL_SMALL OR (READ_DATA AND WRITE_DATA)") without the RS being pre-enrolled with that exact predicate, the AS cannot have pre-populated a policy entry. The construction's §3 must make this runtime-adaptivity requirement explicit and non-trivial, otherwise the claim reduces to "the RS must be pre-enrolled at the AS," which is normal OAuth operation.

**In-threat-model?** **Partially.** The construction survives *only if* runtime-arbitrary predicates (not pre-registered at the AS) are load-bearing. If every predicate the RS might ever request is known at deployment time, filtered introspection matches the claimed property. §8's Gap analysis should add a concrete counter-example where a predicate cannot be pre-registered.

---

### Attack 2: DPoP + PPID Already Breaks Cross-RS Linkability Without ZK

**Attack:** RFC 9449 DPoP provides sender-constraint (token bound to RS-specific proof-of-possession key). RFC 8707 resource indicators bind the token to a specific RS audience. OIDC pairwise pseudonymous identifiers (PPID/sector-scoped `sub`) give each RS a different opaque identifier for the same agent. Combined: RS1 sees `sub=abc123`, RS2 sees `sub=xyz789`, both audience-bound, sender-constrained. Neither RS can correlate the agent across RSes using any token-level data.

**Why it works / why it fails:** The attack correctly eliminates RS-level cross-linkability without ZK. It fails in the *adversarial-AS model*: the AS still knows the real identity behind both PPIDs and holds the correlation. In ZK, the agent presents directly to RS without an AS roundtrip, so the AS *never learns* which RS the agent visited or when. But the construction's written claim (§1, preserved verbatim) is "Agent proves it satisfies a required permission predicate without revealing the full permission set to the resource server." The adversarial-AS model is in the *scenarios* section, not the claim itself. If the AS-side advantage is not in the claim, this attack goes unanswered.

**In-threat-model?** **No — construction must address.** The claim as written does not invoke adversarial-AS. If cross-RS unlinkability *from the AS* is the actual differentiator, it must appear in §1's claim statement, not buried in §3 scenarios. Otherwise DPoP+PPID satisfies the written claim's RS-side property and the ZK advantage is phantom.

---

### Attack 3: Constant-Size Proof Is Already Achieved by Fixed-Scope Tokens

**Attack:** The construction cites "constant-size proof regardless of bitmask width" as a differentiating property (§8 summary table). But for a fixed 8-bit permission space, the AS can issue a token with a `permissions` claim that is a fixed 1-byte field. The JWT is constant-size. The RS checks bit N using a bitwise-AND operation in its policy engine. No ZK required. Even for 64 bits, the JWT `permissions` claim is an 8-byte integer — still constant and smaller than a Groth16 proof (256 bytes). The "constant-size" argument only holds if the construction means the *proof* leaks no information about the *number of set bits*, which is a different (and stronger) claim than size alone.

**Why it works / why it fails:** The attack correctly punctures the naive "constant-size" framing. It fails if the construction means: (a) the proof does not structurally leak the Hamming weight of the permission bitmask (unlike BBS+ where commitment count reveals hidden message count), and (b) the proof size is independent of *how many predicates are simultaneously proved* in a single presentation. The §3 SI game analysis needs to make explicit that the zero-knowledge property covers Hamming weight, not just claim values.

**In-threat-model?** **Yes, construction survives — but the claim must be sharpened.** "Constant-size" should be replaced with "proof structure leaks zero bits about the bitmask Hamming weight or predicate arity." Otherwise, a 64-bit JWT `permissions` field beats ZK on proof size.

---

### Attack 4: SD-JWT + External Range Proof Attachment Closes the "No Predicate" Gap

**Attack:** The construction's §3 ("Gap 0") argues SD-JWT cannot evaluate predicates — only disclose claim values. This is true of SD-JWT *core* (RFC draft-ietf-oauth-selective-disclosure-jwt). But nothing prevents combining SD-JWT with an attached Groth16 range proof or Pedersen commitment over a disclosed claim value. The agent issues: `SD-JWT{ _sd: [hash(permissions_bitmask)] }` plus an attached ZK proof that the committed bitmask satisfies predicate P. The AS-signed SD-JWT anchors the commitment; the attached proof proves the predicate without revealing bitmask contents. This is a hybrid construction already described in academic literature (e.g., CL signatures + Groth16 predicate proofs). The RS verifies the SD-JWT issuer signature + the attached proof — no AS roundtrip.

**Why it works / why it fails:** This hybrid *does* achieve predicate proof with full-bitmask hiding, using the AS as a commitment issuer (not a predicate evaluator). It fails only if the adversarial-AS model is invoked: the AS issued the commitment over the bitmask and therefore *knows* the bitmask. If the AS is trusted to issue commitments correctly, the construction's ZK advantage disappears. The construction's genuine advantage exists only if the agent self-generates the commitment *before* AS issuance and the AS blind-signs it — which is a strong setup assumption not described in the current claim.

**In-threat-model?** **No — construction must address.** §8 Gap 0 explicitly defeats SD-JWT standalone and BBS+ standalone, but does not address SD-JWT + externally-attached ZK predicate proof. This hybrid is the strongest baseline attack. The construction needs either: (a) a formal argument why blind-signed commitments are necessary and the AS cannot know the bitmask pre-issuance, or (b) an updated threat model that scopes to "AS does not see plaintext bitmask at issuance" as a first-class requirement.


## Persona: spiffe_engineer

---

### Attack 1: SPIFFE ZK Attestor Plugin — "Extend, Don't Replace"

- **Attack:** SPIRE ships a plugin interface for both node attestors and workload attestors. Nothing in the SPIFFE spec prohibits a custom workload attestor that, instead of presenting a process UID or Kubernetes pod annotation, generates a Groth16 witness proving the agent's cumulative-bit predicate over a hidden permission bitmask and returns the resulting proof as a structured SVID extension. The SPIRE server validates the proof via an embedded verifier, issues a standard X.509 SVID or JWT-SVID scoped to the proven predicate outcome, and the RS verifies the SVID through the normal SPIFFE Workload API. The entire ZK ceremony happens inside the SPIFFE envelope, not around it. The construction's claim is that no configuration of RFC 7662 + RFC 8693 + RFC 8707 + DPoP can match — but that list conspicuously excludes SPIFFE/SPIRE itself. The claim is scoped against the OAuth baseline, not against attestation-layer protocols.
- **Why it works / why it fails:** The construction's §3 "AS-blind presentation" property is the load-bearing distinction — the agent chooses *at use time* what predicate to prove, and the AS sees nothing. In SPIFFE, the SPIRE server sees the attestation event, defeating AS-blindness. A ZK attestor still requires a roundtrip to SPIRE at SVID issuance. The construction survives if it commits hard to "no SPIRE roundtrip at presentation time," but §3 needs to explicitly name SPIFFE/SPIRE as a baseline system and show why SVID issuance ≠ presentation-time predicate choice.
- **In-threat-model?** No — the construction's Gap analysis in §8 benchmarks against RFC 7662/SD-JWT/BBS+. SPIFFE is unaddressed. Must address.

---

### Attack 2: WIMSE Bound Token + Selective Disclosure — "You're Contributing to the Wrong Draft"

- **Attack:** `draft-ietf-wimse-arch` (WIMSE WG, IETF) explicitly scopes "workload-to-workload" token exchange for AI agents and service meshes. The `wimse-workload-identity-bcp` companion draft permits sender-constrained tokens (DPoP-style key binding) plus a token exchange flow where a workload presents its own credential to obtain a downstream-scoped token. The adversary's argument: WIMSE is actively being designed for exactly the agent-to-resource-server use case in §1. The right move is to write a WIMSE extension that plugs in a ZK proof as one supported `proof_type` in the token exchange, rather than defining a parallel "mutual ZK handshake" protocol. The adversary cites the WIMSE charter's explicit AI-agent scope (added 2025-03) and the fact that the WIMSE working group would accept a `-00` draft for "ZK proof bindings for WIMSE token exchange" today.
- **Why it works / why it fails:** The construction's decisive claim is §8 Gap 0: predicate proof leaks 1 bit vs SD-JWT's K-bit disclosure per query. WIMSE token exchange, as currently drafted, uses JWT or SD-JWT as the exchanged token format — it inherits the same information-theoretic limitation. So the *property* the construction defends is real, but the adversary's point is process/layering, not cryptographic: you're forking where you should be extending. The construction doesn't need to abandon the claim, but it needs to explain why a WIMSE ZK extension wouldn't preserve interoperability while providing the same property — or argue that the WIMSE extension IS the intended deployment path and Bolyra provides the proof system underneath it.
- **In-threat-model?** Partially. The cryptographic claim survives. The "why not contribute to WIMSE" challenge is unanswered and matters for adoption/standards positioning, not for cryptographic correctness.

---

### Attack 3: Narrowly-Scoped SVID Issuance Defeats the "2^64 Permission Space" Scenario

- **Attack:** The construction's §1 scenario: "regulated agent with 2^64 permission space where AS-side policy tables do not scale." SPIRE solves large permission spaces at a different layer: instead of encoding 64-bit bitmasks in a single credential, operators issue role-scoped SVIDs — one SVID per functional role, derived from hierarchical trust domain paths (`spiffe://corp/agent/financial/small`, `spiffe://corp/agent/financial/medium`). The RS enforces RBAC by matching the SVID path against an allow-list. Policy evaluation runs in OPA (Open Policy Agent), which is purpose-built for this and handles millions of evaluations per second with Rego policies. The adversary's claim: the "scalability" argument assumes a monolithic permission token, which is an architecture smell, not a protocol limitation.
- **Why it works / why it fails:** The construction's real differentiator is not scale — it's the *adversarial-AS* scenario in §3 and *runtime-adaptive predicate choice*. Hierarchical SVIDs require the SPIRE server to pre-enumerate roles and issue a SVID for each applicable role. If the agent's permission set is *dynamic* (computed at runtime from a credential issued offline by a third-party operator), SPIRE cannot issue the right SVID without seeing the full permission set — which is exactly what the construction's AS-blind model prohibits. The attack fails on the adversarial-AS scenario, but the construction's §8 currently leads with SD-JWT/BBS+ comparisons rather than making the runtime-adaptive + AS-blind argument the headline. The SPIRE multi-SVID approach needs to be explicitly defeated.
- **In-threat-model?** No — §8 does not address the SPIRE "multiple narrow SVIDs" counter-pattern. Must address.

---

### Attack 4: "Mutual ZK Handshake" Is Just mTLS With Extra Steps

- **Attack:** The construction describes a "mutual ZK handshake" where human and agent both present ZK proofs. SPIFFE's answer to mutual authentication is mTLS with X.509 SVIDs, which provides: (1) workload-to-workload mutual authentication, (2) trust domain isolation via SVID path, (3) certificate rotation every hour via the SPIRE agent without operator intervention, (4) federation across trust domains via SPIFFE Federation bundles. The adversary asks: what does the "mutual ZK handshake" provide that `openssl s_client -cert agent.svid.pem -key agent.svid.key` does not? The X.509 SVID already cryptographically binds the workload's identity to a SPIFFE URI, and mTLS provides mutual proof-of-possession. The ZK layer adds proof-system complexity with no obvious security gain for the mutual authentication property specifically.
- **Why it works / why it fails:** The attack conflates two distinct properties. mTLS with SVIDs proves *workload identity* (this process is `spiffe://corp/service/foo`). The construction's ZK handshake proves a *predicate over hidden attributes* — the RS learns that the agent satisfies `(permissions & REQUIRED_MASK) == REQUIRED_MASK` without learning the full bitmask. An X.509 SVID cannot carry a hidden-attribute predicate proof in its standard extensions without leaking the underlying values in the certificate. The construction survives this attack cleanly, but only if §3 explicitly states: "The mutual handshake property being claimed is predicate binding to a session nonce, not workload authentication — mTLS handles the latter, this construction handles the former." Without that framing, the reviewer reads "mutual handshake" and reaches for SPIFFE.
- **In-threat-model?** Yes — the construction's cryptographic claim survives. However, the framing in §1 invites the conflation. Recommend explicit "out of scope: workload authentication (use SPIFFE)" statement.
