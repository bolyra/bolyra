# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: RAR + JWT Introspection Already Covers Selective Disclosure

- **Attack:** The candidate's core claim — "agent proves it satisfies a required permission predicate without revealing the full permission set to the RS" — is already addressed by the RFC 7662 stack the candidate says it beats. Specifically: RFC 9396 (Rich Authorization Requests) lets the RS request a structured authorization_details object scoped to its resource. The AS evaluates the operator's policy server-side and issues a JWT introspection response (draft-ietf-oauth-jwt-introspection-response) containing only the scopes relevant to that RS. The RS verifies offline. The AS does not return the full permission set. The agent does not reveal capabilities beyond what the RS requested. This is exactly what Auth0 and WorkOS ship today.

- **Why it works / why it fails against the construction:** The construction's claimed gap ("AS-blind presentation — no AS roundtrip, agent chooses what to disclose at moment of use") is the only property RAR cannot match, but that property is not cited in any of the construction's three scenario descriptions. The two scenarios given are (1) 2^64 permission space, (2) semi-trusted AS. Scenario 1 does not require AS-blind presentation — it requires scalable policy evaluation, which is an AS-side performance problem that structured JWTs with indexed bitmasks already handle. Scenario 2 is the only live scenario. The construction needs to make this explicit.

- **In-threat-model?** No — construction must address. The candidate's claim needs a concrete property that RAR + offline JWT introspection fundamentally cannot express. The only survivor is the adversarial-AS game. Everything else is already shipped by incumbents.

---

### Attack 2: The nullifierSecret Fix Introduces an Unacknowledged Key Management Burden

- **Attack:** The fix adds a private input `nullifierSecret` that is "prover-held, never shared." From an enterprise procurement standpoint: where does this secret live? The construction does not say. If it lives in agent memory, it's ephemeral and replay detection breaks across restarts. If it requires a persistent secrets store (HSM, secure enclave, KMS), you've added an infrastructure dependency that WorkOS does not impose. If it's derived from the credential commitment deterministically, an adversarial AS who learns the derivation function recovers it. The gap the fix closes (adversarial AS computing the nullifier) is real, but the fix's operational model is unspecified — which means procurement will ask "how do I rotate this?" and the answer isn't in the construction.

- **Why it works / why it fails against the construction:** The cryptographic fix is sound under Poseidon PRF assumption (A2). But the operational attack surface is new. Auth0/WorkOS have session secret management, rotation APIs, and revocation flows that are production-hardened. The construction now carries a key management problem that didn't exist before the fix. The SSZK game wins; the enterprise security review does not.

- **In-threat-model?** No — construction must address. Key lifecycle (generation, storage, rotation, recovery on agent crash) for `nullifierSecret` needs at least a one-paragraph specification. Without it, the fix is incomplete for any enterprise buyer.

---

### Attack 3: The 2^64 Permission Space Scenario is a Non-Market Scenario

- **Attack:** The first scenario claims "regulated agent with 2^64 permission space where AS-side policy tables do not scale." No production system has 2^64 distinct permissions. HIPAA has ~18 data categories. PCI-DSS has ~12 control domains. The most granular enterprise RBAC systems (AWS IAM, GCP IAM) define permissions as strings enumerated at compile time — they don't use bitmask arithmetic over 64-bit fields. The scenario is cryptographically interesting but buyer-irrelevant. An Auth0 PM presenting to a credit union prospect will say: "They're solving a problem you don't have. We cover your 20 permission types in a scope string."

- **Why it works / why it fails against the construction:** The construction's actual differentiator (adversarial-AS model) is buried behind a scenario that sounds like a toy. The 8-bit cumulative bit encoding documented in `CLAUDE.md` (permissions 0–7, `READ_DATA` through `ACCESS_PII`) is the real use case — and it fits comfortably in a JWT scope claim. The 2^64 framing undermines credibility with buyers who will notice it doesn't apply to them.

- **In-threat-model?** No — construction must address. Drop the 2^64 framing or replace it with a concrete regulated-agent scenario (e.g., an AI treasury agent at a credit union holding simultaneous `FINANCIAL_SMALL` + `READ_DATA` credentials where the RS must not learn which higher permissions exist). This is the actual scenario and it maps directly to the Bolyra permission model.

---

### Attack 4: Proof Latency Kills the "Runtime-Adaptive Predicate" Property

- **Attack:** The construction's gap-to-close mentions "runtime-adaptive predicate over permissions (not fixed at issuance)." This is the most interesting property — the agent evaluates a predicate at the moment of use, not at issuance. But proving time is ~15s (stated in the persona's toolbox as a known cost). If the predicate is evaluated at runtime, the agent must generate a proof at runtime. A 15s latency on each resource server call is not a tradeoff any MCP operator will accept. WorkOS issues tokens in <100ms; Cloudflare Access + remote MCP adds ~5ms at the edge. The runtime-adaptive property only survives if proofs are pre-generated — but pre-generation collapses runtime-adaptive into fixed-at-issuance, which is exactly what JWTs do.

- **Why it works / why it fails against the construction:** The construction can survive this if it specifies that agents pre-prove over a bounded session window (e.g., prove once per session nonce, cache proof for session duration). The `sessionNonce` binding in `Poseidon3(credentialCommitment, sessionNonce, nullifierSecret)` already anchors the proof to a session, suggesting per-session rather than per-call proving. If that's the intended model, the "runtime-adaptive" framing is misleading and should be replaced with "session-scoped, AS-blind scope presentation." That's still a genuine property incumbents can't match, and it's honest about the latency tradeoff.

- **In-threat-model?** Yes — but the construction must be explicit that proving is per-session, not per-call. Otherwise this is a fatal latency objection that no credit union IT department will hand-wave away.


## Persona: cryptographer

---

### Attack 1: Credential Commitment Linkability — The Nullifier Fix Does Not Close the Session-Correlation Leak

**Attack:**
The updated nullifier is `Poseidon3(credentialCommitment, sessionNonce, nullifierSecret)`. The SSZK fix correctly hides the nullifier value from the AS. However, examine what the RS sees as *public inputs* to the Groth16 proof: to satisfy the selective scope predicate, the circuit must commit the agent's credential in some public way so the RS can anchor the claim. If `credentialCommitment` itself appears as a public input (or any deterministic function of it does — e.g., a scope-anchored root), the RS observes the same value across all sessions from the same agent, independent of `sessionNonce`. The RS can trivially build a cross-session dossier: agent A visited RS at T₁, T₂, T₃ using `credentialCommitment = X`.

**Why it works / why it fails:**
The construction (as described) moves the nullifier secret inside the Poseidon call but does not specify whether `credentialCommitment` is a public or private input to the circuit. In Semaphore v4-style constructions, the analogue (`identityCommitment`) is always kept private; what's public is the `merkleRoot`. If Bolyra's circuit follows the same discipline — making `credentialCommitment` private and publishing only a Merkle root over the enrolled commitment set — this attack is mitigated. But the current write-up (`gap_to_close`) does not state this invariant, and the SSZK game definition (A2) must enumerate which circuit public inputs the RS sees. Without that statement, unlinkability is unproven.

**In-threat-model?** No — construction must explicitly state the public input set and prove RS-side unlinkability via a separate game (e.g., an anonymity game where the RS receives two sessions and cannot distinguish which credential produced each nullifier beyond the public root).

---

### Attack 2: Honest-Verifier ZK Is Not Enough — The RS Is A Potentially Malicious Verifier

**Attack:**
Groth16 achieves honest-verifier zero-knowledge (HVZK) under the generic group model. The RS in the adversarial-AS scenario is presented as a "semi-trusted" party. But the construction's stated threat model (`"RS needs cryptographic assurance independent of AS cooperation"`) does not say the RS itself is honest. A malicious RS can:

1. Choose challenges (`sessionNonce`) in a biased or structured way — not uniformly — if it generates them.
2. Issue multiple selective challenges over the same agent (knowing `credentialCommitment` is enrolled) and use proof transcripts to extract information about the private permission bitmask via adaptive chosen-challenge attacks.

HVZK only guarantees simulation by an ideal simulator that sees the statement and is given the randomness of an *honest* verifier. Against a malicious verifier, you need malicious-verifier ZK (MVZK) or, stronger, simulation-extractability (SE-ZK). Groth16 is not SE-ZK without auxiliary random oracle assumptions (cf. Fuchsbauer-Kiltz-Loss 2018). If the RS is adaptive, HVZK proofs can leak.

**Why it works / why it fails:**
The fix adds `nullifierSecret` as a private input — this helps with SSZK. But SSZK ≠ MVZK. An RS that maliciously chooses `sessionNonce = H(credentialCommitment || counter)` — i.e., a structured nonce correlated with the agent's enrollment — can potentially reduce the ZK guarantee. The construction must specify: (a) who generates `sessionNonce` and how its distribution is constrained, and (b) whether the ZK claim is HVZK, MVZK, or simulation-extractable. None of these are stated.

**In-threat-model?** No — the game definition in A2 must specify the nonce generation oracle and prove security against a malicious RS, or restrict the RS to honest nonce generation with a justification for why that assumption holds.

---

### Attack 3: Subverted Per-Circuit Trusted Setup Breaks Soundness and ZK Simultaneously

**Attack:**
The construction uses Groth16 for `AgentPolicy` and `Delegation` circuits (CLAUDE.md). The ~25-constraint addition from `nullifierSecret` changes the R1CS, invalidating the existing `.zkey`. A new per-circuit trusted setup must be run. Groth16's soundness holds only if the toxic waste (the structured reference string trapdoor) is destroyed during the Powers of Tau + circuit-specific phase-2 ceremony. 

Game: Let the adversary *control* the trusted setup (or corrupt a single participant in a n-of-n ceremony with n=1). Then:
- **Forgery**: Adversary computes valid Groth16 proofs for any statement, including claiming permissions they do not hold. Selective scope proof is entirely broken — the RS cannot distinguish a legitimate agent from a forger.
- **ZK breaks too**: Adversary uses the trapdoor to extract the private witness from any submitted proof, recovering `nullifierSecret` and the full permission bitmask.

The "adversarial-AS model" that the construction cites as a differentiator over RFC 7662 is *strictly harder* when the AS is also the party that runs the trusted setup. RFC 7662 with a compromised AS leaks scope to that AS; Groth16 with a compromised setup ceremony leaks scope to any party holding the trapdoor, including third parties.

**Why it works / why it fails:**
The construction says it uses `pot16.ptau` (Semaphore v4 public ceremony for HumanUniqueness) but project-specific keys for AgentPolicy/Delegation. The write-up gives no description of the AgentPolicy phase-2 ceremony: who ran it, what the threshold was, whether it was audited. Without a ceremony transparency log, the subverted-setup attack cannot be ruled out. PLONK avoids per-circuit ceremony, which is why dual-build exists — but the Groth16 path (default for benchmarked performance) remains fully vulnerable.

**In-threat-model?** No — the threat model must state whether the setup is in-scope for the adversary. If setup is trusted (treated as a common reference string, CRS), this must be axiomatized and the CRS trust model disclosed to RS operators. If setup is a selling point of security ("we ran a transparent ceremony"), that ceremony must be documented and verifiable.

---

### Attack 4: AS-Blind Presentation Cannot Support Revocation — The RFC 7662 Gap Claim Reverses

**Attack:**
The candidate's primary differentiation claim is: *"AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)."* This is presented as a property RFC 7662 cannot match. However, RFC 7662 with active introspection *does* support real-time revocation: the RS calls the AS at presentation time, and if the token is revoked, the AS returns `"active": false`. 

In the Bolyra construction, AS-blind presentation means no AS call at verification time. Therefore:
- A credential issued at T₀ with `FINANCIAL_UNLIMITED` that is revoked at T₁ (agent fired, account compromised, delegation chain broken) continues to produce valid proofs until the `expiry` timestamp in the `credentialCommitment` is reached.
- The only revocation primitive available is a nullifier accumulator — a Merkle set of revoked nullifiers published on-chain by the AS. But this reintroduces AS liveness as a dependency and requires the RS to fetch the on-chain state, partially defeating AS-blindness.

The construction's gap analysis lists "AS-blind presentation" as a property *RFC 7662 cannot match*. This is true — but it inverts under revocation. RFC 7662 *can* revoke immediately; the ZK construction *cannot* without on-chain infrastructure. For regulated agent scenarios (the first scenario listed), real-time revocation is likely a compliance requirement. The comparison is incomplete and misleading to operators who rely on it.

**Why it works / why it fails:**
This is not an attack on ZK soundness — it is an attack on the completeness of the differentiation claim. If the construction's documentation reaches operators without a revocation section, operators will deploy AS-blind proofs assuming revocation is handled, then discover they have an indefinite window of unauthorized access post-revocation. The `expiry` field in `credentialCommitment` sets an upper bound, but in high-stakes regulated environments, a 24-hour credential is the shortest practical issuance window — leaving a 24-hour revocation lag.

**In-threat-model?** No — the comparison against RFC 7662 must include a revocation column in the threat model, and the construction must either (a) define a nullifier accumulator protocol with a formal security reduction, or (b) concede that AS-blind presentation trades real-time revocation for presentation privacy, letting operators make an informed choice.


## Persona: cu_ciso

### Attack 1: NCUA Part 748 Audit Trail Is a Boolean Void

- **Attack:** I ask my examiner to pull the access log for when agent `model-xyz` read member account #00123456. The examiner gets a ZK proof receipt that says "yes, this agent satisfied the `READ_DATA` predicate at T=1719000000." That's it. No full permission set, no scope context, no AS-side log (AS-blind by design). The construction's selectivity *is the attack surface* — selective disclosure strips the contextual metadata examiners expect in a Part 748 security program audit trail. NCUA § 748.0(b)(3) requires "detecting, preventing, and responding to attacks" with sufficient logging to reconstruct events. A boolean validity bit is not a reconstructible event.

- **Why it works / why it fails:** The construction explicitly argues AS-blindness as a *feature* (adversarial-AS model, "agent chooses what to disclose at moment of use"). That same property removes the AS as a logging point. The RS gets a verified boolean. Nothing in the construction spec's §§ on scenarios or gap-closing addresses what the RS does with the proof receipt — does it log the full proof? the public inputs? the circuit ID? Without a defined proof-receipt logging schema mapped to a specific control, the examiner sees a black box.

- **In-threat-model?** No. The construction must define a mandatory proof-receipt audit record: at minimum `{circuitId, credentialCommitment, sessionNonce, predicateSatisfied, timestamp}`. Prove that record is sufficient to reconstruct a Part 748-compliant access log. Then get your SOC 2 auditor to attest it.

---

### Attack 2: `nullifierSecret` Key Custody — "Prover-Held" Is Not a Policy

- **Attack:** The fix adds a private input `nullifierSecret` that is "prover-held, never shared." For an AI agent, I ask: who is the prover? It's a process running on operator infrastructure. Where does `nullifierSecret` live? HSM? Env var? Kubernetes secret? If it's a k8s secret, I can pull it with `kubectl get secret`. If it's an env var in a Lambda function, it's in CloudTrail logs. The construction's security proof assumes `nullifierSecret` is uniformly random and unpredictable — the *operational* model is that it lives somewhere in a CI/CD pipeline where a single IAM misconfiguration leaks it. GLBA Safeguards Rule 16 CFR § 314.4(c)(3) requires documented encryption key management with access controls. "Prover-held" is a cryptographic assumption, not a key management policy. My NCUA examiner will ask for the key management SOP. There isn't one in the construction.

- **Why it works / why it fails:** The construction correctly isolates `nullifierSecret` from the AS (fixing the SSZK game). But it says nothing about what happens when operator infrastructure is compromised. The `nullifierSecret` is per-agent-session (same agent + same session = same nullifier), which means a leaked `nullifierSecret` retroactively linkifies all past sessions for that agent. The construction must address: (a) rotation policy, (b) what "compromise" of `nullifierSecret` implies for session history, (c) how this maps to GLBA § 314.4(c) key lifecycle.

- **In-threat-model?** No. The construction is cryptographically clean but operationally silent on key lifecycle. A construction at strength 10 for a CU must include a key management appendix or at minimum reference one.

---

### Attack 3: Poseidon PRF Has No FIPS Certification — Examiner Stops Reading Here

- **Attack:** I hand the construction to my NCUA-contracted IT examiner. She opens the cryptographic primitives section, sees "Poseidon2 / Poseidon3 PRF, assumption A2." She asks for the FIPS 140-3 module certificate or the NIST SP 800-131A algorithm approval. Poseidon is not in either. FFIEC CAT Cybersecurity Controls domain (Baseline, "encryption of sensitive data in transit and at rest") and GLBA § 314.4(e) both require "encryption using industry-tested and accepted standards." NIST defines "industry-tested and accepted." Poseidon is a ZKP-circuit-optimized hash. It is not SHA-3. The construction's entire SSZK proof rests on Poseidon PRF security. From the examiner's posture, this is an unvalidated cryptographic primitive protecting member data access tokens.

- **Why it works / why it fails:** This is a genuine regulatory gap, not a cryptographic weakness. The construction is correct that Poseidon3 closes the SSZK game under assumption A2. But regulatory compliance does not follow from cryptographic correctness. The construction must either (a) map Poseidon to a NIST-equivalent security claim with a third-party attestation, or (b) describe a compliance narrative (e.g., "the proof itself uses Poseidon; the *output* presented to the RS is a standard ECDSA signature over the verified proof result, which is FIPS-compatible"). Without this bridge, the examiner flags the cryptographic module as non-FIPS and the construction fails the vendor assessment.

- **In-threat-model?** No. This is an existential gap for the CU market. No amount of cryptographic elegance survives "not NIST-approved."

---

### Attack 4: Revocation Latency vs. NCUA Part 748 Breach Response Window

- **Attack:** At 2am, my SOC gets an alert: operator `XYZ` private key (used to sign `credentialCommitment`) is leaked. The agent has `FINANCIAL_MEDIUM` permissions (bit 3, implies bit 2 — up to $10K transactions). I need to revoke all credentials signed under that key *immediately*. The construction's on-chain registry holds the Merkle root of enrolled agents. Revocation means submitting an on-chain transaction to remove the leaf, waiting for block confirmation on Base Sepolia (or mainnet), and then rebuilding the Merkle root. On a congested chain, this is minutes to hours. NCUA Part 748 Appendix B (Interagency Guidelines) requires notification and containment of a breach "as soon as possible" — examiners have interpreted this as same-day, and NCUA's 2023 cyber incident reporting rule (12 CFR 748.1(b)) requires reporting within 72 hours. My Tier 1 ops team cannot submit an on-chain revocation transaction. They don't have wallet access. They don't know what a Merkle root is.

- **Why it works / why it fails:** The construction describes replay detection via nullifiers (same agent + same session = same nullifier is rejected). But nullifier replay detection only prevents *replaying a specific proof*. It does not prevent the compromised operator from *generating new valid proofs* against unrevoked `credentialCommitment` values. The construction's scope (§ scenarios) is silent on credential revocation latency and operator-key-compromise response. The gap-to-close section describes the AS-blind presentation advantage — but that advantage becomes a liability when the "AS" you're blinding is also your incident response system.

- **In-threat-model?** No. The construction must specify: (a) a revocation mechanism with SLA ≤ incident-response window, (b) an ops runbook that Tier 1 can execute without blockchain expertise, and (c) how revocation state is observable to an NCUA examiner post-incident.


## Persona: rfc7662_advocate

### Attack 1: AS-Side Filtered Introspection Already Provides Selective Disclosure

- **Attack:** RFC 7662 §3.3 allows the AS to tailor the introspection response per RS. Combined with `draft-ietf-oauth-jwt-introspection-response`, the AS issues a *signed JWT* containing only the scopes relevant to the querying RS—offline-verifiable, no AS roundtrip at presentation time. The agent's full permission bitmask never appears in the JWT the RS receives. The candidate (§ "AS-blind presentation") claims the agent "chooses what to disclose at the moment of use," but the AS-filtered JWT achieves the same *observable outcome at the RS*: the RS sees exactly the scopes it is authorized to see, nothing more.
- **Why it works / why it fails against the construction:** The construction's distinguishing claim requires that the *agent*—not the AS—controls disclosure at runtime. But in the JWT introspection model, per-RS policy is set at the AS at issuance/filter time, not at presentation. The construction survives only if it can demonstrate a *runtime-adaptive* predicate that the agent computes over its credential *after* issuance, without AS participation. The current write-up asserts this but does not exhibit a concrete scenario where the AS-filtered JWT fails while the ZK proof succeeds. Until that scenario is concrete, this attack is **not in threat model as stated**.
- **In-threat-model?** No — construction must exhibit a runtime-adaptive predicate that a static issuance-time AS filter cannot express.

---

### Attack 2: Audience-Bound PPIDs + Resource Indicators Already Break Cross-RS Linkability

- **Attack:** RFC 8707 (Resource Indicators) binds tokens to a specific `resource` URI, so a token issued for `https://rs-a.example` is cryptographically rejected at `rs-b.example`. OIDC pairwise pseudonymous identifiers (PPID) ensure `rs-a` and `rs-b` see different subject identifiers for the same user. Combined, two RSes that collude cannot link sessions *at the RS level*. The candidate claims ZK provides unlinkability across RSes; the baseline already provides this without any ZK.
- **Why it works / why it fails against the construction:** The construction's nullifier (`Poseidon3(credentialCommitment, sessionNonce, nullifierSecret)`) produces a unique value per session. But so does a DPoP proof (`jkt` thumbprint bound per request) combined with per-RS audience tokens: the RS never sees a correlating identifier across resources. The construction survives only if the *AS itself* is the adversary doing the correlating—the "adversarial AS" scenario in the candidate. But the nullifier fix doesn't protect against the AS correlating via `credentialCommitment`, which the AS knows (it issued the credential). The adversarial AS sees `credentialCommitment` at enrollment; `nullifierSecret` is never revealed to the AS, but `credentialCommitment` is public by design. An adversarial AS cannot reconstruct the nullifier, but it can still build a correlation graph over `(credentialCommitment, time, RS)` from its own issuance logs—no nullifier needed.
- **In-threat-model?** Yes — the construction survives RS-level linkability. But the adversarial-AS correlation via issuance metadata is unaddressed.

---

### Attack 3: DPoP Sender-Constraint Without ZK — Where Exactly Does DPoP Fail?

- **Attack:** RFC 9449 DPoP binds an access token to a client's ephemeral public key via a `dpop_jkt` claim. The RS verifies a fresh DPoP proof (with `htm`, `htu`, `iat`, `jti`) on every request, providing sender-constraint and replay prevention without any ZK. The candidate must "name the property DPoP cannot provide." Neither the candidate nor the construction does so explicitly. DPoP provides: (1) sender-constraint, (2) per-request replay protection via `jti`, (3) no credential reuse across endpoints. What is missing?
- **Why it works / why it fails against the construction:** DPoP does not provide *predicate proofs over the credential's internal permission bitmask*. DPoP proves "this key holder sent this request" but cannot prove "this credential's permission bitmask satisfies the predicate `(bits & 0b00001100) == 0b00001100` without revealing the full bitmask." The ZK circuit proves the predicate while keeping unexposed bits hidden from the RS. This is the *only* property the baseline genuinely cannot match. However, the construction's current write-up buries this in "scenarios" rather than leading with it as the formal distinguishing statement.
- **In-threat-model?** Yes — this is the one genuine gap. But the construction must state it as a theorem, not a scenario. "2^64 permission space" is illustrative; the formal claim is: *no AS-side filter can produce a predicate proof over inputs the AS does not observe at filter time.*

---

### Attack 4: The Nullifier Fix Adds a Client-Side Secret Burden That Breaks Stateless Agent Assumptions

- **Attack:** The fix introduces `nullifierSecret` — a prover-held value that must be stored securely, never shared, and survive agent restarts. RFC 7662 baseline has no such requirement: the AS is stateful, tokens are short-lived and refreshable, and the client need not maintain long-term secrets beyond its OAuth client credentials (which have established rotation patterns, hardware attestation via RFC 8705 mutual-TLS, etc.). The construction now requires the *agent* to be a secure enclave for `nullifierSecret`. This is a *new trust assumption* layered on top of the ZK math, not a property inherited from it.
- **Why it works / why it fails against the construction:** If `nullifierSecret` is compromised (exfiltrated from the agent process, leaked in a core dump, extracted via SSRF on the agent's local state), the adversarial AS scenario collapses: the AS can reconstruct the nullifier for all past sessions and build a full correlation graph. The baseline DPoP key is also a client-side secret, but DPoP keys are ephemeral and per-session by design; `nullifierSecret` appears to be long-lived (it must produce the same nullifier for "same agent + same session" replay detection). Long-lived client secrets under an adversarial AS model deserve a threat sub-section the construction does not currently contain.
- **In-threat-model?** Yes — the construction must specify `nullifierSecret` lifecycle: how it is generated, whether it is session-scoped or credential-scoped, what happens on compromise, and why this burden is acceptable relative to the baseline's AS-managed state.


## Persona: spiffe_engineer

---

### Attack 1: WIMSE Token Binding Already Owns "AS-Blind Presentation"

- **Attack:** The construction's headline uniqueness claim — *AS-blind presentation, agent chooses what to disclose at moment of use, no AS roundtrip* — is precisely what `draft-ietf-wimse-arch §4.3` calls "workload-to-workload token binding with sender-constrained proof." A JWT SVID (short-lived, workload-scoped) combined with SD-JWT selective disclosure lets the agent present only the permission subsets the RS requested, offline, without the AS being in the loop. The RS verifies the SPIFFE trust bundle it already has pinned. No ZK circuit needed.

- **Why it works / why it fails:** The construction's `AgentPolicy.circom` adds a ZK proof that a bitmask satisfies a predicate. But SD-JWT already does selective disclosure of individual claims — the RS requests `permission_bits ∩ required`, the agent discloses exactly that subset, signed by the AS. The "AS cannot lie about scope membership" scenario (the construction's adversarial-AS model) is the only gap, but WIMSE addresses this by binding the token cryptographically to the workload's SVID private key — the AS issues a token the workload signs at presentation. AS lying about issuance is caught by the workload's own signature, not a ZK proof.

- **In-threat-model?** **No** — the construction must explicitly argue why WIMSE sender-constrained tokens do not close this gap. Citing `draft-ietf-wimse-arch` as out-of-scope is not sufficient; it's in active IETF standardization and has two WG implementations already shipping.

---

### Attack 2: The `nullifierSecret` Fix Just Reinvents SVID Key Material — In a Worse Place

- **Attack:** The fix introduces a private scalar `nullifierSecret` held by the agent workload and never shared. Where is this stored? The construction is silent. In production SPIFFE deployments, the workload's private key material lives in the SPIRE Agent's SVIDStore, protected by node attestation (TPM, k8s projected service account token, AWS IID). The Workload API delivers key material only to processes that pass workload attestation selectors (pid namespace, cgroup, binary hash). The `nullifierSecret` has no equivalent attestation story — it's just a file or env variable the agent process holds. If the workload is compromised, the adversary gets `nullifierSecret` and can generate valid nullifiers for any `(credentialCommitment, sessionNonce)` pair. The SSZK security argument transfers the trust assumption from AS to the workload execution environment without acknowledging that SPIRE already solves exactly this via TEE/TPM-backed SVIDStore.

- **Why it works / why it fails:** The construction claims Poseidon PRF security under assumption A2 (AS gets all `credentialCommitment` values, `nullifierSecret` stays private). A2 is vacuously broken the moment the workload process is compromised — and the construction provides no mechanism to protect `nullifierSecret` that SPIRE's SVIDStore + node attestation doesn't already provide with stronger OS-level guarantees. The ~25 extra Groth16 constraints buy nothing if `nullifierSecret` leaks from a proc filesystem read.

- **In-threat-model?** **No** — the construction must describe a `nullifierSecret` custody model and explain why it is stronger than, or composable with, SPIRE SVIDStore. Right now it is a weaker version of the same thing.

---

### Attack 3: Proof Size and Latency Are Worse Than a JWT SVID at Every Practical Permission Width

- **Attack:** The construction claims "constant-size proof regardless of bitmask width" as a scalability advantage over RFC 7662 at 2^64 permissions. Let's measure. A Groth16 proof on BN254 is 128 bytes. A JWT SVID with a 64-bit `permissions` claim + ES256 signature is ~220 bytes. A 256-bit permission mask as a hex string in a JWT claim adds 64 bytes — still ~284 bytes total, offline-verifiable with a pinned JWKS. The Groth16 proof is smaller, but proving time on the agent side is ~80–200ms (snarkjs) vs. ~1ms for ES256 signing. The construction's benchmark table (`circuits/scripts/bench_rapidsnark.js`) reports rapidsnark at ~40ms, which is better, but still 40× the JWT path. At 2^64 permission space the JWT claim size grows by `O(log n)` bits in the worst case (if encoding all granted bits) — the ZK proof stays constant. This is the only regime where ZK wins on size. The construction needs to name a realistic deployment where 2^64 bits is the permission space *and* the encoding overhead of a JWT claim is the bottleneck, not the ZK proving time.

- **Why it works / why it fails:** The constant-size argument is technically correct but practically irrelevant at the 8-bit cumulative bitmask the construction actually uses (`bolyra/CLAUDE.md` permissions model, bits 0–7). The 2^64 scenario is a strawman until there is a concrete use case driving it. Against the actual 8-bit implementation, a JWT wins on every metric except the adversarial-AS property.

- **In-threat-model?** **Yes** for the adversarial-AS scenario; **No** for the scalability claim as currently stated. The construction should drop the scalability argument or scope it to the adversarial-AS model exclusively.

---

### Attack 4: The Right Architecture Is a ZK Workload Attestor Plugin, Not a New Protocol

- **Attack:** SPIRE's plugin architecture (`pkg/agent/plugin/workloadattestor`, `pkg/server/plugin/nodeattestor`) is explicitly designed so that organizations can contribute new attestation mechanisms without forking the protocol. The correct contribution of Bolyra's ZK construction to the ecosystem is a SPIRE workload attestor plugin that: (1) runs alongside the workload, (2) generates a ZK proof of credential membership at attestation time, and (3) embeds the proof as a custom SVID extension or JWT SVID claim. The RS then verifies the embedded ZK proof using a pinned verifier key, inside the standard SPIFFE trust model. This approach reuses SPIRE's node attestation chain of trust, SVID rotation, federation, and the Workload API — while adding only the ZK selective-disclosure layer. The construction instead defines a new wire protocol (`spec/draft-bolyra-mutual-zkp-auth-01.md`) that has no trust-domain anchoring, no SVID rotation story, and no node attestation. It is a parallel identity system layered on top of whatever infrastructure is already running, which means operators must run two identity planes.

- **Why it works / why it fails:** The construction's `spec/draft-bolyra-mutual-zkp-auth-01.md` defines its own DID method (`did:bolyra:*`), its own credential commitment scheme, and its own handshake. None of this is anchored to an existing trust domain. In a Fortune 500 running SPIRE, deploying Bolyra means either (a) ignoring SPIFFE entirely and running a parallel credential plane, or (b) somehow bridging `did:bolyra:*` to `spiffe://trust-domain/path` — a mapping the construction does not specify. The WIMSE working group would ask: why not a JWT SVID extension type (`cnf` + ZK proof blob) and a SPIRE plugin? The answer has to be more than "we have a novel circuit" — it needs to be an architectural argument for why the protocol layer is the right home for this.

- **In-threat-model?** **No** — the construction must address the "two identity planes" operational cost and either (a) specify a SPIFFE federation bridge, or (b) argue why replacing SPIFFE entirely is the right call for the target deployer. Silence on this is the strongest practical objection a staff engineer will raise in any RFC review or enterprise sales cycle.
