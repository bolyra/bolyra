# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The Batch Relayer Is a Ghost Trust Assumption That Isn't in the Threat Model

- **Attack:** Section 2 introduces a "batch relayer" to defeat AS-level timing correlation, then hand-waves it with "the relayer sees proofs but cannot link them." But the relayer is a new trusted third party that the formal IND-UNL-AS game (§3) does not include in the adversary's capability set. The game gives the adversary control over the AS and up to `k-1` RSes — it says nothing about relayer compromise. Who runs this relayer in the CU*Answers scenario? CU*Answers itself. CU*Answers is a CUSO, a legal entity that can receive subpoenas, NCUA examination requests, and FinCEN 314(a) information-sharing demands. The relayer receives proofs before batching — it sees submission IP, inter-arrival timing (within the epoch window it controls), and proof size. If it logs those, the NCUA can compel the log. WorkOS doesn't introduce a new infrastructure entity between the agent and the RS. Enterprise procurement asks: "who is in the data path?" Right now the answer is "a batch relayer we haven't defined an SLA or liability model for." That's a non-starter for a credit union's BSA officer.

- **Why it works / why it fails:** The construction relies on the relayer for its timing defense, yet the relayer is outside the formal game. The advantage bound of `1/m` per epoch (§3, timing sub-game) is only valid if the relayer itself is honest — an assumption never stated as a trust requirement. This is a gap, not a mitigation.

- **In-threat-model?** No — construction must address. Either (a) formalize the relayer as a semi-trusted party with an explicit trust assumption in §3, or (b) replace it with an oblivious submission scheme (e.g., Tor hidden service, PIR-based submission) that doesn't require a trusted coordinator. As written, the timing defense is architecturally dependent on trusting a CUSO that is not in scope.

---

### Attack 2: `scopeBlindingSecret` Creates a Worse Key-Management Problem Than the One It Solves

- **Attack:** The construction introduces `scopeBlindingSecret` — a fresh 251-bit scalar generated at enrollment, stored alongside credential material, and never derived from anything recoverable. Section 5 says it is "NOT derived from the credential commitment." That means it is an independent secret with no recovery path. Consider the operational consequence: if an agent's credential store is wiped (device replacement, container restart, cloud provider incident), `scopeBlindingSecret` is gone. The agent must re-enroll, which generates a *new* blinding secret and therefore *new* `scopePseudonym` values at every RS. At every RS where the agent previously held an account, that pseudonymous identity is now orphaned. The agent looks like a new user to Merchant-A, losing purchase history, limits, trusted status. Worse: if the secret *leaks* (cloud backup, memory dump, insider at the operator), all unlinkability is broken *retroactively and permanently* — an adversary with the leaked `scopeBlindingSecret` can compute `Poseidon2(scopeId_X, sbs)` for every RS and reconstruct the full merchant graph. OAuth short-lived tokens bound compromise windows to token TTL (minutes). This construction creates a single 251-bit value whose compromise is unbounded in time. WorkOS doesn't ship a new permanent secret to manage. I can walk into a credit union's CISO office and say: "Bolyra requires every AI agent to maintain a persistent master unlinkability secret. Here's the breach scenario where that secret escapes your HSM."

- **Why it works / why it fails:** The construction provides no key-management specification for `scopeBlindingSecret`: no derivation hierarchy (so it can't be recovered from a BIP-32 seed), no rotation protocol (rotating it orphans all existing RS pseudonyms), no escrow model (loss = re-enrollment). Section 7 (deployment scenario) mentions Alice's agent "generates a random `scopeBlindingSecret` locally" but says nothing about where it lives after that. This is a gap the construction must close before any enterprise operator can evaluate it.

- **In-threat-model?** No — construction must address. The threat model covers adversarial AS correlation but not secrets management failure. A key management specification — derivation (e.g., `HKDF(masterSecret, "scope-blinding-v1")`), rotation semantics, loss/recovery — is a precondition for operator adoption, not an implementation detail.

---

### Attack 3: The Latency Claim Is Benchmark Theater — End-to-End Is ~35 Seconds, Not 0.6 Seconds

- **Attack:** Table in §6 says "Groth16, rapidsnark: < 0.6s." That number requires the `rapidsnark_prover` binary from `circuits/build/` running on server-class hardware with the `.zkey` pre-loaded in memory. In the actual deployment scenario (§7): Alice's agent is running inside a browser extension, a mobile app, or a serverless function. Browser agents use snarkjs WASM (§6 says "< 3s" for snarkjs Groth16). Serverless cold-starts add 1-2s before the prover runs. Then the proof is submitted to the batch relayer, which accumulates proofs and submits in "30-second epochs" (§2). Total end-to-end latency from "agent wants to access Merchant-A" to "Merchant-A verifies the proof": 3s (snarkjs) + up to 30s (batch epoch wait) + block confirmation time = **33-40 seconds**. WorkOS issues a token in under 100ms. Stytch Connected Apps is comparable. For a payment at a point-of-sale terminal, a 35-second authorization is not a performance tradeoff — it's a product that doesn't work. The construction's §8 "structural impossibility" framing implies OAuth's latency is a limitation to overcome, not the reverse. This has it backwards.

- **Why it works / why it fails:** The construction conflates proving time with end-to-end authorization latency. The batch relayer epoch window dominates real-world latency but is described only as a "timing defense," not as a user-experience cost. Section 6 provides no end-to-end latency budget. The 0.6s figure is valid only for the native server-side prover, which is not the default path for mobile or browser agents.

- **In-threat-model?** No — construction must address. The latency analysis must distinguish: (a) server-side agent (native prover), (b) browser/mobile agent (WASM prover), (c) end-to-end including batch epoch. For use cases requiring interactive latency (<2s), the batch relayer must be optional and the construction must specify what timing-correlation mitigation applies when batch submission is bypassed.

---

### Attack 4: `scopeCommitment` Is a Cross-Scope Deanonymization Handle That Delegation Activates

- **Attack:** Section 4, constraint 10 defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. This value is deterministic per agent and **identical across all scopes** — the same agent produces the same `scopeCommitment` at every RS it visits. The construction acknowledges this in §4 ("When cross-scope unlinkability is required WITHOUT delegation, the circuit omits `scopeCommitment` from public outputs"). But then look at the healthcare delegation scenario in §7: Bob's agent carries a delegated credential used at Cedars-Sinai. Delegation *requires* `scopeCommitment` to be present (it is the delegation chain anchor, per §2 "Scope commitment (for delegation chain compatibility)"). So at Cedars-Sinai — an RS that handles PHI and where privacy matters most — the agent's public output includes `scopeCommitment`, which is the same value it would emit at Kaiser, at any other provider, at any scope where delegation is active. A colluding set of RSes (all running on the same Epic EHR infrastructure, say) can trivially correlate all proofs from the same agent by matching `scopeCommitment`. This directly contradicts the top-level claim: "same agent accessing different RS instances produces cryptographically unlinkable authorizations." The construction's mitigation ("at least one honest RS in the chain") does not apply to the colluding RS scenario the IND-UNL-AS game explicitly covers. The `k-1` colluding RS assumption in §3 is violated the moment delegation is used across RSes that share infrastructure.

- **Why it works / why it fails:** The construction's own §4 admits `scopeCommitment` is cross-scope stable and only omits it via a "compile-time flag." In practice, operators enabling delegation — the majority of real enterprise use cases — will have `scopeCommitment` in public outputs. The security argument in §4 that "it is hidden behind Groth16's zero-knowledge property" is incorrect for public *outputs*: public outputs are explicitly not hidden by ZK. The ZK property hides witnesses (private inputs), not public output signals. Any verifier who receives the proof receives `scopeCommitment` in the clear.

- **In-threat-model?** No — this is a direct contradiction of the claim that the construction must address. Potential fixes: (a) derive a scope-specific delegation commitment `Poseidon2(scopeId, credentialCommitment)` instead of a global one, at the cost of breaking the delegation chain's global verification; or (b) define two circuit variants and restrict the unlinkability claim to the non-delegation variant, explicitly carving out delegation from the IND-UNL-AS game. As written, the claim covers both scenarios and the construction does not survive the delegation case.


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. You've provided all three — so now I'll try to break them.*

---

### Attack 1: `scopeCommitment` Is a Permanent Cross-Scope Correlator

- **Attack:** The adversary (AS or any colluding RS) collects public outputs from two proofs `π_A` (scope A, adversary-controlled) and `π_B` (scope B, honest RS). Both proofs expose `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output**. This value is *deterministic per agent across all scopes* — it does not depend on `scopeId` or `scopeBlindingSecret`. An adversary holding `π_A.scopeCommitment` and `π_B.scopeCommitment` trivially tests whether they are equal. If equal, the two proofs originated from the same agent. Unlinkability is broken.

- **Why it (doesn't) work:** The construction acknowledges this in §4 point 5 and offers a "compile-time flag" to omit `scopeCommitment` from public outputs when delegation is not needed. This is not a mitigation — it is a circuit fork. The IND-UNL-AS game (§3) is stated for a single circuit, but the construction actually describes two incompatible circuits: one with cross-scope unlinkability (no `scopeCommitment`) and one with delegation support (`scopeCommitment` present). These cannot simultaneously satisfy the claimed property. No hybrid argument bridges them.

- **In-threat-model?** **No.** The construction must either (a) make `scopeCommitment` private (verified inside the circuit, not revealed), using a separate on-chain nullifier that is scope-scoped and derived from `scopeBlindingSecret` rather than `credentialCommitment`, or (b) formally state that the IND-UNL-AS game applies only to the no-delegation variant and provide a separate security definition for the delegation variant that bounds the resulting linkability.

---

### Attack 2: On-Chain Verification Invalidates the Game Definition

- **Attack:** The game definition (§3, Challenge Phase, step 3) states: *"Adversary A receives only that some proof was submitted for `scopeId_B`, but not the public signals, since the honest RS does not collude."* This assumption is false in the stated deployment model. §7 says proofs are "submitted to the on-chain registry." On-chain transactions are globally public. The adversary controlling the AS — or any passive observer — reads the blockchain and sees `π_B`'s public outputs directly: `scopePseudonym_B`, `nonceBinding_B`, `agentMerkleRoot`, and (per Attack 1) `scopeCommitment`. The honest RS's non-collusion is irrelevant when the ledger is the verifier.

- **Why it works:** The PRF-based reduction (§4) argues that `Poseidon2(scopeId_A, sbs_b)` and `Poseidon2(scopeId_B, sbs_b)` are computationally independent given PRF security. This argument is correct *if the adversary cannot query the PRF at `scopeId_B`*. But the adversary knows `scopeId_B` (it is a public input, derived from the RS domain name, published in discovery metadata) and observes `scopePseudonym_B = Poseidon2(scopeId_B, sbs_b)` on-chain. The adversary now holds two PRF evaluations at two known points under the same key `sbs_b`. PRF security guarantees these evaluations are indistinguishable from two independent random values — so the reduction holds — but the reduction must be restated: the adversary's view is `(scopeId_A, F(scopeId_A)), (scopeId_B, F(scopeId_B))`, not `(scopeId_A, F(scopeId_A))` alone as the game currently models. The game definition is strictly weaker than the actual deployment adversary. The reduction may still go through (standard PRF with two queries), but the game must be corrected or the proof is unsound as written.

- **In-threat-model?** **No.** The game definition must reflect the on-chain adversary who sees all public outputs of all submitted proofs. Concretely: restate Challenge Phase step 3 to give `A` the full public signals of both `π_A` and `π_B`, then re-examine whether the PRF reduction still closes the gap. (It likely does for `scopePseudonym`, but see Attack 1 for `scopeCommitment`.)

---

### Attack 3: Merkle Root as Enrollment Timestamp — Anonymity Set Collapse

- **Attack:** The `agentMerkleRoot` is a public output present in every proof. The AS controls enrollment: it issues the EdDSA signature over each `credentialCommitment` and inserts it into the on-chain Merkle tree. The AS therefore maintains a log of `(credentialCommitment_i, insertion_timestamp_i, resulting_root_i)` for every enrolled agent. When an agent submits a proof with `agentMerkleRoot = R_t`, the adversarial AS looks up all tree roots in its log and recovers the exact set of agents enrolled when `R_t` was the canonical root. In a credit union with 300 members that enrolls agents sequentially, the root changes 300 times, and each root version corresponds to a single additional enrollee. If root `R_t` appeared only when agent `alice` was the most recently enrolled, the proof is trivially deanonymized. Even with bulk enrollment, the root constrains the anonymity set to agents enrolled before timestamp `t`, which degrades unlinkability sharply in low-cardinality deployments.

- **Why it works / why the construction doesn't address it:** The construction argues (§4, point 4) that "all agents share the same root — it reveals the set, not the individual." This is true only when the Merkle tree is append-only and the AS cannot distinguish which root version an agent used. But append-only trees produce monotonically increasing root sequences. In the Bolyra deployment, the AS *knows* which root was active at each point in time because it controls insertions. The batch relayer (§2, §3 timing sub-game) addresses timing correlation of proof *submission*, not the static `agentMerkleRoot` correlation that persists indefinitely across proof submissions.

- **In-threat-model?** **No.** The construction must either (a) use a fixed "epoch root" that is updated only at long intervals (e.g., weekly), so many enrollments accumulate before the root changes, increasing the anonymity set; (b) apply a dummy-insertion strategy to keep root churn unpredictable; or (c) explicitly bound the anonymity set size as a parameter and acknowledge that the IND-UNL-AS advantage is `1/|anonymity_set|` rather than negligible in small deployments. The healthcare scenario (Bob referred from Kaiser to Cedars-Sinai) is particularly fragile: if Kaiser's agent Merkle tree has tens of agents rather than millions, the root narrows the set to a handful of identities immediately.

---

### Attack 4: Subverted Phase 2 — Groth16 Soundness Under Compromised Setup

- **Attack:** The construction uses Groth16 for `ScopeBlindAuth` (§6, proving time table). Groth16 requires a circuit-specific Phase 2 trusted setup. The construction states (CLAUDE.md / §2): "Project-specific keys (Agent/Delegation) use `pot16.ptau`." It does not specify who ran Phase 2 for `ScopeBlindAuth` or what the MPC ceremony looked like. If the AS (or an AS-colluding operator) contributed the *sole* Phase 2 computation, they hold the toxic waste `τ` and can synthesize valid proofs for *any* witness, including fabricated credentials for agents that were never enrolled. Concretely: the adversarial AS generates a `ScopeBlindAuth` proof with a fake `credentialCommitment` for agent Alice's `scopeId`, producing a valid `scopePseudonym_A`. The AS can now impersonate Alice at any RS, bypassing the enrollment Merkle check entirely. The knowledge soundness argument (KS-G16, §4) holds only relative to an honest CRS; under subverted setup, the extractor does not exist.

- **Why it matters for unlinkability specifically:** Even if the IND-UNL-AS game is otherwise sound, subverted setup lets the AS forge proofs for chosen agents at chosen scopes. The AS could generate a "shadow" proof for the same credential commitment Alice used, revealing which `scopeBlindingSecret` Alice would have needed — effectively breaking unlinkability by controlled forgery rather than by breaking the PRF. The simulation-extractability property of Groth16 (Groth16-SE, as defined by Fuchsbauer et al.) requires a non-subvertible setup; the construction provides no simulation-extractability argument.

- **In-threat-model?** **No, and the threat model is silent on setup.** The threat model (§3) lists AS capabilities as: issues credentials, logs interactions, observes network. It does not list "contributes to or controls Phase 2 ceremony" as an adversary capability. For a system where the AS is the explicit adversary, a Phase 2 ceremony that requires the AS's non-participation (or a PLONK-only deployment with universal setup) is non-negotiable. The construction should either (a) mandate PLONK (which has a universal, per-circuit-parameter-free setup) and remove the Groth16 path for `ScopeBlindAuth`, or (b) specify a multi-party Phase 2 ceremony with at least one participant not controlled by the AS, and add "AS did not compromise Phase 2" as an explicit assumption. Leaving this implicit while calling out AS-as-adversary in §3 is a gap that any CRYPTO reviewer will flag on first read.


## Persona: cu_ciso

---

### Attack 1: The Privacy Guarantee Destroys My Audit Trail

**Attack:**
Section 7 ("Concrete deployment scenario") proudly states: *"Desert Financial (AS) sees nothing … Desert Financial has zero visibility into which merchants the agent contacted, when, or how often."*

I am the CISO at Desert Financial. My NCUA Part 748 security program requires me to maintain and monitor activity logs for member-authorized transactions. My BSA/AML compliance officer files Suspicious Activity Reports. My GLBA Safeguards Rule program (16 CFR § 314.4(c)) requires me to monitor for and detect unauthorized access. My SOC 2 Type II audit requires me to demonstrate I *have* monitoring in place.

If my AS sees nothing — by cryptographic design — I cannot:
- Detect an agent acting outside permitted scope
- File a SAR when an agent hits 50 merchants in 10 minutes at 3am
- Demonstrate to an NCUA examiner that I have a monitoring control
- Produce an audit log when a member disputes a charge and law enforcement subpoenas me

The construction's security argument (§3, §8 "Structural impossibility 1") frames AS-blindness as a win. My examiner frames it as a control gap.

**Why it works / why it fails:**
The construction does not address this at all. §7 lists no audit hook. The on-chain Merkle root and proof submissions give me a public ledger that someone accessed *something*, but no mapping to a member identity without the `scopeBlindingSecret` — which the construction explicitly says the AS does not hold.

**In-threat-model?** **No** — construction must address.

The construction needs a regulatory carve-out path: an optional *compliance disclosure channel* where the agent can present a `memberBinding` proof to the credit union's own monitoring system (separate from the AS-as-adversary path) that maps the session back to a member without revealing cross-scope linkage to third parties. Without this, no mid-size credit union subject to NCUA exam can deploy this.

---

### Attack 2: Where Does `scopeBlindingSecret` Live?

**Attack:**
Section 5 states: *"The `scopeBlindingSecret` is a new per-agent secret, generated once at agent enrollment and stored alongside the agent's credential material."*

My vendor management questionnaire has one question that kills more vendors than any other: *"Where exactly does the key live, and what happens if it is lost or stolen?"*

The construction is silent on:
- **Storage substrate** — device keystore? Browser LocalStorage? HSM? Cloud KMS? Each has a different risk profile and NCUA examiner expectation.
- **Loss scenario** — if the device is wiped, the `scopeBlindingSecret` is gone. The agent's `scopePseudonym` at every RS changes on re-enrollment (a new secret means a new pseudonym). Account continuity at Merchant-A is severed. The member calls my Tier 1 ops line.
- **Theft scenario** — if the secret is exfiltrated (e.g., via malware on the agent host), an attacker can impersonate the agent at any RS indefinitely. The construction's credential expiry (`expiryTimestamp`) provides *some* bound, but the `scopeBlindingSecret` itself has no rotation mechanism described.
- **Backup scenario** — any backup of `scopeBlindingSecret` to a recovery service reintroduces a party that can correlate across scopes. The construction's PRF unlinkability argument (§4) collapses if the backup provider is subpoenaed.

**Why it works / why it fails:**
The construction's threat model (§3) defines the trusted component as "the agent's local proving environment." It defers the storage question entirely. This is the cryptographic equivalent of a bank vault designer saying "the combination is secure — storing it is your problem." NCUA examiners do not accept deferred key custody.

**In-threat-model?** **No** — construction must address.

The construction needs a key custody section specifying at minimum: HSM-backed storage recommendation, rotation protocol (what happens when `scopeBlindingSecret` is compromised — can the agent re-enroll with a new secret without losing RS-side account records?), and a concrete answer to whether recovery is possible and what party it requires.

---

### Attack 3: CU*Answers Batch Relayer Is a Single Point of Failure and a Vendor Risk Exam Finding

**Attack:**
Section 7 names **CU*Answers** as the batch relayer for 150+ credit unions: *"Both proofs are submitted through the CU*Answers batch relayer, which aggregates proofs from agents across all 150 member credit unions and submits them in 30-second epochs."*

My FFIEC CAT profile (Domain 2: Threat Intelligence; Domain 5: Cyber Incident Management) and NCUA Letter 01-CU-20 (third-party due diligence) require me to assess:

1. **Concentration risk** — CU*Answers is a CUSO serving 150+ credit unions. If their relayer has a 1% annual outage (35 hours/year), *every* agent-authorized transaction across all 150 member CUs fails to settle during those windows. My SLA with my core processor (Fiserv, Jack Henry) is 99.9%. A batch relayer at 99% is an automatic finding.

2. **Vendor due diligence** — the batch relayer *sees all proofs* before submitting them. The construction states the relayer "cannot link them" because `scopePseudonym` is scope-specific. But the relayer sees the *raw proof bytes*, the *submission timing within the epoch*, and the *source IP / agent endpoint*. A compromised CU*Answers relayer is an adversary with network-level correlation capability — precisely the §3 side-channel threat model. The batch defense requires a *honest* relayer. Nothing in the construction enforces this.

3. **My board narrative** — "We route all member agent authorizations through a Michigan CUSO's batch aggregator on Ethereum" will not survive a board risk committee review.

**Why it works / why it fails:**
The construction's batch relayer is presented as a timing defense (§2, §3 side-channel sub-game) but is underspecified as an operational component. No SLA, no failure mode, no adversarial relayer analysis, no fallback path. The adversary advantage bound of `1/m` per epoch assumes an *honest* shuffling relayer — a compromised relayer can de-anonymize by selectively delaying or omitting proofs.

**In-threat-model?** **No** — construction must address.

The construction needs to either: (a) specify how a *verifiably honest* relayer is achieved (e.g., commit-reveal with on-chain shuffle proof), or (b) define a direct-submission fallback that degrades timing privacy but preserves cryptographic unlinkability. The SLA gap must be closed with a concrete availability architecture.

---

### Attack 4: `scopeCommitment` Is a Cross-Scope Correlation Handle When Delegation Is Deployed

**Attack:**
Section 4 (security argument, point 5) acknowledges: *"`scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is deterministic per agent … it is the same across scopes for the same agent."*

The construction's mitigation is: *"when cross-scope unlinkability is required WITHOUT delegation, the circuit omits `scopeCommitment` from public outputs (a compile-time flag)."*

Section 7's healthcare delegation scenario (the *secondary* use case presented as a design goal) deploys delegation: Bob's agent carries a delegated credential used at Cedars-Sinai. In that scenario, `scopeCommitment` is necessarily in the public outputs — it is the delegation chain anchor (§5.1 "Identity-Bound Scope Commitment").

Now: Kaiser (the issuing AS) sees the delegation event on-chain, including Bob's agent's `scopeCommitment`. Cedars-Sinai (RS-B) sees the same `scopeCommitment` in Bob's `ScopeBlindAuth` proof. If Kaiser and Cedars-Sinai compare notes — or if Kaiser is the adversarial AS and Cedars-Sinai is a colluding RS — they can link the delegation event to the specific RS where the delegated credential was used. The construction's claim that *"Kaiser cannot determine which specialist RS the delegation was used at"* (§7, healthcare scenario) is incorrect when `scopeCommitment` is public.

The construction's response ("the specific RS that will anchor the delegation chain … is assumed honest for the delegation sub-protocol") concedes the point: the IND-UNL-AS game security breaks down precisely in the delegated use case. The game definition in §3 covers `k-1` colluding RSes but the delegation scenario requires the anchor RS to be honest — a trust assumption that is not present in the baseline game definition and is not disclosed to the operator deploying this for healthcare.

**Why it works / why it fails:**
The construction partially acknowledges this in §4 point 5 but buries the concession in a footnote-style "refinement." The healthcare scenario in §7 is presented as a design success, but it requires a trust assumption (honest anchor RS) that undermines the primary IND-UNL-AS claim when delegation is in use. These two sections contradict each other and a careful adversary — or NCUA examiner reviewing the spec — will find the gap.

**In-threat-model?** **Yes, partially** — construction acknowledges it but must tighten the claim boundary. The title claim ("cryptographically unlinkable … even under adversarial AS") must be scoped to the non-delegation case, or the delegation circuit needs a blinded `scopeCommitment` (per-scope variant) so the delegation anchor does not produce a global correlation handle.


## Persona: rfc7662_advocate

---

### Attack 1: `scopeCommitment` Is a Cross-Scope Correlation Handle That Breaks the Primary Use Cases

**Attack:**
Section 2 of the construction outputs `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output**. Both inputs are deterministic per agent: `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` encodes only fixed enrollment-time fields, and `permBitmask` is also per-agent and fixed. Therefore `scopeCommitment` is **the same value in every proof this agent ever generates, across all scopes**.

The construction acknowledges this in §4 ("it is the same across scopes for the same agent") and offers a "compile-time flag" to suppress it when delegation is not in use. But:

1. The **healthcare delegation scenario** (§7, secondary) is the construction's most prominent deployment story. It **requires** delegation, therefore `scopeCommitment` is necessarily public in that scenario.
2. Any RS that receives a delegation-enabled proof and colluding with the AS immediately has a stable per-agent correlation handle. The IND-UNL-AS game in §3 assumes the adversary controls the AS plus up to `k-1` RSes. If even **one** of those RSes receives a delegation proof, the game is lost.
3. The trust partition in §4 ("delegation requires at least one honest RS in the chain") quietly narrows the unlinkability guarantee to non-delegating proofs — but this is not stated in the main claim, which asserts unlinkability "even under an adversarial AS."

**Why it works against the construction:** The reduction sketch in §4 reduces cross-scope linkability to PRF distinguishing advantage on `scopePseudonym`. That reduction is valid **only** when `scopeCommitment` is suppressed. The construction has two protocol modes (delegation on/off) with materially different security properties, but presents a single claim and a single IND-UNL-AS game. The game definition in §3 does not condition on whether `scopeCommitment` is public.

**In-threat-model?** Yes — this is a gap the construction must address. The formal game must either (a) exclude delegation from the unlinkability claim, or (b) introduce a `ScopeBlindCommitment` that randomizes per-proof.

---

### Attack 2: `agentMerkleRoot` Creates Enrollment-Cohort Fingerprints; RFC 8707 Audience Binding Does Not

**Attack:**
The `agentMerkleRoot` is a **public output** shared across all proofs. Section 4 dismisses this: "all agents share the same root — it reveals the set, not the individual." This is true only if the Merkle root is stable across all agents and all time. In practice:

- The agent Merkle tree is **append-only and growing**. The tree root at the time of proof generation depends on how many agents are enrolled. A Merkle proof for a leaf at index `i` is valid against root `R_t` only when `R_t` reflects at least `i` leaves.
- Agents enrolled in a small early cohort (e.g., the first 50 agents in the CU*Answers CUSO pilot) will always produce proofs against a **distinct root** that identifies them as early enrollees. An adversary who observes `agentMerkleRoot = R_early` on two proofs to two different RSes trivially links them to the early-cohort anonymity set — which may be tiny.
- The construction does not specify a "padding to power-of-two" enrollment policy or a root refresh policy. Without one, sparse early enrollment produces roots with near-unique correlation handles.

Compare with RFC 8707 resource indicators: an audience-bound token carries `aud = "merchant-a.example.com"`. The AS sees the audience at issuance, but the **token itself** carries no enrollment-epoch fingerprint visible to RSes. The Bolyra proof's `agentMerkleRoot` leaks more cohort information to RSes than an RFC 8707 audience-bound access token leaks to the AS.

**Why it partially works:** The construction's §4 dismissal is too casual. "Reveals the set" is only a weak argument when the set is large and the root is stable. For the primary credit-union pilot scenario (small early adoption, frequently updated tree), the anonymity set collapsed by `agentMerkleRoot` may be single-digit.

**In-threat-model?** Yes — the construction should specify a minimum anonymity set size for `agentMerkleRoot` and a padding/rotation policy, or omit `agentMerkleRoot` from the public outputs by moving it inside the ZK proof (verifiable by the on-chain registry, not readable by the RS).

---

### Attack 3: The Batch Relayer Is a New AS-Equivalent Centralized Correlator — The Construction Launders the Trust Assumption

**Attack:**
Section 2 introduces a "batch relayer" operated by CU*Answers as the timing-defense mechanism. The relayer collects raw `ScopeBlindAuth` proofs from multiple agents. The construction says the relayer "sees proofs but cannot link them — each proof's `scopePseudonym` is scope-specific and the `credentialCommitment` is hidden."

This is incorrect. The relayer sees the **full unencrypted public inputs** before batching:

| Public input visible to relayer | Correlation value |
|---|---|
| `scopeId` | Identifies the target RS (it's `Poseidon(RS domain)`, but the relayer controls submission routing) |
| `agentMerkleRoot` | Enrollment cohort fingerprint (Attack 2) |
| `scopePseudonym` | Per-(agent, RS) stable identifier across all sessions |
| `nonceBinding` | Per-request, but links to `scopePseudonym` |
| submission timestamp | Within-epoch timing |

A colluding CU*Answers batch relayer can:
1. Build a table of `(scopePseudonym, scopeId, submission_timestamp)` tuples.
2. Because `scopePseudonym` is **stable** for a given (agent, RS) pair across sessions, observe long-run usage patterns: how often does this pseudonym submit proofs to this RS?
3. Correlate submission timing within an epoch to narrow down which physical agent submitted which proof (especially when batch sizes are small in early deployment).

The IND-UNL-AS game in §3 lists "network-level observation of proof submission timing and metadata" as an adversary capability. The **batch relayer has application-layer observation**, not just network-layer. The construction has moved the adversarial observation point from the AS to the relayer, not eliminated it.

**RFC comparison:** RFC 9449 DPoP + a non-logging AS is architecturally equivalent: the AS sees the issuance event, but a policy-controlled AS that does not retain per-request logs provides the same effective privacy against its own analytics team. The construction substitutes one trusted party (AS) with another (relayer) and claims this as "elimination of the AS from the per-request path."

**In-threat-model?** Yes — the construction must explicitly include the batch relayer in the adversary model, prove that the relayer cannot de-anonymize with only the public inputs it sees, or redesign the relayer to receive only opaque ciphertext.

---

### Attack 4: The "Structural Impossibility" Argument Overstates — Per-RS DPoP Keys Achieve RS-Layer Unlinkability Without ZK, and the Residual Gap Is Narrower Than Claimed

**Attack (using RFC 9449 + OIDC PPID):**

The construction's §8 lists five "structural impossibilities." Impossibility 1 claims: "PPID hides the `sub` from RSes but NOT from the AS itself." Impossibility 2 claims "no mechanism for the agent to locally derive an RS-specific pseudonym." Both overstate the gap.

**Achievable with RFC toolbox:**

- **Per-RS DPoP keys (RFC 9449):** If the client registers a distinct DPoP key per resource server and rotates keys per session, the DPoP key thumbprint visible to the RS is different at every RS. This is locally derivable (e.g., `HKDF(master_key, RS_domain)`) and provides RS-level pseudonymity without AS involvement at proof time.
- **Pairwise subject identifiers (OIDC Core §8.1):** The AS computes `sub = HMAC(sector_identifier || local_account_id, salt)` per sector. RSes see different `sub` values. This is AS-computed but it means the RS cannot correlate — only the AS can.
- **JWT introspection response (draft-ietf-oauth-jwt-introspection-response):** Introspection is off the hot path once the RS caches the signed JWT. AS-observable events become infrequent.
- **Non-logging AS policy:** NCUA Regulation V and similar financial privacy regulations require opt-out for affiliate data sharing. A compliant AS that does not log per-request `(agent, RS, timestamp)` tuples achieves the same practical privacy the construction claims.

**What the RFC toolbox genuinely cannot do:**
The construction's real differentiator is the **adversarial AS** case: an AS that actively WANTS to correlate agent activity and has legal authority to do so. In that case, no RFC mechanism prevents AS-side correlation because the AS is the root of trust. Bolyra's ZK-local proving breaks this root dependency.

**But the construction should name this more precisely.** The formal claim ("adversarial AS that actively attempts to correlate") corresponds to a scenario where the financial institution operating the AS has been compromised, coerced (FISA, subpoena), or is itself the adversarial actor. That is a real scenario — especially in the credit-union context where the AS is the member institution — but it is a **narrower** scenario than §8's framing implies. A more honest comparison baseline would be: "An RFC 9449 + per-RS DPoP key + honest AS provides RS-layer unlinkability. Bolyra additionally provides AS-layer unlinkability. Here is the threat scenario where the AS-adversary assumption is load-bearing: [specific case]."

**In-threat-model?** Partially. The construction survives this attack for the adversarial-AS scenario, but the "structural impossibility" language in §8 is technically false for the RS-unlinkability layer. The paper should partition the comparison: "For RS-layer unlinkability, RFC 9449 + per-RS DPoP suffices. For AS-layer unlinkability (adversarial issuer), no RFC mechanism suffices and ZK-local proving is the only known approach."

---

**Summary table:**

| Attack | Survives? | Required fix |
|---|---|---|
| `scopeCommitment` cross-scope correlation | No (construction fails for delegation proofs) | Randomize per-proof or exclude from IND-UNL-AS claim |
| `agentMerkleRoot` enrollment-cohort fingerprint | No (small-cohort deployments collapse anonymity set) | Padding policy + minimum anonymity set bound |
| Batch relayer is a new AS-equivalent correlator | No (relayer sees public inputs including `scopeId`) | Relayer must receive opaque ciphertext or be in adversary model |
| RFC 9449 per-RS DPoP achieves RS-layer unlinkability | Partial (construction survives for adversarial-AS; overstates impossibility otherwise) | Narrow the comparison claim; distinguish RS-layer vs AS-layer unlinkability |


## Persona: spiffe_engineer

---

### Attack 1: `scopeBlindingSecret` is a Long-Lived Correlation Key — SPIRE Rotates This Away Automatically

**Attack:**
Section 5 states that `scopeBlindingSecret` is "generated once at agent enrollment and stored alongside the agent's credential material." This is a 251-bit scalar that never rotates. Every `scopePseudonym` ever produced — across every RS, for the lifetime of the agent — is derived from this one secret. If it leaks (memory scrape, side channel, compromised workload runtime), the adversary can recompute `Poseidon2(scopeId_i, scopeBlindingSecret)` for any scope the agent ever touched, retroactively linking every session the agent had across every RS.

SPIRE's SVID model solves this differently: the SPIRE agent delivers short-lived X.509 SVIDs (default 1-hour TTL) via a local Workload API socket. Key material is ephemeral and re-attested each rotation. An attacker who compromises a workload at time T learns nothing about sessions before T.

The construction has no rotation mechanism for `scopeBlindingSecret`. If the agent rotates it, its `scopePseudonym` at every RS changes — breaking account continuity at those RSes (§7: "Within a single scope, Alice's agent always produces the same `scopePseudonym_A`"). So rotation is structurally impossible without out-of-band re-registration at every RS that holds the old pseudonym. The construction trades ephemeral-key safety for determinism, and the tradeoff is never acknowledged.

**Why it works / why it fails:** The construction's zero-knowledge argument proves unlinkability assuming `scopeBlindingSecret` is never revealed. It says nothing about the secret's lifetime or how to bound blast radius if it is. The IND-UNL-AS game (§3) treats the blinding secret as an opaque challenger-held value and never models the compromised-workload-at-T threat. The game is weaker than the deployed threat model.

**In-threat-model?** No — the construction must address `scopeBlindingSecret` rotation and define the blast radius on compromise. A forward-secret variant (e.g., ratchet `scopeBlindingSecret` per epoch using the previous value as input to a KDF) is feasible but adds significant complexity not present in the draft.

---

### Attack 2: The Batch Relayer Is a Centralized Correlation Oracle — Structurally Weaker Than SPIRE's Node Agent Model

**Attack:**
Section 2 ("Anti-timing gadget: Batch submission envelope") introduces a "batch relayer" that collects proofs from multiple agents and submits them in fixed 30-second epochs. The claimed advantage is `1/m` per epoch timing correlation advantage.

Here is what the relayer actually sees before batching:
- The proof bytes from Alice's agent (at submission time T_1, pre-epoch)
- The destination RS routing header (the relayer must know where to forward the verified proof)
- The proof-arrival timestamp within the epoch

The construction says "the relayer sees proofs but cannot link them." But the relayer can link submission-to-routing: it receives Alice's proof at T_1 destined for Merchant-A, and Bob's proof at T_2 destined for Merchant-B. The `scopePseudonym` values are unlinkable cryptographically, but the relayer has the pre-batch `(agent-IP, RS-destination, arrival-time)` tuple — all in plaintext at the transport layer. If the relayer is run by CU*Answers (§7: "CU*Answers batch relayer"), it is an infrastructure counterparty that the CU itself trusts and audits. The adversarial AS need only subpoena CU*Answers.

SPIFFE handles this via the Workload API: the SPIRE agent runs *on the same node* as the workload and delivers SVIDs over a local Unix domain socket. There is no intermediary. The workload authenticates directly to the target RS using its SVID. No third party handles the credential in transit.

The construction's relayer is the privacy-critical path and gets no formal trust model. It is treated as an architectural diagram element, not a threat actor.

**Why it works / why it fails:** The batch relayer defeats AS-level timing correlation (the AS does not see individual submissions). It does NOT defeat a relayer-as-adversary or AS-that-subpoenas-the-relayer. The IND-UNL-AS game never mentions the relayer as a component — the game implicitly assumes proof submission is magically anonymized before the AS sees it. In practice, the relayer is on the critical path and needs its own threat model entry.

**In-threat-model?** No — the construction's game definition and security argument treat the batch relayer as a trusted anonymous channel. This must be justified formally (e.g., relayer uses anonymous routing, or is decentralized, or uses a mixnet). Alternatively, the relayer trust assumption must be stated explicitly as an out-of-scope dependency.

---

### Attack 3: You Are Reinventing SPIRE's Pluggable Attestor at the Wrong Layer — Contribute a ZK Node Attestor Instead

**Attack (infrastructure-layer):**
SPIRE has a pluggable attestor architecture. Node attestors today include AWS IID, TPM 2.0, k8s PSAT, and custom plugins. A ZK-based node attestor would let a workload prove "I am an enrolled Bolyra agent with permission bitmask P" to a SPIRE server, which would then issue a standard JWT-SVID or X.509 SVID with appropriate SPIFFE ID and SAN extensions carrying the Bolyra claim set. The SVID is then usable everywhere SPIFFE is understood: Envoy sidecar, WIMSE token exchange, AWS IAM Roles Anywhere.

draft-ietf-wimse-arch (WIMSE) already scopes workload-to-workload token exchange with selective disclosure as a design goal. Contributing `scopePseudonym` derivation as a WIMSE "workload identifier privacy" extension would give this construction standards-track leverage, interoperability with existing SPIFFE deployments, and IETF review — rather than requiring every RS to integrate a bespoke Bolyra verifier.

The construction's Section 8 argues five "structural impossibilities" in OAuth/OIDC. None of them address SPIFFE+WIMSE. The omission is conspicuous: WIMSE explicitly addresses the agent-identity-at-RS problem, and SPIFFE's PPID-analog (SPIFFE ID path scoping, e.g., `spiffe://trust.example/agent/alice/scope/merchant-a`) already provides RS-specific identifiers without a new circuit.

**Why it works / why it fails:** The construction is valid as a standalone protocol. The SPIFFE-layer argument is not "this attack breaks the ZK proof" — it is "you are solving this at the wrong abstraction and will not achieve adoption." In practice, a Fortune 500 running SPIRE for its 50,000 workloads will not rip out SPIRE to replace it with a Circom circuit. They will ask for a SPIRE plugin. If Bolyra cannot answer "here is how you run this alongside SPIRE," it has an adoption gap that undermines the healthcare and CU deployment scenarios in §7.

**In-threat-model?** The IND-UNL-AS game is not broken by this. But the *deployment model* is underspecified: the construction never addresses how a SPIFFE-native environment integrates, whether an X.509 SVID can carry a `scopeBlindingSecret` reference, or how the CU's existing SPIRE deployment interacts with the on-chain Merkle tree. The §7 scenario assumes a greenfield Bolyra deployment. The differentiation claim requires a comparison to SPIFFE+ZK-attestor that does not exist in the construction.

---

### Attack 4: The IND-UNL-AS Reduction Is Incomplete for Multi-RS Collusion and `scopeCommitment` Leaks the Agent-Level Fingerprint

**Attack (cryptographic layer):**
The reduction sketch in §4 argues that cross-scope linking requires correlating `Poseidon2(scopeId_A, sbs_b)` with `Poseidon2(scopeId_B, sbs_b)`, and that PRF security makes these computationally independent. This is correct for two RSes.

The game allows the adversary to control up to `k-1` of `k` RSes. When the adversary controls `k-1` RSes, they accumulate `k-1` PRF evaluations: `{Poseidon2(scopeId_i, sbs_b)}` for `i=1..k-1`, all at known inputs `scopeId_i`. The reduction sketch invokes "PRF security" without specifying whether it is the single-evaluation definition (one oracle query) or the multi-evaluation definition (polynomially many oracle queries). Standard PRF definitions are multi-evaluation secure, so this is technically covered — but the sketch should state it explicitly because the adversary's advantage bound changes: it is `(k-1) * ε_PRF` by a hybrid, not just `ε_PRF`.

More concretely: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is exposed as a **public output** (§2, public outputs table). The construction acknowledges this: "it is the same across scopes for the same agent." Section 4's refinement says it can be omitted when delegation is not invoked. But this is a compile-time flag — the circuit is either the delegation-capable variant (leaks `scopeCommitment`) or the delegation-free variant (no `scopeCommitment`). There is no hybrid. A single agent that ever uses delegation at any RS reveals its `scopeCommitment` to that RS, and that `scopeCommitment` is the same value it would reveal at any other RS that requests delegation. The adversary controlling k-1 RSes can check: "does this `scopeCommitment` match what we saw at RS-j?" across colluding RSes, even without breaking the PRF.

The security argument's §4, point 5 tries to dismiss this via Groth16's ZK property: "`scopeCommitment` is hidden behind Groth16's zero-knowledge property." But `scopeCommitment` is explicitly listed as a **public output**, not a private input. Public outputs are visible on-chain. Zero-knowledge hides the *witness*, not the public outputs.

**Why it works / why it fails:** For the non-delegation case (circuit variant without `scopeCommitment`), the PRF reduction is sound modulo the multi-evaluation gap. For the delegation case, `scopeCommitment` is a deterministic, scope-independent fingerprint of the agent's credential that is visible on-chain to any RS the agent delegates through. Any two colluding RSes that both receive delegated credentials from the same agent can link those delegations via matching `scopeCommitment` values — no PRF break required.

**In-threat-model?** Partially. The construction acknowledges the `scopeCommitment` issue and proposes a compile-time flag. The threat is **in-model** for the non-delegation circuit variant. For the delegation variant, the construction explicitly carves out "delegation requires at least one honest RS" — but does not state that cross-scope unlinkability is **broken** (not merely degraded) when the agent uses delegation at two colluding RSes. This needs to be stated as an explicit limitation, not buried in a parenthetical refinement.
