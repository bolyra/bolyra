# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: Enrollment Metadata Graph — The AS Already Has Enough

**Attack:** The construction correctly removes the AS from the per-scope authorization path. But §7 concedes enrollment is "one-time, AS-visible": SECU sees the credential commitment, the permission bitmask `[payments, loans, insurance]`, and the enrollment timestamp. Now layer in what the adversarial AS also sees that §3 does not model:

- **On-chain Merkle root updates are public.** §5 maps "Root history verification" to a 30-entry circular buffer on-chain. Every enrollment transaction that updates the root is observable by anyone watching the chain — including SECU. The root update timestamp is a coarse proxy for agent activity bursts.
- **RS-side dispute signals flow back to SECU out-of-band.** In a real credit union deployment (§7), merchants file chargebacks, insurance providers file claims, and loan originators submit underwriting requests — all through SECU's existing banking rails. SECU correlates the settlement timestamps of those disputes with the enrollment record and reconstructs a probabilistic merchant graph without ever seeing a single scopeNullifier.

The T-batch mitigation in §3 and §7 (500ms jitter + random delay ∈ [0, 2s]) addresses per-session proof generation timing within a single window. It does nothing about week-scale or month-scale settlement timing correlations. The game defined in §3 (IND-UNL-AS) models A querying proofs in a single challenge phase; it does not model A correlating enrollment timestamps against out-of-band banking event streams over time.

**Why it works / why it fails:** The cryptographic claim survives — SECU cannot compute `scopeNullifier_B` from `scopeNullifier_A`. But the *operational privacy claim* in §7 ("SECU must not learn which merchants a member's agent transacts with, GLBA Reg P") can be violated without any cryptographic break. The construction conflates cryptographic unlinkability with operational privacy.

**In-threat-model?** No — §3's threat model does not include out-of-band settlement data, on-chain root update timestamps, or multi-session temporal correlation. The construction must either (a) expand the threat model to explicitly exclude these channels and explain why, or (b) argue that T-batch extends to day-scale patterns.

---

### Attack 2: `agentSecret` Is a God Key With No Rotation Story

**Attack:** §2 defines `agentSecret = Poseidon2(operatorSecret, modelHash)` — a deterministic derivation from the operator secret. Every `scopeNullifier` for every scope the agent ever visits is a deterministic function of this one secret: `Poseidon2(scopeId_i, agentSecret)`. There is no blinding, no epoch, no forward secrecy.

§3 states the adversary "does NOT control the agent's local computation environment." For the SECU deployment in §7, the agent's local computation environment is a cloud VM running at AWS us-east-1 (this is the Bolyra deployment context per CLAUDE.md). Cloud VMs are not unconditionally trusted — they are covered by the operator's SOC 2 scope, subject to hypervisor vulnerabilities, and accessible to cloud provider employees under lawful process.

If `operatorSecret` or `agentSecret` is ever extracted:
- All past and future `scopeNullifier` values are computable for all scopes.
- There is no rotation mechanism described. Re-enrollment generates a new `credCommitment` with a new Merkle leaf, but §2 says `agentSecret` is derived from `modelHash` — changing the secret requires re-keying the model identity, which may not be feasible without re-enrolling every downstream delegation chain (§5 maps delegation to a separate circuit).
- The construction's unlinkability guarantee collapses retroactively across the entire scope history.

Compare: Auth0 issues rotating refresh tokens with revocation endpoints, short-lived access tokens, and HSM-backed signing keys under SOC 2 Type II controls. The construction offers none of these.

**Why it works / why it fails:** The cryptographic construction is sound under the assumption that `agentSecret` is uncompromised. But the construction provides no key lifecycle management — no rotation, no compromise recovery, no forward secrecy. This is not a gap in the ZK proof; it is a gap in the protocol design that an enterprise procurement team will find immediately.

**In-threat-model?** No — §3 models a static adversary who cannot extract the agent secret. Operational key compromise is not addressed. The construction must add an agentSecret rotation protocol and describe its interaction with the Merkle tree enrollment state.

---

### Attack 3: Every RS Must Deploy a ZK Verifier — This Is Harder Than OAuth

**Attack:** §2's "no AS interaction" design requires every Resource Server to:

1. Run or trust a PLONK verifier (on-chain per §5: "agentMerkleRoot is in the on-chain root history buffer").
2. Maintain connectivity to the on-chain root history buffer to validate Merkle roots.
3. Implement the `scopeNullifier` replay detection store — a new per-scope revocation registry.
4. Speak the ScopeIsolatedAuth proof format instead of RFC 6750 Bearer tokens.

In the SECU deployment (§7), the resource servers are "merchant payment processors, loan originators, and insurance providers." These are existing SaaS products — Stripe, Plaid, Fiserv, Jack Henry. Their integration story today with Auth0/WorkOS is: add the Auth0 SDK, configure the JWKS endpoint, validate the JWT. Total engineering time: 2-4 hours. The construction requires them to add a PLONK verifier library, a blockchain RPC connection, and a nullifier store.

§6 says on-chain verification is "~2ms (one pairing check)" — but this assumes the RS is running on-chain. Off-chain PLONK verification requires deploying and maintaining a verifier library in whatever language the RS is written in (Java for Jack Henry, Go for Stripe, Ruby for legacy CU vendors). The construction does not address RS-side SDK distribution, language support, or the upgrade path when the PLONK SRS is updated.

**Why it works / why it fails:** The unlinkability claim is correct — an RS that implements the verifier correctly cannot link across scopes. But the claim is vacuous if no RS deploys the verifier. The construction's privacy guarantee requires adversarial RSes to cooperate with the protocol. A merchant that simply logs the HTTP `Authorization` header (which contains the proof blob) and phones home to SECU breaks the guarantee operationally, without any cryptographic attack.

**In-threat-model?** No — the threat model assumes RS instances "receive every (proof, publicSignals) tuple" and nothing else. It does not model RS-side logging of proof blobs, RS adoption friction, or the multi-language verifier deployment problem. The construction must address the RS SDK story or the privacy claim is only as strong as voluntary RS compliance.

---

### Attack 4: The Proving Time Claim Is Benchmarked on a Server, Not an MCP Client

**Attack:** §6 claims "< 3 seconds on commodity hardware (PLONK at ~5,000 constraints/second on modern CPUs with WASM prover)" for 15,600 constraints. This figure is cited without benchmark source, hardware spec, or browser/runtime context.

MCP clients run in environments that include: VS Code extensions (Electron, V8 JIT), mobile banking apps (iOS/Android, no WASM SIMD on older devices), browser-based financial portals (Safari on iPhone 12, which cannot use SharedArrayBuffer), and embedded systems in ATM kiosks. WASM PLONK provers without SIMD/multithreading fall to roughly 500-1,000 constraints/second on constrained runtimes — pushing the 15,600-constraint ScopeIsolatedAuth proof to 15-30 seconds.

The construction acknowledges in §2 the target is "< 5 seconds" for AgentPolicy (16,000 constraints) and "<3 seconds" for ScopeIsolatedAuth (15,600 constraints). The §6 comparison table lists HumanUniqueness at ~13,000 constraints targeting "< 15s" under Groth16 — a different proof system. The PLONK target of <3s would need to be verified against the same hardware/runtime baseline as the 15s Groth16 target, or the comparison is meaningless.

WorkOS and Auth0 issue tokens in <100ms measured at the API boundary from any client. The construction has no answer for the user who asks "why does my agent pause for 3-30 seconds every time it switches merchants?"

**Why it works / why it fails:** The construction correctly identifies that the proving time target is per-scope, not per-session (the agent caches the proof or batches). But §7's "per-merchant authorization" model implies a new proof is generated each time the agent accesses a new scope — meaning latency is paid once per (agent, scope) pair, potentially on every cold start. The construction does not address proof caching, proof reuse across sessions, or the latency UX for mobile deployments.

**In-threat-model?** No — performance is not in scope for the IND-UNL-AS game. But this is a deployment blocker that the construction must address with concrete benchmarks on realistic client environments (WASM in Safari, Android WebView) or the <3s claim will be the first thing a procurement engineer disproves in a PoC.


## Persona: cryptographer

---

### Attack 1: scopeId is a Public Input — the IND-UNL-AS Game is Trivially Won

- **Attack**: The adversary A reads `public_signals[5]` of `π_left`. The PLONK verifier requires `scopeId` as a public input (§2 signal layout, index 5). Therefore `π_left` embeds `scopeId_b` in its verifier input. A compares this value to `scopeId_0` from the challenge tuple `(π_left, scopeId_0)`. If equal, `b = 0`; otherwise `b = 1`. Advantage is 1, not negl(λ). No cryptographic assumption is needed.

- **Why it works**: The construction has an inherent tension it never resolves. The RS must verify that the proof covers *its specific scope* — this requires `scopeId` to be a public input committed to by the proof. But the IND-UNL-AS game asks whether an adversary can determine *which proof belongs to which scope*. With `scopeId` in the public signals, a proof is literally a signed statement "I am authorized for `scopeId_X`." There is no notion of hiding the scope from an adversary who holds the proof.

- **In-threat-model?**: The adversary A is given the proofs. The AS sees all issuance events and receives `(proof, publicSignals)` from colluding RS instances (§3: "A receives every `(proof, publicSignals)` tuple presented to the colluding RS instances"). The public signals are not hidden from A.

- **Construction must address**: The reduction sketch in §4 asserts in Hybrid 3: *"The public inputs `(scopeId_0, scopeId_1, requiredScopeMask, currentTimestamp)` are the same in both orderings."* This is false. `π_left` has `scopeId_b` in its public signals; `π_right` has `scopeId_{1-b}`. The orderings differ by exactly the bit b that A must guess. The reduction collapses. Either (a) reformulate the game to not hand A the raw proofs (only outputs like authTag), or (b) redesign the circuit so scopeId is committed to privately and the RS receives a scope-binding separately from the proof — but then RS scope verification changes fundamentally.

---

### Attack 2: agentMerkleRoot is a Cross-Scope Fingerprint

- **Attack**: Every ScopeIsolatedAuth proof from the same agent outputs the same `agentMerkleRoot` (public output, index 0) until the Merkle tree is updated. A colluding RS-A and RS-B each receive proofs with `agentMerkleRoot = R` for the same agent. They share this value with the AS. The AS, which manages the Merkle tree (§3: "Challenger generates Bolyra system parameters (Merkle trees, verifier contracts)"), can intersect `agentMerkleRoot` values across its RS partners. All proofs with the same root came from agents enrolled in the same epoch — and if tree updates are infrequent, `agentMerkleRoot` is stable across many authorizations from the same agent.

- **Why it partially works**: In a small deployment (SECU with few AI agent enrollments), the set of agents sharing a given `agentMerkleRoot` may be small — possibly a single batch. Combined with timing metadata, the AS can partition agents by root and then narrow further. In the SECU scenario (§7), SECU *is* the AS and controls Merkle tree update frequency. It can deliberately stagger insertions to ensure each root corresponds to exactly one agent — trivially breaking unlinkability by construction.

- **Why it partially fails**: In a large anonymity set (many agents enrolled per epoch), `agentMerkleRoot` provides k-anonymity of set size N, not individual de-anonymization. The PRF argument on `scopeNullifier` still holds. This is an anonymity-set attack, not a direct cryptographic break.

- **In-threat-model?**: **No** — the construction's threat model (§3) grants A control of the AS and the enrollment log, but the IND-UNL-AS game does not account for A using `agentMerkleRoot` as a grouping key. The game should specify either (a) how often the Merkle tree is updated relative to the challenge, or (b) that A cannot perform tree-update timing attacks. The SECU scenario actively makes this worse: a single credit union with deliberate epoch management could collapse anonymity to size 1. This must be addressed in the security definition or the deployment guidance must prohibit single-agent epochs.

---

### Attack 3: T-real Timing — §7 is a Deployment Hint, Not a Security Argument

- **Attack**: The adversary observes per-proof generation timestamps in the T-real model. Proof generation for ScopeIsolatedAuth takes ~3 seconds on commodity hardware (§6). An agent accessing RS-A at time t₀ produces a proof completing at t₀ + δ₀; accessing RS-B at t₁ produces one completing at t₁ + δ₁. The AS, which observes encrypted traffic metadata (§3: "A sees encrypted traffic metadata (timing, packet sizes)"), watches for outbound TLS connections to RS URIs and correlates them to specific proofs. PLONK proof size is ~1 KB (§6) — distinguishable from other traffic.

- **Why §7 does not address this**: The T-batch mitigation in §7 requires the agent to "batch all scope authorizations into a single timing window (±δ)." This is only viable if the agent knows in advance which scopes it will access — i.e., it must pre-generate all proofs before presenting any of them. In the healthcare variant (§7), an agent visits Provider-A and *then*, based on that visit's outcome, decides to visit Provider-B. Pre-batching is impossible for adaptive workflows. The construction says T-batch provides security; the deployment says T-real is deferred. But §3 defines T-real as an adversary model the construction is supposed to handle (it is listed, not excluded). Saying "security degrades to computational indistinguishability of proof generation times" without defining what that means is not a security argument.

- **In-threat-model?**: **No** — T-real is enumerated in the game (§3) and the claim states "empirical test showing colluding AS+RS cannot de-anonymize" as a gap to close. The timing side-channel in adaptive workflows (non-batchable) is not addressed by the ±2s jitter proposal. The construction should either (a) formally exclude T-real from its security claim and restrict the claim to T-batch, or (b) provide a formal argument (e.g., differential privacy over timing distributions) for the T-real model.

---

### Attack 4: agentSecret Derivation is Underspecified — Security Reduces to an Undefined Assumption

- **Attack**: The construction states `agentSecret = Poseidon2(operatorSecret, modelHash)` with the qualifier "e.g." (§2 integration paragraph). `modelHash` is a public field in `credCommitment = Poseidon5(modelHash, operatorPubkeyAx, ...)`, visible to the AS at enrollment. If `operatorSecret` is the operator's EdDSA signing key material (the key that signs enrollment requests — the AS verifies this signature to authorize enrollment), then the AS has the signing public key `(operatorPubkeyAx, operatorPubkeyAy)` and `modelHash`. A knows that `agentSecret = Poseidon2(operatorSecret, modelHash)`. Breaking DLP on Baby Jubjub is the only barrier. If a different derivation is used (e.g., `operatorSecret` is an independent scalar), the construction leaves this unstated.

- **Why the "e.g." is dangerous**: The PRF reduction in §4 assumes `agentSecret` is unknown to A. Whether this holds depends entirely on how `agentSecret` is derived — a fact the construction defers with "e.g." The security proof treats `agentSecret` as a uniformly random secret, but the concrete construction derives it deterministically from `operatorSecret` and `modelHash`. If `operatorSecret` is reused across enrollment contexts (e.g., same operator key for multiple agents), then a compromise of one agent's context leaks `agentSecret` for all agents enrolled under that operator key. There is no forward secrecy on `agentSecret` — a single key compromise retroactively breaks all past and future scope nullifiers for all agents under that operator.

- **In-threat-model?**: **Partially** — the threat model excludes "the agent's local computation environment" from adversary control. But it does not address operator key compromise, multi-agent operators, or key derivation forward secrecy. The Poseidon-PRF assumption treats `agentSecret` as a long-term PRF key with no rotation mechanism. The construction should (a) specify the exact derivation of `agentSecret` as a normative definition, not an example; (b) define a key rotation or forward-secrecy mechanism; (c) address the multi-agent operator threat where one operator key covers many agents.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Paradox

- **Attack:** The construction's core value proposition — the AS never sees per-scope authorizations — is simultaneously the feature that destroys the credit union's ability to produce a compliant audit log. I point my examiner to **NCUA Part 748, Appendix B, §III.C**: my security program must include "monitoring of systems to detect actual and attempted attacks." I also point to **GLBA Safeguards Rule 16 CFR §314.4(h)**: I must "evaluate and adjust your information security program" based on "the results of the monitoring and testing." If SECU-as-AS is architecturally excluded from the per-scope authorization path (§2, "No AS interaction occurs"), SECU cannot produce access logs for member agent transactions to Merchant RS-A or Insurance RS-B. §7 acknowledges this: "This is the last time SECU observes the agent's authorization activity." The construction is selling GLBA Reg P compliance as its justification while simultaneously eliminating the audit substrate that GLBA Safeguards and NCUA Part 748 require. My examiner will ask me to produce a log of access to member financial data. I cannot. The construction has no answer.

- **Why it works / why it fails:** The construction addresses AS-side *correlation* (§2, §4) with cryptographic rigor but never addresses AS-side *audit obligation*. §7 mentions Reg P as a motivation but does not reconcile it against §314.4(h) or Part 748 monitoring requirements. This is not a ZK limitation — it's an architectural omission.

- **In-threat-model?** No — construction must address. The IND-UNL-AS game (§3) is defined to protect member privacy *from* the AS, but never addresses the credit union's affirmative obligation to *maintain* controlled visibility for regulatory purposes. A privacy-preserving design that also satisfies audit obligations (e.g., encrypted per-scope logs the AS can open only under dual-control for examiner production) is not described.

---

### Attack 2: Key Custody — Where Does `operatorSecret` Live?

- **Attack:** §2 states `agentSecret = Poseidon2(operatorSecret, modelHash)`, committed at enrollment, "never revealed," and used to generate proofs "locally" by the agent. I ask the question my vendor management policy requires: where is `operatorSecret` stored? The construction never says. If it is in browser storage (LocalStorage, IndexedDB, WebCrypto non-extractable key), a single XSS vulnerability, malicious browser extension, or compromised browser profile silently exfiltrates the key that controls all scope-specific nullifiers for that agent forever — no revocation, no detection, because the AS never sees per-scope activity. If it is in a server-side agent runtime, then the *operator* (a third party, not the member) controls the key, which means the construction's privacy claim shifts: unlinkability holds against the AS but not against the operator who holds `operatorSecret`. **NCUA Letter 01-CU-20** and my Vendor Management Policy require me to assess and control how third parties handle member data. I cannot complete that assessment when the key material is in an environment the credit union does not control and cannot audit.

- **Why it works / why it fails:** §2 says `agentSecret` is "committed to during enrollment but never revealed" — this is a cryptographic claim about the commitment, not an operational claim about storage. §7 says the agent "generates a ScopeIsolatedAuth proof locally" but is silent on the trust model for the local environment. The entire security argument (§4 reduction) assumes `agentSecret` is not leaked to the adversary — but the key custody mechanism that enforces this assumption is absent.

- **In-threat-model?** Partially. §3 states the adversary does NOT control "the agent's local computation environment." This assumption is declared but not operationalized. The construction must specify: (a) acceptable key custody options (TEE attestation, HSM, hardware wallet), (b) how the credit union verifies the agent's environment satisfies the assumption at onboarding, and (c) what NCUA-acceptable third-party risk documentation covers the key storage layer.

---

### Attack 3: T-Real Timing — The Construction Punts Without a Proof

- **Attack:** §3 defines three timing models: T-none, T-batch, T-real. Security in T-none is formally argued (§4 reduction). T-real is acknowledged to cause security degradation — the exact quote: "security degrades to computational indistinguishability of proof generation times (addressed in §7)." I turn to §7. The mitigation is: "The agent batches proof generation for all scopes within a configurable window (default: 500ms jitter + random delay ∈ [0, 2s])." That is an application-layer heuristic. There is no formal argument that this batching strategy achieves T-batch equivalence against a network-level adversary. **FFIEC CAT Domain 3 (Cybersecurity Controls)** and my board require that controls be demonstrably effective, not just plausible. In a high-frequency payment scenario — a member agent hitting three merchants in 200ms each during checkout — the proof generation burst pattern becomes identifiable even within the jitter window, because PLONK proof generation time is deterministic on a given circuit (~3s per §6). An adversary observing TLS handshake timing to three RS endpoints within a 3s window, with the enrollment log, can probabilistically link them to the same enrolled agent. The construction claims this is "addressed" but provides no bound on the adversary's advantage in T-real.

- **Why it works / why it fails:** The gap between §3's acknowledgment of T-real degradation and §7's heuristic mitigation is not closed by a security argument. The reduction in §4 is valid for T-none only. The T-batch claim requires a proof that the batching scheme prevents the T-batch adversary from distinguishing individual proof generation events within the window — this is a separate theorem that does not appear.

- **In-threat-model?** Yes — but the construction explicitly defers it and the treatment in §7 is insufficient. The construction must either (a) provide a formal bound on adversary advantage in T-real as a function of batch window size and proof generation variance, or (b) declare T-real out of scope and document which deployment configurations bring the system into T-batch.

---

### Attack 4: Revocation Without a Mechanism

- **Attack:** §2 Step 5c says RS-A verifies that "`scopeNullifier` is not revoked/reused." Revocation is listed as a verification step but never specified. The on-chain infrastructure described is a "30-entry circular buffer" of Merkle roots (§5, root history buffer). A circular buffer of roots proves membership in a historical tree state — it does not support individual leaf revocation. If a member's agent credential is compromised (e.g., `operatorSecret` exfiltrated), how does SECU revoke that agent's authorization? Options implied by the construction but not stated: (a) removing the leaf requires rebuilding the Merkle tree and rotating the root, which invalidates *all* current proofs until the new root propagates to RS instances; (b) a separate on-chain nullifier revocation registry introduces a linkage vector (looking up a nullifier reveals which scope is being revoked); (c) credential expiry (`expiryTimestamp` in the circuit) bounds exposure but can extend years. My examiner will ask: "If you detect a compromised agent at 2am, what is your revocation SLA and what is the blast radius?" The construction cannot answer because revocation architecture is absent. **NCUA Part 748 Appendix B §III.E** requires incident response procedures including containment. Containment requires revocation. Revocation is unspecified.

- **Why it works / why it fails:** The construction is complete on the *positive* authorization path (enrollment → local proof → RS verification). It is silent on the *negative* path (detection → revocation → RS enforcement). The scope nullifier is deterministic per `(scopeId, agentSecret)` — which is the right design for replay detection — but this same determinism means a compromised agent can continue generating valid nullifiers for any scope until expiry, with no mechanism for the credit union to stop it mid-session.

- **In-threat-model?** No — construction must address. The IND-UNL-AS game models a passive correlation adversary; it does not model an active credential compromise scenario requiring revocation. A complete construction needs: a revocation registry design that does not create a linkage oracle, a specified revocation propagation latency SLA, and an incident response procedure mappable to NCUA Part 748 Appendix B.


## Persona: rfc7662_advocate

I have been shipping RFC 7662 introspection in production since 2015. Every ZK paper I have reviewed overclaims against OAuth baselines by attributing structural impossibility to what is actually a deployment choice. Let me break this one.

---

### Attack 1: The IND-UNL-AS Game Is Trivially Winnable — scopeId Is in Plaintext Public Signals

**Attack:**
The construction defines IND-UNL-AS (§3) as: A wins if it can "determine which proof corresponds to which scope." The Challenger sends A two proofs — `π_left` covering `scopeId_b` and `π_right` covering `scopeId_{1-b}` — alongside the labels `scopeId_0` and `scopeId_1`.

But §2's public signal table (index 5) declares `scopeId` a **public output** of the PLONK proof. A PLONK proof's public signals are plaintext — they are the inputs to the verifier and are transmitted in the clear alongside the proof. A reads `π_left.publicSignals[5]`, compares it to `scopeId_0`, and determines `b` with advantage **1**, not `negl(λ)`.

The game is trivially winnable by any adversary with a PLONK verifier call. No cryptographic attack required.

**Why it fails against the construction:**
It does not fail — this is a correctness flaw in the game definition itself. The construction's intended property is *agent-linkage* across scopes (can A determine that `π_left` and `π_right` originate from the same agent?), not *scope identification* (which scope does each proof cover). Those are different games. The hybrid argument in §4 correctly reasons about agent-linkage but the formal game in §3 does not capture it.

**In-threat-model?** Yes — the construction must fix the game. The correct IND-UNL formulation should present A with two proofs at two known scopes from an unknown mix of one or two agents, and ask A to distinguish "same agent" from "different agents." The current game proves nothing because the challenge is trivially resolved from public inputs.

---

### Attack 2: Merkle Root Epoch Leaks the Enrollment Cohort — Anonymity Set May Be 1

**Attack (citing RFC 7662 in spirit):**
RFC 7662 introspection already faces k-anonymity problems when token populations are small — a well-known operational issue. The same flaw exists here, made worse because the construction provides no remedy.

The `agentMerkleRoot` (public signal index 0) identifies which Merkle root epoch the agent used. The 30-entry root history buffer (§3.1, referenced in Bolyra spec) means the root rotates on some schedule — presumably triggered by new enrollments. The AS controls the Merkle tree and maintains a complete log: `(credentialCommitment, leafIndex, rootAtTime_T)` for every enrollment.

**Attack procedure:**
1. AS observes that root `R_7` was published at time T after enrolling exactly 3 agents: Alice, Bob, Carol.
2. An agent presents a ScopeIsolatedAuth proof to colluding RS-A. Public signals include `agentMerkleRoot = R_7`.
3. AS knows the anonymity set is `{Alice, Bob, Carol}`.
4. RS-A, already holding merchant transaction data, can correlate behavior patterns across 3 candidates — trivially in the common case where only one agent of the three has the right `permissionBitmask` bits set for the merchant scope (also public: `requiredScopeMask`, signal index 3).
5. When `requiredScopeMask` is distinctive (e.g., only one enrolled agent has the `insurance` bit set), anonymity set is **1**. Zero cryptographic attack required.

**Why it fails / survives:**
The Poseidon-PRF argument in §4 is correct *conditioned on the anonymity set being large*. If only one agent uses a given Merkle root, the PRF argument is irrelevant — the AS learns which agent accessed which RS by elimination, without inverting any PRF.

The construction's §7 SECU scenario implicitly assumes a large enrollment pool, but nowhere specifies a minimum anonymity set, a batch enrollment policy, or a protocol for populating the tree before the root is published. RFC 7662 deployments handle this with token population controls; this construction has no equivalent.

**In-threat-model?** Yes — the construction claims "AS learns only that the agent has permission bits" but the Merkle root epoch + public `requiredScopeMask` can reduce the anonymity set to 1 in realistic sparse-enrollment deployments. A k-anonymity lower bound on root epoch population is required.

---

### Attack 3: JWT Introspection Response + Per-RS Policy Already Removes AS from the Correlation Path *at the RS Level* — The Construction's §8 Baseline Comparison Is a Strawman

**Attack:**
Section 8 claims the baseline's "fundamental architectural constraint" is that "every authorization requires AS participation at issuance time." True. But the construction conflates two distinct threats:

- **Threat A**: AS observes which RS an agent accesses (AS-side correlation).
- **Threat B**: RS-A and RS-B can link the same agent across scopes (RS-to-RS correlation).

RFC 7662 + `draft-ietf-oauth-jwt-introspection-response` (signed JWT responses) + RFC 9449 DPoP + OIDC PPIDs already eliminates Threat B without any ZK:

1. RS-A calls introspection with token T. AS returns a signed JWT response containing only attributes relevant to RS-A — PPID_A, audience `rs-a.example`, no cross-RS identifiers. RS-A stores `PPID_A`.
2. RS-B calls introspection with a different token T'. AS returns a JWT with `PPID_B ≠ PPID_A` (pairwise subject identifier per RS). RS-B stores `PPID_B`.
3. RS-A and RS-B, even if they collude and share `PPID_A` and `PPID_B`, cannot link them — the AS generates each PPID as `HMAC(sector_id_RS, sub)`, which is opaque to the RS.
4. DPoP sender-constrains each token to its key, preventing stolen-token forwarding across RSes.

The only remaining question is Threat A: **does the AS see the (agent → RS) mapping?** Yes — but the construction's threat model in §3 declares the AS adversarial. In the SECU scenario (§7), SECU *is* the AS and is bound by GLBA/Reg P. If SECU cannot be trusted to maintain its own introspection logs confidentially, the threat model requires cryptographic enforcement of AS exclusion. But then the question is: **is the AS-adversarial assumption realistic for a regulated credit union?**

I am not claiming cryptographic equivalence. I am claiming the construction's §8 comparison should acknowledge that Threat B is already solved by PPID + per-RS policy, and the *exclusive* differentiator is Threat A (AS-side correlation under a fully-adversarial AS assumption). The table in §8 conflates both threats, making the baseline look weaker than it is.

**In-threat-model?** Partially — the construction survives for Threat A (adversarial AS), which is a real and meaningful property. But §8 should explicitly partition the two threats and acknowledge that Threat B is already addressed by PPIDs, rather than presenting the baseline as uniformly inferior. Failing to do so overstates the ZK system's novelty and makes the formal claim appear to cover more than it does.

---

### Attack 4: blindingNonce Is Private — No Freshness Guarantee, No Liveness Proof, No Entropy Source Specified

**Attack (citing RFC 9449 DPoP §9.1 for contrast):**
DPoP specifies nonce freshness precisely: the nonce is server-issued (RFC 9449 §8), bound to the HTTP request via a `DPoP` header including `htm`/`htu`/`iat` claims, and the RS verifies freshness within a configurable window. The entropy source is the OS CSPRNG; the liveness is enforced by server-issued nonce challenge.

The construction's `blindingNonce` (§2, private input) is described only as "fresh random value per proof." It is:

1. **Unverifiable by the RS**: `blindingNonce` is a *private* input. The RS sees only `authTag = Poseidon2(scopeNullifier, blindingNonce)`. The RS cannot verify that `blindingNonce` is fresh, non-repeated, or even random. A deterministic agent that recomputes `blindingNonce = Poseidon2(agentSecret, counter)` with a predictable counter produces `authTag` values that are deterministic and potentially linkable if the counter is guessable or observable.

2. **No replay detection on authTag**: The RS is instructed (§2, protocol step 5c) to check `scopeNullifier` for replay. But two presentations with the same `scopeNullifier` and different `authTag` values are both accepted if the `scopeNullifier` is fresh. If the agent reuses a `blindingNonce` (bad RNG, VM snapshot, rollback attack), two `authTag` values from the same `(scopeNullifier, blindingNonce)` pair are identical — directly linkable across sessions to the same RS, and potentially collectable by a colluding AS+RS across time.

3. **No liveness guarantee**: DPoP's server-issued nonce proves the token was generated *after* the nonce was issued (liveness). The construction's `blindingNonce` provides no such liveness — a proof generated at enrollment time and withheld until later is indistinguishable from a fresh proof. In the healthcare scenario (§7), a stale proof replayed months later could satisfy the expiry check if `expiryTimestamp` is distant, and the RS has no mechanism to detect the replay via `authTag` (since `scopeNullifier` freshness is the only check).

**Why it survives the PRF argument but fails operationally:**
The Poseidon-PRF reduction in §4 assumes `blindingNonce` is uniform. If it is, the authTag is pseudorandom and provides presentation freshness. But the construction does not specify where `blindingNonce` comes from, how agents generate it, or what happens under entropy failure. RFC 9449 solved this with server-issued nonces precisely because client-side randomness is unreliable. This construction has no equivalent mechanism.

**In-threat-model?** Yes — the construction must specify the `blindingNonce` generation protocol (minimum entropy requirement, CSPRNG mandate, or RS-issued nonce challenge), and define whether `authTag` replay within a scope is detected (it is not currently — only `scopeNullifier` replay is checked). Without this, the authTag's "presentation freshness" claim (§2) is operationally unenforceable.


## Persona: spiffe_engineer

### Attack 1: Your Enrollment Step Is Just SPIRE Without SVID Rotation

- **Attack**: SPIRE already does exactly what `AgentPolicy` enrollment does. The `credCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` inserted into the Merkle tree is structurally identical to a SPIRE server issuing an X.509 SVID: the trust domain root is your Merkle root; the `agentSecret` is the workload private key; the `permissionBitmask` is the SPIFFE ID path policy. You could implement a custom SPIRE node attestor plugin that uses a ZK proof instead of a TPM quote and achieve the same enrollment binding. The question is not whether ZK enrollment is novel — it's whether the *rest of the construction* requires a new protocol or can be layered on top of SPIFFE's Workload API.

- **Why it works / why it fails against the construction**: The construction survives on the *post-enrollment* claim, not the enrollment step. §2 explicitly states: "The AS is never contacted at authorization time." In SPIFFE, every JWT-SVID issuance — regardless of how the node was attested — requires a call to the SPIRE server's Workload API, which in turn contacts the SPIRE server to sign a new JWT with an `aud` claim. SPIRE cannot remove itself from the per-scope authorization path without abandoning SVID issuance entirely. Short-lived SVIDs (the standard is 1-hour TTL) mean the AS sees scope-bearing token requests at minimum every hour. This is structurally the same issuance-log correlation attack that §8 identifies. The SPIFFE ZK attestor extension argument does not escape the SVID issuance bottleneck.

- **In-threat-model?** Yes — construction survives. SPIFFE cannot eliminate AS from per-scope path without abandoning the SVID issuance model.

---

### Attack 2: WIMSE Workload-to-Workload Token Exchange Already Removes the AS From the Authorization Path

- **Attack**: WIMSE draft-ietf-wimse-arch §5.3 defines a workload-to-workload authentication flow where a workload presents an initial token (issued by the AS once) to derive resource-specific credentials via a local token exchange, without contacting the AS for each resource access. Combined with SD-JWT selective disclosure (draft-ietf-oauth-selective-disclosure-jwt), the workload can present only the permission bits relevant to each RS. I co-authored this architecture specifically to address the AS-bottleneck problem. You are describing a WIMSE-shaped construction with a heavier proof system on top.

- **Why it works / why it fails against the construction**: WIMSE's token exchange creates derivative tokens — but the derivation chain is visible to the AS that issued the original credential. SD-JWT hides attributes from the *RS*, not from the *issuer*. The issuer signed a credential containing all possible scopes; it knows which scopes the agent was issued credentials for. SD-JWT does not provide IND-UNL-AS: the game specifically makes the AS the adversary, and the SD-JWT issuer can trivially correlate because it holds the original credential with all disclosed and undisclosed claims. The construction's §8 comparison table captures this correctly: "BBS+ addresses holder-to-verifier unlinkability but does not remove the issuer from the authorization path." WIMSE inherits this property from its OAuth 2.0 foundation. The gap is real and not closed by WIMSE.

- **In-threat-model?** Yes — construction survives. WIMSE/SD-JWT does not protect against issuer-correlation; the IND-UNL-AS game is unsatisfiable within the OAuth grant model.

---

### Attack 3: scopeId Is Plaintext in Public Signals — Enterprise Proxy Kills Unlinkability

- **Attack**: §2 public signal index 5 is `scopeId` — a plaintext `F_p` value in the proof transcript. The protocol flow (§2, step 4) sends `(proof, publicSignals)` directly to RS-A over what the construction assumes is a private channel. In the SECU and Kaiser deployments (§7), all outbound agent traffic routes through enterprise-controlled TLS-terminating proxies, load balancers, or API gateways — infrastructure operated by or auditable by the AS operator. The `scopeId` is not a network metadata signal (timing, packet size); it is a structured field in the proof payload. An AS-controlled proxy that terminates TLS sees `scopeId = Poseidon("https://merchant-a.secu.org/")` in the cleartext HTTP/JSON body after TLS termination. This is not a side-channel — it is direct data exfiltration through authorized enterprise infrastructure. The T-real timing model in §3 parameterizes only *timing* side channels. The threat model (§3) states A sees "encrypted traffic metadata" but explicitly does not include A as a TLS-terminating proxy between the agent and RS.

- **Why it works / why it fails against the construction**: This attack does not reduce to Poseidon-PRF and is not covered by the IND-UNL-AS game as stated. The game gives A the enrollment log and colluding RS outputs; it does not give A the proof transcript in transit. In real enterprise deployments — exactly the SECU scenario in §7 — the AS operator *is* the network infrastructure operator. The construction's AS-exclusion guarantee is cryptographic but the threat model does not match the deployment environment. The construction must either (a) seal public signals to the RS public key so that they are opaque to intermediaries, or (b) explicitly add TLS certificate binding to the public signal set so the RS's identity is cryptographically bound to the proof and a proxy cannot relay it without detection.

- **In-threat-model?** **No — construction must address.** The threat model excludes AS-controlled TLS termination from A's capabilities, but §7 deploys in exactly the network topology where this capability exists.

---

### Attack 4: agentSecret Is Long-Term; Retroactive De-anonymization Window Is Unbounded

- **Attack**: SPIFFE SVIDs have a default TTL of 1 hour; compromise window is bounded to one rotation period. The construction's `agentSecret = Poseidon2(operatorSecret, modelHash)` is deterministic and long-term. The only bound is `expiryTimestamp`, which §7 does not specify — for financial credentials (SECU) this could be months. If `operatorSecret` is stored in a key management system (HSM, Vault, AWS KMS) controlled by the operator, and the operator's KMS is audited or compromised at any point during the validity period, all scope nullifiers `Poseidon2(scopeId_i, agentSecret)` become retroactively computable for any RS URI the adversary can enumerate — and RS URIs are public endpoints. The IND-UNL-AS game (§3) explicitly assumes A does not control the agent's local computation environment. This is formally correct but operationally evasive: `agentSecret` is derived from `operatorSecret`, not generated ephemerally in a TEE. The construction does not specify `operatorSecret` rotation policy, `expiryTimestamp` upper bounds, or key escrow restrictions. An AS that compels disclosure of `operatorSecret` (regulatory subpoena, key escrow for financial compliance) retroactively breaks IND-UNL-AS for the entire credential lifetime. BBS+ credentials with holder binding suffer the same issue, but standard deployments use short-lived BBS+ credentials with hardware binding. The construction is silent on `expiryTimestamp` policy and `operatorSecret` protection requirements.

- **Why it works / why it fails against the construction**: The PRF security argument in §4 is sound *conditioned on `agentSecret` being secret*. The construction's Hybrid 1 replaces `scopeNullifier` with a random value under the assumption that `agentSecret` is secret to A. The reduction holds. But "secret to A" is a game-time assumption, not a deployment guarantee. Without specifying: (a) maximum `expiryTimestamp` bound (e.g., 24 hours), (b) `agentSecret` derivation in a hardware-attested enclave, or (c) `operatorSecret` rotation cadence that re-derives `agentSecret` and re-enrolls into a new Merkle leaf, the practical unlinkability window is the full credential validity period and retroactive compromise is operationally realistic.

- **In-threat-model?** **Partial — construction must address operationally.** The IND-UNL-AS game is formally correct, but the construction must add a §9-class deployment requirement specifying `expiryTimestamp` upper bounds and `operatorSecret` protection level (HSM, no key export, no regulatory escrow exception) to make the game assumption match the threat model claimed in §7.
