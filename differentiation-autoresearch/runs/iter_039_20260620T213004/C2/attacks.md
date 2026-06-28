# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: Latency Regression Kills the Auth Critical Path

- **Attack:** The construction's proof generation takes ~15 seconds (Groth16 on the AgentPolicy circuit per `circuits/scripts/bench_rapidsnark.js`). MCP handshakes happen at session initiation — every time a user opens a tool call, the agent must prove. WorkOS and Auth0 issue signed JWTs in under 100ms via their CDN-backed token endpoints. An enterprise CIO is not going to accept a 150× latency regression on auth — especially for agentic workflows where multiple agents chain calls. I'd demo our `/token` endpoint responding in 80ms against your 15s spinner and the meeting is over.

- **Why it works / fails:** The construction closes the IND-UNL-AS formalization elegantly (§3, Theorem 4.1), but the formal proof says nothing about wall-clock latency. The `rapidsnark_prover` binary cuts snarkjs proving time significantly, but the BOLYRA-CLAUDE.md itself notes "~2min" for full proof suites. Even at rapidsnark's best, a single AgentPolicy Groth16 proof is seconds, not milliseconds. The construction does not address proof caching, proof batching, or session-token offloading that would amortize the cost. The IND-UNL-AS game assumes proofs are atomic per session, so any caching scheme that reuses a proof across multiple RS interactions reintroduces linkability — directly negating the C2 claim.

- **In-threat-model?** **No — construction must address.** The construction needs a proof-once-cache-per-epoch design with formal analysis showing the cached credential does not leak cross-scope linkability. Without it, operators will take the 100ms JWT and live with OAuth scopes.

---

### Attack 2: The k-Anonymity Bootstrap Problem (§7 Anonymity Set)

- **Attack:** The well-formedness predicate `W(i_0, i_1)` requires `credAux_0 = credAux_1` — both challenge agents must belong to the same tier. §7 concedes the concrete anonymity set is 20,000 agents per tier in a "CU deployment." I ask: what is the anonymity set on launch day when a credit union has 3 AI agents enrolled? When a healthcare provider has 7? The IND-UNL-AS game with 20,000 agents in an anonymity set is a mature-network argument — it's not a day-1 guarantee. As the AS, I can also assign agents to singleton tiers during onboarding (if I'm adversarial, I control `credAux` at issuance). The construction assumes I'm honest at enrollment but adversarial at correlation — that's inconsistent.

- **Why it works / fails:** Theorem 4.1 bounds the adversary's advantage at `2·ε_PRF(λ, q+2)` — tight and clean. But this is the *computational* advantage, conditioned on `W` holding with a meaningful anonymity set. In the IND-UNL-AS game, the challenger enforces `W`. In production, the AS enforces `W`. If the AS issues `credAux` values that are unique per agent (a natural thing to do — embed agent ID in credAux for debugging), every agent is its own tier-1 anonymity set and the unlinkability guarantee collapses to noise. The construction does not specify what `credAux` is *permitted* to encode, nor does it prevent the AS from using `credAux` as a covert channel.

- **In-threat-model?** **No — construction must address.** The threat model must either (a) constrain `credAux` to be a public, AS-policy-defined tier label with no agent-specific bits, or (b) move `credAux` into the ZK witness and commit to it in the credential hash, hiding it from the AS at verification time. Without this, an adversarial AS bypasses the entire construction through `credAux` manipulation at issuance.

---

### Attack 3: The Wrong Adversary — Enterprises Trust Their AS

- **Attack:** The IND-UNL-AS game models the AS as the primary adversary. But in every enterprise deal I close, Auth0 *is* the AS — and the customer chose us *because* they trust us. The threat model inverts the actual buyer relationship. A credit union CISO asks: "Why am I buying a protocol that assumes my identity provider is my attacker?" This is a research-lab threat model, not an enterprise procurement story. The scenarios in C2 ("CU-as-AS must not see member merchant graph") assume the CU *runs the AS itself* and simultaneously wants protection from its own AS. If the CU doesn't trust itself, they have governance problems, not a cryptography gap.

- **Why it works / fails:** The construction's formal game is internally consistent — it defines unlinkability against a computationally-bounded adversary who controls the AS. But GTM-first, the *framing* destroys the sales motion. The buyer is the CU. The AS is operated by the CU or delegated to Auth0/Okta. Neither is the enemy. The actual threat is a *third-party data broker* or a *compromised RS* attempting to correlate — not the AS. The construction's scenarios mention "CU-as-AS must not see member merchant graph," which implies the CU is operating an AS that must be blind to its own member's behavior — an architectural choice (blind AS) that requires explicit design, not just a ZK proof on the client side.

- **In-threat-model?** **No — construction must address.** The construction needs a buyer-facing threat narrative: *who* is the adversary in the CU's actual deployment? If it's the RS (merchant), the construction needs an IND-UNL-RS game, not IND-UNL-AS. If the AS *is* the CU, unlinkability-from-self is a product feature with a completely different sales story ("privacy-preserving analytics") — not a security claim.

---

### Attack 4: RFC 7591 + Client Attestation Achieves Pseudonymous Agent Auth Without ZK

- **Attack:** My toolbox already has this: RFC 7591 Dynamic Client Registration lets an agent register a *fresh `client_id`* at each RS it accesses. Combined with [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/), the AS attests to the agent's identity class (model hash, operator key) without revealing a persistent agent ID to the RS. The RS sees a fresh pseudonym per session. Correlation across RSes requires the AS to collude — same assumption as the IND-UNL-AS game — and the AS *is* trusted in enterprise deployments (see Attack 3). I get unlinkability-from-RS for free, in under 100ms, with SOC 2 compliance, and no circuits. What does Bolyra add?

- **Why it works / fails:** The construction's C2 claim is specifically about unlinkability *against an adversarial AS* — and this is where DCR+Attestation falls short. A colluding AS can trivially link `client_id` registrations because it's the issuer of both the attestation and the registration. The IND-UNL-AS game is exactly the attack scenario where DCR+Attestation provides zero protection: the AS has all the linking information by design. So the construction *does* cover a real gap — but only if the CU threat model includes a compromised or privacy-invasive AS. The construction must make this case explicitly in §1 with a concrete attack on DCR+Attestation under an adversarial AS, or the `auth0_pm` objection lands: "you're solving a problem we don't have."

- **In-threat-model?** **Yes — construction survives this attack,** but only if §1 includes a concrete distinguishing attack: show a DCR+Attestation transcript under an adversarial AS that breaks cross-scope unlinkability, then show the Bolyra construction's transcript that resists the same adversary. Without that two-column comparison in the paper, the buyer has no reason to believe the ZK overhead is necessary.


## Persona: cryptographer

---

### Attack 1: k-Anonymity Set Collapse for High-Permission Credentials

**Attack:** The well-formedness predicate `W(i_0, i_1): credAux_0 = credAux_1` forces the challenger to pick two agents with *identical* public credential fields — including `permBitmask`. Because `permBitmask` is declared fully public in Property 3.3 (AS-as-issuer model), the adversary sees every agent's permission tier before the challenge phase. A straightforward partitioning attack follows: the adversary restricts its guessing to the sub-population that shares `permBitmask = 0b11111111` (`FINANCIAL_UNLIMITED | SUB_DELEGATE | ACCESS_PII`). In a realistic CU deployment the anonymity set for that tier is *not* 20,000 — it is the cardinality of agents issued `cc` with all eight bits set, which could be O(10–100). The §7 figure of 20,000 is an average across all tiers, and the game definition does not bound the adversary's ability to condition on `permBitmask` to select a thin tier before querying the `Prove` oracle. The IND-UNL-AS game needs a formal anonymity-set-size lower bound that is tier-uniform, or the reduction must account for the partition entropy loss.

- **Why it works:** `W` enforces same-tier matching, but the adversary chooses *which* tier to attack. Thin tiers have small anonymity sets regardless of PRF security.
- **In-threat-model?** No — the construction must either (a) prove that every `(permBitmask, cc)` bucket has ≥ k agents for some concrete k, or (b) add a population-hiding mechanism (e.g., dummy credentials, coarsening of public fields) and prove unlinkability relative to that mechanism.

---

### Attack 2: Groth16 Non-Simulation-Extractability Breaks the PRF Reduction

**Attack:** Theorem 4.1 reduces IND-UNL-AS advantage to `2·ε_PRF(λ, q+2)`. The reduction works by extracting `sbs` from a winning adversary — if the adversary can distinguish which agent produced the challenge proof, the simulator extracts `sbs` and uses it to break PRF. This extraction step assumes Groth16 proofs are *simulation-extractable*: given a CRS and polynomially many simulated proofs from the `Prove` oracle, the adversary cannot produce a fresh valid proof for a witness it does not know.

Groth16 is **not** simulation-extractable under its standard q-KoE / q-PKE assumptions (Fuchsbauer–Orrù–Zaverucha, CRYPTO 2018, explicitly separates SE-SNARKs from Groth16). A concretely malicious adversary can take two oracle proofs `(π_1, π_2)` for different `(agent, scope)` pairs and, under the Groth16 linear structure, interpolate a "hybrid" proof `π_h = α·π_1 + β·π_2` that passes `verifyProof` on a fabricated public input vector — including a nullifier it chose freely. Such a forged proof may win the IND-UNL-AS game (the adversary outputs a challenge transcript it constructed without knowing `sbs`) without violating PRF, collapsing the reduction.

The fix is either: (a) use a simulation-extractable SNARK (e.g., Groth16 + designated-verifier compilation, or Plonky2/Halo2 with SE compiler), or (b) add a separate binding layer (e.g., bind the proof to the nonce via an outer hash commitment before the oracle hands it to the adversary, and prove SE under a strengthened KoE assumption with an explicit citation).

- **Why it works:** Groth16's malleability under linear combination allows proof forgery without witness extraction. The IND-UNL-AS → PRF reduction silently assumes SE holds.
- **In-threat-model?** No — the construction must explicitly state and cite the simulation-extractability assumption, or switch to a scheme where SE is proven.

---

### Attack 3: Nonce Provenance Creates AS+RS Temporal-Correlation Channel Outside the Formal Model

**Attack:** The `Prove(i, scopeId, freshNonce)` oracle treats nonces as exogenous values with a freshness condition, but says nothing about *who generates them* in the real protocol. In the deployment scenarios (§7: CU-as-AS, healthcare delegation), the interaction pattern is:

1. Agent → RS: "I want access to scope S"
2. RS → Agent: nonce `n_RS` (RS-chosen, forwarded through AS)
3. AS → Agent: nonce `n_AS` (AS-chosen, for the AS-side session log)
4. Agent generates `proof_S = Prove(i, S, n_RS)` and submits to RS

If AS and RS collude, they share their nonce-issuance timestamps. An agent that accesses scope S₁ (CU-1) and scope S₂ (CU-2) within a narrow window generates proof requests visible to both AS and RS via nonce-request metadata. Even though the proof transcripts are cryptographically unlinkable (different nullifiers, different anchors), the AS+RS can run a timing join: `{nonce n₁ issued at T₁} ∩ {nonce n₂ issued at T₂ | |T₁ − T₂| < δ}`. For δ = 200ms, and assuming agents have sparse concurrent multi-scope sessions, the false-positive rate is negligible and the de-anonymization rate can approach 100%.

The gap-to-close in the candidate explicitly lists "empirical test showing colluding AS+RS cannot de-anonymize" and "treatment of side channels (timing, nonce freshness)" — neither appears in the formalized construction. The IND-UNL-AS game only models what the adversary learns from proof *values*, not from nonce-request metadata.

- **Why it works:** The game abstracts away the interactive nonce exchange. Colluding AS+RS operate on metadata (timing, IP, nonce sequence numbers) that the formal model discards.
- **In-threat-model?** No — the construction must either extend the game to include nonce-issuance events as adversary observations, or add a protocol-level countermeasure (e.g., agent-chosen nonces with AS/RS endorsement, jitter requirements, or anonymous credential-style blinding on the request phase).

---

### Attack 4: Poseidon2 PRF Security Claim Is Valid Only in the Algebraic Model — Not the Standard Model

**Attack:** Theorem 4.1 states `Adv_IND-UNL-AS ≤ 2·ε_PRF(λ, q+2)`, where the PRF is Poseidon2 keyed by `sbs`. The tightened hybrid argument (2 steps, single assumption, replacing the prior 4-step `ε_{PRF2} + ε_{PRF4}`) invokes Poseidon2 PRF security to replace `sbs`-keyed outputs with uniform random strings.

The problem: **Poseidon2 has no published PRF security proof in the standard model.** The Poseidon2 paper (Grassi et al., CRYPTO 2023) proves collision resistance, preimage resistance, and differential/linear distinguishing bounds under concrete round counts — it does not reduce PRF security to a standard hardness assumption. The only known PRF security arguments for algebraic hashes like Poseidon use the *algebraic circuit model* (ACM) or the *random oracle model* restricted to algebraic adversaries. Against a standard-model adversary who can adaptively query the hash with chosen `sbs` values (which the `Prove` oracle enables via `q+2` queries), there is no known reduction.

Concretely: an adversary who sees `q` oracle outputs `Poseidon2(scopeId_j, sbs)` for known `scopeId_j` values might use the algebraic structure of Poseidon2 (MDS matrix linearity, partial S-box structure) to recover `sbs` faster than brute force. This is not a known practical attack, but the *claimed bound* `2·ε_PRF` is vacuous without a proof that `ε_PRF` is negligible against the relevant adversary class. The construction must either (a) explicitly scope the theorem to the algebraic circuit model and cite an ACM PRF proof for Poseidon2, or (b) use a PRF with a standard-model security proof (e.g., HMAC-SHA256 reduced to PRF-from-PRG, or AES-based PRF under ideal cipher model) and pay the efficiency cost.

- **Why it works:** The reduction's last step invokes Poseidon2 PRF security as if it were a proven primitive. It is not — only collision resistance is formally established. The bound `2·ε_PRF` is a placeholder without a proof that the quantity is small.
- **In-threat-model?** No — the construction must (a) formally state the security model in which Poseidon2 acts as a PRF, (b) cite or provide the reduction, and (c) account for the fact that the `Prove` oracle gives the adversary adaptive keyed-hash queries, which may be outside the scope of existing Poseidon2 security analyses.


## Persona: cu_ciso

### Attack 1: Unlinkability Breaks Fraud Investigation — NCUA Part 748.0(b) / GLBA §314.4(c)

- **Attack:** The construction's core claim — that "colluding AS+RS cannot de-anonymize" — is operationally indistinguishable from "the CU cannot investigate its own fraud." If a member's agent executes unauthorized ACH pulls across three merchant RS instances, and the authorizations are cryptographically unlinkable, my BSA/AML team has no graph to hand to FinCEN and no audit trail to hand to my NCUA examiner. NCUA Part 748.0(b) requires a written program with controls to detect and respond to unauthorized access. §7's k-anonymity deployment scenario (20,000 agents per tier, §7) explicitly suppresses the correlation my ops team needs. The construction offers no reconciliation path — there is no "break-glass" linkage mode for authorized investigators.

- **Why it works / why it fails:** The construction does not address this. §3 (IND-UNL-AS game) defines the adversary as the AS itself, but the AS in a CU context *is* the regulated entity responsible for member protection. The game proves security against the CU's own compliance team.

- **In-threat-model?** **No** — construction must define an authorized-investigator linkage path (e.g., threshold disclosure to HSM-held audit key) that does not break the IND-UNL-AS game against unauthorized parties but satisfies NCUA's audit access requirements.

---

### Attack 2: `sbs` Custody is Unspecified — GLBA §314.4(f) / FFIEC CAT Baseline

- **Attack:** Property 3.2 states `sbs` is "drawn once at enrollment, reused across all sessions." This is the single secret that, if compromised, unlinks every nullifier and retroactively de-anonymizes the member's entire transaction graph. The construction is silent on where `sbs` lives after enrollment. If it's in browser localStorage or a mobile keychain, it is exposed to XSS, malware, and device seizure — none of which require breaking PRF security. GLBA Safeguards Rule §314.4(f) requires controls on service provider access to customer information. FFIEC CAT Baseline Domain 2 requires access management commensurate with risk. "PRF security handles poly(λ) adaptive queries" is a theoretical bound, not an HSM policy.

- **Why it works / why it fails:** The bound `Adv ≤ 2·ε_PRF(λ, q+2)` (Theorem 4.1) assumes `sbs` is uniformly random and secret. If `sbs` leaks through an operational channel (phishing, device compromise, malicious enrollment server), the entire unlinkability claim collapses for that member with no revocation path described in the construction.

- **In-threat-model?** **No** — construction must specify: (a) custody mechanism for `sbs` (secure enclave, FIDO2 hardware key, or MPC-enrolled), (b) revocation/re-enrollment procedure when `sbs` is suspected compromised, (c) what examiners see in a vendor management questionnaire for the enrollment server's access to `sbs` at issuance time.

---

### Attack 3: k-Anonymity Set Size is a Third-Party Dependency — NCUA Part 748 App B / FFIEC Third-Party Risk

- **Attack:** §7 grounds the anonymity claim on "20,000 agents per tier in CU deployment." For a $2B–$5B AUM credit union, total membership is roughly 80,000–150,000. Early AI-agent adoption realistically reaches 3–8% of members, yielding 2,400–12,000 agent-users — and those span multiple tiers. The anonymity set per tier may be 500–2,000, not 20,000. Below the stated threshold, the empirical unlinkability guarantee degrades in ways the formal bound (Theorem 4.1) does not cover, because that bound is information-theoretic only at the stated set size. My NCUA examiner will ask: "What is your residual risk when Bolyra's network is below the minimum anonymity set?" The construction provides no answer, and the CU has no operational lever to control network adoption.

- **Why it works / why it fails:** The construction ties a cryptographic guarantee to a sociological deployment assumption it does not own. This is a third-party concentration risk under NCUA's third-party risk guidance (Letter to Credit Unions 01-CU-20). The CU cannot put "20,000 agents per tier" in its vendor management policy and have it mean anything.

- **In-threat-model?** **No** — construction must bound the unlinkability guarantee as a function of actual anonymity set size *at time of authorization* (not projected network size), and specify the minimum set size below which the CU must reject or flag the authorization.

---

### Attack 4: On-Chain Registry Availability vs. Core Processor SLA — NCUA Part 749 / FFIEC BCP

- **Attack:** The colluding AS+RS scenario (§3, Phase 1 Learning oracle) requires the on-chain registry to be queryable for credential verification. The construction does not state an availability SLA for the on-chain component. Base Sepolia (the target chain per `CLAUDE.md`) is a testnet; mainnet Base L2 has had sequencer outages. NCUA Part 749 requires a written business continuity plan. FFIEC BCP Handbook requires RPO/RTO for critical systems. If the on-chain registry is unavailable, agent authorizations fail — but the construction offers no fallback verification path, no cached proof mode, and no definition of what "unavailable" means operationally. My board-level RTO for member-facing services is 4 hours. I cannot accept "blockchain liveness" as an implicit dependency with no contractual SLA.

- **Why it works / why it fails:** The construction's security properties (Theorem 4.1, Property 3.2, Property 3.3) are all stated in an always-available model. There is no degraded-mode analysis. A partial outage that allows some RS instances to verify while others cannot breaks the cross-scope unlinkability claim in practice — a member's silence on one RS during an outage becomes a linkage signal.

- **In-threat-model?** **No** — construction must define: (a) fallback verification path with equivalent unlinkability guarantees (e.g., cached Merkle root with time-bounded validity), (b) explicit RPO/RTO targets the CU can contractually reference, (c) how partial registry unavailability affects the IND-UNL-AS game (does a silent proof leak identity to a colluding RS?).


## Persona: rfc7662_advocate

*OAuth Working Group veteran. A decade shipping production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.*

---

### Attack 1: Constant `cc` is a stable cross-scope linking handle — the AS already has it

**Attack:** Property 3.3 states the adversarial AS receives all credential fields in Phase 0, explicitly including `cc` (the credential commitment). In every scope-separated ZK proof the agent submits, `cc` must appear as a public input so the RS can check revocation status and credential validity against the on-chain registry. The adversarial AS therefore observes the same `cc` value in every proof across every scope, for every session of that agent. `cc` is a stable pseudonym.

This is structurally identical to an OAuth AS issuing a `client_id`-bound opaque token: the AS knows `client_id` ↔ token ↔ RS call. The ZK construction swaps the token for a nullifier, but the credential commitment `cc` plays the same role as `client_id` when it is a mandatory public witness. RFC 7662 + PPID gives the RS-facing unlinkability the construction claims, while the AS correlation problem is identical in both constructions.

**Why it works / fails:** If `cc` is revealed as a public output in proof verification, the adversarial AS can build a complete traffic graph by joining proof submissions on `cc`. The formal IND-UNL-AS game in §3 models the adversary as receiving `cc` at game setup — but the game does not model it as a per-proof observable. If it is per-proof observable (which on-chain revocation checks would require), the bound `Adv ≤ 2·ε_PRF(λ, q+2)` is vacuous: the adversary wins with advantage 1 without breaking PRF at all.

**In-threat-model?** **Yes — construction must address this.** Either `cc` is never revealed per-proof (requiring a commitment re-randomization step per scope, analogous to Groth16 proof re-randomization) or the proof system must derive a per-scope `cc_scope = PRF(sbs, scopeId || "cc")` that plays the role of the credential identifier at the RS. The current anchor `Poseidon2(Poseidon2(scopeId, sbs), Poseidon2(permBitmask, cc))` reveals `permBitmask` and `cc` publicly — this must be checked against the circuit's public signal list.

---

### Attack 2: Audience-bound DPoP + PPIDs already achieves RS-level unlinkability without AS correlation — what is the AS-adversary advantage actually buying?

**Attack:** RFC 9449 DPoP binds a token to an ephemeral key pair; the AS records `dpop_jkt` (public key thumbprint) at issuance. If the agent uses a fresh DPoP key per scope (which is permitted — key rotation is not prohibited by RFC 9449 §9.3), the RS sees a unique `dpop_jkt` and cannot link across scopes. Combined with OIDC PPIDs (sector-specific `sub` per RS), RFC 8707 audience binding, and AS-side per-RS introspection policy filtering, the RS-facing view is already unlinkable.

The remaining gap in the OAuth stack: the AS holds the PPID mapping table and the `dpop_jkt` history, so a fully adversarial AS could correlate. The construction's claim is that ZK eliminates this AS-side advantage because the AS never learns `sbs`. But the IND-UNL-AS game in §3 gives the adversary `cc`, `permBitmask`, and `credAux` at Phase 0 (AS-as-issuer model). The adversary's distinguishing advantage over fresh-key DPoP is therefore limited to the PRF hardness of `sbs` given `cc`. The question the construction must answer: **what is the concrete security definition that DPoP+PPID+RFC8707 cannot achieve, stated as a game?** Without this baseline comparison, the strength score of 9→10 lacks a formal gap.

**Why it works / fails:** The attack does not break the PRF bound but reveals a definitional gap: the IND-UNL-AS game is not compared to a baseline OAuth game. An RFC 7662 reviewer will note that PPIDs already satisfy an analogous unlinkability game at the RS layer, with the AS as a trusted party — and if the AS is distrusted, fresh DPoP keys close the RS-facing graph. The claimed advantage is AS-facing traffic-graph resistance, but the construction must show a formal separation theorem against the OAuth baseline, not just a PRF reduction.

**In-threat-model?** **Yes — must address in §1 or §2.** A "why not DPoP+PPID" separation section with a formal game distinguishing the AS-adversary model is required. Without it, the construction's threat model appears overclaimed relative to existing standards.

---

### Attack 3: Timing side-channel breaks the formal bound outside the game model

**Attack:** Theorem 4.1 bounds `Adv ≤ 2·ε_PRF(λ, q+2)` over a game that is purely cryptographic — it models adaptive proof queries but not their timestamps. In the cross-CU scenario (§7 deployment), consider: the adversarial AS observes the timestamp `t_as` when agent with credential `cc` calls the AS for scope `S1`, and the colluding RS observes `t_rs` when a ZK proof for scope `S1` arrives. If `|t_as - t_rs| < δ` (where `δ` is the ZK proof generation time, a known constant for a fixed circuit), the AS can link the proof submission to the credential `cc` with probability approaching 1 regardless of PRF security.

The gap-to-close section acknowledges "side channels (timing, nonce freshness)" but the formalized construction in §3–§4 does not extend the IND-UNL-AS game to include a timing oracle or require timing-indistinguishable proof generation. The construction's bound is tight for the cryptographic game but silent on the physical execution model.

**Why it works / fails:** This is not mitigated by the Poseidon2 anchor change or the hybrid argument simplification. Neither modification affects proof generation latency or AS-call timing. The construction survives the formal game but fails a real-world deployment where the AS is also the network-level observer. RFC 7662 + opaque tokens have the same weakness — the AS is on the hot path — but the construction's claim of "adversarial AS cannot de-anonymize" must be scoped to exclude timing.

**In-threat-model?** **Yes — scope claim must be bounded.** Theorem 4.1 should be annotated: "cryptographic unlinkability assuming timing-indistinguishable proof delivery." The §7 empirical test section should include a timing-correlation experiment showing that proof batch submission or rate-limiting prevents sub-δ correlation.

---

### Attack 4: The `W(i_0, i_1)` condition fragments the anonymity set below the 20,000-agent k-anonymity claim

**Attack:** The well-formedness predicate `W(i_0, i_1)` requires `credAux_0 = credAux_1`. If `credAux` encodes the 8-bit `permBitmask`, then the game only guarantees indistinguishability within the same exact bitmask value. The 8-bit encoding allows 256 distinct bitmask values. In the CU deployment scenario, agents with `FINANCIAL_UNLIMITED` (bit 4 set, implying bits 2+3) form a small fraction of 20,000 agents. Agents with both `SIGN_ON_BEHALF` (bit 5) and `ACCESS_PII` (bit 7) form an even smaller subset. The adversary does not need to break PRF — it observes `permBitmask` (public, per Property 3.3) and narrows the anonymity set from 20,000 to the count of agents with that exact bitmask.

In the healthcare referral scenario: an agent credentialed for `ACCESS_PII | SIGN_ON_BEHALF | FINANCIAL_SMALL` (bitmask `0xA5`) may be one of dozens rather than thousands. The adversary correlates cross-scope proofs not by breaking PRF but by eliminating candidates from the known bitmask distribution. Theorem 4.1's bound does not account for this: the PRF advantage is negligible, but the real-world anonymity advantage is non-negligible under a realistic bitmask distribution.

**Why it works / fails:** The formal security claim is preserved (PRF bound holds) but the concrete privacy guarantee in §7 overstates the anonymity set. RFC 7662 with pairwise subjects and AS-side policy makes no such anonymity set claim — it simply does not attempt to hide AS-facing identity from the AS. The ZK construction makes a stronger claim ("adversarial AS cannot de-anonymize") that depends on k-anonymity not formalized in the proof. The 20,000-per-tier figure needs a conditional: "assuming uniform bitmask distribution across the tier" — a deployment assumption, not a security reduction.

**In-threat-model?** **Yes — §7 must tighten or formalize.** Either (a) `credAux` must be bucketed into coarse tiers (e.g., three levels) with enforced minimum anonymity set sizes, or (b) the security claim must be split: Theorem 4.1 provides cryptographic unlinkability; §7 provides a separate, explicitly conditional k-anonymity privacy analysis. Conflating the two into a single "strength score" of 9/10 is misleading to a standards reviewer.


## Persona: spiffe_engineer

> *"I have 847 SPIRE workloads in prod across 11 trust domains. Walk me through why you built a new identity layer instead of contributing a ZK attestor to SPIRE."*

---

### Attack 1: The WIMSE Token Exchange Already Handles Cross-Scope Separation

- **Attack:** `draft-ietf-wimse-arch` §4 defines a workload-to-workload token exchange flow where the caller presents a workload-scoped credential and receives a short-lived, audience-bound access token for each target service. Each exchange produces a distinct, ephemeral token with no shared identifier. A SPIRE deployment with 15-minute SVID TTLs plus per-audience JWT-SVID minting achieves exactly the "same agent, different RS, unlinkable authorization" property claimed here — without any ZK circuit. The construction's §3 game models the AS as adversarial, but in the WIMSE model the AS is the SPIRE server, which is already a trusted root. If you trust it to issue `cc` and sign `permBitmask`, you already gave it enough information to link you.

- **Why it works / fails:** The construction's unlinkability claim holds *cryptographically* — the IND-UNL-AS game is well-formed. But it does not argue *why* the ZK layer is necessary versus short-TTL token exchange with per-audience subjects. The gap is architectural justification, not cryptographic correctness.

- **In-threat-model?** **No** — the construction must address: "Why is ephemeral scoped token exchange insufficient, and what does the ZK layer add that WIMSE token binding does not?"

---

### Attack 2: `permBitmask` Is a Public Fingerprint the IND-UNL-AS Game Concedes

- **Attack:** Property 3.3 explicitly states `cc` and `permBitmask` are public — the adversary receives them in Phase 0. In a real CU deployment, `permBitmask` is low-entropy: most member agents cluster around 2–3 permission profiles (e.g., `READ_DATA | FINANCIAL_SMALL` = `0x05`). A colluding AS+RS observes `(cc, permBitmask)` across all authorization requests. The anonymity set is not 20,000 agents — it is 20,000 agents *filtered to the same bitmask and credential commitment tier*. In SPIFFE terms, this is equivalent to publishing the workload selector set before the SVID is rotated: you haven't protected the workload class, only the instance. The W predicate `credAux_0 = credAux_1` in Definition 3.1 requires the two challenge agents to have identical aux credentials, which the adversary can exploit by selecting agents from the same narrow permission tier to shrink the anonymity set to single digits.

- **Why it works / fails:** Theorem 4.1's bound `Adv ≤ 2·ε_PRF` is tight *given* the W predicate. The predicate concedes that `(cc, permBitmask, credAux)` are linkable. The unlinkability claim survives only if the anonymity set is large; the construction asserts 20,000 per tier but does not prove that the empirical permBitmask distribution keeps set size above a security threshold across all real deployments.

- **In-threat-model?** **Yes** — the game models this, but §7's concrete anonymity-set argument needs to bound set size as a function of actual permission distribution entropy, not just enrollment count.

---

### Attack 3: Long-Lived `sbs` Is a Single Point of Catastrophic Linkage

- **Attack:** Property 3.2 states `sbs` is drawn *once at enrollment* and reused across all sessions, with PRF security providing poly(λ) adaptive query resistance. In a SPIFFE deployment, the analogous long-term secret is the agent's private key, which SPIRE rotates on a configurable schedule (default 24h). Bolyra's `sbs` has no rotation mechanism. A hardware side-channel (cache timing on the Poseidon2 circuit, memory-safety bug in the proving binary, cold-boot on the proving host) that leaks `sbs` retroactively links *every proof ever generated by that agent across every scope* — the PRF is perfectly inverted. The Poseidon2-tree anchor `Poseidon2(Poseidon2(scopeId, sbs), ...)` means `sbs` is the single root of all cross-scope pseudonymity. This is worse than a compromised SVID because SVIDs have bounded TTLs; `sbs` compromise is permanent until re-enrollment.

- **Why it works / fails:** The construction's Theorem 4.1 holds under the PRF assumption, but the threat model does not address `sbs` exfiltration or key rotation. The IND-UNL-AS game gives the adversary oracle access to `Prove(i, scopeId, nonce)` but does not model a "reveal `sbs`" oracle (analogous to an adaptive corruption query in UC composability).

- **In-threat-model?** **No** — the construction must add: (a) a key rotation / re-enrollment protocol for `sbs`, and (b) forward secrecy analysis or an explicit statement that `sbs` compromise is out of scope with a reference to the threat model boundary.

---

### Attack 4: Scope-Request Metadata Leaks the Traffic Graph Before the Proof Is Verified

- **Attack:** The IND-UNL-AS game's `Prove(i, scopeId, freshNonce)` oracle models the moment the ZK proof is *generated and submitted*. But in any real authorization flow — WIMSE token exchange, OAuth 2.0 Rich Authorization Requests, or a Bolyra handshake — the agent must first *request authorization for a scope* by presenting its credential commitment `cc` to the AS before the proof is evaluated. The AS sees `(cc, scopeId, timestamp)` at request time. Even if the nullifier in the returned proof is scope-separated and unlinkable, the AS's request log already maps `cc → [scopeId_1 at t_1, scopeId_2 at t_2, ...]`. The healthcare scenario in §1 ("agent delegation across providers without issuer learning referral network") is defeated: the issuer-AS learns the referral network from the *request pattern*, not the proof content. No change to the Poseidon2 anchor or the IND-UNL-AS game addresses this because the game starts at proof submission, not credential presentation.

- **Why it works / fails:** This is a metadata side-channel outside the formal game boundary. The construction's claim — "adversarial AS that tries to correlate per-agent traffic graphs" — is precisely the threat, but the game does not model the AS's view of pre-proof authorization requests.

- **In-threat-model?** **No** — the construction must either (a) extend the game to model the AS's request-phase view and show `cc` alone is insufficient to reconstruct the traffic graph, or (b) require a blind authorization request mechanism (e.g., a separate unlinkable token for scope negotiation) and cite it as a protocol requirement outside the ZK layer.
