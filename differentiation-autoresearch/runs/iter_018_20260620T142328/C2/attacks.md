# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: Revocation Timeliness — The CISO Termination Test

- **Attack:** The construction eliminates the AS from per-request auth, which also eliminates real-time revocation. Section 2's "root caching" design says agents cache roots "every 6 hours" and the 30-entry root history buffer tolerates stale roots. An enterprise customer (say, NFCU) fires a contractor. Their agent's credential commitment is in the Merkle tree. To revoke, NFCU must rotate the tree root and wait for all agents to pick up the new root — but the protocol explicitly *caches* old roots. A revoked credential is valid for up to 6 hours post-termination. WorkOS and Auth0 revoke tokens in under 1 second via token introspection (RFC 7662) or short-lived JWTs. NFCU's CISO will ask: "How do I meet my Reg E incident response SLAs with a 6-hour revocation lag?" The construction does not address this.
- **Why it works:** The unlinkability claim is structurally purchased by removing the AS from the auth path. But real-time revocation *requires* something on the auth path. You cannot have both AS-free auth-time privacy and AS-enforced sub-second revocation without a separate revocation oracle — which reintroduces a correlation surface the construction explicitly excludes.
- **In-threat-model?** No. The IND-UNL-AS game (§3) is silent on revocation. The construction must address the tradeoff explicitly: either (a) define a revocation mechanism with a formal latency bound and show it doesn't reintroduce AS visibility, or (b) scope the security claim to "non-revoked credentials" and quantify the revocation window for procurement teams.

---

### Attack 2: Operator-as-Adversary — The Threat Model Excludes the Most Realistic Enterprise Principal

- **Attack:** Section 3 defines the adversary as controlling the AS but explicitly *not* "the agent's local proving environment." In the credit union deployment scenario (§7), NFCU is simultaneously: the AS (issues and signs credentials), the operator (runs the agent on NFCU infrastructure), and the entity that "adds the credential commitment to the on-chain Merkle tree." The `credentialSecret` is described as "generated at agent enrollment time and known only to the agent" — but the construction never specifies *who generates it*. In any enterprise shared-infra deployment (Lambda, ECS, Kubernetes sidecar), the operator provisions the agent's runtime environment and can observe or derive the `credentialSecret`. If NFCU generated the secret during enrollment (the natural enterprise pattern where an admin portal creates agent credentials), NFCU trivially computes `Poseidon2(scopeId_amazon, credentialSecret)` for every plausible merchant and deanonymizes the entire traffic graph. The IND-UNL-AS game assumes the agent's local environment is a black box to the adversary — that assumption is false in every enterprise deployment I've seen.
- **Why it works:** The gap is in the enrollment ceremony, not the circuit. The circuit correctly keeps `credentialSecret` private. But the threat model assumes key generation is client-side and operator-opaque. The construction has no ceremony specification for *who generates the secret* and *how the operator is excluded from learning it*. Compare: BBS+ blind signing, or Semaphore v4's client-side secret generation with no operator involvement. Those are explicit about the trust boundary. This construction is not.
- **In-threat-model?** No. The construction must either (a) specify a client-side key generation ceremony that provably excludes the operator from learning `credentialSecret`, or (b) narrow the unlinkability claim to the case where the adversary does *not* control the agent's key generation environment and label this assumption explicitly.

---

### Attack 3: Proving Time in Real Enterprise Runtime Environments

- **Attack:** Section 6 targets "< 3s on consumer hardware" for PLONK and "< 500ms via rapidsnark." The `rapidsnark` path requires a native binary (`circuits/build/rapidsnark_prover`) that cannot run in AWS Lambda, Cloudflare Workers, or any WASM-sandboxed agent runtime. The 3s PLONK target is snarkjs-in-Node — which cannot run in a browser-based MCP client or a mobile agent. In agentic workflows, an agent may call 20–50 tool endpoints per task session. At 3s per proof, that's 60–150 seconds of crypto overhead per task, before any actual work. Auth0 and WorkOS issue tokens in under 100ms P99 globally, with zero client-side compute. Stytch's Connected Apps flow adds one HTTP roundtrip. The procurement question is not "is 500ms acceptable?" — it's "will this work in our Lambda functions, our Vercel Edge, our iOS app?" The answer for `rapidsnark` is no. The answer for snarkjs PLONK is 3+ seconds of blocking compute in a single-threaded agent loop.
- **Why it works:** The construction correctly identifies the proving time concern and benchmarks it, but sidesteps the deployment constraint. The native binary path is incompatible with the serverless and edge runtimes that dominate enterprise MCP deployments. The snarkjs path has unacceptable latency at agent-workflow scale. The construction needs a credible answer for WASM proving (circom-witness-rs + snarkjs WASM?) with measured P50/P99 latencies in Lambda, and a multiplicative cost model for multi-RS agent sessions.
- **In-threat-model?** No (operational, not cryptographic). The construction must include a deployment compatibility matrix — Lambda/Edge/WASM support — and a per-session latency model at 10, 25, 50 RS interactions. Without this, enterprise procurement rejects it on the first RFP question about runtime requirements.

---

### Attack 4: scopeId Is Enumerable — PRF Security Requires a Secret Key, but the Key Space Is Finite

- **Attack:** The unlinkability reduction in §4 claims `Poseidon2(scopeId, credentialSecret)` is PRF-secure because the adversary cannot invert Poseidon or enumerate the key space. But `scopeId = Poseidon("amazon.com")` is a deterministic hash of a *public string*. The effective key is `credentialSecret`. An adversary AS (NFCU) who suspects a member agent interacts with a known merchant universe (say, the top 200 US merchants) can precompute `Poseidon2(Poseidon(merchant_domain), credentialSecret_candidate)` for every `credentialSecret_candidate` in a brute-forceable range — if the secret has low entropy, is derived from a predictable seed, or if NFCU can obtain even one `(scopeId, scopeNullifier)` pair from a colluding RS. The construction says `credentialSecret` is "range-checked to [0, 2^251)" — full 251-bit entropy is assumed but not enforced by key generation ceremony. If the actual secret is a 128-bit hash of a device ID or a user-supplied passphrase, PRF security degrades. The §4 reduction is correct *conditional on* `credentialSecret` having full field entropy. The construction does not specify or enforce the key generation distribution.
- **Why it works:** PRF security against a computationally unbounded adversary colluding with a finite merchant set doesn't require inverting Poseidon — it requires an offline dictionary attack over `credentialSecret` given one known `(scopeId, scopeNullifier)` pair. The adversary just needs one colluding RS, one observed nullifier, and a guessable secret distribution. The reduction sketch (§4, step 1) assumes the PRF key has full entropy; that assumption must be enforced by the protocol's enrollment ceremony, not just assumed.
- **In-threat-model?** Partially. The IND-UNL-AS game (§3) correctly fixes `credentialSecret` as a random element, so the game's adversary cannot win. But the game does not model the case where `credentialSecret` is weak or partially known. The construction must either (a) specify a verifiable key generation ceremony (e.g., commit-and-reveal with a randomness beacon, or client-side CSPRNG with a proof of entropy), or (b) add a lower bound on effective key entropy to the threat model and note that the security claim degrades if key generation is compromised.


## Persona: cryptographer

Applied cryptographer. My stance: a construction without a proof is a blog post. Let me find what the author didn't address.

---

### Attack 1: credentialSecret–leaf unbinding (nullifier malleability / underconstrained circuit)

**Attack:** The Merkle leaf committed on-chain is:

```
credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)
```

`credentialSecret` does **not** appear anywhere in this commitment. It appears only in two places in the circuit:

1. `Num2Bits(251)` range check (constraint §2, item 1)
2. `scopeNullifier = Poseidon2(scopeId, credentialSecret)` (constraint §2, item 8)

There is **no constraint binding `credentialSecret` to the enrolled identity**. The EdDSA signature verifies over `credentialCommitment`, which excludes `credentialSecret`. The Merkle membership check verifies `credentialCommitment` against the root — also excluding `credentialSecret`.

**Concrete exploit (two variants):**

*Variant A — nullifier splitting:* A single enrolled agent holds a valid `(credentialCommitment, Merkle path, EdDSA sig)`. It can pick $k$ independent values $s_1, \ldots, s_k$ for `credentialSecret` and generate $k$ valid proofs at the same RS, each with a distinct `scopeNullifier = Poseidon2(scopeId, s_i)`. The RS's replay-detection mechanism (nullifier deduplication) will treat these as $k$ different agents. One credential → unlimited pseudonyms per scope. The "double-auth detection" goal is broken for malicious provers.

*Variant B — credential hijacking:* On a public-leaf Merkle tree (or any setting where Merkle siblings are computable from on-chain data), adversary B obtains Alice's `credentialCommitment` and Merkle path. B sets `credentialSecret` to any value $s_B$ and constructs a valid `AgentScopeAuth` proof citing Alice's leaf. The resulting `scopeNullifier = Poseidon2(scopeId, s_B)` is fully under B's control. Alice and B have unrelated nullifiers; B is not detectable.

**Why it works:** The circuit proves "I know a witness satisfying these constraints" but `credentialSecret` is a free variable decoupled from the identity-binding gadgets (EdDSA + Merkle). A standard fix is `credentialCommitment = Poseidon6(modelHash, opPubAx, opPubAy, permBitmask, expiry, credentialSecret)` — including the secret in the leaf hash so the EdDSA signature (and Merkle path) implicitly bind it. The analogous human circuit (`HumanUniqueness`, Semaphore v4) does exactly this: `identityCommitment = Poseidon(identityNullifier, identityTrapdoor)`.

**In-threat-model?** **No — construction must address.** This is a soundness gap, not a ZK gap. A-KS-G16/PLONK gives witness extraction but extraction yields an arbitrary `credentialSecret`, not one tied to enrollment. The IND-UNL-AS reduction in §4 doesn't touch this because it only considers honest provers.

---

### Attack 2: Static IND-UNL-AS game — adaptive multi-session correlation attack

**Attack:** The IND-UNL-AS game (§3) gives the adversary **one challenge**: each of Agent_0 and Agent_1 authenticates exactly once. The reduction in §4 then applies PRF security to two evaluations of `Poseidon2(scopeId, ·)`.

Real deployments involve **adaptive, multi-session** access. Consider:

> Adversary A controls RS_a and RS_b. Over time it observes $T$ sessions at RS_a and $T'$ sessions at RS_b. Agent Alice authenticates to both RSes on a repeated schedule. The adversary now has the set of pairs $\{(\text{null}_{a,t})\}_{t=1}^T$ and $\{(\text{null}_{b,t})\}_{t=1}^{T'}$ where all RS_a nullifiers equal the same value (same agent, same scope → same deterministic nullifier) and similarly for RS_b.

The nullifier `Poseidon2(scopeId, s)` is **deterministic per (agent, scope)**. Within a single RS, nullifier repetition is identical — that's intentional (replay detection). But this means the nullifier behaves as a **permanent pseudonymous identifier** at each RS. The adversary at RS_a and RS_b each see a stable pseudonym. 

The correlation attack: if the adversary can link RS_a-pseudonym to RS_b-pseudonym via **timing** — e.g., both appear within 50ms of a shared external event (a payment, a user action), or both rotate to a new Merkle root on the same cycle — it deanonymizes without breaking PRF. The PRF argument in §4 only rules out **cryptographic** linkage; timing is explicitly out-of-scope for the formal game.

**Stronger variant:** A malicious operator who issued Alice's credential knows `(modelHash, opPubAx, opPubAy, permBitmask, expiry)` but not `credentialSecret`. If Alice connects to RS_a, the operator-as-adversary sees `null_a`. It cannot invert PRF to get $s$. But if the operator issues credentials with narrow expiry windows (per-agent distinct `expiryTimestamp`), the set of agents whose credential is valid at RS_b at time $t$ is constrained to those enrolled within a narrow band — probabilistic deanonymization via anonymity-set reduction. The IND-UNL-AS game fixes N enrolled agents but doesn't model this enrollment-time side channel.

**In-threat-model?** **No — construction must address.** The game in §3 is static (one-shot) and treats timing as out of scope. The paper's batched root refresh addresses AS-facing timing but says nothing about adversary-controlled RSes correlating repeated sessions via synchronized pseudonym appearance. A full definition needs to be an **adaptive multi-session** game with $q$-query security, not a static one.

---

### Attack 3: PLONK universal SRS — subverted setup collapses the entire construction

**Attack:** §2 designates PLONK as the primary proving system for `AgentScopeAuth`, citing "universal setup, no per-circuit ceremony." This is correct that PLONK requires only one universal SRS (a structured reference string of the form $(\{[\tau^i]_1\}, \{[\tau^i]_2\})$ for a trusted scalar $\tau$). However, the construction says **nothing** about how this SRS is generated or what trust assumptions are made.

If a PLONK SRS is generated by a single trusted party (or a MPC with a corrupted majority), the party holding the trapdoor $\tau$ can:

1. **Forge proofs for any statement:** Given $\tau$, the adversary computes a fake proof $\pi^*$ for the statement "agent with `credentialSecret = 0` is enrolled in the current Merkle root" without knowing any valid witness. All verifiers accept $\pi^*$.
2. **Selective deanonymization:** The adversary generates proofs with arbitrary public outputs (`scopeNullifier`, `blindedScopeCommitment`), allowing it to impersonate any enrolled agent at any RS.

The threat model in §3 assumes the adversary does NOT control "the Poseidon hash function or Baby Jubjub discrete log." But it says nothing about the SRS. **Subverted SRS is a strictly weaker assumption than breaking DL.** The reduction in §4 assumes A-KS-PLONK holds, which itself assumes the SRS is honestly generated. Under a subverted SRS, A-KS-PLONK fails and the entire reduction collapses.

Groth16 has the same issue (per-circuit toxic waste), but PLONK's universal SRS is a single point of failure across ALL circuits — `AgentScopeAuth`, `AgentPolicy`, `Delegation`, and `HumanUniqueness`. A compromised Groth16 ceremony only breaks one circuit; a compromised PLONK SRS breaks everything.

**In-threat-model?** **No — construction must address.** The threat model must explicitly specify a setup model (e.g., "honest majority MPC with $t$-of-$n$ threshold for SRS generation") and a corresponding SRS assumption. Without it, the claim "no PPT adversary can distinguish..." is vacuously conditioned on a setup trust assumption that's never stated. This is standard: Groth16 and PLONK papers define security in the Algebraic Group Model (AGM) and Generic Group Model (GGM) relative to an honestly-generated SRS. The Bolyra construction inherits this dependency and must make it explicit.

---

### Attack 4: IND-UNL-AS game admits trivial win via `agentMerkleRoot` staleness fingerprinting

**Attack:** The game in §3 gives both agents the same `agentMerkleRoot` (it's a public input). The root history buffer holds 30 entries, refreshed as new agents enroll. The construction says agents refresh roots in "fixed-size batches every 6 hours."

Consider the adversary's view: each proof presentation includes `agentMerkleRoot` as a public value. The on-chain contract emits events for each root rotation. An adversary observing RS_a and RS_b can therefore determine:

- The root `r_a` used in the RS_a proof → was valid in a specific 6-hour window $[t_a, t_a + 6h)$
- The root `r_b` used in the RS_b proof → was valid in a specific 6-hour window $[t_b, t_b + 6h)$

If both proofs use the **same root**, they were generated within the same 6-hour root-caching epoch. This is a necessary (not sufficient) condition for same-agent. Under high-frequency access patterns, the same-epoch constraint reduces the anonymity set.

More precisely: if $N_r$ agents enroll between root rotations (producing a new root per batch), the adversary can partition the enrolled population into root cohorts. Two proofs using the same root $r$ are from agents enrolled in the same cohort — cohort size may be small (e.g., 1–5 agents if enrollment is sparse), reducing the anonymity set below $N$.

The IND-UNL-AS game doesn't capture this because it sets both agents in the same Merkle tree with the same root, but doesn't model the **timing structure of root rotation** relative to agent enrollment and proof generation. The PRF-based reduction is agnostic to root staleness; the actual anonymity set is smaller than the game's $N$.

**In-threat-model?** **Partially.** The batched root refresh (§2) partially addresses this by making root fetches unlinkable to the AS. But the root value itself leaks temporal cohort membership to the colluding RS. The construction must bound the anonymity set as a function of root rotation frequency and enrollment rate, and either (a) fix the root to a long-lived value (weakening freshness), or (b) prove the anonymity loss is negligible relative to the cohort size. Neither is done.


## Persona: cu_ciso

### Attack 1: Audit Trail Destruction Masquerading as Privacy Feature

- **Attack:** NCUA Part 748 Appendix B requires the credit union to maintain records sufficient to reconstruct events during an incident. GLBA Safeguards Rule §314.4(h) requires incident response with "containment, remediation, and notification." The construction's §7 proudly states: *"NFCU sees nothing after enrollment. No token issuance requests. No scope queries. No timing signals."* I hand that sentence to my NCUA examiner during a fraud review — where NFCU's member agent initiated a fraudulent $8,400 payment to a merchant — and I have nothing to give them. No transaction log. No RS-side authentication record that links back to a member. The on-chain `scopeNullifier` is RS-specific and unlinkable by design, which means even if Amazon gives me their nullifier log, I cannot map it to Member #12345's agent. The construction has engineered away my ability to comply with examination expectations.

- **Why it works / why it fails against the construction:** The cryptographic argument (§4) is internally consistent. Unlinkability holds. But unlinkability *is the compliance failure*. The construction treats "AS sees nothing" as a security property; NCUA treats it as an audit gap. Section 8's comparison table lists "zero per-request visibility" under the AgentScopeAuth column as an advantage — it is simultaneously a regulatory defect that the construction never acknowledges.

- **In-threat-model?** No. The IND-UNL-AS game (§3) treats the AS as an adversary to be blinded. NCUA examiners are not in the threat model. The construction must address how a regulated issuer (CU-as-AS) retains compliant audit capability without breaking the unlinkability guarantee — e.g., a member-controlled selective disclosure log, a TEE-based audit escrow, or a separate member-facing audit trail that is architecturally distinct from the AS's view.

---

### Attack 2: credentialSecret Key Custody — Location Unspecified, Vendor Unauditable

- **Attack:** Section 5 defines `credentialSecret` as "a per-agent secret scalar… generated at agent enrollment time and known only to the agent." My Vendor Management Policy requires me to know where cryptographic secrets live and who has contractual accountability for them. The construction is silent. In the concrete deployment scenario (§7), the agent is a "budgeting assistant" — which in practice means it runs in a cloud AI runtime (e.g., an OpenAI function, a LangChain orchestrator on AWS Lambda, or a mobile app). Each option has a different key custody story: a browser LocalStorage secret is exportable by any script on that origin; an AI cloud service secret requires me to audit that vendor's HSM practices; a mobile app secret is subject to jailbreak extraction. The construction treats key custody as out of scope. My examiner does not.

- **Why it works / why it fails against the construction:** The cryptographic properties hold *given* that `credentialSecret` stays secret. The construction provides no mechanism — hardware binding, TEE, HSM requirement, or even a recommendation — for ensuring this. FFIEC CAT Domain 2 (Threat Intelligence) and Domain 3 (Cybersecurity Controls) both require layered key protection. NCUA third-party risk questionnaires will ask: "Where is the cryptographic material stored and who audits that storage?" The construction cannot answer this question for any concrete deployment.

- **In-threat-model?** No. The adversary in §3 explicitly does not control "the agent's local proving environment." This is not an assumption that holds in production — it is the core operational risk the construction waves away. For a credit-union deployment, the answer to "where does the member secret live" must be specified, not deferred.

---

### Attack 3: Revocation Latency — 7-Day Compromise Window Under GLBA Safeguards

- **Attack:** Section 2 defines a 30-entry root history buffer with 6-hour refresh intervals. This means a revoked credential (leaf removed from the Merkle tree, new root published) remains valid against cached roots for up to 30 × 6 hours = 180 hours — 7.5 days. GLBA Safeguards Rule §314.4(h)(2) requires the institution to "contain and control" a breach. If NFCU detects that a member's agent credential was compromised at hour 0 and removes it from the Merkle tree at hour 1, the compromised agent continues to authenticate to any RS using a cached root for up to 7.5 more days. The construction's revocation strategy is expiry-only, and the stale-root tolerance is a design feature for availability that directly conflicts with GLBA's response-time expectations.

- **Why it works / why it fails against the construction:** The root history buffer is necessary for the "AS-free" property — without it, agents would need to contact the AS on every authentication to get a fresh root, which reintroduces AS-visibility. But the tradeoff creates a concrete revocation latency that is unacceptable in a fraud scenario. The construction §2 acknowledges root caching for "anti-timing" but never quantifies the revocation latency or provides an emergency path (e.g., a shorter-window root for high-risk credentials, or an on-chain revocation list that RSes check separately).

- **In-threat-model?** No. The threat model (§3) addresses AS-driven correlation. It does not model a post-compromise NFCU attempting to contain a breach. A formal treatment of revocation timeliness — and how it interacts with the root history buffer — is missing from the construction entirely.

---

### Attack 4: Enrollment Timing as a Deanonymization Side Channel

- **Attack:** Section 2 claims the AS cannot observe per-RS authentication timing because agents present proofs directly to RSes. But the AS *does* observe enrollment: "NFCU adds the credential commitment to the on-chain Merkle tree" (§7). Enrollment is a timestamped on-chain event. Now consider: Amazon's fraud team (or Amazon-as-colluding-RS) notices a new agent first appeared in their system at 14:02 on June 15. NFCU's on-chain Merkle tree shows a new leaf was added at 13:58 on June 15. Among all NFCU members who enrolled a new agent credential within that window, the population is small — possibly unique. The `scopeNullifier` is cryptographically unlinkable, but the enrollment timestamp is public and on-chain, and the construction offers no enrollment batching, covert timing, or cover traffic to prevent this narrowing attack. The §2 "batched root refresh" addresses root-fetch timing, not enrollment timing.

- **Why it works / why it fails against the construction:** The IND-UNL-AS game (§3) sets up a challenger who enrolls N ≥ 2 agents before the attack begins and then issues challenge proofs. In this game, enrollment timing is already fixed before the adversary sees anything. In the real deployment, enrollment and first-use are correlated — potentially within minutes — and the Merkle leaf insertion is a public on-chain event visible to any colluding RS that monitors the contract. The "empirical test showing colluding AS+RS cannot de-anonymize" noted in the gap (candidate §gap_to_close) has not been demonstrated against this vector.

- **In-threat-model?** Partially. The adversary controls "network-level observation of agent-to-RS communication metadata" (§3), but on-chain Merkle insertions are not metadata — they are application-layer events the construction itself requires. This is an in-scope side channel that the construction's batched root refresh mechanism does not address. A solution would require enrollment batching (adding leaves in fixed-size epoch batches at scheduled intervals, regardless of actual enrollment rate), which the construction neither specifies nor estimates the privacy-utility tradeoff for.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Decade shipping production introspection. Every ZK claim is suspect until proven not achievable by a well-configured AS.*

---

### Attack 1: Missing Audience-Binding Enforcement at RS (the `aud` gap)

- **Attack:** RFC 8707 (Resource Indicators) and every JWT profile mandate that the RS *validate* that the token's audience claim equals its own identifier. The `AgentScopeAuth` verification checklist in §2 step 4 lists four checks: root-history membership, scopeNullifier replay prevention, proof validity, and `expiryFlag == 1`. It never states "RS checks that the `scopeId` public input equals the RS's own expected identifier." An agent holding a valid proof for `RS_j` (with `scopeId_j`) can present it to `RS_i`. The PLONK/Groth16 verifier confirms the proof is internally consistent with *some* `scopeId` — it does not know which RS should accept it. `RS_i`'s replay-prevention check on `scopeNullifier` sees a nullifier it has never recorded and passes it. Result: proof re-use across RSes without the agent re-proving.

- **Why it works / why it fails:** The circuit correctly binds `scopeNullifier` to `scopeId` and `credentialSecret`. But cryptographic binding inside the proof is worthless if the verifier never asserts `scopeId == Poseidon(my_domain)`. This is the classical bearer-token audience mistake — a JWT with `"aud": "rs_j"` accepted by `rs_i`. RFC 7662 avoids this by AS-side configuration: the AS only returns an active introspection response when the presenting RS matches the token's intended audience. The construction has no equivalent enforcement step. If `RS_i` is honest and diligent it will check; the spec does not require it.

- **In-threat-model?** Yes — construction survives if §2 step 4 is amended to add explicit check: `scopeId == Poseidon(RS_i.domain)`. But it must be in the protocol spec, not left as an implementation convention. Right now it is a spec gap that allows cross-RS proof reuse, which directly undermines the per-RS nullifier domain separation claim.

---

### Attack 2: Enrollment-Timing K-Anonymity Failure in Small Populations

- **Attack:** The batched root refresh in §2 protects against AS-timing correlation of *root fetches*. It does not protect against timing correlation of *enrollment events*. The AS adds a credential commitment to the Merkle tree at a precise timestamp. The AS knows the leaf value (it computed `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` — all fields it set). In a credit union with 50 enrolled agents, if 3 agents enroll in a given hour and an RS (colluding with the AS) sees exactly 3 new proofs from the same anonymity set within the same window, the AS can narrow its candidate list from 50 to 3. In a small-membership deployment (the credit union scenario in §7 explicitly uses NFCU as issuer), the practical anonymity set may be far smaller than the full Merkle tree.

- **Why it works / why it fails:** The IND-UNL-AS game in §3 is defined over N ≥ 2 agents with no constraint on N. The formal reduction in §4 is clean for large N. But the game assumes the challenger controls enrollment timing; in practice the AS controls enrollment timing and can use it as a side channel. RFC 7662's model is actually *more* uniform here: every RS access looks identical to the AS (a token introspection call), so there is no cold-start asymmetry. The construction has a structural cold-start asymmetry — enrollment is a unique, timestamped, leaf-specific AS interaction that ZK proofs cannot retroactively hide.

- **In-threat-model?** No — the construction must address this. §3 explicitly puts timing side channels in scope ("treat of side channels (timing, nonce freshness)" listed as a gap to close in the candidate metadata). The construction's §2 anti-timing section only covers root-fetch timing. Enrollment-timing correlation is unaddressed and breaks the formal argument for small populations. At minimum, the construction needs a minimum anonymity set size parameter and a recommendation to batch enrollments.

---

### Attack 3: PPID + Signed JWT Introspection Closes the RS-Level Gap — So What IS the Claim?

- **Attack:** Section §8's baseline comparison attributes "AS sees agent, RS, scope, timestamp for every request" as the fatal flaw of RFC 7662. But the comparison is against a *naïvely configured* AS. A hardened AS using (a) pairwise subject identifiers (OIDC PPID — different `sub` per RS), (b) draft-ietf-oauth-jwt-introspection-response (RS receives a signed JWT with RS-scoped claims, AS policy filters response per RS registration), and (c) RFC 9449 DPoP (sender-constraint, proof-of-possession at each RS) already prevents RS-to-RS linkability: no two RSes see the same subject identifier. The AS *does* see the full graph internally, but in the OAuth trust model **the AS is a trusted party by definition** — if you do not trust your AS, you have already exited the OAuth threat model entirely, and ZK does not help because the AS still holds the enrollment record that maps a tree leaf to an agent identity (§5: "NFCU adds the credential commitment to the on-chain Merkle tree" — NFCU knows which leaf is which agent's).

- **Why it works / why it fails:** The construction's real and valid claim is narrow: *the AS cannot build per-request traffic graphs even when compromised or coerced*. That is a GDPR/GLBA regulatory-compliance property (post-hoc auditability protection), not a cryptographic novelty. The §8 table conflates two distinct claims — (1) RS-level unlinkability (achievable with PPID) and (2) AS-level unlinkability (the genuine ZK-only property). The baseline comparison should be scoped to claim (2) only, and the concrete scenarios in §7 should be rewritten to name the specific regulatory threat (e.g., "AS under subpoena must not be able to reconstruct merchant graph," which is a real GLBA concern). As written, the table implies PPID+DPoP is fundamentally deficient for claim (1), which is false.

- **In-threat-model?** Yes — the construction survives for claim (2). But it must tighten §8 to stop asserting equivalence failure on claim (1), or a reviewer will correctly reject the comparison. The current framing overstates the baseline's weakness.

---

### Attack 4: `credentialSecret` Entropy Not Enforced — AS-Aided Brute-Force via Credential Commitment Tree Walk

- **Attack:** The circuit's constraint on `credentialSecret` (§2, private inputs) is `Num2Bits(251)` — a range check confirming the value is in [0, 2^251). The circuit does *not* enforce that `credentialSecret` is independent of the credential fields the AS knows. If a naive implementation derives `credentialSecret` deterministically from the operator's signing key and model hash (e.g., `credentialSecret = HMAC(operatorPrivKey, modelHash)`), then the AS — which knows `operatorPrivKey` and `modelHash` — can compute `credentialSecret` directly and then compute `Poseidon2(scopeId_i, credentialSecret)` for any known RS. The reduction in §4 step 1 says "by A-PRF, the adversary cannot determine whether j = k from the nullifiers" — this holds only if `credentialSecret` is chosen uniformly at random and independently of the AS's knowledge. The circuit does not enforce this; it is a protocol assumption with no circuit-level guarantee.

- **Why it works / why it fails:** The Poseidon PRF assumption (A-PRF, §4) is keyed on `credentialSecret`. PRF security requires the key to be drawn from a distribution the adversary cannot predict. The circuit only checks that the key is 251 bits wide. In RFC 7662's model, the AS generates all token material, so there is no equivalent "secret the issuer must not learn" — the AS's knowledge is architecturally bounded. The `AgentScopeAuth` construction requires the agent to generate `credentialSecret` locally and never expose it. This requirement is documented in §5 prose ("generated at agent enrollment time and known only to the agent") but is absent from the circuit, absent from the wire protocol spec, and has no enforcement mechanism. A reference implementation that shortcuts to a deterministic derivation (common in constrained environments) silently breaks the unlinkability proof.

- **In-threat-model?** No — construction must address this. The spec should either (a) add a `credentialSecretCommitment = Poseidon2(credentialSecret, blindingNonce2)` as a separate enrollment-time on-chain commitment that proves the agent committed to a specific secret before AS enrolled the leaf, making AS-knowledge of the credential fields insufficient to brute-force, or (b) add a protocol-level note specifying that `credentialSecret` MUST be generated via a CSPRNG seeded independently of all credential fields, with a test vector in the conformance suite.


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE production operator, WIMSE co-author. Core position: you are building a privacy layer in the identity protocol where none of the existing abstractions have meaningful footholds. My job is to find where your threat model is underspecified or where your "AS-free" claim overreaches.*

---

### Attack 1: scopeId Has No Binding to RS Identity — Colluding RSes Can Converge on a Shared scopeId

**Attack:**
Section 2 defines `scopeId` as `hash(RS domain)` and uses it as the domain separator in `scopeNullifier = Poseidon2(scopeId, credentialSecret)`. The entire unlinkability argument rests on `scopeId_a ≠ scopeId_b` across RS pairs. But the construction never specifies:

1. **Who computes `scopeId`?** The circuit takes it as a public input. Nothing binds the RS's claimed `scopeId` to a cryptographic identity credential (no TLS certificate, no SPIFFE SVID, no on-chain registry entry).
2. **How does the agent verify the RS's `scopeId`?** If the agent discovers scopeId from an RS-provided parameter at connection time (e.g., in a handshake challenge), a malicious RS can advertise any `scopeId` it wants.
3. **What prevents two colluding RSes from agreeing to use the same `scopeId`?** If RS_a and RS_b both advertise `scopeId = Poseidon("amazon.com")`, they will observe identical `scopeNullifiers` from the same agent, collapsing unlinkability to zero with zero cryptographic effort.

In SPIFFE, workload identity is bound to an X.509 SVID where the SPIFFE ID (`spiffe://trust-domain/path`) is validated by a SPIRE trust bundle rooted in hardware attestation. The RS's identity is authenticated before any credential is presented. Here, `scopeId` is a free parameter that both the agent and the RS plug in by convention.

**Why it works / why it fails against the construction:**
The reduction in §4 assumes `scopeId_a ≠ scopeId_b` as a precondition, but the construction provides no mechanism to enforce this. The IND-UNL-AS game in §3 places both RS_a and RS_b under adversary control — but in the game setup, the challenger assigns `scopeId`s. In deployment, the adversary chooses `scopeId`s. The game is not adversarially closed on scopeId selection.

A concrete exploit: The adversary operates two merchant RSes. Both advertise `scopeId = Poseidon("bank.com")`. Every agent that visits both merchants produces identical `scopeNullifier` values. The adversary trivially reconstructs the cross-merchant graph with a hash join on nullifiers.

**In-threat-model?**
**No.** The construction must specify a `scopeId` registry with cryptographic binding (e.g., on-chain mapping from RS ECDSA public key → scopeId, or requiring the RS to prove ownership of the domain via a VC/SVID before the agent accepts the scopeId). Without this, the unlinkability claim is conditional on a convention that the adversary can violate.

---

### Attack 2: The AS-Free Property Is Structurally Incompatible with Real-Time Revocation — and the Root History Buffer Makes It Worse

**Attack:**
Section 2 states: "The AS is never contacted. No token is issued." Section 7, step 4: "NFCU knows the agent exists but this is the last time it is involved."

SPIFFE/SPIRE handles this via short-lived SVIDs (default TTL: 1 hour) with automatic rotation via the Workload API. Revocation is structural: a compromised credential simply isn't renewed at the next rotation boundary, and the window of exposure is bounded by TTL.

The construction's only revocation mechanism is `expiryTimestamp` baked into the credential at enrollment time. This creates a trilemma:

1. **Long expiry** (e.g., 30 days): An operator who discovers an agent is compromised (model weights leaked, operator key exfiltrated, agent acting maliciously) has no path to invalidate the credential before expiry. The agent continues to produce valid proofs for every RS for the full remaining term, with no AS to contact, no revocation endpoint, and no mechanism to invalidate the on-chain Merkle leaf.

2. **Short expiry** (e.g., 1 hour, matching SPIFFE): The agent must re-enroll frequently. Re-enrollment is the only AS interaction, so a high re-enrollment rate reintroduces AS visibility at enrollment time — the AS sees enrollment cadence as a proxy for activity. Worse, if enrollment is rate-observable (timing of `addLeaf` transactions on-chain), the AS can infer agent activity patterns from on-chain data.

3. **Root history buffer extends the attack window**: The 30-entry root history buffer (`agentMerkleRoot` accepted if it appears in the buffer) means a credential that is "removed" by failing to renew a Merkle root inclusion can still produce valid proofs against any of the 30 buffered roots, potentially days after the intended revocation boundary.

The construction does not mention a Merkle leaf nullification path, a revocation accumulator, or any mechanism for operators to invalidate credentials outside of expiry. In §7 step 5, "NFCU cannot map [scopeNullifier] back to any enrolled agent" is framed as a privacy win, but it's simultaneously a **revocation impossibility**: NFCU also cannot revoke a specific agent's proof-generation capability without revoking the entire Merkle subtree.

**Why it works / why it fails against the construction:**
The construction defines its threat model against AS-correlation attacks but does not define a revocation adversary. A compromised-agent adversary (not in §3) operates indefinitely with a valid credential. The "AS never contacted" property that defeats traffic correlation simultaneously defeats operator remediation.

**In-threat-model?**
**No.** The IND-UNL-AS game in §3 does not model a revocation adversary. The construction must either (a) specify a ZK-compatible revocation accumulator (e.g., a Merkle inclusion proof against a separate revocation tree, with the circuit checking non-membership), or (b) explicitly bound the revocation gap and acknowledge the TTL-vs-correlation tradeoff. This is not a minor omission — it is a production deployment blocker.

---

### Attack 3: Enrollment Records Break the IND-UNL-AS Game at k-Anonymity Boundaries

**Attack:**
Section 7, step 5 states: "NFCU cannot map [scopeNullifier] back to any enrolled agent because NFCU does not know the agent's `credentialSecret`."

This is correct under A-PRF. But the AS does not need to invert the PRF. The AS holds enrollment records with full metadata:

```
(agentId, credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry), enrollmentTimestamp)
```

Note that `credentialCommitment` does **not** include `credentialSecret`. It is a deterministic function of public credential metadata. This has two consequences:

**Consequence A — AS can map credential commitments to agents.** If `modelHash`, `opPubAx`, `opPubAy`, `permBitmask`, and `expiry` are unique per agent (e.g., each agent has a unique `modelHash` or unique `expiry` assigned by the operator), the AS can build a one-to-one map from `credentialCommitment` to enrolled agent. A colluding RS that shares `blindedScopeCommitment = Poseidon3(permBitmask, credentialCommitment, blindingNonce)` with the AS cannot directly de-blind it (the nonce is private). But the AS can filter its enrollment records to the subset with the matching `permBitmask` and narrow the candidate population. For small deployments (e.g., 10 enrolled agents, 2 with `FINANCIAL_UNLIMITED`), the colluding AS+RS can de-anonymize with high probability by population inference, not cryptanalysis.

**Consequence B — The IND-UNL-AS game is underspecified for non-uniform populations.** The game in §3 places N ≥ 2 agents in the tree and asks the adversary to distinguish b=0 from b=1. But the game fixes two agents as the challenge pair and asks about their cross-RS linkage. In reality, the adversary applies the IND-UNL-AS analysis to the full enrollment population. If `permBitmask` or `expiry` partitions the population into small cohorts, the adversary's advantage is not bounded by the PRF security parameter — it is bounded by `1/cohort_size`, which may be non-negligible for real deployments.

In SPIFFE, all SVIDs in a trust domain are structurally similar (same CA, same path schema). Fingerprinting by credential metadata is not useful because all SVIDs look alike. The Bolyra construction's credential metadata (permBitmask, expiry, modelHash) is operationally necessary but creates distinguishing structure the AS can exploit.

**Why it works / why it fails against the construction:**
The cryptographic reduction in §4 is correct: the PRF assumption blocks nullifier-based de-anonymization. But the reduction is against a cryptographic adversary attacking the nullifier channel, not an inference adversary attacking the enrollment record channel. The construction's claim in §7 step 5 overstates the privacy guarantee. It should read: "NFCU cannot directly recover the `credentialSecret` from the `scopeNullifier`, but may narrow the candidate population via enrollment metadata for small cohorts."

**In-threat-model?**
**Partially.** The §3 threat model grants the AS "full state: enrollment records, issuance logs, timing" and defines the IND-UNL-AS game, but the game definition is purely cryptographic (can the adversary distinguish nullifiers?). A population-inference adversary — who uses the AS's enrollment records to build a candidate set and then matches against RS-observed public inputs — is not formalized. The construction must either (a) add a k-anonymity lower bound requirement on enrollment cohort size, or (b) amend the game to include a population-inference adversary model, or (c) require that `credentialCommitment` include a per-agent random salt (making all commitments unlinkable even to the AS's own enrollment records).

---

### Attack 4: The WIMSE Workload Proof Pattern Closes the AS-Visibility Gap — ZK Is Only Necessary for Cross-RS Unlinkability, Not for AS-Free Auth

**Attack:**
Section 8's comparison table claims: "AS is not contacted after enrollment; zero per-request visibility." The WIMSE architecture (draft-ietf-wimse-arch §5) separates the identity token from the authorization token:

- `workload_proof`: a short-lived JWT-SVID or X.509-SVID bound to the SPIFFE ID, issued by SPIRE at SVID rotation (not per-RS-request). An agent rotating SVIDs hourly contacts SPIRE once per hour, not once per RS.
- `access_token`: an AS-issued authorization token, obtained only when the agent requires it. Many RS interactions (read-only, low-risk) accept the `workload_proof` directly without an `access_token`.

Under WIMSE, the AS's per-request visibility is already near-zero for agents that use `workload_proof` directly. The SPIRE agent caches the SVID and presents it without contacting the AS. The AS is only involved in `access_token` issuance, which is scoped to explicit authorization acts, not presence.

The genuine gap is **cross-RS linkability**, not AS-per-request visibility: two RSes that both accept WIMSE `workload_proof` tokens will see the same SPIFFE ID (`spiffe://nfcu.com/agent/budgeter-001`) and can trivially correlate traffic. This cannot be fixed by WIMSE extensions without ZK — the SPIFFE ID is a stable identifier that is the point of the SVID.

The construction's `AgentScopeAuth` circuit addresses exactly this gap. The SPIFFE engineer's strongest honest objection is not "WIMSE already does this" but: **"Why not extend SPIFFE with a ZK attestor that produces a SPIFFE-compatible workload_proof with ZK-anonymous SPIFFE ID derivation?"** Specifically: replace the SVID's Subject Alternative Name with a ZK-derived ephemeral identifier (per-RS nullifier) while keeping the trust bundle, federation, and Workload API plumbing intact.

This is a protocol architecture question, not a cryptographic break of the construction. The construction survives as a cryptographic primitive but must answer: what is the trust domain integration story? Does `agentMerkleRoot` federate into SPIFFE trust domains? Is the on-chain verifier contract a trust anchor analogous to a SPIRE CA?

**Why it works / why it fails against the construction:**
The comparison in §8 is accurate for the `access_token` path but overstates the differential for the `workload_proof` path. The SPIFFE engineer's "you're reinventing at the wrong layer" attack partially lands: the AS-visibility problem is already partially mitigated in WIMSE. The attack fails against the core claim — cross-RS unlinkability is genuinely novel and cannot be achieved by any SPIFFE/WIMSE extension without ZK — but the "AS is never contacted" framing in §8 is weaker than claimed.

**In-threat-model?**
**Yes, construction survives.** The WIMSE workload_proof pattern reduces but does not eliminate the AS-visibility gap, and provides zero cross-RS unlinkability. The ZK construction is structurally necessary for the cross-scope unlinkability claim. However, the construction should acknowledge WIMSE's partial mitigation in §8 and position AgentScopeAuth as a ZK extension to WIMSE's trust model rather than a replacement of it, or explicitly define how the on-chain trust anchor composes with SPIFFE federation.
