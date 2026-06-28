# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Proving Runtime Assumption Breaks the Deployment Model

- **Attack**: Section 6 claims "<0.5s (rapidsnark)" for Groth16 proving. That number requires the `rapidsnark_prover` native binary — a compiled C++ executable checked into `circuits/build/` — running inside the agent's process. But the agents your NFCU scenario (§7) describes don't own their runtime. They run on managed inference endpoints: AWS Bedrock Agents, Azure AI Foundry, Google Vertex AI Agent Engine. None of these let you exec a native binary at inference time. The fallback is snarkjs (pure JS), which Section 6 concedes takes "<3s" — that's a 30x latency penalty versus WorkOS token issuance (<100ms), plus it requires Node.js available as a subprocess from the agent runtime. The presentation protocol (§2, step 2) says "agent generates PLONK proof π locally" — but "locally" is load-bearing and undefined. In the majority of enterprise MCP deployments today, the agent is a managed service, not a self-hosted process with filesystem access.

- **Why it works / fails**: The construction's security argument is airtight. The deployment assumption is not. The construction survives cryptographically but fails at the first integration question: "where does the prover binary live in our Kubernetes pod?"

- **In-threat-model?** No — the construction must specify a deployment architecture for environments where the agent cannot exec a native binary. A server-side proving delegation (where the agent sends private inputs to a Bolyra proving service) reintroduces the AS-trust problem the construction spends §§3-4 eliminating.

---

### Attack 2: The Adversarial-AS Threat Model Has No Enterprise Buyer

- **Attack**: Section 4 ("Why the adversarial-AS model holds") and Failure 3 in §8 spend the most ink on the strongest cryptographic claim: even a fully compromised AS cannot forge proofs. But read the NFCU scenario in §7 carefully — **NFCU is the AS**. NFCU operates its own OAuth infrastructure (or contracts Auth0/Okta). NFCU's threat model is: external attackers compromising tokens in transit, misconfigured scopes leaking privileges, or agents being hijacked. These are all solved by mTLS + short-lived JWTs + DPoP (RFC 9449), which WorkOS already ships. The adversarial-AS scenario — "what if NFCU's own identity provider betrays NFCU?" — is not in any CUSO, NCUA, or FinCEN risk register. Enterprise procurement asks: "what does this protect against?" The honest answer is: "a compromised internal identity provider." The response from the CISO: "that's not our threat; we have a SOC 2 Type II certified IdP with contractual guarantees."

- **Why it works / fails**: Section 8's "Failure 3" correctly identifies that the RFC 7662 stack has no answer to an adversarial AS. But the argument assumes the buyer perceives this as a threat worth solving. GTM-first critique: you've built a bulletproof door for a room nobody is trying to break into.

- **In-threat-model?** No — the construction must articulate a threat that the buyer's security team will find in their existing risk model. AS-blind presentation and adversarial-AS resilience are not in the FFIEC AI Risk Management framework, NCUA Letter 24-CU-02, or any enterprise security control catalog a credit union CISO will reference.

---

### Attack 3: Onboarding Complexity Fails the Procurement Gate Before the POC Starts

- **Attack**: The presentation protocol (§2) requires: (1) Circom circuits compiled and `.zkey` artifacts in `circuits/build/`; (2) a Solidity verifier deployed on Base Sepolia (§7 step 1: "enrolled in the Bolyra agent Merkle tree" = on-chain transaction); (3) the RS checking `agentMerkleRoot ∈ on-chain root history buffer` (§2 step 4a), which requires the RS to make RPC calls to Base Sepolia or maintain a local mirror; (4) a fresh `sessionNonce` generation and distribution flow that does not exist in any current MCP client/server implementation. Compare to Auth0 MCP auth: configure a client application, receive `client_id` + `client_secret`, point MCP server at the token endpoint. Zero blockchain dependencies, zero binary artifacts, zero circuit compilation. The construction's §8 table shows "model identity binding" as a Bolyra advantage — but Auth0 already binds the client to a `client_id` that represents the model. The delta is cryptographic proof of the model hash, which no current enterprise compliance requirement asks for.

- **Why it works / fails**: The construction is technically correct that no OAuth composition achieves AS-blind presentation. But "AS-blind presentation" is not in the enterprise buyer's RFP. Their RFP says "integrate with our existing IdP, pass our security review, show a working demo by Friday." The onboarding cliff — circuits, on-chain contracts, native prover binary, Base Sepolia testnet dependency — loses the deal before the cryptographic properties are ever evaluated.

- **In-threat-model?** No — the construction must define a migration path from OAuth-first deployments. "New deployments only" is not a realistic GTM for any team trying to displace Auth0 in regulated financial services, where existing vendor relationships, SOC 2 audits, and integration libraries (passport-oauth2, django-allauth, etc.) already work.

---

### Attack 4: Cross-RS Unlinkability Solves a Problem the RS Operator Already Has Full Visibility Into

- **Attack**: The session-bound `scopeCommitment` fix (§2, §4 Theorem 2) correctly prevents two colluding *external* RSes from correlating agent presentations. Section 7 step 3 highlights this: "the market data RS and trade engine cannot correlate these presentations even if they collude." But in the NFCU scenario, **NFCU owns all three RSes** — the market data service, the trade execution engine, and the compliance reporting system are all NFCU's internal services. NFCU's audit team *wants* to correlate the agent's presentations across all three to reconstruct what the agent did. The unlinkability property actively harms NFCU's audit and forensics posture. The `nullifierHash` provides per-RS replay detection, but it deliberately prevents cross-RS session linking — which is exactly what a compliance officer needs when investigating a rogue agent that manipulated market data and then covered its tracks by executing unauthorized trades. The construction's privacy guarantee is the enemy of the buyer's compliance requirement.

- **Why it works / fails**: The SSZK security argument (§4 Theorem 2) is technically sound. The problem is that the property it proves is a liability for the stated buyer. The RS unlinkability story only works if RSes are adversaries to each other and the agent operator. In regulated financial services, the operator, the RSes, and the auditor are all the same legal entity — NFCU. The privacy guarantee the construction offers them is: "your own compliance team cannot correlate your own agent's actions across your own internal services."

- **In-threat-model?** No — the construction must identify a buyer topology where RSes are genuinely independent parties with conflicting interests and no shared audit authority. The MCP ecosystem does have this topology (third-party tool servers, external APIs), but §7's NFCU scenario is the wrong example. The right scenario — an agent calling Stripe, Salesforce, and a healthcare API simultaneously — is not addressed, and that scenario requires cross-organization privacy guarantees that are harder to sell to regulated entities anyway.


## Persona: cryptographer

Applied cryptographer. Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The construction has both — so let me find where the gaps between the game definitions and the stated adversary capabilities produce real breaks, not just quibbles.

---

### Attack 1: AS Precomputation of nullifierHash Breaks SSZK — Advantage = 1

**Attack:**

The construction enrolls credentials by adding `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)` to the on-chain Merkle tree. To do so, the AS must receive (at minimum) the *commitment value* — it inserts the leaf. Under the threat model, A controls the AS entirely. Therefore A knows `credCommitment_0` and `credCommitment_1` for both challenge credentials before the SSZK game begins.

The nullifier is defined as: `nullifierHash_j = Poseidon2(credCommitment_b, sessionNonce_j)`.

A controls A_S and therefore knows both preimages. Given any observed tuple `(sessionNonce_j, nullifierHash_j)` from a challenge query, A computes:

```
H0 = Poseidon2(credCommitment_0, sessionNonce_j)
H1 = Poseidon2(credCommitment_1, sessionNonce_j)
```

If `nullifierHash_j == H0`, then `b = 0`. If `nullifierHash_j == H1`, then `b = 1`. Since C0 ≠ C1, these produce distinct values with overwhelming probability. A wins SSZK with advantage ≥ 1 − negl(λ) — in practice, advantage 1 after a single query.

**Why it works:**

Theorem 2 (§4) claims `Adv_SSZK(A) ≤ q · Adv_PRF(A') + Adv_ZK(A'') + negl(λ)`. The reduction assumes A's advantage comes only from breaking Poseidon PRF security or the ZK property. But A's winning strategy requires neither — it uses only information A possessed *before the game started*, directly as the AS. The proof reveals nothing extra; the AS's prior knowledge is sufficient. The PRF security argument in §4 step 3 says "Poseidon is a PRF under A2, the sequence {nullifierHash_j} is computationally indistinguishable from random." This is true from the perspective of a party that does NOT know the PRF key (credCommitment). A controls the AS and DOES know the PRF key for both candidates. The indistinguishability argument fails exactly here.

**In-threat-model?** **No — construction must address this.** The adversarial-AS claim in §4 is the headline differentiator, but SSZK is broken in precisely that model. A minimal fix: the nullifier must incorporate a secret unavailable to the AS — e.g., a prover-generated blinding factor committed during enrollment but never revealed to the AS. Alternatively, reformulate SSZK to only claim unlinkability against parties that do *not* possess enrolled credential commitments, making the AS explicitly out of scope for unlinkability (which contradicts §7 item 4).

---

### Attack 2: Colluding RSes Control sessionNonce — SSZK Assumption Violated

**Attack:**

SSZK game step 3 specifies: "A specifies `(requiredScopeMask_j, currentTimestamp_j, sessionNonce_j)` where each `sessionNonce_j` is fresh." Freshness is written in as a *precondition of the game* — but A controls up to n−1 colluding RSes, which means A controls the nonces those RSes send to the agent. Nothing in the circuit or the presentation protocol forces the RS to generate a fresh random nonce. The agent accepts any nonce the RS supplies.

A simple attack: two colluding RSes RS_A and RS_B both send the same fixed nonce `N = 42` to the same agent in two separate sessions. The agent computes:

```
scopeCommitment_A = Poseidon3(permBitmask, credCommitment, 42)
nullifierHash_A   = Poseidon2(credCommitment, 42)

scopeCommitment_B = Poseidon3(permBitmask, credCommitment, 42)   ← identical
nullifierHash_B   = Poseidon2(credCommitment, 42)               ← identical
```

RS_A and RS_B observe identical `(nullifierHash, scopeCommitment)` tuples and trivially link both presentations to the same agent — Adv_SSZK = 1 with no cryptographic work.

**Why it works / why it fails against the construction:**

The entire cross-RS unlinkability argument in §4 (Theorem 2, step 4) reduces to "each `sessionNonce_j` is fresh, so the PRF outputs are independently distributed." This reduction holds only if nonce freshness is *enforced*, not merely assumed. The construction enforces nonce freshness only for replay prevention on the *honest RS's* used-nonce set — not for inter-RS nonce coordination. The honest-RS model silently smuggled into SSZK contradicts the stated adversary that controls n−1 RSes.

A structural fix requires the agent to contribute to nonce generation — e.g., a commit-reveal protocol where the agent samples its own randomness `r`, the RS sends `N_RS`, and `sessionNonce = H(r, N_RS)`. The agent's `r` must be committed before `N_RS` is known, preventing the RS from back-computing. This adds one round trip and must be enforced in the presentation protocol description, not just assumed in the game.

**In-threat-model?** **No — the SSZK game as written admits a trivially winning strategy for the stated adversary.** The game must either restrict nonce choice to honest RSes (contradicting the adversary model) or enforce joint nonce generation.

---

### Attack 3: Groth16 Subverted CRS Breaks All Security Properties

**Attack:**

Theorem 1 (SSU) and Theorem 2 (SSZK) both invoke assumption A1 — "knowledge soundness of Groth16." Knowledge soundness of Groth16 holds in the CRS model only when the CRS was generated honestly. Under a subverted CRS — one where the toxic waste `(α, β, γ, δ, τ)` is known to the adversary — the following holds: for any statement `x` and any target output `y`, there exist fake proving keys such that `Groth16.Verify(vk, x, π)` accepts for a proof `π` that encodes no valid witness. The construction names "sound under adversarial AS" as a headline property in §1, but the adversarial-AS threat model does not include the Groth16 trusted setup as an AS control surface. This is an omission, not a design choice.

**Why it works / why it fails against the construction:**

No trusted setup ceremony is described, no MPC protocol is cited (Hermez ceremony, MACI-style), and no mechanism for independent CRS verification is specified. In a deployment where the operator (or even the AS) conducts the per-circuit trusted setup, this party learns the toxic waste and can forge SSU proofs on demand: "prove that permBitmask satisfies requiredScopeMask* for any requiredScopeMask*" — collapsing SSU security to zero.

For the PLONK variant: the universal KZG SRS is also a trusted setup. The PLONK construction avoids the per-circuit ceremony but does NOT avoid trusted setup entirely. A subverted universal SRS breaks PLONK for every circuit simultaneously, which is worse in deployment. The construction uses the language "no per-circuit ceremony" to suggest setup security is improved for PLONK, but the SRS generation trusted setup remains and is larger in attack surface.

**Reduction inversion:** The construction's SSU reduction (§4, Theorem 1) extracts a witness from any forging adversary via knowledge soundness. But the knowledge extractor exists only in the honest CRS model. A subverted CRS allows proofs without corresponding witnesses; no extractor can recover a witness because none exists. The reduction breaks at step 2 of the sketch.

**In-threat-model?** **Partially — the construction must explicitly bound its security to the honest-CRS assumption and specify how that assumption is instantiated.** The adversarial-AS model is hollow if the AS conducted or influenced the Groth16 per-circuit setup. Even if the AS did not, the setup ceremony participants must be enumerated and the multi-party computation audited.

---

### Attack 4: agentMerkleRoot as Epoch-Correlated Anonymity Set Reducer

**Attack:**

Step 5 of Theorem 2 states: "`agentMerkleRoot`: Both C0 and C1 are enrolled in the same tree, so the root is identical regardless of b. This signal leaks nothing."

This analysis is correct only in steady state with synchronized enrollment epochs. But the construction specifies a 30-entry root history buffer (§2, step 4a), meaning the RS accepts proofs for any root within the last 30 tree states. Because the Merkle tree is append-only and each enrollment updates the root, the specific `agentMerkleRoot` value in a proof implies a cohort: all agents enrolled between root R_{k} and R_{k+30}. If enrollment rates are low — plausible in a specialized enterprise deployment (§7, NFCU) — this cohort may be small. An adversary observing `agentMerkleRoot = R_k` across a sequence of sessions knows the presenting agent was in the enrollment cohort corresponding to that root, and that the credential has not been rotated (no re-enrollment) since.

Two colluding RSes seeing the same `agentMerkleRoot = R_k` in two proofs from different sessions cannot be told apart by the session-bound outputs — but they know the presenting agent is in the SAME cohort in BOTH sessions. In a low-enrollment-rate deployment, "same root" may identify the agent up to a set of size O(1).

**Why it works / why it fails against the construction:**

The SSZK game explicitly places C0 and C1 in the same tree, making the root identical. But the game considers only two agents. In a real deployment, A's goal is not only distinguishing C0 from C1 in the game but correlating sessions of the same agent across RSes. If the tree has N agents and roots update per-enrollment, two colluding RSes seeing the same root `R_k` know the agent is one of at most (history buffer width × enrollment rate) agents. For NFCU with 100 enrolled agents and a 30-root window, this is 30 agents — not negligible anonymity set reduction.

Further: the 30-entry history buffer implies that presentations can be made against roots up to 30 enrollments old. If A controls the AS and can throttle new enrollments (denial-of-service on enrollment, explicitly allowed by the threat model in §4: "A compromised AS can refuse to enroll new agents"), A freezes the root at `R_k` and ensures that every agent using that root is identifiable as "enrolled before the freeze." The anonymity set does not grow; it is frozen.

**In-threat-model?** **Partially — the construction must specify minimum anonymity set size as a parameter and the root history buffer size must be analyzed against enrollment rate in the SSZK proof.** The current game definition assumes the game-level tree is large enough that root equality is non-informative. This must be made explicit and bounded.


## Persona: cu_ciso

### Attack 1: The Audit Trail Is Cryptographically Opaque to My Examiners

- **Attack:** I pull out NCUA Part 748, Appendix A, Section II.C: "The security program must include... audit controls that record and examine activity on the institution's information systems." My NCUA examiner shows up and asks: "Show me every time Agent X accessed member financial records in Q3." I open the on-chain registry and see `nullifierHash = 0x3f7a...` and `scopeCommitment = 0xab12...`. I cannot tell the examiner *which agent*, *which resource server*, or *what permissions were exercised* — because cross-RS unlinkability (Section 4, Theorem 2, SSZK) is a stated design goal. The privacy guarantee you're selling me is legally indistinguishable from destroying evidence. GLBA Safeguards Rule §314.4(e) requires monitoring and testing of the security program. A proof system whose core selling point is that even colluding RSes can't reconstruct access history is structurally incompatible with that requirement.

- **Why it works:** The construction succeeds at zero-knowledge but fails at accountability. The SSZK game (Section 3) explicitly models the adversary as "two colluding RSes that pool transcripts" — and proves they cannot link sessions. But my *compliance function* IS that colluding RS. I need the ability to reconstruct "Agent Y presented with FINANCIAL_MEDIUM scope to the trade execution RS at 14:32 UTC on Sept 4." The construction gives me no mechanism for this. `sessionNonce` is RS-generated and ephemeral. There is no logging layer between the circuit and the chain. The construction's threat model and NCUA's audit requirements are in direct opposition.

- **In-threat-model?** No — the construction must address this. A regulated institution needs a privileged audit path (e.g., an institution-controlled logging sidecar that records `(agentCredentialID, requiredScopeMask, sessionNonce, timestamp)` before proof generation) that is explicitly outside the ZK layer. This needs to be in the deployment architecture, not hand-waved to the operator.

---

### Attack 2: Operator EdDSA Key Compromise Makes Revocation Impossible and Examiners Hostile

- **Attack:** Section 4 states: "A compromised AS... cannot retroactively revoke a presentation already verified on-chain (immutability)." You call this a feature. I call it a category-1 incident response failure. My scenario: an operator's EdDSA signing key (Baby Jubjub private key) is exfiltrated via a compromised CI/CD pipeline. Every agent credential ever signed by that key is now suspect. Under NCUA 748.1 and the FFIEC Cybersecurity Assessment Tool (Domain 3 — Cyber Incident Management), I am required to contain the incident and terminate unauthorized access. The construction's immutable Merkle tree means I cannot invalidate existing credentials — they remain valid until `expiryTimestamp` lapses (Section 2, `LessThan(64)` gadget). What is that expiry window? If it's 90 days, I have 90 days of unrevocable agent access after a key compromise. My examiner will cite this as a critical gap in my incident response plan.

- **Why it works:** The construction's Merkle tree is append-only by design (Section 4: "The AS cannot modify the tree without a transaction visible to all"). Key compromise requires emergency revocation, not append. The 30-entry root history buffer (Section 5) compounds this: even if I publish a new root that excludes compromised credentials, the RS's verification accepts any root in the 30-entry window. Depending on block times and buffer management, old roots remain acceptable for a meaningful time window. The construction has no emergency revocation path, no credential blocklist, and no out-of-band kill switch. This fails FFIEC CAT Domain 3 (Escalation and Notification) and NCUA's expectation of documented access termination procedures.

- **In-threat-model?** No — the construction explicitly defers revocation to expiry and treats immutability as a security property. A regulated deployment needs a revocation mechanism (e.g., a separate on-chain revocation registry that the RS checks alongside the Merkle root, with a defined SLA for revocation propagation) and a documented key ceremony that satisfies GLBA §314.4(c) access controls.

---

### Attack 3: The On-Chain Root Anchor Is a Third-Party With No SLA

- **Attack:** Section 5 maps `agentMerkleRoot` to the "Agent Merkle tree, §3.1" and the deployment scenario (Section 7) uses Base Sepolia. Step 4a of the presentation protocol says: "RS verifies: agentMerkleRoot ∈ on-chain root history buffer." My question is simple: what is Base Sepolia's uptime SLA? What is the fallback when the chain is congested or the RPC endpoint is unavailable? My core processor (Fiserv, Jack Henry) has a contractual 99.9% uptime SLA. Base Sepolia, being a public testnet, has no SLA at all — and even Base mainnet's uptime is governed by the L2 sequencer, which is a centralized component operated by Coinbase. Under NCUA Part 748 and the FFIEC Third-Party Risk Management guidance (2023), I must assess the risk of every third party in my critical path. "The blockchain" is a fourth-party dependency I cannot audit, cannot contract with, and cannot hold accountable during an NCUA exam. If the RS cannot verify `agentMerkleRoot ∈ on-chain root history buffer` because the RPC endpoint is down, what happens? The construction is silent on fallback behavior.

- **Why it works:** The 30-entry root history buffer (Section 5) is designed as an availability hedge — stale roots remain valid. But this introduces a different risk: a stale root may not reflect recent revocations or enrollments. The construction has a fundamental tension between availability (accept old roots) and consistency (revocations must propagate). For a CU running payment settlement or portfolio management agents, neither pole of this tradeoff is acceptable without explicit SLA definition. The FFIEC CAT expects third-party dependencies to be inventoried, assessed, and contracted — none of which applies to Base.

- **In-threat-model?** No — the construction treats on-chain anchoring as a security primitive without addressing its availability and SLA characteristics. A production deployment needs: (1) a defined RPC provider with contractual SLA, (2) a fallback caching layer with explicit staleness bounds, and (3) an operator-controlled root registry that can be mirrored off-chain for the RS, with the on-chain source as the authoritative tie-breaker.

---

### Attack 4: My Tier 1 Ops Team Cannot Operate This at 2am

- **Attack:** Member calls at 2am: "I can't access my account — the app says the AI agent failed authentication." My Tier 1 operator opens the runbook. The agent presented a PLONK proof. The RS returned `PLONK.Verify = false`. My operator needs to answer: was this a (a) expired credential (`expiryTimestamp < currentTimestamp`), (b) wrong Merkle root (stale root not in 30-entry buffer), (c) nullifier replay (nonce reuse), (d) circuit proving failure (snarkjs/rapidsnark error), (e) operator key rotation that invalidated the credential, or (f) requiredScopeMask mismatch? The proof is a single 192-byte blob. The error surface is entirely opaque. There is no error code, no structured failure reason, no differential diagnostic. PLONK.Verify returns `true` or `false`. The construction (Section 2, Presentation Protocol, Step 4) describes four verification checks but provides no mechanism for a failing RS to communicate *which* check failed, or for an operator to triage the failure without cryptographic expertise. Under NCUA Part 748 and GLBA §314.4(a)(3), I must have documented procedures for detecting and responding to security events — including access failures. A black-box `false` from a ZK verifier is not a diagnosable security event.

- **Why it works:** The zero-knowledge property that makes this construction valuable is exactly what makes it operationally opaque. A failed proof reveals nothing about *why* it failed. The construction provides no structured error reporting layer, no observability hooks, and no graceful degradation path. A Tier 1 operator cannot distinguish a cryptographic failure from a configuration error from an expired credential without access to the agent's private inputs — which defeats the entire point. This is not a theoretical concern: FFIEC's Operations domain in the CAT explicitly tests whether incident detection and response procedures are documented and executable by operations staff, not just security engineers.

- **In-threat-model?** No — the construction is entirely focused on cryptographic correctness and says nothing about operational observability. A production deployment needs a structured error taxonomy (credential expired vs. Merkle root stale vs. scope predicate failed), a non-ZK diagnostic sidecar (e.g., the RS echoes back which of the four verification steps failed, without leaking proof internals), and a runbook that Tier 1 can execute without a PhD in ZKPs.


## Persona: rfc7662_advocate

---

### Attack 1: The Numeric-Claim Jailbreak — "Failure 2" Is a Strawman

**Attack:** Section 8, "Failure 2" dismisses runtime-adaptive predicates by asserting "OAuth scopes are string-typed" and that the AS would need to "pre-compute and sign every possible mask conjunction." This is a strawman. A well-configured AS can embed the raw numeric bitmask as a standard JWT extension claim — e.g., `"pbm": 47` — in a token or in a jwt-introspection-response (draft-ietf-oauth-jwt-introspection-response) signed offline and cached at the RS. The RS then evaluates `token.pbm & requiredMask == requiredMask` entirely locally, with no AS roundtrip, against any mask the RS chooses at request time. No pre-computation of conjunctions is required because the bitmask arithmetic is done at the RS, not the AS.

DPoP (RFC 9449) sender-constrains the token to the agent's key, and RFC 8707 audience-binds to the RS endpoint, giving the RS: an offline-verifiable, sender-constrained, audience-bound token carrying the raw numeric permission field against which it can evaluate any predicate at runtime.

**Why it works / why it fails:** The construction's §8 "Failure 2" column entirely depends on scope strings. Against a numeric-claim deployment, the argument evaporates. The construction does not acknowledge this configuration exists, which means "Failure 2" proves only that *naïve* OAuth scope strings can't do this — not that RFC 7662 + extensions can't.

The construction's actual surviving differentiators after this attack land on Failure 1 (AS-blindness) and Failure 3 (adversarial AS). Those are real. But the "runtime-adaptive predicate" bullet in the 4-property claim is not independently unique: it's a corollary of the adversarial-AS and AS-blind properties, not a fourth independent axis.

**In-threat-model?** No — the construction must strike or substantially restate "Failure 2." The correct argument is: the numeric-claim JWT *still* requires trusting the AS's assertion about the bitmask value. The independently-verifiable claim is that in Bolyra the bitmask is enforced by arithmetic circuit constraints over an operator-signed commitment, making predicate evaluation trust-free with respect to the AS. That is real. But "OAuth can't do runtime-adaptive predicates" is false.

---

### Attack 2: SSZK Privacy Is Trivially Broken When the AS Is the Enrollment Authority

**Attack:** Theorem 2 (§4) claims `Adv_SSZK(A) ≤ negl(λ)` because the adversary does not know `credCommitment_b`. The proof rests on "Without knowing `credCommitment_b`, these [nullifierHash, scopeCommitment] look like random values."

But the SSZK game (§3) says the adversary controls the AS. In every realistic deployment — including the NFCU scenario in §7 — the AS is the enrollment authority: it receives the agent's credential parameters (or initiates the enrollment transaction) and adds the leaf to the Merkle tree. This means the adversary knows *both* `C0.credCommitment` and `C1.credCommitment` at the time the game starts, because the AS computed or recorded them during enrollment.

With that knowledge, the adversary trivially wins on the *first* adaptive query. The adversary specifies `sessionNonce_j` (they choose it per the game). They receive `nullifierHash_j`. They compute:

```
h0 = Poseidon2(C0.credCommitment, sessionNonce_j)
h1 = Poseidon2(C1.credCommitment, sessionNonce_j)
```

If `nullifierHash_j == h0`, output `b' = 0`. If `== h1`, output `b' = 1`. `Adv_SSZK = 1`, not negligible.

**Why it works / why it fails:** The reduction in §4 Theorem 2 step 3 asserts "the adversary cannot correlate nullifiers across sessions to determine whether the same credential was used." This is true against an adversary who does not know `credCommitment_b`. It is false against an AS that enrolled the credential. The game definition artificially separates "Challenger" (enrollment) from "adversary (AS)" — but the construction's own threat model (§3) says the adversary controls the AS *completely*, which includes read access to the AS database containing enrollment records.

The session-bound `scopeCommitment` (§2, the Poseidon3 hardening) does not help here because the adversary breaks the scheme via `nullifierHash`, not `scopeCommitment`.

**In-threat-model?** Yes — but it exposes a gap in the game definition. The SSZK game needs to explicitly bound what the adversary learns from the enrollment oracle. If enrollment is modelled as a black box (AS adds leaf without seeing credential internals), the proof stands. If enrollment is modelled honestly (AS sees all credential fields, as in practice), SSZK fails. The construction must pick one and defend it. The deployability claim in §7 implicitly assumes the second model.

---

### Attack 3: sessionNonce Is Not RS-Bound — One-Shot Cross-RS Replay

**Attack:** Protocol step 1 reads: "RS generates fresh sessionNonce, sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to agent." Nowhere in the protocol or threat model is the sessionNonce cryptographically bound to the RS's identity. The nullifier `Poseidon2(credCommitment, sessionNonce)` goes into the *originating RS's* replay set — not into a global registry.

An active network adversary (explicitly within the threat model: "The adversary controls the network between agent and RS") executes:

1. Intercept RS_A's challenge `(mask_A, ts_A, nonce_A)` in transit to the agent.
2. Intercept agent's response `(π_A, root, nullifier_A, scopeCommitment_A, mask_A, ts_A, nonce_A)` in transit to RS_A.
3. Forward the original exchange to RS_A normally (RS_A accepts, nullifier_A enters RS_A's set).
4. Construct a forged session at RS_B by presenting `(π_A, root, nullifier_A, scopeCommitment_A, mask_A, ts_A, nonce_A)` to RS_B as if it were a fresh presentation.

RS_B checks: `agentMerkleRoot ∈ history buffer` ✓; `PLONK.Verify(vk, publicSignals, π_A) = true` ✓ (same nonce, same proof); `nullifier_A ∉ RS_B's used-nonce set` ✓ (RS_B has never seen it); `currentTimestamp within clock skew` — potentially fails if `ts_A` is stale, but this window is typically minutes to hours. RS_B accepts.

The attack requires `mask_A ⊇ mask_B` (RS_B's required mask is a subset of mask_A). For agents with broad permissions, this is likely.

**Why it works / why it fails:** The fix is trivial: include RS endpoint URL or identity in the sessionNonce — `nonce = Hash(RS_id || random)` and enforce `Hash(RS_id || sessionNonce)` as an additional public signal the RS checks. The construction neither specifies this nor includes RS identity anywhere in the circuit's public inputs. The presentation protocol in §2 has no field for RS identity. RFC 9449 DPoP by comparison binds the `htu` (HTTP target URI) and `htm` (method) into the token, making cross-RS replay impossible at the protocol level.

**In-threat-model?** Yes — the threat model explicitly grants the adversary network control. This is a concrete gap in the presentation protocol (§2 step 1) that the construction must address before claiming cross-RS security.

---

### Attack 4: The Adversarial-AS Argument Assumes Operator ≠ AS Organizationally — A Premise That Fails in Most Enterprise Deployments

**Attack:** Section 4 ("Why the adversarial-AS model holds") grounds all four security properties in the claim that the AS cannot forge the operator's EdDSA private key. The reduction in Theorem 1 (SSU) terminates at EdDSA unforgeability on Baby Jubjub. The entire adversarial-AS separation depends on the operator key being *organizationally and infrastructurally separate* from the AS.

In the NFCU scenario (§7): "NFCU deploys AI agents... NFCU's operator signs agent credentials." NFCU is both the operator (holds the EdDSA signing key) and the party running the AS. When the construction says "if NFCU's OAuth AS is breached," it means a breach of NFCU's infrastructure — the same infrastructure that houses the operator HSM or signing service. A sufficiently privileged attacker who can compromise the AS database can also exfiltrate the operator signing key from the same security perimeter.

RFC 7662 + RFC 8705 (mTLS-certificate-bound tokens) offers a structurally comparable defense: the agent holds a private key (mTLS certificate) the AS cannot forge. The AS attests to scope; the agent proves possession at presentation time. A compromised AS can still forge the scope claim, yes — but that is already Bolyra's "Failure 3." The structural question is whether Bolyra's EdDSA-in-circuit operator key is meaningfully separated from AS infrastructure in practice, not in theory.

**Why it works / why it fails:** Against an adversary who compromises only the AS software stack (not the HSM), the construction's argument holds: the operator's EdDSA private key lives in a separate HSM, and AS process compromise doesn't yield the key material. Against an adversary with full organizational access (exfiltration, insider threat, supply chain), both fail equally. The construction implies a stronger threat model than it delivers in the enterprise case, where the AS and the operator key share a security boundary.

The genuine surviving claim: if an organization deliberately architects with a hardware-isolated operator signing key (e.g., HSM managed by a separate team under dual-control), Bolyra provides a cryptographic guarantee that the AS cannot retroactively modify presentation semantics — an RS that verified a proof cannot be told later "actually that agent lacked permission X." RFC 7662 has no equivalent: AS-controlled token revocation can rewrite history at introspection time. This is real, but the construction should scope the adversarial-AS argument to the HSM-isolated operator key model rather than the general enterprise deployment.

**In-threat-model?** Partially. The SSU/SSZK game definitions treat the operator key as outside adversary control, which is a modeling choice, not a protocol property. The construction should add a deployment prerequisite: "this construction provides SSU/SSZK security under adversarial AS *if and only if* the operator EdDSA key material is isolated from AS infrastructure (e.g., hardware-separated HSM)." Without this qualifier, the adversarial-AS advantage is overstated for the typical enterprise deployment this construction targets.


## Persona: spiffe_engineer

---

### Attack 1: This Is a SPIFFE Attestor Plugin, Not a New Protocol

**Attack:** The entire construction maps one-to-one onto SPIFFE/SPIRE primitives. The operator EdDSA keypair is the SPIRE server's intermediate CA. The Merkle tree enrollment is SPIRE node attestation. The SVID (JWT or X.509) is the credential commitment. SPIRE already supports custom attestor plugins — a ZK attestor that wraps the `SelectiveScopeProof` circuit is a ~500-line Go plugin, not a new protocol. The "AS-blind, runtime-adaptive" presentation is WIMSE token narrowing (draft-ietf-wimse-workload-identity-token §4.3): the agent exchanges a broad JWT SVID at the SPIRE Workload API for a narrow audience-restricted token using RFC 8693 `token_exchange`, and the RS verifies it offline against the SPIRE bundle endpoint. No AS roundtrip required at presentation time.

**Why it works / why it fails:** The construction doesn't engage with this framing at all. Section 8 ("Why the baseline cannot match") only addresses RFC 7662 + BBS+ and never considers SPIFFE/WIMSE. The WIMSE token exchange gives AS-blind presentation if the RS holds the SPIRE bundle. The "runtime-adaptive predicate" attack in Failure 2 only works against string-typed OAuth scopes — it doesn't address WIMSE's capability model, which can carry structured attributes. The construction's claim of novelty depends on ignoring an entire deployed workload-identity stack.

**In-threat-model?** No — the construction must engage with SPIFFE + WIMSE, not just RFC 7662. The strongest form of the claim (§8, Summary table) requires a direct comparison against WIMSE token exchange with structured claims, not just OAuth scope strings.

---

### Attack 2: Operator Key Custody Collapses the Adversarial-AS Threat Model

**Attack:** Section 3 places the operator's EdDSA signing key outside the adversary's control: "The adversary does NOT control … the operator's EdDSA signing key." But the threat model also says the adversary controls the AS "completely — can read/modify its database." In every realistic enterprise deployment, the entity operating the AS is the same entity that manages credential issuance, which means managing the operator signing keys. If the AS's database is compromised, the HSM or KMS holding the operator signing key is almost certainly co-located in the same trust boundary. The construction splits one trust relationship (AS) into two (AS + operator key) and then claims the second is immune by fiat. This is the SPIFFE bootstrap problem in disguise: SPIRE's trust chain bottoms out at node attestation (TPM, cloud instance identity doc, k8s service account JWT) — a hardware-rooted trust boundary. Bolyra's analogous root is the operator EdDSA key with no specified custody model. The adversarial-AS claim (§4, "Why the adversarial-AS model holds") holds only if operator key custody is genuinely independent of the AS, and the construction never specifies how.

**Why it works / why it fails:** The construction's §7 NFCU scenario says "NFCU's operator signs agent credentials" — NFCU is the entity running the AS. The "fully compromised AS" adversary model requires NFCU to have signed credentials with correct permissions before being compromised, and then never rotates the tree root. A post-compromise enrollment of a malicious credential is indistinguishable from a legitimate enrollment because the attacker controls the Merkle tree append operation (they compromised the AS, which is also the enrollment infrastructure). The on-chain tree is append-only and consensus-protected, but the adversary can append a new fraudulent credential before the construction claims adversarial control begins. The SSU reduction in Theorem 1 doesn't bound this attack vector.

**In-threat-model?** No — the construction must specify operator key custody and clarify where the adversarial-AS boundary sits relative to enrollment infrastructure.

---

### Attack 3: The On-Chain Root Anchor Trades One Trusted Third Party for Another

**Attack:** Step 4a of the presentation protocol requires the RS to verify `agentMerkleRoot ∈ on-chain root history buffer (30-entry window)`. This introduces a blockchain dependency that SPIFFE avoids entirely. In a SPIFFE deployment, an RS verifies an SVID offline against the SPIRE bundle (a CA certificate chain), which is a ~2 KB file, cached locally, refreshed via the SPIRE Bundle API with short TTLs. No network call required at verification time. Bolyra's RS must either: (a) maintain a live connection to Base Sepolia and query the on-chain contract at each verification, or (b) cache the root history buffer and manage its freshness. Option (a) adds L2 RPC latency (~50–100 ms) to every RS-side verification. Option (b) creates a staleness window — a revoked root (agent Merkle tree updated to remove a compromised leaf) won't be reflected until the cache refreshes. The 30-entry window is an operational parameter with no specified TTL or invalidation protocol. SPIFFE's SVID rotation (default 1-hour TTL, automatic re-issuance) gives a deterministic revocation bound; Bolyra's root history window does not.

**Why it works / why it fails:** Section 4 ("Why the adversarial-AS model holds") lists "retroactive revocation" as something the AS cannot do — "immutability." But this cuts both ways: if a credential is compromised, it cannot be purged from the Merkle tree, only overwritten by advancing the root. RSes holding a stale root cache from within the 30-entry window will still accept proofs from a compromised credential. The construction never specifies how RS-side root cache freshness is enforced or what the revocation latency bound is.

**In-threat-model?** No — the construction must specify root cache freshness semantics, RS root-sync protocol, and revocation latency bound. "On-chain, consensus-protected" is not a substitute for a concrete revocation protocol.

---

### Attack 4: The SSZK Game Grants the Challenger Nonce Selection — RS Nonce Entropy Is Unaddressed

**Attack:** Section 3.2 (Game SSZK) says "A specifies (requiredScopeMask_j, currentTimestamp_j, sessionNonce_j) where each sessionNonce_j is fresh." The adversary in the SSZK game *generates the nonces*. But in §2's presentation protocol, Step 1 says "RS generates fresh sessionNonce" — the RS generates nonces, not the agent and not the adversary. The game is modeling a scenario where the adversary-controlled RSes choose the nonces, which is consistent with "n-1 colluding RSes." Fine. But the cross-session unlinkability argument in §4 (Theorem 2, point 4) depends on "each `sessionNonce_j` is fresh" — where freshness is defined by the RS's RNG quality. If two colluding RSes coordinate to reuse the same `sessionNonce` across two sessions (or if their nonce RNG is weak, e.g., time-seeded), the construction degrades to the original `Poseidon2` vulnerability: `scopeCommitment_j == scopeCommitment_k` iff the sessions share a nonce. In SPIFFE, mTLS nonce freshness is guaranteed by TLS 1.3's built-in nonce mechanism. Bolyra delegates nonce generation to the RS with no specified entropy requirements, no nonce reuse detection, and no protocol-level freshness guarantee. A SPIFFE deployment inherits TLS 1.3's nonce guarantees for free; Bolyra requires every RS implementer to independently implement a secure CSPRNG and nonce deduplication.

**Why it works / why it fails:** The SSZK proof holds under the assumption of fresh nonces, but the construction shifts the security burden to RS implementers without specifying a mechanism. In SPIFFE/WIMSE, nonce freshness is a TLS property, not an application property. The §2 presentation protocol says the RS sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the agent, but there is no protocol step where the agent challenges the RS's nonce freshness or where nonce reuse across RSes is detected. Two colluding RSes that pool nonces and deliberately reuse a value can collapse cross-session unlinkability to zero without breaking any cryptographic primitive — they're just coordinating their own nonce generation.

**In-threat-model?** No — the construction must specify RS nonce generation requirements (CSPRNG minimum, bit length, uniqueness scope) and define whether nonce reuse across RSes is a protocol violation or a deployment concern. The SSZK security bound should be stated as conditional on RS nonce freshness, with a concrete mechanism for enforcing it.
