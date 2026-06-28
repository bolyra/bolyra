# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Revocation is not a threat model item — and that's the problem

- **Attack**: The construction's threat model explicitly states the "on-chain Merkle tree state is immutable once committed; root history buffer is append-only" (§3). The 30-entry circular root history buffer is marketed as a liveness feature. But from a credit union's operations desk: what happens when the loan agent is compromised at 2am on a Saturday? The operator needs to revoke that credential. The construction offers no mechanism — the credential commitment is already in the immutable Merkle tree, and the root history buffer will keep serving that root for 30 tree updates, which in a low-churn deployment could be days or weeks. Auth0 and WorkOS revoke a token server-side in milliseconds via a simple API call. The NCUA's Information Security Examination booklet (§II.A) requires that institutions maintain controls for "timely termination of access" — "30-root-updates later" does not satisfy this.

- **Why it works / why it fails**: The construction does not address revocation in any section. §7 discusses NCUA compliance in terms of audit-trail replay but says nothing about emergency revocation. The only recourse visible in the protocol is to rotate the on-chain Merkle root — but that requires an operator-initiated transaction, and the root history buffer's purpose is to give live proofs a validity window. Revocation and liveness are in direct tension, and the construction does not resolve it.

- **In-threat-model?** No — the construction must address emergency credential revocation with a concrete SLA. Without it, every enterprise procurement review will fail at "what happens when we fire an AI vendor at midnight."

---

### Attack 2: The sub-1-second claim is a native binary dependency that most deployments cannot satisfy

- **Attack**: §6 says Groth16 with rapidsnark is "<1s on a server with rapidsnark binary." But the credit union's AI agent is not running on a dedicated server with a compiled rapidsnark binary — it is running in a Lambda function, a Kubernetes sidecar, or a SaaS-managed AI orchestration platform. The snarkjs/WASM fallback is listed as "< 8s on a modern laptop." The attack prompt is direct: "WorkOS issues tokens in <100ms. Why would any operator accept that tradeoff?" The answer "use rapidsnark" requires: (1) a compiled native binary per target architecture, (2) a persistent compute process (not serverless), (3) a deployment and patching lifecycle for that binary. The construction acknowledges this only in §6 under "Proving time targets" without addressing the operational requirement. The agent in §7 generates a proof "via rapidsnark (<1s)" as if rapidsnark is a drop-in library call, but it is a native binary launched via subprocess (`sdk-python` already does this pattern per the Python SDK notes). This is a DevOps dependency that a solo-founder protocol cannot paper over with benchmark numbers.

- **Why it works / why it fails**: The construction's competitive advantage in §8 Gap 4 ("128-byte constant proof") is real cryptographically. But the delivery mechanism for that proof requires infrastructure the buyer must operate. Auth0 delivers `POST /oauth/token` → 100ms → done, from any HTTP client, no binary required. The asymmetry is not about proof size; it is about who owns the compute.

- **In-threat-model?** No — the construction must specify the proving infrastructure deployment model, not just the proving time. A construction that requires a native binary server for the happy path has a UX cliff that the buyer's platform team will immediately reject.

---

### Attack 3: "AS-blind" is a compliance liability, not a competitive moat

- **Attack**: §8 Gap 1 leads with "No AS is contacted. The RS specifies `requiredScopeMask` and receives a proof — the AS is not in the protocol flow at all." This is marketed as adversarial-AS soundness. From a NCUA-regulated credit union's perspective, the AS being absent from the authorization flow is a problem, not a feature. NCUA Supervisory Letter 07-CU-13 (Third-Party Relationships) and the FFIEC IT Handbook (Access Control) require that the institution maintain a centralized record of every access authorization event — who authorized what, when, under what policy. An "AS-blind" flow means: no SIEM integration point, no real-time policy enforcement update without re-enrollment, no centralized rate-limiting of agent access at the authorization layer, no compliance report that the exam team can pull without parsing ZK proof transcripts. The §7 scenario says "Under NCUA examination, the credit union can replay the proof transcript to demonstrate that the agent was authorized for exactly the requested scope." The NCUA examiner is not going to replay a Groth16 proof. They are going to ask for a CSV export from the IAM platform audit log. Auth0 and WorkOS produce this in two clicks. Bolyra requires building a custom indexer for on-chain events plus proof transcript storage.

- **Why it works / why it fails**: The construction's §3 threat model correctly argues that a compromised AS cannot forge proofs. The construction's §7 deployment scenario incorrectly assumes that a credit union's compliance need is "can we cryptographically prove the scope was valid" rather than "can we produce a centralized audit trail in the format our examiners accept." These are different problems. The ZK property solves the first; it actively undermines the second by removing the AS from the flow.

- **In-threat-model?** No — the construction assumes the adversarial-AS threat is the credit union's primary concern. The actual procurement objection is regulatory compliance tooling, not cryptographic trust anchor selection. The construction needs a centralized audit bridge or must explain why NCUA will accept on-chain proof transcripts as an examination artifact.

---

### Attack 4: Public blockchain dependency is a third-party vendor risk that fails FFIEC review

- **Attack**: The construction requires an "on-chain agent Merkle tree" on a public blockchain (Base, per the deploy target in `CLAUDE.md`). Every time an operator enrolls a new agent, a transaction is written to a public blockchain. The RS must either query the on-chain root history buffer or cache it. This creates: (1) **public enrollment disclosure** — the Merkle tree is public, so any observer can see how many agents the credit union has enrolled and when, even if credential commitments are opaque. (2) **Blockchain network dependency** — if Base experiences congestion, an L1/L2 sequencer outage, or a smart contract upgrade, the RS's root cache goes stale and proof verification fails or degrades. The construction's §2 says "root history buffer is append-only" — meaning the RS must trust that the on-chain root it cached is current, or it must poll the chain on every request. (3) **FFIEC technology risk** — FFIEC guidance requires institutions to assess concentration risk in third-party technology providers. A solo-founder ZK protocol anchored to a specific L2 blockchain is a novel and unreviewed dependency class for most credit union IT risk programs. Auth0 runs on AWS with published SLAs, SOC 2 Type II, ISO 27001, and FFIEC-recognized cloud security posture. "Trust the Base sequencer and our Solidity verifier contract" is not a comparable answer.

- **Why it works / why it fails**: The construction's §8 Gap 3 argues correctly that on-chain roots provide adversarial-AS soundness. But the procurement attack is not about soundness — it is about operational risk classification. A credit union's IT risk committee will classify a blockchain dependency as an emerging technology with unclear regulatory posture, require a risk assessment, and likely require pre-approval from NCUA before deploying. This is a real sales cycle blocker that the construction does not acknowledge.

- **In-threat-model?** No — the construction does not address the operational risk posture of the on-chain dependency, the behavior under L2 outage, or the FFIEC third-party risk assessment process that any credit union IT committee will require before deploying.


## Persona: cryptographer

Applied cryptographer. Unless I see a game definition, a correct reduction, and a simulator construction, it's marketing. The construction below is more carefully specified than most, but has at least three problems that survive contact with a reduction.

---

### Attack 1: Nullifier Encodes the Bitmask — The SI Reduction Is Unsound

**Attack**: The adversary in `SI(λ, Q)` receives `nullifierHash_j = Poseidon2(credComm_b, sessionNonce_j)` as a public output. Both `credComm₀` and `credComm₁` are enrolled public Merkle leaves; `sessionNonce_j` is a public input. The adversary computes both candidate values:

```
h₀ = Poseidon2(credComm₀, sessionNonce_j)
h₁ = Poseidon2(credComm₁, sessionNonce_j)
```

It observes `nullifierHash_j` and compares. This is a deterministic arithmetic operation requiring zero cryptographic assumptions. The adversary identifies `b` with probability 1 from a **single query** (j = 1).

**Why it works / why it fails against the construction**: The root cause is `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiry)`. Since `B₀ ≠ B₁` and Poseidon is collision-resistant (**A3**), we have `credComm₀ ≠ credComm₁`. The nullifier therefore takes provably distinct values for b=0 and b=1. The adversary needs no proof oracle.

The construction's §4 response is: "the Groth16 ZK guarantee covers public outputs: the simulator produces `(π̃, outputs)` jointly indistinguishable from real `(π, outputs)`." **This is wrong.** The standard Groth16 ZK property is: for a *fixed* statement `x`, the proof `π` is simulatable — `{Prove(pk, x, w)} ≈_c {Sim(vk, x)}`. The statement `x` is fixed; ZK hides the *witness given the statement*, not the statement itself. Here `x₀` and `x₁` contain provably distinct `nullifierHash` field elements. The adversary needs only to read the public outputs; it never examines `π`. ZK says nothing about hiding `x₀` from `x₁`.

The claimed "formal argument" invokes a non-standard ZK notion: that Groth16 produces `(π, f(w))` indistinguishable across different witnesses, even when `f(w)` is a *public output*. That notion doesn't exist in any standard definition of ZK and is false by the semantic meaning of "public."

**In-threat-model?** **Yes, this breaks the construction.** The SI game security claim is vacuous: the adversary wins with probability 1 at no computational cost. The construction cannot fix this by calling it a "nullifier purpose is replay detection, not privacy" — both `credComm₀` and `credComm₁` are enrolled, but the nullifier still encodes which of the two was used via the bitmask.

**Fix direction**: Decouple the nullifier from `permissionBitmask`. For example, derive a separate `identitySecret = Poseidon3(modelHash, Ax, Ay)` independent of the bitmask and compute `nullifierHash = Poseidon2(identitySecret, sessionNonce)`. This requires a new private input and a restatement of the SI game to a weaker "scope-only" variant. The trade-off is that two credentials with the same model/operator identity produce colliding nullifiers — replay protection degrades unless the RS is partitioned by agent identity.

---

### Attack 2: Per-Circuit Trusted Setup Is Unspecified — SSU Theorem Has a Vacuous Hypothesis

**Attack**: **A1** ("knowledge soundness of Groth16 in the generic group model") is the foundation of the SSU theorem. Groth16 knowledge soundness holds only when the CRS is *honestly generated* with the toxic waste (trapdoor `τ`) destroyed. A party that retains `τ` for the `AgentSelectiveScope` circuit can produce a valid proof `(π*, pubSignals*)` for any statement, including permission bitmasks that were never operator-signed and credentials that are not Merkle members. The EdDSA check and Merkle membership check are bypassed entirely — a Groth16 proof with a known trapdoor is a simulation, not an extraction.

The construction's §7 deployment scenario (credit union operators) relies on this circuit-specific key. The construction cites `pot16.ptau` as the universal SRS but is silent on what ceremony produced the circuit-specific `zkey` for `AgentSelectiveScope`. The `AgentPolicy` and `Delegation` circuits share the same gap. No ceremony transcript is referenced; no multi-party computation is described; no verifiable contribution record is cited.

**Why it works / why it fails**: The SSU security argument in §4 opens with "Challenger runs `Setup(1^λ)` producing Groth16 CRS `(pk, vk)`." In a game, the challenger is honest by definition. In deployment, the entity that ran `compile:circuits` and `snarkjs groth16 setup` is the trust anchor. If it is a single party (a solo-founder dev machine, as the CLAUDE.md workspace context strongly implies), the SSU theorem's hypothesis is not satisfied in practice. A1 requires "generic group model" — GGM arguments assume the adversary cannot forge CRS elements, but a CRS generator with `τ` is not a generic-group adversary; it is the trusted setup.

**In-threat-model?** **Partially.** The threat model (§3) specifies "A does not control the BN128 pairing" and "A does not control the on-chain Merkle tree state" but says nothing about A controlling the CRS generator. This is the classic *subverted setup* threat, and the construction has not defined its adversary's power over the ceremony. PLONK is listed as an alternative with the rationale "avoids per-circuit ceremony" — but the construction still uses `pot16.ptau` (a universal SRS) which has the same trust assumption, merely elevated to the universal level. The construction must specify a ceremony or switch its security claim to the CRS model with an explicit trust assumption on the setup party.

---

### Attack 3: SSU Needs Simulation-Extractable Knowledge Soundness, Not Standard Knowledge Soundness

**Attack**: The SSU game requires the extractor to operate against an adversary `A` that has seen `Q` honestly generated proofs `(π₁, …, πQ)` before producing its forgery `π*`. This is exactly the *simulation-extractability* (SE) setting. The construction's A1 cites Groth16 knowledge soundness in the GGM — but standard Groth16 knowledge soundness is defined for an adversary that has seen *no* honest proofs. In the multi-proof adaptive setting (the SI game runs Q rounds of honest proofs), the standard extractor requires rewinding the adversary. Rewinding resets the adversary's view of the Q honest proofs, which changes the internal state the adversary used to produce `π*`. The knowledge extractor's output may not be valid under the original proof transcript.

Concretely: Let `A` use the Q observed honest proofs to perform a Fiat–Shamir mauling or a proof-of-knowledge reuse attack (plausible for PLONK, which uses a random oracle; less so for Groth16 in GGM). Then the standard knowledge extractor, which rewinds to re-query the PLONK random oracle, may extract a witness only under the rewound oracle — not the real oracle. The SSU game does not bound this gap.

The simulation-extractable Groth16 variant (see Groth–Maller 2019, and FKMV 2012 for the general framework) provides straight-line extraction without rewinding. The construction relies only on base Groth16 knowledge soundness. Whether standard Groth16 achieves SE in the GGM is believed-but-unproven; the construction should either cite a SE-Groth16 variant or restrict the SSU adversary to a setting where it sees no honest proofs before forging.

**In-threat-model?** **Yes — this is a real gap for the PLONK path.** For Groth16 in the pure GGM (no random oracle), the argument is cleaner but still relies on the non-rewinding extractor. For the PLONK path (A2, AGM + ROM), the random oracle makes this concrete: the adversary in the SI game sees Q proofs, each of which involves a transcript with the ROM. Rewinding for extraction changes ROM query history. The SSU security reduction for the PLONK deployment has an unquantified SE gap. The construction should state A1/A2 with an explicit SE qualifier and cite the corresponding theorems, or it cannot use the SSU theorem as stated.

---

### Attack 4: Predicate-Channel Leakage Understated Under Implication Rules

**Attack**: §4 claims "Q adaptive queries with arbitrary masks yield at most Q bits of information about B (one pass/fail bit per query)." This treats all 64 bits as independent. But the construction itself enforces implication constraints:

```
bit4 → {bit3, bit2}
bit3 → bit2
```

A single query with `requiredScopeMask = e₄` (singleton bit 4, value `0b00010000`) has three possible outcomes: FAIL (bit 4 unset) or PASS. If PASS, the circuit has *already constrained* bits 3 and 2 to be set (the cumulative implication gadget rejects any bitmask where bit 4 is set but bits 3 or 2 are not). A PASS response reveals three bits simultaneously, not one.

More formally: the predicate-agreement constraint in the SI game requires `(B₀ & M_j == M_j) ⟺ (B₁ & M_j == M_j)`. For `M_j = e₄`, this constraint is `(B₀[4] == 1) ⟺ (B₁[4] == 1)`. But due to implication, if both bitmasks agree on bit 4 = 1, they are also both constrained to have bits 3 and 2 set. A single PASS query on the bit-4 mask thus collapses three bits simultaneously. The adversary reaches full bitmask recovery in fewer than 64 queries — approximately 61 queries (64 unconstrained bits minus 3 for the implication closure). This is a minor deviation from the stated bound but demonstrates that the implication rules the construction uses as a *security feature* (§2, §8 Gap 5) also tighten the predicate channel, contrary to the "one bit per query" claim. The operational mitigations (rate limiting, minimum Hamming weight) should be recalibrated against the effective entropy of 61 bits, not 64.

**In-threat-model?** **Yes, but low severity.** This doesn't break unforgeability or the SI game — it tightens the predicate channel bound from 64 to ~61 bits in the worst case. The rate-limiting and mask-commitment mitigations in §3 remain valid. The construction should correct the "Q bits from Q queries" claim to account for the implication structure.


## Persona: cu_ciso

---

### Attack 1: Revocation Is Not in the Construction

- **Attack**: I terminate a loan agent on a Friday afternoon — vendor contract ends, employee who operated it leaves, or the private key is suspected compromised. I need that agent's credential dead *now*. The construction tells me the on-chain Merkle tree is **append-only** and the root history buffer holds **30 entries** (§2, §5 mapping table). I ask the board: "How long does a revoked credential remain valid?" The honest answer is: until the root buffer rotates past all roots that contain its leaf. The construction says nothing about how frequently roots are updated, so that window could be minutes or weeks. During that window, the agent can still generate valid proofs — cryptographically sound, operationally catastrophic.

- **Why it works / fails**: The construction's security game (SSU, §3) is defined against forgery — producing a valid proof without a valid credential. It does not define an adversary who *holds a legitimately enrolled credential that the operator has decided to invalidate*. There is no circuit constraint, no nullifier mechanism, and no on-chain registry call that checks "is this credential still authorized?" The nullifier (§2) prevents *replay* of a specific proof, but a revoked-credential holder can generate a *fresh* proof with a new nonce as long as their leaf is in an active root. This is not in the threat model.

- **In-threat-model?** No — the construction must address emergency credential revocation: define a revocation list checked by the RS during step 5 of the verification flow (§2), specify root-update SLA, or explain how the 30-entry buffer TTL bounds revocation latency. NCUA Part 748 requires timely access revocation as a security program control. "The Merkle root will eventually rotate" is not an answer my examiner will accept.

---

### Attack 2: The Audit Log Is a Cryptographic Assertion, Not an Audit Trail

- **Attack**: There is an incident. A fraud-detection agent accessed member accounts it shouldn't have. The NCUA examiner sits down and asks for the audit trail showing (a) which agent, (b) which member accounts or data, (c) which permissions exercised, (d) at what time, (e) authorized by whom. I hand the examiner the proof transcript from §7: a 288-byte Groth16 proof and 5 public signals — `agentMerkleRoot`, `nullifierHash`, `requiredScopeMask`, `currentTimestamp`, `sessionNonce`. The examiner learns that *some enrolled agent* satisfied *some permission predicate* at *some time*. The construction explicitly brags that "the RS never sees the full bitmask" and "the RS learns nothing about `permissionBitmask` beyond the predicate outcome." That privacy guarantee is my audit liability.

- **Why it works / fails**: The construction argues the proof transcript is sufficient for audit (§7: "The proof transcript is logged for audit"). But a Groth16 proof answers exactly one question: did the prover satisfy the predicate? It does not record what data was accessed, what action was taken, which member was affected, or whether the `requiredScopeMask` was appropriate for the business purpose. The nullifier prevents replay but does not bind the proof to a business transaction. The construction conflates *authorization audit* (did the agent have the right?) with *activity audit* (what did the agent do?). FFIEC CAT Domain 3 (Cybersecurity Controls) and GLBA Safeguards 16 CFR §314.4(h) require logging sufficient to reconstruct events — not just prove that access was cryptographically authorized.

- **In-threat-model?** No — the construction must specify what application-layer audit record accompanies the proof, how the RS binds the proof to a specific business transaction (loan ID, member account, action type), and how the credit union produces a human-readable audit trail for examination. The ZK proof is one component of an audit log, not a substitute for one.

---

### Attack 3: Operator Key Custody Is the Actual Trust Anchor, and It's Unaddressed

- **Attack**: The construction's entire soundness argument reduces to: "the operator's EdDSA private key was not compromised." §8 Gap 3 says "a compromised AS cannot forge an operator signature (EdDSA EUF-CMA under DLP on Baby Jubjub)." True. But the threat model (§3) simply declares: "A does not control... the Baby Jubjub discrete log" and "A does not possess any honest operator's EdDSA private key." That exclusion is a cryptographic convention, not an operational control. I now ask: where does the operator key live? Is it in an HSM? Which HSM? Is it FIPS 140-2 Level 3? Is it in AWS KMS, and if so, has that KMS been assessed under NCUA's third-party risk framework? Is it in a developer's environment variable? Is it in a CI/CD secret that 12 engineers can read? The construction is completely silent on key management.

- **Why it works / fails**: Compromising the operator EdDSA key is a total break — the attacker can sign arbitrary credential commitments for any bitmask, enroll them in the Merkle tree, and generate valid proofs with `FINANCIAL_UNLIMITED | ACCESS_PII` forever. This is worse than a compromised AS in the RFC 7662 world, because the AS can be rotated, revoked, and audited via standard PKI and OAuth server controls. The operator EdDSA key has none of that infrastructure — the construction invents a trust anchor and says nothing about how to protect it. NCUA Part 748 Appendix B and the GLBA Safeguards Rule both require key management programs with documented controls, rotation schedules, and access logging. "Baby Jubjub DLP hardness" is an assumption in a security proof, not a key custody policy.

- **In-threat-model?** No — the construction must specify key management requirements for the operator EdDSA key: HSM requirement, key rotation policy, ceremony procedure for initial key generation, and what happens when the key is suspected compromised (ties back to Attack 1 — the entire enrolled credential set is now suspect).

---

### Attack 4: The On-Chain Registry Is an Unvetted Third-Party Vendor with No SLA

- **Attack**: Step 5 of the verification flow (§2) requires the RS to confirm `agentMerkleRoot ∈ on-chain root history buffer`. The construction assumes the RS can read the on-chain root at proof verification time. The deployment scenario (§7) places this on a blockchain — the credit union's core banking RS must make an on-chain read to verify every agent authorization. I pull up my Vendor Management Policy and NCUA Letter 01-CU-20 (third-party risk). I need: a SOC 2 Type II report, a vendor risk assessment, a contractual SLA with uptime guarantees, an incident response procedure, and indemnification language. The "Ethereum network" or "Base" cannot provide any of these. There is no vendor to assess. There is no contract to review. There is no SLA to enforce.

- **Why it works / fails**: The construction acknowledges the root history buffer (30 entries, §2) but treats the on-chain registry as infrastructure, not as a third-party dependency. It mentions "cached" root reading in step 5 ("read from contract or cached") but gives no specification for the cache: how stale can it be, what's the TTL, what happens when the cache is out of sync with the chain, and who is responsible if a valid root is missing from the cache when a legitimate agent needs authorization at 2am? My core processor has a contractual 99.95% uptime SLA with indemnification. If the blockchain node is unavailable, agent authorization fails with no fallback and no contractual recourse. The FFIEC CAT requires resilience testing and documented recovery procedures for all dependencies. The construction offers none.

- **In-threat-model?** No — the construction must address: (a) the root caching specification (max staleness, consistency guarantees), (b) fallback behavior when on-chain reads fail, (c) how the credit union satisfies NCUA third-party risk requirements for the on-chain registry dependency, and (d) whether a permissioned or consortium deployment mode exists that a credit union can vendor-assess. The phrase "on-chain" is not a substitute for a vendor contract.


## Persona: rfc7662_advocate

I have shipped RFC 7662 deployments at three financial institutions. I am not impressed by novel cryptography that reconstructs what standards already give you. Let's see what actually holds up.

---

### Attack 1: Nullifier Distinguishability Trivially Breaks the SI Game

- **Attack:** The SI game (§3, "Refined privacy game") enrolls two credentials with distinct bitmasks B₀, B₁ sharing the same `(modelHash, operatorPubkey, expiry)`. Because `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)`, different bitmasks produce different `credComm₀ ≠ credComm₁`. Both are public Merkle leaves. The session nonce is a public input. The observed `nullifierHash_j = Poseidon2(credComm_b, sessionNonce_j)` is a public output in `publicSignals_j`. The adversary computes both candidates:

  ```
  cand₀ = Poseidon2(credComm₀, sessionNonce_j)
  cand₁ = Poseidon2(credComm₁, sessionNonce_j)
  ```

  and compares with the observed `nullifierHash_j`. Since `credComm₀ ≠ credComm₁`, the candidates differ with overwhelming probability under A3, so the adversary recovers `b` with probability 1 — not `1/2 + negl(λ)`.

- **Why the construction's defense fails:** §3 resolves this by appealing to Groth16 ZK (A6), citing: *"for any statement x and any two valid witnesses w₀, w₁ for x, the distributions (π₀, f(w₀)) and (π₁, f(w₁)) are computationally indistinguishable."* This misapplies A6. Groth16 ZK guarantees that the **proof elements** π are simulatable given the public statement — it says nothing about the distinguishability of **public outputs** when those outputs are deterministic functions of the witness that the adversary can independently compute. The nullifier is not hidden by ZK; it is a plaintext field in `publicSignals_j`. The adversary does not break any cryptographic assumption — it performs two Poseidon2 evaluations on publicly known values.

  The correct Groth16 ZK statement is: Sim(vk, x) produces π̃ indistinguishable from a real proof, where x is the full public statement including public outputs. The simulator must fix a specific `nullifierHash` in x. But in the SI game, the adversary observes the nullifier and uses it to distinguish — ZK indistinguishability of the proof element π is irrelevant when the distinguishing information is the public output, not π.

- **In-threat-model?** Yes. The threat model explicitly states: *"On-chain observer: A reads the full Merkle tree state, including all enrolled `credentialCommitment` leaf values."* Nullifier distinguishability is a direct consequence. The SI game's indistinguishability claim as written (`|Pr[b'=b] - 1/2| ≤ Adv^ZK_Groth16`) is false; the true advantage is `Pr[b'=b] = 1 - negl(λ)`. The construction must either (a) reformulate the SI game to fix a single `credentialCommitment` and vary only the witness bitmask without changing the commitment — which requires redesigning the commitment scheme — or (b) accept that the standalone mode provides *identity privacy* (not bitmask privacy) only when the RS does not know which agent it is talking to, which contradicts the stated scenario in §7.

---

### Attack 2: Signed JWT Introspection Response Eliminates the AS from the Verification Hot Path — Gap 1 Is Misframed

- **Attack:** The construction's §8 Gap 1 ("AS-Blind Presentation") argues that the baseline requires the AS in every protocol flow. This is directly contradicted by `draft-ietf-oauth-jwt-introspection-response`: the AS pre-signs an introspection response JWT and hands it to the client. The RS verifies it offline against the AS's public key. At verification time, the AS is not contacted. The RS receives `(jwt_introspection_response, DPoP_proof)`, verifies the JWT signature against a pinned AS key, checks expiry, and authorizes — zero AS roundtrips.

  With per-RS filtering policy at the AS (a standard deployment pattern), the AS issues `jwt_introspection_response_for_RS_X` containing only the scopes RS-X is authorized to see. The client presents this RS-specific JWT. RS-X learns only the scopes it was granted visibility into — structurally identical to §2's claim that "the RS learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`."

- **Why it partially fails:** The construction's real differentiator is §8 Gap 3 (adversarial-AS soundness), not Gap 1 as framed. The signed JWT introspection response eliminates the AS from the verification hot path, but the trust anchor is still the AS signing key. A compromised AS can issue a pre-signed JWT claiming false scopes — the RS's offline verification cannot detect this. The Bolyra construction's trust anchor (operator EdDSA key + on-chain Merkle root) survives AS compromise. Gap 1 should be collapsed into Gap 3: the distinguishing claim is not "no AS roundtrip at verification" but "correct even under adversarial AS." The current framing of Gap 1 is vulnerable to the RFC 9449 + signed-JWT-introspection counter-argument and will be exploited by reviewers familiar with `draft-ietf-oauth-jwt-introspection-response`.

- **In-threat-model?** Yes. RFC reviewers will cite this draft specifically. The construction must rewrite Gap 1 to acknowledge that offline verification is achievable in the baseline, and sharpen the argument to focus exclusively on what a compromised-AS adversary achieves against each system. As currently written, Gap 1's claim of architectural uniqueness is not sustained.

---

### Attack 3: Gap 6 ("Privacy Beyond Predicate Outcome") Does Not Distinguish Bolyra from RFC 7662 — Only from BBS+

- **Attack:** §8 Gap 6 argues that Bolyra achieves "proof leaks only pass/fail; SI-secure under Groth16 ZK" while BBS+ "leaks claim values per disclosure." This is a comparison with the wrong baseline. A correctly-configured RFC 7662 AS can return a binary pass/fail introspection response — specifically, a response that includes only `"active": true/false` with no `scope` field. The RS learns exactly the same information: does the agent have the required permission, yes or no.

  Under adaptive Q-query probing by colluding RSes, both Bolyra standalone mode and RFC 7662 binary introspection are subject to the same predicate-channel leakage: Q independent mask queries yield at most Q bits of information about the bitmask. The construction explicitly acknowledges this in §3: *"An adversary that queries with all 64 single-bit masks learns the full bitmask via pass/fail outcomes. This is not a ZK violation — it is inherent to any authorization system."* Correct — but this means both systems are equally vulnerable, and the "operational mitigations" (rate limiting, minimum mask Hamming weight) are policy controls that an RFC 7662 deployment can adopt identically.

  The SI game's `|Pr[b'=b] - 1/2| ≤ Adv^ZK_Groth16` bound applies when masks satisfy the predicate-agreement constraint. But any RFC 7662 AS returning binary responses subject to the same constraint is also bounded by predicate-agreement — the ZK layer adds nothing over the information-theoretic limit inherent to the authorization predicate itself. The only system Gap 6 actually distinguishes is BBS+ (which reveals claim *values*, not just pass/fail), not the RFC 7662 baseline.

- **Why it partially survives:** The construction does provide cryptographic proof that the proof transcript reveals *nothing beyond* the predicate outcome — not just a policy promise. An RFC 7662 AS could in principle return more information than it claims to. The ZK proof gives the RS a cryptographic receipt: the predicate was satisfied, nothing else. This is a real property but narrower than Gap 6 claims. It should be restated as "cryptographic proof of predicate satisfaction without policy dependence on the AS's discretion," not "privacy beyond predicate outcome."

- **In-threat-model?** Yes. The construction must either (a) restrict Gap 6 to the comparison with BBS+ and acknowledge that RFC 7662 binary introspection achieves functionally identical leakage, or (b) argue that an RFC 7662 AS cannot be cryptographically bound to return only binary responses — which is true but requires an adversarial-AS argument, redirecting back to Gap 3. Gap 6 as currently written overstates the privacy advantage against the RFC 7662 baseline.

---

### Attack 4: The Cumulative Implication Enforcement (Gap 5) Is Achievable at AS-Issuance Time Without Circuit Constraints

- **Attack:** §8 Gap 5 claims: *"BBS+ has no mechanism to enforce that bit 4 → bit 3 → bit 2 within a selective disclosure presentation... an AS could enforce this at issuance, but a compromised AS (Gap 3) would not."* The second sentence does the work: the defense collapses into Gap 3, not an independent Gap 5 property.

  In a non-adversarial-AS model, AS-side issuance policy trivially enforces implication closure. The AS refuses to issue a token with `FINANCIAL_UNLIMITED` unless `FINANCIAL_MEDIUM` and `FINANCIAL_SMALL` are also set. This is a table lookup, not cryptography. RFC 8693 token exchange can enforce the same rules on re-issuance. The cumulative implication constraints in the circuit (§2, gadget 5: 3 R1CS constraints) add zero security beyond what the AS enforces at issuance in the non-adversarial model.

  In the adversarial-AS model (Gap 3), a compromised AS can issue a BBS+ credential with `FINANCIAL_UNLIMITED` set and `FINANCIAL_MEDIUM` unset. The circuit would reject this at proof generation — but a compromised AS wouldn't use the Bolyra circuit. It would issue a direct JWT. So the Gap 5 claim only holds in the adversarial-AS threat model, which is already Gap 3.

- **Why it partially survives:** The circuit does provide an *unconditional* enforcement guarantee: no valid Groth16 proof exists for a bitmask that violates implication closure, regardless of how the bitmask reached the agent. Even if the operator made a key management error and signed a malformed credential, the circuit rejects it at proof time. An RFC 7662 AS can enforce at issuance but cannot retroactively invalidate an already-issued token that was issued with a policy bug. This is a genuine operational advantage: the circuit catches malformed credentials before they can be presented to an RS.

  However, this should be presented as an operational robustness property, not as a fundamental cryptographic gap. Gap 5 should be merged into Gap 3 and reframed as "adversarial-AS or policy-buggy-AS model: the circuit is the last line of defense." Standing alone as an independent gap, it does not survive the scrutiny of *"a well-configured AS enforces this at issuance."*

- **In-threat-model?** Yes, but Gap 5 is not an independent gap — it is a consequence of the adversarial-AS model (Gap 3). The construction should consolidate §8 to present Gaps 3 and 5 together, or standalone Gap 5 will be dismissed by RFC reviewers as "just configure your AS correctly." The circuit's enforcement value is real; its framing as an independent structural gap is not.


## Persona: spiffe_engineer

---

### Attack 1: This is a SPIRE Workload Attestor Plugin, Not a Protocol

- **Attack**: The construction's §2 verification flow — agent enrolls a credential with an EdDSA-signed commitment, a Merkle root anchors trust, a nonce-bound proof is presented at request time, RS verifies against a known root — is structurally identical to how SPIRE's workload attestor API works. The "AS-blind" property the construction claims in §8 Gap 1 is already achieved by SPIRE's local workload API: the workload calls the SPIRE agent over a Unix socket, the agent issues a JWT-SVID locally, no external AS roundtrip occurs. Your `operatorPubkey` is a trust domain intermediate. Your `agentMerkleRoot` is a trust bundle. Your EdDSA signature is an SVID signature. What you have built is a SPIRE workload attestor that (a) accepts EdDSA-signed model credentials, (b) evaluates a scope predicate using ZK, and (c) issues a scoped JWT-SVID — roughly 500 lines of Go to extend an existing production system. The construction must justify why a new wire protocol and on-chain Merkle tree is preferable to writing a SPIRE attestor plugin that runs inside a trust domain you already operate.

- **Why it works / why it fails against the construction**: The construction's §8 Gap 3 ("Adversarial-AS Soundness") is the only structural gap. SPIRE's trust anchor is the SPIRE server's signing key — a compromised SPIRE server can issue false SVIDs, exactly the failure mode §8 argues against. The Bolyra construction's trust anchor is the operator EdDSA key plus an immutable on-chain Merkle root, neither of which the AS controls. This is a real architectural difference. But the construction never states this gap explicitly — §8 argues "the AS's signing key is a single point of compromise" without acknowledging that SPIRE operators routinely distribute trust via HSMs and hardened SPIRE server clusters (HA mode, OPA-gated). The construction must narrow its claim: it provides cryptographic soundness against a compromised *software* AS with access to its signing key. That is a narrower claim than §8 makes.

- **In-threat-model?** Partial — the adversarial-AS gap is real, but the construction overclaims its scope relative to hardened SPIRE deployments. The construction should explicitly bound the threat model to "software AS with extractable signing key" rather than "any authorization server."

---

### Attack 2: WIMSE Transaction Tokens Already Specify Your sessionNonce Pattern

- **Attack**: The construction's §2 verification flow steps 1–3 — RS generates `sessionNonce`, sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the agent, agent binds proof to nonce — is the WIMSE transaction token pattern (draft-ietf-wimse-arch §5–6). A WIMSE transaction token is a short-lived, context-specific token that (a) binds to the initiating workload's identity, (b) carries the requested authorization context including scopes, and (c) is issued for a single transaction. The RS's `requiredScopeMask` maps to a WIMSE `authorization_details` claim (RFC 9396); the `sessionNonce` maps to the WIMSE `req_cnf` (request confirmation). Section §8 enumerates RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, and BBS+ — but omits WIMSE entirely. Your construction is re-specifying WIMSE's transaction token layer with a ZK proof backend instead of a signed JWT backend. The question is not whether Bolyra is better than RFC 7662 — the question is whether it should be a WIMSE extension, not a parallel protocol. A ZK-backed WIMSE transaction token would contribute to an IETF standard and gain ecosystem adoption; a standalone wire format does not.

- **Why it works / why it fails against the construction**: The WIMSE draft (as of its current scope) does not mandate a specific proof mechanism for the transaction token — it allows extension. A WIMSE transaction token carrying a Groth16 proof as its `cnf` (confirmation) claim, with `requiredScopeMask` in `authorization_details`, is architecturally valid. This does not break the ZK construction; it reframes it as a WIMSE profile. The construction's claim of "constant-size proof" (§8 Gap 4) and "AS-blind presentation" (§8 Gap 1) survive as properties of a WIMSE ZK profile. What fails is the "new protocol" framing — the construction should be a WIMSE extension, and its §8 comparison table should include WIMSE.

- **In-threat-model?** No — the construction does not address WIMSE and cannot claim to be "fundamentally incompatible with existing standards" without accounting for an active IETF draft that covers its core session-binding pattern. The construction must address WIMSE or explicitly scope out of it.

---

### Attack 3: The SI Game's Privacy Argument is Cryptographically Wrong — Nullifier Hash Directly Identifies b

- **Attack**: The Refined SI Game (§3) claims indistinguishability under Groth16 ZK (A6). The argument in §3 "Nullifier distinguishability — tighter analysis" states: "the distributions (π₀, f(w₀)) and (π₁, f(w₁)) are computationally indistinguishable, where f denotes the public output function of the circuit." This claim is false when f(w₀) ≠ f(w₁), which is exactly the case here.

  In the SI game, both `credComm₀ = Poseidon5(modelHash, opAx, opAy, B₀, expiry)` and `credComm₁ = Poseidon5(modelHash, opAx, opAy, B₁, expiry)` are enrolled in T and are therefore **public Merkle leaves known to the adversary**. The public output at index 1 is `nullifierHash_j = Poseidon2(credComm_b, sessionNonce_j)`. The adversary knows `credComm₀`, `credComm₁`, and `sessionNonce_j` (a public input at index 4). It computes:

  ```
  h₀ = Poseidon2(credComm₀, sessionNonce_j)
  h₁ = Poseidon2(credComm₁, sessionNonce_j)
  ```

  and compares against the observed `nullifierHash_j`. Since `credComm₀ ≠ credComm₁` (they encode different bitmasks), `h₀ ≠ h₁` by Poseidon collision resistance (A3). Exactly one matches. The adversary recovers b with probability 1 using zero proof-theoretic work.

  The construction's rebuttal invokes Groth16 ZK: "if the adversary could distinguish via the nullifier value, it distinguishes real from simulated — breaking A6." This is a category error. The Groth16 ZK property states that **the proof π is simulatable given the public statement** — where the public statement includes the public outputs. The Groth16 simulator Sim(vk, x) takes x = `(agentMerkleRoot, nullifierHash, requiredScopeMask, currentTimestamp, sessionNonce)` as input, including `nullifierHash`. The simulator does not *choose* the nullifier hash — it takes it as given. The adversary's distinguishing attack operates entirely on `nullifierHash` as a public value; it does not need to examine π at all. No ZK property protects public outputs from being read.

  The correct Groth16 ZK claim is: given a *fixed* statement x (including a fixed nullifierHash), the proof π is simulatable without the witness. This says nothing about whether two statements with different nullifierHash values can be distinguished — they can, trivially, by inspecting the public output.

- **Why it works / why it fails against the construction**: The attack succeeds. The SI game as formulated does not provide indistinguishability when both `credComm` values are public. The construction needs one of three fixes: (a) use a randomized nullifier that is not determined by `credComm_b` alone — e.g., `nullifierHash = Poseidon3(credComm, sessionNonce, blindingFactor)` where `blindingFactor` is a private input chosen fresh per proof — so the adversary cannot compute candidate nullifiers from public inputs; (b) reframe the SI game to use a single enrolled credential (not two) and claim privacy only against "what bitmask does this known agent hold," making the nullifier non-distinguishing by construction; or (c) drop the SI game claim and replace it with a weaker "predicate-outcome-only" claim that honestly acknowledges the nullifier leaks credential identity. Option (b) matches the actual deployment scenario in §7, where the loan agent is a known entity and only bitmask privacy matters.

- **In-threat-model?** Yes — this is a direct break of the construction's stated SI security game. The construction must address it before the claim stands.

---

### Attack 4: "Portable Identity" is Already SPIFFE Trust Domain Federation — Name the Gap

- **Attack**: The construction's deployment scenario (§7) describes a credit union agent presenting a proof to a partner RS (a core banking API provider) with "no call to the credit union's AS." The portability claim is that the agent credential enrolls once and is verifiable by any RS that reads the on-chain Merkle root. In SPIFFE, this is trust domain federation: TrustDomain A (the credit union) publishes a federation bundle endpoint; TrustDomain B (the core banking provider) fetches it and trusts SVIDs from A. An agent with an SVID from A is verifiable by any relying party that has fetched A's bundle — no AS roundtrip, no re-issuance. The on-chain Merkle root is functionally a SPIFFE federation bundle that happens to be hosted on a blockchain instead of an HTTPS endpoint. The construction must articulate what "portable" means beyond what SPIFFE trust domain federation provides. Specifically: (a) does "portable" mean cross-trust-domain without prior federation agreement? If so, the Bolyra RS must still know the `AgentSelectiveScope` verifier key and the on-chain registry address — that is a prior agreement, structurally equivalent to a federation bundle fetch. (b) Does "portable" mean the credential works for RSes that have never interacted with the operator? The operator still must have enrolled the agent in a Merkle tree the RS trusts — again, a prior relationship equivalent to federation.

- **Why it works / why it fails against the construction**: The attack partially works. The construction's portability advantage is real only in one narrow case: a blockchain-anchored Merkle root is *permissionlessly readable* — any RS with an Ethereum RPC can verify the root without the operator's cooperation, whereas SPIFFE federation requires the operator to run and maintain a federation bundle endpoint. This is a genuine difference for adversarial or highly decentralized deployments where the operator cannot be relied upon to maintain an HTTPS endpoint. But §7 describes a NCUA-regulated credit union with existing infrastructure obligations — they will absolutely maintain an HTTPS endpoint. The construction should scope its portability claim to "permissionless RS verification without operator availability" and acknowledge that for cooperative deployments, SPIFFE federation achieves the same property with no on-chain dependency.

- **In-threat-model?** Partial — the portability claim survives only for the permissionless-RS case, not for the cooperative-federation case that §7 actually describes. The construction needs to tighten its scenario framing or the portability claim overstates the gap.
