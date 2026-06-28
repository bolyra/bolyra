# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Latency Compounds in Agentic Loops — The 0.5s Claim Doesn't Survive Contact with Reality

- **Attack:** The construction claims rapidsnark at `< 0.5s` and snarkjs/WASM at `< 5s`. In a single MCP tool call, 0.5s is painful but maybe acceptable. But MCP agents don't make one tool call — they make 30-80 in a single task session. A GPT-4o coding agent scaffolded with 40 tool calls × 0.5s = **20 seconds of pure auth overhead per task**, before any network latency or actual computation. With WASM in-browser (the "Browser / Node.js" row in §6), 40 × 5s = **3.5 minutes of auth**. The construction never addresses this compounding. WorkOS issues tokens in < 100ms and they're cacheable across the session — the per-call overhead in the baseline is effectively 0ms after the first issuance. Additionally, §6 doesn't mention the cold-start cost: the `.zkey` artifact for a 20K+ constraint circuit is multiple megabytes. A server-side agent cold-starting in Lambda or a container needs to load and parse this on first call. What's that latency?

- **Why it works / why it fails:** The construction scopes its latency claim to the proving step only. It does not model amortization across a session, cold-start overhead, or the operational pattern of modern MCP deployments. The 0.5s claim is a best-case single-proof number on a warm server with rapidsnark already loaded. There is no counter-argument in the document to the 40-call multiplication problem. The construction's §7 scenario (CUSO credit union platform) imagines single discrete API calls; it does not model agentic loops.

- **In-threat-model?** No — the construction must address this. Minimum needed: (a) explicit statement that the proof is generated once per session (not per tool call), or (b) a session token design where a single proof unlocks a short-lived bearer token that is then used OAuth-style for the rest of the session. Without this, the latency story collapses against any incumbent that already has session caching.

---

### Attack 2: The 30-Root History Buffer Makes Revocation a 30-Epoch SLA, Not Instant

- **Attack:** §7 states: "Revocation is handled by updating the Merkle tree (removing the credential leaf)." §2 states the RS checks `agentMerkleRoot` against the "on-chain root history buffer (last 30 roots)." So: after a CU-A agent credential is compromised, the operator removes the leaf and publishes a new Merkle root. The attacker continues generating valid proofs against any of the previous 29 roots still in the buffer. The construction does not specify the root rotation interval. If it's 10 minutes (a reasonable block cadence on Base), a revoked credential remains exploitable for **300 minutes — 5 hours**. Auth0/WorkOS token revocation via JWK rotation or token blacklist propagates globally in < 60 seconds. For NCUA-regulated institutions processing inter-CU wire initiations (the §7 scenario explicitly includes `FINANCIAL_UNLIMITED`), a 5-hour revocation window is a regulatory non-starter.

- **Why it works / why it fails:** The construction's root history buffer is correctly motivated — it handles the race condition where a root update is in-flight when a valid proof is generated. But the construction never specifies: (a) how often roots rotate, (b) what the maximum revocation latency is, (c) whether emergency revocation (dropping a specific nullifier rather than waiting for root rotation) is supported. The SSU game in §3 does not model revocation at all — it assumes static enrollment. A real enterprise deployment needs revocation as a first-class security primitive with a defined SLA.

- **In-threat-model?** No — the construction's threat model (§3) explicitly excludes revocation. The adversary is defined as not controlling the on-chain Merkle root. But credential compromise → revocation race is a standard enterprise security scenario that NCUA examiners will ask about. The document needs a §3.5 covering the revocation threat model and a concrete SLA claim.

---

### Attack 3: The Trust Model Inversion Is a Procurement Liability, Not an Asset

- **Attack:** The construction's headline claim (§8, Gap 3) is "adversarial-AS resilience" — the AS is not in the trust path. The document presents this as a feature for the CUSO scenario where 200 CUs can't agree on a single trusted AS. But flip the frame: **the construction replaces AS trust with on-chain Merkle root trust and a Groth16 trusted setup**. The CU's CISO now has to evaluate: (a) the security of the Base Sepolia / Base mainnet L2, (b) the integrity of the `pot16.ptau` Phase 1 ceremony, (c) the correctness of the Circom circuit (no under-constrained signals, no soundness bugs), and (d) a solo-founder vendor with no SOC 2. The AS trust model they're replacing (Auth0) has SOC 2 Type II, FIPS 140-2 validated HSMs, a 24/7 security team, cyber insurance, and a decade of audit history. NCUA §701.27 requires documented third-party due diligence. The CU's examiner will ask for all of this. The construction cannot provide it. The trust model inversion doesn't reduce trust requirements — it shifts them to entities (L2 consensus, ceremony integrity, circuit correctness) that are harder to audit and have no SLA.

- **Why it works / why it fails:** The construction correctly identifies that AS-honesty is an architectural assumption of the OAuth stack. But it underestimates that enterprise buyers evaluate vendor trust holistically, not just cryptographically. The on-chain root being "consensus-secured" doesn't help a compliance officer who needs a signed SOC 2 report. The construction's §7 regulatory value argument (NCUA §701.27) is the strongest section of the document, but it cuts both ways: the same §701.27 that motivates avoiding a centralized AS also requires due diligence on Bolyra as a vendor. There is no response to this in the document.

- **In-threat-model?** No — this is a GTM/procurement attack, not a cryptographic one, and the construction is silent on it. At minimum, the document needs a companion vendor trust section: what certifications are planned, what the rollout path to SOC 2 is, and why the ceremony / circuit audit risk is bounded (point to specific auditors, specific audit reports).

---

### Attack 4: The SP Game Has a Credibility Problem — `credCommitment` Is Not Fully Hidden

- **Attack:** The corrected SP game in §3 / §4 argues that the adversary cannot distinguish `b₀` from `b₁` because `credentialCommitment` is a private witness. Specifically: "A does NOT receive sessionNonce in isolation — it is a public input the adversary can read. However, A cannot invert Poseidon3 to recover `b_c` from `(scopeCommitment, credCommitment_c, sessionNonce)` without also knowing `credCommitment_c`, which is a private witness." But `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` is a *public output*. The adversary observes both `nullifierHash` and `scopeCommitment` from the same proof. If the adversary is the SP game's challenger enrolling *two known agents* with known `(modelHash, opAx, opAy, expiry)` differing only in `permissionBitmask`, then `credCommitment₀ = Poseidon5(modelHash, opAx, opAy, b₀, expiry)` and `credCommitment₁ = Poseidon5(modelHash, opAx, opAy, b₁, expiry)` are both *computable by the adversary* — the adversary enrolled both agents and knows all five inputs to Poseidon5. The only unknown is which bitmask was chosen. The adversary computes `nullifier₀ = Poseidon2(credCommitment₀, sessionNonce)` and `nullifier₁ = Poseidon2(credCommitment₁, sessionNonce)`, compares against the observed `nullifierHash`, and wins with probability 1. The SP argument in §4 step 4 claims "both `credCommitment₀` and `credCommitment₁` are unknown" — but this is false in the game as defined, where the adversary is the entity that enrolled both agents.

- **Why it works / why it fails:** The SP game in §3 step 2 says "Challenger enrolls two agents" — it is ambiguous whether the adversary controls the enrollment inputs or the challenger does. If the challenger controls enrollment (and the adversary does *not* know `modelHash`, `opAx`, `opAy`, `expiry`), then the argument holds. But if the adversary is a compromised operator who enrolled both agents (which is exactly the §7 scenario where individual CUs enroll their own agents), the adversary knows all five Poseidon5 inputs and can compute both credential commitments from the observed `nullifierHash`. The construction needs to tighten the SP game: either (a) specify that the adversary does not learn the enrollment inputs for the challenged agents (which is an unrealistic restriction in the CUSO scenario where each CU is its own operator), or (b) acknowledge that SP holds only against external RSes, not against the enrolling operator — and document what "SP against the operator" means or why it's out of scope.

- **In-threat-model?** Yes, partially — the construction acknowledges the SP game was broken in the prior version and corrected it. But the corrected game has an implicit assumption about adversary knowledge of enrollment inputs that is not stated and may not hold in the deployment scenario described in §7. This is a fixable gap in the formal argument, not a construction break — but it needs to be fixed before the claim "Pr[A wins SP] ≤ 1/2 + negl(λ)" can stand.


## Persona: cryptographer

Applied cryptographer. Four attacks follow. I focus on the gap between the formal game definitions as written and what they actually prove.

---

### Attack 1: SP Game Collapses Under Its Own Threat Model — AS Knows `credentialCommitment`

**Attack:** The threat model (§3) explicitly grants A full AS control. In the Bolyra enrollment flow, the *operator* computes `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` and signs it. The adversary who controls the AS controls the operator key, performed the enrollment, and therefore knows `credentialCommitment` for every agent it enrolled — by construction.

In the SP game (§3), the adversary is given `(πc, publicSignals)` including `scopeCommitment = Poseidon3(b_c, credCommitment_c, sessionNonce)`. The SP argument claims A cannot win because "A does not know `credCommitment_c`." But A enrolled the agents. A computed `credCommitment_c` during enrollment. A knows `sessionNonce` (public input). A now evaluates `Poseidon3(b₀, credCommitment₀, sessionNonce)` and `Poseidon3(b₁, credCommitment₁, sessionNonce)` and compares against `scopeCommitment`. Pr[A wins SP] = 1.

**Why it works / fails:** The SP argument's load-bearing claim — "A cannot invert Poseidon3 without knowing `credCommitment_c`" — is true as a preimage statement but false as an adversarial-capability statement. The adversary does not need to invert anything. It has the preimage because it ran the enrollment. The session-randomization by `sessionNonce` prevents cross-*presentation* linkability between two agents that have the same operator; it does not hide the bitmask from the party that issued the credential.

**In-threat-model?** No. The SP game §3 lists "compromise the AS entirely" as a permitted query in Step 3, then builds the SP security argument on the premise that `credCommitment_c` is unknown to A. These two premises are inconsistent. The game must either (a) restrict the adversary to not control the enrolling operator, explicitly separating the *enrolling operator* from the *AS* in the threat model, or (b) prove SP only against non-issuing RSes — which is a weaker and different claim than what §3 asserts.

---

### Attack 2: On-Chain Merkle Leaf Exposure Enables Bitmask Enumeration, Breaking SP

**Attack:** The SP argument's key assumption is that `credCommitment_c = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` is an unknown private witness. But this value is a leaf in the on-chain Merkle tree. In all practical on-chain Merkle registry implementations (including Semaphore, from which this construction inherits), leaf insertions are emitted as events so that provers can reconstruct Merkle paths. This makes every `credCommitment_c` a publicly recoverable value.

If `credCommitment_c` is readable from chain events, any adversary can:

1. Read `credCommitment_c` from the insertion log.
2. Read `sessionNonce` from the public circuit signals.
3. Enumerate the realistic bitmask space. With 8 defined permission bits (§1, permissions model), there are at most 256 candidate values; in practice, a specific agent role uses far fewer. For each candidate `b_candidate`, compute `Poseidon3(b_candidate, credCommitment_c, sessionNonce)` and compare to the observed `scopeCommitment`.

The bitmask is fully recovered in at most 256 Poseidon evaluations — trivially feasible.

**Why it works / fails:** The circuit treats `credCommitment_c` as a *private circuit witness* (the prover doesn't put it in `publicSignals`), but privacy in a circuit is not privacy on a blockchain. The Merkle root is on-chain; inserting a leaf necessarily reveals the leaf value to anyone watching the registry contract. §7 explicitly says "NCUA examiners can audit the on-chain enrollment registry," confirming the registry is publicly readable. The SP argument never accounts for the distinction between circuit witness privacy and deployment privacy.

**In-threat-model?** No. The construction must specify whether leaf values are hidden (commitment scheme with blinding, opaque off-chain tree) or public. If the deployment model requires auditable enrollment (§7), the construction must add a blinding factor to `credentialCommitment` and keep it off-chain, or accept that scope privacy from on-chain observers is not provided. As written, the property claimed in the SP game — `Pr[A wins SP] ≤ 1/2 + negl(λ)` — does not hold in the concrete deployment described in §7.

---

### Attack 3: Groth16 Non-Simulation-Extractability Breaks SSU ∧ SP Composition

**Attack:** The reduction sketch for SSU (§4) invokes knowledge soundness (A1): given a valid proof π*, extract the witness `w`. The SP security argument invokes zero-knowledge (A6): there exists a simulator that produces indistinguishable proofs without knowing the witness. These two uses occur in the same security model, but standard Groth16 is **not simulation-extractable (SE)**.

Formally: if A sees simulated proofs (from the ZK simulator, used in the SP game's reduction) and then outputs a forged proof (attacking SSU), the knowledge extractor used in the SSU reduction may not function correctly — the CRS it was given is the simulated CRS, not the real CRS with the same trapdoor structure. Groth16's knowledge soundness holds for the real CRS; the ZK simulator uses a trapdoor-augmented CRS. These are different setups.

A PPT adversary that simultaneously requests proofs (query phase in SSU, Step 3) and observes them under ZK simulation while later forging is exactly the scenario where SE is required. The gap is known: Abdolmaleki et al. (CCS 2019) explicitly show that Groth16 is not SE without modification, and that composing soundness with ZK in a concurrent model requires SE.

The consequence: the joint claim "SSU holds (under A1) AND SP holds (under A6) for the same construction" requires either proving SE for the AgentPolicy circuit's Groth16 instantiation, or proving that the SSU and SP games are *sequential* (not concurrent). The draft proves neither.

**Why it works / fails:** In the specific AgentPolicy circuit, the adversary in SSU can request honest proofs (gadget 3's EdDSA verifier means the adversary cannot sign arbitrary credentials, limiting the attack surface). So SE may not be exploitable in practice here. But the reduction sketch in §4 is incomplete — it does not identify why the concurrent composition is safe for this circuit.

**In-threat-model?** Yes, the construction can survive this, but the security argument must be tightened. The draft should either cite a simulation-extractable variant (e.g., Groth16 with rerandomization-resistant structure, or PLONK with Fiat-Shamir in the ROM which is SE in the ROM), or prove that the SSU query phase cannot produce simulated proofs that help the SSU forgery. As written, the reduction sketch in §4 is incomplete for the concurrent adversary implied by the §3 threat model.

---

### Attack 4: Groth16 Phase 2 Trusted Setup Is an Unnamed Single Point of Failure for SSU

**Attack:** SSU (§4) rests on A1: "knowledge soundness of Groth16 in the generic group model + random oracle model for Fiat-Shamir." This is a valid cryptographic assumption *conditioned on an honest CRS*. But Groth16 requires a **per-circuit** trusted setup (Phase 2 ceremony), distinct from the universal Phase 1 (`pot16.ptau`). The `pot16.ptau` file is the Phase 1 powers-of-tau; Phase 2 generates the circuit-specific `(.zkey)` from it.

The threat model (§3) says A does not control "the Groth16/PLONK trusted setup (honest-majority ceremony assumption)." But the Phase 2 ceremony for `AgentPolicy` is not described anywhere in the construction. If Phase 2 was performed by a single party (the Bolyra team), there is no honest-majority — a single trapdoor holder can generate valid proofs for *any* statement, including SSU forgeries where `requiredScopeMask* & permissionBitmask ≠ requiredScopeMask*`. The SSU game is completely broken for any adversary holding the Phase 2 toxic waste.

Game statement under subverted setup:

```
If τ (Phase 2 trapdoor) is known:
  A can compute π* for any (requiredScopeMask*, publicSignals*) trivially.
  SSU advantage = 1, regardless of A1.
```

The Phase 1 ceremony reuse from Semaphore (§2 notes `HumanUniqueness` reuses the Semaphore v4 ceremony) is a good operational pattern, but `AgentPolicy` does **not** reuse the Semaphore ceremony — it has a project-specific Phase 2. The construction correctly notes this in the circuit table, but the SSU assumption that "A does not control the setup" is an *operational* claim, not a *cryptographic* one. It cannot be reduced to A1.

**Why it works / fails:** A subverted Phase 2 is not a failure of A1 (which assumes an honest CRS) — it is a failure of the operational assumption that the ceremony was conducted correctly. The PLONK alternative (§2.3) has a universal SRS (no per-circuit Phase 2), but the universal SRS still has a structured reference string with a trapdoor. If the SRS generator is dishonest, PLONK also provides no security. Neither variant escapes this.

**In-threat-model?** Partially. The threat model explicitly places the trusted setup outside adversary control as an assumption, but does not specify: (a) how many parties participated in the Phase 2 ceremony for `AgentPolicy`, (b) whether ceremony transcripts are publicly verifiable, or (c) what happens if a future ceremony participant leaks their contribution. Under the criterion that "no PPT adversary wins SSU" — a single trusted Phase 2 contributor is not PPT; it is a pre-computation assumption. The construction must either specify a minimum multi-party threshold for Phase 2 and link to ceremony outputs, or migrate to a transparent setup (e.g., STARKs, Halo2 IPA, or PLONK with a KZG SRS from a sufficiently large ceremony like the EIP-4844 ceremony). As written, the SSU claim's security is contingent on an undescribed ceremony that could have a single point of failure.


## Persona: cu_ciso

---

### Attack 1: Trusted Setup Toxic Waste — Undetectable Universal Forgery

**Attack:** The construction's Groth16 soundness rests on "honest-majority ceremony assumption" for `pot16.ptau` (Phase 1) and the project-specific `.zkey` files (Phase 2). Any participant in either ceremony who retained their randomness contribution ("toxic waste") can generate a valid proof for *any* `permissionBitmask` satisfying *any* `requiredScopeMask` — including permissions the agent was never granted. The forgery is computationally indistinguishable from an honest proof. The on-chain verifier accepts it. The RS accepts it. No on-chain state changes; there is no detection path.

**Why it works / fails:** The construction's adversarial-AS-resilience argument (§8, Gap 3) explicitly removes AS from the trust path and replaces it with "the proving system's knowledge soundness guarantee." That guarantee collapses entirely if the setup ceremony is compromised. The construction cites `pot16.ptau` reuse from Semaphore v4 but does not reference the ceremony's attestation artifacts, participant list, or toxic waste destruction evidence. For the project-specific Phase 2 ceremony, the CLAUDE.md simply says it uses `pot16.ptau` — no documentation of Phase 2 ceremony participants or destruction of intermediate randomness is provided.

Under **FFIEC CAT Domain 3 (Cybersecurity Controls)** and **NCUA Part 748, Appendix A**, the CU is required to document and assess the security controls of all technology components in its supply chain. A cryptographic ceremony is a critical control — the examiner will ask for the attestation log and destruction evidence. There is none documented here. The PLONK path avoids a per-circuit ceremony but still relies on the universal SRS; its trust assumptions are similar. The construction provides no incident response plan for "the ceremony was compromised."

**In-threat-model?** No — **the construction must address this.** Required additions: (1) link to Semaphore v4 ceremony attestations and the project's Phase 2 ceremony transcript, (2) define the procedure for emergency circuit upgrade if the setup is compromised (new ceremony + on-chain verifier contract swap), (3) document the detection mechanism — since forgeries are indistinguishable, the only detection signal is off-chain behavioral anomaly, which requires a monitoring layer the construction does not specify.

---

### Attack 2: 30-Root Buffer Revocation Lag Violates Incident Response SLA

**Attack:** Revocation works by removing a credential commitment from the Merkle tree, which changes the root. The RS accepts any `agentMerkleRoot` in the **last 30 on-chain roots** (§2, "root history buffer"). An adversary — or a compromised-but-not-yet-evicted agent — can generate proofs against a root from up to 29 updates ago, even after revocation. The window is not time-bounded in the construction; it is update-count-bounded. If the Merkle tree sees low update activity (off-hours, weekend), a revoked agent may remain capable of generating accepted proofs for hours.

**Why it works / fails:** The construction acknowledges revocation in §7 ("Revocation is handled by updating the Merkle tree") but does not specify the worst-case revocation lag, nor bound the time between a revocation enrollment transaction and the revoked credential falling outside the 30-root buffer. On Base mainnet with block times of ~2 seconds, 30 roots could expire in minutes *if* updates are frequent — but in a deployed CUSO with 200 CUs making infrequent enrollment changes, the tree might see one update per day. A revoked agent's credential remains valid against the 30-root buffer for up to 30 update events, which could span days.

**NCUA Part 748, Appendix A, Section III.C** requires CUs to have controls ensuring "prompt revocation of access privileges." **GLBA Safeguards Rule (16 CFR §314.4(c)(3))** requires access termination for service providers upon contract termination. "Prompt" in examination context means minutes, not buffer-count-dependent lag. The CU's examiner will ask: "Show me a test case where you revoke an agent at T=0 and prove it cannot authenticate at T=0+5 minutes." The construction cannot guarantee this.

**In-threat-model?** No — **the construction must address this.** Required: (1) define maximum acceptable revocation lag (e.g., "revoked credentials are invalid within 2 Merkle tree updates, each update committed within N minutes, giving worst-case lag of 2N minutes"), (2) specify the on-chain update frequency SLA and who is obligated to maintain it, (3) consider emergency revocation via a separate on-chain revocation registry that the RS checks independently of root history — a revoked-nullifier-set approach would give immediate revocation at the cost of one additional on-chain lookup.

---

### Attack 3: Audit Trail Opacity Fails NCUA Examiner Discovery

**Attack:** NCUA sends an examiner following a member complaint that their loan underwriting data was accessed without authorization. The examiner asks: "Pull the access log for Member #78234 for Q1. Show me which agent accessed it, what permissions it held, and whether authorization was valid." The CU points to its ZK audit trail: on-chain nullifier hashes and Merkle roots. The examiner sees `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` — an opaque 32-byte field. The `agentMerkleRoot` is a hash with no human-readable agent label. The `scopeCommitment` is session-randomized and unlinkable by design.

**Why it works / fails:** The construction's privacy properties are exactly the adversary here. §7 claims "NCUA examiners can audit the on-chain enrollment registry without accessing any agent's private credential fields" — but what the examiner actually needs is a mapping from `nullifierHash` → (agent name, CU identity, permission tier, timestamp). That mapping does not exist in the on-chain state. The CU must maintain a separate off-chain correlation log (`sessionNonce` → agent identity) to reconstruct audit trails. The construction is silent on this requirement.

This creates a compliance architecture split: the ZK layer provides cryptographic authorization proof; a separate plaintext logging layer (managed by whom? stored where? retained how long?) provides human-readable audit trails. **NCUA Part 748, Appendix B** (GLBA Safeguards, incident response) and the FFIEC's examination handbook on **audit log completeness** require that audit trails be sufficient to reconstruct events. Two layers that must be correlated — one cryptographic, one plaintext — create an internal control gap: if they diverge (log tampering, key loss), the examiner cannot verify the on-chain proof against the business record.

**In-threat-model?** No — **the construction must address this.** Required: (1) specify the off-chain audit log schema the CU must maintain alongside ZK proofs, including retention period, access controls, and tamper-evidence requirements, (2) define how `nullifierHash` maps to a human-readable agent identity in the CU's records management system, (3) provide a sample examiner-ready report format that cross-references on-chain proof hashes with the plaintext log — something a Tier 1 ops team can produce at 2am without a cryptographer on call.

---

### Attack 4: Operator Private Key as Single Point of Failure Under Safeguards Rule

**Attack:** Every agent credential is signed by the `operatorPrivKey` (Baby Jubjub EdDSA). This key appears as private input `(sigR8x, sigR8y, sigS)` in the circuit. The construction's §8 "Model-identity binding" relies on the operator key: "Changing the model or operator requires a new credential." The threat: the operator private key must be accessible to the agent runtime at credential issuance time (to produce the EdDSA signature). If this key lives in a server-side environment, HSM requirements are unstated. If this key lives in a browser or a containerized Lambda (as implied by "Browser / Node.js" in §6 proving targets), it is accessible to any code executing in that context.

**Why it works / fails:** A compromised `operatorPrivKey` allows the attacker to issue arbitrary credentials for any `permissionBitmask` and enroll them in the Merkle tree under the legitimate operator's identity. The agent's Merkle membership proof would be valid. The construction's adversarial-AS-resilience (AS cannot forge proofs) is irrelevant here — the *operator* is the trust anchor for credential issuance, and operator key compromise is not in the threat model definition (§3 lists "adversary does NOT control: the agent's private credential fields" but operator key compromise is a distinct attack surface). Key rotation requires re-enrollment of *every* agent credential signed by that key — the construction does not specify the re-enrollment procedure, blast radius, or notification requirement.

Under **GLBA Safeguards Rule §314.4(h)** (service provider oversight) and **NCUA Part 748 Appendix A** (access controls), the CU must assess how the operator key is protected, rotated, and monitored. The construction provides no guidance on key management — no HSM requirement, no key ceremony for operator keys, no rotation schedule, no specification of what happens when key compromise is detected.

**In-threat-model?** No — **the construction must address this.** Required: (1) define operator key management requirements: HSM-backed, not browser-accessible, rotated on a defined schedule, (2) specify re-enrollment procedures upon operator key compromise, including maximum lag between key compromise detection and completion of re-enrollment, (3) address the blast radius — a single operator serving 200 CUs in the CUSO scenario has a single key compromise affecting all enrolled agents; consider per-CU operator keys or a hierarchical key structure, (4) provide a Vendor Management questionnaire response that maps operator key controls to FFIEC CAT Domain 2 (Threat Intelligence) and Domain 3 (Cybersecurity Controls) — without this, the NCUA examiner's third-party due diligence checklist cannot be completed.


## Persona: rfc7662_advocate

### Attack 1: "AS-Blind" Is a Strawman — jwt-introspection-response Already Removes the AS from the Hot Path

- **Attack:** Section 8, Gap 1 claims the baseline requires AS contact at presentation time, but this has been false since draft-ietf-oauth-jwt-introspection-response reached RFC track. A signed JWT introspection response is cached at the RS; subsequent verifications are pure offline JWT signature checks — no AS roundtrip. Pair this with RFC 8707 audience-bound tokens issued at enrollment time, and the AS is contacted exactly once per (agent, RS) registration, not per request. This is structurally identical to Bolyra enrollment. The construction's "new RS without AS contact" advantage reduces to a single-ceremony-per-RS difference, not a fundamental architectural gap. DPoP (RFC 9449) adds per-request key-binding via a fresh DPoP proof, so the hot-path token presentation is fully offline. The actual differentiator in the construction is the *adversarial-AS* scenario (Gap 3), not AS-blindness per se. By presenting these as two separate gaps, the construction inflates the comparative advantage.

- **Why it fails against the construction:** Partially. The construction does survive the adversarial-AS scenario independently — a compromised AS cannot forge Groth16 proofs for the honest agent's credential. But Gap 1 as stated is vulnerable: the argument that "the baseline requires AS contact at presentation time" is simply wrong for the jwt-introspection-response + long-lived audience-bound JWT case. The construction should collapse Gap 1 into Gap 3 and tighten the claim to "adversarial-AS resilience," dropping the weaker "no AS roundtrip" framing.

- **In-threat-model?** No — construction must address. Gap 1 as written is inaccurate. The paper conflates *hot-path AS contact* (solved by baseline) with *AS-trust elimination* (not solved by baseline). Fix by merging Gap 1 into Gap 3 with precise language.

---

### Attack 2: The Scope Privacy Proof Collapses When Merkle Leaf Values Are On-Chain

- **Attack:** Section 3 (SP game, step 4) claims the adversary "cannot invert Poseidon3 to recover b_c from (scopeCommitment, credCommitment_c, sessionNonce) without also knowing credCommitment_c, which is a private witness." The entire SP security argument rests on `credentialCommitment_c` being unknown to the adversary. But §2 (gadget 4) specifies `BinaryMerkleRoot(20)` with `credentialCommitment` as the leaf value, and §7 explicitly states "NCUA examiners can audit the on-chain enrollment registry." An on-chain Merkle tree with public leaf values means both `credCommitment₀` and `credCommitment₁` — the two enrolled agents in the SP game — are publicly readable from the blockchain. The adversary performs the following distinguisher with probability 1:

  1. Read `credCommitment₀` and `credCommitment₁` from the on-chain registry.
  2. Observe `nullifierHash = Poseidon2(credCommitment_c, sessionNonce)` and public `sessionNonce` from the proof's public signals.
  3. Compute `Poseidon2(credCommitment₀, sessionNonce)` and `Poseidon2(credCommitment₁, sessionNonce)`.
  4. Compare with `nullifierHash`. Exactly one matches. Output `c` with certainty.

  The same attack applies via `scopeCommitment = Poseidon3(permissionBitmask, credCommitment_c, sessionNonce)` if the adversary also enumerates candidate bitmasks — but the nullifier path is cleaner and requires no bitmask guessing.

  The construction cannot fix this by appealing to Poseidon preimage resistance (A3), because no preimage inversion is needed — the inputs are already public from the blockchain.

- **Why it fails against the construction:** It doesn't fail. This is a genuine break of the SP game as stated. The construction either (a) must concede that credential commitments are public Merkle leaves and that SP holds only in a model where the Merkle tree is a commitment scheme with hidden leaf values (requiring a new hiding assumption), or (b) must redesign the tree to store `hash(credentialCommitment || blindingFactor)` as leaves with a separate enrollment proof that the blinding factor commits to the correct credential — adding non-trivial circuit complexity and a new secret to protect per-agent.

  Note the tension: §7 uses on-chain transparency as a *regulatory advantage* ("NCUA examiners can audit the enrollment registry"), while the SP proof requires leaf values to be opaque. The construction cannot simultaneously claim both.

- **In-threat-model?** Yes — construction must address. The SP proof is unsound as written when combined with a transparent on-chain Merkle tree.

---

### Attack 3: Enrollment Authority = Scope Authority — Adversarial-AS Resilience Is Circular

- **Attack:** Section 8, Gap 3 states: "A compromised AS cannot forge scope satisfaction proofs for agents it did not enroll." Section 3 (SSU game) restricts the winning condition to forgeries against "the honest agent's leaf." This game definition excludes the operationally critical attack:

  In the CUSO deployment scenario (§7), each credit union enrolls its own agents using its own `operatorPrivKey`. The credit union IS the AS-equivalent — it controls the `permissionBitmask` assigned at enrollment and signs the credential commitment. A compromised CU does not need to forge the honest agent's credential; it simply:

  1. Generates a fresh `operatorPrivKey'`.
  2. Creates a new credential commitment with `permissionBitmask = 0xFF`.
  3. Calls the shared Merkle tree's enrollment contract to insert this leaf.
  4. Presents a valid Groth16 proof — which the construction accepts, because it IS a valid proof for a legitimately enrolled credential.

  The SSU game declares this "not a win" because the forgery targets a new leaf, not the honest agent's leaf. But from the CUSO platform's perspective, the attack is successful: an agent from CU-A is now accessing the platform with inflated permissions that CU-A's compliance officer never authorized. RFC 7662 with a centralized AS has the same vulnerability — a compromised AS issues inflated tokens. The construction provides no advantage: both systems' security reduces to "the enrollment/issuance authority is honest." The game definition papers over this by excluding the practical attack from the win condition.

  Additionally, the construction requires a shared enrollment contract on-chain. Who administers write access to this contract? If a single smart-contract owner can arbitrarily insert leaves (or the contract is upgradeable), the Merkle root is not consensus-secured in the way §3 implies — it is secured by the contract's access control, which is an off-chain governance assumption identical in character to "the AS is honest."

- **Why it fails against the construction:** It exposes an undisclosed scope. The construction is correct within its formal game (SSU protects the honest agent's credential), but the game scope is too narrow to cover the CUSO scenario's actual threat. The §7 scenario implicitly requires a separate trust assumption: "the Merkle tree smart contract correctly restricts enrollment to authorized operators per CU." This assumption is never stated in §3 or §4.

- **In-threat-model?** No — construction must address by either (a) narrowing the deployment claim in §7 to acknowledge that the shared Merkle enrollment contract is itself a trust anchor with governance risk, or (b) expanding the SSU game to include "rogue enrollment" adversaries and demonstrating that the circuit or on-chain policy prevents inflated-bitmask enrollments.

---

### Attack 4: SD-JWT + Per-Bit Claims Already Achieves the Bitmask Predicate Claim at Constant Size

- **Attack:** Section 8, Gap 2 argues BBS+ cannot evaluate bitwise AND over a 64-bit field. This is correct but irrelevant: `draft-ietf-oauth-selective-disclosure-jwt` (SD-JWT, now on RFC track as RFC 9278-related) represents each permission as an independent disclosable claim. Represent the 64-bit permission space as 64 SD-JWT disclosures: `{"_sd": ["bit_0", "bit_1", ..., "bit_63"]}` where each `bit_k` is a separate hashed disclosure. To prove `requiredScopeMask = 0b10000001` (bits 0 and 7), the holder discloses exactly 2 salted hash preimages. The RS sees exactly the bits that are required and nothing else. The presentation is:

  - **Constant-size in required bits:** O(|requiredScopeMask popcount|) disclosures. For `requiredScopeMask` with k bits set, the proof is k disclosure preimages — each 32 bytes. For the typical case k ≤ 8, this is 256 bytes, comparable to the PLONK proof.
  - **AS-blind (after issuance):** SD-JWT holder binding (with DPoP) allows offline presentation without AS contact.
  - **RS-adaptive at runtime:** The RS specifies which bits it wants; the holder reveals only those. No reissuance.
  - **Standard tooling:** OpenID4VP + SD-JWT has production implementations in multiple wallets.

  The construction counters in Gap 2 that "predicate evaluation is over a *hidden* bitmask — the RS learns *only* that the predicate holds, not which bits are set." But in the SD-JWT model, the RS also does NOT learn which bits are NOT set — it only receives the disclosed bit preimages. The construction's claim that the RS learns "which additional bits are set" from the baseline is false for SD-JWT: undisclosed bits are salted hashes with random salts; the RS cannot brute-force them or determine whether any undisclosed bit is 0 or 1 without the salt.

  The genuine remaining distinction is the **implication closure** (cumulative-bit constraint): SD-JWT cannot *enforce* that `FINANCIAL_UNLIMITED` implies `FINANCIAL_MEDIUM` without either (a) the AS asserting the implication at issuance (which the adversarial-AS model rejects) or (b) an out-of-band verification rule at the RS. Bolyra's circuit enforces this cryptographically in R1CS. For the specific case where implication closure must be cryptographically enforced — not just policy-declared — the construction has a genuine advantage. But §8 Gap 2 does not isolate this as the load-bearing claim; it broadly attacks BBS+ and SD-JWT's predicate expressiveness, which overstates the gap.

- **Why it fails against the construction:** Partially. SD-JWT undermines the "no selective disclosure in the baseline" claim for the straightforward case. The construction survives on the implication closure sub-claim and on the full bitmask confidentiality claim (SD-JWT reveals the SET bits, even if it hides the unset ones). But §8 Gap 2 must be substantially rewritten to (a) acknowledge SD-JWT as a partial match, (b) isolate the cryptographic implication enforcement as the specific gap, and (c) acknowledge that O(k) vs O(1) proof size is a quantitative, not qualitative, difference for small k.

- **In-threat-model?** No — construction must address. Gap 2 as written overstates the baseline's weakness by ignoring SD-JWT. The claim survives only if narrowed to: "cryptographic enforcement of implication closure over a fully hidden bitmask, with O(1) proof size regardless of permission-space width."


## Persona: spiffe_engineer

---

### Attack 1: "AS-blind" is conflated with "adversarial-AS-resilient" — SPIFFE SVIDs already give you the first

**Attack:** The construction's §8/Gap 1 bundles two distinct properties under "AS-blind presentation":

- **(A) Presentation-time AS-blindness:** The RS validates the credential without calling the AS at request time.
- **(B) Adversarial-AS resilience:** A *compromised* AS cannot forge scope proofs for credentials it did not honestly enroll.

Property (A) is trivially achieved by any cached credential: a SPIRE-issued JWT-SVID has a TTL (typically 5–60 min in production deployments) during which the workload presents it offline with no SPIRE server contact. The RS verifies the SVID signature against the bundle endpoint—no AS roundtrip. SPIRE's workload API delivers the SVID to the workload process over a Unix domain socket; the workload caches it locally and presents it to any downstream RS until TTL expiry. Gap 1's argument — "the agent generates proofs locally, no AS is contacted" — exactly describes SVID caching. The ZK machinery adds nothing to property (A) that a cached JWT-SVID does not already provide.

Property (B) is the genuine differentiator, and the construction's §4 SSU game correctly characterizes it. But §8/Gap 1 leads with property (A) as if it were novel, then quietly imports property (B) to do the real work. A SPIFFE operator reading this sees the bait-and-switch immediately.

**Why it works / why it fails:** The construction does survive on property (B) — a Groth16 proof is extractable under knowledge soundness regardless of AS honesty; a forged JWT-SVID from a compromised SPIRE server is not. But the claim in §8/Gap 1 that "AS-blind presentation" is something "no configuration of RFC 7662 … can match" is false as stated. RFC 7662 with jwt-introspection-response *caching* achieves property (A). The adversarial-AS argument (B) must be stated separately and argued on its own merits.

**In-threat-model?** No — the construction must split Gap 1 into two sub-claims and defend only (B) as novel. Conflating them exposes the overall §8 comparison table to the objection that every bullet point is inflated by the same imprecision.

---

### Attack 2: WIMSE transaction tokens already design for runtime-adaptive scope narrowing — and you didn't compare against them

**Attack:** `draft-ietf-wimse-arch` (WIMSE WG, active IETF work) defines a *transaction token* (txn-token) service. The flow:

1. Workload presents its SVID + a requested downstream scope to the Transaction Token Service (TTS).
2. TTS evaluates policy (OPA, Cedar, or bespoke), issues a short-lived, audience-specific, narrowed txn-token.
3. Workload presents txn-token to the downstream RS. No original AS contact at RS verification time.

The construction's §1 property "runtime-adaptive: the RS chooses `requiredScopeMask` at the moment of the request; the agent proves satisfaction without reissuance" is the exact design goal of WIMSE txn-token. The RS specifies what scope it needs; the workload obtains a narrowed txn-token for that specific downstream call. The construction's §8/Gap 2 argues that "bitwise AND over a 64-bit field with implication closure requires arithmetic-circuit-level evaluation" — but WIMSE's TTS runs arbitrary policy; it can evaluate `(permissions & required_mask) == required_mask` in microseconds without a ZK circuit.

The construction's §8 comparison table lists `RFC 7662 stack` and `BBS+ layer` as the baseline but omits WIMSE entirely. This is the most directly relevant competing standard — a deployed, IETF-chartered architecture for exactly the workload identity + runtime scope narrowing use case the construction targets. The claim "no composition or baseline can simultaneously achieve all six properties" cannot be evaluated without addressing WIMSE.

**Why it works / why it fails:** WIMSE's TTS is an online trusted party — the workload must contact it per transaction, which breaks property (A) (presentation-time AS-blindness) and property (B) (adversarial-AS resilience). So the construction does survive on those two axes. But the construction has not made this argument. It has simply not engaged with WIMSE, which is the canonical workload identity answer to runtime-adaptive authorization. Any WIMSE co-author reviewing this paper will immediately flag the omission.

**In-threat-model?** No — the §8 comparison table must add a WIMSE column and explicitly argue why the TTS-online requirement is a disqualifying constraint in the adversarial-AS scenarios the construction targets. Without this, the claim "no composition can match all six simultaneously" is undefended against the most relevant prior art.

---

### Attack 3: The 30-root history buffer is a revocation window — SPIFFE SVIDs beat this

**Attack:** The verification protocol (§2, Step 5) accepts any proof whose `agentMerkleRoot` appears in "the last 30 roots" of the on-chain history buffer. Revocation is achieved by removing the credential leaf and publishing a new root. But:

- Old roots persist in the buffer after revocation.
- A revoked agent with a cached proof (or the ability to generate fresh proofs before the old `credentialCommitment` is purged from the buffer) can present valid proofs to any RS that checks against the buffer.
- The revocation latency window = `rootUpdateFrequency × 30`.

The construction does not specify root update frequency. On Base Sepolia at typical block times (~2 s), an L2 transaction can post a new root in seconds — but the *operator* must trigger and pay for that transaction. In the §7 CUSO scenario with 200 CUs, the shared Merkle tree update requires a transaction per enrollment/revocation event. If root updates batch (e.g., once per hour), the 30-root buffer gives a **30-hour revocation window**.

In SPIFFE/SPIRE production deployments, SVIDs carry a TTL (commonly 1 hour, often 5–15 min for sensitive workloads). Effective revocation latency = max(remaining SVID TTL). A revoked SPIRE workload registration cannot re-attest; the SVID expires and the workload loses access within its TTL. For a 5-minute SVID TTL, effective revocation latency is ≤ 5 minutes with no on-chain transaction required.

The §7 scenario invokes NCUA §701.27 third-party due diligence. Under NCUA examination standards, a revocation event (compromised agent, terminated employment, suspicious activity) with a multi-hour revocation window is a material control failure. SPIFFE's TTL-based model is documented and auditable; the construction's revocation SLA is unstated.

**Why it works / why it fails:** The construction could address this by (a) specifying a minimum root update frequency, (b) reducing the buffer to fewer roots, or (c) adding a separate revocation accumulator (e.g., a sparse Merkle tree of revoked nullifiers checked outside the circuit). None of these are present. The `BinaryMerkleRoot` check in §2/constraint 4 is a membership proof, not a non-membership proof — it cannot encode revocation without a tree update, and the buffer window is unspecified.

**In-threat-model?** No — the construction must specify revocation latency SLA and compare it to SPIFFE SVID TTL-based effective revocation. For the CU regulatory deployment in §7, this is not optional.

---

### Attack 4: Trust-domain federation in SPIFFE gives "portable identity across 200 CUs" without a blockchain — name the gap

**Attack:** The §7 deployment scenario frames the CUSO problem as: "The CUSO cannot run a single centralized AS trusted by all 200 CUs." This is the canonical SPIFFE federation problem, solved by `spiffe://trust-domain/path` federation across trust domains:

1. CU-A operates `spiffe://cu-a.cuso.net/` with its own SPIRE server.
2. The CUSO registers a federation relationship with each CU's bundle endpoint (an HTTPS endpoint serving the CU's trust root).
3. The CUSO RS validates `spiffe://cu-a.cuso.net/agent/fraud-detector` SVIDs against CU-A's bundle — no single centralized AS, no shared Merkle tree.

The construction replaces this with an on-chain Merkle tree where all 200 CUs share a single enrollment root. This design choice introduces a **shared-root blast radius**: a Merkle tree compromise or a malicious tree update (if the tree operator is compromised) invalidates or corrupts credentials for all 200 CUs simultaneously. SPIFFE federation contains the blast radius to one trust domain — CU-A's compromise does not affect CU-B's identity root.

The construction's §8/Gap 3 argues that the on-chain Merkle root is more trustworthy than individual CU AS instances. But the trust model has shifted to: "trust the Base Sepolia L2 consensus + the Merkle tree update operator." This is not obviously superior to "trust each CU's SPIRE server independently" — it trades N independent trust anchors for 1 shared on-chain anchor (with its own failure modes: smart contract bugs, chain reorgs, key compromise of the tree update operator).

The SP game in §3 explicitly puts the on-chain Merkle root outside adversary control ("The adversary does NOT control: the on-chain Merkle root"). But in a 200-CU deployment, the entity that controls tree updates (whoever holds the update key or administers the contract) is a centralized party — exactly the centralization the construction claims to eliminate.

**Why it works / why it fails:** The construction survives if it can argue that (a) the on-chain Merkle root is secured by L1/L2 consensus rather than a single operator key (requiring the tree update contract to be permissionless or governed by a multisig with quorum across CUs), and (b) the ZK scope proofs add adversarial-AS resilience that SPIFFE federation cannot match (because federation still trusts each CU's SPIRE server for *that* CU's credentials). These are defensible positions, but neither is made explicit. The construction treats the on-chain root as axiomatically trustworthy without specifying the governance of tree updates — which is where the real centralization risk lives in a 200-CU deployment.

**In-threat-model?** Yes (construction survives on the adversarial-AS point), but partially no — the shared-root blast radius and tree update governance are unaddressed, and the comparison to SPIFFE federation's blast-radius isolation is absent from §7 and §8. The regulatory argument in §7 cuts both ways: NCUA examiners will ask "who controls the Merkle tree update key?" as surely as they will ask about revocation latency.
