# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Witness Custody Problem Breaks the "Without Exposure" Claim

- **Attack:** The construction's headline claim is that the auditor verifies the chain "without reconstructing intermediate scopes or participants." But focus on who generates the proof. `DelegationAuditChain` requires *all* private inputs — `delegatorScope[i]`, `delegateeScope[i]`, `delegatorCredCommitment[i]`, `sigR8x/y/S[i]`, `delegateeMerkleProofSiblings[i][20]` — for every hop at proof-generation time (§2, private inputs table). In a 4-hop NFCU loan pipeline (§7, Scenario 1), those witnesses are generated across potentially 4 different systems. Someone has to collect and store them — in cleartext — before handing them to the prover. That log of assembled witnesses *is* a reconstruction of the chain. The ZK proof hides the data from the *auditor*, but the prover role requires a system that has seen everything. The construction does not specify who the prover is, where it runs, or what trust boundary it operates within. If a centralized "witness aggregator" exists, it's a new trusted third party with full chain visibility — exactly what the construction claims to eliminate.

- **Why it works:** §2 is silent on witness lifecycle. §7's NCUA scenario describes what the examiner *sees* but not what system assembles the witnesses to generate the proof. In the whistleblower scenario (§7, Scenario 2), if the "relay agent" at hop 3 must hand its private scope value to a prover process, the source's data leaves the source's custody. This is not a ZK property — it's an operational gap outside the circuit.

- **In-threat-model?** No. The threat model (§3) defines adversary capabilities in terms of circuit-level forgery and extraction. It does not model a prover-side compromise or the organizational question of who assembles witnesses for a multi-org chain. **Construction must address.**

---

### Attack 2: Your NCUA Scenario Assumes Regulators Speak PLONK

- **Attack:** §7 claims the NCUA examiner "can verify" the proof — specifically, "a single PLONK verify() call on-chain (~300K gas on Base) or off-chain (< 10ms in snarkjs)." NCUA Letter 23-CU-15, which the construction cites, requires "adequate controls over third-party/fintech relationships" — interpreted by field examiners through policy documentation, audit trails in human-readable logs, and third-party assessments (SOC 2, SAS 70 lineage). NCUA does not accept cryptographic proofs as evidence of controls. Examiners don't run `snarkjs.groth16.verify()`. They ask for a policy, a named vendor with a support contract, and a signed attestation from a CPA or IT auditor. WorkOS, Auth0, and Okta all have compliance teams, pre-built NCUA examination packages, and relationships with the Big 4 firms that do CU IT audits. Bolyra has a PLONK verification key.

- **Why it works:** The construction mistakes cryptographic verifiability for regulatory acceptability. These are orthogonal. A PLONK proof can be correct and still be inadmissible as evidence of "adequate controls" because no examination framework has defined how to interpret `finalScopeCommitment` or `auditNullifier` in a safety-and-soundness context. The construction's "concrete deployment scenario" reads like a features slide, not a procurement conversation.

- **In-threat-model?** No. The threat model (§3) is purely cryptographic. GTM and regulatory acceptance are out of scope for the paper — but they are the *only* scope for an enterprise procurement decision at a $170B credit union. **Construction must address**, at minimum by acknowledging this gap and scoping the claim to "cryptographic auditability" rather than "regulatory compliance."

---

### Attack 3: `chainLength` Is Public — Metadata Breaks Whistleblower Anonymity

- **Attack:** The whistleblower scenario (§7, Scenario 2) claims the journalist can "verify that the delegation chain narrowed monotonically... without learning the source's identity." But `chainLength` is a **public input** (§2, public inputs table). In a newsroom context, if only one known 4-hop AI relay pipeline exists at the source institution, publishing a proof with `chainLength = 4` is a fingerprint. More precisely: the combination of `(rootScopeCommitment, chainLength, finalDelegateeMerkleRoot, auditNullifier)` is public. The `finalDelegateeMerkleRoot` is verifiable against the on-chain agent registry. If the journalist-facing agent's enrollment is linkable to a known organization's Merkle subtree, an adversary correlates the terminal node. Chain length combined with terminal identity is a structural graph disclosure. The construction's privacy argument (§4, Game 2) proves only that intermediate values are hidden given *identical* endpoint commitments — it does not address cases where endpoint or chain-length metadata enables deanonymization.

- **Why it works:** Game 2 (§3) requires "identical rootScopeCommitment and finalScopeCommitment" in the challenger setup — a very strong precondition. Real adversaries don't need to distinguish two prepared chains; they correlate `finalDelegateeMerkleRoot` against a known set of enrolled agents to narrow candidate sets. The Merkle root history is on-chain and public by design (§7: "verifiable against on-chain agent registry root history buffer"). The construction provides no analysis of this metadata channel.

- **In-threat-model?** Partially. Game 2 addresses a narrow version of privacy. The Merkle root correlation attack is outside Game 2's preconditions. **Construction must address** by either restricting the whistleblower scenario claim or adding a formal treatment of metadata leakage through public outputs.

---

### Attack 4: The Trust Anchor Requires Bolyra to Be Alive Forever

- **Attack:** The entire construction anchors on `rootScopeCommitment` being cross-referenced against a `HandshakeVerified` on-chain event (§7: "cross-reference rootScopeCommitment with on-chain HandshakeVerified event"). The `finalDelegateeMerkleRoot` must be verifiable against "on-chain agent registry root history buffer." This means: (a) Bolyra's contracts must be deployed and live on Base (or Base Sepolia), (b) the agent registry Merkle tree history must be queryable indefinitely, and (c) the verification key (PLONK `vk`) must be preserved and trusted. For the NCUA scenario, the loan origination audit proof might need to be re-verified 7 years later (federal record-keeping requirements for mortgage-related records). If Bolyra pivots, is acquired, or shuts down, the on-chain anchor becomes an orphaned contract. The proof is mathematically valid but institutionally unverifiable — the examiner cannot cross-reference `rootScopeCommitment` against a defunct registry. Auth0 has an 18-year operational history, 99.99% SLA contracts, and enterprise data retention guarantees. Bolyra's persistence model is not specified anywhere in the construction.

- **Why it works:** The construction's §5 mapping says the chain anchor is "rootScopeCommitment from HandshakeVerified event" — but emitting that event requires an active contract and an operator. The PLONK proof is self-contained; the *interpretation* of its public outputs is not. Enterprise procurement at a credit union requires a vendor with a contractual obligation to maintain the reference infrastructure for the audit window. "The math is correct" does not satisfy this requirement.

- **In-threat-model?** No. The threat model (§3) does not model liveness of the on-chain registry or the long-term availability of the verification key. These are operational assumptions treated as axioms. **Construction must address**, or explicitly scope the claim to exclude long-term regulatory audit scenarios.


## Persona: cryptographer

Applied cryptographer, IACR. I read your hop-skip fix and your reduction sketches. Here is what I found.

---

### Attack 1: Phantom Intermediate Agents — Unconstrained Intermediate Merkle Roots

- **Attack:** For each hop `i`, the circuit computes `delegateeMerkleRoot[i]` via `BinaryMerkleRoot(MAX_DEPTH)`. Only `delegateeMerkleRoot[chainLength - 1]` is surfaced as the public output `finalDelegateeMerkleRoot`. For every intermediate hop `k < chainLength - 1`, the computed root is a private signal that the circuit throws away — it is never constrained against any canonical enrollment registry root and never appears in any public output.

  A malicious prover constructs a 4-hop chain. Hops 0, 2, 3 use legitimate enrolled agents. Hop 1 uses a phantom agent — a credential commitment that is *not* in the production enrollment tree. The prover constructs a fake Merkle subtree containing only this phantom credential and supplies the corresponding sibling proof. The circuit at hop 1 happily computes `delegateeMerkleRoot[1]` = (root of the fake subtree) and moves on. Because `delegateeMerkleRoot[1]` is private and unconstrained, this computation imposes no verifiable obligation. The EdDSA signature at hop 2 is over `Poseidon4(SC_1, delegateeCredCommitment[2], ...)`, where `delegateeCredCommitment[2]` is a legitimate credential — so the signature check passes. The phantom agent at hop 1 signed hop 2's delegation token with a key the prover generated ex nihilo.

  The proof verifies. The auditor sees `finalDelegateeMerkleRoot` (the legitimate agent at hop 3) and concludes all four enrolled entities participated under a narrowing chain. The phantom entity at hop 1, operating outside the registry, is invisible.

- **Why it works:** Section 2 defines `BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[i], ...)` for every hop, but expresses `finalDelegateeMerkleRoot = delegateeMerkleRoot[chainLength - 1]` only. There is no constraint of the form `delegateeMerkleRoot[i] === canonicalRegistryRoot` for `i < chainLength - 1`. The circuit proves "each intermediate delegatee is a leaf of *some* Merkle tree" — not "of the *canonical* Bolyra enrollment tree." These are different statements.

- **In-threat-model?** **No.** Game 1 (Narrowing Soundness) only addresses whether scopes narrow. Game 3 (Chain Forgery) addresses whether the chain is spliced at the scope-commitment level. Neither game captures the requirement that every agent is legitimately enrolled. The construction must either (a) make `delegateeMerkleRoot[i]` a public output for every active hop, or (b) add a constraint that all active-hop Merkle roots equal a single canonical root (public input), or (c) prove inclusion against a root committed to on-chain. As written, a prover can insert phantom agents at any non-terminal position in the chain.

---

### Attack 2: Chain Prefix Suppression — rootScopeCommitment Selection Is Out-of-Circuit

- **Attack:** `rootScopeCommitment` is a public input. The circuit enforces that the prover's chain starts from it. The security narrative in §7 says the auditor "cross-references `rootScopeCommitment` with the on-chain `HandshakeVerified` event." But this cross-referencing is **not enforced inside the circuit** — it is an out-of-circuit operational step.

  Suppose the actual pipeline is A → B → C → D → E, and the A → B delegation *expands* a permission (a policy violation). The prover presents a proof for the sub-chain B → C → D → E, using `Poseidon2(B.scope, B.credCommitment)` as `rootScopeCommitment`. If there exists a `HandshakeVerified` event on-chain for Agent B (e.g., B was the initiating party in a separate handshake), the auditor finds a matching anchor and accepts the proof. The A → B violation is invisible — the circuit has no means to require that `rootScopeCommitment` corresponds to the *genesis* of the pipeline rather than any enrolled agent's handshake.

  More precisely: the construction never defines what "genesis" means. Any enrolled agent can originate a handshake and emit a `HandshakeVerified` event. The prover picks whichever handshake is convenient as the proof anchor. The auditor, seeing `rootScopeCommitment` match some `HandshakeVerified` event, has no proof that the event corresponds to the start of the specific pipeline under audit.

- **Why it works:** The circuit constrains the chain *forward* from `rootScopeCommitment` but does not constrain what `rootScopeCommitment` represents. The threat model lists "The chain does NOT start from a delegator whose Poseidon2(scope, credCommitment) = sc_root" as the Chain Forgery game (Game 3). That game addresses hash-preimage forgery, not the distinct attack of *legitimately but selectively anchoring to a mid-pipeline handshake*. Both are valid preimages; only one corresponds to the true genesis.

- **In-threat-model?** **No.** Game 3 would need to be restated: the adversary wins if the verified chain omits any hops that preceded `rootScopeCommitment` in the actual pipeline. Closing this requires either (a) a protocol-level rule that only the first handshake in a session can be used as a root anchor, enforced on-chain (no two `HandshakeVerified` events share a session ID unless it's a genesis event), or (b) the `rootScopeCommitment` encodes the session genesis in a way that makes prefix suppression distinguishable to the auditor.

---

### Attack 3: auditNullifier Equivocation — Multiple Valid Proofs Per Session

- **Attack:** `auditNullifier = Poseidon2(rootScopeCommitment, sessionNonce)`. For a fixed `(rootScopeCommitment, sessionNonce)`, the nullifier is a constant regardless of `chainLength`, `finalScopeCommitment`, or the private witnesses. A malicious operator generates two valid PLONK proofs:

  - π₁: `chainLength = 4`, `finalScopeCommitment = SC_narrow` (4-hop narrowing chain, correct)
  - π₂: `chainLength = 2`, `finalScopeCommitment = SC_broad` (2-hop chain, where hops 3 and 4 are omitted — perhaps because they involved a policy-violating tool call *after* the delegation was issued but before the audit was triggered)

  Both proofs verify independently. Both have the same `auditNullifier`. The operator submits π₁ to the on-chain nullifier registry (to prevent further submissions). The operator then presents π₂ to a different auditor who queries the nullifier registry, sees the nullifier as "used," and concludes "this session has already been audited — the first audit result stands." The two auditors see contradictory chain lengths and final scopes, with no protocol mechanism to detect the equivocation.

  Even without a second auditor, the operator could choose which proof to register (the more favorable one) and archive the other as a post-hoc cover story for a different regulator.

- **Why it works:** The nullifier binds to two values; the proof binds to all public signals. Nothing forces `auditNullifier` to be a commitment to the *specific audit result* — it is only a commitment to the session. Two structurally different audit claims (different `chainLength`, different `finalScopeCommitment`) over the same session are both valid, and the nullifier cannot distinguish them.

- **In-threat-model?** **No.** No game in §3 addresses equivocation across multiple valid proofs for the same session. The fix is straightforward: `auditNullifier = Poseidon4(rootScopeCommitment, sessionNonce, chainLength, finalScopeCommitment)`. This binds the nullifier to the complete audit result, so any two valid proofs for the same session either produce the same nullifier (identical claim) or different nullifiers (independent claims, both registereable — a different problem requiring a uniqueness rule at the registry level).

---

### Attack 4: Knowledge Soundness Is Insufficient for Composable Privacy — SE-ZK Gap

- **Attack:** §4 claims participant privacy via "the honest-verifier zero-knowledge property of PLONK." The deployment scenarios in §7 describe proofs published publicly (journalist posts the audit proof alongside the story; NCUA examiner receives the proof electronically). In these settings the proof is available to all parties indefinitely, and the scenario explicitly supports composability: "Any reader can verify."

  Standard PLONK in AGM+ROM achieves **simulation-extractability (SE)** for soundness but only **honest-verifier ZK (HVZK)** for privacy — unless Fiat-Shamir is applied with a proper ROM hash over *all* circuit inputs and the proof transcript is bound to the context. Non-interactive PLONK via Fiat-Shamir achieves NIZK in ROM, which is sufficient for malicious-verifier ZK. However, the construction does not claim **simulation-extractable ZK (SE-ZK)**, which is the property needed when proofs are used as inputs to other proofs or protocols.

  Concretely: suppose an external audit aggregator ingests multiple `DelegationAuditChain` proofs and generates an aggregate proof (a recursive SNARK) over them. Without SE-ZK, a malicious prover could craft a proof that is valid under the outer verifier but for which no honest witness exists — the outer circuit accepts the proof because standard ZK soundness does not rule out "knowledge-free" proofs in composed settings. The `finalDelegateeMerkleRoot` output could be maliciously chosen in a way that passes the outer circuit's checks while pointing to a fake registry root. SE-ZK (as defined by Groth-Maller or by the SNARKY compiler) closes this gap; standard PLONK-via-FS does not automatically provide it.

  Additionally: the privacy claim (Game 2) requires that the challenger's two chains produce computationally indistinguishable proofs. This holds under standard NIZK. But if the proving implementation leaks side-channel information (proof generation time is proportional to the number of non-zero witnesses, hint: scope bitmask popcount), the proof itself may be ZK while the *generation context* is not. This is not in scope for the formal argument but matters for the whistleblower scenario in §7.

- **Why it works:** The security argument in §4 cites "honest-verifier zero-knowledge property of PLONK" and concludes privacy. HVZK → NIZK via FS is standard but the composition claim requires SE-ZK, which requires an additional argument (or a reference to Lipmaa-Siim-Zajac or similar). The construction simply does not state whether SE-ZK holds, leaving composed usage unanalyzed.

- **In-threat-model?** **Partially no.** Game 2 as stated is a standard IND game against a computationally bounded distinguisher and is achievable under NIZK. The gap arises only under composition (recursive proofs, verifier-as-prover). The construction should (a) either explicitly restrict scope to non-composed usage, or (b) claim SE-ZK and cite the reduction, or (c) add a disclaimer that recursive composition requires an SE-ZK argument not provided here.


## Persona: cu_ciso

---

### Attack 1: The Third-Party Identity Erasure Attack

- **Attack:** The construction explicitly hides "which specific AI models were used," "which operator signed each credential," and "the actual permission bitmasks at any hop" (§7, "What the examiner does NOT see"). I hand my NCUA examiner a PLONK proof and public signals consisting of opaque Poseidon hashes. My examiner opens NCUA Letter 23-CU-15 and NCUA Part 748.0(b)(2) — both require me to demonstrate *adequate oversight of third-party relationships*, which the Interagency Guidance on Third-Party Relationships operationalizes as knowing who your vendors are, what access they have, and being able to audit their actions. The `modelHash` and `operatorPrivKey` are private inputs. I cannot tell my examiner which AI vendor ran hop 2 of the loan origination pipeline or what permissions it held. The construction's privacy guarantee is exactly what the NCUA's third-party risk program requires me to destroy.
- **Why it works:** The threat model (§3) correctly identifies the auditor as the party being given a *narrowing proof*, not an *identity disclosure*. But NCUA third-party risk examination is not a narrowing proof use case — it is an identity-and-access accountability use case. The construction conflates "examiner can verify the chain was well-formed" with "examiner is satisfied with our third-party program." These are orthogonal claims.
- **In-threat-model?** No. The construction must address the layered audit model: ZK proof handles narrowing, but a separate permissioned disclosure mechanism (e.g., operator registers identity with the CU out-of-band; the CU holds that mapping) handles third-party identity accountability. Without this, the Navy Federal scenario (§7) collapses on the first examiner question: "Who is Agent B?"

---

### Attack 2: The Legal Hold / Incident Reconstruction Attack

- **Attack:** At 2am, the fraud team flags an anomaly: Agent C in the loan pipeline generated a suspicious document. FinCEN issues a subpoena. My legal team issues a litigation hold. The NCUA issues a Document Request for all records related to the transaction. I have: one PLONK proof, five public signals (opaque hashes), and `chainLength = 4`. The private inputs — `delegatorScope[2]`, `delegateeCredCommitment[2]`, `delegateeMerkleProofSiblings[2][*]`, the EdDSA keys — exist only in the prover's memory at proof generation time. §2 nowhere specifies that private inputs must be durably stored. If the proving infrastructure discards witnesses after proof generation (standard practice for privacy), I have a cryptographic guarantee that narrowing occurred, but no record of *what was narrowed from what, by whom, at what timestamp*. The PLONK proof is a one-bit answer to the wrong question. The subpoena wants the full witness transcript.
- **Why it works:** The construction's zero-knowledge property (§4, Privacy argument) guarantees the proof leaks nothing beyond public signals. This is a feature for the construction and a liability for the CU's records retention obligations under 12 C.F.R. Part 749 (NCUA Records Preservation) and the GLBA Safeguards Rule's incident response requirements. The `auditNullifier` proves replay prevention. It does not prove what Agent C did to a member's PII.
- **In-threat-model?** No. The construction requires a companion answer: where are the private witnesses durably stored, under what access controls, and how does the CU produce them on legal demand without breaking the chain's privacy guarantees for uninvolved hops? This is a protocol gap, not a circuit gap.

---

### Attack 3: The Proving Infrastructure SLA Attack

- **Attack:** The construction advertises 6-second proving time (rapidsnark, 8 hops) and 50-second proving time (snarkjs, 8 hops) in §6. My core processor (FIS, Fiserv, Jack Henry) posts a 99.9% uptime SLA with defined RPO/RTO. If the delegation audit proof must be generated before a loan origination step completes — and the proving node goes down or degrades — every AI-assisted transaction in the pipeline blocks. The fallback path is undefined. The construction contains no discussion of: (a) what happens when proof generation fails mid-chain, (b) whether the CU can operate in a degraded mode without the ZK layer, (c) what the SLA commitment for the proving infrastructure is, (d) who operates the Merkle registry that `finalDelegateeMerkleRoot` is verified against. FFIEC CAT Cybersecurity Maturity requires CUs to have resilience plans for critical technology dependencies. "Proving infrastructure" is now a critical dependency with no documented SLA, no fallback, and a 50-second worst-case path on commodity hardware.
- **Why it works:** The construction treats proof generation as an instantaneous step in the handshake flow. In production, it is a compute-intensive external service call with its own failure modes. The 1% outage budget mentioned in the attack prompt (my core processor's SLA) corresponds to ~88 hours/year. If my proving infrastructure targets the same budget, it compounds against my core — my effective availability for AI-assisted transactions drops below the NCUA's expectation for member-facing services.
- **In-threat-model?** No. The construction addresses cryptographic soundness but not operational resilience. A deployment guide must address: proving infrastructure topology, fallback policy, SLA targets, and how the Merkle root history buffer (mentioned in §7 as the anchor for `finalDelegateeMerkleRoot`) is kept available and consistent.

---

### Attack 4: The Examiner Interpretability / SOC 2 Bridge Attack

- **Attack:** I'm preparing for my SOC 2 Type II audit covering the AI loan pipeline. My auditor (a Big 4 firm) asks me to demonstrate that the control "delegation of AI agent permissions is bounded and auditable" is operating effectively. I produce the PLONK verification key and a set of audit proofs. The auditor's testing procedure requires: (1) selecting a sample of transactions, (2) examining the authorization chain, (3) confirming controls operated as designed. Step (2) is impossible with the construction as written. The auditor sees `rootScopeCommitment = 0x3f7a...` and `finalScopeCommitment = 0x8c12...` — both opaque. The auditor cannot confirm that the control "prevents PII access after hop 1" was operating, because the permission bitmasks are private. The auditor can run `verify()` and get `true`, but cannot express a control opinion on the population — every proof for every transaction is indistinguishable from the auditor's perspective. SOC 2 CC6.1 (logical access) and CC6.3 (access removal) require that controls be testable by the auditor against specific criteria. "The PLONK proof verified" is not a testable control — it is a black box assertion.
- **Why it works:** The construction's comparison table (§8) argues it beats RFC 8693 on auditability. This is true for the cryptographic auditor (the verifier running `verify()`). It is false for the *compliance auditor* who must form an opinion on whether controls are designed and operating effectively. The compliance auditor needs to trace a sample transaction from member intent → agent A permissions → agent B permissions → outcome, and confirm the chain stayed within policy. The ZK proof proves the chain was internally consistent, not that it matched the CU's documented policy.
- **In-threat-model?** No. The construction must address the two-audience audit problem: the cryptographic auditor (PLONK verifier, satisfied by the proof) and the compliance auditor (SOC 2 / NCUA examiner, requires human-readable traceability for sampled transactions). These require different disclosures at different trust levels, and the construction currently provides only the former.


## Persona: rfc7662_advocate

---

### Attack 1: The "No Trusted Third Party" Claim Is False — You Traded the AS for the CRS

**Attack:** The construction's central differentiation claim (§8, "No trusted third party") is that verification requires only the PLONK verification key and public signals, with no AS needed. But the construction specifies `pot17.ptau` as the universal SRS (§6, §5 primitive mapping). A PLONK universal SRS is itself a trusted setup — if the ceremony is toxic-waste-poisoned (i.e., the trapdoor `τ` is known), the soundness property collapses entirely: an adversary can produce a valid proof for *any* false statement, including a chain that expands scope at every hop.

Compare that to the RFC 7662 baseline. The AS is an operational entity with runtime monitoring, audit logs, regulatory oversight, and incident response procedures. A compromised AS can be detected (anomalous token issuance shows up in logs), key-rolled, and audited. A poisoned pot17.ptau is silently exploitable forever — every audit proof ever generated becomes suspect, with no detection mechanism.

The construction further cites `pot16.ptau` for 4-hop chains and `pot17.ptau` for 8-hop chains (§6), both sourced from what are described as existing ceremonies. The security of every audit claim in the NCUA scenario (§7) is conditioned on the integrity of whoever ran those ceremonies.

**Why it works / why it fails:** The construction survives if — and only if — one accepts ceremony integrity as equivalent to AS operational trust. The construction does not argue this equivalence. It asserts "no trusted third party" while simultaneously depending on one. The attack is partially addressed by noting that universal setups (unlike per-circuit Groth16) allow public verifiability of the ceremony transcript via phase-2 contributions — but this is not argued in the construction and the pot files are referenced without ceremony provenance.

**In-threat-model?** No — the construction must address this. Specifically: cite the ceremony provenance, argue the trust equivalence, or acknowledge the assumption explicitly in §4.

---

### Attack 2: The Root Scope Is Hidden From the Only Party Who Needs to See It

**Attack:** The NCUA deployment scenario (§7) claims the examiner can verify that "every hop narrowed permissions monotonically." But the circuit proves monotonic narrowing over *private* scope values. The examiner sees `rootScopeCommitment` — a Poseidon hash — and learns nothing about the actual root scope bitmask.

For NCUA Letter 23-CU-15 compliance, the examiner's actual question is not "did scopes narrow?" but "was the root agent appropriately scoped for a home equity loan origination?" An AI agent with `READ_DATA | WRITE_DATA | ACCESS_PII | FINANCIAL_UNLIMITED | SUB_DELEGATE` (0xFF) as its root scope that narrowed to `READ_DATA` (0x01) still satisfies the circuit — and the examiner cannot tell that the initial grant was egregiously over-permissioned.

RFC 7662 with per-RS introspection policy answers the regulator's actual question: the AS's token issuance policy is auditable, the scope values are human-readable strings in the token, and the RS introspection response includes the `scope` claim. An examiner reading a Supervisory Committee report wants scope strings (`loan:originate:read`, `member:pii:read`), not a Poseidon hash and a subset proof.

The construction's privacy guarantee — the property that makes it differentiated — is directly at odds with regulatory utility in the one concrete compliance scenario the construction uses to justify deployment.

**Why it works / why it fails:** The attack is not fully addressed. The construction sidesteps it by asserting that the examiner "can verify" monotonic narrowing, without confronting that the narrowing of *what* is invisible. The construction could address this by defining a selective disclosure path (e.g., reveal `rootScopeCommitment`'s preimage to the regulator under a separate disclosure protocol), but no such mechanism exists in §2 or §7.

**In-threat-model?** No — the construction must address this. The compliance scenario requires either (a) a selective disclosure mechanism for the root scope to the regulator, or (b) an argument that proving narrowing without scope visibility satisfies NCUA examination standards — a legal claim the construction cannot make.

---

### Attack 3: `finalDelegateeMerkleRoot` Is a Stable Cross-Session Identifier — Worse Than a PPID

**Attack:** The public output `finalDelegateeMerkleRoot` (§2, Terminal outputs) is the Merkle root computed from the terminal agent's credential commitment and Merkle proof path (§2, constraint 8). Because `BinaryMerkleRoot(MAX_DEPTH=20)` computes a deterministic root from a fixed credential commitment and fixed sibling path, this output is *stable* across all sessions where the same terminal agent participates.

An adversary who collects multiple audit proofs — for example, a financial regulator, a counterparty, or a compromised auditor — can correlate all proofs sharing the same `finalDelegateeMerkleRoot` to the same terminal agent, across time, across different pipelines, and across different root scope commitments. This is a permanent, undeniable pseudonym for the terminal agent.

The construction contrasts itself against RFC 7662 / OIDC PPIDs (§8, "Whistleblower/source anonymity") by claiming "no mechanism for anonymous participation" in the baseline. But RFC 8707 audience-bound tokens with pairwise subject identifiers (OIDC PPID, RFC 7662 `sub` with sector identifier) generate *per-RS, per-audience* identifiers — the correlation domain is explicitly limited to a single resource server. The ZK construction generates a *universal, permanent* pseudonym that correlates across all resource servers, all auditors, and all sessions for the life of the credential.

The whistleblower scenario (§7, Scenario 2) is acutely vulnerable: any reader of the published audit proof can identify all prior audit proofs from the same journalist-facing terminal agent, building a dossier of the agent's participation across multiple source relationships.

**Why it works / why it fails:** The construction does not address this. The `finalDelegateeMerkleRoot` is described as useful for "cross-reference with on-chain agent registry root history buffer" (§7) — i.e., it is explicitly designed to be linkable to the on-chain registry. The privacy argument in §4 ("Game 2: Participant Privacy") covers intermediate participants but explicitly leaks the terminal agent's Merkle root as a public output, making no claim about terminal agent unlinkability.

**In-threat-model?** No — the construction must address this. A nullifier-style per-session terminal identifier (e.g., `Poseidon2(delegateeCredCommitment[chainLength-1], sessionNonce)`) would break cross-session correlation while still allowing the auditor to verify Merkle membership without learning the stable identity. The current design makes the terminal agent permanently deanonymizable.

---

### Attack 4: The Off-Circuit First Hop — Who Authorized `rootScopeCommitment`?

**Attack:** Constraint 2 at hop 0 enforces `Poseidon2(delegatorScope[0], delegatorCredCommitment[0]) == rootScopeCommitment`. The construction requires the auditor to "cross-reference `rootScopeCommitment` with on-chain `HandshakeVerified` event" (§7). But this cross-reference is entirely off-circuit: the circuit proves that the chain starts from *some* Poseidon preimage that matches the public input, not that the root credential was legitimately issued, not that the root scope was authorized by any policy, and not that the entity who triggered the `HandshakeVerified` event had the authority to grant `rootScopeCommitment` in the first place.

The trust anchor is: whoever controls enrollment into the Merkle tree (whose root appears in `finalDelegateeMerkleRoot`) and whoever deployed the smart contract that emitted `HandshakeVerified`. This is a trusted third party — specifically, the Bolyra protocol operator. The construction relocates the AS to the Merkle tree administrator and contract deployer, without naming them as trust assumptions.

Contrast with RFC 8693 Token Exchange: the AS is the named, auditable party whose policy governs what initial scopes can be granted and to whom. Token exchange audit trails are AS logs. The AS's authorization policy is the root-of-trust, and it is explicit, inspectable, and subject to regulatory examination. In the construction, the root-of-trust is the Merkle tree administrator — an unnamed entity whose authorization policy is not described, not auditable, and not in the circuit.

Concretely: a malicious Merkle tree administrator at Navy Federal could enroll a rogue agent with bitmask `0xFF`, produce a valid `HandshakeVerified` event, and then generate an audit-passing chain that narrowed from `0xFF` down to `0x01` — the circuit proves narrowing, the examiner is satisfied, and the over-permissioned root is invisible (per Attack 2). The RFC 8693 baseline with AS-enforced issuance policy blocks this at the source.

**Why it works / why it fails:** The construction does not name the Merkle tree administrator as a trust assumption, does not describe the enrollment policy (what determines which agents are admitted to the tree and at what initial scope), and does not provide a circuit or protocol for verifying that `rootScopeCommitment` was issued under authorized policy. The security argument in §4 treats `rootScopeCommitment` as a fixed, trusted public input — but who fixes it and why they should be trusted is a gap the construction inherits from the broader Bolyra handshake spec, not from this circuit.

**In-threat-model?** No — the construction must address this. Either (a) add a circuit or protocol that bounds valid root scopes to an on-chain policy registry (making the policy itself a public input), or (b) explicitly name the Merkle tree administrator and enrollment policy as trusted third parties in §3 (Threat Model), with the same scrutiny applied to the AS in the baseline comparison.


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE prod for a Fortune 500, co-author on WIMSE drafts. Objecting from the infrastructure-identity layer, demanding justification for every deviation from existing abstractions.*

---

### Attack 1: Wrong Layer — A SPIRE ZK Attestor Plugin Covers 80% of This

- **Attack:** SPIRE already has a plugin interface for node attestation (`NodeAttestor`/`WorkloadAttestor`). A ZK attestor plugin could emit JWT-SVIDs carrying a ZK proof extension claim (a custom `x-bolyra-narrowing-proof` SVID extension). Each workload/agent hop issues its SVID via SPIRE, and the audit reduces to: verify the JWT-SVID chain (WIMSE `act` structure, RFC 8693 §2.1) plus one PLONK proof that the embedded proof extension encodes monotonic narrowing. No new protocol, no new Merkle enrollment registry — the workload's SPIFFE ID (`spiffe://trust-domain/agent/model-hash`) provides the enrollment anchor, and SPIRE's attestation plugins provide the identity binding that Bolyra's Merkle tree is trying to provide.

- **Why it works / why it fails against the construction:** The construction's §8 table correctly notes that the baseline BBS+ + WIMSE stack "cannot prove an ordering/subset relationship over hidden bitmasks" — the AS sees all scopes in cleartext. But the SPIFFE engineer's counter is narrower than the §8 straw-man: a ZK attestor *plugin* could embed the scope commitment and its preimage into the SVID's private-claims extension, with the ZK proof covering the subset relation over those hidden values. SPIRE node attestation would still bind the identity. The construction never addresses why the protocol must live *below* the SPIFFE identity layer rather than as an extension *within* it. The §8 table attacks the baseline; it doesn't attack "SPIFFE + ZK attestor."

- **In-threat-model?** **No.** The construction must address why layering inside SPIRE's attestor plugin interface is insufficient. Concretely: SPIFFE identities are process/node scoped, not credential-scoped. SPIRE has no native concept of a permission bitmask, cumulative encoding, or sub-delegation narrowing. A plugin could carry the proof but SPIRE would have no way to enforce the semantics natively. The construction should make this argument explicitly rather than leaving it implicit.

---

### Attack 2: Intermediate Enrollment Anchors Are Completely Unverified

- **Attack:** In constraint 8, `delegateeMerkleRoot[i]` is computed for every hop `i`. But only `finalDelegateeMerkleRoot = delegateeMerkleRoot[chainLength - 1]` appears as a **public output** (§2, Public outputs table). Intermediate roots `delegateeMerkleRoot[0]` … `delegateeMerkleRoot[chainLength - 2]` are private — they are computed in-circuit but never exposed and never constrained to equal any known-good registry root.

  A malicious prover constructs a fraudulent Merkle tree `T'` containing an arbitrary `credCommitment'` as its only leaf. For hop `i < chainLength - 1`, the prover uses `T'` as the Merkle tree, inserts whatever credential commitment they wish, and satisfies constraint 8 trivially (BinaryMerkleRoot accepts any tree). Only the terminal hop's Merkle root is externally verifiable against the on-chain agent registry. The intermediate agents are "enrolled" in thin air.

  The §7 deployment scenario says the examiner can verify "The terminal agent was a legitimately enrolled entity (cross-reference `finalDelegateeMerkleRoot` with on-chain agent registry root history buffer)." The examiner **cannot** verify the same for intermediate agents, because those roots are never surfaced.

- **Why it works / why it fails against the construction:** The construction's soundness argument (§4, Reduction sketch: Chain Integrity) reduces Poseidon collision resistance for the *scope commitment chain* — it shows that the scope values at each hop are cryptographically linked. But scope commitment linking and enrollment verification are orthogonal properties. A prover can supply `delegateeCredCommitment[i]` as any field element, link it into the scope chain (constraint 6, delegation token), and also satisfy constraint 8 against a privately constructed tree. The proof verifies. The intermediate participant is not enrolled in any real registry.

  In SPIFFE terms: SPIRE node attestation cryptographically binds a SPIFFE ID to a hardware or platform attestation. Every hop in a SPIFFE chain has an externally verifiable identity anchor. Bolyra's Merkle enrollment for intermediate hops has no such externally verifiable anchor in this construction.

- **In-threat-model?** **No.** This is a gap the construction must close. Fix: Add a public input `enrollmentMerkleRoot` (the on-chain registry root, assumed known to the auditor) and add a constraint per active hop: `delegateeMerkleRoot[i] === enrollmentMerkleRoot` (or a per-epoch root from a public history buffer). This makes intermediate enrollment verifiable.

---

### Attack 3: `chainLength` Is Prover-Supplied — Chain Truncation Attack

- **Attack:** `chainLength` is a **public input** (§2, Public inputs table). In PLONK, public inputs are supplied by the prover and passed to the verifier; the verifier checks that the proof is consistent with the supplied public signals, but has no independent knowledge of what the *true* chain length should be.

  Scenario: the actual delegation chain in the Navy Federal loan pipeline (§7) has 6 hops — the 4 listed plus two intermediate compliance-check agents inserted by the CU's policy engine. The delegating party generates an audit proof with `chainLength = 4`, omitting hops 4 and 5. The circuit verifies for the 4-hop truncated chain. The NCUA examiner sees a valid proof with `chainLength = 4`. Nothing in the construction's cryptography detects that two hops were dropped.

  The hop-skip fix (§2.4) addresses a different problem: *gap attacks within a declared `chainLength`* (prover sets `hopActive[i] = 0` for `i < chainLength`). It correctly prevents gaps. But it says nothing about the prover under-declaring `chainLength` to omit terminal hops. The construction explicitly notes: "The prover has no freedom to skip or reorder hops" within `chainLength` — but the prover has complete freedom to choose `chainLength` itself.

  In SPIFFE: every SVID issuance event is logged on the SPIRE server. The total number of issuances in a workload chain is independently auditable from server logs. `chainLength` has an external reference. In Bolyra, it does not.

- **Why it works / why it fails against the construction:** There is no mechanism in the construction to bind `chainLength` to an externally verifiable event count. The `rootScopeCommitment` is anchored to a `HandshakeVerified` on-chain event (§7), but there is no on-chain record of every intermediate delegation event that would let the auditor independently determine the true `chainLength`.

- **In-threat-model?** **No.** The construction must either: (a) emit on-chain events for each delegation (giving the auditor an independent chain-length oracle), or (b) make `chainLength` derivable from a public commitment to the full chain (e.g., hash of the ordered delegation-token sequence), so that a truncated proof produces a different public signal than the true chain. Otherwise the NCUA examiner has no cryptographic assurance that they are seeing the complete chain.

---

### Attack 4: "Cross-Org" Claims Require a Shared Merkle Tree, Which Is a Centralized Trust Anchor

- **Attack:** §8 claims: "Cross-org chain audit — The circuit is organization-agnostic. Any enrolled agent (in the shared Merkle tree) can participate. No shared AS or federation anchor needed."

  But enrollment requires inserting `Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` into *the* Merkle tree whose root is eventually published on-chain as the registry root. For a cross-org chain (Agent A from Org 1, Agent B from Org 2, Agent C from Org 3), all three agents must be enrolled in **the same Merkle tree** controlled by a single on-chain registry contract. Someone controls that contract. That entity is a centralized trust anchor — it decides who can be enrolled. The claim "no federation anchor needed" is only true for the *verification* path; the *enrollment* path has a single-controller Merkle tree.

  SPIFFE federation is genuinely decentralized at the enrollment layer: each trust domain (`spiffe://org1.example/`, `spiffe://org2.example/`) controls its own bundle endpoint and SPIRE server. Federation is established by bilateral bundle exchange, not by enrollment in a shared registry. No single entity controls who can be a SPIFFE participant.

  The journalist/source scenario (§7, Scenario 2) makes this worse: the source's agent and the journalist's agent must both be enrolled in the same on-chain registry, which means the registry operator knows that both participants used the system (even if not their identities). For a genuine whistleblower scenario, even enrollment metadata is sensitive.

- **Why it works / why it fails against the construction:** The construction's ZK layer correctly hides *which* enrolled credential was used (credential commitment is a private input). But it cannot hide *that* a credential was enrolled in the registry. The registry is a public on-chain contract; the set of enrolled `Poseidon5(...)` leaf hashes is visible to any observer. For truly anonymous cross-org delegation, the enrollment layer must also be private (e.g., blind enrollment via ZK membership proof of a private tree), which the construction does not specify.

- **In-threat-model?** **Partial.** For the NCUA regulatory scenario (§7, Scenario 1), centralized enrollment is acceptable — the CU controls the registry. But for the whistleblower scenario and the "cross-org" generalization, the construction must either (a) acknowledge the centralized enrollment assumption as a constraint on the threat model, or (b) specify a private enrollment sub-protocol (e.g., blind Merkle insertion via a separate ZK proof). The current §3 threat model is silent on the enrollment trust model entirely.
