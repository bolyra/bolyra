# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Prover Nobody Hired

**Attack:**
Section 7 presents a Navy Federal scenario where the NCUA examiner "requests proof" and "receives a single PLONK proof." But who runs the prover? The circuit has ~139,400 constraints (8-hop PLONK). The prover must hold all private witness inputs: `delegatorScope[h]`, `delegateeCredCommitment[h]`, EdDSA signatures, Merkle siblings — across every hop. That means either (a) the last agent in the chain reconstructs the entire chain's private state to prove it, which requires every upstream hop to hand its private credential material downstream, or (b) a separate "audit orchestrator" collects witness data from all hops. Neither is specified.

**Why it works:** The construction describes the circuit and the verifier's experience, but the *prover workflow* is entirely absent. In an adversarially-decomposed pipeline (journalist → source → relay → publication), the source agent cannot hand its private `delegatorCredCommitment` to the relay without defeating the anonymity guarantee in the whistleblower scenario. You can't simultaneously hide intermediate nodes from the auditor *and* aggregate the proof across all intermediate nodes' private state — unless you use recursive proving or a multi-party witness generation protocol, neither of which is specified.

Auth0's MCP auth answer here: the AS holds the delegation log and generates the audit report centrally. One API call to `/api/v2/logs` returns an RFC 8693 `act` chain in structured JSON. Boring, but it works on day one, exportable to Splunk, no witness aggregation problem.

**In-threat-model?** No — construction must address the witness assembly protocol, especially for the whistleblower scenario where witness holders are adversarially separated.

---

### Attack 2: `chainLength` Is a Fingerprint

**Attack:**
`chainLength` is a **public output** (Section 2). GAME-HIDE (Section 3) is proven only for chains `C0, C1` with "identical `(initialScopeCommitment, finalScopeCommitment, chainLength)`." In the whistleblower scenario (journalist → source → relay → publication), chain length = 4. If an adversary observes on-chain audit proofs and knows that only one journalist operates a 4-hop chain anchored at a given `initialScopeCommitment`, they've partially identified the pipeline structure. Combined with timing correlation (proof submitted ~T seconds after the source event), chain length alone can be a strong de-anonymizing fingerprint in sparse deployment.

More concretely: `allDelegateesMerkleRoot` is also public. This root identifies which agent registry all hops belong to. If Org A runs a 4-hop chain and Org B runs a 3-hop chain, an auditor can trivially distinguish them. The construction claims GAME-HIDE, but the game's construction condition — same-length chains with same endpoint commitments — is a strongest-case scenario. Real deployments don't satisfy it.

**Why it works:** GAME-HIDE holds mathematically, but it assumes the adversary cannot use side channels: chain length, Merkle root provenance, timing, and the on-chain `lastScopeCommitment[sessionNonce]` anchor (also public, Section 2). The construction's privacy guarantee is conditional on a population of identical-length, identical-endpoint chains. In thin-deployment enterprise contexts, this population is often size 1.

**In-threat-model?** No — the privacy argument in Section 4 does not account for combinatorial side-channel attacks on the public outputs.

---

### Attack 3: No Revocation, No Sale

**Attack:**
Section 8 contrasts Bolyra favorably: "No trusted third party. The circuit IS the enforcement." But enforcement of *what, when*? If the KYC tool agent (hop 2 in the Navy Federal scenario) is compromised at `T+1h` after a delegation chain is live, what happens? There is no revocation mechanism in the construction. The `delegateeExpiry` constraint enforces that the delegatee's credential wasn't expired *at proof generation time*, not that the credential was never revoked after issuance.

WorkOS, Auth0, and Stytch provide token introspection and real-time revocation. A Navy Federal security team that discovers a compromised agent at 2am can revoke it in the AS and invalidate all active delegations within seconds. Bolyra's answer — rotate the on-chain agent Merkle root and invalidate the registry — is a global operation that invalidates all valid chains, not just the compromised one. The construction does not specify per-credential revocation without MerkleRoot rotation.

**Why it works:** The "no AS" architectural choice eliminates the revocation control plane. The construction's threat model (Section 3) does not model *post-issuance credential compromise* — only forgery and narrowing violations at proof time. A Navy Federal CISO asking "if one of our AI agents is compromised, how fast can we shut it down?" gets no answer from this construction.

**In-threat-model?** No — post-issuance revocation is absent from the threat model and deployment scenario.

---

### Attack 4: The Examiner Cannot Verify the Proof

**Attack:**
Section 7 states the NCUA examiner receives "a single PLONK proof" with public signals. The construction says the examiner can verify `initialScopeCommitment` "against on-chain handshake record" and `allDelegateesMerkleRoot` "against on-chain agent root history." This requires the examiner to (a) run a PLONK verifier, (b) query the Bolyra on-chain registry on Base Sepolia, and (c) understand what a `Poseidon4` commitment means for compliance purposes.

NCUA examiners submit findings in FFIEC format. Their toolchain is Examiner's Guide worksheets, SQL exports, and vendor-supplied PDF audit reports. The construction produces a cryptographic artifact that proves something to a BN128-aware verifier. It produces nothing that maps to 12 CFR Part 748 (NCUA's IT examination standards), NIST 800-53, or any compliance framework the examiner is actually graded on.

WorkOS's answer: audit logs in JSON, exportable to Splunk, mapped to SOC 2 controls, with a compliance PDF your legal team can hand to the examiner. The examiner signs off in an afternoon.

The construction's claim in Section 8 — "Auditor sees only the scope commitments (Poseidon hashes), never the bitmasks" — is presented as a *feature*. To the examiner, seeing only Poseidon hashes instead of human-readable permission names is a *defect*. "READ\_DATA | FINANCIAL\_SMALL" in plaintext is auditable. `Poseidon2(0x05, 0x...)` is not.

**In-threat-model?** No — the construction optimizes for cryptographic verifiability and explicitly sacrifices human-readable auditability, which is the primary requirement for the regulatory scenario it claims to target.


## Persona: cryptographer

Applied cryptographer, IACR publications, reviews for CRYPTO/EUROCRYPT/S&P. Stance: unless I see a threat model, a game definition, and a reduction sketch, it is marketing. The construction has all three. My job is to find where the game definitions are too weak, the reductions hand-wave, or the circuit leaves a gap the formal argument ignores.

---

### Attack 1: History Rewriting via Shadow Chain

**Attack:** The adversary operates a real four-hop pipeline in which hop 3 expands permissions relative to hop 2 (a genuine monotonic violation). Rather than submitting a proof of the real chain, they fabricate a "shadow" chain: hop 2's agent (a colluding party, explicitly allowed — the threat model permits up to `MAX_HOPS - 1 = 7` colluding agents) issues a fresh EdDSA-signed delegation token directly to hop 4 with scope `≤ scope_2`, completely bypassing hop 3. The adversary now generates a `ChainAuditProof` for this shadow chain (`chainLength = 3`, valid narrowing throughout). The proof passes every circuit check: EdDSA signatures verify, Merkle proofs are valid, bitwise subset holds, expiry holds.

**Why it works:** GAME-NARROW asks only: *can A produce a proof π such that Verify = 1 AND some extracted witness violates the bitwise subset?* The shadow-chain proof satisfies neither trigger: the extracted witness is a legitimate 3-hop chain with no violation. The game does not ask: *does this proof faithfully represent the pipeline that actually ran?* The `initialScopeCommitment` is pinned on-chain, but every intermediate delegation token is off-chain. No on-chain record binds "the delegation token actually invoked at runtime" to "the delegation token witnessed in the proof." Colluding agents can issue fresh tokens post-hoc.

**In-threat-model?** **No — the construction must address this.** The correct game would be:

```
GAME-FAITHFUL:
Phase 1: Challenger records all delegation token issuance events on-chain
         (nullifier registration or token commitment).
Win: A produces a valid ChainAuditProof whose extracted per-hop
     delegationTokenHash for some hop h does not match any registered
     on-chain token in the lineage rooted at initialScopeCommitment.
```

The construction must publish per-hop `delegationNullifier` values as public outputs (they are listed in the primitive mapping table but absent from the public outputs specification) and enforce on-chain nullifier existence checks at proof verification time. Without this, GAME-NARROW proves only syntactic consistency of the proof against itself, not fidelity to the executed pipeline.

---

### Attack 2: Stale Timestamp / Prover-Controlled Liveness

**Attack:** `currentTimestamp` is a public input supplied by the **prover** at proof-generation time. The circuit enforces `currentTimestamp < delegateeExpiry[h]` for every active hop (constraint 2f). Suppose the adversary generates a valid audit proof at time `T1` with `currentTimestamp = T1`. At time `T2 > T1`, some intermediate delegation expires or is administratively revoked off-chain. The adversary presents the old proof to a new auditor, keeping `currentTimestamp = T1`. The verifier receives `(π, pubInputs)` where `pubInputs.currentTimestamp = T1`. The proof is valid — the circuit was satisfied at `T1`. The verifier has no way, from the proof alone, to determine that `currentTimestamp` is stale.

**Why it works:** The `auditNonce` is fresh (auditor-chosen), but it is not cryptographically bound to `currentTimestamp`. An adversary can take any old proof, replace `auditNonce` with a fresh one... wait, they cannot do that without re-proving. But the weaker version works: if the auditor accepts proofs without asserting `currentTimestamp ≥ (wall_clock - Δ)`, any old proof is valid indefinitely. The construction requires the verifier to perform this check but never specifies it — Section 3 does not add it to the verifier's obligations, and the smart contract verification in Section 6 merely calls `Verify(vk, π, pubInputs)`.

More precisely, the `auditDigest = Poseidon4(initialScopeCommitment, finalScopeCommitment, chainLength, auditNonce)` commits to the nonce but NOT to `currentTimestamp`. A fresh nonce generates a fresh digest even with an old timestamp. There is no binding.

**In-threat-model?** **No — the construction must address this.** Fix: include `currentTimestamp` in `auditDigest` (`Poseidon5(initial, final, length, nonce, currentTimestamp)`) and require the on-chain verifier to assert `currentTimestamp ≥ block.timestamp - STALENESS_WINDOW`. Alternatively, make `currentTimestamp` a verifier-supplied argument, not a prover-supplied public input.

---

### Attack 3: GAME-HIDE Is Conditioned on Endpoint Equality, Breaking Whistleblower Anonymity

**Attack:** GAME-HIDE constructs challenge chains `C0, C1` with "identical `(initialScopeCommitment, finalScopeCommitment, chainLength)`." The reduction sketch then says: "The public outputs are identical for `C0` and `C1` by construction. Therefore ε = 0." This is circular — it assumes the inputs to the game satisfy a constraint that real deployments will routinely violate.

Concretely, in the whistleblower scenario (Section 7): journalist agent → source agent → anonymizing relay → publication tool. Suppose there are two possible source agents in the Merkle tree: `src_A` (the real source) and `src_B` (another journalist's source). The auditor knows both are enrolled. The scope at hop 2 necessarily narrows from the journalist's credential scope. If `src_A` and `src_B` carry different permission profiles (different `delegateeScope` values), then the resulting `finalScopeCommitment` and `initialScopeCommitment` of the two hypothetical chains will differ, breaking GAME-HIDE's precondition. The game inapplicable; the auditor distinguishes with advantage 1 by simply computing which `initialScopeCommitment` matches the on-chain value.

More formally: the game as stated requires the challenger to construct `C0, C1` with identical public signals. In practice the only way to achieve this is if both chains share the same endpoint commitments AND chain length — which means the privacy guarantee is conditional on identical endpoint scopes. Real pipelines with heterogeneous agent classes will leak participant identity through scope fingerprinting at the endpoints.

**In-threat-model?** **No — the game definition is too weak.** The correct game requires the challenger to construct `C0, C1` with identical *only* the public outputs declared (including `allDelegateesMerkleRoot`), but then the reduction must prove that no polynomial-time distinguisher can identify the intermediate participant set even when `initialScopeCommitment` reveals the root scope. This requires a scope-blinding mechanism (salt or randomization of scope commitments) so that the same bitmask maps to unpredictable commitments. The current `Poseidon2(permissionBitmask, credentialCommitment)` is deterministic — the same bitmask + same credential always produces the same commitment, so scopes are trivially fingerprintable if credentials are known.

---

### Attack 4: Subverted PLONK SRS Renders GAME-NARROW Vacuous

**Attack:** The construction elects PLONK over Groth16 for `ChainAuditProof` "to avoid per-circuit ceremony." Section 4's assumption KS-Groth16 is quietly replaced by the analogous q-SDHI assumption in the generic group model for PLONK. The security argument in Section 4 says: "The adversary does NOT control the Groth16/PLONK proving system (knowledge soundness holds)." This is a setup assumption, not a reduction — it is condition on the SRS being generated honestly. If the PLONK SRS was generated with a known trapdoor `τ`, any adversary knowing `τ` can:

1. Evaluate the circuit's constraint polynomials at `τ` directly
2. Construct a proof `π*` satisfying `Verify(vk, π*, pubInputs) = 1` for an **arbitrary** `pubInputs` vector — including one where `chainLength = 4`, `auditDigest` looks fresh, but the private witness actually expands permissions at hop 3
3. The knowledge extractor cannot distinguish `π*` from a legitimate proof; there is no extractable witness because the proof was forged, not generated by the circuit's relation

The construction cites `pot16.ptau` or `pot18.ptau` as the SRS. These are locally generated files. Section 6 does not specify whether they were produced by a multi-party computation with at least one honest party. If generated by a single party (as is common in local development and testing), the trapdoor is known to that party.

The GAME-NARROW reduction sketch says: "By KS-Groth16, the knowledge extractor E extracts a valid witness." But KS-Groth16 is a property of the proof system under an honest CRS. The reduction sketch does not include a sub-game for CRS generation, does not specify the ceremony used, and does not prove that the deployed `pot18.ptau` was generated honestly. The formal claim outstrips the deployment guarantee.

**In-threat-model?** **No — the construction must address this.** Required: (a) specify that `pot18.ptau` derives from a widely-participated ceremony (e.g., Ethereum's KZG ceremony or the Hermez Phase 1 Powers of Tau with 1,000+ independent participants); (b) add a game `GAME-SETUP` that models a subverted SRS and argues that the threat model explicitly excludes adversary-controlled setup; (c) if universal composability is claimed, prove security in the universal composability framework under an ideal functionality for the SRS, not just in the standalone game model.


## Persona: cu_ciso

### Attack 1: Forensic Black Hole — The Proof Is for the Good Path

- **Attack:** During an NCUA examination following a disputed stablecoin transfer, the examiner asks: *"Your settlement agent executed a $47,000 transfer to a sanctioned wallet. Show me which agent authorized it and what scope it had."* The CISO hands over a valid `ChainAuditProof`. The examiner asks follow-up questions. The proof says the chain was 4 hops and monotonically narrowed — it says nothing about what the agents *did* with their delegated permissions. Scope is hidden. Agent identities are hidden. The proof cannot answer: which hop executed the transfer? Did the compliance agent actually check OFAC? Was the settlement agent's `FINANCIAL_SMALL` scope the one that executed the transfer, or was it bypassed at the application layer?

- **Why it works:** `ChainAuditProof` proves *delegation integrity* — that the permission bitmasks narrowed correctly. It does not prove *behavioral integrity* — that the agents stayed within their permissions at runtime. An agent with `FINANCIAL_SMALL | READ_DATA` can receive a valid delegation proof and then call any API it has network access to. The circuit cannot observe what the agent did outside the proof system. NCUA Part 748 §II.A requires a security program with "detection, response, and recovery" — you need a timeline of *who did what*, not a proof that the mandate structure was valid. A proof that says "trust the math" fails the incident response workflow because the math only covers the delegation graph, not the execution trace.

- **In-threat-model?** No. The construction explicitly scopes itself to "auditor verifies that a delegation chain narrowed monotonically." Behavioral audit is out of scope, but the deployment scenario (§7) frames this as the NCUA audit artifact for a stablecoin pipeline. That framing overstates what the proof covers. The construction must either (a) narrow the deployment claim to "delegation audit only, not behavioral audit," or (b) add a behavioral trace commitment (e.g., per-hop action logs bound to the delegation nullifier) and explain how those are produced without breaking privacy.

---

### Attack 2: Witness Custody Is a GLBA Data Retention Problem

- **Attack:** The `auditNonce` is "auditor-chosen" (§2, Public inputs table), implying the proof is generated *on-demand* in response to an examination request. To generate the proof, the prover needs all private inputs for every active hop: `delegatorScope[h]`, `delegateeScope[h]`, `delegatorExpiry[h]`, EdDSA signatures, and Merkle sibling hashes. In a 4-hop live pipeline, who retains these values between transaction time and audit time? Each agent in the pipeline knows only its own slice. Someone must aggregate and persist the full witness.

  If NFCU's audit team retains the witness: they are storing the exact scope values and credential commitments that the ZK proof was designed to hide — creating a plaintext data store that is now a high-value target and subject to GLBA Safeguards Rule data minimization and retention requirements. If each agent retains its own slice: the aggregation step at audit time requires contacting all 4 agents (some of which may be third-party vendor systems), re-assembling the witness, and hoping all parties are still available and cooperative. If the proof is pre-generated at transaction time with a *fixed* nonce: the auditor cannot provide a fresh nonce, breaking the replay-binding guarantee and requiring the CU to generate and store a proof for every transaction — storage and key management at scale.

- **Why it works:** §7 describes the audit trigger as a post-hoc event ("NCUA examiner *requests* proof"). The construction provides no witness lifecycle management. The very data it hides from the auditor must be preserved by *someone* to produce the proof. Under GLBA Safeguards Rule (16 CFR Part 314) and the NCUA's own data retention guidance, the CU must document what customer-sensitive data it holds and for how long. Scope values tied to member transactions are customer financial data. Retaining them in a witness store is a data element that requires controls, classification, and retention policy — none of which are in scope for the construction.

- **In-threat-model?** No. The construction treats private inputs as ephemeral by design (they are never revealed), but does not address how they survive from transaction execution to audit-triggered proof generation. This is an operational gap, not a cryptographic one, and it's one my vendor management policy and GLBA compliance program will surface immediately during onboarding.

---

### Attack 3: `allDelegateesMerkleRoot` Is a Hidden Centralized Trust Anchor

- **Attack:** Constraint 2h requires: `computedRoot === allDelegateesMerkleRoot` for *every* active hop. The `allDelegateesMerkleRoot` is a single public output, uniform across all hops, verified against on-chain agent root history. This means every delegatee in the chain — regardless of organizational affiliation — must be a leaf in the *same* Merkle tree with the *same* root at proof time.

  In the Navy Federal cross-org scenario (§7): the KYC tool agent is presumably a third-party vendor (e.g., Alloy, Socure). For that agent to appear in `allDelegateesMerkleRoot`, NFCU must either (a) enroll the vendor's agent into NFCU's own agent tree — requiring NFCU to take custody of the vendor's `credentialCommitment` and vouch for it, or (b) rely on a shared global agent tree — which is exactly the shared trust anchor the baseline comparison (§8) claims Bolyra eliminates. The construction says "no Authorization Server" but substitutes a global enrollment registry whose root is checked on-chain. That registry *is* a trust anchor. If the Bolyra enrollment contract is compromised or the registry operator is subpoenaed, the claimed anonymity collapses.

- **Why it works:** §8 ("Why the baseline cannot match") claims "No trusted third party. The circuit IS the enforcement." But the circuit checks against `allDelegateesMerkleRoot`, which is anchored to an on-chain agent tree maintained by *someone*. The FFIEC CAT's "Threat Intelligence and Collaboration" domain asks about third-party risk and concentration risk. The on-chain enrollment registry is a third party. My vendor management policy requires SOC 2 Type II for any system that processes or validates access to member data pathways. Who operates the Bolyra enrollment contract? What's the key management for the contract owner? If the registry goes down, no agent in any cross-org chain can generate a valid proof.

- **In-threat-model?** Partially. GAME-FORGE (§3) addresses phantom delegatees not in the Merkle tree — the adversary model covers *invalid enrollment*. It does not address *who controls the enrollment tree* or what happens when that controller is unavailable, legally compelled, or compromised. The cross-org privacy guarantee is only as strong as the enrollment trust model, which is unspecified.

---

### Attack 4: The Proof Artifact Is Not an Auditor-Legible Document

- **Attack:** I take the `ChainAuditProof` PLONK proof to my NCUA examination. The examiner opens the FFIEC CAT and asks me to map my audit evidence to the "Cyber Risk Management and Oversight" domain, specifically the third-party risk management section. The proof is a sequence of BN128 field elements. The examiner needs: (1) a human-readable policy document mapping this control to Part 748, (2) a tested and validated procedure for generating and verifying the proof, (3) evidence that the verifier contract was independently audited, and (4) a named vendor responsible for the Bolyra protocol with a signed BAA or equivalent.

  None of these exist in the construction. §7 says "NCUA examiner requests proof" — but the examiner does not have a PLONK verifier, does not understand `auditDigest = Poseidon4(...)`, and cannot assess whether the `pot18.ptau` ceremony was trustworthy. The construction treats cryptographic soundness as a substitute for regulatory legibility. These are orthogonal properties.

- **Why it works:** The NCUA's examination process operates on documented controls, validated procedures, and auditable vendor relationships — not cryptographic proofs. The construction would need to be wrapped in: a mapping to specific NCUA Part 748 controls, an examiner-facing attestation layer (a signed PDF summarizing what the proof establishes, issued by a responsible party), a SOC 2 Type II report covering the Bolyra protocol and its on-chain components, and a named vendor with indemnification and incident response SLAs. The ZK proof is the *technical layer*; the regulatory layer is entirely missing. Until Bolyra itself is a named, audited vendor with regulatory mappings, my examiner will treat this as an unvetted open-source cryptographic library — which triggers my vendor management policy's "high risk" classification under NCUA's third-party risk guidance (Letter to Credit Unions 01-CU-20).

- **In-threat-model?** No. The construction's threat model covers cryptographic adversaries. The regulatory acceptance problem is not a cryptographic threat — it's an institutional one. The deployment scenario (§7) implies the proof *is* the audit artifact. In practice, the proof needs a human-readable attestation wrapper, a responsible issuer, and a regulatory control mapping before any credit union CISO can present it to an examiner without professional liability exposure.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. I've shipped RFC 7662 introspection at scale. Every ZK claim here is a hypothesis until you show me what breaks in my toolbox.*

---

### Attack 1: The Single `allDelegateesMerkleRoot` Collapses Cross-Org Into a De Facto Authorization Server

**Attack:** Section 2 constraint 2h requires `computedRoot === allDelegateesMerkleRoot` for **every** active hop, and `allDelegateesMerkleRoot` is a **public output** verified against an on-chain agent root history buffer. In a cross-org pipeline — the Navy Federal scenario in §7 — every participating organization's agents must be enrolled in the **same** Merkle tree, under the same root, committed on the **same** chain. Someone writes agents into that tree. Someone controls the contract. Someone runs the sequencer or L2.

That entity is a trust anchor. Call it what it is: a distributed Authorization Server with a consensus gossip layer bolted on.

The construction's §8 column "Works without Authorization Server" is falsified by its own constraint inventory. What the construction eliminates is the *introspection hot path* — the runtime AS query — not the trust anchor itself. RFC 9728 Protected Resource Metadata already decouples AS discovery from the hot path. A signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response) cached at the RS is also offline-verifiable with no AS roundtrip. The baseline's trust anchor is an HTTPS endpoint. This construction's trust anchor is a smart contract. Smart contract bugs have caused losses measured in nine figures. "The laws of arithmetic" guarantee nothing about the correctness of the enrollment logic that wrote those leaves.

**Why it fails against the construction:** It doesn't fully fail — the construction can respond that the Merkle root is updatable by each org's own enrollment authority without a central gatekeeper, using a forest-of-roots or union-accumulator approach. But the current construction as written uses a **single shared root** (`allDelegateesMerkleRoot` is singular). Multi-org requires either (a) one root per org and a cross-root aggregation proof the construction doesn't specify, or (b) a shared root requiring a shared enrollment authority.

**In-threat-model?** No. The construction must address cross-org enrollment governance or weaken the "no shared trust anchor" claim in §8.

---

### Attack 2: Auditor-Supplied `currentTimestamp` Creates an Unacknowledged Trust Assumption Absent From the Baseline

**Attack:** Section 2 lists `currentTimestamp` as a **public input** described as "auditor-supplied." Constraint 2f enforces `currentTimestamp < delegateeExpiry[h]` in-circuit. The `auditDigest` binds `auditNonce` but NOT `currentTimestamp` — it is `Poseidon4(initialScopeCommitment, finalScopeCommitment, chainLength, auditNonce)`. A prover can generate a valid proof at time *T* for a delegation chain where every expiry is `T + 1 second`, then present that proof to an auditor who supplies `currentTimestamp = T`. The proof verifies. At time *T + 2*, the delegations are expired, but the audit artifact remains valid.

More precisely: proof generation requires `currentTimestamp < delegateeExpiry[h]`, so the prover must use a timestamp *before* all expirations. But the audit proof's validity period is unbounded upward unless the verifier independently enforces freshness of `currentTimestamp` relative to wall clock. The construction says nothing about who enforces this or how.

In RFC 7662, expiry enforcement is unambiguous: the AS compares `exp` against AS server time at introspection. The signed JWT introspection response includes an `iat` field the RS can use to bound acceptable staleness. Token expiry is a first-class protocol property with a 12-year operational track record.

**Why it fails against the construction:** The construction can fix this by including `currentTimestamp` in `auditDigest` and requiring the on-chain verifier to check `currentTimestamp >= block.timestamp - ALLOWED_SKEW`. But it doesn't do this today, and the threat is real: a chain that expires one minute after proof generation produces an "all hops valid" audit artifact that is perpetually valid in the construction's current form.

**In-threat-model?** No. The construction must either include `currentTimestamp` in `auditDigest` or specify an on-chain freshness bound on the audit proof's `currentTimestamp` public input.

---

### Attack 3: Public `chainLength` + `allDelegateesMerkleRoot` Together Form a Fingerprinting Oracle That Exceeds PPID-Level Linkability

**Attack:** The GAME-HIDE definition in §3 requires that C0 and C1 have "identical (`initialScopeCommitment`, `finalScopeCommitment`, `chainLength`)." This is a precondition, not an outcome. In practice:

- `chainLength` is public. In the NFCU scenario, 4-hop chains are distinguishable from 3-hop or 5-hop chains. If an organization runs a pipeline with a known topology (chatbot → KYC → compliance → settlement), `chainLength = 4` is identifying metadata.
- `allDelegateesMerkleRoot` is public. The root encodes a **snapshot** of the agent registry at enrollment time. Two proofs sharing the same root were generated against the same registry state. Two proofs with different roots were not. An auditor who observes multiple audit proofs can cluster them by Merkle root, reconstructing organizational affiliation without knowing any participant identity.

Concretely: in the journalist scenario (§7, whistleblower variant), if organization A uses `root_A` and organization B uses `root_B`, the auditor learns which organization's registry each hop belongs to — not who the agent is, but which team they're on. Pairwise pseudonymous identifiers (OIDC PPIDs, per §3 of the construction's own §8 row) operate per-RS and prevent cross-RS correlation at the credential level. The construction's approach leaks a coarser but still damaging organizational graph via the public Merkle root.

GAME-HIDE's claim of "ε = 0" holds only when C0 and C1 share ALL public outputs including `allDelegateesMerkleRoot`. If they don't — and in cross-org deployments they won't — the game doesn't apply, and the privacy guarantee evaporates precisely where the construction most needs it.

**Why it fails against the construction:** The construction could respond by using a commitment to a set of accepted roots rather than a single root, and keeping the Merkle root private with a set-membership proof against a public root commitment. But this adds another layer of circuits not in the current design, and the current public output `allDelegateesMerkleRoot` is directly fingerprinting.

**In-threat-model?** No. The construction's GAME-HIDE precondition is too strong for the cross-org deployment scenario it claims to support. The threat must be addressed or the scenario must be scoped down.

---

### Attack 4: RFC 8693 + AS-Side Per-RS Introspection Policy Already Provides Offline Narrowing Attestations — The "Cannot" in §8 Is Overstated

**Attack:** The §8 comparison row "Prove narrowing without disclosing scopes — Impossible" is not technically justified. Here is the baseline construction that achieves the same auditor-visible property:

1. The AS issues RFC 8693 token exchange tokens, recording per-hop scope values server-side (AS has this state anyway — it issued the tokens).
2. When the auditor requests a delegation audit, the AS generates a **signed JWT** (draft-ietf-oauth-jwt-introspection-response) containing:
   - `hop_count`: integer
   - `narrowing_verified`: boolean
   - `initial_scope_class`: coarse bucket (e.g., "financial_medium") — not the bitmask
   - `final_scope_class`: coarse bucket
   - `chain_valid_at`: timestamp
3. The auditor receives a signed, cacheable, offline-verifiable artifact. The AS never discloses intermediate scopes to the auditor. The AS enforces narrowing at issuance. The auditor trusts the AS's signature.

The construction's response to this in §8 is "AS compromise breaks the guarantee." True. But: the construction requires (a) correct BN128 implementation, (b) correct Circom constraint generation with no under-constrained signals, (c) correct Poseidon implementation, (d) correct smart contract verifier, (e) correct on-chain enrollment. Any of these failing breaks the ZK guarantee. The honest comparison is not "perfect ZK vs. compromised AS" but "novel multi-layer ZK stack vs. RFC 7662 with a decade of battle-tested implementations."

The genuine property the baseline cannot achieve is **AS-free cross-org narrowing proof** where no party possesses the scopes. In the NFCU scenario, the AS *by design* holds the plaintext scope values — it issued the tokens. The ZK construction's value proposition is narrower than §8 admits: it shines specifically when the proving party should not trust the auditing party AND when no AS ever held plaintext scope values. That is a real capability. But it is not "AS-free audit" generically — it is "AS-free audit when no AS exists in the architecture." The construction should scope this claim precisely rather than claiming the baseline "cannot" do it.

**Why it fails against the construction:** This attack weakens, not defeats. The construction does provide a strictly stronger guarantee in the threat model where no AS is trusted — including the journalist scenario. The weakness is the overclaimed §8 comparison inviting this exact rejoinder, which erodes credibility for the legitimate novel properties.

**In-threat-model?** Partial. The baseline CAN provide offline narrowing attestations when an AS exists and is trusted. The construction must sharpen its "cannot" to "cannot without trusting the AS," and make the AS-free architecture a first-class design requirement rather than an incidental property.


## Persona: spiffe_engineer

### Attack 1: `allDelegateesMerkleRoot` Uniformity Destroys the Cross-Org Claim

- **Attack:** Section 2, constraint 2h asserts `computedRoot === allDelegateesMerkleRoot` for every active hop — a single root covering all delegatees across the full chain. The construction's §7 concrete scenario claims this works "across organizational boundaries without a shared authorization server." But if the NFCU chatbot delegates to an external settlement-network agent (different operator, different registry), that agent is enrolled in a *different* on-chain Merkle tree. The circuit forces a single `allDelegateesMerkleRoot` public output checked against the on-chain agent root history buffer. Either (a) all cross-org agents must be co-enrolled in *one* registry (making the registry the shared trust anchor you claimed to eliminate), or (b) the proof simply fails because the external agent's Merkle proof is against a different root.

  SPIFFE handles exactly this via trust bundle federation: each trust domain publishes its own bundle endpoint; a relying party accepts SVIDs rooted in any federated domain. The construction has no analog — it collapses cross-org federation into a single-root assumption.

- **Why it works / fails:** The circuit constraint is unambiguous — one root, all hops. The claim that the construction "supports cross-org agent handoff" is directly contradicted by §2's circuit definition.

- **In-threat-model?** No. The construction must either (a) change `allDelegateesMerkleRoot` to a per-hop root array and adjust the public signals, or (b) retract the cross-org claim. This is a design gap, not a cryptographic failure — but the §8 baseline comparison table row "Cross-org without shared trust anchor" is currently false as written.

---

### Attack 2: Prover-Controlled `active[h]` Enables Chain-Length Misrepresentation

- **Attack:** Section 2's constraint logic states: *"Inactive hop: no constraints, values ignored."* The `active[h]` flag is a **private input** controlled entirely by the prover. Nothing in the circuit forces `active[h] = 1` for hops that contain valid delegation data. A prover with a 4-hop real chain can set `active[2] = 0` and `active[3] = 0`, witness-generate a valid proof with `chainLength = 2`, and the circuit accepts it — the NCUA auditor is told the pipeline had 2 hops when it had 4. The two hidden hops could be the KYC agent and the compliance agent — precisely the hops a regulated entity might want to obscure.

  SPIFFE token chains (`act` claim in RFC 8693) have the opposite property: the full `act` chain is present in plaintext, and any hop count reduction requires token reissuance (which the AS logs). The construction's ZK approach buys participant privacy but loses hop-count integrity unless the prover is forced to include all hops.

- **Why it works / fails:** `GAME-NARROW` and `GAME-FORGE` do not cover this. `GAME-FORGE` checks that `initialScopeCommitment` is on-chain and that delegatees are in the Merkle tree. It does not check that `chainLength` equals the true number of hops in the pipeline. There is no on-chain record of individual hop count — only the endpoints.

- **In-threat-model?** No. The construction must add a mechanism to enforce completeness of the chain. One approach: each hop emits a nullifier (already listed in the Bolyra primitive mapping — `delegationNullifier`) that must be committed on-chain at delegation time; the audit proof must prove all on-chain nullifiers between `initialScopeCommitment` and `finalScopeCommitment` are included. Without this, `chainLength` is a prover-asserted claim, not a cryptographic invariant.

---

### Attack 3: The On-Chain Registry IS the Shared Authorization Server

- **Attack:** The construction's §8 table claims the baseline is "Impossible" without an AS, while the construction needs "No trusted third party." But §2's public input `initialScopeCommitment` is checked against `lastScopeCommitment[sessionNonce]` on-chain (§5, "Chain anchor"), and `allDelegateesMerkleRoot` is checked against "on-chain agent root history buffer" (§3, Game 3). Who writes to these on-chain structures? Something must enroll agents, record scope commitments, and maintain the root history. That entity — whether a contract owner, a DAO, or an operator — is the authorization server. It just speaks Solidity instead of OAuth.

  SPIRE node attestation bootstraps identity from hardware/hypervisor properties (TPM, EC2 instance identity document, k8s service account) with no pre-registration beyond the SPIRE server's attestor plugin. The Bolyra model requires explicit enrollment (`credentialCommitment` in the Merkle tree) before any delegation can be proven. For a dynamic AI pipeline where tool-agents are ephemeral containers spun up per-request, this enrollment ceremony is the latency bottleneck that SPIRE's workload API eliminates.

- **Why it works / fails:** The construction correctly replaces a *centralized* AS with a *decentralized* registry (on-chain smart contract), which is a genuine improvement for censorship resistance and auditability. But "no trusted third party" overstates the case. The claim should be "no single-party AS whose compromise unilaterally breaks the guarantee" — the Merkle root is enforced by the circuit, not by the registry operator's honesty. That is the real claim, and it is defensible. The current framing invites this attack.

- **In-threat-model?** Partially. The cryptographic claim (circuit enforces narrowing regardless of registry state) survives. The marketing claim ("no shared trust anchor") does not. The construction should reframe: the registry's *enrollment decisions* are trusted, but its *policy enforcement* is not — narrowing is enforced by the circuit, not the registry operator.

---

### Attack 4: `currentTimestamp` Is Prover-Asserted; Expiry Liveness Is Off-Circuit

- **Attack:** Section 2 lists `currentTimestamp` as a public input described as "Auditor-supplied current time." In a ZK proof, public inputs are committed by the **prover** at proof generation time, not supplied by the verifier at verification time (in standard Groth16/PLONK, the verifier passes public inputs to `verifyProof`, but the prover chose them). The construction says the auditor "receives a single proof" — meaning the prover generated the proof with a specific `currentTimestamp` and the auditor verifies it. Nothing forces `currentTimestamp` to equal the actual wall-clock time at proof generation. A prover with credentials expiring at T=1000 can generate the proof with `currentTimestamp = 999`, pass in-circuit expiry checks, and deliver the proof to an auditor at T=1100 — the proof verifies, but the credentials were expired when the audit was triggered.

  JWT-SVID expiry (`exp` claim) is checked by the relying party at presentation time against its own clock — no prover input. X.509 SVID validity windows are enforced by the TLS stack, not by the credential holder. The construction's "expiry liveness enforced in-circuit" is weaker than these baseline mechanisms because the prover controls the timestamp.

- **Why it works / fails:** The fix is for the auditor to supply `currentTimestamp` as a verifier-side public input override rather than accepting whatever the prover committed. In practice this means the audit protocol must specify: "verifier supplies `currentTimestamp` from its own clock; proof is rejected if the committed value lags by more than T_skew." This is a protocol-level specification gap, not a circuit-level flaw — but §7's claim that "proof generation fails if any hop is expired at audit time" is false when the prover controls the timestamp. The construction's §8 row "Expiry liveness: Token expiry is a claim in the JWT; auditor must inspect it" applies equally to Bolyra unless the audit protocol pins the timestamp to the verifier's clock.

- **In-threat-model?** No. The construction must specify that `currentTimestamp` is verifier-supplied (auditor's clock) and document the allowable skew window. Otherwise the expiry liveness advantage over the JWT baseline disappears.
