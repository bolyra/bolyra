# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Blinding Salt Retention Problem — Undisclosed Secret Management Burden

- **Attack**: Section 2 ("Required upstream change") quietly introduces a new operational requirement: *every delegating agent must retain its `blindingSalt` indefinitely and supply it as a private input to the next hop's Delegation proof*. This is a new secret per hop per session. The construction says "each delegator retains their blinding salt" but does not specify how. In a 4-hop AI pipeline (the NFCU scenario), that means four separate agents — possibly operated by four different orgs (NFCU, TransUnion, two internal teams) — each need to store, retrieve, and securely pass a field element secret. If *any* salt is lost or unavailable at audit time, the audit proof *cannot be generated*. The construction provides no key management protocol, rotation policy, cross-org salt transfer mechanism, or recovery path.

  WorkOS's MCP auth is stateless from the operator's perspective: the AS holds the delegation record; the operator presents the token. There is no per-hop secret the operator must retain. Auth0 AI's approach (documented at their MCP auth overview) puts delegation state in the AS. The burden here is reversed — Bolyra pushes secret state to every node in the chain, which is exactly the complexity AWS IAM, Auth0, and WorkOS built their businesses to eliminate.

- **Why it works**: Section 7 describes a 4-hop cross-org scenario with TransUnion as hop 2. Getting TransUnion's agent to (a) retain a per-session blinding salt, (b) expose it securely to NFCU's compliance agent for audit proof generation, and (c) do this across organizational boundaries without a shared AS is a procurement and integration problem, not a cryptography problem. The construction does not address any of it.

- **In-threat-model?** No. The security model assumes salts are available to the prover at audit time. The construction does not model what happens when they are not, nor does it provide a protocol for cross-org salt coordination. This is a gap the construction must address.

---

### Attack 2: NCUA Examiners Do Not Verify PLONK Proofs

- **Attack**: Section 7 cites the NCUA examination and FFIEC SR 11-7 analogue as the concrete compliance trigger. The examiner receives `(proof, narrowingValid=1, policyOk=1, chainAnchor, terminalScopeCommitment)`. The construction then describes the examiner reconstructing Poseidon3 hop digests, querying on-chain `DelegationVerified` events, hashing 8 digests, and matching `chainAnchor`.

  NCUA examination is conducted by human examiners using BSA/AML tools, spreadsheets, and audit reports — not BN254 pairing checkers. FFIEC guidance asks for *documented AI model risk management processes*, audit trails, and evidence of controls — all of which Auth0, WorkOS, and Stytch can satisfy with SOC 2 Type II reports, immutable audit logs (Cloudtrail, Datadog), and dashboard exports. The construction does not explain *how* an NCUA examiner would actually consume the PLONK proof. It assumes the examiner operates a Poseidon hasher and an Ethereum RPC endpoint.

  Even in the best case — NFCU building a compliance portal that presents examiner-friendly output — that portal is trusted infrastructure that the examiner is ultimately relying on, reintroducing exactly the trusted-third-party problem the construction claims to eliminate. The examiner who cannot run `ethers.js` against a Base Sepolia node themselves is trusting NFCU's portal, not the proof.

- **Why it works**: The construction's "why the baseline cannot match" table (Section 8) argues that Auth0/WorkOS require trusting the AS. But NCUA examination *already* accepts the AS as a trusted party — NFCU's SOC 2-certified AS is precisely what satisfies SR 11-7. The ZKP proof proves something the examiner has no mandate to verify cryptographically, to an examiner who has no tooling to verify it.

- **In-threat-model?** No. The threat model (Section 3) is cryptographic — it proves soundness against adversaries who can fabricate chains. It does not model the compliance consumption path or the examiner's capability assumptions. The construction must either narrow its deployment claim (this is for automated on-chain auditors, not human NCUA examiners) or explain the examiner-facing tooling layer and the trust it reintroduces.

---

### Attack 3: The "< 2 Seconds" Claim is the Circuit, Not the Flow

- **Attack**: Section 6 claims `DelegationChainAudit` targets "< 2 seconds" PLONK proving. The comparison in the attack prompt is WorkOS issuing tokens in < 100ms. The construction partially addresses this by scoping the comparison to the audit circuit alone — but it does not account for the full audit proof generation latency in the NFCU scenario.

  To generate the `DelegationChainAudit` proof, the prover must supply `delegationNullifier[i]`, `chainPredecessor[i]`, and `blindingSalt[i]` for each hop. These come from the per-hop `Delegation` circuit executions (each ~22K constraints, the largest circuit in the system per Section 2's comparison table). In a 4-hop live pipeline, the upstream `Delegation` proofs are generated at delegation time (not audit time), so they are not re-proved during audit — but the prover must still *retrieve* them. If the pipeline crosses orgs (TransUnion hop), retrieval requires a cross-org API call and the salt coordination problem from Attack 1. If any hop's delegation proof was not retained (agent restart, session expiry), the audit proof cannot be constructed.

  More pointedly: WorkOS's < 100ms is end-to-end, including network round trips. The Bolyra audit flow involves: on-chain event retrieval (1–3s on L2 depending on indexer), Poseidon preprocessing of hop digests (client-side), PLONK proof generation (< 2s claimed), and verifier contract call (gas + finality). Total wall-clock time in the NFCU scenario is 5–15 seconds minimum, not comparable to < 100ms token issuance.

- **Why it works**: The construction's latency comparison (Section 6, "< 2 seconds") addresses only the audit circuit in isolation. The enterprise operator asking "why would I use this instead of WorkOS" is comparing *end-to-end auth latency*, not circuit-level proving time. The construction has no latency budget for the full audit generation flow.

- **In-threat-model?** No (it is not a cryptographic failure, but it is an unanswered GTM objection). The construction must provide an end-to-end latency estimate for the audit flow in the NFCU scenario, including event retrieval and cross-org coordination, and explain why that tradeoff is acceptable for audit-time (not request-time) use cases.

---

### Attack 4: On-Chain Anchor Requires Blockchain Infrastructure the Auditor Doesn't Have

- **Attack**: The construction's anchoring mechanism (Sections 2, 5, 7) requires the auditor to retrieve `DelegationVerified` events from the on-chain registry and cross-reference them against the `chainAnchor`. Per `CLAUDE.md`, the deploy target is **Base Sepolia** — a testnet. Audit-grade evidence anchored to a testnet is not admissible for regulatory examination purposes. Even if deployed to Base mainnet, the construction introduces a new infrastructure dependency: the auditor needs access to a Base RPC endpoint, or must trust an indexer that exposes the `DelegationVerified` events.

  Cloudflare Access for enterprise MCP runs on Cloudflare's global network with 99.99% SLA, SOC 2 Type II, FedRAMP Authorization, and HIPAA BAA availability. The Bolyra registry is a Solidity contract on Base (an Ethereum L2) — with no disclosed uptime SLA, no canonical indexer, and a dependency on L1 Ethereum for finality. If the registry contract is upgraded or the admin key is compromised, all prior audit proofs become unverifiable.

  The construction claims "no trusted third party" (Section 8) — but the Base sequencer *is* a trusted third party for finality. Coinbase controls the Base sequencer. NFCU's NCUA examiner trusting the chain anchor is trusting Coinbase's sequencer liveness and the registry contract's immutability. The construction does not address contract upgradeability, admin key management, or sequencer trust.

- **Why it works**: The "no trusted third party" claim in Section 8 is technically accurate for the cryptographic layer (PLONK verifier is trustless) but false for the infrastructure layer. An NCUA examiner cannot accept "the proof is valid per the BN254 pairing" if the underlying event log requires trusting a Coinbase-operated sequencer and an unaudited Solidity contract on a testnet.

- **In-threat-model?** No. The threat model (Section 3) scopes the adversary to cryptographic attacks, not infrastructure compromise. The construction must address: (a) mainnet deployment timeline and SLA, (b) registry contract upgradeability and admin key controls, (c) sequencer trust model, and (d) examiner-accessible event indexing without requiring a blockchain node — before citing NCUA examination as a concrete deployment scenario.


## Persona: cryptographer

> "Unless I see a tight game definition, a clean reduction, and an honest list of assumptions, the security argument is a proof sketch at best and marketing at worst."

---

### Attack 1: Tight-Chain Scope Deduction Defeats `ScopeRecovery` Under MAX_HOPS-1 Corruption

**Attack:**

The `ScopeRecovery` game permits the adversary to corrupt up to `n-1` hops of an `n`-hop chain. Consider a minimal tight chain: `MAX_HOPS = 8`, adversary corrupts 7 hops, leaving hop `j` honest. From the corrupted neighbors the adversary learns:

- `scope[j-1]` (upstream neighbor, corrupted)
- `scope[j+1]` (downstream neighbor, corrupted)

The monotonic narrowing constraint enforces `scope[j+1] ⊆ scope[j] ⊆ scope[j-1]` (bitwise). For 8-bit bitmasks, the number of valid candidates for `scope[j]` is the interval `[scope[j+1], scope[j-1]]` in the Boolean lattice, counted by `2^{popcount(scope[j-1]) - popcount(scope[j+1])}`. When `scope[j-1] = scope[j+1]` (a common operational pattern — "pass-through" delegation), there is exactly **one** valid value for `scope[j]`. The adversary outputs it and wins with probability 1.

**Why it works:**

The blinding salt prevents recovering `scope[j]` from the commitment alone, but the blinding salt does nothing to prevent *inferring* `scope[j]` from the narrowing structure. The adversary is not performing a preimage attack; they are performing a constraint-satisfaction attack using knowledge of adjacent scopes. The win condition in `ScopeRecovery` is `scope*[j] = scope[j]` — it does not specify *how* the adversary recovers the scope.

**Why the paper's bound is wrong:**

The claimed `Pr[A wins] ≤ 256/|F_p|` only bounds the preimage attack. It does not account for the adversary class that deduces scope via the narrowing partial order. In the worst case (tight chain, MAX_HOPS-1 corruptions), `Pr[A wins] = 1`.

**The construction's acknowledgment is inadequate:**

Section 3 says: *"In the degenerate case where narrowing constraints uniquely determine scope[j], the adversary learns the scope from the narrowing structure alone — but this is inherent to the delegation semantics, not a failure of the commitment scheme."* This is an admission that the `ScopeRecovery` game is not won with negligible probability in general. Calling it "inherent" does not make it acceptable — it means the game must be reformulated with a tighter corruption bound (e.g., no adjacent corruptions), or the privacy claim must be weakened. As stated, the `ScopeRecovery` claim is false at MAX_HOPS-1 adversarial corruptions.

**In-threat-model?** **No.** The game explicitly permits MAX_HOPS-1 corruptions. The claimed probability bound fails. Construction must either tighten the corruption bound in the game definition or replace the privacy claim with a conditional one (e.g., `Pr[A wins] ≤ negl(λ) + 1/lattice_interval_size`).

---

### Attack 2: Knowledge Soundness of PLONK Is Not a Self-Contained Assumption — ROM and AGM Are Missing

**Attack:**

The reduction in Section 4 begins: *"By PLONK knowledge soundness, extract witness..."*. This invocation treats knowledge soundness as a standalone assumption. It is not. Non-interactive PLONK proofs (the only viable option for offline audit verification) are compiled from the interactive PLONK protocol via Fiat-Shamir. Knowledge soundness of the resulting NIZK requires:

1. **Algebraic Group Model (AGM)**: The inner product argument in PLONK's polynomial commitment (KZG) is knowledge sound only when the prover is restricted to computing group elements as linear combinations of those in the SRS. Without AGM, a standard-model adversary can violate extractability.
2. **Random Oracle Model (ROM)**: The Fiat-Shamir transform replaces the verifier's random challenges with hash outputs. Knowledge soundness in this setting requires the hash to be a random oracle. With a concrete hash (e.g., SHA-256 or Poseidon used as the FS hash), the reduction invokes the ROM.

The construction's assumption list (Section 4) enumerates: PLONK knowledge soundness, Poseidon collision resistance, Poseidon preimage resistance, DLOG on Baby Jubjub. Neither AGM nor ROM (for the FS transform) appear. This is not a minor omission — without these, there is no theorem that says the PLONK extractor exists. The "knowledge soundness of PLONK" bullet point in the assumptions is circular: it names the conclusion of the sub-proof, not the primitives that establish it.

**Concrete consequence:**

If the ROM assumption for Fiat-Shamir fails (e.g., if Poseidon used in the FS hash has structural weaknesses exploitable by the prover), the extractor in step 1 of the reduction does not exist. The entire soundness argument collapses. This is not hypothetical — the PLONK knowledge soundness proof in Gabizon et al. (2019) explicitly uses the AGM; the Fiat-Shamir ROM is separately required in the work of Chiesa et al. (2019) on succinct NIZK.

**Concretely, the stated assumptions do not imply the reduction:**

Even granting Poseidon collision resistance and DLOG on Baby Jubjub, if the Fiat-Shamir hash in the PLONK prover is not a random oracle, step 1 ("extract witness by PLONK knowledge soundness") has no formal basis. The reduction is incomplete as written.

**In-threat-model?** **No.** The paper must explicitly state AGM + ROM as assumptions, or use an alternative compilation (e.g., interactive verification with round-reduction). As written, the security proof rests on an unstated assumption that subsumes the result being proved.

---

### Attack 3: Sequential Coherence Is a Hybrid Claim — Circuit Proof Alone Does Not Imply It

**Attack:**

Section 4, step 8 asserts: *"chain coherence is now enforced by the circuit."* This is incorrect. Sequential coherence (`prevSC_i^chain = newSC_{i-1}^chain` for on-chain events) follows from combining:

- **Constraint 4** (in-circuit): `chainPredecessor[i] = scopeCommit[i-1]`
- **Step 7** (Poseidon collision resistance applied to hop digests): `chainPredecessor[i] = prevSC_i^chain` AND `scopeCommit[i-1] = newSC_{i-1}^chain`

Step 7 in turn requires the auditor to have already verified game conditions (c) and (d): that each `hopDigest[i]` matches the triple from on-chain events, and that those events are retrieved correctly from the chain. These are **external auditor-side checks**, not in-circuit constraints. The PLONK verifier accepts or rejects a proof given its public inputs and outputs — it does not query on-chain events or reconstruct hop digests from chain data.

**The attack:**

A malicious prover generates a proof over a fabricated chain: all 8 hops are on-chain delegation events, but they are from four different unrelated sessions, spliced together. The in-circuit constraints are satisfied (the private witness `chainPredecessor[i]` values are chosen to be consistent). The `chainAnchor` output is computed correctly from these fabricated hop digests. The PLONK proof is valid.

If the auditor does not independently verify that the on-chain events corresponding to each `hopDigest[i]` form a sequentially linked chain (i.e., check `prevSC_i^chain = newSC_{i-1}^chain` for all `i`), the auditor cannot detect the splice. The proof does not self-certify sequential coherence — it certifies only that the prover's witness was internally consistent and that the `chainAnchor` was computed according to the circuit.

**Why this matters for the claimed construction:**

The paper conflates two distinct verification steps:

1. **Proof verification**: `PLONK.Verify(vk, publicInputs, proof) = 1` — this is what the ZK protocol guarantees.
2. **Chain anchor verification**: auditor checks `chainAnchor` against on-chain events AND that those events are sequential — this is an additional protocol step outside the proof.

Conditions (c) and (d) of `NarrowingAuditSoundness` embed this external check into the win condition, making it a requirement on the auditor rather than a guarantee of the proof system. If an implementation omits step 2 — which is easy to do, since the proof verification step alone returns a boolean — the sequential coherence guarantee is absent. The game condition papers over this gap by requiring the adversary to produce a `chainAnchor` that cross-references valid events (condition c) AND that those events are sequential (condition d). But condition (d) is satisfied by the on-chain facts, not by the proof — a well-formed proof could have condition (c) satisfied with non-sequential events if the auditor performs the chain anchor recomputation against events fetched in the wrong order or against a stale snapshot.

**In-threat-model?** Partially. The game conditions (c)+(d) are sufficient IF the auditor implements them correctly. But the claim that "circuit enforces coherence" is overclaimed — coherence requires both the circuit and the auditor's external check. The construction should reformulate: coherence is an auditor-protocol property, not a bare ZK proof property. An API that returns only `narrowingValid = 1` from proof verification, without bundling the on-chain anchor check, gives a false sense of security.

---

### Attack 4: Blinding Salt Retention Creates an Unmodeled Protocol Failure — Audit Is Not Always Possible

**Attack:**

The construction introduces `blindingSalt[i]` as a new private input in `AgentPolicy` and `Delegation` circuits, and requires delegators to retain this salt for use in subsequent delegation proofs (chain-linking constraint: the next hop's `Delegation` circuit takes the prior delegator's salt to reconstruct their scope commitment). Section 2 states:

> "The only coordination requirement is that each delegator retains their blindingSalt to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking."

This coordination requirement is not modeled anywhere in the threat model (Section 3) or the security games.

**The attack:**

1. **Salt loss:** A delegator at hop `j` loses or rotates their `blindingSalt[j]` before audit time. The prover who generates the audit proof (e.g., NFCU's compliance agent) cannot reconstruct `scopeCommit[j]` to satisfy constraint 4. The audit proof cannot be generated. The construction provides no recovery mechanism — no blinding salt escrow, no commitment to the salt on-chain, no threshold key management.

2. **Salt reuse across sessions:** If a delegator reuses the same `blindingSalt` across two different sessions with the same `scope` and `credCommitment`, the two on-chain scope commitments are identical. An adversary who sees these two commitments learns that the same agent had identical permissions in both sessions — a linkage attack that partially defeats the cross-session unlinkability the construction implicitly targets.

3. **Adversarial delegator withholds salt at audit time:** In the whistleblower scenario, an intermediate relay agent (hop `j`) wishes to prevent audit by simply refusing to provide `blindingSalt[j]`. Since the audit proof cannot be generated without all salts, any single intermediate node can veto the audit. This violates the construction's claim that the auditor can verify the chain without requiring intermediate participants' cooperation beyond what is on-chain.

**Why the threat model must address this:**

The `NarrowingAuditSoundness` game defines what the adversary sees and controls, but it does not specify the protocol for assembling the audit proof witness. The proof generation phase requires all `blindingSalt[i]` values from all participating delegators. If the adversary controls even one delegator and withholds their salt, audit liveness fails. This is not addressed in the security argument — the reduction assumes the prover has all private inputs available without explaining how this is achieved in practice.

**What a formal treatment requires:**

Either (a) the construction must define a salt commitment protocol (e.g., the delegator commits to their salt on-chain at delegation time, with a zero-knowledge opening later) so salt availability is guaranteed without revealing the salt, or (b) the threat model must explicitly scope out liveness attacks and acknowledge that audit requires delegator cooperation. As stated, the construction conflates audit soundness (which it proves) with audit liveness (which it does not address and which fails under adversarial salt withholding).

**In-threat-model?** **No.** The threat model does not model adversarial salt withholding or salt loss. The construction must either provide a salt availability mechanism or explicitly bound audit to cooperative delegators and remove the implicit liveness claim.


## Persona: cu_ciso

---

### Attack 1: Regulatory Mapping Gap — You Can't Hand `narrowingValid=1` to an NCUA Examiner

- **Attack**: The construction's public output to the auditor is a PLONK proof with `narrowingValid=1`, `policyOk=1`, `chainAnchor`, and `terminalScopeCommitment`. An NCUA examiner conducting a Part 748 examination is looking for *documented access control procedures*, *evidence of least-privilege enforcement*, and *third-party risk management artifacts*. Section 7 of the construction describes an examiner verifying `Poseidon3(nullifier_i, prevSC_i, newSC_i)` hop digests from on-chain events. No NCUA examiner will do this. The examiner questionnaire asks: "Do you have documented procedures for granting, modifying, and revoking access to member information systems?" (NCUA Part 748, Appendix A, III.C). A ZK proof answers a different question entirely. The FFIEC CAT Domain 3 (Cybersecurity Controls) Control 3.1.1 asks for a "formal access control policy" — not a circuit constraint table. The construction maps to no FFIEC CAT baseline statement, no GLBA Safeguards Rule section (16 CFR Part 314), and no NCUA examination workpaper. An examiner who cannot tie the artifact to a named control will document it as a gap, not a compensating control.

- **Why it works**: The construction is technically rigorous but legally opaque. It never performs the translation layer. Section 7 describes the examiner "retrieving DelegationVerified events and verifying hop digests" — this assumes the examiner has Poseidon3 tooling, understands BN254 scalar fields, and has authority to accept cryptographic proofs in lieu of documented access control evidence. None of these are true. The construction claims "FFIEC guidance on AI model risk management (SR 11-7 analogue)" in Section 7 without citing a specific control or showing how `narrowingValid` maps to SR 11-7's model validation requirements.

- **In-threat-model?** No — this is out of scope for the cryptographic threat model but directly in scope for the deployment claim. The construction must address: (a) a translation layer that maps `narrowingValid=1` to named NCUA/FFIEC controls with examiner-readable evidence, (b) guidance on what supplementary documentation accompanies the proof (since the proof is not self-explanatory to a non-cryptographer), and (c) explicit citation of which NCUA Part 748 Appendix B subsection or FFIEC CAT statement this satisfies. Without this, the NFCU scenario in Section 7 fails at the first examiner conversation.

---

### Attack 2: Blinding Salt Key Custody — You Created a New Critical Secret With No Management Story

- **Attack**: Section 2 introduces `blindingSalt[i]` — a per-hop random field element with ≥ 128 bits of entropy that each delegator "retains locally and passes as a private input to the next hop's delegation proof." Section 4 (Required upstream change) states the delegator must supply their blinding salt when the next hop's delegation proof reconstructs their scope commitment for chain linking. This salt is now a **critical encryption key under NCUA Part 748 Appendix B / GLBA Safeguards Rule 16 CFR 314.4(c)(3)**: it must be generated via a CSPRNG, stored durably and securely (encrypted at rest), backed up with documented recovery procedures, protected from unauthorized access, and auditable for rotation/expiry. The construction says nothing about any of this. Worse: if a delegator's system crashes and the salt is lost, the chain cannot be linked in a subsequent audit proof — the construction's chain-linking constraint 4 requires `blindingSalt[i]` to reconstruct `scopeCommit[i-1]` for the next hop. A lost salt breaks audit defensibility permanently for that session.

- **Why it works**: The construction introduces the blinding salt as a cryptographic necessity (Section 3, ScopeRecovery game) but treats it as a throwaway "private input chosen at delegation time." In a credit union deployment, this salt is managed by the NFCU loan intake agent's infrastructure — a third-party AI system. The salt escapes Bolyra's control the moment it's generated. Under NCUA's Third-Party Risk Management guidance (Letter to Credit Unions 07-CU-13 and its successors), NFCU must assess this third-party's key management practices, include salt custody in the vendor contract SLA, and demonstrate to examiners that the salt cannot be exfiltrated (which would allow a compromised insider to brute-force scope values retroactively, undoing the ScopeRecovery guarantee). The construction's claim in Section 3 — `Pr[ScopeRecovery] ≤ 2^{-246}` — assumes the adversary cannot obtain the salt. A vendor breach collapses this to `Pr[ScopeRecovery] = 1` for all past sessions where the vendor held the salt.

- **In-threat-model?** No — the adversary model in Section 3 explicitly excludes "blinding salts of honest participants" from what the adversary sees, but does not bound the adversary who compromises the delegator's infrastructure (key management system, HSM, or cloud secret store). The construction must specify: (a) where the blinding salt lives (HSM? KMS? in-memory ephemeral?), (b) what happens to auditability if the salt is lost (is the session permanently unauditable?), (c) whether the salt must be escrowed to enable future regulatory examination — and if so, to whom, creating a new trust assumption — and (d) how salt custody fits into NCUA's vendor management requirements.

---

### Attack 3: Privacy Guarantee Inverts at Incident Response — You Can't Debug What You Can't See

- **Attack**: Section 7's journalist/source variant and the core privacy guarantee state that "the auditor does NOT learn who the intermediate agents are." The construction achieves this: `credCommitment[i]` values are private inputs, and the chain anchor reveals only nullifiers (pseudonymous, session-unlinkable). At 2am, a suspicious transaction triggers a fraud alert on the NFCU loan origination pipeline. My Tier 1 ops team opens a ticket. The question is: which agent in the chain exceeded its mandate, and what did it do? The answer under this construction is: *unknowable without the private inputs*. The examiner the next morning asks: "Show me the audit log for the agent that accessed member PII at 02:47." The proof says `narrowingValid=1` — the chain *did* narrow properly. But it doesn't say who touched what. The privacy guarantee that makes the construction valuable to the journalist/source scenario is a direct liability in the incident response scenario at a federally examined financial institution.

- **Why it works**: The construction conflates two incompatible audit regimes in Section 7. For an NCUA examiner, "audit" means a *forensic trail* — who accessed what, when, with what authorization, with what outcome — per NCUA Part 748 Appendix B §III.D (audit trail requirements) and FFIEC IS Examination Handbook (Audit section). For a whistleblower/journalist scenario, "audit" means *structural verification without participant disclosure*. These are opposites. The construction's single circuit serves both but satisfies neither completely: NFCU examiners need participant identification (which the construction hides by design), while journalists need participant hiding (which NCUA examiners would treat as obstruction). Section 7 presents Navy Federal as the primary deployment target — a federally examined credit union — but delivers whistleblower-grade anonymity that NCUA examiners cannot accept as a substitute for access logs.

- **In-threat-model?** No — the threat model in Section 3 addresses adversary `A` trying to break cryptographic properties, not the operational scenario where the *legitimate* auditor needs information the construction deliberately withholds. The construction must address: (a) a dual-mode audit proof — one for structural verification (current construction) and one for forensic disclosure (e.g., threshold decryption of participant identities under examiner subpoena), (b) how NCUA Part 748 Appendix B §III.D audit trail requirements are satisfied when intermediate participants are cryptographically hidden, and (c) whether the construction is appropriate for FFIEC-examined institutions at all, or only for non-regulated pipeline audits.

---

### Attack 4: On-Chain SLA and Third-Party Vendor Risk — The Registry Is a New Critical Dependency With No Uptime Guarantee

- **Attack**: Section 5 (Bolyra Primitive Mapping) and Section 7 require the auditor to "retrieve DelegationVerified events from on-chain state." Sections 2 and 7 require the `HandshakeVerified` event and `lastScopeCommitment[sessionNonce]` to be readable on-chain. The PLONK verifier contract must be callable. This means Base Sepolia (or whatever production chain Bolyra uses) is now a **critical third-party service provider** under NCUA's Third-Party Relationship guidance and FFIEC Business Continuity Management Booklet (2019). NFCU's loan origination pipeline cannot produce an examiner-acceptable audit proof if the chain is unavailable, congested (events not indexed), or reorganized (events rolled back). Base Sepolia is a testnet. If this moves to Base mainnet, Coinbase/OP Stack's SLA applies — which is not an NCUA-examined institution and has no formal uptime commitment in any credit union vendor contract template. My core processor (Symitar, FiServ) has a 99.9% uptime SLA with NCUA-auditable incident reporting. The on-chain registry has no equivalent.

- **Why it works**: The construction's chain anchor verification in Section 7 requires the examiner to retrieve on-chain events: "Retrieves the 4 `DelegationVerified` events for this `sessionNonce` from on-chain state." This is an active, real-time dependency — not a self-contained proof artifact. If the chain is unavailable at examination time, the examiner cannot verify the chain anchor against on-chain state, and the audit proof is unverifiable. Section 8's "Offline verifiability" claim ("PLONK proof + on-chain event cross-reference. No real-time API calls to any authority") is misleading: the proof itself is offline-verifiable, but the *chain anchor verification* requires querying on-chain events. These are not the same. An examiner who has the proof but cannot access the chain cannot complete the Section 7 verification procedure. The construction also introduces a new attack surface: an adversary who can suppress on-chain event indexing (e.g., via block explorer DoS) prevents the auditor from completing chain anchor verification, making `narrowingValid=1` unverifiable even when it is true.

- **In-threat-model?** No — the threat model explicitly addresses adversary capabilities over the proof and witnesses but says nothing about availability of the on-chain registry. The construction must address: (a) what the RTO/RPO is for the on-chain event store, (b) whether the `DelegationVerified` events must be archived in an NCUA-accessible off-chain store (e.g., S3 with write-once retention) as a fallback, (c) how the construction fits NCUA's third-party risk management requirements for a critical vendor with no audited uptime SLA, and (d) whether a credit union can satisfy FFIEC Business Continuity requirements while depending on a blockchain for audit evidence during examination.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by a well-configured AS.*

---

### Attack 1: AS-Side Signed JWT Attestation Closes the Scope-Hiding Gap Without ZK

- **Attack**: `draft-ietf-oauth-jwt-introspection-response` lets the AS return a *signed JWT* as its introspection response — offline-verifiable, no live AS query required (closing the Table 8 "Offline verifiability" distinction). More importantly, RFC 9728 PRM lets each RS declare what claims it needs; the AS applies per-RS scope filtering. Since the AS issued every delegation token, it already holds all intermediate scopes. It can compute `∀i: scope[i] ⊆ scope[i-1]` internally and return a signed attestation — `{"narrowing_held":true,"chain_length":4,"session":"X","terminal_scope_class":"read-only"}` — without disclosing any intermediate scope values to the auditor. RFC 8707 audience binding ties this JWT to the specific examiner and session. The auditor gets an offline-verifiable JOSE artifact proving monotonic narrowing held with no scope leakage. This directly attacks the "Prove narrowing without disclosing scopes" row in Table 8.

- **Why it works / why it fails against the construction**: This is a valid substitute for any deployment with a shared AS. The construction's counters are: (a) the AS *learns* all intermediate scopes to compute the check — fatal in the journalist/source scenario where the AS is the adversary, (b) cross-org pipelines have no shared AS, (c) AS compromise collapses the entire guarantee. These counters hold for those scenarios. However, the construction's Table 8 claim of "No trusted third party" is itself overstated. It trades AS trust for trust in: the PLONK universal trusted setup ceremony, the BN254 pairing assumption, and the correctness/immutability of the Bolyra-deployed registry smart contract. For NFCU — which already operates a SOC 2 / FedRAMP-compliant AS for member services — the construction replaces a well-audited, institutionally-governed trust anchor with one deployed by a startup. That is not obviously an improvement against NFCU's actual threat model.

- **In-threat-model?** Partially — No. The AS-attestation approach fails for journalist/source (AS must not learn sources) and genuinely cross-org scenarios (no shared AS). The construction survives there. But the NFCU scenario as written does not require AS-free verification: NFCU owns its own AS, the NCUA examiner is not an adversary of the AS, and the examiner is compelled by law to accept FIPS-approved artifacts. The construction must sharpen its threat model to identify precisely which scenarios *require* AS-free verification rather than treating it as universally load-bearing. The current Table 8 overstates the gap.

---

### Attack 2: Adaptive `auditPolicyMask` Queries Recover Terminal Scope in Eight Proofs

- **Attack**: The `ScopeRecovery` game (Section 3) models a single-shot adversary who outputs one guess `scope*[j]`. The claimed bound `Pr[A wins] ≤ 256/|F_p| ≈ 2^{-246}` holds only under this model. But `auditPolicyMask` is a public *input* the auditor specifies — the construction places no restriction on how many times an auditor may request a proof for a given session. An examiner compelled to audit NFCU's pipeline can request eight proofs for the same `sessionNonce`, each with `auditPolicyMask = 1 << b` for `b ∈ {0,...,7}`:

  ```
  Query b=0: auditPolicyMask = 0x01 → policyOk ∈ {0,1} reveals bit 0 of scope[terminal]
  Query b=1: auditPolicyMask = 0x02 → policyOk reveals bit 1
  ...
  Query b=7: auditPolicyMask = 0x80 → policyOk reveals bit 7
  ```

  Eight adaptive binary-membership queries yield the exact terminal scope bitmask. The blinding salt `blindingSalt[terminal]` provides zero protection here: `policyOk` directly encodes a one-bit function of `scope[terminal]` for each query, and the Poseidon preimage hardness argument does not apply to a function the circuit computes and *outputs in plaintext*.

- **Why it works / why it fails against the construction**: The construction's implicit defense is that the *prover* controls proof generation. In the NFCU case, NFCU's compliance agent generates proofs and could refuse fine-grained queries. But in a regulatory examination context, NCUA can compel proof generation with any `auditPolicyMask` the examiner chooses — the construction provides no mechanism to limit adaptive policy mask queries while still permitting legitimate audits. A fix exists in principle: commit to a single `auditPolicyMask` in the session state before audit begins, or replace the binary `policyOk` output with a range proof that proves containment without revealing which specific bits exceed the mask. Neither fix is in the current construction.

- **In-threat-model?** Yes — this is a genuine formal gap the construction must address. Section 3's `ScopeRecovery` game must be extended to model adaptive `auditPolicyMask` queries, and the security argument must either prove the construction is still secure under this model (it isn't, as shown) or provide a mechanism — pre-committed policy mask, masked `policyOk`, or a range proof over the terminal scope — that closes it. The `2^{-246}` bound is incorrect for any realistic audit scenario where the examiner specifies the policy mask.

---

### Attack 3: FIPS 140-3 Compliance Precludes the Construction's Centerpiece Regulatory Scenario

- **Attack**: Section 7 explicitly grounds the construction's real-world validity in an NCUA examination of Navy Federal Credit Union under FFIEC SR 11-7 analogue guidance. Under NCUA's Information Security Examination Procedures, regulated institutions must use FIPS 140-3 validated cryptographic modules. FIPS 140-3 covers: SHA-2, SHA-3, AES, RSA, ECDSA over P-256/P-384, X25519/X448. The construction's primitives — Poseidon hash over BN254 scalar field, BN254 Groth16/PLONK pairing — do not appear on any NIST-approved algorithm list. NIST has not standardized Poseidon (the NIST lightweight cryptography competition concluded with Ascon; a separate ZKP-oriented hash standardization effort is in progress but not complete as of mid-2026). The BN254 curve is explicitly excluded from SP 800-186 (NIST-approved curves for key agreement/signatures). An NCUA examiner's verification tooling — constrained to FIPS 140-3 certified modules — cannot implement BN254 pairing verification. The on-chain registry lives on an EVM chain, itself not a FIPS-compliant system. Contrast with `draft-ietf-oauth-jwt-introspection-response` using HMAC-SHA256 or ECDSA-P256: deployable today in NFCU's existing FIPS-validated infrastructure.

- **Why it works / why it fails against the construction**: This does not break the cryptographic soundness argument. It breaks the construction's claim of *regulatory utility* — specifically the NFCU scenario that anchors Section 7. The entire NCUA examiner story depends on the examiner being able to verify the PLONK proof. If the examiner's toolchain cannot verify BN254 pairings, the proof is not evidence NCUA can accept regardless of its mathematical correctness. The construction might adapt by substituting FIPS-approved hash functions (SHA3-256 replacing Poseidon), but this would require non-trivial R1CS redesign and would lose Poseidon's constraint-efficiency advantage (~400 constraints per Poseidon3 vs. thousands for SHA3-256 in an R1CS). The BN254 curve issue is harder: PLONK on BLS12-381 or a NIST curve might be acceptable post-standardization, but that requires a new universal setup and is not interchangeable with the current construction.

- **In-threat-model?** No — this is a deployment gap the construction must address or disclaim. The regulatory scenario is presented as the primary real-world validation for the construction's commercial relevance. If FIPS compliance precludes it, the construction must either (a) scope its regulatory claim to post-NIST-standardization timelines and identify the specific NIST effort that will address Poseidon/BN254, (b) identify a FIPS-compatible ZK stack with comparable efficiency, or (c) remove the NFCU/NCUA framing and anchor the claim in non-FIPS environments. Leaving it as-is misleads potential regulated-industry adopters.

---

### Attack 4: Blinding Salt Retention Requirement Reintroduces a Centralized State-Management Trust Point

- **Attack**: Section 2 ("Required upstream change") states: "the only coordination requirement is that each delegator retains their `blindingSalt` to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment." In AI agent pipelines — the construction's first-listed target deployment ("tool-call chains") — intermediate agents are frequently stateless or ephemeral: serverless functions, containerized tools with no durable storage, short-lived model context windows. If an intermediate agent at hop `i` loses its `blindingSalt` (container eviction, process crash, memory-only runtime), chain-audit proof generation for that session becomes permanently impossible: `blindingSalt[i]` is the only witness satisfying constraint 4's predecessor-linking equality, and it is unrecoverable from on-chain data by design. The session's narrowing audit silently fails — not because narrowing didn't hold, but because a witness was lost.

  The natural operational fix — escrow blinding salts in a durable store — collapses the "no trusted third party" guarantee. Any escrow holding `{blindingSalt[i]}` alongside the public Merkle tree's `{credCommitment[i]}` can enumerate all 256 candidate scopes per hop: `Poseidon3(s, credCommitment[i], blindingSalt[i])` for `s ∈ {0,...,255}`, matching against on-chain `scopeCommit[i]`. The escrow recovers the full scope of every hop in 256 × `n` hash evaluations — precisely the attack the blinding salt was designed to prevent. The baseline (RFC 8693) has no analogous problem: token state is persisted durably in the AS, and token loss does not break auditability; the AS log is the ground truth by design.

- **Why it works / why it fails against the construction**: The construction's authors can respond that blinding salt retention is a standard key management responsibility, no different from any other cryptographic secret. This is formally correct. But the RFC 7662 baseline imposes *no analogous per-hop secret retention requirement* for ephemeral pipelines — token exchange state is AS-managed. The construction imposes a new operational burden that is particularly sharp for the exact deployment class it targets. Furthermore, in the journalist/source variant, requiring each relay agent to durably retain its salt across sessions introduces a correlatable state artifact that itself becomes a target for coercion: "produce your blinding salt" is a compelled disclosure of relay identity that no equivalent RFC 8693 deployment requires from intermediate nodes.

- **In-threat-model?** Partially. The cryptographic soundness is unaffected — this is an operational critique, not a cryptographic break. However, the construction's "no trusted third party" claim is practically contingent on solving blinding salt persistence without centralized escrow. For ephemeral AI agent pipelines specifically, this is not a solved problem. The construction should specify a concrete salt lifecycle: how salts are generated, where they are stored, for how long, under what access controls, and what happens to auditability if a salt is lost. Without this, the "no trusted third party" advantage is a theoretical property that real deployments will erode through necessary operational centralization.


## Persona: spiffe_engineer

---

### Attack 1: SPIRE's ZK Attestor Plugin Closes the Same Gap Without a New Protocol Stack

**Attack:**
SPIRE's [attestor plugin API](https://spiffe.io/docs/latest/deploying/attestation/) allows arbitrary workload attestation logic. A ZK attestor plugin — one that accepts a Bolyra-style Poseidon commitment against an on-chain agent registry as the attestation evidence — would issue a SPIFFE ID (`spiffe://bolyra.ai/agent/<nullifierHash>`) to any ZKP-enrolled agent. Hop-level delegation maps directly to SPIRE registration entry hierarchies and SVID path scoping. The cross-org narrowing the construction claims in §8 ("Cross-org without shared AS") is exactly what SPIFFE federation handles: trust domain federation (`spiffe://nfcu.com` ↔ `spiffe://transunion.com`) with JWT SVIDs carrying permission claims. WIMSE `draft-ietf-wimse-arch` §5.1 explicitly puts workload-to-workload scope narrowing across trust domains in scope. The construction's §8 table dismisses "cross-org without shared AS" as a Bolyra advantage — but SPIFFE federation IS that mechanism. The correct contribution is a WIMSE draft extension for ZK attestation, not a parallel protocol.

**Why it works / why it fails against the construction:**
The construction does have a genuine gap that SPIFFE federation doesn't address: the *privacy* dimension. JWT SVIDs with permission bitmask claims are plaintext. SPIFFE federation trust anchors see the full scope at each hop. The §8 claim about scope hiding ("Auditor sees only `narrowingValid = 1`") has no SPIFFE equivalent — SPIRE registration entries and JWT claims are not computationally hiding. However, the construction's §1 claim of broad applicability ("not just narrow regulatory audit") is undercut by the fact that 95% of deployments don't need scope hiding from the auditor — NCUA examiners in §7 are legally entitled to see scopes; they just don't want to see *participants*. For that narrower goal, SPIFFE's pairwise pseudonymous PPIDs (OIDC) are sufficient.

**In-threat-model?** No — the construction does not justify why extending SPIFFE is inferior to a new protocol for the non-privacy-critical case, and §8 overstates the gap. The construction must address: *for which deployments is scope hiding from the auditor a requirement (not just a nice-to-have), and why does that subset justify a full parallel identity stack?*

---

### Attack 2: Blinding Salt Retention Is an Unmodeled Key Management Hazard That Creates a Covert Channel

**Attack:**
Section 2 ("Required upstream change") states: "each delegator retains their `blindingSalt` to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking." In the §7 NFCU scenario, the TransUnion credit-scoring agent (Hop 2) must retain `blindingSalt[2]` indefinitely — or until an audit is triggered. AI tool-call agents are commonly stateless serverless functions (AWS Lambda, GCP Cloud Run). Their memory is ephemeral. The salt is not output by any Bolyra circuit and is not recoverable from on-chain state (by design — it's the hiding primitive). If the Hop 2 agent is replaced, restarted, or its local state is lost, the audit proof **cannot be generated**. The chain is permanently unauditable. This failure mode is entirely absent from the §3 threat model.

Worse: the ScopeRecovery game (§3) assumes `blindingSalt[i] ←$ F_p uniformly at random` but the circuit does NOT constrain the entropy of the salt. The adversary who controls the audit proof generator (e.g., NFCU's compliance agent generating the proof) chooses the salts. A malicious proof generator can encode bits of information in the low-order bits of each `hopDigest[i]` by selecting salts that produce controlled `Poseidon3` outputs — the auditor sees only the anchor hash and cannot detect this steganographic channel. The construction's §3 adversary model says the adversary "does NOT control... the blinding salts of honest participants" — but the proof generator who assembles the audit proof has exactly that control.

**Why it works / why it fails against the construction:**
SPIFFE's Workload API handles credential lifecycle automatically via SPIRE's short-lived SVID rotation. There is no analogous lifecycle mechanism in Bolyra for salt retention. The construction has no salt escrow, no salt recovery path, and no out-of-band coordination protocol defined. Against the covert channel sub-attack: the construction's §3 ScopeRecovery game binds to fixed public `scopeCommitment` values on-chain, so a malicious salt choice that alters `hopDigest` outputs would produce a non-matching `chainAnchor` — the chain anchor check (§7, step 3) would fail. This neutralizes the steganographic attack on the *chain anchor* specifically. However, the salt retention failure mode is not neutralized — it is a genuine operational gap.

**In-threat-model?** No (salt retention failure) / Yes (salt entropy covert channel via audit proof generator — the chainAnchor check blocks it). The construction must address: salt lifecycle management, recovery procedures for ephemeral agents, and whether the audit proof generator is assumed honest or adversarial. If adversarial, the "does NOT control blinding salts" assumption in §3 is violated.

---

### Attack 3: `chainLength` Is a Public Input — the Journalist/Source Scenario Leaks Network Topology

**Attack:**
`chainLength` is listed as a public input (§2, Public inputs table) with no privacy qualification. In the §7 journalist/source variant, the editor (auditor) learns the exact number of relay hops. In real journalist relay networks (SecureDrop, Tor onion routing), the number of hops is itself sensitive — it reveals the network's anonymity set structure. `chainLength = 3` with a 4-hop design tells the editor there are exactly 2 relay agents between journalist and source. Combined with on-chain `DelegationVerified` event timestamps (block timestamps are public), the editor can apply inter-arrival timing analysis: if blocks 10, 10, 11 contain the three delegation events, all three hops were active within ~24 seconds, implying a single automated pipeline rather than human relay agents. `MAX_HOPS = 8` (§2) with `chainLength = 3` further exposes the headroom — a sophisticated editor infers the network has at most 5 additional hops of capacity, bounding the anonymity set.

The construction's §7 journalist claim ("editor does NOT learn: who the intermediate agents are") is technically correct but the *structural* anonymity is broken. The construction's §3 adversary model does not model timing side-channels on on-chain events. SPIFFE's mTLS SVIDs don't have this problem: each hop is a separate TLS connection; no party accumulates the chain count, and the "auditor" verifying the final result sees only the terminal SVID.

**Why it works / why it fails against the construction:**
The construction could make `chainLength` a private input and prove it is consistent with `chainAnchor` via an in-circuit sum check (constraint 2 already computes `sum(hopActive[i]) === chainLength`). If `chainLength` were hidden, the auditor would need to know it to verify the `auditPolicyMask` applies to the *terminal* hop — but the terminal multiplexer (constraint 7) could be replaced with a "prove the policy holds for ALL active hops" check, making `chainLength` unnecessary as a public input. This is not the current design.

**In-threat-model?** No — the construction claims journalist/source anonymity but exposes chain length and on-chain timing, which the threat model (§3) does not account for. The construction must either (a) drop the journalist/source claim, (b) hide `chainLength`, or (c) add timing obfuscation to the deployment model.

---

### Attack 4: The Trust Root Is the Verifier Contract Deployment — an Out-of-Scope Governance Problem

**Attack:**
The §4 security argument lists four named assumptions (PLONK soundness, Poseidon collision resistance, Poseidon preimage resistance, Baby Jubjub DL hardness). It does not list a fifth implicit assumption: **the on-chain Solidity verifier contract is deployed with the `.zkey` that matches the circuit**. The entire reduction in §4 steps 6–11 depends on "by game conditions (c) and (d), the auditor has verified that each `hopDigest[i]` matches the on-chain triple from `DelegationVerified` events." Those events are only authentic if the verifier contract accepted valid PLONK proofs — which requires the deployed contract to match the `.zkey`. CLAUDE.md itself flags this exact risk: *"Solidity verifiers must match .zkey — when you re-run trusted setup or change a circuit, regenerate the verifier contract from the new vkey.json. Tests will pass against the wrong verifier locally if witness signatures happen to match."*

An adversary with write access to the contract deployment pipeline (CI/CD compromise, upgrade proxy admin key theft) deploys a verifier contract that accepts proofs from a different `.zkey` — one for which the adversary knows a trapdoor. The adversary then posts fabricated `DelegationVerified` events with arbitrary `(nullifier, previousScopeCommitment, newScopeCommitment)` triples. The `DelegationChainAudit` circuit faithfully proves narrowing over these fabricated on-chain triples. The NCUA examiner's chain anchor verification (§7, step 3) matches because the fabricated events were constructed to match. The proof is sound relative to the corrupted on-chain state.

SPIRE's equivalent trust root — the SPIRE server's CA key — is standardly protected by HSM with hardware-backed key attestation (PKCS#11, AWS CloudHSM). Bolyra's equivalent protection for the verifier contract admin key and `.zkey` provenance is entirely unspecified. The §3 adversary model says "adversary does NOT control the BN254 pairing" but says nothing about controlling the verifier contract deployment.

**Why it works / why it fails against the construction:**
The construction has no circuit-level defense against this attack — it is a governance/deployment security problem. The construction could mitigate by (a) deploying the verifier behind an immutable proxy (no upgrade path) and using a public `.zkey` ceremony with published transcripts, or (b) requiring the PLONK universal reference string to be the PLONK trusted setup transcript with public verifiability. Neither is specified. The §4 claim "no trusted third party" is false: the deployer of the verifier contract is a trusted party, and deployer key management is a single point of failure outside the cryptographic model.

**In-threat-model?** No — the construction's §3 adversary model does not include the verifier contract deployer or CI/CD pipeline as adversarial. The construction must either (a) formally add verifier contract deployment integrity to the trust model with explicit mitigations, or (b) restrict its "no trusted third party" claim to exclude the verifier deployer.
