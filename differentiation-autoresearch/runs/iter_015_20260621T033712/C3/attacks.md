# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Witness Retention Honeypot

- **Attack:** The construction is explicit: "no reliance on…on-chain intermediate state" (§2). The proof is self-contained. But generating a proof for an NCUA examiner requires that *someone* hold all the private witness inputs — `delegatorScope[i]`, `delegateeScope[i]`, `delegatorCredCommitment[i]`, `sigR8x[i]`, full Merkle sibling arrays — for every hop, for every delegation chain, for however long audit retention requires (Navy Federal is under 7-year NCUA exam cycles). The construction is completely silent on where this witness material lives between delegation time and audit time.

  Auth0 and WorkOS answer this trivially: their token issuance logs, stored in a SOC 2-attested data pipeline, *are* the audit record. Bolyra replaces that with a requirement for operators to maintain raw cryptographic witness bundles in cold storage — bundles that are, individually, far more sensitive than a token log (they contain the actual scope values the construction claims to hide). If that storage is compromised, the privacy guarantee collapses entirely. The operator has traded a centralized log for an even more sensitive centralized witness archive.

- **Why it works / why it fails:** The construction does not address witness custody, rotation, or availability. It treats proof generation as a point-in-time operation without modeling the time gap between delegation and audit. This is a real operational gap, not a cryptographic one. The privacy argument in §3 (Game 2) applies to the verifier, but the *prover* necessarily holds all private inputs — creating a target.

- **In-threat-model?** No — the construction must address where witness material lives, who holds it, and what the audit trail looks like if the witness archive is unavailable at exam time.

---

### Attack 2: `finalDelegateeMerkleRoot` De-Anonymizes the Terminal Agent Across Proofs

- **Attack:** Section 2 lists `finalDelegateeMerkleRoot` as a public output, described in §7 as "verifiable against on-chain agent registry root history buffer." In any realistic deployment — including the NFCU loan pipeline in §7 — the same terminal agent (Agent D, the e-signature orchestrator) processes thousands of loan applications. Each audit proof for each application emits the same `finalDelegateeMerkleRoot`. An adversary who can observe multiple audit proofs can trivially cluster them: "this nullifier set all shares `finalDelegateeMerkleRoot = 0xABCD…` — they all ended at the same agent."

  The Participant Privacy game (§3, Game 2) is defined for a single proof against a single challenger. It says nothing about unlinkability across proofs. For the whistleblower scenario (§7 Scenario 2), this is fatal: the journalist-facing agent appears as the terminal node in every story. Anyone who can collect audit proofs from published stories can enumerate all chains that ended with the same journalist agent. The construction explicitly says the journalist "publishes the audit proof alongside the story" — handing the adversary the correlation vector.

- **Why it works / why it fails:** The ZK argument holds per-proof under honest-verifier ZK. But the public output selection creates a cross-proof linkability channel. This is a standard pseudonymity failure: the construction achieves per-interaction privacy but not multi-interaction unlinkability for the terminal participant.

- **In-threat-model?** No — the construction must either (a) use a per-session blinded `finalDelegateeMerkleRoot` (e.g., Poseidon2(delegateeMerkleRoot, sessionNonce)), or (b) explicitly bound the privacy claim to single-proof contexts and remove the whistleblower scenario, which requires multi-proof unlinkability.

---

### Attack 3: NCUA Doesn't Speak PLONK

- **Attack:** Section 7 grounds the entire enterprise deployment scenario in NCUA Letter 23-CU-15 ("adequate controls over third-party/fintech relationships"). The construction then describes what the examiner "sees" and "can verify." But the verification step requires: running a PLONK verifier against a verification key distributed by Bolyra, understanding what `rootScopeCommitment` means, cross-referencing an on-chain Base Sepolia event, and trusting that `chainLength = 4` reflects the actual pipeline structure (not a prover-selected padding strategy using `hopActive`).

  NCUA examiners today accept: SOC 2 Type II reports, internal audit workpapers, third-party assessment letters, and vendor-provided configuration screenshots. There is no NCUA guidance, examination manual section, or industry precedent for accepting a PLONK proof as evidence of "adequate controls." WorkOS ships a SOC 2 Type II report and a vendor questionnaire template. The §8 comparison table claims Bolyra wins on "offline verifiability" vs. RFC 7662 introspection — but offline verifiability is not the examiner's problem. Their problem is producing something their legal and compliance team can attach to an examination response.

- **Why it works / why it fails:** The claim conflates *cryptographic soundness* with *regulatory acceptance*. A construction can be mathematically airtight and regulatorily useless simultaneously. The construction must identify a specific regulatory pathway — an existing NCUA interpretive ruling, a NIST framework mapping, or an examiner-accepted substitute procedure — that makes a PLONK proof an acceptable control artifact.

- **In-threat-model?** No — the §7 deployment scenario collapses without a regulatory acceptance argument. The construction must either (a) name a concrete regulatory pathway or (b) reframe the deployment scenario as an *internal* audit tool that produces human-readable outputs alongside the proof.

---

### Attack 4: `hopActive` Padding Leaks Circuit Structure to an Adaptive Adversary

- **Attack:** Section 2 describes inactive hop handling: for `i ≥ chainLength`, `hopActive[i] = 0` and constraints trivially satisfy. The prover supplies `chainLength` as a *public input*. This means the verifier knows the exact number of active hops. But more importantly: `MAX_HOPS = 8` is hardcoded into the circuit. Any deployment of this circuit reveals to an observer that the operator's pipeline is bounded at 8 hops maximum. If the actual pipeline is 2 hops, `chainLength = 2` leaks that directly.

  More precisely: the construction offers no padding of `chainLength` itself. For the whistleblower scenario, if only one journalist in a given country operates a 4-hop relay (because most use 2 or 3), `chainLength = 4` is a fingerprint. Stytch's connected apps model and WorkOS's MCP auth don't have this property — OAuth scopes are semantically opaque strings, not structured pipeline depths. The construction gains nothing over "pass a scoped token and log the issuance" for an adversary who can observe audit nullifiers and chain lengths across a population of proofs.

- **Why it works / why it fails:** The ZK guarantee covers private *values* but `chainLength` is explicitly public. The construction frames this as necessary for the circuit (the mux logic requires knowing how many hops to activate), but it leaks pipeline topology. For narrow-domain deployments (whistleblower routing, specific regulatory pipelines), this is a real deanonymization vector. The §3 threat model does not list `chainLength` as a leakage channel or bound what an adversary can infer from it across a population.

- **In-threat-model?** No — the construction must either (a) pad `chainLength` to a fixed value (always claim `MAX_HOPS`) and prove in-circuit that `chainLength ≤ MAX_HOPS` without revealing the exact value, or (b) explicitly add `chainLength` to the list of information the auditor learns and bound its consequences in the privacy argument.


## Persona: cryptographer

Applied cryptographer. Unless I see a game definition, a simulator, and a reduction to a named assumption, it's marketing. The construction here is more careful than most — it has games, reductions, and assumption lists. But there are four specific places where the argument either breaks or is incomplete.

---

### Attack 1: `hopActive` / `chainLength` Decoupling — Soundness Bug

- **Attack:** `hopActive[i]` is listed as a *private input* (per-hop). `chainLength` is a *public input*. The circuit contains no constraint of the form:

  ```
  hopActive[i] === (i < chainLength) ? 1 : 0
  ```

  A malicious prover submits `chainLength = N` publicly but sets `hopActive[k] = 0` for some middle hop `k` where the monotonic narrowing constraint would otherwise be violated. By the construction's own inactive-hop rule, all of hop k's constraints are multiplied by zero and trivially satisfied. The `effectiveSC[k]` mux propagates `prevSC[k]` unchanged. Hop k+1 then links to hop k-1's output scope commitment — skipping the offending hop entirely.

- **Why it partially works:** The prover can misrepresent the actual delegation topology. They can claim `chainLength = 4` while only 3 hops are genuinely constrained — inserting phantom hops or suppressing real hops. This doesn't let a single terminal scope *exceed* the root scope (the non-skipped hops still narrow), but it lets the prover present a false picture of the delegation graph to an auditor: the number of real delegations performed may differ from `chainLength`, and intermediate participants can be entirely fabricated (as the skipped hop's EdDSA check is neutralized).

- **In-threat-model?** **No — the construction must address this.** The fix is a public commitment to the `hopActive` vector or an in-circuit derivation: `hopActive[i] := (i < chainLength)`, with `chainLength` forcing bits deterministically. As written, the game NarrowingSoundness only asks whether *scope* narrows, not whether `chainLength` accurately reflects the number of real delegations. The compliance use case (NCUA examiner counting delegation hops) relies on `chainLength` being meaningful — the construction leaves it unanchored.

---

### Attack 2: Intermediate Delegator Enrollment Gap

- **Attack:** At hop `i`, the circuit performs a Merkle membership proof for `delegateeCredCommitment[i]`. At hop `i+1`, the delegator is linked only via the scope commitment equality:

  ```
  Poseidon2(delegatorScope[i+1], delegatorCredCommitment[i+1]) === newScopeCommitment[i]
  ```

  This does *not* separately enforce `delegatorCredCommitment[i+1] = delegateeCredCommitment[i]`. It only requires the Poseidon2 of the *pair* to match the prior hop's output. A second preimage `(s', c') ≠ (delegateeScope[i], delegateeCredCommitment[i])` with the same Poseidon2 value would allow injection of an unenrolled phantom delegator at every intermediate position.

  More concretely: only the *terminal delegatee* (`finalDelegateeMerkleRoot`) is linked to on-chain enrollment state. Every intermediate delegator's identity is verified only via hash-preimage linking, not via Merkle membership. The adversary controlling intermediate agents (explicitly in scope per the threat model) can generate valid EdDSA keys for phantom entities that have never been enrolled.

- **Why it matters:** The construction's §7 compliance scenario claims "the terminal agent was a legitimately enrolled entity." True. But it makes no claim about intermediate agents — a 4-hop NFCU chain could have 3 phantom middle agents. The auditor cannot distinguish a real 4-hop chain from a chain that actually ran 1 real hop followed by 3 phantom hops (with matching EdDSA keys invented on the fly).

- **In-threat-model?** **No for the compliance use case.** The privacy game (Game 2) treats this correctly — intermediate identities are private by design. But the soundness game (NarrowingSoundness) says nothing about whether intermediate participants are *real* enrolled agents. A separate game is needed: "EnrollmentSoundness — the adversary cannot produce a valid audit proof for a chain where any active hop involves a non-enrolled participant." That game is currently unformalized and unproven.

---

### Attack 3: HVZK Applied to an Active Auditor — Privacy Argument Incomplete

- **Attack:** Section 4's privacy argument states: "By the *honest-verifier* zero-knowledge property of PLONK (composable ZK in the AGM+ROM), the proof π reveals no information about private inputs beyond what is deducible from the public signals."

  This is wrong on two levels. First, HVZK is defined for a verifier that uses *honestly generated* challenges. PLONK is a NIZK via Fiat-Shamir; the challenges are fixed by the random oracle. But the privacy game (Game 2) has the challenger send the same proof to an *active* adversary A. If A can trigger multiple proof generations (e.g., audit the same chain twice with different session nonces), it can run an offline distinguisher that correlates proof transcripts.

  Second, "composable ZK in the AGM+ROM" is not the same as UC-ZK (universally composable zero-knowledge). PLONK in the AGM+ROM achieves *simulation-extractability* (which implies non-malleability), but simulation extractability is an extractability property, not a composable ZK property. The zero-knowledge simulator for PLONK requires the simulation trapdoor (related to the SRS toxic waste). If the same verifier is also receiving proofs from other circuits (e.g., the Bolyra handshake proof), concurrent simulation is not covered by the AGM+ROM analysis.

- **Concrete distinguishing attack (Game 2 variant):** Suppose A has oracle access to the proof generation oracle with fixed `rootScopeCommitment`. A generates 2^k proofs for chains of length `chainLength = 1` with varying scopes. In the AGM+ROM, each proof string encodes group elements as linear combinations of SRS elements, encoding circuit-specific information algebraically. Under repeated proof exposure, A can mount an algebraic attack (in the generic group model) to extract information about witness components — this is exactly what simulation-extractability *prevents* for soundness but does not address for ZK.

- **In-threat-model?** **Partially no.** The Game 2 statement says A sees one proof. With a single proof and honest PLONK, HVZK suffices in the ROM. But the broader deployment claim — that the NCUA examiner (who may request many audit proofs over time, from the same root commitment) learns nothing — requires *composable* ZK or a proof-per-session randomness argument. The construction does not address multi-proof privacy.

---

### Attack 4: Scope Commitment Enumeration Against Small Anonymity Sets

- **Attack:** The auditor observes `finalScopeCommitment = Poseidon2(delegateeScope[N-1], delegateeCredCommitment[N-1])` and `finalDelegateeMerkleRoot`. In the whistleblower scenario (§7, Scenario 2), suppose the auditor knows:
  1. The on-chain agent registry (the Merkle tree is public; leaves are public credential commitments for enrolled agents).
  2. The permission bitmask space is 8 bits (256 possible values).

  The auditor enumerates: for each enrolled agent `c_j` in the registry and each bitmask `s ∈ {0,...,255}`, compute `Poseidon2(s, c_j)`. If any value matches `finalScopeCommitment`, the auditor has recovered both the terminal participant and their exact permission scope — the two things the ZK property is supposed to hide.

  The anonymity set is `|enrolled agents| × 256`. In the NFCU scenario with a curated registry, this may be thousands of entries, not cryptographically large. In the journalist scenario, the "Relay agent" and "Journalist-facing agent" populations are likely small enough to enumerate in seconds.

- **Why it works:** The zero-knowledge property guarantees that the proof reveals no information about private inputs *beyond what is deducible from public signals*. `finalScopeCommitment` is a public signal. The ZK property does not prevent inference from public signals — it only says the proof transcript itself adds nothing. Enumeration uses only the public output, the public Merkle tree, and offline Poseidon evaluation: no proof structure is needed.

- **In-threat-model?** **Yes, but the privacy claim is overstated.** The construction claims "What the examiner does NOT see: ... The actual permission bitmasks at any hop." This is false for the terminal hop whenever the enrollment set is enumerable. The privacy game (Game 2) requires two chains with *identical* `rootScopeCommitment` and `finalScopeCommitment` — this hides the case where different chains lead to the same final commitment, but it does not model the case where the adversary uses the *value* of `finalScopeCommitment` to enumerate preimages offline. The threat model needs an explicit "small anonymity set" caveat and should consider a `finalScopeNullifier` (blinded with a fresh random salt) in place of the raw `finalScopeCommitment`.


## Persona: cu_ciso

---

### Attack 1: The Examiner Cannot Read a Hash — NCUA Part 748 / FFIEC CAT Audit Trail Failure

- **Attack:** Section 7 of the construction tells the NCUA examiner what they "see" during a safety-and-soundness exam: `rootScopeCommitment` (opaque hash), `finalScopeCommitment` (opaque hash), `chainLength = 4`, `auditNullifier` (opaque token), and `finalDelegateeMerkleRoot` (opaque hash). The construction then claims the examiner can "verify that every hop narrowed permissions monotonically (circuit soundness)." But *how*? The examiner needs a PLONK verifier, the verification key, and the public signals. NCUA Part 748 Appendix A requires a documented security program with audit trails that are *complete, accurate, and timely*. An opaque proof is none of those to a human examiner. The FFIEC CAT (Domain 2: Threat Intelligence; Domain 5: Cyber Incident Management) requires that audit evidence be *interpretable by institution staff and examiners* — not by a BN128 pairing function. The NCUA examiner questionnaire for third-party AI systems will ask: "Show me the log of what each AI agent did and what data it touched." The answer here is: "Here is a 800-byte PLONK proof." That is not an audit trail. That is a cryptographic object requiring a PhD to interpret.

- **Why it works / why it fails:** The construction's deployment scenario (§7) implicitly assumes the examiner runs a verifier. It provides no tooling, no examiner-facing UI, no translation layer between the proof and the regulatory control language. The chain length is revealed, but the chain length is not a control — it's a count. Nothing in the public signals maps to NCUA control objectives. The FFIEC CAT maturity levels (Baseline → Innovative) require *documented processes*, not proofs. A "self-contained PLONK proof" is not a documented process.

- **In-threat-model?** **No** — the construction's threat model (§3) covers cryptographic adversaries. It does not address the regulatory legibility problem. The construction must produce a human-readable attestation layer *alongside* the proof: a signed examiner report that maps public signals to NCUA control IDs, maintained by a licensed third party (SOC 2 Type II auditor), that the examiner can actually read. Until then, the claim "usable by NCUA examiner" is not supportable.

---

### Attack 2: The Proof Proves What Could Have Happened, Not What Did — Retrospective Forgery

- **Attack:** The construction proves the *existence* of a delegation chain satisfying monotonic narrowing — it does not prove that *this specific chain was the one actually executed*. The witness is constructed by the prover (the AI pipeline operator), who controls all private inputs (§2, private inputs table). After an actual pipeline run where Agent B secretly held `ACCESS_PII` (bit 7), the operator can construct a *different*, compliant witness — one that shows Agent B held only `FINANCIAL_MEDIUM` — submit it to the circuit, produce a valid PLONK proof, and present it to the NCUA examiner. The proof verifies. The examiner is satisfied. The actual breach is buried. The circuit enforces narrowing over the *witness provided*, not over the *execution that occurred*. Nothing in the construction binds the witness to runtime behavior. `rootScopeCommitment` is anchored to a `HandshakeVerified` on-chain event (§7), but the *intermediate* hops are entirely prover-controlled private inputs. A corrupt operator has a clean audit trail by construction.

- **Why it works / why it fails:** The construction's soundness argument (§4, Narrowing Soundness game) is valid in its own terms: no adversary can forge a proof for a non-narrowing chain given correctly-provided inputs. But the game definition assumes the *chain describes what actually happened*. An adversary who runs one chain and proves a different chain is outside the game. This is not a cryptographic break — it is a protocol gap. The circuit is a statement about a witness, not a statement about runtime execution. The GLBA Safeguards Rule (16 CFR Part 314.4(c)) requires the CU to *monitor and test* controls, which means the control must be binding on actual behavior, not reconstructable post-hoc.

- **In-threat-model?** **No** — the threat model explicitly grants the adversary control of "all intermediate delegation agents (keys, credentials, enrollment)" and "the chain construction (can pick any scope values)." This correctly scopes the cryptographic game. But it does not address the operational forgery: a legitimate operator (not a cryptographic adversary) who runs a non-compliant pipeline and then constructs a compliant proof. The construction needs a binding mechanism between proof and runtime — e.g., the delegation token (`Poseidon4` in §2, constraint 6) must be logged on-chain or in a tamper-evident append-only store *at the time of execution*, before the audit, so the prover cannot swap witnesses post-hoc.

---

### Attack 3: Incident Response Blackout — GLBA Breach Notification Conflict

- **Attack:** At 2am, the SOC gets an alert: a member's PII was exfiltrated through the loan origination pipeline (§7 scenario). The SOC analyst opens a ticket. They have: four opaque hashes, `chainLength = 4`, and an 800-byte PLONK proof. They cannot determine *which agent* accessed the PII, *what specific data* was accessed, *what permissions were active at the time of access*, or *who to call*. The privacy properties that protect whistleblower sources (§7, Scenario 2) and hide intermediate participants also destroy the forensic record. GLBA Section 501(b) requires the CU to have a written information security program that includes a response plan for *unauthorized access to member information* — which requires knowing what was accessed by whom. NCUA's cyber incident notification rule (Part 748.1(e), effective 2023) requires notification within 72 hours of a reportable cyber incident, and the notification must describe the *nature of the incident*. "We have a ZK proof that monotonic narrowing occurred" does not describe the nature of an incident.

- **Why it works / why it fails:** The construction is correct that the ZK proof reveals no intermediate information to the auditor. That is the privacy guarantee. But the *operator* who constructed the proof *does* have the witness — they know all the private inputs. The question is whether the operator is the same party as the incident responder, and whether the operator is willing/able to disclose the witness under legal compulsion. In a regulated CU environment, the operator is a third-party AI vendor. Under NCUA Letter 23-CU-15, the CU is responsible for the third party's actions. The CU cannot rely on "the vendor has the witness" as an incident response plan. The construction provides no mechanism for the CU (the regulated entity) to independently access intermediate chain data for incident response without violating the protocol.

- **In-threat-model?** **No** — the construction's threat model covers cryptographic privacy, not operational disclosure. The construction must specify a privileged disclosure path: e.g., a separate encrypted witness escrow (encrypted to the CU's incident-response key, not revealed to auditors) that allows the CU's security team to decrypt intermediate scopes and participants in a declared incident, without revealing them to the general auditor. Without this, the privacy guarantee and the regulatory compliance obligation are structurally in conflict.

---

### Attack 4: The Circuit Is an Unaudited Vendor — Third-Party Risk Under NCUA Letter 23-CU-15

- **Attack:** The construction introduces a new trust root: the PLONK verification key (derived from `pot17.ptau`) and the correctness of the `DelegationAuditChain` circuit. Under NCUA Letter 23-CU-15 and the CU's Vendor Management Policy, any third party whose failure could cause a material security or compliance impact must undergo due diligence: documented security assessment, contract provisions, monitoring plan, exit strategy. The ZK circuit is that third party. If the circuit has a soundness bug (constraint 3 in §2 — the per-bit subset check — is incorrect for the inactive-hop case due to the `hopActive` multiplication pattern used), every "valid" audit proof is a forgery and the CU doesn't know it. Who audited the circuit? The construction claims soundness under knowledge soundness of PLONK (§4), but that is a *mathematical* argument conditional on the circuit correctly encoding the intended semantics. Circuit audit (formal verification or independent constraint review) is distinct from the cryptographic reduction. Specifically, constraint 10 (inactive hop identity via mux) is described in prose but not formally specified in the constraint logic block — an auditor cannot verify it from the document as written. The `pot17.ptau` ceremony is referenced without provenance: who ran it, what participants, what is the toxic waste disposal record? For a $2B–$10B CU, introducing an unaudited cryptographic component into a regulatory audit workflow is itself an exam finding under FFIEC CAT (Domain 1: Cyber Risk Management, governance of technology risk).

- **Why it works / why it fails:** The construction's cost estimate (§6) and deployment scenario (§7) assume the circuit is correct. The security argument (§4) proves properties *of the specified circuit*, not of the *implemented circuit*. In practice, the Circom implementation is what runs — and Circom has a well-documented history of underconstrained circuits (the `circom_tester` dependency noted in `bolyra/CLAUDE.md`). The construction does not cite any independent circuit audit, formal verification (e.g., Lean4 or Coq formalization of the constraint system), or third-party review. For a regulatory workflow, the circuit's correctness assurance must be at least as strong as a SOC 2 Type II report — which means continuous, not one-time.

- **In-threat-model?** **No** — the threat model assumes the circuit is correctly implemented (adversary does not control the CRS or Poseidon). Regulatory risk from circuit bugs, ceremony compromise, or underconstrained silent failures is outside scope. The construction must reference a circuit audit trail (who reviewed constraints, what tooling, what formal properties were machine-checked) and a ceremony provenance document before a regulated CU can adopt it as a compliance control.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping RFC 7662 in production. I've seen ZK promises dissolve into AS-equivalent trust before. Let's see if this one holds.*

---

### Attack 1: "AS-Sees-Cleartext Is Only Threatening If You Fear Your Own AS"

**Attack:** In the construction's primary deployment scenario (§7, Navy Federal Credit Union), the Credit Union operates the Authorization Server. The AS issued every delegation token in the chain — it already knows every scope value in cleartext at issuance time. Now the NCUA examiner arrives. Under `draft-ietf-oauth-jwt-introspection-response`, the AS signs an offline-verifiable JWT asserting "the chain from `sub` narrowed monotonically through N hops to final scope `{READ_DATA}`." The examiner verifies the AS signature (same trust they extend to NFCU's other signed disclosures). The construction's §8 row "No trusted third party" claims this requires "AS trust or AS policy logs" — but the examiner already extends that trust by regulatory necessity. The NCUA examiner does not and cannot independently verify NFCU's circuit-level controls any more than it verifies their Postgres schema. AS trust here is not a gap; it is the auditor's ground truth. The ZK machinery produces the same auditor-visible assertion the signed JWT response already provides, at 100x the engineering cost.

**Why it works / why it fails:** This attack is lethal for the NCUA scenario as written. The construction's "no AS" advantage is load-bearing only when the adversary *is* the AS or when the AS cannot be trusted to truthfully attest narrowing. In a CU deployment, the AS is the CU itself — the same entity the examiner is auditing. The NCUA doesn't distrust NFCU's AS more than it distrusts NFCU's PLONK prover. The construction must argue why a circuit's soundness guarantee is more auditor-credible than a signed AS attestation when both are produced by the same institution.

**In-threat-model?** No — the NCUA scenario does not establish that AS trust is unavailable or compromised. The construction must either (a) add a deployment scenario where the AS is adversarial, or (b) restrict the "no trusted third party" claim to cross-org or adversarial-AS contexts only.

---

### Attack 2: `finalDelegateeMerkleRoot` Is a Stable Identifier — The Terminal Agent Is Not Hidden

**Attack:** The construction reveals `finalDelegateeMerkleRoot` as a public output (§2, Terminal outputs). The construction also ties verification to "on-chain agent registry root history buffer" (§7, "What the examiner can verify"). If the agent registry is public — which it must be for the verification step to work without AS involvement — an adversary enumerates registry states, computes `Poseidon2(credentialCommitment, ...)` for every enrolled agent, and recovers the terminal agent's identity by matching against `finalDelegateeMerkleRoot`. In the whistleblower scenario (§7 Scenario 2), the journalist's AI agent is a known, stable entity: its Merkle root does not change between sessions. A sufficiently resourced adversary (e.g., a government demanding registry access) trivially de-anonymizes the terminal participant. The construction's Game 2 (§3, Participant Privacy) addresses this inadequately: the privacy game fixes `rootScopeCommitment` and `finalScopeCommitment` as equal between the two challenge chains, but does not include `finalDelegateeMerkleRoot` in the adversary's view as a distinguishing oracle. The game is thus weaker than the construction's prose privacy claims.

**Why it works / why it fails:** RFC 9449 DPoP provides sender-constraint without revealing key material beyond a confirmation claim. For chain privacy, `pairwise_sub` identifiers (OIDC PPID §3.3.2) create per-RS pseudonymous IDs that don't correlate across RPs. Neither leaks a stable identifier to the auditor. The construction leaks a stable Merkle root — a stronger identifier than a PPID — for the terminal agent in every audit proof. The RFC 7662 baseline with PPIDs does *better* on terminal-agent privacy in the single-auditor case.

**In-threat-model?** No — the privacy game in §3 does not model an adversary who holds a registry lookup table. The construction must either (a) show that registry enumeration is infeasible (it isn't if the registry is public), (b) move `finalDelegateeMerkleRoot` to a private input and replace it with a nullifier-style output, or (c) constrain the whistleblower scenario to deployments where the registry itself is private/permissioned.

---

### Attack 3: (`rootScopeCommitment`, `chainLength`, `finalDelegateeMerkleRoot`) Form a Fingerprint in Low-Entropy Deployments

**Attack:** RFC 8707 Resource Indicators (audience binding) and RFC 9449 DPoP produce tokens that are audience-bound and sender-constrained — their public metadata (audience, `jti`, DPoP key confirmation) is high-entropy and context-specific, not a stable long-term identifier. The construction's three public signals — `rootScopeCommitment` (tied to a specific `HandshakeVerified` on-chain event at a specific block), `chainLength` (exact hop count), and `finalDelegateeMerkleRoot` (stable terminal identity per Attack 2) — jointly fingerprint the delegation chain. In the NFCU loan origination example, there is likely exactly one 4-hop chain anchored to a given member's handshake event. The combination (`rootScopeCommitment` = member handshake event, `chainLength = 4`, `finalDelegateeMerkleRoot` = known e-signature agent) lets any observer with access to the on-chain handshake log re-associate the "anonymous" audit proof to a specific loan application and member. The construction's §8 claim "participant identities are private inputs" is formally true but practically defeated when public signals reduce the anonymity set to one.

**Why it works / why it fails:** The construction's §3 Game 2 requires the challenger to hold `rootScopeCommitment` and `finalScopeCommitment` equal. In real deployments, `rootScopeCommitment` is an on-chain event logged with a timestamp and initiating transaction — it may uniquely identify a session before the adversary even looks at the ZK proof. The proof then adds `chainLength` and `finalDelegateeMerkleRoot` as corroborating signals. The privacy game is defined over a controlled challenger setup that doesn't reflect realistic adversarial information access (chain explorers, timing correlation, registry enumeration). This is a gap in the formal security argument, not just in deployment notes.

**In-threat-model?** No — the privacy game in §3 does not model adversaries who cross-reference public blockchain state with the public signals. The construction should either bound its privacy claim to the on-chain event being unlinkable to a session (which contradicts §7's verification step that explicitly cross-references the `HandshakeVerified` event), or introduce a blinding mechanism for `rootScopeCommitment` in the audit proof.

---

### Attack 4: BBS+ + Cross-Credential Equality Proofs Close the Per-Hop Gap — The Construction Overstates the Baseline's Inability

**Attack:** §8 states: "BBS+ can hide individual claims but cannot prove an ordering/subset relationship over hidden bitmasks." This is outdated. The BBS+ 2023 specification (draft-irtf-cfrg-bbs-signatures) supports bound proofs; when combined with NIZK range/equality arguments over committed values (e.g., Bulletproofs or Sigma protocols), a verifier CAN receive a proof that a hidden bitmask value `s₁` satisfies `s₁ ⊆ s₀` without seeing either. Concretely: issue a BBS+ credential containing the committed bitmask; the holder generates a presentation that binds the bitmask to a Pedersen commitment; a companion Bulletproof shows `(s₁ & ~s₀) == 0` for the committed values. This is implementable today with librustzcash-style range proof gadgets. The RFC 7662 + BBS+ + WIMSE baseline in §8 is a strawman — the construction compares itself to RFC 8693's plaintext `act` claim tree, not to a properly composed BBS+ + range-proof stack. The honest comparison must address why a VC presentation bundle with per-hop BBS+ credentials and cross-credential equality proofs (proving each hop's commitment input matches the prior hop's output commitment) cannot replace the `DelegationAuditChain` circuit.

**Why it works / why it fails:** The attack succeeds in showing that §8's table entry is misleading. However, the attack has a real limit: BBS+ cross-credential linking requires each credential issuer to embed a shared commitment scheme, which requires coordination at issuance time — exactly the "shared AS or federation trust anchor" the construction flags. In a cross-org pipeline where hop 2's credential was issued by a different CA than hop 1's, there is no shared commitment basis for a cross-credential equality proof without a WIMSE-style federation anchor. The `DelegationAuditChain` circuit handles this natively because all scope commitments use the same Poseidon schema regardless of issuer. So the attack is partially valid: the baseline CAN match the single-issuer case, but genuinely cannot match the cross-org case without a new shared standard.

**In-threat-model?** Partially. The construction's §8 comparison table must be corrected: replace "BBS+ cannot prove subset relationships over hidden values" with the accurate claim "BBS+ cross-credential equality proofs require a shared commitment basis across issuers, which in cross-org settings requires a WIMSE-equivalent federation anchor that the baseline does not yet standardize." The current phrasing overstates the technical impossibility and understates the organizational/standardization gap, which is the real and defensible differentiator.


## Persona: spiffe_engineer

*Staff engineer running SPIFFE/SPIRE at a Fortune 500, co-author on WIMSE drafts. Stance: you built a new identity protocol where a SPIRE plugin would have been sufficient.*

---

### Attack 1: The SPIRE Plugin Miscount — Wrong Layer, Not Wrong Idea

- **Attack:** SPIRE's plugin architecture already provides the extension point you needed. A custom workload attestor can gate SVID issuance on a ZK proof: the agent presents a ZK witness to the SPIRE agent, the attestor verifies the circuit, and SPIRE issues a short-lived X.509 SVID with the verified scope encoded in the SPIFFE ID path (e.g., `spiffe://bolyra.ai/agent/scope-0x03/exp-1751500800`). The delegation chain audit then becomes standard SVID chain inspection — no new protocol, no new circuit format, no new on-chain registry. You've built an entire protocol when you needed a ~300-line Go attestor plugin.

- **Why it works / why it fails:** It works as a layer argument: the construction invents a new credential format (`DelegationAuditChain` proof), a new on-chain anchor (`HandshakeVerified` event, `finalDelegateeMerkleRoot`), and a new verifier contract — none of which exist in current SPIFFE deployments. The response "but our claim hides scope values" is partially true but deflectable: SPIFFE IDs *can* be opaque tokens rather than human-readable paths; the ZK proof of scope membership can be used as the attestation *input* to SPIRE without encoding scope in the SVID itself. The ZK stays; the new protocol layer evaporates.

  The construction's genuine differentiator — that intermediate scope values are **private inputs** to the auditor — does not survive this attack cleanly. A SPIRE-native approach would require the SVID to encode a commitment to scope, not the scope itself, which demands exactly the circuit the construction describes. The attack exposes a missing justification: §8's comparison table argues against "RFC 8693 + BBS+ + WIMSE" but **never argues against ZK-augmented SPIRE**. That gap is real.

- **In-threat-model?** **No — construction must address.** The construction claims "no trusted third party" (§8, row 3), but SPIRE's attestation model *is* a trusted party — it's just infrastructure-layer trusted, not AS-layer trusted. The distinction matters for the deployment argument. The construction should either (a) explicitly argue why ZK-augmented SPIRE is insufficient (e.g., SPIFFE ID path length limits, no Merkle membership proof in SVID extensions), or (b) position the `DelegationAuditChain` circuit as the attestor backend for a SPIRE plugin, collapsing the "new protocol" objection.

---

### Attack 2: `chainLength` + `finalDelegateeMerkleRoot` as a Pipeline Fingerprint

- **Attack:** The construction's public signals include `chainLength` (public input, §2) and `finalDelegateeMerkleRoot` (public output, §2). In the NFCU deployment scenario (§7), every loan origination audit proof emits `chainLength = 4` and the same `finalDelegateeMerkleRoot` (Agent D, the e-signature orchestrator, is always the terminal agent). An adversary — including the NCUA examiner — who observes a corpus of audit proofs learns:
  1. The pipeline has exactly 4 hops.
  2. The terminal agent's enrollment root is stable across all proofs until a registry rotation.
  3. Proofs with matching `(chainLength, finalDelegateeMerkleRoot)` belong to the same pipeline variant.

  This is a **pipeline fingerprinting oracle**. SPIFFE addresses the analogous problem with short-lived SVIDs (default 1-hour TTL in SPIRE) that rotate the stable identifier. The construction has no equivalent rotation mechanism — `finalDelegateeMerkleRoot` is the Merkle root of the on-chain agent registry, which changes only on explicit registry updates, not per-session.

- **Why it works / why it fails:** The zero-knowledge property (§4, Game 2) protects only the *private inputs*. `chainLength` and `finalDelegateeMerkleRoot` are explicitly public. The construction's privacy claim (§7: "what the examiner does NOT see") never claims these are hidden — but it also never acknowledges what they reveal. In the whistleblower scenario (§7, Scenario 2), a traffic analyst correlating audit proofs by `chainLength = 4` and a stable `finalDelegateeMerkleRoot` can determine that the journalist always uses the same 4-hop relay structure and the same terminal agent, which is significant de-anonymization even without learning intermediate identities.

- **In-threat-model?** **No — construction must address.** The threat model (§3) defines Participant Privacy over intermediate nodes but does not model the auditor's ability to correlate *across* proofs. An adversary who sees N proofs from the same pipeline learns the pipeline's arity and terminal identity. The construction should either (a) make `chainLength` a private input with a zero-knowledge range proof (proving `chainLength ≤ MAX_HOPS` without revealing the exact value), or (b) rotate `finalDelegateeMerkleRoot` per session by committing to a per-session subtree root rather than the global registry root.

---

### Attack 3: Expiry Narrowing Proves Relative Order, Not Absolute Safety — No SVID-Style TTL

- **Attack:** Constraint 5 (§2) enforces `delegateeExpiry[i] ≤ delegatorExpiry[i]`. This is a *relative* ordering constraint. The auditor sees neither `delegatorExpiry[0]` (the root expiry) nor any intermediate expiry — all are private inputs. A malicious operator constructs a delegation chain where `delegatorExpiry[0]` is the Unix timestamp for year 2099, and each hop narrows by 1 second. All circuit constraints are satisfied. The auditor cannot distinguish a 1-hour delegation chain from a 73-year delegation chain. SPIRE enforces absolute TTLs at the platform level — SVIDs expire in minutes to hours, not decades, and the SPIRE server enforces this at issuance time as a non-delegable policy.

- **Why it works / why it fails:** The construction's privacy guarantee — that expiry values are private inputs — is the *source* of this vulnerability. The auditor cannot verify that root expiry was reasonable. The construction could add a public bound: require that `delegateeExpiry[chainLength-1]` (the terminal expiry) is a public output, allowing the auditor to verify the chain doesn't persist indefinitely. But this partially breaks privacy — the terminal agent's expiry leaks timing information. The deeper problem is that the construction conflates "auditor cannot learn intermediate state" with "auditor has sufficient assurance." These are different claims. An NCUA examiner (§7) needs to know that no single agent credential was valid for an unreasonable duration — but the construction prevents exactly that verification.

- **In-threat-model?** **No — construction must address.** The security argument (§4) proves narrowing soundness and participant privacy but says nothing about the *magnitude* of the root scope or the root expiry. A construction that proves "each hop narrowed relative to the prior" is silent on whether the prior was safe. Adding a public `maxExpiryBound` as a circuit parameter — constrained such that `delegateeExpiry[chainLength-1] ≤ maxExpiryBound` where `maxExpiryBound` is a public input — would allow the auditor to verify absolute expiry bounds without learning individual hop expiries.

---

### Attack 4: The WIMSE Comparison Is a Straw Man — TraTs Already Have Delegation Chains

- **Attack:** The §8 comparison table argues against "RFC 8693 + BBS+ + WIMSE" as a monolithic baseline. But WIMSE `draft-ietf-wimse-workload-to-workload` (specifically the Transaction Token / TraT proposal) is not the same as RFC 8693. TraTs carry a `req_cnf` (request confirmation) binding the token to the calling workload's credential, and the `az_details` claim carries delegation context *including chained workload identifiers*. The WIMSE architecture explicitly models multi-hop workload chains. The comparison row "Cross-org chain audit: No single standard produces a unified narrowing proof across trust domains" is false as of `draft-ietf-wimse-arch-07`: WIMSE federation explicitly specifies how trust domain boundaries are crossed using SPIFFE bundle endpoint federation.

  More concretely: the construction's claim that "RFC 8693 `act` claim tree is plaintext" (§8, row 2) is used to argue that WIMSE cannot hide intermediate participants. This is accurate for RFC 8693. But it's a mismatch — WIMSE TraTs don't use the `act` claim tree. They use workload-bound tokens with the SPIFFE ID as the subject, and the question is whether intermediate workload IDs need to be hidden from the *terminal relying party* (WIMSE concern) vs. hidden from an *auditor* (the construction's concern). These are different threat models. The construction never acknowledges this distinction.

- **Why it works / why it fails:** This attack doesn't break the circuit's soundness or privacy properties. It attacks the construction's *positioning* and *necessity* argument. If WIMSE TraTs already provide delegation chain provenance with federation across trust domains, the gap the construction is filling is narrower than claimed: it reduces to "auditor cannot see intermediate scopes or identities" — which is a specific regulatory niche (whistleblower, source protection), not the general multi-org claim made in §1 and §8.

  The construction survives as a valid technical contribution if it resopes its claim. "We add ZK privacy over hidden intermediate scopes and participants to a WIMSE-compatible delegation chain" is a defensible and novel claim. "We replace WIMSE" is not.

- **In-threat-model?** **No — construction must address.** The construction should (a) cite current WIMSE TraT drafts accurately and distinguish the auditor-privacy threat model from the relying-party-privacy threat model, and (b) clarify whether `DelegationAuditChain` is intended as a drop-in replacement for WIMSE or as a ZK extension that can be layered on top. The latter is significantly more deployable: existing SPIFFE/SPIRE operators would add the ZK audit proof as a supplemental artifact without discarding their SVID infrastructure.
