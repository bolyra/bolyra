# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The 12-Second Human Handshake Disqualifies Every Interactive MCP Flow

- **Attack:** The construction's §6 explicitly states that `HumanUniqueness` (Groth16 with rapidsnark) targets **<12s proving time** — left unchanged from the base Bolyra construction. An `AgentScopeAuth` PLONK proof adds another <3s. A full delegated handshake (`proveHandshake(human, agent)`) that binds to a fresh `sessionNonce` per request therefore runs 12–15 seconds on the critical path. Auth0 token issuance is <100ms. WorkOS MCP auth similarly sub-200ms. MCP tool calls happen in tight, multi-turn loops inside agent reasoning steps. At 12s per authorization, a 10-tool agent workflow costs 120 seconds in proof generation alone before the first tool result returns.

  The construction offers no solution: `HumanUniqueness` is explicitly marked "No modification needed" in §6 and §5. The batch nonce scheme (§2.3) eliminates AS round-trips but does not eliminate proof generation latency on the agent side. Suggesting "submit through a shared relayer that batches on fixed intervals" (§4.3) only pushes latency onto the relayer queue; it does not reduce wall-clock time for the requesting agent.

- **Why it works:** The construction's performance framing addresses only the *comparison to Groth16 baseline* (PLONK avoids per-circuit ceremony) and the *constraint budget* (fits in pot16.ptau). It never benchmarks against the incumbent's <100ms bar or addresses what happens in a synchronous MCP call where the tool server is waiting on proof generation. The credit union scenario in §7 describes an agent interacting with Amazon and Costco RSes — both expect near-synchronous responses.

- **In-threat-model?** No. The construction must address: (a) when does the human proof get generated — enrollment-time vs. per-session, (b) if enrollment-time, how does the construction guarantee freshness for the session nonce binding without a new proof, (c) what the end-to-end latency budget is for an MCP tool call under this construction.

---

### Attack 2: Batch Nonce Pre-Issuance Creates a Revocation Blind Spot — OAuth Doesn't

- **Attack:** §2.3 positions AS removal from the per-request hot path as a privacy feature. The AS issues 100 blinded nonce commitments at enrollment; the agent consumes them offline. The on-chain registry validates freshness against the committed set. Fine. Now the operator discovers at 2 AM that the agent's credential was exfiltrated — key leaked in a container log. Under RFC 7009 (OAuth token revocation), NFCU calls one endpoint and every outstanding token is dead in <1s. Under this construction, the compromised agent has up to 99 unconsumed nonces it can burn through at full speed, generating valid proofs against all RSes, until the operator can (a) remove the credential from the Merkle tree on-chain and (b) invalidate all remaining nonce commitments on-chain. That's two on-chain transactions, subject to block time and gas, with no emergency revocation path. The construction never specifies the revocation protocol.

  The regulatory scenario in §7 worsens this: NFCU is cited as satisfying NCUA Reg E and CFPB agent-authorization rules through cryptographic guarantees. A regulator asking "show me your incident response for a compromised agent credential" gets back "wait for the next block and submit two transactions." That does not pass an NCUA IT examination.

- **Why it works:** §8 "Structural Impossibility 5" attacks OAuth's per-request AS hot path as a timing side channel. But the construction implicitly trades revocation granularity for unlinkability. This trade-off is not acknowledged or addressed. The credit union threat model requires immediate, reliable revocation — it's not optional.

- **In-threat-model?** No. The construction must specify: the revocation protocol, its latency bound, how the on-chain registry handles a "revoke all nonces for credential X" operation atomically, and how NFCU communicates this to all RSes that may have previously verified a now-revoked nonce commitment.

---

### Attack 3: scopeBlindingNonce Is Novel Key Material With No Recovery or Rotation Protocol

- **Attack:** §2.1 lists `scopeBlindingNonce` as a private input: "per-scope random blinding factor (generated client-side, stored locally)." The unlinkability proof (§4.2) depends on `scopeBlindingNonce` remaining secret and fresh. The construction creates a third category of secret the agent must manage alongside `agentSecret` and the pre-issued nonce pre-images. No recovery path is specified for any of these.

  Loss scenario: agent local storage is wiped (container restart, ephemeral infra). The agent loses `scopeBlindingNonce` for amazon.com. Its `scopeNullifier` for that RS is now unrecoverable — it cannot prove consistency with any previously issued `scopePseudonym` at that RS without regenerating a new blinding nonce, which produces a different `scopePseudonym`. The RS's session continuity breaks. NFCU has no visibility into this because the AS was removed from the hot path.

  Theft scenario: attacker exfiltrates `scopeBlindingNonce`. Now `scopeNullifier = Poseidon2(rsIdentifier, Poseidon2(agentSecret, scopeBlindingNonce))` is computable with the stolen nonce and any attempt to observe authorization patterns reveals exact scope-targeting. The blinding factor becomes the weakest link. Auth0 has no analogous single-point secret that, if stolen, collapses a privacy guarantee — tokens are already public and scoped.

- **Why it works:** The construction's security argument in §3.1 states the adversary "cannot compromise the agent's local storage." For a proof-of-concept, this is reasonable. For an enterprise deployment — containerized agents, distributed inference, EKS pods — it is an unmet operational requirement that the construction entirely punts to the implementer.

- **In-threat-model?** No. The construction must specify: how `scopeBlindingNonce` is backed up, whether it is derivable from a higher-entropy root secret (removing the separate storage requirement), and what the rotation protocol is if it is suspected to be compromised.

---

### Attack 4: scopePseudonym Is a Permanent Per-RS Tracking Cookie — and the AS Can Use It

- **Attack:** §2.1 defines `scopePseudonym = Poseidon2(rsIdentifier, agentSecret)` as a **public output** and explicitly calls it "stable per-RS identity for session continuity." The IND-UNL-AS game (§3.2) correctly prohibits the adversary from linking authorizations *across different RS values*. But it says nothing about linkability *within* a single RS.

  Within Amazon's RS, every authorization from the same agent — across sessions, months, nonce rotations, even credential renewals (if `agentSecret` is stable) — produces the identical `scopePseudonym`. Amazon receives a permanent, unforgeable pseudonymous identifier for every agent. This is a persistent tracking identifier more durable than a cookie (which expires) or a device fingerprint (which drifts). The adversary in the IND-UNL-AS game is the AS; the RS is not constrained from building lifetime behavioral profiles on `scopePseudonym`.

  For the healthcare variant in §7: UnitedHealthcare operates as AS. A specialist RS sees `scopePseudonym` across every patient-agent visit. The specialist can sell behavioral profiles keyed on `scopePseudonym` to data brokers. The construction prevents UHC-the-AS from learning which specialists you visited; it does not prevent specialist-the-RS from profiling your visit history. HIPAA minimum necessary standard applies to both.

  The reduction sketch in §4.2 does not address this because it only games the AS+colluding-RS coalition linking *across RSes*. Intra-RS linkability is a feature of the design that undermines the privacy narrative in §7 for deployments where the RS itself is adversarial.

- **Why it works:** The construction's §7 states NFCU achieves "cryptographic guarantee, not policy promise" on merchant graph privacy. But a merchant RS holds the complete visit graph for every `scopePseudonym` — which is exactly the cross-session linkage graph. The claim is technically correct only within the narrow scope of the formal game (AS-side correlation). A procurement review at a health system or credit union will read "unlinkable authorizations" and expect unlinkability at the RS layer as well.

- **In-threat-model?** No. The construction should clarify the threat boundary: RS-side profiling on `scopePseudonym` is explicitly out of scope, and the privacy claim in §7's "NFCU cannot build merchant graphs" should be scoped to "NFCU-as-AS cannot build merchant graphs" — the merchant (RS) absolutely can, and this is left unaddressed in both the formal game and the deployment narrative.


## Persona: cryptographer

Applied cryptographer (IACR publications, reviews for CRYPTO/EUROCRYPT/S&P). My stance: unless I see a sound game, a clean reduction, and a simulator, it's marketing. The construction in front of me is more rigorous than most ZK identity papers I review, but I have found four gaps that range from "the proof sketch is wrong" to "this is a full concrete break."

---

### Attack 1: `blindedScopeCommitment` Precomputation — Full Concrete Break of AS-Side Unlinkability

- **Attack.** The AS is the credential issuer. It knows, for every enrolled agent `i`, the full tuple `(modelHash_i, operatorPubkeyAx_i, operatorPubkeyAy_i, permissionBitmask_i, expiryTimestamp_i)` because it signed `credentialCommitment_i = Poseidon5(...)`. `rsIdentifier` is a *public circuit input* — it is emitted on-chain with every proof. Therefore the AS can directly compute, for every enrolled agent `i` and every observed RS identifier `rs_j`:

  ```
  blindedScopeCommitment_{i,j}
    = Poseidon2(perm_i, Poseidon2(credComm_i, rs_j))
  ```

  This is a pure offline table-lookup. No PRF inversion. No extraction. The AS builds a `(i, j) → value` dictionary at enrollment time and matches against every on-chain `blindedScopeCommitment` event. **Matching deanonymizes which agent visited which RS.**

- **Why it works.** The commitment is supposed to hide the agent's identity at an RS. But it contains exactly two ingredients — `credentialCommitment` (issued by the AS, fully known to it) and `rsIdentifier` (public input, on-chain). Poseidon provides collision resistance and PRF-style output distributions, but neither protects against a party that knows *both* inputs. There is no secret randomness in `blindedScopeCommitment` that is unknown to the AS.

- **Why the reduction fails.** Section 4.2's hybrid argument replaces `Poseidon2(s_b, ·)` with a random function to argue that `scopeNullifier*` looks random. But the reduction never touches `blindedScopeCommitment`, which contains no `agentSecret` at all — it is deterministic in `credComm` and `rsId`, both AS-visible. The reduction is simply silent on this output.

- **In-threat-model?** No — the threat model (§3.1) explicitly makes the AS the adversary with "full access to all issuance logs." The construction must either (a) add fresh randomness to `blindedScopeCommitment` whose pre-image is hidden from the AS (e.g., include `agentSecret` or a fresh per-proof randomizer as a private input), or (b) drop `blindedScopeCommitment` from the public output set and accept that cross-hop chain-linking must be done in ZK.

---

### Attack 2: IND-UNL-AS Game Is Under-Powered — AS's A Priori Knowledge Not Modeled

- **Attack.** The game (§3.2) grants the adversary A access to an `Authorize(agentId, rsId, ...)` oracle. But the AS adversary does not *need* this oracle — it already knows all enrolled agents' credential commitments, permission bitmasks, operator keys, and expiries from the enrollment phase. The game should give A this enrolled-agent table as explicit setup knowledge, not gate it behind oracle queries. As written, the game models a strictly weaker adversary than the actual AS.

- **Why it matters.** Consider the concrete advantage gap. The game's Phase 1 oracle teaches A nothing that A doesn't already know as the issuer. The restriction "A has not previously queried `(agent_b, rs*)`" is therefore vacuous as a security boundary — the adversary already has enough information to run the Attack 1 precomputation table without any oracle interaction. The reduction's final bound `2 · Adv^{PRF}_{Poseidon2}(λ)` only bounds adversaries constrained by the game's oracle structure; it says nothing about an adversary exploiting a priori issuance knowledge.

- **Formal statement of the gap.** Let `I_b = (credComm_b, perm_b)` be agent_b's issuance record. The correct game must give A the set `{I_0, I_1, ..., I_m}` at Setup. The theorem as stated does not cover the strengthened adversary `A'` that uses `I_b` directly. Whether `A'`'s advantage is also `negl(λ)` is a separate theorem that requires a separate reduction — one that must account for Attack 1 or argue why `blindedScopeCommitment` is still hiding under `A'`'s view.

- **In-threat-model?** No — the AS in §3.1 has "full access to all issuance logs." The game must match that capability. The game as written is insufficient to support the claim. The proof needs to be rederived with A receiving the full credential table, and Attack 1 must be closed first.

---

### Attack 3: Malicious-Verifier ZK is Unaddressed — Simulator Is Missing

- **Attack.** The RS is an adversarial verifier in this construction (§3.1 says the adversary controls up to n-1 RSes). Groth16 satisfies *honest-verifier zero-knowledge* (HVZK) under a trusted setup — but the RS is allowed to choose public inputs adversarially. Specifically, a malicious RS selects `rsIdentifier`, `sessionNonce`, and `currentTimestamp` strategically across multiple sessions with the same agent. HVZK provides no guarantee against a verifier who adaptively tailors public inputs to correlate private witness information.

- **Concretely.** Suppose a colluding RS-A runs two sessions with the same agent and sets `sessionNonce` to values `n1, n2` of its choice. It observes `sessionBinding_1 = Poseidon2(scopeNullifier, n1)` and `sessionBinding_2 = Poseidon2(scopeNullifier, n2)`. If `scopeNullifier` is stable within a session (§2.1, output 2), the adversary can check consistency: `Poseidon2(scopeNullifier, n1) =? observed_1` for all candidate `scopeNullifier` values. With enough sessions, this is an offline dictionary attack on `scopeNullifier`, which then links all sessions to one agent.

- **The simulator is never defined.** Section 2 specifies constraints, §3 specifies the game, §4 sketches the PRF reduction — but there is no simulator `S` for the MVZK property. Without a simulator that can produce accepting transcripts without the witness, the zero-knowledge claim is unverified against any adversary that deviate from honest verifier behavior. For a protocol where the verifier (RS) is explicitly adversarial, this is not a minor gap.

- **Required fix.** Prove simulation extractability (SE-NIZK), not just HVZK. Alternatively, replace the RS-adversarial case with a protocol that uses a common reference string where the RS's input choices are committed before proof generation. Neither is present in the current construction.

- **In-threat-model?** No — the threat model puts up to n-1 RSes under adversary control, making malicious-verifier ZK the correct notion. The construction only achieves HVZK (standard for Groth16/PLONK), which does not compose under this threat model.

---

### Attack 4: `scopeBlindingNonce` Creates an Unresolvable Nullifier Dilemma

- **Attack.** The `scopeNullifier = Poseidon2(rsIdentifier, Poseidon2(agentSecret, scopeBlindingNonce))` is asked to serve two contradictory purposes simultaneously:
  1. **Replay prevention:** A used nullifier must be registered on-chain and rejected on re-presentation. This requires the nullifier to be *stable* for a given credential use — the on-chain set grows monotonically.
  2. **Cross-RS unlinkability:** The PRF argument in §4.2 requires `scopeBlindingNonce` to be fresh at the challenge so that `derivedSecret` looks random. If the same `nonce` is reused across authorizations to the *same* RS, the same `scopeNullifier` appears in every proof — creating a durable per-agent, per-RS identifier visible in the on-chain nullifier set.

- **The dilemma.** Fix `scopeBlindingNonce` per (agent, RS): then `scopeNullifier` is stable within that RS (as explicitly stated — "deterministic per (agent, RS, blindingNonce)"), and it is a **permanent linkable identifier** for that agent at that RS visible in on-chain logs. Fix it per authorization: then the nullifier set cannot prevent replay, because each proof produces a fresh nullifier that was never registered before. The construction says the nonce is "stored locally" and "per-scope random blinding factor" — it does not resolve which regime applies or how nonce lifecycle management interacts with the on-chain nullifier registry.

- **Concrete exploit under the fixed-nonce regime.** An adversary that sees multiple on-chain proofs with the same `(rsIdentifier, scopeNullifier)` pair across different `sessionNonce` values learns that the same agent authorized at that RS multiple times. Linking these observations across two colluding RSes is prevented by the PRF — but linking observations *within* a single RS is explicitly permitted by the design. The on-chain nullifier event log therefore constitutes a per-RS agent activity log, which may be more than the privacy claim intends.

- **Missing in §4.3.** The side-channel treatment covers timing (batch nonce issuance) and proof size, but never addresses the nullifier log as a within-RS deanonymization surface. The batch blind nonce commitment scheme (§2.3) randomizes `sessionNonce` but does not affect `scopeNullifier`, which is constant across sessions at the same RS.

- **In-threat-model?** Partially. Within a single RS, the stable `scopeNullifier` is arguably intentional (session continuity). But the on-chain event log makes this visible to the AS too, which observes all on-chain data (§3.1). The construction needs to either (a) explicitly scope the within-RS linkability claim and bound it as an intended property, clearly separating it from the AS-facing unlinkability claim, or (b) use a per-authorization nullifier with a separate epoch-based double-spend check — a non-trivial engineering change.

---

### Summary

| Attack | Severity | Breaks IND-UNL-AS? | Required to address |
|--------|----------|-------------------|---------------------|
| 1 — `blindedScopeCommitment` precomputation | **Critical** | Yes, directly | Add hidden randomness (e.g., `agentSecret`) to the commitment, or remove it from public outputs |
| 2 — Game under-models AS prior knowledge | **High** | Game is invalid | Restructure game to give A the full issuance table at setup; re-derive the reduction |
| 3 — No MVZK / no simulator | **High** | Breaks ZK claim under adversarial RS | Define simulator; prove SE-NIZK or restrict RS to semi-honest |
| 4 — Nullifier dilemma | **Medium** | Partial — within-RS leakage | Specify nonce lifecycle precisely; bound and justify within-RS linkability |

Attacks 1 and 2 are tightly coupled: closing Attack 1 by adding `agentSecret` to `blindedScopeCommitment` would make the precomputation infeasible, but the game would still need to be strengthened (Attack 2) to give the adversary the issuance table and show that the new construction survives. Attacks 3 and 4 are independent and require separate proofs.


## Persona: cu_ciso

---

### Attack 1: BSA/AML Transaction Monitoring Obligation — The Construction's Privacy Win Is a FinCEN Enforcement Risk

- **Attack:** Section 7 frames AS blindness as a GLBA §502 win: *"NFCU proves to NCUA examiners that it cannot build merchant graphs."* I bring this to my BSA Officer. She stops me immediately. BSA/AML (31 U.S.C. §5318(g), FinCEN's 2016 CDD Rule, and the FFIEC BSA/AML Examination Manual Chapter 4) require the CU to monitor member transaction activity for suspicious patterns — structuring, layoff purchases, smurfing across merchants. If my AS is cryptographically blind to which RSes my members' agents contact, I *cannot* fulfill my SAR filing obligation. I can't aggregate the Amazon + car dealer + wire transfer activity that triggers a 314(b) information-sharing request. FinCEN can assess civil money penalties against my board members personally under 31 U.S.C. §5321. My examiner has the FFIEC BSA/AML Exam Manual open. Where in this construction do I find the transaction monitoring feed that satisfies it?

- **Why it works / why it fails:** The construction never addresses the AS-as-monitor role. It treats the AS purely as a privacy adversary (§3.1) and optimizes to blind it. This is the right model for a merchant-facing privacy protocol but the wrong model for a federally supervised depository institution that is simultaneously required to surveil member activity. The IND-UNL-AS game formalizes exactly the property that creates the BSA gap. There is no hybrid architecture described where a compliant monitoring plane coexists with the unlinkability guarantee.

- **In-threat-model?** No. The construction must address how a regulated CU operator satisfies transaction monitoring obligations when the AS is cryptographically excluded from the member-merchant activity graph. The construction needs a compliance carve-out architecture — e.g., a member-consented, CU-side audit log that is separate from the unlinkable proof flow — or it cannot deploy at a federally insured CU.

---

### Attack 2: scopeBlindingNonce Custody — No Recovery Path, No Tier-1 Playbook

- **Attack:** Section 2.2 lists `scopeBlindingNonce` as *"generated client-side, stored locally."* Section 2.3 says the agent stores batch nonce pre-images locally — 100 blinded nonces whose openings live on the member's device. My member is 64 years old. She drops her phone in the lake. She calls at 2am. My Tier 1 rep opens the runbook. There is no step for "recover scopeBlindingNonce." The existing 100 batch nonce commitments are now locked on-chain with no matching pre-images. Her AI agent is dead. What's the re-enrollment procedure? How long does it take? Does re-enrollment invalidate the old Merkle leaf, and if so, who signs the revocation? Section 2.3 describes the issuance flow but contains zero words about revocation, re-keying, or device recovery. NCUA Part 748 §II(A)(1)(iii) requires business continuity planning for critical member-facing services. This is a critical path with no documented recovery.

- **Why it works / why it fails:** The construction explicitly front-loads AS interaction to enrollment to achieve timing unlinkability (§2.3, §4.3). That architectural choice concentrates all recovery complexity at the client. The batch nonce design is sound cryptographically but operationally stranded — it assumes durable, recoverable local storage that the construction never specifies or bounds. GLBA Safeguards Rule §314.4(f) requires a CU to test and maintain a written incident response plan. There is no incident described in this construction that would be recoverable by operations staff without cryptographic intervention.

- **In-threat-model?** No. The construction must define: what "stored locally" means (browser localStorage, OS keychain, hardware token), what the recovery SLA is, whether the CU can re-issue batch nonces without compromising unlinkability, and what the Tier 1 escalation script looks like. Without this, no ops team can run it, and no examiner will accept it under Part 748 business continuity review.

---

### Attack 3: Base Mainnet Is an Uncontracted Critical Vendor — Vendor Management Policy Blocks Deployment

- **Attack:** Section 7 deploys on-chain verification to Base Sepolia and then Base mainnet. Section 2.3 routes proof submissions through *"a shared relayer."* I pull up my Vendor Management Policy and NCUA Letter to Credit Unions 01-CU-20. Every significant technology service provider must have a written contract with: defined SLAs, audit rights (right-to-examine clause), business continuity provisions, data ownership and return clauses, and incident notification timelines. I have no contract with Coinbase for Base mainnet availability. I have no contract with whoever operates the shared relayer. Base's documented uptime target is not an NCUA-acceptable SLA document. If the chain is congested during month-end ACH settlement and my members' agents can't authorize transactions, I have no SLA remedy and no escalation path. My examiner's third-party risk questionnaire has a field for "does the CU have a written agreement with this provider?" The answer is no for Base, no for the relayer, and no for Bolyra at Series A.

- **Why it works / why it fails:** The construction's §4.3 notes that relayer-based submission protects timing privacy, but it introduces the relayer as an unexamined dependency. The on-chain registry is treated as infrastructure, not as a vendor relationship requiring governance. FFIEC CAT Domain 3 (Cyber Risk Management) explicitly requires third-party oversight with commensurate rigor to criticality. Blocking a member's agent from authorizing a $50 grocery purchase because Base had a sequencer outage is a member harm event, not an abstract uptime number.

- **In-threat-model?** No. The construction must map every external dependency (Base L2, relayer operator, Bolyra registry) to a vendor management tier, specify contractual requirements, and document what the fallback is during dependency outages. Until Bolyra holds a SOC 2 Type II and Coinbase offers a CU-facing SLA for Base, this construction cannot pass a vendor due diligence review at any federally insured CU.

---

### Attack 4: The GLBA §502 Compliance Argument Is Backwards — An Examiner Will Cite It as a Deficiency

- **Attack:** Section 7 states: *"NFCU proves to NCUA examiners that it cannot build merchant graphs (cryptographic guarantee, not policy promise). This exceeds GLBA §502 requirements and preempts CFPB enforcement actions."* I bring this to my compliance counsel. She reads GLBA §502 (15 U.S.C. §6802). It restricts the CU from *disclosing* nonpublic personal information to nonaffiliated third parties. It does not require the CU to be operationally blind to member activity. The CU satisfies §502 with a privacy notice and opt-out mechanism — standard practice since 2001. Being cryptographically incapable of seeing member merchant activity does not "exceed" §502; it creates a new regulatory gap under NCUA Part 748 Appendix A §III(C), which requires audit logs of member data access events. If my examiner asks "show me the access log for member #4471's agent authorizations for Q1," and the answer is "the construction cryptographically prevents that log from existing," I have a Part 748 finding, not a compliance win. The construction's framing inverts the regulatory incentive structure.

- **Why it works / why it fails:** The construction's regulatory argument (§7) was written from the perspective of member privacy advocacy, not CU examination defense. GLBA §502 is a floor for data sharing disclosure, not a ceiling on CU visibility into member activity. The NCUA examiner's primary concern is not whether NFCU tracks merchant graphs — it's whether NFCU can demonstrate adequate controls, audit trails, and member account integrity. A cryptographic guarantee that the CU *cannot* produce an audit trail is the opposite of examination-defensible. It is precisely the kind of architectural decision that earns a Matter Requiring Attention in the exam report.

- **In-threat-model?** No. The construction must separate the privacy claim from the compliance claim. A legitimate regulatory narrative would be: "The CU satisfies §502 through policy; the ZK construction provides an *additional*, member-elected privacy tier that does not replace the CU's audit logging obligations." The current §7 framing, taken literally, would cause a compliance-aware deployment team at NFCU to reject the architecture as examination risk, not embrace it as examination advantage.


## Persona: rfc7662_advocate

_An OAuth WG veteran who has shipped production introspection for a decade. Every ZK claim is suspect until proven not achievable by RFC 7662 + extensions._

---

### Attack 1: `rsIdentifier` Is a Public Input — Scope Blinding Is Self-Contradictory

**Attack:** §2.1 (Public inputs table) lists `rsIdentifier` as a **public input** to `AgentScopeAuth`. Public inputs in Groth16/PLONK are known to the verifier, included in the proof transaction calldata, and emitted in on-chain events visible to all observers — including the AS. The construction's own circuit specification gives the game away.

Yet §8 ("Structural impossibility 2") claims:

> "Bolyra's scope nullifier `Poseidon2(rsIdentifier, derivedSecret)` is computed client-side. **The `rsIdentifier` is a private input to the circuit.** The AS never learns it."

This is a direct, unambiguous contradiction between §2.1 and §8 within the same document. If `rsIdentifier` is a public input (as the circuit table says), the AS reads it from every on-chain `Verify` event and trivially reconstructs the exact agent-to-RS mapping it was supposed to be denied. The "cross-scope unlinkability" claim collapses to zero — the AS has `(rsIdentifier, scopeNullifier, agentMerkleRoot, timestamp)` for every authorization.

Making `rsIdentifier` a private input is the correct fix, but it requires a redesign: the on-chain verifier must then accept the proof without knowing `rsIdentifier`, which means it cannot check that the `scopeNullifier` is correctly bound to the RS it is verifying for. The RS must supply `rsIdentifier` to the verifier contract, which puts it back in the calldata. The construction needs to explain how an RS-authenticated private channel for `rsIdentifier` avoids on-chain exposure — and none is described.

**In-threat-model?** Yes. Construction must address — this is a specification-level contradiction, not a theoretical concern.

---

### Attack 2: `blindedScopeCommitment` Is Trivially Invertible by the AS

**Attack:** `blindedScopeCommitment = Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsIdentifier))`

The AS is the **credential issuer**. It knows every input to `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` for every enrolled agent — it computed and signed this at enrollment time. It therefore knows `credentialCommitment_i` for all `i`.

From the on-chain proof, the AS also observes `rsIdentifier` (see Attack 1 — it is a public input) and `requiredScopeMask`. The agent's actual `permissionBitmask` is a superset of `requiredScopeMask`, but the AS issued the credential with a specific `permissionBitmask`. For each enrolled agent `i`, the AS computes:

```
candidate_i = Poseidon2(permBitmask_i, Poseidon2(credComm_i, rsIdentifier))
```

It then compares each `candidate_i` to the observed `blindedScopeCommitment`. This is an `O(n)` lookup over the enrolled agent set. It succeeds with certainty because all inputs are AS-known.

The reduction in §4.2 does not model this. The hybrid argument replaces `Poseidon2(s_b, ·)` with a random oracle — but the adversary the reduction considers is one who tries to distinguish PRF outputs at a fresh key. The issuer adversary does not need to evaluate the PRF: it already knows the **plaintext preimage** of `credentialCommitment` for every enrolled agent. The PRF is irrelevant when the key material is known to the attacker by construction.

The §3.1 adversary definition says the AS "cannot break discrete log" and "cannot find Poseidon collisions." It does not account for an AS that simply evaluates Poseidon on its own known inputs. This is not a collision or DL break — it is a straightforward forward computation.

**In-threat-model?** Yes. Construction must address — the issuer-as-correlator scenario is the entire adversarial premise, and the commitment scheme fails against it.

---

### Attack 3: `scopePseudonym` Is a Stable, On-Chain Correlator Visible to Every Observer

**Attack:** `scopePseudonym = Poseidon2(rsIdentifier, agentSecret)` is a **public output**, emitted on-chain for every proof. It is deterministic on `(agentSecret, rsIdentifier)` — no blinding nonce. This is explicitly described as "stable per-RS identity for session continuity."

Consequence: every authorization proof for the same (agent, RS) pair emits an identical `scopePseudonym`. Any observer — the AS, an indexer, any colluding RS — builds a table `{ scopePseudonym → repeat visits }` for free. The on-chain history is permanent; linkability of repeat visits to the same RS is not a "should resist" property but a guaranteed leak by construction.

More critically: the claim in §3.1 bounds the AS to `Adv^{PRF}(λ)`. But the AS need not break any PRF. It observes the stable `scopePseudonym_A = Poseidon2(rs*, s_A)` at a given RS. If it can later induce the agent to authorize at the same RS again under any context (e.g., an RS it controls, or a retry), it re-observes the same value and confirms the link. The blinding nonce in `scopeNullifier` prevents nullifier replay, but `scopePseudonym` provides the stable anchor the IND-UNL-AS game is supposed to eliminate.

The IND-UNL-AS game (§3.2) restricts the adversary from querying `(agent_b, rs*)` before the challenge, but after the challenge (Phase 2), the adversary can query `(agent_0, rs_other)` and `(agent_1, rs_other)` for RSes controlled by the AS. If the AS operates even one RS, it has `scopePseudonym_0_j = Poseidon2(rs_j, s_0)` and `scopePseudonym_1_j = Poseidon2(rs_j, s_1)` for known `rs_j`. The challenge `scopePseudonym* = Poseidon2(rs*, s_b)` is at a fresh `rs*`, so PRF prevents distinguishing. But this assumes `rs*` is fully controlled by the adversary to be "challenge-fresh." In deployment, the AS issues `rsIdentifier` values or can learn them from registration — the game's fresh-`rs*` constraint may not hold under realistic AS capabilities.

**In-threat-model?** Partially. The IND-UNL-AS game technically handles this if `rs*` is fresh. But the deployment threat — repeat-visit linkability at the RS level, and the AS as a registered RS — is not addressed. The construction should clarify whether `scopePseudonym` stability is acceptable and under which threat model.

---

### Attack 4: Pre-Issued DPoP + PAR Falsifies "Structural Impossibility 1"

**Attack (baseline defense):** §8, "Structural impossibility 1" states:

> "No configuration of PPID, DPoP, RFC 8707, or BBS+ removes the AS from the issuance hot path."

This is asserted without proof and is false for a class of RFC-compliant deployments.

RFC 9449 DPoP allows the AS to issue sender-constrained access tokens bound to a client public key. RFC 9126 Pushed Authorization Requests allow the AS to pre-authorize requests before the agent contacts any RS. Combined with RFC 8693 Token Exchange, an AS can issue a batch of short-lived, pre-computed, RS-scoped DPoP tokens at enrollment time — one per RS the agent is permitted to contact — stored locally by the agent. At authorization time, the agent presents the pre-issued token with a fresh DPoP proof. **No per-request AS interaction occurs.**

This mirrors §2.3's "Oblivious Nonce Issuance Protocol" precisely. The AS sees only the batch issuance event, not individual authorization timings. The tokens are audience-bound via RFC 8707 `resource` parameter (so they cannot be presented to the wrong RS), sender-constrained via DPoP (so they cannot be replayed by a passive observer), and short-lived.

The Bolyra construction's advantage over this approach is not AS hot-path elimination — both achieve it. The genuine advantages are narrower: (a) the AS still sees the RS list at batch issuance time in the DPoP model (§2.3 does not — `rsIdentifier` is computed client-side, *if* it is truly private, which Attack 1 disputes); (b) delegation chain topology (RFC 8693 requires AS roundtrip per hop); (c) the formal IND-UNL-AS game with a cryptographic reduction (the DPoP model has no equivalent formalism). The construction's impossibility claims should be scoped to these specific sub-properties rather than the broad "AS is always in the hot path" assertion, which is falsifiable by RFC 9126 + 9449 + 8707 composition.

**In-threat-model?** No — this is a challenge to the baseline comparison in §8, not to the ZK construction itself. The construction survives, but the "structural impossibility" framing is overstated and will not survive WG scrutiny. A more defensible claim: "RFC 9449 + PAR eliminates per-request AS timing exposure but does not eliminate AS knowledge of the RS list at batch issuance; Bolyra eliminates both under the assumption that `rsIdentifier` is a private circuit input."


## Persona: spiffe_engineer

I run SPIFFE/SPIRE in production for 40k+ workloads and co-authored the WIMSE architecture draft. My view: your IND-UNL-AS game is elegant, but your circuit spec contradicts your own security claim, your Merkle root leaks an anonymity-set fingerprint, your issuer-side lookup attack is unbounded, and your threat model assumes hardware-grade storage with nothing to back that up.

---

### Attack 1: `rsIdentifier` Is a Public Input — the Core Privacy Claim Collapses

- **Attack:** Section 2.1 explicitly classifies `rsIdentifier` as a **public input** to `AgentScopeAuth`:

  > | `rsIdentifier` | F_p | Resource Server scope identifier (Poseidon hash of RS URI) |

  Public inputs are part of the verifying key evaluation and are emitted verbatim in the on-chain event log. Your own threat model (§3.1) grants the adversary AS "full access to all emitted events, stored nullifiers, Merkle roots, and scope commitments." Therefore the AS reads `rsIdentifier` directly from every on-chain authorization event.

  Section 8 ("Structural impossibility 2") then states:

  > "The `rsIdentifier` is a **private input** to the circuit. The AS never learns it."

  This is a direct internal contradiction. The PRF-based `scopeNullifier` argument is irrelevant — the AS doesn't need to invert a PRF; it reads the RS identity off the ledger.

- **Why it works:** The unlinkability reduction in §4.2 assumes `rs*` is hidden from the adversary during Phase 1 queries. If `rsIdentifier` is public, Phase 1 learning queries already hand the AS `(agent_b, rsId_prev)` mappings, and the challenge `rs*` is also visible. The hybrid H1→H2 step breaks: `scopeNullifier* = Poseidon2(rs*, Poseidon2(s_b, r_b))` is unlinkable, but the AS already knows `rs*` from the public input and can compute the table `{Poseidon2(rs*, Poseidon2(s_i, r_i))}` for all enrolled agents if it also knows the blinding nonce structure.

- **In-threat-model?** **No — construction must address.** Either `rsIdentifier` must be moved to a private input (requiring a new public commitment to prove the range check `requiredScopeMask` without revealing which RS), or the claim in §8 must be retracted. Making `rsIdentifier` private while keeping `requiredScopeMask` public likely requires a range-proof gadget over the RS-specific permission subset, adding ~500–2,000 constraints.

---

### Attack 2: `agentMerkleRoot` Is a Global Group Tag — Anonymity Set Is Tree-Scoped

- **Attack:** Every authorization proof emits `agentMerkleRoot` as a public output. This is the root of the entire enrollment tree, shared by all agents in that deployment. In the credit-union scenario (§7), NFCU operates one Merkle tree for its agent registry. On-chain, every authorization from any NFCU member agent produces the same `agentMerkleRoot`. So far this is fine — it identifies the tree, not the leaf.

  The problem: `scopePseudonym = Poseidon2(rsIdentifier, agentSecret)` is a **stable, blinding-nonce-free** public output described as "stable per-RS identity for session continuity." It is deterministic across all sessions for the same `(agent, RS)` pair. An RS colluding with the AS sees:

  ```
  (agentMerkleRoot=NFCU_root, rsIdentifier=amazon, scopePseudonym=X, ...)  session 1
  (agentMerkleRoot=NFCU_root, rsIdentifier=amazon, scopePseudonym=X, ...)  session 2
  ```

  The AS, observing the on-chain event stream, sees `(agentMerkleRoot, rsIdentifier, scopePseudonym)` for every submission. Combined with the tree membership bound (say, 10,000 NFCU member agents), the `scopePseudonym` is a permanent, cross-session tracking handle within each RS. The anonymity set for de-anonymization is now 10,000 rather than all agents globally. With timing correlation across RSes (which the AS observes, per §3.1), the effective anonymity set shrinks further.

  Compare this to SPIFFE: an X.509 SVID rotates its leaf certificate on short lifetimes (default 1 hour in SPIRE). There is no persistent pseudonym exposed per workload-RS pair.

- **Why it works:** The IND-UNL-AS game (§3.2) only prohibits A from querying `Authorize(agent_b, rs*, ·, ·)` before the challenge. It does not prevent A from collecting `scopePseudonym` values for `rs*` from the on-chain event log after the challenge proof is submitted. Since `scopePseudonym` is stable and public, A learns a permanent per-(agent, RS) tag from the first authorized session onwards. The game definition does not model this post-challenge observability window.

- **In-threat-model?** **No — construction must address.** `scopePseudonym` should incorporate a rotation mechanism (per-epoch blinding) or be removed entirely in favor of `sessionBinding`. If session continuity requires a stable identifier, it should be negotiated out-of-band rather than embedded as a public output.

---

### Attack 3: Issuer-Side Lookup Attack on `blindedScopeCommitment` — RS Universe Is Enumerable

- **Attack:** The AS (NFCU) issues the credential and therefore knows `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` for every agent it enrolled (it signed it). The construction emits `blindedScopeCommitment = Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsIdentifier))` as a public output.

  The AS precomputes a lookup table:

  ```
  T[agentId][rsId] = Poseidon2(perm_agentId, Poseidon2(credComm_agentId, Poseidon("rsURI")))
  ```

  for every `(agentId, rsId)` pair in a finite RS universe. RS URIs are enumerable: NFCU has a finite list of merchant partners (Amazon, Costco, etc.). The table has `|agents| × |RS candidates|` entries. For 10,000 agents and 500 merchant RSes, that is 5,000,000 Poseidon evaluations — trivially fast (milliseconds on modern hardware).

  On observing a `blindedScopeCommitment` on-chain, the AS performs a table lookup and recovers both the agent identity and the RS with probability 1, assuming the RS universe is known. This attack does not require breaking any cryptographic assumption.

- **Why it works:** The construction's security argument (§4.2) treats `rsIdentifier` as an input that the adversary cannot enumerate. This is only true if the RS namespace is unbounded or if RS identifiers have high entropy beyond their URI preimage. Neither is asserted. The WIMSE draft (§4, "Token Binding and Audience Restriction") at least limits this to registered audiences with opaque identifiers — Bolyra's `Poseidon("rsURI")` is deterministic and reconstructible by anyone who knows the URI list.

- **In-threat-model?** **No — construction must address.** The construction must either (a) require RS identifiers to have at least `λ` bits of entropy beyond their URI (e.g., include a per-enrollment random salt known only to the RS), or (b) acknowledge that `blindedScopeCommitment` does not hide RS identity against an issuer that knows the RS universe. Neither condition is stated.

---

### Attack 4: `agentSecret` Storage Is Unspecified — the Core Threat Model Assumption Is Weaker Than SPIFFE Node Attestation

- **Attack:** The entire construction rests on this adversary exclusion (§3.1):

  > "The adversary **cannot:** Compromise the agent's local storage (the `scopeBlindingNonce` and `agentSecret` remain private)."

  No mechanism is specified for how `agentSecret` is stored, protected, or bound to the workload. In the target deployment — containerized AI agents on cloud infrastructure (§7: "member delegates financial agents") — the operator controls the container runtime. The operator can attach a debugger, take a memory dump, or access the container filesystem. In AWS ECS, GCP Cloud Run, or k8s, a cluster admin can exec into any container and read process memory.

  SPIRE addresses exactly this: node attestation via TPM 2.0 (`tpm_attestor`), AWS Nitro (`aws_iid` attestor), or GCP Confidential VM ensures the SVID private key is bound to hardware. The key material physically cannot leave the attestation boundary even if the host OS is compromised. SPIRE's threat model explicitly covers the malicious operator case for certain attestor types.

  Bolyra's threat model does not. An operator who is also the AS (NFCU in §7 runs both the AS and could run the agent infrastructure) can extract `agentSecret` and `scopeBlindingNonce`, trivially synthesize valid witnesses for `AgentScopeAuth`, and forge authorizations. The IND-UNL-AS game becomes moot: the AS wins with advantage 1 by directly reading the agent's secret.

- **Why it works:** This is not a ZK soundness attack — Groth16/PLONK knowledge soundness is irrelevant if the adversary has the witness in plaintext. The gap is that the construction's cryptographic claims are only as strong as the storage model for `agentSecret`, and that model is left as a deployment concern. In the exact deployment scenario described (credit union operating AS + member agent infrastructure), the threat is structural.

- **In-threat-model?** **No — construction must address.** The construction should either (a) require hardware-backed key storage (TEE, TPM, or Secure Enclave) and specify a concrete attestation binding to the circuit inputs, or (b) scope the threat model to exclude the operator-as-adversary case and state this limitation explicitly. Extending SPIFFE with a ZK attestor — using SPIRE to attest the workload and derive `agentSecret` within an SVID issuance flow — would give hardware-grade key protection without requiring a new storage model.
