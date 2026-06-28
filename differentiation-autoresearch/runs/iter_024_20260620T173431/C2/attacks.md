# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: The Latency Cliff Kills Real-Time API Use Cases

- **Attack:** Section §6 of the construction honestly admits the target proving times: PLONK `ScopedPresentation` at <3s, Groth16 at <1.5s, `HumanUniqueness` at <15s. My product issues an opaque access token in <100ms via a warm Auth0 token endpoint. In the Amazon merchant API scenario (§7 "Credit union cross-merchant unlinkability"), the agent waits 2.5 seconds before the RS can even begin processing the request. For synchronous API calls — payment authorization, real-time eligibility checks, point-of-sale — this is a hard no. The latency budget for a checkout API is typically 200ms end-to-end. The construction burns 2.5s before the RS sees a single byte of application data.

- **Why it works / why it fails:** The construction argues rapidsnark on M1/M2 or a 4-core x86 server achieves ~0.8s Groth16 and ~2.5s PLONK (§6), but this assumes the agent *is* the prover running on capable hardware. In practice, an AI agent embedded in a serverless function, a mobile wallet, or a constrained IoT controller does not have a native rapidsnark binary. The construction defers this to "commodity hardware" without specifying a fallback for resource-constrained agents. Auth0 tokens are a symmetric HMAC verification in microseconds. The gap is 10-30x on fast hardware and 100x+ on constrained deployments.

- **In-threat-model?** No — the construction does not address latency as a threat or a deployment constraint. It lists "target" times without an engineering path for environments where rapidsnark is unavailable. The procurement question is simple: "Can my agent authorize a payment in the same round-trip as my existing OAuth flow?" The answer today is no.

---

### Attack 2: Unlinkability Is the Wrong Property for Enterprise Audit Requirements

- **Attack:** The construction's core claim (§1, §7) is that "no coalition of the AS and any strict subset of RSes can determine whether two authorizations originated from the same agent." I sell this property as a *liability* to enterprise buyers. SOC 2 Type II, FedRAMP Moderate, and PCI DSS 4.0 all require attributable audit trails: who accessed what resource, when, and under what authorization. The construction's CU scenario (§7) explicitly says "Amazon knows: [nothing about Alice's identity]." That is precisely the audit trail an enterprise compliance officer needs to produce in response to a subpoena, an NCUA examiner request, or a PCI forensic audit.

- **Why it works / why it fails:** The construction acknowledges NCUA §701.36 limits on member surveillance as a *feature* (§7). But it does not distinguish between *issuer* surveillance (which NCUA limits) and *regulator-accessible* audit trails (which NCUA mandates). Auth0's MCP auth routes every token through the AS, which creates a tamper-evident log that can be produced to regulators without revealing member behavioral patterns to other merchants. Bolyra's architecture, by design, produces no such log anywhere — the AS sees only enrollment; RSes see pseudonymous nullifiers. There is no mechanism for a CU to produce "Alice's agent accessed Amazon on March 3rd" to an NCUA examiner without Alice's cooperation in revealing her `scopeBlinder`. That is not a compliance-ready audit trail.

- **In-threat-model?** No. Section §3 defines the adversary as an entity trying to *link* authorizations. The compliance adversary is an entity trying to *produce* attributable records on demand. These are opposite requirements. The construction must define an audit-credential mechanism — or explicitly scope out regulated industries, which eliminates the primary deployment scenario in §7.

---

### Attack 3: Scope Blinder Loss Creates Irrecoverable State Divergence

- **Attack:** Section §2 requires the agent to store one `scopeBlinder` per `(credential, scopeId)` pair "in agent's local secure enclave." The `scopeNullifier` is deterministic on this blinder. If the agent loses the blinder — device wipe, migration, key rotation after compromise — it generates a new `scopeBlinder` for the same `scopeId`. The new proof produces a *different* `scopeNullifier`. The RS's double-spend set has the old nullifier. The agent effectively forks its identity at that RS: old sessions are orphaned and the new nullifier is treated as a fresh agent. There is no recovery protocol specified.

- **Why it works / why it fails:** The construction uses the `scopeNullifier` for Sybil detection within a scope (§2 Key design decisions: "Same agent + same scope → same `scopeNullifier`"). This invariant breaks on blinder loss. Worse: if a credential is compromised and the operator re-enrolls the agent with a new `credentialCommitment`, *all* existing `scopeNullifier` values at all RSes become unreachable — there is no revocation signal the RS can act on, because the RS only knows the nullifier, not the credential. The construction's §2 delegation extension does not address this case either. Auth0's server-side token store handles key rotation, session migration, and revocation atomically with a single API call.

- **In-threat-model?** No. The construction treats the scope blinder as a solved storage problem ("stored locally"). It does not specify: (a) what format the blinder store takes, (b) backup/recovery semantics, (c) what happens when a compromised credential is rotated, or (d) how RSes handle nullifier orphaning. These are not cryptographic questions — they are deployment questions that will surface in the first enterprise pilot.

---

### Attack 4: The "No AS in the Loop" Architectural Claim Eliminates Policy Enforcement

- **Attack:** Section §2 ("No AS in the loop") frames AS bypass as a privacy feature. My sales team frames it as "no centralized policy enforcement point." Auth0 MCP auth, WorkOS, and Cloudflare Access all enforce policy at the AS: real-time scope downgrade, session kill, IP-based anomaly detection, step-up authentication triggers, usage-based rate limiting, and abuse circuit-breakers. All of these fire at token issuance time — before the RS sees any request. Bolyra's architecture has no equivalent: the credential is enrolled on-chain at issuance (§7 step 1), and all subsequent policy is baked into the `permissionBitmask` at that moment. An operator cannot say "revoke FINANCIAL_SMALL for Alice's agent effective now" without on-chain credential revocation — which is a transaction, not a millisecond policy push.

- **Why it works / why it fails:** The construction's root history buffer (§5: "30-entry circular buffer per tree") handles Merkle root staleness but does not provide sub-second credential revocation. In Auth0, I can kill a session in <1s via the Management API. In Bolyra, revocation requires: (1) on-chain Merkle tree update removing the credential leaf, (2) waiting for block finalization on Base Sepolia (~2s), (3) RS cache invalidation of the previous root. In a fraud scenario — agent credential stolen, operator needs to kill it *now* — the Bolyra path is 5-30 seconds of exposure depending on block time and RS caching. The construction does not specify a revocation latency SLA anywhere in §7.

- **In-threat-model?** No. The IND-UNL-AS game (§3) models an adversary trying to *correlate* authorizations. It does not model an adversary exploiting the *absence* of a real-time policy enforcement point. The construction's response to "how do I kill a compromised agent credential in under one second?" is architecturally unanswered, and this question will appear in every enterprise security review.


## Persona: cryptographer

---

### Attack 1: IND-UNL-AS Game Proves the Wrong Property

**Attack:** The adversary does not play the IND-UNL-AS game as defined. Instead, it mounts a *graph-linking* attack: it observes a stream of presentations arriving at RS-A and RS-B (both colluding), and asks "do presentation π₁ at RS-A and presentation π₂ at RS-B originate from the same agent?" — without any prior knowledge of which agents are in the Merkle tree.

**Why the game doesn't cover it:** §3's IND-UNL-AS game is an *indistinguishability-of-senders* game: the adversary knows A₀ and A₁ (it enrolled them), is handed a proof from one, and must guess which. That is cross-agent indistinguishability, not cross-scope unlinkability. The actual merchant-graph threat in §7 is: given (π_amazon, π_pharmacy) arriving in the wild, can the adversary determine they share a single agent, *without knowing the candidate agents in advance*? This is an *anonymity set* property, closer to the Pfitzmann–Hansen notion of k-anonymity or the Camenisch–Lysyanskaya unlinkability definition. The PRF reduction in §4 shows public outputs at `scopeId*` look random, but it does not bound the adversary's advantage at linking two already-observed presentations. A traffic-volume adversary that sees 1 presentation at RS-A and 1 at RS-B at the same millisecond timestamp has a 1-in-|anonymity-set| correlation advantage that falls entirely outside the game.

**In-threat-model?** No. The game must be replaced with (or supplemented by) a *session-unlinkability* game: adversary sees two transcripts (scope_1, π₁) and (scope_2, π₂) and wins if it can guess b where transcript b came from the same agent with non-negligible advantage. The current reduction gives no handle on this.

---

### Attack 2: Merkle Root Epoch Fingerprinting (Timing Deanonymization via Public Output)

**Attack:** The adversary AS controls enrollment and therefore knows the exact sequence of Merkle root values and *which agents are in each root*. The `agentMerkleRoot` is a **public output** of every `ScopedPresentation` proof (§2, Public outputs table). A colluding (AS, RS) pair observes the `agentMerkleRoot` value in a presentation proof and maps it to the enrollment epoch.

Concretely: if the AS enrolled agents in batches of 10, and each batch produces a distinct root R_k, then any proof that carries root R_k was generated by one of those 10 agents — not from the full enrolled set. If one of the 10 agents in batch k is the only one with `permissionBitmask` satisfying the RS's `requiredScopeMask`, the anonymity set collapses to 1.

This is not a PRF attack, not a ZK failure. It is pure public-output metadata: the circuit *outputs* the root by design (so the RS can check it against on-chain history), and the AS *knows* which roots correspond to which enrollment cohorts.

**Why the construction doesn't address it:** §3 timing extension only covers proof-generation jitter (±500ms). §7 deployment scenario never discusses root-epoch correlation. The 30-entry root history buffer (§5 "root history buffer") makes it *worse*: it gives the adversary a coarse timestamp window of at most 30 root transitions within which the proof was generated.

**Mitigation needed:** Agents should use a historical root (not the latest one) chosen uniformly at random from the full history buffer, or all roots must have indistinguishable epoch membership — which requires uniform enrollment batch sizes or a decoupled accumulator.

**In-threat-model?** No. The game assumes adversary controls AS and ≤N-1 RSes; root-epoch fingerprinting requires only the AS's enrollment log plus one colluding RS. No PRF break needed.

---

### Attack 3: Universal SRS Subversion (pot16.ptau Toxic Waste Attack)

**Attack:** §2 and §8 claim "PLONK avoids per-circuit ceremony." This is correct for *Groth16 Phase 2* but it conflates two separate ceremonies. PLONK (specifically KZG-PLONK as used by snarkjs/rapidsnark) requires a **universal structured reference string** — the `pot16.ptau` file. If any single MPC participant in the Powers of Tau ceremony retained the toxic waste `τ`, they can compute `[τⁱ]_1` for any i, and then forge a PLONK proof π* for any statement — including a fake `ScopedPresentation` claiming any `agentMerkleRoot`, any `scopeNullifier`, any `permissionBitmask`.

The AS that controls the ceremony (or bribes one participant) can:
1. Pick any two enrolled agents' `credentialCommitment` values (known from on-chain).
2. Forge a valid PLONK proof with `scopeNullifier` matching either agent.
3. Submit to any RS. RS verifies against on-chain root — passes.

This completely undermines soundness, and without soundness, the zero-knowledge hybrid argument in §4 is vacuous: H₂ relies on the ZK simulator, but a soundness break means the adversary can produce valid proofs without a witness, so the ZK property is irrelevant.

**The construction's §4 reduction assumes G16-ZK/PLONK-ZK as named assumptions, but never names the SRS trust model.** Section 3 explicitly states "adversary does NOT control the on-chain smart contract logic (public, deterministic)" but says nothing about control of the SRS ceremony.

**In-threat-model?** No. The construction must add a named assumption: "The pot16.ptau MPC ceremony is honest" (or more precisely: "At least one participant destroyed their randomness"). Without this, the adversary game is undefined against a ceremony-compromised SRS. This is especially relevant for the credit union deployment in §7 — NCUA-regulated entities cannot rely on an anonymous ceremony.

---

### Attack 4: scopeId Namespace Collision Breaks Cross-RS Unlinkability

**Attack:** `scopeNullifier = Poseidon2(scopeId, innerHash)` is deterministic per (agent, scopeId). The cross-scope unlinkability argument rests entirely on different RSes using *different* scopeIds. The construction defines scopeId as "RS-specific scope identifier (e.g., `Poseidon("CU-A-merchant-read")`)" (§2, Public inputs table) but **provides no mechanism for enforcing global uniqueness**.

Two colluding RSes — say RS-A and RS-B — can independently claim `scopeId = Poseidon("payments-v1")`. They then observe identical `scopeNullifier` values for the same agent. The construction's Sybil-detection property (same agent + same scope → same nullifier) is exactly what enables cross-RS linkability when two RSes share a scopeId. This requires zero cryptographic capability: no PRF break, no circuit vulnerability, just string coordination.

For the delegated case in `ScopedDelegation` (§2, "Modified circuit"), chain linking uses `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder)` — if the delegator presents to two RSes with the same scopeId, both see the identical `blindedScopeCommitment` as well.

**The reduction in §4 takes scopeId* as distinct from all Phase 1 scopes**, which is fine for the game. But in deployment, the construction provides no registry, certificate, or on-chain enforcement that prevents two RSes from choosing the same scopeId string. The §7 credit union scenario says `scopeId = Poseidon("CU-A-merchant-read")`, `Poseidon("pharmacy")`, etc. — these are informal suggestions with no collision prevention.

**In-threat-model?** No. If `scopeId` uniqueness is not enforced by the protocol (e.g., on-chain registry, DID-based RS identifier hashed into scopeId), then colluding RSes can trivially link agents across scopes by agreeing on a scopeId — reducing the anonymity set to zero at no cryptographic cost.


## Persona: cu_ciso

### Attack 1: The Unlinkability Feature Is the BSA/AML Violation

- **Attack:** The construction's concrete deployment scenario explicitly states: *"The CU does not know which RSes any agent contacted."* That sentence is your NCUA examiner writing a Matter Requiring Attention. Under 31 U.S.C. §5318(g) and NCUA's BSA/AML examination procedures (NCUA Letter 22-CU-05), the CU is affirmatively required to monitor member transaction patterns for suspicious activity and file SARs within 30 days of detection. The construction achieves cryptographic unlinkability for the CU — and then cites NCUA §701.36 as the justification. §701.36 governs member data sharing with third parties, not the CU's own internal monitoring. The CU is not a "third party" to itself. The construction has confused a privacy obligation to members with a prohibition on internal AML controls. A CU that genuinely cannot reconstruct "Agent X contacted RS-A, RS-B, and RS-C in a pattern consistent with structuring" is a CU that cannot file a SAR — and that is a criminal liability, not a feature.

- **Why it works / why it fails against the construction:** The construction does not address this at all. §8 "Why the baseline cannot match" treats AS-unlinkability as an unqualified good. It is not. The CU-as-issuer role is operationally dual: the CU must be blind to member merchant graphs for privacy but must also be able to reconstruct suspicious cross-RS patterns for AML. The construction collapses this distinction. No circuit constraint preserves selective disclosure for the issuer-as-regulator while denying it to the issuer-as-surveiller — those are the same entity.

- **In-threat-model?** No. The IND-UNL-AS game treats the AS as an undifferentiated adversary. It does not model the AS as a regulated institution with mandatory surveillance obligations. The construction must address how a CU operator maintains BSA/AML visibility over its own enrolled agents without breaking the unlinkability guarantee for cross-CU coalitions.

---

### Attack 2: Scope Blinder Key Custody — Operational Single Point of Failure

- **Attack:** The `scopeBlinder` is the only new cryptographic element (§5, final paragraph). It is generated locally, stored locally, never transmitted, never escrowed. The construction says "stored in agent's local secure enclave" and leaves it there. My attack prompt: *"Key custody: where does the member secret live? If it's a browser, you've lost me."* For the Navy Federal deployment scenario (§7, 13M members), each member agent holds up to N scope blinders — one per (credential, scopeId) pair — and these blinders are the unlinkability keys. There is no recovery path. If Alice's device is lost, stolen, wiped, or migrated, her scope blinders are gone. Every RS she had established a `scopeNullifier` relationship with now sees a new, unrelated nullifier — breaking continuity for double-spend detection at those RSes. Worse: the CU cannot reconstruct or re-derive these blinders because the CU was specifically excluded from knowing them. My Tier 1 ops team cannot help Alice recover her merchant session state at 2am. The NCUA examiner reviewing the CU's business continuity plan (Part 748, Appendix B) will ask: "what is your recovery procedure for this secret material?" The answer in this construction is: "there isn't one."

- **Why it works / why it fails against the construction:** The construction optimizes for zero AS knowledge, which makes the scope blinder irrecoverable by design. The security argument (§4) treats blinder secrecy as a feature (AS cannot compute `innerHash`). It is simultaneously an operational catastrophe for member-facing services at scale. GLBA Safeguards Rule (16 CFR §314.4(f)) requires a written incident response plan that includes "procedures to preserve and recover data." The scope blinder has no preservation path.

- **In-threat-model?** No. The threat model (§3) explicitly excludes "the agent's local state" from adversary control, treating this as a safe assumption. It is safe for the security game but catastrophic for production deployment. The construction must specify a key custody model — hardware security module, threshold secret sharing with CU participation, or device-bound TPM attestation — or acknowledge that at-scale member deployment is out of scope.

---

### Attack 3: Revocation Latency Window Creates Unauditable Authorization Surface

- **Attack:** The construction inherits Bolyra's 30-entry circular buffer per tree (§5, "Root history buffer"). A compromised agent can continue presenting valid `ScopedPresentation` proofs against any of those 30 historical Merkle roots for the duration it takes those roots to age out of the buffer. The construction provides no mechanism for the CU to determine which RSes were contacted during this window — by design, the CU cannot compute the `scopeNullifier` for any scope because it lacks the `scopeBlinder`. When Alice's agent is compromised and the CU revokes her credential by removing the leaf from the current tree, the attacker has a window of up to 30 state transitions to drain access across all in-scope RSes. My Tier 1 ops team is on the phone with Alice at 2am. What do they do? They cannot tell Amazon "this agent's authorizations from the last 48 hours are fraudulent" because they cannot identify which `scopeNullifier` values correspond to Alice's credential. GLBA Safeguards Rule §314.4(h) requires the CU to monitor and respond to "security events affecting customers." The construction makes the scope of those security events permanently opaque to the CU.

- **Why it works / why it fails against the construction:** The construction does not address revocation response procedures at all. It treats the Merkle root buffer as a liveness tool (§5 table, "Root history buffer: 30-entry circular buffer per tree") without analyzing it as a revocation latency surface. The FFIEC CAT (Domain 3, Cybersecurity Controls) requires documented incident response with defined recovery time objectives. The construction provides no mechanism for notifying affected RSes of a compromised nullifier set because the CU doesn't know the nullifier set.

- **In-threat-model?** No. The IND-UNL-AS game models a passive inference attack against unlinkability. It does not model the post-compromise incident response scenario where the CU needs to notify RSes and bound the blast radius. The construction must specify either: (a) a CU-accessible revocation mechanism that does not require knowing the scope blinders, or (b) an RS-side mechanism for the agent to publish a signed revocation across all its scope nullifiers, or (c) an explicit acknowledgment that revocation during a compromise produces an unauditable gap.

---

### Attack 4: On-Chain Registry Availability Is Not a Vendor Management Story

- **Attack:** Every RS verification step anchors on `agentMerkleRoot` against the on-chain state (§2, "No AS in the loop": "The RS verifies the PLONK/Groth16 proof directly against the on-chain `agentMerkleRoot`"). The construction names Base Sepolia as the deployment target (bolyra/CLAUDE.md). Base (an Ethereum L2) has experienced sequencer outages — most recently significant degradation events where transaction finality was unavailable for periods exceeding one hour. My core processor (FIS, Jack Henry) has a contractual 99.9% uptime SLA, which translates to ~8.7 hours of permitted downtime per year. If the on-chain root is stale, unavailable, or in reorg, the RS cannot verify any presentation proof — every agent authorization fails closed. The construction offers no fallback. FFIEC CAT Maturity Level 3 (Domain 2, Threat Intelligence) requires documented availability risk assessments for all critical systems. The construction has replaced a battle-tested OAuth AS (which I can run on-premises in my data center, replicated, with contractual SLA) with a public blockchain that I cannot contractually obligate, cannot run myself, and cannot certify to my examiner.

- **Why it works / why it fails against the construction:** The construction dismisses the baseline partially on availability grounds ("AS impotence") without addressing the baseline's operational advantage: the CU can run its own OAuth AS with defined RPO/RTO, vendor contracts, and disaster recovery. The on-chain Merkle root has none of these. §7 deployment scenario does not mention availability SLAs, fallback behavior during network degradation, or how the root history buffer interacts with L2 reorg scenarios (if a reorg removes the most recent root, which of the 30 buffered roots is canonical?).

- **In-threat-model?** No. The threat model (§3) models network-level observation of timing but not network-level unavailability of the verification anchor. The construction must specify: the target chain's uptime SLA, fallback behavior when the on-chain root is unavailable or under reorg, and how this maps to FFIEC CAT availability controls. Without this, the construction cannot satisfy a NCUA third-party vendor risk assessment for any production deployment.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.*

---

### Attack 1: Pre-Issued Scoped Token Battery Demolishes §8 Axis 1

- **Attack:** §8's first structural axis — "AS is in the issuance path — always. Every OAuth token passes through the AS at issuance" — conflates *issuance-time* with *presentation-time* AS visibility, then uses that conflation to argue OAuth is categorically inferior. But RFC 8693 Token Exchange combined with offline self-contained JWTs already separates these. A well-configured AS can issue a *battery* of scope-specific, RS-specific JWTs at enrollment time (one per anticipated RS), each containing an opaque subject, embedded permission claims, and an RS-locked audience (RFC 8707). The AS logs only "N tokens issued for credential C" — not "token T₇ was presented to RS-Amazon at 14:32." At verification time, the RS validates the JWT locally (HMAC or ECDSA, no introspection call). The AS never appears in the presentation path again. This is §8 axis 1 defeated without ZK.
- **Why it works / fails against the construction:** The construction never addresses pre-issued token batteries. §8's six axes assume the AS always sees `(agent_id, RS, scope, timestamp)` at presentation time — that assumption is false for pre-issued offline tokens. The axis 1 argument is load-bearing for the "Bolyra is categorically superior" claim; if RFC 8693 pre-issuance achieves presentation-path AS bypass, the gap narrows to what Bolyra provides *additionally* (ZK of which credential, ZK of permission values). The construction must bound what the AS learns *at issuance* under the token battery model, not just at presentation.
- **In-threat-model?** No — the IND-UNL-AS game does not model an AS that pre-issues per-RS tokens at enrollment time. The game assumes the AS observes scope parameters on-demand. **Construction must address this.**

---

### Attack 2: Timing Traffic Graph Is Not Covered by the Formal Game, Yet the Claim Invokes It

- **Attack:** The stated claim is "cryptographically unlinkable authorizations even under adversarial AS that *tries to correlate per-agent traffic graphs*." Traffic graphs are inherently timing graphs. The IND-UNL-AS game in §3 is explicitly non-temporal: it samples a single challenge proof and makes no binding statement about inter-presentation timing. The threat model grants the adversary "network-level observation of proof submission timing to the non-colluding RS." In Phase 1 of the game, the adversary — controlling the AS and N-1 RSes — requests proofs from A₀ and A₁ and observes proof-generation latency (the adversary controls the RS that issues `presentationNonce`, so it timestamps both request and response). This creates per-agent timing fingerprints. In the Challenge phase, the adversary watches network-level arrival time at the honest RS and matches against Phase 1 fingerprints. The construction's countermeasure — "random delay before submitting any proof to an RS" — is an application-layer SHOULD, not a circuit constraint, and specifies no required distribution or minimum jitter window.
- **Why it works / fails against the construction:** The cryptographic reduction in §4 is sound *within its game*. But the game is weaker than the claim. The reduction proves Adv_IND-UNL-AS(A) ≤ negl(λ) only for a PPT adversary constrained to the game's oracle model, which excludes timing. The real adversary is not so constrained. DPoP + RFC 9449 makes no stronger formal timing claim — but it also does not assert unlinkability against "adversarial AS correlating traffic graphs." Bolyra's abstract does. This is a truthfulness gap between the informal claim and the formal game.
- **In-threat-model?** Partially — timing is acknowledged in §3 "Timing side-channel extension" but the extension is informal and the jitter distribution is unspecified. The game extension does not integrate with the main IND-UNL-AS advantage bound. **Construction must either tighten the game to exclude timing from the claim, or specify and prove a concrete jitter-based timing-unlinkability bound.**

---

### Attack 3: scopeBlinder Security Rests on an Unspecified Local-State Threat Model

- **Attack:** The entire cross-scope unlinkability property reduces to the secrecy of `scopeBlinder`. The construction places the blinder in the "agent's local secure enclave" (§7, step 2). The adversary in §3 explicitly controls the AS, which in a realistic deployment means the AS operator controls the cloud infrastructure where the agent process runs. RFC 7662 introspection requires no per-agent secret stored on operator infrastructure — the token is self-describing and opaque to the operator. Here, the AS-as-operator can read process memory, container filesystems, or key management APIs (AWS KMS, HSM) where the scopeBlinder is stored. If the AS recovers `scopeBlinder` for any agent, it can compute `innerHash = Poseidon2(credentialCommitment, scopeBlinder)` (it already knows `credentialCommitment` — it enrolled the credential on-chain) and thereafter predict `scopeNullifier` for *all* scopes for that agent. Unlinkability collapses entirely — not partially, but for all N scopes simultaneously.
- **Why it works / fails against the construction:** The circuit correctly keeps `scopeBlinder` private. But "private circuit input" ≠ "secret from the operator." The IND-UNL-AS game specifies "The adversary does NOT control the agent's local state (secret key, scope blinders)" — this exclusion is the entire basis for AS impotence in §4's reduction. In a cloud-hosted agent, this exclusion assumption is false by default. The construction needs a hardware isolation model (e.g., TEE with remote attestation, or the agent runs on user hardware). This is a deployment constraint, not a protocol guarantee, and it is not stated as a system requirement anywhere in §§1–7.
- **In-threat-model?** No — the game's exclusion of "agent's local state" from the adversary's control is an assumption that is not justified for the stated deployment scenario (CU-operated AI agents, §7). **Construction must either restrict the adversary model to user-device agents or specify a TEE/HSM requirement as a formal system precondition.**

---

### Attack 4: Poseidon-PRF Is a Non-Standard Assumption Weaker Than HMAC-SHA256 — The Reduction Understates Cryptographic Risk

- **Attack:** The security reduction in §4 bottoms out at "P-PRF: Poseidon2 is computationally indistinguishable from a random function when keyed on a secret input." This is a non-standard assumption. Poseidon was designed as an algebraic hash for ZK arithmetic circuits (BN254/BLS12-381 fields), not as a keyed PRF. The PRF security of Poseidon-sponge constructions in non-algebraic settings is studied but not standardized — there is no NIST evaluation, no RFC, and fewer than 6 years of public cryptanalysis relative to HMAC-SHA256's 30+ years. The RFC 7662 baseline's MAC-based token binding uses HMAC-SHA256, which reduces to a PRF assumption with a standardized, heavily analyzed primitive. §8 axis 6 claims the construction "reduces AS-unlinkability to the Poseidon PRF assumption and Groth16/PLONK zero-knowledge — both well-studied in the ZK literature." This is accurate but omits that "well-studied in ZK literature" ≠ "well-studied as a PRF." The ZK literature studies Poseidon's *collision resistance* and *preimage resistance*, not its PRF security in the key-recovery sense used here.
- **Why it works / fails against the construction:** This does not break the construction — it weakens the comparative security argument in §8. If the P-PRF assumption is weaker than claimed, the "negligible advantage" bound in Theorem 1 rests on a shakier foundation than HMAC-based token binding. More concretely: if an adversary finds a distinguisher against Poseidon2 as a PRF (not a collision — a *distinguisher from random*), it directly breaks the `scopeNullifier` derivation chain, since `scopeNullifier = Poseidon2(scopeId, Poseidon2(credentialCommitment, scopeBlinder))`. The RFC 7662 advocate can use this to argue that the baseline's security assumptions are strictly stronger, not weaker.
- **In-threat-model?** Yes, in the sense that the construction survives if P-PRF holds — but the reduction's security claim is overstated relative to the assumption's maturity. **Construction should cite concrete Poseidon PRF analyses (e.g., Grassi et al. 2021 security analysis, BN254-field sponge PRF bounds) and quantify the assumption's strength against known algebraic attacks, rather than asserting it parenthetically as "well-studied."**


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE production operator, WIMSE co-author. Thesis: workload identity is solved at the right layer. This construction is solving it at the wrong one.*

---

### Attack 1: Enrollment timing oracle collapses the anonymity set — the IND-UNL-AS game is incomplete

**Attack:** The IND-UNL-AS game (§3) stipulates that the Challenger "enrolls two agents A₀, A₁" without specifying that enrollment is simultaneous or epoch-batched. In production, the AS issues and enrolls credentials over time, and each enrollment transaction is timestamped on-chain. The on-chain Merkle leaf insertion is a public event with a block timestamp. A colluding AS + RS now has two clocks:

- **AS clock:** "I enrolled credential C at block B, timestamp T₀."
- **RS clock:** "I received a `ScopedPresentation` proof at wall time T₁."

When the agent presents to the RS immediately or within a narrow temporal window after enrollment (common for fresh credential issuance), the AS+RS coalition can compute Δ = T₁ − T₀ and cross-match across its enrollment log. For a CU that enrolls 10 agents per day, a 1-hour temporal window collapses the anonymity set from all enrolled agents to ~1. The `scopeNullifier` is never inspected — timing alone suffices.

**Why it works / why it fails:** The game is immune because it enrolls both A₀ and A₁ in the same setup phase, eliminating any timing differential. Real deployments do not have this property. The construction delegates timing countermeasures to §3's "application-layer requirement" of ≤500ms jitter — but jitter over the enrollment-to-presentation delta (which can be hours or days for fresh credentials) is not addressed, and cannot be — it is not a circuit constraint.

**In-threat-model?** No. The game is correct for proofs already in the system; it does not model enrollment-epoch correlation. The construction must either (a) mandate epoch-batched enrollment (all credentials issued in a batch at fixed intervals, erasing individual enrollment timestamps) or (b) extend the game to include an enrollment-time oracle. The §7 credit union scenario — where a CU issues credentials to specific member agents — is particularly exposed because the AS has a 1:1 mapping of member to enrollment time.

---

### Attack 2: WIMSE WIT + SPIRE local issuance already provides "no AS in the presentation path" — the residual delta is a governance choice, not a cryptographic gap

**Attack:** The construction's centerpiece claim is §2: "No AS in the loop — the RS verifies the PLONK/Groth16 proof directly against the on-chain `agentMerkleRoot`. The AS is not contacted at verification time." The comparative section §8 argues this is structurally impossible in OAuth because "every OAuth token passes through the AS at issuance."

This is not accurate for SPIFFE + WIMSE. The SPIRE agent runs inside the workload's trust domain and issues X.509 SVIDs and JWT SVIDs locally via the Workload API — without any network round-trip to the SPIRE server at presentation time. Specifically:

- **JWT SVID with `aud` claim:** The SPIRE agent issues RS-specific JWT SVIDs where `aud = [RS-URI]`. The SPIRE server is not contacted per-presentation; the SPIRE agent holds a short-lived X.509 SVID and signs JWT SVIDs locally. The AS (SPIRE server) never sees individual RS authorizations.
- **WIMSE WIT (draft-ietf-wimse-arch §5):** The Workload Identity Token includes a `wth` (workload-to-workload context hash) binding, providing proof-of-possession equivalent to Bolyra's `presentationBinding`. The WIT is generated locally by the SPIRE agent.
- **Pairwise pseudonymous identifiers:** SPIFFE IDs are scoped to trust domains and paths. An operator can provision path-scoped SPIFFE IDs per RS relationship: `spiffe://cu-a.trust/agent/alice/rs-amazon` vs `spiffe://cu-a.trust/agent/alice/rs-pharmacy`. The SPIRE server assigns these without the RS knowing the mapping.

The genuine residual delta is: "the SPIRE server operator (= AS) knows which RS-scoped SVIDs it issued." The construction's §2 "AS impotence" argument only holds because the AS does not know the `scopeBlinder`. But in SPIFFE, the SPIRE server operator is definitionally a trusted party in the trust domain — if you do not trust your own SPIRE server, your governance model is broken, not your cryptography. Re-framing this as a cryptographic property solved by a new ZK circuit re-solves a problem that should be solved by trust boundary design.

**Why it works / why it fails:** This is not an attack on correctness — the construction is cryptographically sound conditional on the AS being adversarial. The attack is that the adversarial-AS assumption is an architectural boundary violation in any real-world deployment. The §7 CU scenario explicitly positions the CU as both issuer and AS — if the CU is adversarial to its own members, this is a regulatory/governance failure (NCUA §701.36 already constrains it), not a cryptographic one.

**In-threat-model?** The adversarial AS is in-scope by the game definition. The construction survives on its own terms. But the WIMSE alternative must be explicitly compared: the claim in §8.1 ("The AS is in the issuance path — always") is false for WIMSE local issuance + SPIRE Workload API. The differentiation argument requires acknowledgment that WIMSE + local SVID issuance eliminates most of §8's six failure modes without ZK proofs — and that the *remaining* gap (AS knows which RS-scoped SVIDs exist, not which were presented) is narrower than claimed.

---

### Attack 3: Per-issuer `agentMerkleRoot` leaks trust domain membership, collapsing the anonymity set claim

**Attack:** The construction's §1 claims: "no coalition of the Authorization Server and any strict subset of RSes can determine whether two authorizations originated from the same agent." The `agentMerkleRoot` is a **public output** of every `ScopedPresentation` proof (§2, public outputs table). In any realistic deployment, each credential issuer (each credit union, each hospital system) maintains its own agent Merkle tree with its own root.

Therefore:
1. The RS observes `agentMerkleRoot = R_CU-A` from a proof.
2. The RS knows (from on-chain state) that root `R_CU-A` corresponds to the Merkle tree maintained by CU-A.
3. The RS now knows: "this agent is a CU-A member." The anonymity set is bounded by the number of agents enrolled under `R_CU-A`, not the global population.

For the §7 cross-merchant scenario: Amazon's RS sees `agentMerkleRoot = R_NavyFederal`. Amazon knows this is a Navy Federal member. If Navy Federal has 13M members but only 50K have enrolled agents, the anonymity set is 50K — not the global agent population. If the CU+Amazon are colluding, they narrow further: the CU knows it enrolled 50K agents; Amazon knows 15K of them transacted in a given month. The intersection is 15K, not negl(λ).

The §4 security argument never bounds the anonymity set — it only argues that within the anonymity set, the adversary cannot distinguish A₀ from A₁. But it says nothing about the size of that set or what `agentMerkleRoot` reveals about it.

**Why it works / why it fails:** The IND-UNL-AS game (§3) neutralizes this by construction: both A₀ and A₁ are enrolled in the same Merkle tree, so `agentMerkleRoot` is identical for both and carries no distinguishing information. But in production, if each issuer has a distinct tree, `agentMerkleRoot` is a fingerprint for the issuer. The SPIFFE analogy: `agentMerkleRoot` plays the role of a SPIFFE trust domain — it identifies the issuing organization, not the individual, but the issuing organization is already identifying information in small-membership or high-correlation scenarios.

**In-threat-model?** No. The construction must state explicitly whether cross-issuer mixing (all issuers share one Merkle tree) is required for the anonymity claim, or whether per-issuer trees are acceptable with a bounded anonymity set caveat. The §7 scenario implicitly assumes a per-CU tree (the CU is the tree operator), which makes the anonymity claim hold only within that CU's enrolled population — a much weaker statement than §1 implies.

---

### Attack 4: `scopeBlinder` secrecy assumption breaks for cloud-native agent deployments — the threat model excludes the most common production topology

**Attack:** The adversary model (§3) states: "The adversary does NOT control: the agent's local state (secret key, scope blinders)." The `scopeBlinder` is "stored in agent's local secure enclave" (§7). This assumption is violated in every common cloud-native workload deployment:

- **AWS Lambda / Google Cloud Run / Azure Functions:** The function runtime is managed by the cloud provider. The operator (= AS in the §7 CU scenario) who deploys the Lambda has access to its environment variables, `/tmp` storage, and memory via CloudWatch, cloud debuggers, and snapshot-based debugging. "Local secure enclave" does not exist in serverless.
- **Kubernetes pods:** The operator controls the pod spec, can exec into containers, can mount the pod's filesystem, and can capture core dumps. If the AS operator also runs the cluster, they can exfiltrate `scopeBlinder` values.
- **Operator = AS:** In the §7 scenario, the CU operates both the credential issuer (AS) and the infrastructure on which member agents run (if the CU provides an agent platform). The CU can read the `scopeBlinder` from its own agent runtime, compute `innerHash`, and reconstruct `scopeNullifier` for any scope — breaking unlinkability entirely.

SPIFFE's answer to this is node attestation: the SPIRE agent attests at the kernel/hypervisor level (TPM-based, AWS IID, GCP PIK) and the SVID is bound to the workload process identity. The trust hierarchy is explicit: trust the SPIRE server, or don't use SPIFFE. The security boundary is stated, not assumed away. Bolyra's "local secure enclave" assumption is a load-bearing security claim with no mechanism — it works for on-device agents (mobile, browser extension) and fails for the majority of enterprise AI agent deployments which are cloud-hosted.

**Why it works / why it fails:** The construction survives if the agent runs on hardware the AS does not control (user's device with a TPM-backed secure enclave, browser with SubtleCrypto non-extractable keys). It breaks silently — with no circuit-level enforcement — for cloud agents. The IND-UNL-AS game formalizes this as "adversary does not control agent local state," which is a correct exclusion for the formal proof but papers over the gap between the game and the §7 deployment scenario.

**In-threat-model?** No. The construction must either (a) restrict the deployment scope to on-device agents with hardware-backed key storage (and explicitly exclude cloud agents from the unlinkability guarantee), or (b) propose a mechanism for `scopeBlinder` generation and storage that holds under operator-level adversaries — e.g., a TEE-based agent runtime with remote attestation, or deriving `scopeBlinder` from a hardware-backed root key using a VRF so even the AS cannot extract it. The §7 credit union scenario, where CU infrastructure runs the member's agent, is precisely the case where this assumption fails.
