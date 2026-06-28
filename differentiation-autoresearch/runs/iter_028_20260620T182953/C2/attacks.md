# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The Latency Cliff — 3 seconds vs. 100 milliseconds is not a tradeoff, it's a product kill

- **Attack:** Your construction targets < 3s for PLONK proving on "commodity hardware." WorkOS, Auth0, and Stytch issue tokens in < 100ms via a REST call. An LLM agent making 20 tool calls per session — each requiring a fresh authorization — burns **60 seconds** in proving time alone. Real agentic workloads (LangChain pipelines, AutoGPT loops, MCP tool chains) make authorizations in a hot path. At 3s per call, the agent's wall-clock latency budget is gone before any business logic runs. Section 2.6 describes the "AS-free" verification flow as a feature, but operators will read "AS-free" as "no shared infrastructure = no latency optimization = no caching = I pay 3s per call forever."

- **Why it works / why it fails:** The construction offers no answer to this. Section 6 cites "< 3s" as a target, not a guarantee, and qualifies it as "commodity hardware" without specifying what that means in a Lambda or Kubernetes pod. PLONK's universal setup eliminates per-circuit ceremony cost, but it does not eliminate proving time. Section 8's comparison table celebrates AS removal but does not price the compute swap: instead of a 100ms network call to WorkOS, the operator pays 3s of CPU per authorization. The construction does not address caching (reusing proofs), batching (proving multiple scopes together), or offloading (delegating proving to a server-side TEE, which re-introduces the AS-like trust problem it was designed to eliminate).

- **In-threat-model?** No. The threat model (§3) models a cryptographic adversary, not a latency-sensitive operator. The construction must address: (a) what is the actual proving time on AWS Lambda arm64 at the constraint count in §6, (b) whether proof reuse across epochs is permitted without breaking unlinkability, and (c) what the UX degradation curve looks like for agentic chains with 10+ sequential tool calls.

---

### Attack 2: The `scopeBlindingSecret` Derivation Example Breaks the Core Claim Against an Adversarial Operator-AS

- **Attack:** Section 2.4 gives the concrete derivation: `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`. Section 3.1 explicitly permits the threat model case where "The AS may be the same entity as the credential issuer (operator)." These two statements together break the IND-UNL-AS game entirely. If the adversarial AS *is* the operator, it holds `operatorPrivKey`. It computes `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`. It then computes `Poseidon2(scopeId_X, scopeBlindingSecret)` for every scope X it suspects the agent might visit. It matches the outputs against observed `scopedNullifier` values received by colluding RSes. The adversary wins with advantage **1** — not negl(λ) — using only arithmetic, no cryptographic break required.

- **Why it works:** The construction's reduction in §4.2 models `scopeBlindingSecret` as an unknown key held only by the agent. The reduction is tight under that assumption. But §2.4's concrete derivation *gives the key to the operator*, who the threat model (§3.1) explicitly identifies as a potential adversary. The IND-UNL-AS game (§3.2) does not model the case where the PRF key is known to the adversary because the adversary derived the agent's credential. The game should exclude operator-controlled derivation of `scopeBlindingSecret`, but the spec does not require this — it offers `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` as a suggested implementation.

- **In-threat-model?** No. This is a direct contradiction between §2.4 and §3.1 that breaks the IND-UNL-AS reduction. The construction must either: (a) require that `scopeBlindingSecret` be generated entirely within the agent's local execution environment with no operator-visible derivation path, and enforce this as a hard protocol invariant, or (b) redefine the adversary to exclude operator-AS collusion — which guts the most commercially relevant threat scenario (the credit union as-AS case described in §7).

---

### Attack 3: The Anonymity Set Is the Tree — and You're the Only Leaf

- **Attack:** `agentMerkleRoot` is shared by all enrolled agents (§2.2, public output). The construction claims this means it "is shared by all agents, not identifying." But the on-chain Merkle tree is public. An RS that receives a `ScopedAgentAuth` proof can observe: (1) the current `agentMerkleRoot` value, (2) the set of leaf-insertion events on-chain up to that root, and (3) the block timestamp of the most recent insertion. If the Bolyra agent Merkle tree has 50 enrolled agents at launch, the anonymity set is 50. If an RS also knows (from its own enrollment records or from the operator's metadata) that only one agent in the tree has `FINANCIAL_SMALL` permissions and was enrolled this week, it can narrow the set to 1 without touching the nullifier. The IND-UNL-AS game (§3.2) does not model auxiliary information about tree membership. The "agentMerkleRoot is not identifying" claim holds only when the tree is large and the adversary has no side information about which leaf belongs to which agent — conditions that do not hold at launch or in narrow enterprise deployments.

- **Why it works:** Auth0 has 18,000+ enterprise customers. Bolyra has zero production deployments. The root history buffer (§3.4, 30 entries) mitigates proof-generation latency but does nothing to increase the anonymity set size. Every credit union that deploys Bolyra first gets a tree with O(10²) agents. The unlinkability guarantee degrades proportionally to set size — this is the same k-anonymity collapse that breaks Tor in low-traffic conditions. The construction offers no k-anonymity lower bound, no minimum tree size requirement, and no mechanism for bootstrapping anonymity set size before the product has traction.

- **In-threat-model?** No. The threat model assumes only cryptographic adversaries, not traffic-analysis adversaries with auxiliary information. The construction must bound the anonymity set and specify a minimum deployment size below which the unlinkability claim does not hold.

---

### Attack 4: "No AS" Is a Liability to Enterprise Procurement, Not a Feature

- **Attack:** The construction's §8 calls AS removal a "category change in the trust model." Enterprise procurement at a credit union reads this as: no audit log, no centralized revocation, no SIEM integration, no compliance trail. WorkOS has SOC 2 Type II, a 99.99% SLA, a dedicated CSM, and a revocation API that fires in < 500ms. When a rogue agent credential must be revoked — because the operator's key was compromised, because the member terminated their account, because regulators require immediate access termination — the Bolyra answer is: update the on-chain Merkle tree and wait for the 30-entry root history buffer to expire. Until then, old proofs against stale roots remain valid. Section 3.4 explicitly notes the 30-entry buffer "tolerates proof generation latency" — it also tolerates a window where revoked agents continue to authorize. The NCUA examiner's question is not "how does your PRF work?" It is "how do I revoke an agent in under 60 seconds and prove to auditors that I did?"

- **Why it works:** The construction has no revocation mechanism beyond tree root rotation. The root history buffer creates a revocation lag whose duration depends on how quickly the tree root advances — a function of how many other agents are concurrently enrolling. In a low-traffic CU deployment with 50 agents, the root may not advance for hours, leaving a revoked credential valid against stale roots. The construction does not address emergency revocation, regulatory hold orders, or audit log requirements. These are not cryptographic gaps — they are procurement blockers that incumbents solved years ago. A solo founder with no SOC 2, no enterprise support tier, and a revocation mechanism dependent on on-chain tree churn is not a vendor a credit union's board will approve, regardless of the strength of the IND-UNL-AS reduction.

- **In-threat-model?** No. The threat model treats revocation as out of scope. The construction must specify a revocation SLA, the mechanism for emergency credential termination without waiting for root rotation, and the compliance audit trail available to regulated operators — or explicitly disclaim that the current construction is not suitable for regulated financial deployments, which directly contradicts the scenarios in §7.


## Persona: cryptographer

**Stance:** The construction is more carefully specified than most. The IND-UNL-AS game is a real attempt, the circuit separation between `ScopedAgentAuth` and `DelegationEntry` is architecturally motivated, and the PRF reduction sketch is structurally sound. But there are four concrete gaps that a reviewer at CRYPTO would reject as written.

---

### Attack 1: scopeBlindingSecret Derivation from operatorPrivKey Collapses PRF Assumption When AS = Operator

**Attack:** Section 2.4 specifies:

> `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`

Section 3.1 (adversary capabilities) states:

> "The AS may be the same entity as the credential issuer (operator)."

The adversary $\mathcal{A}$ controls the AS. The AS is the operator. The operator holds `operatorPrivKey`. Therefore $\mathcal{A}$ can compute:

```
scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")
scopedNullifier_X   = Poseidon2(scopeId_X, scopeBlindingSecret)  ∀ scopeId_X
```

Given any `scopeId` published by any RS, $\mathcal{A}$ precomputes the expected nullifier for every enrolled agent credential it issued. In the IND-UNL-AS game (§3.2 Step 3), the adversary receives the challenge public output vector and immediately computes `Poseidon2(S_a, scopeBlindingSecret)` vs `Poseidon2(S_b, scopeBlindingSecret)` — deterministic comparison, advantage 1.

**Why it works:** The reduction in §4.2 claims:

> $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\mathcal{B}} + \text{Adv}^{\text{KS}}_{\text{PLONK}}$

PRF security requires that the key (`scopeBlindingSecret`) is unknown to the distinguisher. When AS = operator, the key is directly derivable from material the adversary controls. The PRF bound is vacuous: $\text{Adv}^{\text{PRF}}_{\mathcal{B}} = 1$, so the overall bound provides no guarantee.

**In-threat-model?** **No — construction must address.** The threat model explicitly permits AS = operator in §3.1. The `scopeBlindingSecret` derivation path in §2.4 must be severed from `operatorPrivKey`. The blinding secret must be generated independently at the agent side (e.g., from agent-local randomness at enrollment time) and must never be derivable from any key held by the operator or AS. The current "e.g." note is the security-critical path, not an implementation detail.

---

### Attack 2: `blindingCommitment` Is a Dead Constraint — Double-Spend Detection Is Not Enforced Against Malicious Agents

**Attack:** Section 2.2, Constraint 9:

> `blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)` — intermediate constraint (not a public output)

The circuit computes `blindingCommitment` as an intermediate signal. It is never compared to any public value, never stored on-chain, and never transmitted. In a Circom circuit, an intermediate signal assignment (`x <== f(a,b)`) enforces that `x` is correctly computed from `a` and `b` — but if `x` is not checked against an external commitment or used in a subsequent equality constraint that bottoms out at a public output, the "binding" is inert. Any field element is a valid `scopeBlindingSecret` for any valid `credentialCommitment`.

Concrete malicious-agent attack: An agent with a valid credential (Merkle proof passes, EdDSA check passes) generates a fresh `scopeBlindingSecret' ← $\mathbb{F}_p$ for each request to the same RS. Each request produces a distinct `scopedNullifier' = Poseidon2(scopeId, scopeBlindingSecret')`. The RS's double-spend nullifier set never sees a collision. The agent authorizes unlimited times within the same scope, defeating the sole replay-prevention mechanism.

**Why it works / why it fails:** The construction in §2.6 Step 4 states the RS "checks `scopedNullifier` against its local double-spend set." This check is the only double-spend defense. Without an on-chain or publicly verifiable anchor tying `scopeBlindingSecret` to a specific credential at enrollment time, nothing prevents an agent from cycling through fresh blinding secrets. The PLONK knowledge soundness (A-KS) proves the prover knows *a* valid witness — not that the witness was generated with the enrolled blinding secret.

**In-threat-model?** **No — construction must address.** The fix requires publishing `blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)` as a public output at agent enrollment time (or as part of the Merkle leaf preimage), and adding it as a public input to `ScopedAgentAuth` so the circuit checks consistency. This does expose a per-agent persistent commitment but one that reveals no scope information.

---

### Attack 3: On-Chain `scopeCommitment` Is a Persistent Cross-Session Identifier — `DelegationEntry` Trivially Links Agent Appearances

**Attack:** Section 2.3 specifies:

> `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`

The `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiry)` is stable for a given agent credential. `permissionBitmask` is also stable. Therefore `scopeCommitment` is constant across all `DelegationEntry` proofs submitted by the same agent.

Section 2.3 further states the registry stores `lastScopeCommitment[sessionNonce] = scopeCommitment`. An on-chain adversary (capability explicitly granted in §3.1: "$\mathcal{A}$ reads all on-chain state") can enumerate all entries in the mapping and group them by `scopeCommitment` value. Every group is a single agent's delegation chain initiations across all sessions. This produces:

- A count of how many times the agent has initiated delegation chains
- The timestamps of each initiation (block timestamps)
- A stable pseudonymous agent identifier (`scopeCommitment`) linkable across all sessions

Section 3.3 defends this by claiming: "it reveals only that the agent is capable of delegating, not where it authorizes." This defense is correct for RS-linkage but misses session-linkage. An adversary watching the on-chain mapping over time learns the full temporal activity pattern of any delegating agent.

**Why it works:** The game definition (§3.2) gives $\mathcal{A}$ on-chain observation capability. The IND-UNL-AS game is scoped to RS-facing `ScopedAgentAuth` outputs — it does not model the `DelegationEntry` on-chain leakage. In §3.3's collusion resistance argument (§4.3), the construction correctly argues that on-chain `scopeCommitment` cannot be linked to `scopedNullifier` without breaking PRF. But it does not address the orthogonal leakage: on-chain linkage of the same agent's delegation chain initiations to each other.

**In-threat-model?** **No — construction must address.** The IND-UNL-AS game definition should be extended with a separate `IND-DEL-SESS` property covering the delegation path, or `DelegationEntry` should add an epoch-scoped commitment randomizer so repeated delegations by the same agent produce distinct on-chain entries. The current treatment of on-chain `scopeCommitment` as a non-issue (§3.4 final row) is incomplete.

---

### Attack 4: IND-UNL-AS Reduction Uses PLONK ZK Simulator Without Establishing Simulation Soundness — Adversary Can Detect Simulated Proofs in Query Phase

**Attack:** Section 4.2, Step 2 of the reduction:

> "Simulates a valid PLONK proof using the PLONK simulator (exists by zero-knowledge property)."

In the Fiat-Shamir instantiation of PLONK (the deployment model used here, §5 "PLONK with universal setup"), zero-knowledge is achieved by randomizing the proof transcript. In the ROM, $\mathcal{B}$ can program the random oracle to simulate. However, standard Fiat-Shamir PLONK is **not simulation-extractable**: given a simulated proof transcript, a computationally unbounded adversary (or a PRF-distinguisher that observes ROM queries) can potentially detect that the proof was simulated rather than generated from a real witness, because the ROM programming leaves a statistical footprint in the query pattern.

Concretely: $\mathcal{B}$ simulates query-phase proofs by programming the RO. $\mathcal{A}$ can observe all RO queries made during proof generation (both simulated and real). A non-black-box adversary that inspects RO query sequences can distinguish "RO programmed backward from challenge" (simulation) vs "RO queried forward from witness" (real proof). If $\mathcal{A}$ can distinguish, the query-phase simulation in the reduction is not perfect, introducing a gap between the simulated game and the real game that the reduction does not account for.

The bound in §4.2 states:

> $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\mathcal{B}} + \text{Adv}^{\text{KS}}_{\text{PLONK}}$

There is no simulation-soundness term. If simulation is distinguishable, $\mathcal{A}$ can use this to learn that challenge proofs are "real" while query-phase proofs were "simulated," which breaks the game structure and inflates $\mathcal{A}$'s advantage beyond what this bound captures.

**Why it partially fails against the construction:** For the IND-UNL-AS game specifically, $\mathcal{A}$'s goal is to distinguish *which scope* a proof was generated for, not to detect simulation vs reality. Even if $\mathcal{A}$ can tell query-phase proofs are simulated, this only matters if it changes $\mathcal{A}$'s view of the *scope content* — which it doesn't, because scope-identifying information flows only through the PRF oracle output (`scopedNullifier`). So the simulation-distinguishing capability doesn't directly lift to a scope-distinguishing capability.

However, the gap is still formal: the reduction proof as written does not establish that the simulation is indistinguishable, so the tightness claim ($+\text{negl}(\lambda)$) is unproven. The correct approach is to require simulation-extractable PLONK (e.g., via the Fischlin transform or a dedicated SE-PLONK instantiation) and cite the appropriate theorem, or to restructure the reduction to avoid simulation entirely by using the knowledge extractor and real witnesses.

**In-threat-model?** **Formally incomplete — construction should address.** The claim is not broken by this gap but the proof as written has a hole. The construction must either (a) specify that SE-PLONK is used and cite the security theorem, or (b) restructure §4.2 to use the knowledge extractor rather than the ZK simulator for query-phase proofs.


## Persona: cu_ciso

---

### Attack 1: NCUA Part 748 / GLBA Audit Trail Inversion

- **Attack:** The construction's core guarantee — that NFCU cannot reconstruct the merchant graph (§7, step 6: "NFCU sees only the initial enrollment event") — is precisely what NCUA Part 748 Appendix B and the GLBA Safeguards Rule (16 CFR §314.4(h)) require a covered institution to *preserve*. An NCUA examiner presenting Information Security Program questionnaire item "demonstrate access logging for member financial data" cannot be answered. The CU's incident-response playbook (Part 748 Appendix B, §III.C) requires the institution to "assess the scope of an incident" — which requires knowing which member accessed which resource server and when. The construction structurally prohibits this.

- **Why it works / why it fails:** The paper addresses cryptographic unlinkability but says nothing about the lawful-intercept carve-out or the institution's obligation under Part 748 to produce access logs on demand. Removing the AS from the hot path (§2.6) removes the only entity positioned to generate examiner-grade audit records. The threat model explicitly lists "NFCU's view: zero visibility into merchant contacts" as a *feature*. An NCUA examiner reads this as a missing control.

- **In-threat-model?** **No — construction must address.** The paper's scenario (§7) frames AS-blindness as a privacy win. It needs a parallel treatment: either a privacy-preserving audit log mechanism (e.g., encrypted per-session audit receipt sent only to the CU's SIEM, provably excluded from RS view), or an explicit statement that the construction is scoped to *agent-to-RS* authorization and the CU's audit layer lives outside this protocol. Neither exists in the current draft. Without it, the CU's examiner outcome is worse, not better.

---

### Attack 2: Blinding Secret Compromise Has No Examiner-Defensible Incident Response

- **Attack:** Section 2.4 states `scopeBlindingSecret` is "stored alongside the agent's credential material" and "never leaves the agent's local storage." When a member's device is stolen or malware extracts the blinding secret, the CU faces a Part 748 Appendix B breach notification obligation. The examiner will ask: "What did you revoke, when, and how did you confirm revocation was complete?" The answer under this construction is: revoke the credential commitment from the Merkle tree. But `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)` — the blinding secret is the rotating factor. If the attacker already holds the blinding secret, they can compute valid nullifiers for every scope the compromised agent ever used, and the CU cannot distinguish attacker-generated proofs from legitimate ones *after the fact*. There is no certificate revocation list analogue that lets a CU prove to an examiner "access after T was unauthorized."

- **Why it works / why it fails:** The construction addresses double-spend detection within a scope via nullifier checking (§2.5), but this requires the attacker to reuse the *same* nullifier. A sophisticated attacker with the blinding secret submits one proof per scope per epoch — never triggering a replay. The RS sees a valid, fresh proof. The CU has no audit trail (Attack 1) and no revocation mechanism for mid-session key compromise. The Merkle root exclusion (revoke the leaf) only prevents *new* credentials from being issued — it does not invalidate proofs already in flight or help reconstruct what the attacker accessed.

- **In-threat-model?** **No — construction must address.** The threat model (§3.1) explicitly states the adversary does NOT control "the agent's local execution environment." This assumption is operationally untenable for a CU: member devices are outside the CU's security perimeter. FFIEC CAT Domain 2 (Threat Intelligence) requires controls that assume endpoint compromise. The construction needs a blinding secret rotation protocol and a mechanism by which a CU can prove to an examiner the scope of a breach.

---

### Attack 3: On-Chain Registry Is an Unclassified Third-Party with No SLA the CU Can Vendor-Manage

- **Attack:** Section 2.6, step 4 requires the RS to verify the PLONK proof "against the on-chain `agentMerkleRoot` (via root history buffer lookup)." This means Base Sepolia (or whatever L2 hosts the registry contract) is in the critical path for every authorization. NCUA's Third-Party Risk Management guidance (Letter to Credit Unions 07-CU-13, superseded by 2023 interagency guidance) requires the CU to document the vendor's: (a) business continuity plan, (b) SLA with financial penalties, (c) right-to-audit clause, (d) data location and sovereignty. A public blockchain smart contract satisfies none of these. The 30-entry root history buffer (§2.5, §5 table entry) mitigates *latency* between proof generation and root update, but it does not mitigate a chain outage. If Base Sepolia has a 4-hour outage, every RS authorization fails — there is no fallback path in the construction.

- **Why it works / why it fails:** The construction presents the on-chain registry as a trust anchor (§2.6: "RS verifies proof against on-chain roots") without addressing what happens during chain unavailability. For a CU with a core processor SLA of 99.95% (~4.4 hours/year downtime), adding a public blockchain dependency with no contractual SLA makes the examiner's vendor risk worksheet impossible to complete. The construction says nothing about fallback modes, caching strategies, or what the RS does when the chain is unreachable.

- **In-threat-model?** **No — construction must address.** This is pure operational risk, not cryptographic risk, and the construction is silent on it. A minimum viable treatment: specify a caching policy for the root history buffer (the RS can serve authorizations from its last-known valid root for up to N minutes during chain unavailability), define an explicit degraded-mode policy, and note that the on-chain registry operator must be treated as a critical vendor under NCUA third-party risk guidance.

---

### Attack 4: BSA/AML Monitoring Is Structurally Blind

- **Attack:** The healthcare scenario (§7) and the CU scenario both celebrate that "Kaiser cannot determine whether the patient visited Quest, Cedars-Sinai, or both." For a credit union, this is a Bank Secrecy Act problem, not a privacy feature. The CU's BSA Officer is required to file Suspicious Activity Reports (SARs) when a member's agent exhibits anomalous patterns — e.g., authorizing `FINANCIAL_SMALL` at 47 merchants in 90 minutes, which is a structuring indicator. Under the construction, the CU sees: one enrollment event. The BSA Officer has zero signal. The FinCEN SAR obligation (31 U.S.C. §5318(g)) is not discharged by "we designed the system so we can't see it." Examiners specifically test whether the institution's AML program covers *all channels* through which member transactions occur, including agent-mediated ones (FFIEC BSA/AML Examination Manual, "New and Evolving Payment Methods" section).

- **Why it works / why it fails:** The construction's IND-UNL-AS game (§3.2) is a cryptographic soundness argument, not a regulatory compliance argument. The adversary in the game is a traffic-graph-building AS. The adversary not modeled is a FinCEN examiner asking "show me your AML monitoring coverage for agent-mediated transactions." The AS-free architecture removes the only feasible monitoring point. Individual RSes (Amazon, Costco) have no obligation to report to the CU's BSA Officer — they report to their own compliance programs. The CU is left holding AML liability with no monitoring capability.

- **In-threat-model?** **No — construction must address.** This is the hardest attack to mitigate within the construction's privacy guarantees, because meaningful AML monitoring and cryptographic unlinkability from the issuer are structurally in tension. The construction needs to either: (a) carve out a privacy-preserving AML disclosure mechanism (e.g., a threshold-revealed audit log that fires only on anomaly detection, using MPC or threshold decryption), or (b) explicitly disclaim CU deployments where the issuer has BSA obligations and limit the use case to non-bank operators. The current §7 scenario explicitly targets CUs, making this omission a gap the construction must confront.


## Persona: rfc7662_advocate

> OAuth Working Group veteran, ten years of production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 and its extensions.

---

### Attack 1: Operator-Derived Blinding Secret Hands Privacy Key to the Adversarial AS

**Attack:** §2.4 specifies `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`. The operator computes this value and hands it to the agent alongside the credential. §3.1 simultaneously declares that "The adversary controls: The Authorization Server (AS): Full control over token issuance logic… The AS may be the same entity as the credential issuer (operator)."

These two design decisions are mutually fatal. If the AS is the operator — the explicitly in-scope adversary — it knows `operatorPrivKey` for every credential it has issued. It can therefore derive `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")` for every enrolled agent, and precompute the full lookup table `scopedNullifier_i = Poseidon2(scopeId_i, scopeBlindingSecret)` for every known RS scope. When RS-A logs `scopedNullifier_A` and RS-B logs `scopedNullifier_C`, the AS immediately recovers which agents produced them. The IND-UNL-AS game (§3.2) is broken with advantage 1: the adversary doesn't need to guess which of two scopes was used — it can recompute the expected nullifier for both and compare.

The reduction in §4.2 claims that unlinkability reduces to Poseidon PRF security — but the reduction assumes `scopeBlindingSecret` is unknown to the adversary. That assumption is violated by the derivation protocol in §2.4. The privacy argument assumes a fresh, agent-controlled secret; the key management section hands that secret to the credential issuer who is also the declared adversary.

**Why it works / fails:** Works cleanly. The construction has a formal gap between its threat model (§3.1: AS may be operator) and its key derivation design (§2.4: blinding secret derived from operator key). The reduction in §4.2 is internally valid but rests on a premise — that `scopeBlindingSecret` is inaccessible to the adversary — that §2.4 contradicts.

**In-threat-model?** Yes. The adversarial AS is explicitly in-scope. **Construction must address this.** The fix is to require that `scopeBlindingSecret` be generated by the agent independently of the operator (e.g., sampled locally and never transmitted to the operator), and that the circuit's binding constraint (§2.2, constraint 9) be the *sole* link between the blinding secret and the credential. §2.4 must be rewritten to prohibit operator-derived blinding secrets.

---

### Attack 2: The IND-UNL-AS Game Models the Wrong Adversary Goal

**Attack:** The IND-UNL-AS game as stated in §3.2 asks: given the adversary's query-phase proofs for scopes $S_1, \ldots, S_{n-2}$, can it tell whether the challenge proof covers unused scope $S_a$ or unused scope $S_b$? This is a *scope-identification* game, not a *cross-session linkage* game.

The real-world attack from colluding RSes is different: RS-A and RS-B each hold one proof they received. They want to determine whether both proofs came from the same agent or from two different agents. The construction never defines a game for this scenario — it is strictly not captured by IND-UNL-AS.

To see why these are different: in the IND-UNL-AS query phase the adversary observes multiple proofs from ONE agent for ONE agent's query set. The challenge asks about unused scopes. But in the multi-agent collusion scenario the adversary observes proofs from an unknown number of agents across an unknown number of RS-scope interactions and wants to partition those proofs into per-agent equivalence classes. A proper game would place two agents $A_1, A_2$ into the system, issue proofs for each at overlapping RSes, and ask the adversary to determine which RS-A proof and which RS-B proof share an agent. The IND-UNL-AS game as stated would be trivially won by the construction even if it used a weak PRF, because the challenge phase provides two fresh scopes the adversary has never queried — it cannot use any cross-scope comparison strategy.

The claim in §8 that the game provides a "tight reduction" is technically accurate for the game-as-written, but the game-as-written does not model the most natural colluding-RS attack. JWT-introspection-response (draft-ietf-oauth-jwt-introspection-response) provides a formal privacy model from the AS-facing direction that is at least as well-specified; Bolyra should match or exceed that formalism, not define a custom game optimized for the construction's strengths.

**Why it works / fails:** Works as a critique of formal rigor. The construction survives an adversary playing the game-as-written, but the game-as-written does not prove the property the concrete scenario (§7) requires. An adversary in the NFCU scenario has proofs from RS-Amazon and RS-Costco and wants to link them. The IND-UNL-AS game never gives the adversary this structure.

**In-threat-model?** Yes. **Construction must address this** by replacing or supplementing IND-UNL-AS with a multi-agent, multi-RS unlinkability game, or explicitly arguing that IND-UNL-AS implies it. The reduction sketch in §4.2 needs to show that an adversary winning the correct game can be used to win IND-UNL-AS, not just the converse.

---

### Attack 3: RFC 9068 Structured Access Tokens + PPIDs Eliminate the AS from the RS Verification Hot Path

**Attack:** The construction's headline differentiator in §8 is "AS is never contacted after enrollment. Verification is RS-local against on-chain roots." The baseline comparison claims "AS must be contacted for every token issuance." But RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) and draft-ietf-oauth-jwt-introspection-response directly refute this characterization of the baseline.

Under RFC 9068, a structured access token is a self-contained signed JWT. The RS verifies the JWT signature against the AS's cached public key — no AS network call, no hot-path dependency. Combined with RFC 8707 resource indicators (audience-bound tokens) and OIDC pairwise pseudonymous identifiers, the RS verification path is: local JWT signature check + local PPID lookup. This is structurally equivalent to Bolyra's: local PLONK proof check + local Merkle root lookup against cached on-chain state. Neither requires a synchronous AS round-trip per request.

The AS is on the path only at token *issuance* — and §2.6 step 1 ("RS publishes its `scopeId` and `requiredScopeMask` on-chain") implies that Bolyra's equivalent of token issuance is enrollment, which is also an AS-touching event. The construction correctly identifies that the AS sees scope at issuance in the RFC 9068 baseline, but the claim "AS must be contacted for every token issuance" conflates issuance with per-request verification. For long-lived tokens (e.g., 24-hour DPoP-bound JWTs per RFC 9449), the AS hot-path absence is equivalent to Bolyra's for the entire token lifetime.

**Why it works / fails:** Partially works: the construction overstates the baseline's per-request AS dependency. Where the construction genuinely wins is the *issuance-time* privacy: even a single RFC 9068 token request tells the AS which scope the agent requested. Bolyra's enrollment reveals no per-RS scope information to the AS. But the "AS never on hot path" framing in §8 is imprecise and will be challenged by any production OAuth deployment using cached JWKs and long-lived tokens.

**In-threat-model?** No — the construction survives this attack at the issuance-time privacy level. **But §8's comparative table must be corrected** to distinguish per-request hot-path absence (achievable by RFC 9068 for the RS verification step) from issuance-time scope privacy (not achievable by any OAuth variant, which is where Bolyra's actual advantage lies).

---

### Attack 4: Stable `scopeCommitment` on the Public Chain Links Repeat Delegation Initiations

**Attack:** When an agent initiates a delegation chain, it submits a `DelegationEntry` proof on-chain (§2.3). The public outputs — including `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` — are stored in the on-chain registry and are visible to all chain observers (§3.1: "The adversary reads all on-chain state, including `scopeCommitment` values").

The `scopeCommitment` is derived exclusively from the agent's `permissionBitmask` and `credentialCommitment`. Both are stable for the life of the credential. If the same agent initiates a second delegation chain — for a different sub-agent, a later session, or a different set of delegates — it submits a second `DelegationEntry` proof. The second proof produces the same `scopeCommitment` (same credential, same bitmask). Any chain observer, including a colluding RS or the adversarial AS, can scan on-chain state and identify that two `DelegationEntry` events share the same `scopeCommitment`. This links the two delegation initiations, revealing that the same agent created multiple delegation chains.

§3.4 (on-chain side-channel mitigation) claims: "The adversary learns that an agent initiated a delegation chain, but not which RSes the agent subsequently contacts." This is true for RS-facing authorization. But it does not address what the adversary learns from multiple on-chain `DelegationEntry` proofs sharing a stable `scopeCommitment`: the adversary learns the complete timeline of when this agent initiated delegation chains, reconstructs the activity graph of the agent's delegation behavior, and can correlate delegation timing with RS-access timing from logs — even without the RS-facing proofs. In the healthcare scenario (§7), Kaiser learns not just that a delegation chain was seeded once, but every time the patient agent creates a new delegation arrangement — violating the referral-network opacity claim.

**Why it works / fails:** Works as a concrete attack on the delegation privacy claim in §7. The single-delegation case is safe. The multi-delegation case — which is the realistic operational scenario for any long-lived agent — leaks a stable cross-session fingerprint on the public chain. RFC 8693 token exchange, while AS-visible, at least does not publish delegation events to a global immutable ledger.

**In-threat-model?** Yes. **Construction must address this.** A mitigation would be to blind the on-chain `scopeCommitment` with a fresh per-session random scalar — producing a randomized commitment that is verifiably derived from the credential (satisfying the delegation chain constraint) but unlinkable across sessions. This requires adding a `delegationBlindingNonce` (analogous to `scopeBlindingSecret`) to the `DelegationEntry` circuit and updating the `ScopedDelegation` chain-linking constraint accordingly.


## Persona: spiffe_engineer

*Staff engineer running SPIFFE/SPIRE at Fortune 500 scale, co-author of WIMSE drafts. Core stance: you are reinventing at the wrong layer.*

---

### Attack 1: The SPIFFE PRF-SVID Extension — your construction is a SPIRE attestor plugin in disguise

**Attack:**

The `ScopedAgentAuth` circuit's core unlinkability gadget (§2.2, constraint 7) is:

```
scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)
```

This is structurally identical to a SPIRE JWT-SVID where the `sub` claim is derived per-audience using a PRF over a stable workload secret. SPIFFE already defines the audience (`aud`) field in JWT-SVIDs as RS-specific. If SPIRE's `NodeAttestor` plugin is extended to:

1. Accept a ZK proof that the workload knows `scopeBlindingSecret` without revealing it (a single range proof, no circuit needed)
2. Issue a JWT-SVID with `sub = PRF(scopeBlindingSecret, aud)` — deterministic per workload × audience, unlinkable across audiences

…you get the same IND-UNL-AS property claimed in §3.2, using an established standards-track identity fabric. The SPIFFE trust domain federates across CUs out of the box. The construction does not cite this and does not justify why a SPIRE attestor plugin was rejected.

**Why it works / why it fails against the construction:**

It works as an existence argument: the IND-UNL-AS game (§3.2) can be satisfied without a ZK circuit. The construction's response would be that SPIRE's SVID issuance still contacts the SPIRE server (i.e., a live AS), violating §2.6's "AS is never contacted after enrollment." But this is operationally manageable: SPIRE SVIDs are short-lived (1h TTL), and the SPIRE Workload API issues them locally from the SPIRE agent process — the agent process caches the SVID and the workload never calls out to the SPIRE server per-request. The "AS-free hot path" claim in §2.6 applies equally to SPIRE in steady state.

**In-threat-model?** No — construction must address why SPIRE's Workload API (local agent cache, no per-request AS contact) does not satisfy the "AS is never contacted" property claimed in §2.6. If the answer is "enrollment privacy" or "no SPIRE operator dependency," that argument must be made explicit. Currently §8's comparison table pretends the only baseline is OAuth, ignoring SPIFFE entirely.

---

### Attack 2: `scopeBlindingSecret` has no rotation — unlinkability has no forward secrecy

**Attack:**

§2.4 specifies:

```
scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")
```

This is a deterministic, long-lived derivation from the operator's private key. In SPIFFE/SPIRE terms, this is a master identity key from which all per-scope pseudonyms are derived — precisely the key management antipattern that SPIRE's short-lived SVID rotation is designed to avoid.

Concretely:

- If `operatorPrivKey` is compromised at time $T$, an adversary can retroactively recompute every `scopedNullifier` ever issued across every scope the agent ever visited: `Poseidon2(scopeId_X, Poseidon2(operatorPrivKey, "bolyra-scope-blind"))`. The IND-UNL-AS game is broken retroactively for all past authorizations.
- The construction provides no rotation mechanism. If the agent rotates its credential (new `operatorPrivKey` → new `credentialCommitment`), the old Merkle leaf must be revoked and all historical `scopedNullifier` values become unlinkable to the new credential — but the double-spend store at each RS still holds the old nullifiers. The RS cannot associate old and new nullifiers without the agent self-disclosing, which requires a protocol the construction does not define.
- §2.5's epoch binding (`epochBinding = Poseidon2(scopedNullifier, epochId)`) provides within-scope time bucketing but does not provide forward secrecy for the `scopeBlindingSecret` itself.

SPIFFE X.509-SVIDs rotate every hour and provide forward secrecy via ECDH key agreement on the mTLS channel. The unlinkability analog in SPIFFE (audience-derived pseudonyms) would rotate with the SVID.

**Why it works / why it fails against the construction:**

The construction's §3.4 side-channel table addresses timing, proof generation variance, and IP correlation — but does not mention key compromise. The IND-UNL-AS game (§3.2) explicitly assumes the adversary does NOT control the agent's local execution environment and that `scopeBlindingSecret` is not leaked. This assumption is an axiom, not a guarantee. A construction that derives an epoch-independent, rotation-free master secret from the operator key and then makes unlinkability hinge on that secret's confidentiality is operationally fragile. The claim of strength-9 in §1 is inconsistent with a missing key rotation lifecycle.

**In-threat-model?** No — the construction must define a `scopeBlindingSecret` rotation protocol that preserves double-spend detection continuity at existing RSes and does not require the agent to disclose its identity to migrate nullifier stores.

---

### Attack 3: On-chain `scopeCommitment` + known enrollment data = dictionary attack on credential commitment

**Attack:**

The adversary AS controls the following (§3.1):

- The credential issuance record: `(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` — the AS issued or at minimum observed the enrollment
- On-chain state: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` stored in `lastScopeCommitment[sessionNonce]` by `DelegationEntry` proofs (§2.3)

`credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`

All five inputs are known to the AS from the enrollment event. The AS can compute `credentialCommitment` directly and verify: does `Poseidon2(permissionBitmask, credentialCommitment)` match the on-chain `scopeCommitment`? This is not a brute-force attack — it is a one-shot verification using known plaintext.

The construction's §3.3 argues: "An adversary observing on-chain state learns the set of agents that have initiated delegation chains, but cannot link a `scopeCommitment` to any RS-facing `scopedNullifier` without recovering `scopeBlindingSecret`." This is true for the RS-facing nullifier linkage, but it misses a different question: **the AS already knows which agents have initiated delegation chains by identity**, because `credentialCommitment` is computable from enrollment data the AS holds. The unlinkability claim that "the on-chain `scopeCommitment` does not reveal which RSes the agent subsequently contacts" (§3.4) is correct but weaker than advertised — the AS can already confirm *that a specific named agent* initiated a delegation chain, collapsing the anonymity set to size 1 for any agent the AS enrolled.

**Why it works / why it fails against the construction:**

§4.3's collusion resistance argument (point 3) correctly notes that linking `scopeCommitment` to `scopedNullifier` requires breaking Poseidon PRF. But it does not address the AS's ability to deanonymize the `DelegationEntry` proof entirely using enrollment plaintext — without touching the PRF. The WIMSE architecture separates the issuer from the AS for precisely this reason: issuers know credential contents, but token endpoints perform policy enforcement without seeing credential internals. The construction conflates "AS" and "credential issuer" — in the cross-CU scenario (§7), NFCU as AS also issued the credential, so it has all five Poseidon5 inputs.

**In-threat-model?** No — §3.1 grants the adversary AS "full control over token issuance logic" which implies knowledge of enrollment inputs. The construction's §3.4 side-channel table and §4.3 collusion argument do not address this attack vector. The non-delegation flow is clean; the delegation flow has a deanonymization path the construction does not close.

---

### Attack 4: The IND-UNL-AS game excludes WIMSE's in-scope problem statement — this should be a contribution, not a fork

**Attack:**

The WIMSE architecture draft (`draft-ietf-wimse-arch`) defines workload-to-workload token exchange with audience binding as a first-class primitive. WIMSE's problem statement explicitly covers the scenario where a workload (agent) presents credentials to multiple resource servers without the token issuer reconstructing the full graph. The WIMSE working group has active discussions on unlinkability properties for workload token presentation.

The construction's §8 comparison table evaluates against "PPID + RFC 8707 + DPoP + BBS+" but omits WIMSE entirely. This is not a neutral omission — it is the directly relevant IETF work item. The claim "no RFC defines unlinkability against AS" is accurate today but WIMSE is explicitly chartered to address this gap.

The specific attack: the IND-UNL-AS game in §3.2 defines a property that is a strict subset of what WIMSE's `workload-proof-of-possession` binding is designed to provide. If the construction's authors contributed the Poseidon PRF nullifier approach as a WIMSE token binding extension — specifically as a `cnf` (confirmation) claim mechanism where the confirmation key is scope-derived — the same unlinkability guarantee would sit inside a standards-track specification with IETF review, rather than in a project-specific game definition with a non-peer-reviewed reduction sketch. The PLONK knowledge-soundness term in §4.2's bound (`Adv^KS_PLONK`) relies on the algebraic group model, which is a non-standard assumption not currently endorsed by any IETF security area review.

**Why it works / why it fails against the construction:**

The construction's genuine contribution — removing `scopeCommitment` from the RS-facing circuit and confining it to a separate on-chain-only `DelegationEntry` circuit — is architecturally novel and the reduction tightness argument in §4.2 is sound. But the construction presents this as a complete alternative protocol rather than a component that extends existing workload identity infrastructure. WIMSE's token exchange model could adopt the ZK nullifier as the `cnf` mechanism without rebuilding enrollment, federation, revocation, or trust-domain management. The construction inherits none of WIMSE/SPIFFE's operational machinery (HSM-backed issuance, node attestation, rotation, federation across trust domains) and does not explain how these are replaced.

**In-threat-model?** No — the construction is not required to be a WIMSE extension, but §1's claim of providing a "formal IND-UNL-AS game" as a differentiator is weakened if WIMSE closes the same gap on a standards track using standard assumptions. The construction should either (a) cite WIMSE and articulate why the ZK approach is necessary rather than complementary, or (b) position itself explicitly as a WIMSE credential binding mechanism. The current framing — "this is not an incremental improvement, it is a category change" (§8) — is overclaimed relative to what the formal security argument actually establishes.
