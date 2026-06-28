# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

### Attack 1: The Cross-Org Witness Assembly Gap

- **Attack:** Section 7 describes a 4-hop pipeline crossing NFCU → Chainalysis → Circle. The construction states "any participant (or a designated auditor relay) generates a `DelegationAuditRollup` PLONK proof with all four hops' scope/credential data as private witness." But `delegatorScope[i]`, `delegateeScope[i]`, `delegatorCredCommitment[i]` for every hop are *private* inputs that no single party legitimately holds. NFCU owns hops 0-1. Chainalysis owns hop 2. Circle owns hop 3. To assemble the full witness, someone must aggregate across three separate legal entities. If a trusted aggregator holds that data, the privacy claim collapses — the aggregator sees every intermediate scope and credential commitment. If you use MPC to distribute witness generation, that's a separate protocol not described in the construction, with its own security model, latency, and integration cost.
- **Why it works:** The construction is entirely silent on witness assembly across org boundaries. The threat model (§3) assumes the adversary "does not control the root delegator's secret key" but says nothing about witness custody or the aggregator role. The PLONK soundness argument in §4 holds only if the witness is honestly assembled — it says nothing about *who* assembles it or what they learn during assembly.
- **In-threat-model?** No. The construction must define a witness-assembly protocol (MPC, per-hop partial witnesses, or a designated relay with explicit trust assumptions) and prove that the aggregator learns nothing beyond what the public outputs already reveal. Until then, the cross-org privacy claim in §7 is unsubstantiated.

---

### Attack 2: The Regulator Actively Opposes This Privacy Guarantee

- **Attack:** The §7 scenario claims NFCU wants to hide its AML provider (Chainalysis) and settlement layer (Circle) from the NCUA examiner. But NCUA examination practice (NCUA Letter to Credit Unions 01-CU-20, and the updated Third-Party Vendor Risk guidance) *requires* credit unions to disclose their material technology vendors, including subcontractors, to examiners. The NCUA doesn't just want to know that "monotonic narrowing held" — it wants to know who Circle is, whether Circle has its own SOC 2, and what Circle's incident response plan looks like. Hiding Circle from the examiner doesn't satisfy NCUA examination requirements; it likely violates them. The privacy guarantee in this construction solves a problem the regulator explicitly prohibits you from solving.
- **Why it works:** The construction's §7 "why this matters beyond regulatory niches" pivot — healthcare, journalism — is real, but the flagship scenario (Navy Federal + NCUA) is structurally broken. An enterprise procurement team will ask their legal and compliance team, who will flag this immediately. The construction frames vendor-chain privacy as a feature; the regulator frames it as a red flag.
- **In-threat-model?** No. The construction must either replace §7's flagship scenario with one where the privacy guarantee is actually desired by the verifier (journalist/source is better), or add a mode where the auditor can optionally receive vendor chain disclosure without breaking the ZK construction for other participants.

---

### Attack 3: Per-Hop Proof Latency Is In the Critical Path, Not the Audit

- **Attack:** Section 7 states: "Three delegation hops execute, each producing a per-hop Delegation proof (already in Bolyra spec)." The rollup audit proof is post-pipeline and claimed at <5s — accepted as not blocking real-time flow. But those per-hop Delegation proofs *are* in the critical path of the tool call pipeline. The existing `Delegation` circuit (not the rollup) must complete before each hop's tool call can proceed. WorkOS MCP auth issues a scoped token in <100ms with a single HTTPS round-trip. If each Bolyra delegation hop requires a Groth16 or PLONK proof before the tool call executes, you have added 2-5 seconds of latency *per hop* to what is otherwise a real-time agent pipeline. An 8-hop pipeline becomes 16-40 seconds of proof overhead before a single tool call completes.
- **Why it works:** The construction benchmarks the *rollup* circuit at <5s (§6) but does not quote the per-hop Delegation circuit proving time. The bolyra CLAUDE.md notes "test:circuits:slow runs full Groth16/PLONK proving ~2min" — even if per-hop proofs are faster than the full test suite, any sub-second latency claim for per-hop proofs needs to be substantiated. The rollup offloads audit latency off the critical path, but per-hop proving latency is not addressed.
- **In-threat-model?** Partially. The construction claims the rollup is post-pipeline (correct), but it implicitly depends on per-hop Delegation proofs that are generated inline. The construction must either (a) quote per-hop proving times, (b) describe a deferred-proof mode where tool calls proceed optimistically and the chain is retroactively proven, or (c) acknowledge the latency tradeoff explicitly instead of presenting <5s as the headline number.

---

### Attack 4: Trusted Setup Provenance and Enterprise Risk

- **Attack:** The construction uses PLONK with a "universal setup" (§5: `pot16.ptau`). But `pot16.ptau` is the Bolyra project-specific Powers of Tau, generated for the project. Who ran the ceremony? How many participants? Is the toxic waste verifiably destroyed? Auth0, WorkOS, and Cloudflare's MCP auth products rely on TLS and OAuth — well-understood primitives with 20 years of operational history, FIPS 140-2 certified implementations, and no ceremony provenance risk. An enterprise buyer's security team will ask: "If the trusted setup is compromised, every audit proof ever generated is forgeable. What's your ceremony transcript? Who audited it?" The construction's §4 assumes KS-PLONK holds but doesn't address the trust model for the SRS itself. A solo founder running a 1-participant Powers of Tau ceremony is not the same assurance level as the Semaphore v4 ceremony (which NFCU's procurement team will ask you to distinguish).
- **Why it works:** This is a procurement-layer attack, not a cryptography-layer attack. The construction correctly notes that PLONK avoids *per-circuit* ceremonies (§2, Circuits table). But it still requires *some* SRS. The CLAUDE.md notes `HumanUniqueness` reuses the public Semaphore v4 ceremony — but `DelegationAuditRollup` is a new circuit. Does it reuse `pot16.ptau`? Who generated `pot16.ptau`? The construction doesn't say, and the procurement team will ask before signing a contract that puts NCUA audit artifacts on a ZK proof with unvetted ceremony provenance.
- **In-threat-model?** No. The construction's security argument (§4) is conditioned on KS-PLONK, which is conditioned on the SRS being honestly generated. The construction must either (a) reference a public, multi-party SRS (e.g., Ethereum's KZG ceremony, Aztec's Ignition) that `pot16.ptau` is derived from, or (b) explicitly document the ceremony process and acknowledge the trust assumption. Leaving this implicit is a procurement blocker with any enterprise buyer who has a real security team.


## Persona: cryptographer

Applied cryptographer, IACR member. I've reviewed the `DelegationAuditRollup` construction in detail. Here are four attacks that the current draft does not adequately address.

---

### Attack 1: Chain Truncation — Audit Completeness is Not Proven

**Attack:**
The adversary is the pipeline operator (controls all intermediate agents). The on-chain registry stores exactly one artifact: `rootScopeCommitment = Poseidon2(delegatorScope[0], delegatorCredCommitment[0])`. Nothing on-chain records how many hops actually executed or what terminal commitment resulted.

Suppose the actual pipeline is 4 hops, where hop 3 expands a permission (a narrowing violation). The prover generates a `DelegationAuditRollup` proof with `chainLength = 3`, marking hop 3 inactive. Constraint 7 forces inactive hops to identity pass-through, so the proof is valid for a 3-hop chain. The auditor verifies the proof, concludes "3 hops, all narrowing held," and the 4th unauthorized hop is simply absent from the proof — yet it executed.

**Why it works:**
`chainLength` is a public output chosen by the prover. The only on-chain anchor is `rootScopeCommitment`, which is fixed at handshake time and is consistent with any truncation of the actual pipeline. There is no on-chain commitment to `chainLength` or to the terminal commitment, and no mechanism for the auditor to verify that the proof covers the complete execution trace.

**Formal gap:**
The Audit Forgery Game (§3) defines win condition (a) as a narrowing violation *in the witness*. But a hop that is simply omitted from the witness — with `chainLength` set below the actual execution depth — is not a forgery by the game's definition. The game only asks whether the proof verifies against a *valid* chain; it does not ask whether the proof covers the *full* chain. Audit **completeness** (the proof covers every hop that executed) is not defined as a win condition and is not enforced by any circuit constraint.

**In-threat-model?** No. The adversary controls intermediate agents (§3 capabilities) and can elect which hops to include in the witness. The construction must either (a) commit `(chainLength, terminalScopeCommitment)` on-chain at each delegation step so the auditor can verify the proof covers all recorded hops, or (b) add a completeness win condition to the Forgery Game with a corresponding circuit constraint binding the proof to an on-chain execution log.

---

### Attack 2: Phantom Agent Injection — No Enrollment Membership Proof on Intermediate Hops

**Attack:**
The adversary is any participant who generates the rollup proof. `delegateeCredCommitment[i]` for intermediate hops is a private witness field element — it is never verified as a leaf in the on-chain agent Merkle tree. The circuit only enforces chain linking (equality of scope commitments between adjacent hops) and scope narrowing.

The attacker constructs a fabricated intermediate credential commitment `CC_phantom` — a value that satisfies `Poseidon2(delegateeScope[i], CC_phantom) = Poseidon2(delegatorScope[i+1], CC_phantom)` (trivially, since chain linking equates the previous hop's delegatee commitment to the next hop's delegator commitment). The phantom commitment does not correspond to any enrolled agent. The prover uses `CC_phantom` for hops 1–(n-1), inserting an unenrolled relay into the chain. The rollup proof verifies; the auditor believes the chain passed through enrolled agents only.

**Why it works:**
The Bolyra spec defines agent enrollment via a Merkle tree of `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` commitments (§Agent Proof Specification). The `DelegationAuditRollup` circuit maps `delegateeCredCommitment[i]` to this structure in the primitive table (§5), but adds **no Merkle membership gadget** for intermediate hops. The `rootScopeCommitment` is anchored on-chain (via the initial handshake, which does run an `AgentPolicy` proof), but hops 1 through `chainLength-1` carry no such anchor.

**Formal gap:**
The privacy proof (§4, Audit Privacy Theorem) argues the simulator need not know intermediate commitments — which is correct for the ZK claim. But this same argument shows that the commitment values are entirely unconstrained with respect to the enrollment registry. The soundness proof (§4, Audit Soundness Theorem) only argues narrowing and chain linking, not enrollment membership. Phantom agents are not a forgery under the current game definition.

**In-threat-model?** No. The adversary controls intermediate agents and can supply arbitrary credential commitments as private witnesses. The construction must add a `BinaryMerkleRoot` membership proof for each `delegateeCredCommitment[i]` against the on-chain agent Merkle root (a public input), adding approximately `depth × Poseidon2` constraints per hop (~200 constraints per hop at depth 20, still well within the `pot16.ptau` ceiling).

---

### Attack 3: Privacy Game Adversary is the Verifier — HVZK Does Not Suffice

**Attack:**
The Audit Privacy Game (§3, win condition: deanonymization) places the **auditor** in the adversary role — the adversary sees the proof and tries to recover intermediate witness values. The security proof (§4) reduces to "ZK-PLONK: the proof reveals nothing about the witness beyond the public signals."

Standard PLONK (GWC19, Maller et al.) achieves **honest-verifier zero-knowledge** (HVZK): if the verifier follows the prescribed verification algorithm, simulation holds. It does not achieve **malicious-verifier ZK** or **simulation-extractable ZK** without additional machinery. A malicious auditor who:

- submits a manipulated verification key (e.g., a key for a related but subtly different circuit),
- performs multiple parallel verifications of proofs sharing witness elements, or
- exploits algebraic structure in the AGM to correlate public group elements across proofs,

is not bound by HVZK. The Fuchsbauer–Kiltz–Loss (CCS 2022) and Bünz–Fisch (EUROCRYPT 2023) frameworks show that lifting PLONK to simulation-extractable ZK requires non-trivial extensions (e.g., trapdoor-free SRS, additional blinding).

**Formal gap:**
The construction names the assumption "ZK-PLONK" without specifying whether it means HVZK or SE-ZK. The reduction sketch (§4) says "by ZK-PLONK, there exists a simulator `S` that produces proofs indistinguishable from real proofs given only the public signals." This is the HVZK simulator definition. The audit privacy game's adversary is the verifier — this requires the stronger, **malicious-verifier ZK** property, which standard snarkjs PLONK does not formally guarantee. The gap is between the game's adversarial model and the named assumption's scope.

**In-threat-model?** Yes, partially — but the construction must either (a) explicitly restrict the adversary to honest verification (a significant weakening of the privacy claim), or (b) name and cite a concrete SE-ZK or simulation-sound variant of PLONK and confirm the implementation achieves it. The latter is a non-trivial deployment requirement that the current §4 does not acknowledge.

---

### Attack 4: Journalist Variant — k-Anonymity Collapses Against an On-Chain-Aware Auditor

**Attack:**
The journalist/source variant (§2, final paragraph) hides `rootScopeCommitment` behind a `BinaryMerkleRoot(depth=10)` gadget over a set of K recent handshake roots. The auditor learns only the Merkle root of the handshake set, not which specific `rootScopeCommitment` initiated the chain.

The Merkle tree's leaves are drawn from `lastScopeCommitment` values stored by the on-chain registry (§5, §7 flow step 1: "Auditor obtains `rootScopeCommitment` from on-chain registry"). These values are **public on-chain state** — any observer, including the auditor, can enumerate all K values at depth 10 (K ≤ 1024 leaves). Given the Merkle root, the auditor checks all K known `rootScopeCommitment` values to find which leaf's hash chain produces the advertised root. This is K hash evaluations — trivially feasible for K ≤ 1024.

The journalist variant provides **zero anonymity** if K is small (e.g., "recent handshake roots" over a low-traffic period might be a handful of values) or if the auditor has any auxiliary information (e.g., timestamp, member count, session nonce range) narrowing the candidate set.

**Formal gap:**
The construction offers no anonymity set size lower bound, no entropy argument for the effective k, and no mechanism to prevent the auditor from enumerating all candidate roots. The correct construction would require the Merkle tree to be populated with a **minimum anonymity set** of indistinguishable decoy commitments with a formal anonymity game (e.g., an IND-based game where the challenger chooses among two possible `rootScopeCommitment` values and the adversary guesses which was used). Without this game definition and a reduction to Poseidon preimage resistance over a set of size ≥ k_min, the privacy claim in the journalist variant is informal. The privacy reduction in §4 does not cover this variant at all.

**In-threat-model?** No — the construction's threat model (§3) does not specify the journalist/source variant's adversary capabilities (specifically, on-chain read access and the resulting enumeration attack). The variant must either define a minimum anonymity set k_min with a formal privacy game, or acknowledge that the anonymity guarantee is computational only when k is large enough to make enumeration infeasible.


## Persona: cu_ciso

### Attack 1: The Privacy Guarantee Is a Regulatory Liability, Not a Feature

- **Attack:** The construction's headline claim — "auditor learns nothing about which agents participated or what intermediate scopes were" — is precisely the *opposite* of what NCUA examiners require. NCUA Interpretive Ruling and Policy Statement 07-1 (Third-Party Relationships) and Letter to Credit Unions 01-CU-20 mandate that the credit union *demonstrate oversight* of every material third party in a service chain. The deployment scenario explicitly cites this: the CU "does not want the examiner to learn that Chainalysis is their AML provider." That is not a feature to protect — that is the disclosure the examiner is *entitled to demand*. The CU must maintain a vendor register, conduct due diligence, and show the examiner that each third party in scope has been vetted. A ZK proof that cryptographically erases Chainalysis and Circle from the audit record does not satisfy NCUA Part 741.11 third-party oversight; it actively obstructs it. The CISO who presents this proof to an examiner as evidence of compliant vendor oversight will face a Matter Requiring Attention on the spot.

- **Why it works / fails:** The construction cannot survive this. It is not a technical flaw in the circuit — the circuit is internally consistent. The flaw is that the construction optimizes for a property (intermediary hiding) that is orthogonal or adversarial to the CU's actual regulatory obligation. The Section 8 differentiation table ("No org sees another org's internal scopes") is a sales pitch, not a compliance argument. NCUA is precisely the org that is supposed to see those scopes.

- **In-threat-model?** No. The construction must address this directly: define a *two-tier audit artifact* — a privacy-preserving proof for the AML/settlement layer (for public disclosure or cross-org coordination) and a separate, unredacted delegation log held in the CU's SOC 2 Type II-attested evidence vault for examiner-only access. The ZK proof is not a substitute for the examiner's right to inspect vendor relationships; it can only layer on top of it.

---

### Attack 2: The "Audit Trail" Is a 800-Byte Opaque Blob

- **Attack:** Section 7 states "The NCUA examiner verifies the single proof." This assumes the examiner is equipped and willing to run PLONK proof verification. They are not. NCUA examiner questionnaires ask for *human-readable evidence*: timestamped logs, access control matrices, screen captures from core systems, policy documents. A BN128 elliptic curve verification is not in the FFIEC CAT evidence taxonomy. When the examiner asks "show me the audit trail for this stablecoin transfer," the CU hands them an `auditDigest = Poseidon3(...)` and a proof blob. The examiner writes "audit trail not available in comprehensible form" and the finding goes to the board. NCUA Part 748 Appendix A (Guidelines for Safeguarding Member Information) requires the institution maintain records demonstrating that its security program is functioning. "A PLONK proof verified to true" is not a security program record in any format NCUA has defined. The `chainLength = 4` and `terminalScopeCommitment = 0x...` tell the examiner nothing about what transaction occurred, for which member, at what time, approved by whom.

- **Why it works / fails:** The construction has a complete coverage gap between circuit outputs and regulatory evidence standards. Public signals (`chainLength`, `terminalScopeCommitment`, `auditDigest`) are cryptographic artifacts with no semantic mapping to NCUA's documentation requirements. The construction provides no "translation layer" — no human-readable report, no timestamped log, no mapping of the `auditPolicyMask` bits to the institution's written security policy.

- **In-threat-model?** No. The construction must specify a *companion audit report format*: a structured JSON or PDF artifact that maps `auditPolicyMask` bits to named permission labels, binds the proof to a wall-clock timestamp and a member transaction ID (in human-readable form), and is signed by the CU's authorized officer. The PLONK proof is cryptographic backing for this report, not a replacement for it. Without the companion format, no examiner and no board will accept this as evidence.

---

### Attack 3: On-Chain Registry SLA Is Below Core Processor Standards

- **Attack:** The entire verification flow depends on reading `rootScopeCommitment` from an on-chain registry (Section 2, Verification Flow, Step 1). In the deployment scenario this is Base (mainnet or Sepolia). Base is an Ethereum L2 with ~99.9% historical uptime — meaning roughly 8.7 hours of downtime per year. The CU's core processor (Symitar, Fiserv, FiServ DNA) SLA is typically 99.95%–99.99%. NCUA Business Continuity Planning guidance (NCUA Letter 21-CU-04, derived from FFIEC BCP handbook) requires that critical systems supporting member transactions have recovery time objectives measured in minutes, not hours, and that single points of failure are identified and mitigated. The on-chain registry is a single point of failure for every delegation audit: if Base is down, no `DelegationAuditRollup` proof can be anchored. There is no fallback. There is no offline verification path. The stablecoin transfer pipeline for a $175B institution grinds to a halt. The CISO's vendor management policy will reject any dependency with a published SLA lower than the core processor without an explicit compensating control and board-approved exception.

- **Why it works / fails:** Section 6 gives proving time (< 5s) and gas cost (~230K) but provides no availability analysis, no disaster recovery design, and no fallback for registry unavailability. The construction silently inherits all of Base's operational risk and infrastructure dependencies (sequencer centralization, Ethereum L1 finality, RPC node availability) without disclosing them.

- **In-threat-model?** No. The construction must specify: (a) a cache layer where `rootScopeCommitment` values are mirrored to a CU-controlled high-availability store (e.g., HSM-backed database) with a defined freshness window; (b) an offline verification path using cached commitments when the chain is unavailable; (c) an explicit SLA budget analysis comparing the registry's availability to the CU's BCP requirements; (d) incident classification for registry unavailability (is this a P1 incident for the CU? what's the runbook?).

---

### Attack 4: Breach Response Is Blind — GLBA Safeguards and Incident Forensics

- **Attack:** Suppose hop 2 (the Chainalysis AML agent) is compromised mid-session. The attacker exfiltrates member account data using the `READ_DATA` permission. The `DelegationAuditRollup` proof, generated after the session, will verify correctly — `chainLength = 4`, monotonic narrowing held, terminal scope satisfied `FINANCIAL_SMALL`. The proof is clean. The breach happened *inside* a valid proof. Now the GLBA Safeguards Rule (16 CFR Part 314, amended 2023) requires the CU to notify the FTC within 30 days of discovering a breach affecting 500 or more customers, to provide a description of what information was acquired, and to maintain an incident response plan. NCUA Part 748 Appendix B similarly requires a response program with containment, notification, and forensic capabilities. The CISO asks: given a clean `DelegationAuditRollup` proof and a reported breach, how do I (a) confirm which member records were accessed, (b) determine the attack vector, (c) provide the mandatory notification content, (d) demonstrate to the examiner that my incident response plan functioned? The construction provides none of this. The privacy properties that hide intermediate participants and scopes from the auditor also hide them from the incident responder. The `auditDigest` is a commitment to a clean chain — it is forensically inert.

- **Why it works / fails:** The construction conflates *proof of policy compliance* with *forensic evidence*. A ZK proof that "the rules were followed during issuance" says nothing about what happened at runtime inside each agent's execution environment. The threat model in Section 3 defines adversaries who forge proofs — it does not model adversaries who operate *within* valid proof boundaries (a compromised agent with legitimately granted `READ_DATA` scope). The gap is not in the circuit; it is in the claim that this construction satisfies audit requirements in the regulatory sense.

- **In-threat-model?** No. The construction must acknowledge the boundary: the `DelegationAuditRollup` proves *issuance-time policy compliance*, not *runtime behavior*. A companion runtime audit log (separate from the ZK proof, maintained in the CU's SIEM) must capture session-level access events for forensic use. The ZK proof provides the policy compliance layer; the SIEM provides the forensic layer. These are not substitutes. The deployment scenario at Section 7 should state this explicitly or risk misrepresentation to CISOs who may assume the proof covers incident forensics.


## Persona: rfc7662_advocate

---

### Attack 1: The Registry IS an Authorization Server — "No AS in Trust Path" Is a Shell Game

**Attack:**
Section 8 claims the construction's decisive advantage is "Verify without a trusted Authorization Server — no AS is in the trust path." But examine the NFCU deployment scenario (§7): the `rootScopeCommitment` is written to an on-chain registry contract during the initial handshake. *Who authorizes that write?* The handshake itself — which is governed by the Bolyra AgentPolicy circuit, a universal verification key, and whoever deployed the registry contract. That contract is the AS. It enforces issuance policy, holds the trust anchor, and is the single point of verification-key compromise. The construction doesn't eliminate the AS; it instantiates it as an immutable smart contract and calls it a "registry."

Compare with RFC 7662 + draft-ietf-oauth-jwt-introspection-response (signed JWT response): the AS issues a signed JWT at introspection time, verifiable offline with the AS's public key. If the AS's signing key is the trust anchor, that's exactly equivalent to trusting the Bolyra verification key embedded in the registry. Both reduce to "trust the entity that set up the trust anchor." The construction must articulate *why* a Solidity contract holding a Poseidon commitment is a weaker trust anchor than an AS's signing key — or concede the "no AS" framing is rhetorical.

**Why it works / why it fails against the construction:**
The construction survives narrowly: the registry contract is *append-only* and *permissionless to verify* (anyone can call `verifyProof` without AS involvement after the fact). A traditional AS can revoke, modify, or selectively respond. But the construction's §3 threat model does NOT include a compromised or colluding registry deployer. If the registry deployer is adversarial, they can manipulate `rootScopeCommitment` at write time. The "no AS" claim is partially true for *post-handshake* verification but false for *handshake authorization*.

**In-threat-model?** No — construction must address this. §3 excludes the registry deployer from the adversary model but §8 claims full AS elimination. The claim must be scoped accurately or the threat model must explicitly include the registry deployer as trusted.

---

### Attack 2: Signed JWT Introspection Response Has Been Off the Hot Path Since 2021

**Attack:**
The construction's §8 row "Verify without a trusted AS" sets up a strawman: it imagines RFC 7662 requires a live AS call at verification time. That was true in 2012. draft-ietf-oauth-jwt-introspection-response (now RFC 9701) has the AS issue a *signed JWT as the introspection response*, cryptographically bound to the requesting RS's `resource` identifier (via RFC 8707 Resource Indicators). The RS caches and verifies this offline — no AS on the hot path, same as PLONK proof verification. The signed introspection JWT is a static artifact, verifiable with the AS public key, with configurable TTL.

For the NFCU audit scenario specifically: the AS issues a signed JWT introspection response per-hop, each bound to the downstream RS's audience. An auditor collects the four signed JWTs (one per hop). Each JWT carries `scope`, `sub` (as PPID — pairwise, unlinkable across RSes), `aud` (bound to the specific RS), and `act` chain. The AS *could* omit intermediate `sub` values from the response it returns to a given RS if its per-RS policy dictates it. This is exactly RFC 9701 §7 ("the AS MAY filter the introspection response based on the requesting RS").

**Why it works / why it fails against the construction:**
It fails on one point: the AS *sees* the intermediate scopes when issuing the introspection JWTs — even if individual RSes don't. The construction's §8 says "no org sees another org's internal scopes." Under RFC 9701, the AS does. In the NFCU scenario, NFCU's AS learns Chainalysis is the AML provider. This is a real gap only if the AS is cross-org (i.e., not NFCU-controlled). In single-org pipelines or where the AS is trusted by all parties, RFC 9701 fully matches. The construction must be explicit: the advantage is *specifically* the cross-org case where no single party can be the AS.

**In-threat-model?** Partially. The construction survives for genuine cross-org pipelines (NFCU → Chainalysis → Circle) where no single AS is acceptable to all parties. It does NOT survive for single-org or same-trust-domain pipelines. §8 should qualify its "constant-size artifact" and "no AS" claims as cross-org-only advantages, not universal ones.

---

### Attack 3: DPoP + Audience Binding + PPIDs Break Cross-RS Linkability at the RS Level — AS-Side Advantage Requires an Adversarial AS

**Attack (verbatim from attack_prompts):** "Audience-bound tokens + PPIDs already break cross-RS linkability at the RS level. Why is the AS-side advantage load-bearing?"

Under RFC 9449 (DPoP), each token is sender-constrained: RS-B (Chainalysis) receives a token bound to Chainalysis's `aud`, requiring a DPoP proof-of-possession from the delegatee's ephemeral key. RS-B cannot replay this token to RS-C or correlate it with RS-A's token (different `aud`, different DPoP key). Under OIDC Pairwise Subject Identifiers, each RS sees a different `sub` for the same user — no RS-vs-RS linkability on identity. RFC 8707 Resource Indicators bind the token's `scope` to a specific resource at issuance time.

The only entity that sees across all hops is the AS. The construction's audit privacy advantage — "intermediate participants hidden from the auditor" — requires the AS to be adversarial or untrustworthy. If the AS is trusted (which it must be in any RFC 8693 deployment), RS-level privacy is already achieved. The rollup's auditor learns less than a trusted AS, but learns *exactly the same as any individual RS* under the DPoP + PPID + audience-binding stack.

The construction's §7 says "NFCU does not want the examiner to learn that Chainalysis is their AML provider." Under RFC 8693 + DPoP + RFC 8707: the NCUA examiner as auditor would receive only the tokens scoped to their audit role — they would NOT receive the cross-hop `act` chain unless the AS policy authorized it. Per-RS introspection policy (RFC 9701 §7) can filter the `act` chain out of the response returned to the examiner's audit client.

**Why it works / why it fails against the construction:**
It fails on the adversarial AS scenario: if NFCU's AS is subpoenaed, if the AS logs are leaked, or if the AS is operated by a third party (common in federated enterprise deployments), the AS-side data exposure is a real risk. The ZK rollup eliminates AS-side data collection entirely — there is nothing to subpoena because the intermediate scopes never leave the prover's witness. This is a legitimate advantage, but it is *narrower* than §8 implies. The construction must frame this precisely: "advantage over RFC 8693 + DPoP is specifically AS-data-minimization, not RS-level unlinkability."

**In-threat-model?** Yes — the construction survives *with qualification*. The threat model in §3 must include "AS is honest-but-curious or subpoena-able" for the advantage to be non-trivial. Without this, the attack shows RFC 9449 + PPID + RFC 9701 achieves RS-level privacy equivalently. §8 currently overstates the gap.

---

### Attack 4: Pedersen Commitments + Bulletproof Range Proofs Prove Bitwise Subset Over Hidden Scopes — The BBS+ Dismissal Misidentifies the Baseline

**Attack:**
Section 8's "best baseline attempt" for "Prove monotonic narrowing over hidden scopes" is BBS+ selective disclosure. This is a strawman. BBS+ is a *selective disclosure* scheme, not a *predicate proof* system. The correct baseline for proving a relational property over committed values is **Pedersen commitments + Bulletproofs** (Bünz et al., 2018; RFC-adjacent, widely deployed in Monero, Confidential Transactions).

The attack: commit to each hop's scope as `C_i = Commit(scope_i, r_i)` using Pedersen commitments. To prove `scope_i ⊆ scope_{i-1}` (bitwise subset), compute `delta_i = scope_{i-1} XOR scope_i` (bits that were dropped). Observe: `scope_i ⊆ scope_{i-1}` iff `scope_{i-1} & ~scope_i == 0` iff `delta_i = scope_{i-1} - scope_i` with all bits non-negative (equivalently: `delta_i >= 0` AND `delta_i + scope_i == scope_{i-1}`). A Bulletproof range proof over `delta_i` (proving `delta_i ∈ [0, 2^64)`) combined with a homomorphic commitment equality (`C_{delta_i} + C_i = C_{i-1}`, using commitment homomorphism) proves bitwise subset containment over committed values without revealing `scope_i`, `scope_{i-1}`, or `delta_i`. The per-hop proofs are ~700 bytes each (64-bit range proof). Eight hops: ~5.6 KB, logarithmically aggregatable via Bulletproof batch verification.

This baseline is not cited anywhere in the construction. The §8 table's dismissal of BBS+ does not apply to Pedersen + Bulletproofs. The construction must either (a) show why Pedersen + Bulletproofs cannot prove the relational property described, or (b) benchmark against Bulletproofs and show the PLONK rollup is smaller, faster, or achieves additional properties Bulletproofs do not.

**Why it works / why it fails against the construction:**
The construction has two genuine advantages over Pedersen + Bulletproofs here:

1. **Chain linking:** The Bulletproof baseline proves each individual hop's subset constraint, but does not prove the *chain links* (that the delegatee at hop i-1 is the delegator at hop i) without additional machinery. The rollup's constraint 3 (`Poseidon2(delegatorScope[i], delegatorCredCommitment[i]) === Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])`) binds scope and identity together at each hop link. Pedersen commitments would require separate identity commitments and a proof that the identity commitment at hop i-1's delegatee equals the identity commitment at hop i's delegator — which requires a sigma protocol or a separate ZK proof, not a native Bulletproof property.

2. **Credential commitment binding:** The rollup binds scope to credential commitments (`Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)`) at each hop, preventing scope-credential detachment attacks. Pedersen commitments on scope alone don't bind to credential identity.

**In-threat-model?** No — the construction must address this baseline. §8's dismissal of alternatives is weakened by citing only BBS+. The construction survives if it specifically argues why Pedersen + Bulletproofs fail on chain linking and credential binding, but it must make that argument explicitly. Currently it does not.


## Persona: spiffe_engineer

**Background:** Staff engineer, SPIFFE/SPIRE in production at a Fortune 500, 11,000+ workloads attested daily, co-author of draft-ietf-wimse-arch. My prior is that if a workload identity problem is not solved by SPIRE + WIMSE token exchange, the gap is narrow and the fix is a plugin, not a new protocol.

---

### Attack 1: The SPIRE Audit Log Is Already This Proof

- **Attack:** The construction's §3 threat model places "the SPIRE server" outside the adversary's control — it does not exist in the model at all. But in any real deployment running SPIFFE, scope narrowing is *enforced by the SPIRE server at SVID issuance time*. The AS does not merely attest identity; it signs every SVID with the approved scope. Its issuance log is a tamper-evident record of every scope transition. A NCUA examiner who trusts the SPIRE server (and SPIRE attestation already anchors trust in TPM/Nitro attestation, not in operator promises) can call `spire-server bundle show` and inspect the SVID issuance log for the session. They see: chain has N hops, terminal scope is X, each hop narrowed. The ZK rollup replicates this property at ~8,500 constraints and several seconds of proving time.
- **Why it works / why it fails:** It *works* for the majority of enterprise deployments: operators who run SPIRE already have this audit capability, do not pay proving overhead, and do not need a blockchain registry. It *fails* on the specific privacy axis the construction targets: the SPIRE log reveals intermediate scopes and SPIFFE IDs in the clear. If NFCU genuinely cannot let NCUA see `spiffe://chainalysis.com/aml-agent` in the issuance log, the ZK rollup is justified. But the construction (§8) frames "no AS in the trust path" as universally superior — it is only superior in the subset of cases where the auditor is a privacy adversary against intermediate participants.
- **In-threat-model?** **No.** The construction must explicitly scope out the case where the auditor is also the operator of the SPIRE trust domain, or where SPIRE audit logs satisfy the examiner. The NFCU scenario implicitly assumes the NCUA examiner has no SPIRE access — this assumption is unstated and fragile. Add it to §3 or the claim is overclaimed.

---

### Attack 2: You Replaced SPIFFE Federation With a Blockchain and Called It "No Infrastructure"

- **Attack:** Construction §8 states: "Cross-org delegation (NFCU → Chainalysis → Circle) requires either a shared AS or bilateral federation agreements." This is accurate for WIMSE today. But the construction's proposed alternative is an *on-chain registry* storing `rootScopeCommitment` and a *shared PLONK verification key*. That is not "no federation infrastructure" — it is a different federation infrastructure: a smart contract on Base Sepolia that all three orgs must read and trust. Compare the operational surface: bilateral SPIFFE federation requires exchanging CA bundles (a one-time, per-pair operation with `spire-server bundle show | spire-server bundle set`); the construction requires all three orgs to (a) integrate with Base Sepolia, (b) trust the on-chain registry contract, (c) run PLONK verifier tooling, and (d) maintain the `rootScopeCommitment` lifecycle on-chain. For Fortune 500 orgs already running SPIRE with federation already configured, this is strictly more infrastructure, not less.
- **Why it works / why it fails:** The attack *lands* on the infrastructure comparison. NFCU, Chainalysis, and Circle all operate in regulated financial services; they will not expose audit infrastructure to a public L2 without significant legal review. The bilateral SPIFFE federation path — already in production at comparable orgs — has lower compliance overhead. The attack *fails* to address the privacy property: federated SPIRE still exposes SPIFFE IDs and scopes to each org's SPIRE server, which logs them. The blockchain registry only stores a commitment, not the plaintext scope.
- **In-threat-model?** **No.** The construction must acknowledge the trust infrastructure trade-off explicitly. "No federation required" should read "no bilateral AS agreements required, but a shared on-chain registry is required, and all participants must trust Base Sepolia finality." The current framing in §8 is misleading to infrastructure engineers evaluating adoption.

---

### Attack 3: Build a SPIRE ZK Attestor Plugin — Same Properties, Half the Protocol

- **Attack:** SPIRE's plugin architecture supports custom node attestors and workload attestors. The WIMSE WID (Workload Identity Document) is designed to carry extensible attestation evidence. The SPIFFE engineer's concrete proposal: write a SPIRE node attestor plugin that, during workload registration, generates a ZK proof of enrollment (the `HumanUniqueness` circuit or equivalent) and embeds the resulting `nullifierHash` into the SPIFFE ID path (`spiffe://bolyra.ai/agent/{nullifierHash}`). The SVID's scope claims (via `jwtClaims` extension or a custom X.509 SAN) carry the permission bitmask. The delegation rollup is replaced by JWT SVID `act` chains with BBS+-derived scope predicates per hop. The key claim: you get ZK-attested workload identity inside the SPIFFE/WIMSE ecosystem without forking the trust model, without a blockchain registry, and reusing the Workload API that every service mesh already integrates.
- **Why it works / why it fails:** The attack correctly identifies that ZK attestation is a *plugin*, not a *protocol*. A SPIRE attestor plugin for `HumanUniqueness` would take ~500 LoC. However, the attack *fails* on the delegation audit's core property: BBS+ selective disclosure can hide individual claim values within a single multi-message signature from a single issuer. It cannot prove a *relational ordering property* (`scope_n ⊆ scope_{n-1}`) over hidden bitmasks across credentials from multiple issuers. The SPIFFE engineer might counter: "Use a predicate proof over the BBS+ signature for the subset check." But no standardized BBS+ predicate system supports arbitrary bitwise subset containment over private multi-issuer chains. The `DelegationAuditRollup` circuit enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` in the PLONK constraint system — there is no analogue in SVID tooling today.
- **In-threat-model?** **Yes — construction survives**, but it should explicitly state in §8 why a SPIRE plugin path is insufficient rather than conflating it with "RFC 8693 + BBS+." The WIMSE working group is actively discussing predicate proofs; a SPIRE ZK attestor could narrow the gap in 12-18 months. The construction should cite this as a future-risk to its differentiation rather than ignoring it.

---

### Attack 4: `chainLength` Is a Public Output — You're Leaking Pipeline Topology

- **Attack:** Circuit public output `chainLength` (§2, Public outputs table) is visible to the auditor. In the NFCU deployment scenario (§7), a 4-hop chain reveals structural information: NFCU uses exactly four distinct agent delegations for a stablecoin transfer. Combined with industry knowledge of which orgs run SPIRE trust domains in fintech, an adversary can narrow hypotheses about the pipeline's composition even without knowing individual SPIFFE IDs or scopes. In SPIFFE, the equivalent would be SVID issuance counts per session — but those are retained only in the operator's SPIRE logs, not published to a blockchain-anchored audit digest. The `auditDigest = Poseidon3(rootScopeCommitment, terminalScopeCommitment, chainLength)` (§2) permanently encodes hop count into the on-chain artifact. If NFCU changes providers from a 4-hop to a 3-hop pipeline, the chain length change is detectable across audit epochs even when intermediate participants are hidden.
- **Why it works / why it fails:** This is a *real metadata leak* not addressed anywhere in the construction. The threat model's deanonymization win condition (§3) states the adversary cannot recover "any intermediate `delegatorScope[i]`, `delegateeScope[i]`, or `credentialCommitment[i]`" — but it says nothing about chain length, which is *designed to be public*. An auditor correlating `chainLength` across regulatory periods, combined with knowledge of org-level outsourcing patterns, can fingerprint pipeline topology changes. The journalist/source variant (§2, final subsection) hides `rootScopeCommitment` but still exposes `chainLength` — an adversary observing audit digests over time can correlate "source chains always use 3 hops" with known relay infrastructure.
- **In-threat-model?** **No.** The construction must either (a) add `chainLength` to the private witness and replace the public output with a range proof (`chainLength ∈ [1, MAX_HOPS]` with a single bit), or (b) acknowledge this as an explicit out-of-scope metadata leak with a stated rationale. The journalist/source variant in particular cannot claim full participant anonymity while leaking hop count in the audit digest.
