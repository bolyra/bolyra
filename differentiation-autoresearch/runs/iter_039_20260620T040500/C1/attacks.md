# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Theorem Precondition Is Never Satisfied In Production

**Attack:** Theorem 3 rests on the premise that the AS "does not observe `b` at filter time." In every real deployment — Auth0, WorkOS, Stytch — the AS *issued* the token. It owns `b` by construction. The adversarial-AS scenario (AS exists but doesn't know `b`) is a coherent mathematical object but not a real enterprise deployment. Enterprises self-host Auth0 or pay WorkOS to run it; they are the AS. The impossibility proof is vacuously true in a threat model that no buyer's procurement questionnaire will ever ask about.

**Why it works / fails:** The construction's Section 8 "Failure 1" explicitly names AS-blindness as the headline result, but it never demonstrates a plausible scenario where an enterprise both (a) operates an AS they cannot trust with the full bitmask, yet (b) trusts that AS enough to handle authn in the first place. The corollaries (suppression resistance, escalation resistance) inherit this gap — they protect against a malicious AS, but if your AS is malicious you have fired your IAM vendor, not bought a ZK library.

**In-threat-model?** No — construction must address the split-trust scenario concretely: name a real buyer who operates an AS they distrust with scope, and explain why they wouldn't just replace the AS.

---

### Attack 2: RFC 8707 Resource Indicators Already Scope at Issuance — No AS Roundtrip Required

**Attack:** The claim in the candidate states the gap includes "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)." But RFC 8707 resource indicators + audience-restricted access tokens already achieve this: the AS issues a token scoped to exactly the RS being called, with only the permissions relevant to that RS in the `scope` claim. The RS verifies offline via JWKS — zero AS roundtrip at presentation time. The agent never presents a "full permission set" to the RS because the token was scoped at issuance. WorkOS ships this today. The construction's Section 4 proof sketch covers RFC 7662 introspection and BBS+ but the audit trail doesn't show it explicitly falsified the RFC 8707 + audience-restricted issuance path.

**Why it works / fails:** The ZK construction lets the *agent* choose disclosure at *use time*, after issuance. RFC 8707 pushes that choice to the AS at issuance time. These are different trust delegation points, but from the RS's perspective the result is identical: it sees only the permissions relevant to it. The construction needs to show a concrete scenario where agent-side runtime choice matters — e.g., a single credential being presented to multiple RS endpoints with different predicate requirements in a single session, without re-issuing. Otherwise the claim reduces to "we moved the scope filter from AS to agent" which is a trust model reshuffling, not a new capability.

**In-threat-model?** Partially — the construction survives if it explicitly scopes the claim to multi-RS single-issuance sessions; it fails if the headline claim is stated broadly as "RFC 7662 cannot match this."

---

### Attack 3: The "2^64 Permission Space" Scenario Is a Strawman for GTM

**Attack:** The candidate's scenario 1 cites "2^64 permission space where AS-side policy tables do not scale." No enterprise IAM system in production has 2^64 permissions. Auth0 supports thousands of custom claims; WorkOS uses role hierarchies. The 8-bit cumulative encoding in Bolyra's `CLAUDE.md` has exactly 8 permissions (bits 0–7). The constant-size proof property ("regardless of bitmask width") is only differentiated at bitmask widths that don't exist in any real product today. A procurement buyer asking "why Bolyra over WorkOS" will never hear "because your permission space might someday reach 2^64."

**Why it works / fails:** The construction may be technically correct that ZK proof size is independent of bitmask width. But the claimed "regulated agent" scenario in Section 8 maps to an 8-bit bitmask per `circuits/src/AgentPolicy`. The constant-size property therefore provides no marginal benefit over a JWT `scope` string at any plausible real-world bitmask size. The attack succeeds unless the construction either (a) drops the scalability claim from the GTM pitch, or (b) demonstrates a concrete regulated industry (FINRA, ONC TEFCA, etc.) with a permission space that genuinely stresses token-based systems.

**In-threat-model?** No — the construction must tie its formal properties to a concretely sized, named real-world permission space, or strike the scalability framing from the competitive claim.

---

### Attack 4: 15-Second Proof Latency Fails the "Paste an API Key" Onboarding Heuristic

**Attack:** Using the attack prompt directly: WorkOS issues tokens in <100ms. Bolyra's `circuits/scripts/bench_rapidsnark.js` (per `CLAUDE.md`) exists to quantify proof time — the fact that it's a dedicated benchmark file implies the number is non-trivial. Even with `rapidsnark` the groth16 AgentPolicy prove time on commodity hardware is measurable in seconds, not milliseconds. Every resource server call that requires a fresh proof (due to nonce binding in the handshake — "every handshake commits to a fresh `sessionNonce`") pays this cost. The construction's Theorem 3 is information-theoretically correct but the latency regression makes it a non-starter for synchronous API gating, which is the primary MCP auth use case.

**Why it works / fails:** The construction's defense is presumably that proofs are generated once per session, not per call. But "per session" proof generation still blocks the first request in a session by seconds, in a world where Auth0 M2M token issuance takes ~80ms end-to-end. The `sessionNonce` binding (`spec/draft-bolyra-mutual-zkp-auth-01.md`) means you can't pre-generate the proof without knowing the nonce, so you cannot cache it across sessions. The construction does not address this latency gap anywhere in the sections modified this iteration.

**In-threat-model?** No — the construction must either bound the proof latency with hardware specs and compare to incumbent token issuance, or scope the claim to batch/offline verification contexts where the latency tradeoff is acceptable to the buyer.


## Persona: cryptographer

---

### Attack 1: Theorem 3 Does Not Cover BBS+ Selective Disclosure — The Impossibility is Circular

- **Attack:** Theorem 3 claims BBS+ falls under the assertion-based impossibility: *some entity must observe the full bitmask `b` to produce a predicate assertion.* This is false as stated. In BBS+, the *issuer* signs a vector of attributes (the full bitmask `b`) at issuance time. At presentation time, the *holder* — not the issuer — runs the selective disclosure proof. The issuer never observes which predicate `P(b, m)` the holder will prove at runtime. The holder selectively opens the committed attributes needed to satisfy `P` while hiding the rest. This is exactly the "AS-blind presentation" the construction claims is impossible for assertion-based systems. If BBS+ credential issuance = AS issuing a committed signature over `b`, and the holder does zero-knowledge opening at presentation, Theorem 3's impossibility does not apply.

- **Why it works / fails:** The theorem's formal statement needs to distinguish between (a) *producing the predicate assertion* and (b) *issuing a commitment that enables the holder to later produce the assertion.* BBS+ splits these roles. Unless Section 4 formalizes `F` as a function that maps (RS query, bitmask) → assertion entirely within the AS's computation — with no holder contribution — the proof sketch has a gap. The paper mentions "jwt-introspection, BBS+, RFC 8693" as covered, but does not show a reduction for BBS+ with holder-side proofs.

- **In-threat-model?** No — construction must address this. Either tighten the theorem to exclude BBS+ (and then the claimed impossibility has a workaround) or add a security argument explaining why BBS+ with holder proofs still cannot achieve the full property set (e.g., revocation, runtime-adaptive predicates). Without this, Theorem 3 is false as written.

---

### Attack 2: Nullifier Precomputation by a Colluding AS + RS

- **Attack:** The nullifier scheme is not formally specified in the construction (neither the candidate JSON nor the section changes name a concrete function). Assume the natural choice: `nullifier = H(secret || scope_id)` where `scope_id` is a public parameter known to the AS. If the AS registers agents and learns their `secret` during enrollment — or learns a commitment to `secret` that leaks partial information — the AS can build a nullifier table for all enrolled agents for each `scope_id`. This breaks the unlinkability/pseudonymity claim: a colluding AS + RS can cross-reference nullifiers to link all presentations by the same agent across sessions.

- **Why it works / fails:** The construction's "adversarial-AS model" (Section 8 Failure 1, Scenario 2) claims cryptographic assurance *independent of AS cooperation.* But unlinkability against a *colluding AS+RS* is a strictly stronger property than unlinkability against a passive RS. The threat model as presented does not specify the adversary's capabilities: is the AS honest-but-curious, semi-honest, or actively malicious? Each requires a different game definition. The attack works if the AS touches `secret` during enrollment. If the nullifier uses a blinded secret the AS never sees, state that explicitly with a formal definition of the enrollment protocol.

- **In-threat-model?** No — construction must address this. State the nullifier game: define `Unlink(AS-colluding)` as a formal experiment, specify what the AS observes at enrollment, and prove that nullifiers are unlinkable given that view.

---

### Attack 3: Subverted Groth16 CRS Collapses Computation-Integrity Trust

- **Attack:** Theorem 3's headline result is that Bolyra replaces "assertion-based trust" with "computation-integrity trust." The entire argument rests on the soundness of the Groth16 proof system. Groth16 requires a circuit-specific trusted setup (toxic waste `τ`). If the setup is subverted — either the setup authority is malicious or the ceremony is compromised — knowledge of `τ` allows an adversary to forge proofs for *any* witness, including proofs that `P(b, m) = true` for a bitmask `b` the agent does not possess. Under a subverted CRS, the "computation-integrity trust" guarantee vanishes and the adversary can produce valid-looking proofs for arbitrary permission predicates with no computational barrier.

- **Why it works / fails:** The construction's claimed advantage over OAuth is that the AS cannot lie about scope membership (suppression resistance, escalation resistance per the two corollaries). But under subverted setup, *any party with knowledge of `τ`* — including a compromised setup authority, a malicious AS that ran the ceremony — can forge exactly such lies, defeating both corollaries. The construction does not cite a multi-party ceremony, does not claim setup transparency via a verifiable random function, and does not address post-setup security. The "impossibility" result only holds relative to an honest CRS.

- **In-threat-model?** No — the construction must bound the trust assumptions explicitly. Add a formal CRS model: define `F_CRS` as a functionality, state which adversaries are excluded (subverted `τ`), and argue why the deployment threat model makes this acceptable (e.g., cite the specific ceremony, number of parties, transcript availability). Without this, Theorem 3 is an impossibility result *conditioned on an honest setup* — not an unconditional structural advantage over assertion-based systems.

---

### Attack 4: Zero-Knowledge Claim is Under-Specified — No Simulator, No Malicious-Verifier Guarantee

- **Attack:** The paper claims the agent proves predicate satisfaction "without revealing the full permission set to the resource server." This is a zero-knowledge claim. For ZK to hold against a *malicious RS*, the protocol must be simulation-extractable or at minimum achieve malicious-verifier zero-knowledge (MVZK). Groth16 achieves only honest-verifier zero-knowledge (HVZK) in the generic group model. A malicious RS can choose its verification challenges adversarially. In a multi-session setting where the RS interacts with the same agent across many sessions (plausible for an AI agent with long-running tasks), the RS accumulates transcripts `{(proof_i, statement_i)}`. Without simulation extractability, these transcripts could leak information about the hidden bitmask `b` across sessions, violating the stated privacy guarantee.

- **Why it works / fails:** Concretely: the nullifier `H(secret || scope_id)` is revealed each session. If the predicate `P(b, m)` is evaluated for varying `m` across sessions, an adaptive RS choosing `m_1, m_2, ...` could run a binary-search-style distinguisher over which bits are set. This requires the RS to be active (choosing challenge messages), but the threat model for "adversarial AS" already contemplates a malicious party — and a colluding malicious RS is at most as strong. The construction must either (a) prove simulation extractability of the composed proof system, (b) formally bound what the RS learns across sessions, or (c) restrict the threat model to honest-verifier RS and state this explicitly as a limitation.

- **In-threat-model?** No — the ZK claim needs a simulator. The current construction writes "agent proves without revealing" without defining a simulation-based experiment. State the formal game: define a simulator `Sim` that produces transcripts indistinguishable from real proofs without knowing `b`, prove the indistinguishability holds under the appropriate hardness assumption, and specify whether the guarantee holds for a malicious RS across polynomially many sessions.


## Persona: cu\_ciso

---

### Attack 1: The Examiner Can't Read a ZK Proof

- **Attack:** I pull up Section 4 (Theorem 3) during an NCUA examination and hand it to the examiner. The theorem proves that *no AS-side filter can produce a predicate proof over inputs the AS does not observe*. Fine. But my examiner isn't asking about information-theoretic impossibility — she's asking me to produce a complete audit trail under **NCUA Part 748 Appendix B §III.C** ("audit of information systems and access controls") and **GLBA Safeguards Rule 16 CFR §314.4(c)(3)** ("monitor and log access to customer information"). What did Agent X access? Which bits of the 8-bit bitmask were actually exercised on a given transaction? When? The construction's predicate proof reveals only `P(b, m) = true`. It does not emit a human-readable, timestamped, non-repudiable access log that maps to member records. The nullifierHash prevents double-use but it's a hash — it tells the examiner nothing about *what* was authorized.

- **Why it works / fails:** The construction's design goal is *not revealing* the full permission set — exactly the property the examiner needs reconstructed in the event of a breach or disputed transaction. The construction does not address how the credit union produces a **GLBA-compliant audit trail** that maps ZK events to member accounts. Suppression resistance (Corollary 1) and escalation resistance (Corollary 2) are proofs about what the *agent* can't do — they say nothing about what *the credit union's ops team* can produce on demand.

- **In-threat-model?** No. The construction must address the audit materialization problem: how a verifiable, examiner-readable access record is derived from nullifierHash + proof transcript, and which party holds it in a form admissible to an NCUA examination.

---

### Attack 2: Operator Key Custody Is Completely Outside the Construction

- **Attack:** Section 3 (or equivalent) describes agent credentials as EdDSA-signed by the operator's private key, with the 8-bit cumulative bitmask committed into the circuit. Theorem 3 is information-theoretically tight. But it assumes the operator's private key is trustworthy. My question under **GLBA Safeguards Rule §314.4(f)** ("oversee service providers") and **FFIEC CAT Domain 3** (cybersecurity controls, access management): Where does `operatorPrivKey` live? If it's in an env var in a container, a secrets manager with broad IAM access, or — worst — derivable from a browser-side wallet, the attacker doesn't need to break the ZK circuit. They issue themselves a credential with `FINANCIAL_UNLIMITED` (bit 4) set, get a valid proof, and my member loses money. The construction's on-chain `Delegation.circom` enforces scope narrowing downstream, but the *root* credential can be minted with any bitmask if `operatorPrivKey` is compromised. The circuit doesn't know the key was stolen.

- **Why it works / fails:** Theorem 3's impossibility result is about AS-blind predicate proofs — it doesn't say anything about root key compromise. The attack is entirely outside the threat model the construction analyzes. The construction lists `HumanUniqueness`, `AgentPolicy`, `Delegation` circuits but provides no key lifecycle, HSM binding, key rotation ceremony, or revocation path for a compromised operator key that isn't blocked at the on-chain registry (which requires a transaction, which takes time, during which the stolen key is live).

- **In-threat-model?** No. The construction must address operator key custody: HSM or hardware-binding requirements, revocation latency from compromise-to-block, and which NCUA/GLBA control the credit union maps this to in its vendor risk assessment.

---

### Attack 3: On-Chain Registry Availability Breaks My BCP Exam Question

- **Attack:** Section 5 or equivalent references the on-chain `humanMerkleRoot` and nullifier registry deployed to Base Sepolia (per `CLAUDE.md`). Verification of a `HumanUniqueness` proof requires checking the on-chain root. My **NCUA Part 748 Appendix B §IV** ("business continuity planning") examination question is: *What is your RTO/RPO for member-facing authentication if this dependency is unavailable?* Base Sepolia is a testnet — production would use Base mainnet or equivalent. L2 chains have had sequencer outages (Optimism had a ~4-hour outage in 2023; Base had degraded periods). My core processor (Fiserv/Jack Henry/Symitar) guarantees 99.95% uptime contractually. The construction offers no degraded-mode fallback. If the chain is congested or the sequencer is down, can a member authenticate? If not, that's a BCP gap my examiner will cite.

- **Why it works / fails:** The construction's strength claim (Theorem 3, adversarial-AS model) is about cryptographic properties, not operational continuity. The construction does not describe a fallback authentication path, a cached root mechanism with bounded staleness, or how the credit union satisfies BCP requirements without a live chain read. This isn't a ZK problem — it's an infrastructure availability problem that the construction treats as out of scope.

- **In-threat-model?** No. The construction must quantify the availability dependency on the on-chain registry, state the expected SLA, and describe the BCP path (e.g., cached root with TTL, fallback to AS-mode with explicit degradation flag) that the credit union can document in its NCUA examination workpapers.

---

### Attack 4: Theorem 3 Is Not a SOC 2 Control and My Vendor Management Policy Requires One

- **Attack:** My **Vendor Management Policy** (required under NCUA Letter 07-CU-13 and updated 2023 NCUA guidance on third-party relationships) requires that before onboarding any technology vendor touching member data or authentication, I obtain: (a) SOC 2 Type II covering the relevant trust service criteria, (b) penetration test results from an independent assessor, (c) a right-to-audit clause. Theorem 3 proves a mathematical impossibility about assertion-based systems. It does not: attest that the `Delegation.circom` and `AgentPolicy.circom` implementations are free of under-constrained signals (a class of ZK implementation bug that formal math does not catch); confirm the `pot16.ptau` ceremony wasn't backdoored; or certify that the snarkjs/rapidsnark prover used in production matches the proving key. A formal theorem about protocol design is not an audit artifact. My examiner will ask: "Who independently verified the circuit?" The answer in the construction is: no one mentioned.

- **Why it works / fails:** The construction's Theorem 3 addresses a design-level impossibility, not an implementation assurance. ZK circuit bugs (under-constrained Merkle depth, missing range checks) have broken production systems that had correct mathematical designs (e.g., Tornado Cash's early circuit bugs, Zcash Sprout's quadratic constraint error). The construction's `FORMAL-PROPERTIES.md` exists but is not an independent audit. A credit union CISO cannot hand a math theorem to an NCUA examiner as a substitute for SOC 2 Type II or a penetration test report covering the circuit and verifier contracts.

- **In-threat-model?** No. The construction must state the independent assurance path: which firm will audit the circuits, what the SOC 2 scope covers, and how the credit union satisfies NCUA third-party due diligence requirements — none of which Theorem 3 addresses.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Show me the delta — not the philosophy.*

---

### Attack 1: BBS+ Selective Disclosure Already Breaks Theorem 3's Stated Impossibility

- **Attack:** Theorem 3 claims "*some* entity must observe the full permission bitmask `b`" and that this is information-theoretic. But BBS+ selective disclosure satisfies *all* of Theorem 3's conditions while still being "assertion-based." The AS signs the full bitmask `b` at issuance (so the AS observes `b` — the theorem's condition is met). At runtime, the agent produces a BBS+ ZK proof of opening that reveals only `P(b, m) = true` without disclosing `b` to the RS. No AS roundtrip. No full bitmask revealed. RS-verifiable offline. The paper explicitly lists BBS+ in the proof sketch but dismisses it in a single clause — that dismissal is load-bearing and must be formalized.

- **Why it works / fails:** The construction's escape route is that BBS+ requires the predicate structure to be committed at issuance (you select which attributes to reveal *over a fixed schema*), while a ZK circuit can evaluate an *arbitrary* boolean function over `b` that was unknown at issuance. This is a real distinction — but the current Theorem 3 does not state it. The theorem talks about *observation*, not *predicate flexibility*. As written, BBS+ is a counterexample to the stated theorem, not to the underlying intuition.

- **In-threat-model?** No — the construction must either (a) restate Theorem 3 to hinge on *predicate-agnosticism at issuance*, not mere AS-observation, or (b) explicitly prove BBS+ is insufficient for the claimed predicate class. The current proof sketch does not do this.

---

### Attack 2: The "Adversarial AS" Clause Is Not Justified in the Regulated-Agent Scenario

- **Attack:** Section 8 Failure 1 re-leads with Theorem 3 as a "structural impossibility of the assertion-based trust model" — meaning the AS cannot lie about scope membership. But the construction's own stated scenarios (Section of the candidate JSON) are *regulated agents* and *semi-trusted AS*. In a regulated deployment, the AS is a licensed entity subject to audit, liability, and cryptographic logging (RFC 9728 PRM + signed audit trails). An adversarial AS in that context is a compromised licensed operator — a threat that breaks *both* OAuth and ZK at the hardware/key-management level. The adversarial-AS model is only load-bearing if the agent operates in a *trustless* environment, which contradicts the regulated framing.

- **Why it works / fails:** The ZK construction survives if it limits the adversarial-AS claim to *privacy* (the AS cannot learn which predicate the agent used at runtime, even if the AS is honest) rather than *integrity* (the AS cannot forge scope membership). The integrity argument is where the regulated-agent framing undercuts the claim — a regulated AS that lies about scope commits fraud and can be prosecuted. The construction is conflating two distinct adversaries.

- **In-threat-model?** Partially. The construction must separate (a) AS-privacy (ZK provides this; RFC 7662 does not) from (b) AS-integrity (both models fail equally against a compromised AS). Theorem 3 as written covers integrity, but the stronger and harder-to-refute claim is actually the privacy one.

---

### Attack 3: RFC 8693 + Narrow-Scope Offline JWT Covers the AS-Blind Presentation Claim

- **Attack:** The candidate's gap analysis lists "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at moment of use)" as a required distinguishing property. RFC 8693 token exchange plus pre-issued, short-lived, RS-specific JWT introspection responses already achieves this. Workflow: (1) Agent exchanges its broad-scope token at the AS for a narrow-scope RS-specific JWT, binding audience via RFC 8707. (2) JWT is signed; RS verifies offline with the AS public key — no roundtrip. (3) Agent presents only the RS-specific JWT; the RS sees only the scopes relevant to it. The AS is not on the verification hot path. The agent "chooses" which narrow token to present.

- **Why it works / fails:** The attack fails on *predicate runtime-adaptivity* — the narrow token must be minted *before* the RS specifies `m`. If `m` is determined by the RS at the moment of the API call (e.g., "prove you have permission over resource class X where X is supplied in the request"), the agent cannot pre-fetch the right token. This is the genuine gap. But the construction's Section 4 and Section 8 do not demonstrate a concrete scenario where `m` is truly runtime-determined rather than enumerable at agent initialization. Without that concrete scenario, the RFC 8693 workflow is a valid baseline match.

- **In-threat-model?** No — the construction must exhibit a concrete interaction where `m` arrives at proof time (not at token-fetch time) and where pre-minting tokens for all possible `m` is infeasible. A `2^64` permission space is mentioned in the JSON but absent from the construction text.

---

### Attack 4: The Constant-Size Proof Claim Collapses at 8-Bit Bitmask Width

- **Attack:** The candidate's gap analysis mentions "constant-size proof regardless of bitmask width" as a candidate distinguishing property. But the actual Bolyra implementation uses an 8-bit cumulative bitmask (per `CLAUDE.md` permissions model, 8 named bits). BBS+ selective disclosure over 8 attributes produces a constant-size proof (BBS+ proof size is O(k) where k is the number of *disclosed* attributes, bounded above by 8). At 8-bit width, BBS+ is computationally and size-equivalent to a ZK circuit. The "constant-size regardless of bitmask width" argument only differentiates ZK from BBS+ at widths where BBS+ proof size grows non-trivially — roughly 64+ attributes. The construction does not operate in that regime.

- **Why it works / fails:** The construction survives if it either (a) commits to the `2^64` use case and provides a circuit that actually handles that width, or (b) drops the constant-size claim from the distinguishing-property list and focuses solely on the predicate-agnosticism and AS-privacy properties. As currently framed, the construction's strongest formal result (Theorem 3) is justified against an 8-bit permission space that BBS+ handles comfortably — making the ZK overhead unjustified on that property alone.

- **In-threat-model?** No — this is a scope-of-claim problem, not a cryptographic attack. The construction should either scope the claim to the actual implementation width and demonstrate why BBS+ fails there, or expand the implementation to the large-permission-space scenario the theorem is designed to cover.


## Persona: spiffe_engineer

### Attack 1: ZK Attestor Plugin — Layer, Don't Fork the Protocol

- **Attack:** SPIRE exposes a plugin interface for node attestation (`NodeAttestor`, `WorkloadAttestor`). A ZK attestor plugin could issue X.509 SVIDs whose SAN extensions carry only `commit(b) = H(b, r)` rather than `b` itself. The workload then runs the ZK circuit locally and presents `(proof, commit, m)` to the RS. SPIRE never sees `b`; the proof-of-commitment is self-verified. This is architecturally identical to what Section 4 describes, but it rides inside the SPIFFE trust envelope — existing SPIRE federation, TTL rotation, and SVID revocation all still apply. Where, precisely, does Theorem 3 invalidate this design?

- **Why it works / why it fails:** Theorem 3's proof sketch covers entities that *produce a verifiable assertion* — it argues that some entity must observe `b` to sign a statement `P(b,m) = true`. But in the ZK-attestor-in-SPIRE variant, *no entity asserts* `P(b,m) = true`; the workload self-certifies via a computation-integrity proof, exactly as Bolyra does. Theorem 3 does not distinguish between a free-standing protocol and the same mechanism hosted inside a SPIFFE-named credential shell. The construction does not explain why this layering fails or what SPIFFE invariants prevent it.

- **In-threat-model?** No — the construction must address this. The adversarial-AS claim does not survive if the same ZK predicate mechanism can be retrofitted as a SPIRE attestor plugin, because it means Bolyra is a deployment configuration choice, not a structural impossibility result. Section 8 Failure 1 must explain why the SPIFFE extension path is architecturally blocked, or the "no future OAuth/SPIFFE extension can fix it" claim is overreached.

---

### Attack 2: WIMSE Holder-Binding Already Achieves AS-Blind Presentation

- **Attack:** WIMSE `draft-ietf-wimse-arch` (Section 6, "workload identity token exchange") allows a workload to obtain a sender-constrained access token and present it to an RS without an AS roundtrip. The workload holds a private key, the token binds to that key via DPoP or MTLS-confirmation, and the workload chooses which token to present at request time. This is the construction's "agent chooses what to disclose at the moment of use" scenario. The AS issues the token once; all subsequent RS presentations are AS-blind. Why is Bolyra's construction not simply WIMSE with a ZK-valued `cnf` (confirmation) claim?

- **Why it works / why it fails:** Theorem 3's proof covers this: the WIMSE AS still observes the full `b` when it signs the sender-constrained token — holder-binding changes *who presents* but not *what the AS knew at issuance*. The corollary on suppression resistance (Section 4) correctly holds: the WIMSE AS can still choose to emit `b' ⊂ b` in the token, and the RS has no proof that `b'` faithfully reflects the actual permission set. However, the construction's Section 8 proof-sketch does not cite WIMSE by name, only RFC 8693 (token exchange). A WIMSE co-author reading this would immediately note the gap and argue the impossibility result was not proven against holder-binding specifically.

- **In-threat-model?** Yes — Theorem 3 structurally covers WIMSE holder-binding, but the construction must explicitly name WIMSE in the proof sketch enumeration (Section 4) or the claim that "no future OAuth extension can fix it" is empirically falsifiable by anyone who reads `draft-ietf-wimse-arch`.

---

### Attack 3: The Adversarial-AS Threat Model Is Inapplicable to the Stated Enterprise Scenario

- **Attack:** The construction's Scenario 2 is "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." For a Fortune 500 running SPIRE in-cluster, the AS *is* internal infrastructure — the threat model of an adversarial AS is equivalent to "your own SPIRE server lies to your own RS." That is not a workload identity threat; it is an insider threat or supply-chain compromise of your control plane. SPIFFE solves the adversarial-AS model differently: the RS independently verifies the SVID against the SPIFFE trust bundle it fetched out-of-band. Theorem 3 is an information-theoretic result, but information-theoretic results are only relevant when the threat model includes the party who holds the information as adversarial. The construction does not scope this clearly.

- **Why it works / why it fails:** The adversarial-AS model is legitimately novel for multi-tenant SaaS or cross-organization agent delegation — cases where you *cannot* trust the AS because it belongs to another party (e.g., an AI-agent marketplace operator issuing permissions on behalf of a human). But the construction conflates this narrow valid case with the general enterprise scenario. SPIFFE federation across trust domains gives you RS-side verification against a foreign trust bundle without trusting the foreign AS on any individual assertion — which partially addresses the semi-trusted-AS case without ZK.

- **In-threat-model?** Yes — the construction survives in the multi-tenant / cross-org case, but it must sharply delineate where SPIFFE federation is sufficient versus where Theorem 3's impossibility bites. The current draft does not draw this line. Section 8's summary table should include a "SPIFFE federation" row or the applicability claim is too broad.

---

### Attack 4: The 8-Bit Circuit Contradicts the 2^64 Scalability Claim

- **Attack:** Scenario 1 in the candidate states "regulated agent with 2^64 permission space where AS-side policy tables do not scale." Theorem 3 is stated over an arbitrary bitmask `b`. But `AgentPolicy.circom` is a fixed 8-bit circuit (`circuits/src/AgentPolicy`). A 2^64 permission space requires a 64-bit circuit — a different trusted setup, different `.zkey`, different Solidity verifier. The construction claims constant-size proof "regardless of bitmask width" but the circuit width is parameterized at compile time, not at proof time. Changing permission space width requires a new ceremony. In SPIFFE terms: SPIRE path-based identity encodes arbitrarily rich permission structure in the URI path, requires no trusted setup, and is O(1) rotation via X.509 TTL. What is the concrete circuit-level mechanism for width-independence and where is the trusted setup story for widths > 8?

- **Why it works / why it fails:** The ZK predicate proof is computationally constant-size *for a fixed circuit*, but "constant-size regardless of bitmask width" is only true if the circuit template is parameterized and compiled to multiple widths — each needing its own ceremony. The construction does not address multi-width ceremony management. The 2^64 scenario is therefore either aspirational (not yet implemented) or requires a universal circuit (e.g., PLONK with a RAM gadget), which is not what `AgentPolicy.circom` is. This is an implementation gap that undermines Scenario 1.

- **In-threat-model?** No — the construction must either (a) clarify the claim is "constant-size for a fixed permission width" rather than "regardless of width," (b) describe a universal circuit design that supports variable-width bitmasks without per-width ceremonies, or (c) retire Scenario 1 until the 64-bit circuit exists. As written, the 2^64 scenario is a paper claim with no circuit artifact behind it.
