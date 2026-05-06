# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Deferred audit is post-breach, not pre-breach

- **Attack:** The construction's three latency modes are misrepresented as enforcement. "Pre-authorized scope commitments (~200ms)" requires knowing the full agent graph before pipeline start — so it only works for static, pre-declared pipelines. For dynamic AI pipelines (§2.4's own scenario), the deferred mode applies: ChainAuditProof generated post-pipeline at ~4.8s. This means scope violations are detected **after the pipeline completed and the tool calls executed**. An agent that exceeded its mandate already wrote to the database, called the external API, or exfiltrated the document. Auth0's approach issues a scoped token at delegation time, before any action — enforcement is temporal, not forensic.

- **Why it works / why it fails:** The construction conflates auditability with enforcement. The claim says "auditor verifies that no hop exceeded its mandate" — but in the AI pipeline scenario, the audit happens after the damage. The construction must distinguish between (a) pre-execution scope enforcement and (b) post-execution audit trails. It currently conflates both and calls them "concrete latency solutions."

- **In-threat-model?** **No.** §2.4 must clarify which mode applies to which threat. Deferred audit does not substitute for pre-execution enforcement. The 200ms pre-auth mode must explicitly address how it handles mid-pipeline scope expansion (e.g., a tool that requests elevated permissions at runtime).

---

### Attack 2: The on-chain governance registry is enterprise poison

- **Attack:** C14 requires `Poseidon2(pk_reg.x, pk_reg.y) === regKeyCommitment` against an **on-chain governance registry**, and the regulator must publish `PoK(sk_reg)` via EdDSA. Procurement's question: "Where does our key live?" Answer: on a blockchain your enterprise doesn't control, governed by a protocol you can't SLA-bind, operated by a solo founder. Auth0 stores `pk_reg` equivalent in a SOC 2 Type II certified key management system with 99.99% SLA, audit logs queryable via API, and a 200-person support org. The transparency log binding (designed to prevent adversarial-AS key substitution) introduces a liveness dependency on a permissionless external system that enterprise infosec will reject on day one.

- **Why it works / why it fails:** The construction's security argument for C14 is sound at the cryptography level. It fails at the procurement level. "On-chain" means a different threat model for enterprise IT: key rotation requires a blockchain transaction (latency, gas costs, governance vote?), key compromise requires a hard fork or registry migration, and the audit trail lives outside your SOC 2 boundary. WorkOS handles this entirely within their SOC 2 perimeter with standard certificate rotation.

- **In-threat-model?** **No.** The construction must offer an off-chain registry mode (e.g., a CT-log-style append-only log operated by the customer or a trusted HSM provider) without compromising the `pk_reg` binding guarantee. Alternatively, it must explicitly scope the on-chain registry to the regulatory niche and present a different architecture for enterprise deployments.

---

### Attack 3: Bitmask lattice doesn't model real enterprise permissions

- **Attack:** §2.1 defines scope as a join-semilattice over **cumulative bitmasks** with tier implications. Real enterprise AI tool permissions aren't bitmask-decomposable. A tool might have permission "read Salesforce records where owner == caller AND deal_stage == 'Closed Won' AND revenue > $500K" — this is a predicate, not a bit. Auth0 Fine-Grained Authorization and WorkOS FGA both handle arbitrary RBAC/ABAC permission models. The construction's narrowing predicate `C_narrow` (bitwise subset + tier implications) enforces monotonic narrowing over a flat lattice — but the claim is about AI agent pipelines in §2.4, where permissions are contextual, parameterized, and often non-monotonic (a delegatee might have broader read access but narrower write access than the delegator).

- **Why it works / why it fails:** Game 1 (NARROW-FORGE) is a clean soundness argument for the bitmask model. But a buyer-level question is: "Can I represent my actual permission model in your lattice?" If the answer requires encoding ABAC predicates as bitmask tiers, the integration complexity explodes, and the onboarding story ("first, enumerate all your permissions as bits") is worse than Auth0's dashboard. The gap-to-close explicitly calls for "formal semantics of narrowing proof" — the current bitmask construction doesn't close this gap for non-lattice permission models.

- **In-threat-model?** **No.** The construction must address how parameterized permissions (content-filtered, context-dependent) are encoded in the lattice, or explicitly bound the claim to permission models that are bitmask-representable and acknowledge the limitation.

---

### Attack 4: Phantom hops leak chain topology to a side-channel adversary

- **Attack:** C8 uses dummy slots to hide chain length, and the construction claims "phantom hops are proven harmless" via C3 narrowing + C5 chain-linking. But the circuit has a **fixed max chain length N** — this is a public circuit parameter. A network adversary watching proof sizes and verification times learns: (a) the pipeline used a circuit of capacity N, bounding chain length to [1, N], and (b) the proof generation time correlates with real vs. dummy hop ratio (phantom hops still execute Poseidon2 in-circuit but with different constraint density). More concretely: in the journalist/source agent chain scenario (§C3 scenarios), an adversary who knows that the journalist's tool pipeline always uses N=4 circuits, and who observes that a specific proof was generated with an N=8 circuit, learns that the chain has >4 hops — narrowing the anonymity set. This is a classic padding oracle analogue.

- **Why it works / why it fails:** Session-unlinkability (Game 3, `blindedChainDigest`) prevents cross-session correlation but does not address within-session topology leakage from the circuit parameterization itself. The construction must argue that N is either (a) fixed globally (all proofs use the same N, eliminating the side channel at the cost of efficiency) or (b) randomly sampled from a public distribution such that observed N reveals no information about actual chain length.

- **In-threat-model?** **Partial.** The construction's unlinkability game addresses cross-session correlation but not intra-proof topology leakage via circuit size. For the journalist/whistleblower scenario specifically, this is a meaningful gap that the write must address.


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The construction has more scaffolding than most, but scaffolding is not a proof.*

---

### Attack 1: Nullifier Universe Enumeration Against Small Populations

**Attack:** In a credit union context, the enrolled population N is small — often hundreds to low thousands. The `chainNullifier` must be derived from participant-side inputs (delegator key, scope_id, or similar) that the Audit Server (AS) can observe indirectly via the transparency log. The construction's Game 3 (SCOPE-EXTRACT) argues cross-session advantage is computationally bounded by the blinding: `blindedChainDigest = Poseidon2(chainNullifier, Σblinding)`. But the adversary doesn't need to invert Poseidon2 — it only needs to determine *which* of N possible chainNullifiers produced a given proof. The adversary precomputes `Poseidon2(chainNullifier_k, *)` for all k ∈ [N], then runs a distinguishing game over external proof metadata (circuit-specific wire commitments, verifier transcript shape). If ANY public wire in the PLONK transcript leaks correlation to chainNullifier identity before blinding is applied, the brute-force succeeds in O(N · polylog) time, not exponential.

**Why it fails or survives:** The construction never specifies what `chainNullifier` is derived from, only how it is blinded. If chainNullifier = Poseidon2(sk_delegator, epoch), and sk_delegator is never revealed, the universe brute-force requires inverting Poseidon2, which holds under ROM. But if chainNullifier includes any public input (scope tier level, latticeRoot, regKeyCommitment), the universe collapses from cryptographic to demographic.

**In-threat-model?** No — construction must specify chainNullifier's derivation inputs and prove that no public circuit wire is correlated with pre-blinding nullifier identity. Game 3 as stated does not bound this leakage.

---

### Attack 2: Bitmask Lattice Soundness Without a Formal Reduction

**Attack:** §2.1 defines the scope lattice as a join-semilattice over "cumulative bitmasks with tier implications." `C_narrow` checks two things jointly: (a) bitwise subset `B_{i+1} ⊆ B_i` and (b) tier implication `T_{i+1} ≤ T_i`. These are stated as a conjunction, but they are algebraically independent predicates over different domains. An adversary constructs a delegation chain where: B_{i+1} passes the bitwise check (it is a proper subset), but T_{i+1} encodes a higher-privilege tier that is implied by the bitmask assignment rules — exploiting any gap between the bitmask interpretation and the tier encoding. Concretely: if tier is encoded as the Hamming weight of the bitmask, and the adversary finds two bitmasks B, B' with B' ⊂ B but popcount(B') > popcount(B) (possible if bits encode non-uniform privileges), `C_narrow` may accept while scope monotonicity is violated in the semantic domain.

Game 1 (NARROW-FORGE) "states soundness over this predicate" — but stating a game is not proving it. The reduction must show that any PPT adversary winning NARROW-FORGE can be used to break a named hardness assumption. This reduction sketch is absent.

**Why it fails or survives:** If the bitmask-to-tier mapping is injective and monotone-preserving (i.e., B' ⊂ B implies tier(B') ≤ tier(B) by construction), the attack fails. But the construction calls these "tier implications" as if they are additional rules layered on top of bitmask order — which implies they are *not* already captured by bitmask subset, meaning the conjunction can be gamed at the seam.

**In-threat-model?** No — construction must provide the NARROW-FORGE reduction to a named assumption, and must prove that the bitmask domain and tier domain are jointly monotone with no exploitable gap.

---

### Attack 3: ZK Simulator Existence Under Deployed SRS

**Attack:** SE-PLONK (Maller et al. 2019, blinding polynomial technique) provides zero-knowledge and simulation-extractability. The ZK property requires a simulator that, given the SRS trapdoor τ, produces indistinguishable transcripts without the witness. The construction claims "Game 4 reduction uses SE-PLONK against malicious verifiers in Scenario B" — the journalist/source scenario where the auditor must learn nothing about intermediate nodes.

Here is the problem: in any real deployment, τ is destroyed after the trusted setup ceremony (or derived from a universal SRS via randomized polynomial commitment). If the auditor IS the adversary (malicious verifier, Scenario B), the simulator needs τ to produce fake proofs. But if τ is gone, the standard ZK simulator cannot run. The construction must use a *straight-line* ZK property (ZK without the trapdoor, via statistical hiding or rewinding-free simulation) — which SE-PLONK does not provide in its standard formulation.

More precisely: SE-PLONK achieves ZK under the *honest* SRS assumption and provides extractability under malicious provers. The combination of malicious verifier ZK + SE-PLONK requires a non-standard composition argument that is absent here.

**Why it fails or survives:** If the construction uses a universal SRS (e.g., KZG over a trusted ceremony with N participants) and the auditor contributes to the ceremony, τ is never reconstructible by the auditor alone — so the standard ZK simulator cannot be run by the auditor either. This is circular and does not constitute a ZK proof. The construction must either: (a) use statistical ZK (not SE-PLONK), (b) restrict Scenario B to honest-verifier ZK with a separate argument for unlinkability, or (c) provide a rewinding-free simulator construction.

**In-threat-model?** No — the ZK claim against malicious verifiers requires a simulator that the construction does not specify. "SE-PLONK" is not sufficient justification without addressing trapdoor availability.

---

### Attack 4: Workload Attestation Freshness and Post-Pipeline Proof Forgery

**Attack:** C8 binds `workloadAttestation[i] = Poseidon2(delegateeCredCommitment, workloadNonce)`. §2.4 mode (a) specifies that ChainAuditProof is generated *post-pipeline* at ~4.8s. SPIFFE SVIDs are short-lived X.509 certificates (default TTL: 1 hour, sometimes 5 minutes in hardened deployments). TPM quotes are nonce-bound but the nonce is chosen by the challenger — not by the circuit.

The attack: an adversary compromises a pipeline participant *after* the pipeline completes but *before* the ChainAuditProof is generated. Using the compromised key, the adversary generates a fresh SPIFFE SVID (or requests a new TPM quote with a workloadNonce of its choosing) and substitutes it into the delegateeCredCommitment for hop i. Since ChainAuditProof is generated post-hoc, the circuit has no binding to the *actual* SVID active during the pipeline execution — only to whatever credCommitment is presented at proof-generation time. This is a post-compromise scope laundering attack: a hop that exceeded its mandate at runtime can present clean credentials at audit time.

**Why it fails or survives:** The attack is blocked only if `workloadNonce` is derived from a value committed to *during pipeline execution* and verifiably logged (e.g., a signed timestamp from a distributed ledger entry made at hop execution time). The construction does not specify how workloadNonce is chosen or whether it is bound to an immutable execution log. "Poseidon2(delegateeCredCommitment, workloadNonce)" is a commitment, not a proof of freshness.

**In-threat-model?** No — post-pipeline proof generation in mode (a) creates a window for credential substitution. The construction must either: (a) commit workloadAttestation during execution with a verifiable timestamp, (b) restrict mode (a) to scenarios where SVIDs are long-lived and revocation is checked in-circuit, or (c) formally define the post-compromise security game and show workloadNonce is bound to an execution-time anchor the adversary cannot control retroactively.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Is a Black Box My Examiner Cannot Read

- **Attack:** During an NCUA Part 748 examination, the examiner asks for evidence that delegated AI agents operated within authorized scope during the past quarter. I hand them a `ChainAuditProof` — a Groth16/PLONK proof blob and a Poseidon2 hash chain. The examiner asks: "Who verifies this? How do I know the verifier is correct? Is there a third-party attestation of the verifier itself?" The construction (§2.4, deferred offline audit mode) produces a cryptographic artifact, but nowhere does it specify the examiner-facing interface — who runs the verifier binary, how that binary is audited, whether there is a SOC 2 Type II report on the verification service, or whether the output can be reduced to a human-readable assertion (e.g., "Agent X did not exceed scope Y during window Z").

- **Why it works / why it fails:** NCUA Part 748 Appendix B requires an "appropriate audit trail" for access controls. The construction proves the narrowing property but produces no artifact that translates the proof into plain-language compliance evidence. An NCUA examiner is not going to run `snarkjs verify`. The construction is silent on the verification infrastructure layer — who certifies the verifier, under what standard.

- **In-threat-model?** No — construction must address. Needs a verifier attestation layer (e.g., SOC 2-scoped verification service, or a deterministic open-source verifier with reproducible builds), plus an examiner-facing report format that reduces proof output to auditable assertions.

---

### Attack 2: Root Delegation Key Custody Is Unspecified — If It's a Browser, You've Lost Me

- **Attack:** C8 binds intermediate hop identity to SPIFFE SVIDs and TPM quotes for workload nodes. Good. But what about the member's root delegation key — the `sk` at the apex of the chain that authorizes the first hop? The construction never specifies where this lives or what custody model governs it. In the AI pipeline scenario, a member (or the credit union acting on their behalf) must hold a signing key to initiate the delegation chain. If that key is in the browser (WebCrypto, localStorage, or a browser extension), I have a GLBA Safeguards Rule §314.4(f) problem: authentication credentials are in an uncontrolled endpoint. If it's in a HSM, who manages the HSM, under what key ceremony, with what M-of-N policy?

- **Why it works / why it fails:** The construction's formal guarantees (NARROW-FORGE soundness, session-unlinkability) are mathematically tight but operationally inert if the root key is compromised before it ever enters the circuit. The GLBA Safeguards Rule requires the credit union to "develop, implement, and maintain" administrative, technical, and physical safeguards — a browser-resident root key satisfies none of these. The construction outsources this problem to the deployer without acknowledging the gap.

- **In-threat-model?** No — construction must address. Needs a key custody specification for the chain root: at minimum, a threat model section covering HSM, browser, and mobile wallet custody options with GLBA/FFIEC CAT mapping for each.

---

### Attack 3: Privacy Guarantee Inverts Into Incident Response Liability

- **Attack:** An AI agent in the pipeline executes an unauthorized wire transfer referencing a member account. Incident response begins. My Tier 1 ops team escalates. I need to answer three questions for the board and the NCUA: (1) Which hop in the chain authorized this action? (2) What scope did that hop believe it had? (3) Can I revoke just that hop without tearing down the whole chain? The construction's core privacy guarantee — "auditor verifies narrowing without reconstructing intermediate scopes or participants" — is precisely the property that makes these questions unanswerable in real time. The journalist/source scenario (Construction §2.1, Scenario B) is explicitly designed to hide intermediate participants from the auditor. In a credit union incident, I am the auditor, and I need to un-hide.

- **Why it works / why it fails:** The construction conflates the regulatory auditor (who wants aggregate assurance) with the incident responder (who needs forensic granularity). For whistleblower chains, hiding participants from the auditor is a feature. For financial services incident response, it is a FFIEC CAT Domain 5 failure — specifically, the inability to perform "forensic analysis of an incident." The construction offers no escape hatch: a break-glass mode where the credit union (not the regulator) can recover intermediate scope assertions under a documented legal hold.

- **In-threat-model?** No — construction must address. Needs a tiered disclosure model: ZK for routine regulatory audit, escrow-based recovery for incident response, with a documented legal hold procedure and vendor cooperation SLA.

---

### Attack 4: On-Chain Registry Availability Is Not My Core Processor's SLA

- **Attack:** C14 verifies `regKeyCommitment` against an on-chain governance registry. The registry is on a public or permissioned blockchain. I ask: what is the P99 availability of that registry over the past 12 months? What is the RTO/RPO if it goes down? The construction's §2.4 deferred offline audit mode (~4.8s) addresses proof generation latency but says nothing about registry availability during proof generation or verification. If the on-chain registry has a 1% outage budget — 87 hours per year — that exceeds the availability guarantee of my Fiserv core processor contract (99.95%). My Vendor Management Policy requires third-party systems in the critical path to meet or exceed my core processor SLA. An on-chain registry with consensus-layer dependencies does not have a contractual SLA I can present to my board or my NCUA examiner.

- **Why it works / why it fails:** NCUA examiners reviewing third-party risk (Part 748, FFIEC IT Examination Handbook on outsourcing) ask for vendor contracts with defined SLAs, business continuity provisions, and right-to-audit clauses. A public blockchain has none of these. The construction's pre-authorized scope commitment mode (~200ms, §2.4c) might partially mitigate runtime dependency, but the pre-authorization still requires a registry write at setup time — which is also availability-constrained.

- **In-threat-model?** No — construction must address. Needs either (a) a permissioned registry with a contractual SLA and defined failover, (b) a cache/fallback mechanism that degrades gracefully to pre-authorized commitments with documented security assumptions during outage, or (c) an explicit availability threat model section that maps registry SLA to FFIEC CAT maturity levels.


## Persona: rfc7662_advocate

### Attack 1: Per-RS Introspection Policy + RFC 8693 `act` Claim Subsumes the Narrowing Proof

- **Attack:** RFC 8693 §4.1 defines the nested `act` claim precisely to represent delegation chains. Each hop calls the AS to exchange the current token for a narrower-scoped successor via Token Exchange; the AS logs the full chain internally. For audit, the AS issues a signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response) attesting `act`-chain monotonic narrowing. The AS strips intermediate `act` nodes from responses sent to RS-facing parties but hands the full signed chain to the auditor directly. No ZK required. The auditor trusts the AS signature, exactly as they would trust the construction's `pk_reg` commitment in C14.

- **Why it works / why it fails:** The construction's C14 anchors `pk_reg` to an on-chain governance registry and requires `PoK(sk_reg)` via EdDSA — but the auditor's root of trust is still a key published by the regulatory authority. If that key is trusted, a signed JWT introspection response chain signed by the same authority is *equi-trusted*. The construction does not argue that the transparency log provides stronger guarantees than an AS-signed JWT; §2.1 and C3 prove narrowing in-circuit but never compare this to the AS-signed baseline's trust properties.

- **In-threat-model?** No — the construction must explicitly argue why AS-signed attestation of scope narrowing is insufficient. The only load-bearing distinction would be if the AS itself is adversarial (it could lie in its signed response). The construction does not name "malicious AS" as a threat actor in Game 1 (NARROW-FORGE) or Game 3 (SCOPE-EXTRACT).

---

### Attack 2: DPoP Sender-Constraint Covers the Phantom-Hop Problem Without ZK

- **Attack:** The construction's C8 workload attestation uses `Poseidon2(delegateeCredCommitment, workloadNonce)` to bind real hops to SPIFFE SVIDs/TPM quotes and proves phantom (padding) hops are "harmless." The claimed property is that a verifier cannot inject a phantom hop that expands scope. But RFC 9449 DPoP already sender-constrains each token to a specific key pair at issuance. A phantom hop that injects a DPoP-bound token it did not generate cannot present a valid DPoP proof of possession — the AS rejects the exchange. Scope expansion via phantom insertion is blocked at the AS token exchange layer, not in-circuit.

- **Why it works / why it fails:** The construction counters this only implicitly: C5 (chain-linking) + C3 (narrowing) together are claimed to prevent scope expansion even for phantom slots. But the circuit's soundness in this case depends on the prover being honest about which slots are phantom. The construction does not specify how the verifier distinguishes a real hop with a revoked credential from a phantom slot — if both produce a "harmless" commitment, a colluding prover can downgrade a real adversarial hop to a phantom, effectively hiding it from the auditor. DPoP's AS-enforced sender constraint catches this because the AS *sees* every real exchange.

- **In-threat-model?** Yes — the construction survives if C8's workload nonce is AS-issued and verifiable against a public log. But this is not stated in the construction; §2.4 and C8 treat workload attestation as prover-supplied. The construction must specify whether workloadNonce is AS-issued or self-attested, and close the gap if self-attested.

---

### Attack 3: PPID + RFC 8707 Resource Indicators Already Breaks RS-Level Linkability; AS-Side Advantage Is Not Load-Bearing

- **Attack:** OIDC Pairwise Subject Identifiers (PPID, Core §8.1) give each RS a different `sub` value for the same user. RFC 8707 resource indicators bind tokens to specific `resource` URIs, preventing cross-RS token replay. Combined, no RS in the delegation chain can link a user's activity across other RSes. The construction's C10 session unlinkability (Game 3, SCOPE-EXTRACT, `blindedChainDigest = Poseidon2(chainNullifier, Σblinding)`) is presented as novel. The adversary asks: what linkability does C10 prevent that PPID+RFC 8707 does not?

- **Why it works / why it fails:** PPID+RFC 8707 breaks RS-to-RS linkability. C10 claims to break *cross-session* correlation even for an auditor holding multiple proofs for the *same* chain. But the construction's Scenario A (AI pipeline) requires the auditor to verify the *same* chain across sessions — C10's `blindedChainDigest` makes same-chain proofs "computationally independent across sessions." This means the auditor cannot confirm audit continuity (that session 2's proof covers the same chain as session 1's). The construction does not provide a chain identity handle that is unlinkable to the auditor but linkable to a compliance officer — a property that requires more than blinding and that RFC 9449 + PPID cannot provide, but that the construction also does not cleanly provide.

- **In-threat-model?** Partial — C10 provides a real property (cross-session auditor unlinkability) that PPID+RFC 8707 cannot. But the construction must formally separate "RS-level linkability" (already solved by OIDC) from "auditor cross-session linkability" (the genuine novel claim) and prove C10 provides the latter without breaking audit continuity for the *compliance auditor* role.

---

### Attack 4: Journalist/Whistleblower Scenario Collapses Under Legal Compulsion of AS or Infrastructure Operator

- **Attack:** Scenario B requires intermediate nodes to stay hidden *from the auditor*. The construction addresses this with SE-PLONK (Game 4, §A2, simulation-extractability). The ZK proof hides intermediate participants from the verifier's view of the proof transcript. But the construction's workload attestation in C8 uses SPIFFE SVIDs and TPM quotes — infrastructure-level identifiers issued by a SPIFFE control plane or TPM manufacturer. These identifiers are *known to the infrastructure operator* (the organization running the service mesh). RFC 8693 token exchanges for each hop are logged at the AS. Neither the AS logs nor the SPIFFE control plane are within the ZK boundary. An auditor with subpoena power over the AS or infrastructure operator retrieves the full chain without breaking the ZK proof.

- **Why it works / why it fails:** The construction's threat model (implicit in Game 4) appears to assume an honest-but-curious auditor who only sees the proof transcript. It does not model a *legally coercive* auditor who can compel the AS or infrastructure operator. SE-PLONK's simulation-extractability protects against a *malicious verifier* who deviates from the protocol — it does not protect against an adversary who bypasses the protocol entirely via legal process. For the journalist/whistleblower scenario to hold, the construction must either (a) require that intermediate nodes operate with no SPIFFE/TPM registration visible to any operator, which conflicts with C8's binding requirement, or (b) explicitly scope the threat model to protocol-level adversaries only and disclaim protection against infrastructure-level coercion.

- **In-threat-model?** No — the construction must either acknowledge this threat model boundary explicitly or add an infrastructure anonymity layer (e.g., anonymous credentials at the SPIFFE layer) to C8. As written, C8 and Scenario B are in tension.


## Persona: spiffe_engineer

> *"You're hashing an SVID into a circuit and calling it a protocol. I run SPIRE at 40k workloads. Let me show you where this breaks."*

---

### Attack 1: SPIRE Has a Plugin Boundary — You Crossed It Without Justification

- **Attack:** C8 requires `workloadAttestation[i] = Poseidon2(delegateeCredCommitment, workloadNonce)` bound to SPIFFE SVIDs and TPM quotes. SPIRE's architecture exposes a **node attestation plugin interface** (NodeAttestor gRPC interface). A ZK narrowing proof is a node attestor artifact — it attests a property of the workload at registration time and can be embedded as an X.509 SVID extension or custom SPIFFE ID path segment. The construction builds a parallel attestation pipeline *outside* the Workload API entirely, requiring deployers to run two attestation systems for the same workload. The adversary writes a SPIRE ZK-attestor plugin in ~400 lines that calls the prover sidecar, returns the commitment, and the SPIRE server issues a standard SVID with the `narrowingRoot` extension. Zero new protocol.

- **Why it works / why it fails:** The construction's §2.4 three-mode latency solution (deferred, IVC fold, pre-authorized) all assume a standalone prover separate from SPIRE. The plugin path collapses deferred and pre-authorized modes into normal SVID issuance latency (~10ms). The construction never justifies why a plugin is architecturally insufficient — it just assumes the prover is out-of-band.

- **In-threat-model?** **No** — the construction must explain why narrowing proofs cannot be SPIRE attestor plugin outputs. If they can, the "new protocol" claim evaporates. The construction must either show a property SVID extensions cannot carry (e.g., the multi-hop chain digest that spans trust domains) or contribute a plugin spec instead of a standalone construction.

---

### Attack 2: WIMSE Token Exchange Already Has Delegation Semantics — Where Is the Gap?

- **Attack:** `draft-ietf-wimse-arch` §6 defines **workload-to-workload token exchange**: a workload presents a WIT (Workload Identity Token), exchanges it at a token service for a scoped downstream token, and the downstream token carries the delegation chain in a `wia` claim. The scope lattice in §2.1 of the construction maps directly to WIMSE scope restriction: each exchange can only reduce the `scope` claim set, which is monotonic narrowing by token-exchange policy. The adversary proposes a WIMSE profile extension: add a `narrowing_commitment` claim carrying `Poseidon2(scope_bitmask)` and a batch verifier at the audit endpoint. This is a WIMSE contribution, not a new protocol. The journalist/source scenario (Scenario B) maps to WIMSE's `private_claims` extension, currently in-scope for the WG.

- **Why it works / why it fails:** The construction's Session B gap claim says "intermediate nodes must stay hidden from auditor." WIMSE token exchange *does* reveal intermediate token issuers to the token service. The ZK construction hides intermediates from the auditor *and* the token service. This is a real gap — but the construction doesn't state it. It just asserts the construction is "usable beyond narrow regulatory niches" without positioning against WIMSE at all.

- **In-threat-model?** **Partially.** The hiding-from-token-service property is a genuine gap WIMSE cannot close today. But the construction must name this explicitly (§1 or the gap-to-close field) and show that the WIMSE WG cannot add a blind-token-exchange mode. Failing to engage with WIMSE makes the construction look unaware rather than deliberately differentiated.

---

### Attack 3: Phantom Hop SPIFFE Binding Creates a Real-vs-Phantom Confusion Attack

- **Attack:** C3 narrowing + C5 chain-linking are claimed to make phantom hops "harmless" (§2 construction note on workload identity binding). But phantom hops by construction carry no real SPIFFE SVID — they are dummy slots with fabricated commitments. The attack: the adversary controls an intermediate SPIRE instance in a federated trust domain. They register a **real workload** with a SPIFFE ID `spiffe://attacker.example/phantom-slot-7` whose credential commitment collides (or is made to match via commitment malleability) with the phantom slot's `workloadAttestation[i]`. Post-audit, the adversary claims phantom slot 7 was actually their real workload — retroactively injecting a participant into the chain. The auditor cannot distinguish "always-phantom" from "phantom that became real" because C8's binding uses `Poseidon2(delegateeCredCommitment, workloadNonce)` and the workload nonce is never bound to the SPIRE issuance timestamp or certificate serial.

- **Why it works / why it fails:** The construction states phantom hops are "proven harmless: C3 narrowing + C5 chain-linking prevent scope expansion even with phantom workloads." This only proves scope can't expand — it does not prove participant identity is fixed at proof generation time. A SPIRE federation admin can register a new workload retroactively. There is no temporal binding between the circuit's `workloadNonce` and the SPIRE server's SVID issuance log.

- **In-threat-model?** **Yes, and the construction must address it.** Fix: bind `workloadAttestation[i]` to `Poseidon2(svid_serial_number, issuance_unix_epoch, delegateeCredCommitment)` with the epoch as a public input anchored to the proof timestamp. Phantom slots use a canonical null serial (`0x00...00`) that the circuit constrains to never appear in real SPIRE CA logs. This closes the retroactive injection path.

---

### Attack 4: C10 Session Unlinkability Is Defeated by SVID Rotation Side-Channel

- **Attack:** C10 introduces `blindedChainDigest = Poseidon2(chainNullifier, Σblinding)` to make same-chain proofs computationally independent across sessions (Game 3, SCOPE-EXTRACT). But `workloadAttestation[i]` contains a hash over an SPIFFE SVID. SVIDs have short TTLs (SPIRE defaults: 1 hour for X.509, configurable to 5 minutes). The SPIRE CA issues SVIDs with sequential certificate serial numbers logged in the CA's audit trail. An auditor who is *also* a SPIRE operator (or subpoenas the SPIRE server) can enumerate SVID serials issued in a time window, compute `Poseidon2(serial, epoch, credCommitment)` for each, and match against the public `workloadAttestation[i]` values emitted in proofs. C10's blinding randomizes the *chain digest* but does not re-randomize the per-hop workload attestation commitments, which are deterministic given the SVID.

- **Why it works / why it fails:** The construction's unlinkability game (Game 3) models the adversary as having access only to the proof transcript. It does not model an adversary with *out-of-band SPIRE CA access* — a realistic adversary in enterprise deployments where the auditor is internal. The blinding in C10 protects cross-session chain correlation but not within-session workload deanonymization via CA side-channel.

- **In-threat-model?** **No** — and this is a significant scoping failure for the journalist/source scenario (Scenario B). If the adversary can correlate SVID serial numbers to proof commitments, the entire "intermediate nodes must stay hidden from auditor" claim collapses for any auditor with SPIRE CA access. Fix: either (a) randomize `workloadAttestation[i]` with a fresh blinding factor per session *before* hashing, or (b) explicitly exclude SPIRE-operator-level adversaries from the threat model and state this as a limitation.
