# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Latency Profile Kills the AI-Pipeline Use Case

- **Attack:** The construction claims <5s PLONK proving time, which it frames as an improvement over a baseline. But the primary scenario is a *multi-tool AI pipeline* — exactly the context where you need sub-100ms hop transitions. Auth0 MCP auth and WorkOS MCP auth issue tokens in <100ms. If each tool-call delegation hop requires a fresh proof, a 4-hop chain costs >20s of pure proof generation time before the model even executes. Real-world LangGraph/AutoGen deployments timeout at 30s per node. The construction is "fast for ZK" but catastrophically slow for the claimed use case.

- **Why it works / why it fails:** The construction's §proving-time section claims <5s as a win, but does not address *amortization across hops* or *streaming/pre-computation* strategies. It treats each proof as independent. If the auditor needs a proof per pipeline invocation, not per deployment, the latency compounds.

- **In-threat-model?** No. The construction must address: (a) whether proofs are per-invocation or per-deployment, (b) whether recursive aggregation collapses the 8-hop proof to a single verification, and (c) what the P50/P99 latency looks like under real hardware. Without this, the AI-pipeline scenario is marketing, not architecture.

---

### Attack 2: The 8-Hop Ceiling Is a Hard Spec Limiter With No Migration Path

- **Attack:** The circuit unrolls up to 8 delegation hops. This is a compile-time constant baked into the PLONK constraint system. Real enterprise AI pipelines (Salesforce Agentforce, ServiceNow AI agents, internal LangChain deployments) have dynamic, graph-shaped delegation — not linear chains. When a customer hits hop 9, what happens? You need a new circuit, a new trusted setup ceremony, a new verifier contract. OAuth scopes just add a `scope=` param. RFC 8693 token exchange adds a `chain` header. Neither requires a ceremony to extend.

- **Why it works / why it fails:** The construction does not discuss what happens at the boundary. BBS+ selective disclosure and RFC 8693 chaining are both *unbounded by design*. The 8-hop constant is an optimization artifact presented as if it were a feature. An enterprise procurement team reading this will immediately ask: "What is your upgrade path when we hit the limit?" The construction has no answer.

- **In-threat-model?** No. The construction must either (a) prove 8 hops is sufficient for all target scenarios with empirical data, (b) describe a recursive/folding construction (e.g., Nova/SuperNova) that makes the bound dynamic, or (c) explicitly scope the protocol to chains where N ≤ 8 is a design invariant. Currently it claims generality it doesn't deliver.

---

### Attack 3: The Auditor Model Is Incompatible With Regulatory Reality

- **Attack:** The construction's entire value proposition is that an auditor can verify monotonic narrowing *without reconstructing intermediate scopes or participants*. But NCUA examination procedures (the cited scenario) require examiners to see the actual delegation records — not a proof that they were valid. NCUA Examination Procedures §2100 requires loan origination audit trails to be *legible and reconstructible*. A ZK proof that "trust me, the chain was valid" is not a substitute for a discoverable record. The construction conflates "privacy-preserving auditability" with what regulators actually accept.

- **Why it works / why it fails:** Auth0's audit log, WorkOS's event stream, and Cloudflare Access's logging all produce human-readable, subpoena-able records. The construction produces a proof. In a regulatory examination, the examiner will ask for the underlying records, and "we have a ZK proof" will not satisfy that request. The journalist/source scenario is real, but it is not an enterprise buying center — it is a civil liberties edge case.

- **In-threat-model?** No. The construction needs a disclosure mechanism: a mode where the proof is accompanied by an encrypted payload that *only* the examiner (with a court order or regulatory authority) can decrypt. Without this, the NCUA scenario is a liability, not a feature. The current construction would actually *fail* a regulatory audit by design.

---

### Attack 4: Integration Surface Requires Custom Verifiers in Every Auditor Stack

- **Attack:** To consume a ChainAuditProof, an auditor must run a PLONK verifier. This means every audit tool — Vanta, Drata, Splunk, Datadog, ServiceNow GRC — must either (a) integrate a Bolyra verifier SDK, (b) trust a Bolyra-operated verification oracle, or (c) run a verification node. Auth0 MCP auth integrates via standard OAuth 2.1 + PKCE. WorkOS ships an MCP server you drop in. Stytch uses Dynamic Client Registration (RFC 7591). All three work with *zero* changes to the auditor's tooling. Bolyra requires the auditor to adopt new infrastructure before they can read a proof. The onboarding funnel is: learn ZK → run verifier → trust Poseidon parameters. That is worse than paste-an-API-key by at least two enterprise procurement cycles.

- **Why it works / why it fails:** The construction does not describe a verification API, a hosted verifier, or an SDK with a one-line integration path. It describes a circuit. There is a large gap between "we have a correct circuit" and "an auditor at SECU can click 'verify' in their existing GRC tool." The construction assumes the verifier deployment problem is solved; it is not.

- **In-threat-model?** No. The construction must specify: (a) the exact verifier integration surface (REST endpoint? WASM library? smart contract?), (b) who operates the verification infrastructure and what their trust assumptions are, and (c) how an auditor bootstraps trust in the verifier itself. Without this, the construction is a cryptographic result, not a product.


## Persona: cryptographer

I'm reading the construction description. Fixed-size PLONK circuit, 8 hops unrolled, four named security games with reductions to PLONK soundness and Poseidon collision resistance. Let me find the load-bearing assumptions the author glossed over.

---

### Attack 1: Fixed-Width Circuit Leaks Chain Length via Padding Distinguishability

- **Attack:** The circuit unrolls exactly 8 hops regardless of actual chain length. Shorter chains require dummy hops padded with sentinel values (zeroed scopes, null participants, or some placeholder). The adversary — the auditor — submits two delegation chains of length 3 and length 7, receives their proofs, and attempts to distinguish them. If dummy-hop slots use a fixed sentinel (e.g., `scope = 0`, `participant = H(0)`), the auditor can check: does the public commitment Merkle root, witness structure, or any public input to the PLONK verifier differ statistically between real and dummy slots? Alternatively, a timing side-channel: padding real slots with constraints identical to live slots costs the same compute, but if the prover short-circuits on zero-scope inputs, proof generation time leaks length.

- **Why it works / fails:** The "length extraction" game as described must bound the adversary's advantage over a 1/8 random guess. This requires that dummy-hop witnesses are *computationally indistinguishable* from real-hop witnesses — which requires dummy scopes to be drawn from the same distribution as real scopes (not zero). The construction must specify the dummy-hop generation procedure and prove it's indistinguishable. A natural fix (random dummy scope values) introduces a new problem: the monotonic narrowing check must still hold across dummy hops, constraining the distribution.

- **In-threat-model?** No — the length extraction game is named but the dummy-hop regime is not formally specified. The reduction to "PLONK soundness + Poseidon collision resistance" does not cover distinguishability of padding; that requires a separate ZK (simulatability) argument.

---

### Attack 2: Semantic Vacuousness of Bitwise-Subset Narrowing — Empty-Scope Bypass

- **Attack:** "Monotonic bitwise-subset narrowing" means `scope[i+1] & ~scope[i] == 0` (no bit set in child that isn't set in parent). The adversary is a malicious intermediate delegator at hop k who sets `scope[k] = 0b00000000`. This is a valid narrowing from any parent scope (empty set is subset of everything), and the circuit accepts it. Now every subsequent hop trivially satisfies narrowing (the empty set is a subset of the empty set). The full chain produces a valid `ChainAuditProof` in which every hop from k onward has zero permissions — yet the leaf agent was actually granted a *different* out-of-band scope not reflected in the chain, and the auditor sees a valid proof.

- **Why it works / fails:** This is not a cryptographic break of PLONK or Poseidon — it's a *semantic gap*. The narrowing forgery game must define what a "forgery" is: a proof that convinces the verifier of a false narrowing relation. But if the empty-scope delegation is syntactically valid, the prover is not lying. The construction must add a *liveness constraint* (e.g., `scope[i] != 0` for all non-dummy hops, or a minimum-scope floor enforced in-circuit). Without this, an adversary can always produce a trivially-valid audit proof that reveals nothing about actual capability flow.

- **In-threat-model?** No — the construction claims the proof is "usable beyond narrow regulatory niches" and covers AI agent pipelines where mandate enforcement is the core property. The empty-scope attack directly violates that. The narrowing forgery game must include a liveness predicate; without it, the game definition is under-specified.

---

### Attack 3: PLONK Trusted Setup Subversion — Auditor-as-SRS-Participant

- **Attack:** PLONK (specifically, the KZG-commitment variant) requires a structured reference string derived from a secret `τ`. If *any* participant in the SRS ceremony is the adversary — or if the adversary is a regulatory body (NCUA) that participated in or obtained `τ` — they can forge proofs for any circuit relation. Concretely: the adversary constructs a fake `ChainAuditProof` asserting that a 6-hop chain narrowed monotonically, when in fact hop 3 widened scope (a regulatory violation). The reduction to "PLONK soundness" holds only under an *honest* SRS; the construction must state this assumption explicitly and explain who runs the ceremony for the NCUA scenario.

- **Why it works / fails:** For the journalist/source scenario, the adversary is a government auditor who may have coerced an SRS participant. This is precisely the subverted-setup threat model. The construction's claim that it "beats the baseline on 6 structural properties that RFC 8693 + BBS+ fundamentally cannot provide" is weakened if the SRS is a single point of failure — BBS+ requires no trusted setup. The construction should either: (a) use a transparent setup (STARK-based or IPA-based polynomial commitment), (b) prove security under a subverted SRS (simulation-extractability survives partial subversion in some schemes), or (c) explicitly bound the trust assumption and argue it's acceptable for the NCUA case but *not* the journalist case.

- **In-threat-model?** Partially — the four security games reduce to PLONK soundness, but that reduction implicitly assumes an honest SRS. If the construction targets both regulatory and adversarial-auditor scenarios (as the gap-to-close requires), this assumption is load-bearing and must be surfaced as a named assumption, not buried in "standard PLONK security."

---

### Attack 4: Cross-Chain Correlation Attack on Participant Privacy via Scope-Narrowing Fingerprints

- **Attack:** The auditor observes *multiple* `ChainAuditProof` instances over time (realistic for a compliance auditor reviewing 1000 loan originations). Each proof hides intermediate participants but reveals the root commitment, the leaf commitment, and the final narrowed scope (at minimum, the verifier must see *something* to anchor the audit). The adversary mounts a statistical correlation attack: if intermediate agent A always narrows from scope `0b11001100` to `0b00001100`, and agent B always narrows from `0b11001100` to `0b11000000`, then across 50 proofs, the auditor observes two distinct narrowing *fingerprints* at the same depth position and infers two distinct intermediate participants exist — even without extracting their identities. In the journalist/source scenario, this partitions sources by their characteristic delegation patterns, potentially de-anonymizing them without breaking any single proof.

- **Why it works / fails:** The participant extraction game is defined for a *single* proof. It does not bound an adversary's advantage over *polynomially many* adaptively-chosen proofs. This is the standard gap between honest-verifier ZK (HVZK) and simulation-extractability (SE-ZK): HVZK simulatability holds proof-by-proof, but an adversary with auxiliary information from prior proofs can break privacy. The construction's ZK proof (PLONK is HVZK against the verifier) does not provide *multi-proof* unlinkability. A proper fix requires either: scope commitments randomized per-proof (requiring nonce freshness arguments), or a formal definition of the participant extraction game that quantifies over the adversary's entire view of the proof system across all invocations.

- **In-threat-model?** No — the construction describes the journalist/source scenario as a target use case, but the participant privacy game is not defined over an adaptive, multi-proof adversary. This is the hardest gap to close and the most damaging to the "whistleblower-safe agent delegation" claim. Without a simulation-based argument that holds under repeated proof submission, the participant privacy claim is only marketing.


## Persona: cu_ciso

---

### Attack 1: Hidden Participants = NCUA Vendor Access Log Gap

- **Attack:** NCUA Part 748 Appendix B §III.C requires the credit union to maintain audit logs documenting *who* accessed member data and *what* they did with it. The construction explicitly hides "all intermediate scopes, participants, and chain length from the auditor." I cannot satisfy my examiner's third-party risk questionnaire if I cannot name the entities in hops 2–7 of the loan pipeline chain. The construction proves that *narrowing occurred* but cannot prove that every hop was a properly vetted third party under my Vendor Management Policy. Hop 3 could be a foreign fintech with no GLBA agreement — the proof is silent.

- **Why it works / fails:** The construction's privacy guarantee is technically sound against a passive auditor but creates a structural compliance gap. NCUA examiners don't accept "trust the math" — they want a named entity, a contract, and an access log entry for every party that touched member PII. The zero-knowledge property is precisely what breaks this. The SECU loan pipeline scenario (referenced but not fully specified in the construction) would require the CU to separately maintain a *plaintext* participant registry — which defeats the confidentiality claim and introduces a second attack surface.

- **In-threat-model?** No. The construction must address: what does the auditor actually receive, and how does that map to NCUA's third-party entity identification requirement? A proof of monotonic narrowing over anonymous hops is not a substitute for a vendor access log.

---

### Attack 2: Incident Response — Privacy Guarantee Becomes Forensic Obstruction

- **Attack:** At 2am, a member reports fraudulent activity traced to the loan pipeline. My incident response team invokes GLBA §501(b) breach response and NCUA Part 748 Appendix B §IV notification obligations. Forensics need to reconstruct which delegated agent accessed which scope at which timestamp. The construction proves that the chain *was* well-formed at proof-generation time, but the proof hides participants and chain length. I cannot reconstruct the access chain post-incident. I hand my NCUA examiner a PLONK proof and ask them to accept it as an audit trail. They decline. I am now in a notification failure.

- **Why it works / fails:** The construction treats "hiding from the auditor" as a uniform property — but NCUA post-incident forensics require a *different auditor posture* (investigating examiner, not routine examiner). The construction has no notion of a **trapdoor reveal** or **regulatory escrow** — a mechanism to disclose the full chain to a credentialed regulator under defined conditions while hiding it from routine audits. BBS+ selective disclosure handles this via holder-bound proofs that can be selectively opened. The construction's comparison to BBS+ claims 6 structural wins but doesn't address this operational mode.

- **In-threat-model?** No. The construction must formalize a `RegulatorReveal` mode: a separate proof (or a witness escrow scheme) that lets a credentialed NCUA examiner reconstruct the full chain post-incident without exposing it during routine audits.

---

### Attack 3: Root Key Compromise Forges the Entire History

- **Attack:** The chain is anchored to a root EdDSA keypair on BabyJubjub — presumably the credit union's institutional signing key. FFIEC CAT Domain 2 and GLBA Safeguards Rule §314.4(h) require documented key lifecycle management including rotation and revocation. If that root key is compromised (e.g., via insider threat or HSM failure), an adversary can backdate and fabricate an entire delegation chain that passes all four of the construction's security games — because the games reduce to PLONK soundness and Poseidon collision resistance, not to root key unforgeability under compromise. The construction has no revocation primitive. A compromised key means every historical proof is suspect, with no mechanism to distinguish real chains from forged ones.

- **Why it works / fails:** The four formal security games (narrowing forgery, participant extraction, scope extraction, length extraction) all assume the root key is honest. This is a standard cryptographic assumption but it is not an operational assumption — HSMs fail, insiders exist, and NCUA examiners will ask "what is your key rotation schedule and what happens if your signing key is exposed?" The construction is silent on this. There is no `RevocationWitness` circuit, no epoch-bound validity, no forward-secrecy mechanism across the 8-hop window.

- **In-threat-model?** No. The construction must either (a) define a key epoch mechanism where proofs are bound to a specific root key version, allowing revocation to invalidate only chains from a compromised epoch, or (b) explicitly state that root key management is out of scope and document what operational controls the deploying institution must layer on top.

---

### Attack 4: Bolyra Primitives Have No SOC 2, No Pen Test, No Regulatory Track Record

- **Attack:** My Vendor Management Policy requires any software handling member credential issuance or access control to provide a SOC 2 Type II report or equivalent third-party assessment before onboarding. The construction is built entirely on Bolyra primitives — Poseidon2/4, PLONK, BabyJubjub EdDSA, BinaryMerkleRoot. These are novel cryptographic software components with academic security proofs but no operational vetting history. I will ask: Where is the independent implementation audit? Where is the FIPS 140-2/3 certification or exception documentation? Where is the bug bounty history? The construction's security argument ("reductions to PLONK soundness + Poseidon collision resistance") is peer-reviewed math, not an operational assurance. Poseidon has had differential cryptanalysis results published since 2023. PLONK implementations have had soundness bugs (e.g., the Aztec PLONK bug). The construction does not specify which PLONK implementation is used or its version.

- **Why it works / fails:** This is not a cryptographic attack — it is a procurement and vendor risk attack. The construction can be mathematically correct and still be operationally blocked because the deploying institution cannot satisfy its own vendor onboarding controls. The construction references ~110K constraints and <5s proving time but does not name the prover library, version, or audit status. My NCUA examiner's third-party risk questionnaire will ask for these. The construction's comparison to RFC 8693 + BBS+ is also a liability here — those standards have IETF provenance and multiple interoperable implementations with known audit histories. Bolyra has none.

- **In-threat-model?** No. The construction must either (a) specify the exact implementation stack and its audit status, or (b) explicitly scope the claim to "cryptographic construction" rather than "deployable system" and stop citing NCUA/SECU operational scenarios that imply production deployment readiness.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. I've shipped introspection in production since before PKCE was mandatory. Every ZK claim below is measured against what a well-configured AS can already do today.*

---

### Attack 1: The AS Already Knows the Chain — Let It Attest

**Attack:** Under RFC 8693, the Authorization Server *issues* every delegation token at every hop. It already holds the full chain in its token store. A modern AS with per-RS introspection policy (draft-ietf-oauth-jwt-introspection-response §3) can return a signed JWT to the auditor containing exactly:

```json
{
  "chain_valid": true,
  "monotonic_narrowing": true,
  "final_scope": "read:loan_status",
  "hops": 4
}
```

...and *nothing else*. No intermediate scopes, no intermediate principals, no RFC 8693 `actor` sub-chain. The AS filters the introspection response by auditor identity using standard AS policy. This is a **signed, AS-attested audit assertion** with zero ZK machinery.

**Why it works against the construction:** The construction (§3, "Threat Model") never explicitly names the AS as an adversary. If the AS is trusted — as it must be in any RFC 8693 deployment, because the AS *issued* the tokens — then the AS can produce the same end-property the ZK circuit proves. The ZK proof's "hiding" is meaningful only if the AS cannot be trusted to produce the filtered assertion honestly. The construction must prove *why the AS is adversarial*, not just assume it.

**In-threat-model?** **No** — the construction must explicitly scope its threat model to "AS = adversary" or "AS is offline/unavailable to auditor." Without that, Attack 1 is a simpler baseline that achieves the stated property.

---

### Attack 2: PPIDs + DPoP Already Break Cross-Hop Participant Linkability

**Attack:** The construction claims (§2, Scenario 1) that it hides "participants" from the auditor. But RFC 8693 + OIDC pairwise pseudonymous identifiers (PPIDs, OIDC Core §8.1) + RFC 9449 DPoP already provide:

- **Per-RS participant unlinkability**: Each RS in the delegation chain sees a different pairwise subject identifier (`sub`) for the same human or agent. Cross-RS correlation by participant identity is broken at the RS level.
- **Sender-constraint without ZK**: DPoP binds each token to a proof-of-possession key. An auditor querying RS-1 sees a DPoP-bound token for `sub_pairwise_1`; querying RS-2 sees `sub_pairwise_2`. No correlation.

The construction's §4.2 ("Participant Hiding") claims the circuit commits to Poseidon2 hashes of participant keys and never exposes them to the verifier. But the *verifier already cannot link* PPID-scoped principals across hops — the same property — without any ZK circuit.

**Why it partially fails:** The AS still holds the PPID mapping table and can reconstruct the full chain. PPIDs break RS-level linkability, not AS-level. So if the auditor has AS access, they can reconstruct participants. The construction's advantage is real *only* in the "auditor has RS-level access but not AS-level access" scenario. That scenario is plausible but narrow — the construction must argue it explicitly rather than treating participant hiding as a universally novel property.

**In-threat-model?** **Partially** — construction survives for the "AS-level adversarial auditor" scenario, but must stop claiming participant hiding is novel against RFC baselines when the auditor is RS-level only.

---

### Attack 3: Fixed 8-Hop Unrolling Leaks Chain Length Upper Bound

**Attack:** The construction (§5, "Circuit Design") states the PLONK circuit "unrolls up to 8 delegation hops in a single circuit" and claims "length extraction" resistance in Security Game 4. But fixed-width unrolling with padding is *not* length hiding — it is length *bounding*.

A verifier receiving a proof from this circuit learns immediately: **the chain has at most 8 hops**. The padding witnesses are distinguishable from real hops at the constraint level only if the padding is indistinguishable — but the circuit must enforce that padded hops have a canonical "null" commitment. If the auditor knows the Poseidon2 hash of the null-commitment constant (which is public), they can count non-null commitments in the public inputs and recover exact chain length.

Compare: RFC 8693 with AS-filtered introspection can return `"hops": null` — genuinely withholding chain length. The ZK circuit's fixed unrolling *structurally* leaks that chain length ≤ 8, and likely leaks exact length unless null-commitment indistinguishability from real commitments is proven. Security Game 4 in §6.4 must prove that the null-commitment hash is computationally indistinguishable from a real scope commitment under the Poseidon2 collision resistance assumption. If this reduction is not in the paper, the length-hiding claim is unsupported.

**In-threat-model?** **Yes, but incompletely addressed** — construction must add a formal indistinguishability argument for null-commitment padding or acknowledge the ≤8 upper bound leak as an accepted limitation.

---

### Attack 4: Tool-Call Hops Are Not OAuth Principals — The AI Pipeline Claim Is Undefined

**Attack:** The construction's stated gap-to-close includes "AI agent pipelines where each hop is a tool call, not an org." RFC 8693 explicitly models the `actor` claim for *service-to-service delegation* where each actor is an OAuth client with a `client_id`. A tool call within an agent process is not an OAuth principal — it has no `client_id`, issues no token exchange request, and cannot be independently introspected by an RS.

The construction's §7 ("AI Agent Pipeline Scenario") presumably maps tool calls to circuit hops. But the formal semantics of "a tool call narrows scope" requires defining:

1. What constitutes the tool call's "identity commitment" (the Poseidon2-hashed input)?
2. Who generates and signs the scope commitment for a tool call that has no private key?
3. How does the circuit distinguish a legitimate tool-call hop from a forged one injected by a compromised agent runtime?

RFC 8693 avoids this problem by requiring that every `actor` be a registered OAuth client that can authenticate to the AS. The ZK construction sidesteps AS registration but inherits the same question: **who vouches for the tool call's identity commitment?** Without a signing key per tool call — which reintroduces PKI complexity — the commitment is self-asserted by the agent runtime and provides no security against a malicious runtime forging a hop.

**In-threat-model?** **Yes — this is a gap the construction must address.** The journalist/source scenario (human principals with established keys) is cleanly in-scope. The AI agent pipeline scenario requires either (a) per-tool-call signing keys (complex), (b) a trusted execution environment attestation per hop (TEE dependency), or (c) an explicit acknowledgment that the construction only proves *internal consistency* of the chain, not that individual hops were generated by legitimate tools. Claiming "whistleblower-safe agent delegation" requires addressing this or the AI pipeline scenario should be scoped out.


## Persona: spiffe_engineer

---

### Attack 1: The 8-Hop Cap Is an Arbitrary Circuit Parameter, Not a Security Bound

- **Attack:** The circuit unrolls exactly 8 delegation hops. In production SPIFFE/SPIRE deployments, delegation depth is unbounded at the protocol layer — SPIRE issues X.509 SVIDs and JWT-SVIDs without chain depth constraints. Real AI agent pipelines (LangGraph with recursive sub-agents, tool-calling agents that spawn sub-agents, multi-model orchestrators) routinely exceed 8 hops. The construction section that defines the circuit unrolling must explain: what happens at hop 9? Does the proof simply fail to generate? Does the prover silently truncate? Either answer is a soundness failure: an attacker can route a forbidden scope through hops 9–N, and the auditor sees a valid 8-hop proof that does not cover the full chain.

- **Why it works / fails:** The construction does not appear to define how chain length is committed to in a way the auditor can verify is complete. If the auditor cannot distinguish "this proof covers all 7 hops in the chain" from "this proof covers the first 7 of 12 hops," the narrowing guarantee is vacuous for long chains. The PLONK circuit proves correctness of what is *inside* the circuit, not completeness of the chain itself.

- **In-threat-model?** No — the construction must address how the auditor verifies chain completeness, not just narrowing within the unrolled window.

---

### Attack 2: Scope Narrowing Without Policy-Engine Attestation Is Incomplete for SPIFFE-Native Workloads

- **Attack:** SPIFFE SVIDs carry *identity*, not *authorization*. Scopes/mandates live in a separate policy engine (OPA, Cedar, AWS Cedar Agent, Envoy RBAC). The construction's bitwise-subset narrowing model assumes the delegation token encodes the mandate directly — that is the OAuth/WIMSE model, not SPIFFE. In a SPIFFE-native AI pipeline, the "mandate" for each hop is a policy evaluation result at runtime, not a field in the credential. To prove monotonic narrowing, the construction must either (a) also ZK-prove policy engine state at each hop, which is not in scope and would require circuit integration with Rego/Cedar evaluation, or (b) require all SPIFFE workloads to embed scopes in their tokens, which contradicts SPIFFE's design principle of identity-only credentials. The "multi-tool AI pipeline" scenario (Scenario 1) hits this directly: if each tool call is a SPIFFE workload making an authorization decision via OPA, the ChainAuditProof circuit has no data to hash into the scope commitment at each hop.

- **Why it works / fails:** The construction appears to assume scopes are prover-supplied inputs committed via Poseidon2 hashes. But there is no mechanism to bind those prover-supplied scope values to the actual policy evaluation that occurred at runtime. A malicious prover can supply narrower-than-actual scopes, produce a valid proof, and the circuit cannot detect it.

- **In-threat-model?** No — the construction must define how scope inputs are bound to runtime authorization decisions, or explicitly limit applicability to OAuth/WIMSE credential types and exclude SPIFFE workloads.

---

### Attack 3: The Journalist Scenario Leaks Trust-Domain Membership to the Auditor

- **Attack:** The construction claims to hide all intermediate participants from the auditor. But PLONK proof verification requires public inputs — specifically, the root commitment that anchors the chain. In SPIFFE terms, the root of a delegation chain is the trust domain anchor (the SPIRE server's root CA, or the trust bundle). If the journalist's SPIRE instance is in trust domain `spiffe://journalist-org.example/` and the source's workload is in `spiffe://source-protection.example/`, the auditor learns exactly which trust domains participated — because trust domain membership is *public* by SPIFFE design (trust bundles are distributed publicly for federation). The ChainAuditProof hides the *path* (intermediate hops) but the endpoint trust domains appear in the public inputs. For the journalist/source scenario (Scenario 2), this is sufficient to de-anonymize the source: the auditor sees "a chain anchored at trust domain X rooted in source-protection.example." The set of workloads in that trust domain may be small.

- **Why it works / fails:** This is a metadata leak at the circuit interface boundary, not a break of the PLONK construction itself. The circuit is sound for what it proves; the problem is that the public input surface is larger than the construction acknowledges.

- **In-threat-model?** No — the construction must either (a) show that trust domain anchors are also hidden (requiring additional anonymization infrastructure not defined here), or (b) scope the journalist scenario to single-trust-domain deployments only.

---

### Attack 4: This Is a WIMSE Extension Problem, Not a New Protocol

- **Attack:** WIMSE (draft-ietf-wimse-arch, currently in IETF OAuth WG) explicitly targets workload-to-workload delegation with token exchange and scope reduction. Section 5 of the current WIMSE architecture draft describes the "on-behalf-of" flow where a workload exchanges a token for a narrower-scoped token at each hop, and the draft has open issues explicitly tracking selective disclosure and audit properties. The ChainAuditProof construction is essentially a ZK privacy layer on top of what WIMSE token exchange already defines. Building this as a standalone Bolyra construction means: (1) every enterprise already running SPIFFE/WIMSE infrastructure must adopt a second credential stack to use it, (2) the construction cannot interoperate with WIMSE token exchange endpoints without translation, (3) the claim "beats RFC 8693 + BBS+ on 6 structural properties" compares against a token format spec, not against the WIMSE delegation flow — an unfair baseline. The correct contribution is a WIMSE Privacy Extension I-D that adds a ZK narrowing proof to the existing token exchange response, reusing SPIFFE trust anchors.

- **Why it works / fails:** This is not a cryptographic break — the construction may be sound. But soundness is not adoption. WIMSE already has the mandate scoping semantics; the construction duplicates them with incompatible wire formats. Until the construction defines a WIMSE interop profile or explains why WIMSE's scope is technically insufficient (not just politically slower), enterprise SPIFFE/WIMSE shops will not deploy it.

- **In-threat-model?** No (this is an ecosystem/adoption attack, not a cryptographic one) — but the construction must address it in the gap analysis, particularly given the stated goal of usability "beyond narrow regulatory niches." Narrow regulatory niches are exactly where non-standard stacks get deployed; broad enterprise adoption requires WIMSE alignment.
