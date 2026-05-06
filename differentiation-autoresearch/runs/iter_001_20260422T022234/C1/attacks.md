# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The "AS-Blind" Property Inverts the Regulated-Industry Threat Model

- **Attack:** Property 2 ("AS-blind runtime presentation — no AS roundtrip") is marketed as a feature. I will take this directly to SECU's CISO and BSA officer and show them the NCUA examination manual, which requires complete audit trails of permission exercise events. FFIEC guidance on AI model risk requires that every agent action be attributable and reconstructible. If the AS never sees which RS was contacted or which scope predicate was invoked, SECU cannot produce that audit trail. I close with: "Your vendor has built a system your examiners will flag as a control gap."

- **Why it works / why it fails:** The construction's adversarial-AS model (Property 3) assumes AS is semi-trusted and adversarial — a reasonable threat model for general enterprise SaaS. But SECU's actual threat model is the *inverse*: the regulatory auditor is the principal, and the AS is the trust anchor the auditor relies on. AS-blindness removes exactly the visibility the credit union is *required* to provide. The construction has no answer to this — it doesn't address audit log requirements or show how AS-blind proofs compose with existing SIEM/audit infrastructure.

- **In-threat-model?** No. Construction must address.

---

### Attack 2: 3-Second Proving Time Compounds Fatally in Agentic Workflows

- **Attack:** The construction claims "<3s proving time." I'll build a simple capacity model for SECU's loan origination agent: a single loan file touches compliance RS, member-services RS, and document-storage RS — three sequential proof generations = 9 seconds of wall-clock latency *before any business logic runs*. WorkOS issues tokens at <100ms; three calls = 300ms. I present this as a 30x latency multiplier to SECU's VP of Digital, who has an existing SLA with members that loan status updates within 5 seconds of submission. I don't need to win the cryptography argument — I just need to win the "does this break our SLAs" argument.

- **Why it works / why it fails:** The construction advertises constant-size proofs (Property 4) but says nothing about proof *reuse*, *caching*, or *batching*. If a credential's `requiredScopeMask` is RS-specific and runtime-adaptive (the core claim), it cannot be precomputed. The construction must show either (a) hardware acceleration path to sub-100ms, (b) a proof-caching scheme that doesn't break cross-RS unlinkability, or (c) acknowledgment that this targets async batch workflows only.

- **In-threat-model?** No. Construction must address.

---

### Attack 3: On-Chain Merkle Root Is a Deployment Blocker, Not a Trust Anchor

- **Attack:** Property 3 states: "credential commitment is a Poseidon5 hash in an on-chain Merkle tree" and "AS can't alter permissions post-enrollment without a new root (publicly observable event)." I route this to SECU's vendor management team, who are running the standard NCUA Letter 01-CU-20 third-party due diligence checklist. Questions I raise: Which chain? Who operates the validator set? What is the disaster recovery SLA if the chain is partitioned or the RPC provider is unavailable? What are the gas economics at scale — does SECU pay per enrollment? Who controls key rotation for the on-chain contract? Auth0 has a 99.99% uptime SLA backed by AWS multi-region. The construction has no equivalent. The on-chain dependency converts a cryptographic property (tamper-evidence) into an operational dependency that a credit union's IT risk committee will reject.

- **Why it works / why it fails:** The construction treats on-chain anchoring as a pure trust property but does not address operational availability, cost model, or the organizational question of who owns the contract. For a credit union with a 5-year core banking contract and no blockchain infrastructure, this is a go/no-go blocker regardless of the ZK math.

- **In-threat-model?** No. Construction must address.

---

### Attack 4: RFC 7662 + JWT Introspection Response Already Covers the Stated Scenarios with Zero New Infrastructure

- **Attack:** The construction's `gap_to_close` section correctly identifies that "RFC 7662 allows AS-side policy to return minimal scope per RS" — but then concedes this in the claim rather than refuting it. I will demo WorkOS's MCP auth flow: the RS calls introspection with `resource` (RFC 8707), receives a JWT introspection response scoped to that RS, and verifies offline. The scope returned is RS-specific and already minimal. The AS-side policy table *does* scale — it's a JWT issuance, not a table scan. The construction's "2^64 permission space" scenario is a strawman: no production credit union has 2^64 distinct permissions; they have role hierarchies that collapse to tens of distinct grants, which AS-side filtering handles trivially. I haven't needed a circuit.

- **Why it works / why it fails:** This is the construction's weakest point. The claimed differentiation ("no AS roundtrip, agent chooses what to disclose at the moment of use") is real — but the construction's own gap analysis admits the incumbent baseline is close. The construction must demonstrate a *concrete* scenario where RFC 7662 + RFC 8707 + JWT introspection response *provably fails* and where an AS-blind predicate proof is *required* — not just cleaner. Without a falsifiable gap, procurement will always choose the vendor with existing SOC 2 Type II and $0 integration cost.

- **In-threat-model?** Partially. The adversarial-AS scenario (Property 3) is a genuine gap in the RFC baseline — but the construction must show SECU actually faces an adversarial AS, not just assume it.


## Persona: cryptographer

---

### Attack 1: AS Nullifier Precomputation (Breaks CRU Game)

- **Attack:** The CRU game claims cross-RS unlinkability against an adversarial AS. But the nullifier is `rsNullifier = Poseidon2(credentialCommitment, rsIdentifier)`. The AS *computed and stored* `credentialCommitment` at enrollment time. The set of RSes at SECU is finite and publicly known (loan origination, compliance, member services — say N < 100). The AS precomputes the full nullifier table: for every enrolled agent × every known rsIdentifier. If nullifiers appear in any observable channel (on-chain logs, RS access logs the AS can subpoena, audit trails), the AS performs a lookup and recovers the full RS visit graph for every agent.

- **Why it works:** The "PRF security of Poseidon2" reduction assumes the key is *secret from the adversary*. Here the "key" is `credentialCommitment`, which the AS derives and can store. Poseidon PRF security gives you unlinkability only when the input key is hidden from the distinguisher — the CRU game as described places the AS in an adversarial role but the construction hands it the PRF key at enrollment. This is a circular assumption failure.

- **In-threat-model?** **No — construction must address.** The CRU reduction sketch must either (a) prevent AS from observing nullifiers post-issuance, (b) derive the nullifier from a component the AS never sees (e.g., an agent-held secret blinded from AS), or (c) restate CRU as passive-AS-only and add a new game for active-AS.

---

### Attack 2: HVZK vs. Simulation-Extractable ZK Under Repeated Queries

- **Attack:** PLONK achieves *honest-verifier* zero-knowledge (HVZK). The RS is not an honest verifier — it is explicitly adversarial in the ASI scenario (§: "AS-blind presentation, AS cannot lie about scope membership"). A malicious RS runs a *chosen-challenge adaptive probing* attack: it requests proofs for a sequence of `requiredScopeMask` values it controls as public inputs, starting with high-entropy masks and performing binary search. After O(log 64) = 6 interactions, it can identify exactly which bits are set in the hidden bitmask via rejection patterns — even without extracting the witness directly — because HVZK only guarantees that *each individual proof transcript* is simulatable, not that the *joint distribution across multiple proofs with adversarially chosen public inputs* leaks nothing.

- **Why it works:** HVZK simulation produces transcripts for *fixed* public inputs chosen before the proof. With *adaptive* public input choice (malicious verifier controls `requiredScopeMask`), the zero-knowledge proof for "predicate satisfied / not satisfied" becomes an oracle for the hidden bits. Simulation-extractable ZK (SE-PLONK, requiring the Algebraic Group Model + Fiat-Shamir in ROM) would not close this gap either — SE adds extraction, not adaptive-query indistinguishability. What is needed is *malicious-verifier ZK* with adaptive public inputs, which requires a UC-style simulation argument the construction does not provide.

- **In-threat-model?** **No.** The construction states "ZK claim: agent reveals nothing beyond predicate satisfaction" but names no simulator, states no hybrid argument, and does not bound the adversary to a single proof query. Must define the ZK game with adaptive public input oracle access and prove indistinguishability.

---

### Attack 3: Subverted SRS → Universal Soundness Collapse

- **Attack:** PLONK requires a universal SRS generated via a multi-party ceremony. The construction's three games (SSU, CRU, ASI) reduce to "PLONK knowledge soundness," but knowledge soundness is *conditional on an honestly generated SRS*. Under a subverted SRS (one toxic-waste participant did not destroy their share), the adversary can generate PLONK proofs for any circuit statement, including `reqBits[i] * (1 - permBits[i]) === 0` for a bitmask the agent *does not hold*. The Poseidon Merkle commitment is irrelevant here: the adversary forges the entire proof, claiming Merkle inclusion of a credential that was never enrolled.

- **Why it works:** The ASI game states "AS cannot alter permissions post-enrollment without a new root." But a subverted SRS adversary does not need to alter the Merkle root — they forge the PLONK proof that correctly verifies against the *existing* root. The Merkle root is sound; the proof of correct Merkle-path verification is not. This is precisely the gap between "commitment binding" and "proof soundness" that the construction conflates.

- **In-threat-model?** **Partially.** The construction must define whether the SRS ceremony is in-scope. If SRS is trusted-setup (not modeled as adversarial), this is an explicit assumption that must appear in the threat model header — not buried in "reduction to PLONK knowledge soundness." At minimum, add an assumption box: *"We assume an honestly generated SRS. Under subverted SRS, SSU/CRU/ASI all fail."* The current draft says nothing about setup trust.

---

### Attack 4: Vacuous Predicate via Adversarial RS Mask Selection

- **Attack:** The RS supplies `requiredScopeMask` as a *public input* to the PLONK verifier. The circuit constraint is: `reqBits[i] * (1 - permBits[i]) === 0` for all i. Set `requiredScopeMask = 0x0000...0000` (all zeros). Then `reqBits[i] = 0` for all i, and `0 * (1 - permBits[i]) = 0` trivially — the constraint is satisfied for *any* credential, including ones with zero permissions. Any agent, regardless of enrollment, produces a valid proof. A malicious or misconfigured RS can bypass all scope enforcement by sending a zero mask.

- **Why it works:** The construction does not require the RS to commit to a *non-trivial* mask, nor does the circuit enforce a lower bound on the Hamming weight of `requiredScopeMask`. More importantly, nothing binds the RS's mask to the credential's enrollment-time declared scope: the RS is free to weaken its own requirements to `0`, granting universal access. The ASI game covers AS misbehavior; no game covers RS predicate forgery/weakening.

- **In-threat-model?** **No — critical gap.** Either (a) require `requiredScopeMask` to be signed by a trusted RS registry and verify the signature inside the circuit, (b) add a circuit constraint `popcount(requiredScopeMask) >= threshold`, or (c) add an explicit game: *RS-predicate integrity* — adversary controls `requiredScopeMask`, wins if they can produce an accepting proof for a credential that genuinely lacks the required permissions. Currently this game does not exist and the attack is trivially winning.


## Persona: cu\_ciso

### Attack 1: Cross-RS Unlinkability Destroys the Audit Trail (NCUA Part 748 / FFIEC CAT)

- **Attack:** Property 5 of the construction (`rsNullifier = Poseidon2(credentialCommitment, rsIdentifier)`) is marketed as a privacy feature — different RS, different nullifier, AS never sees which RS was contacted. The CISO flips this: *that is an audit gap, not a feature.* Under NCUA Part 748.1, the credit union must maintain records sufficient for examination. FFIEC CAT Domain 3 (Cybersecurity Controls) requires privileged-access logging. If the AS never observes which resource server an agent contacted, and each RS only sees "predicate satisfied," there is no single entity that holds a complete access log. During a breach — or an NCUA exam — the examiner asks: "Show me every system this agent touched between 14:00 and 15:00 on March 3rd." The answer is fragmented across individual RS logs, each containing only a PLONK proof blob and a nullifier. The AS has nothing. The construction does not specify an audit aggregation layer.

- **Why it works against the construction:** The construction is silent on audit log architecture. Section 5 ("Cross-RS unlinkability") achieves its goal precisely by eliminating the AS as an observer. There is no compensating control described.

- **In-threat-model?** No — the construction must address this. Candidate fix: a separate, examiner-facing audit transcript signed by the RS (not the circuit) that logs nullifier, RS identity, timestamp, and predicate mask — without revealing the full bitmask to the AS.

---

### Attack 2: Key Custody Is Unspecified — the Witness Lives Somewhere (GLBA Safeguards Rule § 314.4(c))

- **Attack:** The construction enrolls a credential "once on-chain" as a Poseidon5 commitment. At proof-generation time the agent must supply the *preimage* — the actual 64-bit bitmask plus the secret blinding factor — as the PLONK witness. The commitment is public; the witness is not. Where does the witness live between proof generations? The construction is silent. The CISO's attack prompt is exact: "If it's a browser, you've lost me." GLBA Safeguards Rule § 314.4(c) requires the CU to assess, manage, and oversee third-party service providers' handling of member information. If the witness is held in agent runtime memory (heap), a browser session, or a software wallet without HSM backing, any memory-scraping exploit or container escape yields the preimage — and with it, the ability to generate proofs as that agent indefinitely. The on-chain commitment cannot be revoked without a new Merkle root (itself a publicly observable event, per Property 3, but with lag).

- **Why it works against the construction:** Property 3 ("Adversarial-AS integrity") only addresses the AS's inability to alter permissions post-enrollment. It says nothing about the *agent-side* secret management. The circuit's security reductions (SSU, CRU, ASI games) assume the witness is honestly held — they do not model a compromised agent endpoint.

- **In-threat-model?** No — the construction must specify key custody. Candidate fix: require the witness to be sealed in a TEE or hardware-backed keystore; define a credential rotation SLA when a compromise is suspected.

---

### Attack 3: "Predicate Satisfied" Is Not an NCUA-Auditable Authorization Decision (FFIEC CAT / NCUA Third-Party Risk)

- **Attack:** The construction's output to every RS is a single bit: predicate satisfied. The RS learns `reqBits & permBits == reqBits`, nothing more. The CISO asks: "How do I map this to a specific NCUA Part, GLBA section, or FFIEC control number in my exam prep?" NCUA examiners use written questionnaires that ask for documented authorization matrices — who is authorized to do what, under which approval workflow, reviewed by whom. A PLONK proof does not appear in any NCUA examination workpaper template. The examiner cannot read it, the board cannot ratify it, and the CU's vendor management policy cannot assess it because the construction does not specify what a "permission bit" corresponds to in business terms. There is no mapping from `permBit[i]` to "approved for loan origination read access, reviewed by CISO on date X."

- **Why it works against the construction:** The construction operates entirely at the cryptographic layer. It proves a *mathematical* predicate, not a *regulatory* authorization. The gap is between the formal security games (SSU, CRU, ASI) and the NCUA's plain-English examination framework.

- **In-threat-model?** No — the construction must address regulatory mapping. Candidate fix: define a published bitmask schema (e.g., a registry document mapping bit positions to named entitlements), require AS-signed issuance records (separate from the on-chain commitment) that an examiner can read, and certify the schema under the CU's access control policy review cycle.

---

### Attack 4: On-Chain Merkle Root Availability Violates Core-Processor SLA Expectations (NCUA Part 748 / Business Continuity)

- **Attack:** Property 3 anchors credential integrity to a Poseidon5 Merkle root stored on-chain. At proof-generation time, the agent must present a Merkle inclusion proof against the current root. If the chain is unavailable — congested, forked, or under a denial-of-service event — agents cannot generate valid proofs, and RSes cannot verify them. The CISO's attack prompt is precise: "If your on-chain registry has a 1% outage budget, that's more than my core processor." A 1% annual outage is ~87 hours. NCUA Part 748 requires a tested business continuity plan; FFIEC BCP guidance requires the CU to understand the RTO/RPO of every dependency in the member-service chain. The construction does not specify: What is the chain's SLA? What is the fallback when the chain is unavailable? Can previously-cached roots be used, and for how long, before they become stale enough to allow a revoked credential to prove membership?

- **Why it works against the construction:** The construction's adversarial-AS integrity model requires the Merkle root to be authoritative and current. Any caching window that allows proof against a stale root re-opens the window for a revoked credential to authenticate. There is no revocation latency or degraded-mode protocol described.

- **In-threat-model?** No — the construction must specify chain SLA, maximum root staleness window, and the degraded-mode policy (e.g., fail-closed with a signed AS fallback JWT) that an NCUA examiner can review as part of the BCP documentation.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. I've shipped token introspection for ten production ASes. Every ZK claim below I've tried to kill with RFCs first.*

---

### Attack 1: Signed JWT Introspection Response Already Removes the AS from the Hot Path

- **Attack:** The construction's claim #2 ("AS-blind runtime presentation — no AS roundtrip, agent chooses what to disclose at the moment of use") is directly replicated by `draft-ietf-oauth-jwt-introspection-response`. The AS issues a signed JWT introspection response with per-RS filtered scopes (AS-side policy per RFC 7662 §2.1 "active" response). The RS caches it, verifies offline using the AS's public key. Zero AS roundtrip at runtime. The construction claims this as a differentiator but never rebuts the offline-JWT baseline.

- **Why it fails against the construction:** The residual gap is *who knows what, and when.* In the JWT introspection flow, the AS knows (a) which RS requested the introspection at issuance and (b) the scope subset it returned. A compromised AS can issue a fraudulent introspection JWT falsely asserting scope membership — the RS has no way to detect this, because the RS's trust anchor *is* the AS signing key. In the ZK construction, the AS signs only the Merkle root (a publicly observable on-chain commitment). The RS-specific proof is generated by the agent locally; the AS never sees `rsIdentifier`. A compromised AS cannot forge a valid PLONK proof without breaking knowledge soundness (§ "Adversarial-AS integrity").

- **In-threat-model?** **Yes** — construction survives, but only because it invokes the adversarial-AS sub-scenario. The construction must make this threat model boundary explicit and prominent. If the AS is honest (the common enterprise case), the JWT introspection baseline is indistinguishable in the property the construction advertises. Honest-AS deployments get no meaningful benefit from the ZK layer here.

---

### Attack 2: PPIDs + RFC 8707 Audience Binding Already Kills Cross-RS Linkability at the RS Level

- **Attack:** The construction's claim #5 ("Cross-RS unlinkability — AS never sees which RS was contacted") conflates two distinct linkability surfaces: (a) RS-to-RS linkability and (b) AS-to-everything linkability. RFC 8707 Resource Indicators bind tokens to a specific `resource` URI so RS-A's token is cryptographically useless at RS-B. OIDC Pairwise Pseudonymous Identifiers (PPIDs, per OIDC Core §8.1) give each RS a different `sub` value derived from a sector identifier. Together, RS-A and RS-B cannot correlate users even if they collude. The construction's `rsNullifier = Poseidon2(credentialCommitment, rsIdentifier)` is an in-circuit PPID — it's the same concept, different crypto.

- **Why it fails against the construction:** PPIDs are generated and stored by the AS. The AS maintains the deanonymization table (`real_sub → {RS-A: ppid_a, RS-B: ppid_b, ...}`). Under the adversarial-AS model the construction invokes, the AS is the attack surface — it can correlate all RS contacts trivially by querying its own table. The construction's rsNullifier is computed *inside the PLONK circuit* from a witness the AS never sees (`rsIdentifier` is provided at proof time by the agent, not the AS). So AS-level cross-RS correlation is impossible without breaking the Poseidon PRF assumption.

- **In-threat-model?** **Yes** — the construction survives, but again only in the adversarial-AS sub-scenario. The construction's write-up (property #5) does not distinguish between RS-level and AS-level unlinkability. An adversary reading the claim "AS never sees which RS was contacted" will immediately respond: "PPIDs already solve RS-level linkability." The construction must tighten this to: "AS-level cross-RS unlinkability, unachievable even with PPIDs because the AS holds the deanonymization table."

---

### Attack 3: The Adversarial-AS Threat Model Is Out-of-Scope for the Stated SECU Scenario

- **Attack:** The construction's differentiation collapses to a single load-bearing property: the adversarial-AS model. Properties #2, #3, and #5 all reduce to "the AS cannot be trusted." But the stated deployment scenario (§ "Scenario") is SECU — a North Carolina credit union — running AI agents across its *own* internal RSes (loan origination, compliance, member services). SECU *is* the AS operator. The adversarial-AS model asks SECU to protect against SECU. This is not a threat model any CISO would sign. RFC 7662 + JWT introspection response is fully sufficient when the AS and the relying organization are the same legal entity.

- **Why it works / why it fails:** This attack does not fail against the construction — it exposes a threat model mismatch. The construction is solving a real problem (federated multi-organization agent ecosystems where the AS is a third-party IdP), but the SECU scenario it illustrates is the weakest possible instantiation of that problem. The construction should use a scenario where the AS is genuinely external and potentially adversarial — e.g., a shared CUSO-operated AS serving 40 credit unions, where each CU's RS must verify agent permissions without trusting the shared AS.

- **In-threat-model?** **No** — the construction must address this. Either replace the SECU example with a multi-party CUSO scenario, or explicitly scope the adversarial-AS model and provide a separate honest-AS justification for why ZK adds value there too. As written, a reviewer can dismiss the entire construction by saying "SECU runs its own AS; RFC 7662 is fine."

---

### Attack 4: Constant-Size Proof Is Not a Baseline Gap — JWT Scope Filtering Is Already Compact

- **Attack:** The construction's claim #4 ("~500 bytes PLONK proof regardless of bitmask width") implies the baseline grows with permission set size. It does not. RFC 7662 returns an `active: true` JSON response with a `scope` string containing only the scopes the RS is authorized to see (per-RS AS policy). The signed JWT introspection response encodes this as a compact JWT — typically 300–450 bytes for a realistic filtered scope set. Extending the permission space from 64 to 256 bits adds *zero bytes* to the baseline too, because the baseline never encodes the bitmask — it encodes the filtered scope *strings*, which are RS-specific and small. The construction's "constant-size regardless of bitmask width" is only an advantage over a straw-man baseline that naively returns the full bitmask.

- **Why it fails against the construction:** The construction's genuine size advantage is not constant-size per se, but *zero cardinality leakage*. A filtered JWT introspection response reveals how many scopes the agent holds for this RS (`scope` string length leaks cardinality). The PLONK proof is a fixed-size boolean: "predicate satisfied" — it leaks nothing about how many of the 64 bits are set, or how close the agent is to holding additional permissions. This is a real property, but it's not what the construction calls out. Calling it "constant-size" invites the JWT-introspection rebuttal and buries the actual differentiator.

- **In-threat-model?** **No** — the construction must reframe this claim. Replace "constant-size proof regardless of bitmask width" with "zero cardinality leakage: the proof reveals only predicate satisfaction, not the Hamming weight of the permission bitmask or the margin above the required threshold." That is a property the filtered-JWT baseline cannot provide without additional obfuscation (padding, dummy scopes), which is non-standard and fragile.


## Persona: spiffe_engineer

---

### Attack 1: Short-TTL SVID + Offline JWT Validation Already Achieves AS-Blind Presentation

- **Attack:** Section 3 of the construction asserts *"AS-blind runtime presentation — credential enrolled once; agent proves any RS-specified requiredScopeMask locally. No AS roundtrip."* But SPIFFE JWT-SVIDs with a 1-hour TTL already do exactly this. The SPIRE agent rotates the SVID in the background; *at presentation time* the agent presents a locally cached SVID to the RS, who validates it with the public JWKS endpoint — no AS contact, no roundtrip. The RS can enforce scope policy offline using the `scope` claim in the JWT-SVID. The construction conflates "no roundtrip at presentation time" (SPIFFE already has this) with "AS never learns about this interaction" (a different, stronger property it does not cleanly define).

- **Why it works / why it fails:** The construction does achieve a stronger property — the AS *cannot reconstruct the specific RS-agent interaction graph* because the RS-targeted nullifier is never transmitted to the AS. But the construction does not formally define this as *interaction unlinkability* distinct from *presentation unlinkability*. Without that definition, a reviewer cannot distinguish it from SVID caching, and the claim strength is 4/10 for good reason.

- **In-threat-model?** No — the construction must add a formal definition separating *presentation unlinkability* (SPIFFE achieves) from *interaction graph unlinkability* (what the construction actually achieves) and demonstrate the RFC 7662 baseline leaks the latter.

---

### Attack 2: This Is a SPIRE Plugin, Not a New Protocol

- **Attack:** SPIRE has a first-class plugin architecture — custom node attestors, workload attestors, and key manager plugins. The WIMSE arch draft (§ 4.3) explicitly anticipates ZK-based attestation plugins for workload identity. The entire SelectiveScopeProof construction — on-chain Merkle root, PLONK circuit, rsNullifier — is a workload attestor that could be implemented as a SPIRE plugin: attest the workload's on-chain credential commitment, produce a ZK proof as the SVID payload, cache it for 1h. The RS verifies the ZK proof instead of a signature. Nothing in the SPIFFE spec prohibits this. The construction is reinventing a protocol when it should be filing a SPIRE plugin PR and a WIMSE draft contribution.

- **Why it works / why it fails:** The construction doesn't engage with this at all. It asserts differentiation from RFC 7662 + DPoP + BBS+, but never shows why the PLONK circuit cannot be a SVID extension. The adversarial-AS model (§ 4) actually *weakens* under SPIFFE federation: if the on-chain contract is controlled by the same entity as the SPIRE server, the trust boundary is identical.

- **In-threat-model?** No — the construction must address why the ZK proof cannot be expressed as a SPIFFE SVID extension or WIMSE token body, and why a new on-chain root of trust is preferable to SPIFFE's existing bundle refresh mechanism.

---

### Attack 3: On-Chain Merkle Root Does Not Satisfy the Adversarial-AS Model

- **Attack:** Section 4 claims *"AS can't alter permissions post-enrollment without a new root (publicly observable event). Under CR-Poseidon, the bitmask is bound."* But this conflates *detection* with *prevention*. Who controls the on-chain contract? If the AS controls the Merkle root update key (the only realistic deployment: the AS is the entity that enrolls credentials), the AS can rotate the root at will. It is observable — but the agent proves against the *current* root, not a pinned historical root. A malicious AS can insert a fraudulent bitmask leaf, publish a new root, wait one proof-generation cycle, and the agent will prove against the tampered bitmask without knowing. The on-chain audit trail makes this detectable *in retrospect*, not preventable. SPIFFE's trust bundle refresh via HTTPS with PKIX pinning has identical security properties and doesn't require a blockchain.

- **Why it works / why it fails:** The construction must distinguish between (a) root controlled by AS — equivalent to trusting the AS, audit-only; (b) root controlled by a third party or by threshold — the AS is genuinely adversarial. Case (b) requires specifying the governance model, which the construction omits entirely. The "adversarial-AS integrity" claim is unsubstantiated without a key-custody model.

- **In-threat-model?** Yes, partially — the construction survives if it specifies that the Merkle root update key is held by an entity independent of the AS (e.g., the credit union's HSM, a governance committee). But as written, the model is incomplete.

---

### Attack 4: rsNullifier Linkability Under AS–RS Collusion

- **Attack:** Section 5 claims *"Different RS = different nullifier. AS never sees which RS was contacted."* The circuit computes `rsNullifier = Poseidon2(credentialCommitment, rsIdentifier)`. The AS issued the on-chain commitment and therefore knows `credentialCommitment`. If the AS and RS collude — the SECU scenario involves a *single credit union* operating both the AS and multiple RSes (loan origination, compliance, member services) — the colluding parties can compute `Poseidon2(credentialCommitment, rsIdentifier)` for every known RS and match against submitted nullifiers. The construction provides unlinkability from the *RS perspective* (RS B cannot link agent interactions at RS A) but not from the *AS-RS collusion perspective*. In the SECU scenario, this distinction is meaningless: the credit union controls both sides.

- **Why it works / why it fails:** The construction names the SECU scenario explicitly but does not model intra-institution collusion. The security games (SSU, CRU, ASI) would need an explicit corruptible-RS oracle that can share state with the AS. Without it, the cross-RS unlinkability claim overstates the guarantee for the primary named deployment scenario.

- **In-threat-model?** No — the construction must either (a) restrict the unlinkability claim to *third-party RSes* outside the AS's control, or (b) replace `credentialCommitment` in the nullifier with a blinded derivative unknown to the AS, and prove the AS cannot reverse it.
