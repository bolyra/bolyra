# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Proving Latency Destroys the Agentic Use Case

- **Attack**: The PM asks SECU's infrastructure team to benchmark a realistic agentic workload. An agent doing a loan origination flow makes 8–12 API calls across core banking, compliance, fraud, and CRM. At <5s per PLONK proof (Section 6 target), that's 40–60 seconds of pure proof-generation overhead per user-initiated transaction. JWT issuance at Auth0 is <100ms; a full OAuth token exchange end-to-end is <200ms. The PM presents this to SECU's CTO as a 200–300× latency regression on every agentic API call.

- **Why it works**: Section 6 is honest: ~20,000 constraints, cites Semaphore v4 at ~2s on "commodity hardware." But agent containers in production are not Apple M-series with AVX-512. They're shared vCPUs in ECS or Lambda with cold-start overhead. The construction provides no proof caching, pre-generation, or batching strategy. Section 7's SECU deployment scenario never mentions latency budget. The spec budget is "< 5 seconds" — this is a ceiling, not a target, and it applies per proof per API call.

- **In-threat-model?** No. Section 6 acknowledges constraint count but does not model multi-call agentic workflows, CPU provisioning, or proof amortization. The construction must address: (a) proof pre-generation keyed to known RS `requiredScopeMask` values, (b) batch verification across multiple RS calls in a single agent workflow, or (c) a hybrid where short-lived JWT tokens are issued *by the agent itself* after a single proof, valid for N calls within a session window. Without this, the 5-second bound is a non-starter for any production agentic deployment.

---

### Attack 2: `scopeCommitment` Is a Persistent Cross-RS Tracking Cookie

- **Attack**: The PM asks the Bolyra team to demo cross-RS unlinkability. Two different resource servers — the loan origination API and the fraud detection service — both receive a proof from Agent-X. The PM points to the public outputs in Section 2: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Both RSes receive the *identical* `scopeCommitment` value for every session Agent-X runs. The PM shares this with SECU's privacy officer: "You claimed agents are unlinkable across services. Here's the same value in both request logs."

- **Why it works**: The construction's CrossLink game (Section 3) acknowledges the problem directly: "scopeCommitment is identical across sessions for the same agent." The attempted mitigation is: "this is true for BOTH agents from the adversary's view." This fails. The game asks whether a *single RS* can distinguish which of two agents it is talking to. But the real linkability threat is: can two *collaborating* RSes (or a single RS observing multiple calls) link both requests to the same agent? The answer is trivially yes via `scopeCommitment`. The nullifier (`Poseidon2(credentialCommitment, sessionNonce)`) is session-fresh, but `scopeCommitment` is not. Section 1 Property 4 ("unlinkable across resource servers") is falsified by the construction's own public output table.

- **In-threat-model?** No. The construction claims unlinkability as a first-class property in the abstract and in Property 4, but the scopeCommitment makes every proof from the same agent linkable across any two RSes that compare logs. Fix requires either (a) removing `scopeCommitment` as a public output and moving it entirely into the nullifier derivation, or (b) randomizing it per session using the `sessionNonce`: `scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`. This breaks the "delegation chain seed" use case in §4.1 — a genuine design tension the construction does not resolve.

---

### Attack 3: No Revocation = NCUA Incident Response Failure

- **Attack**: The PM asks SECU's compliance team a single question: "If Agent-X is compromised at 9am on Monday, how quickly can you revoke its permissions?" Under JWT/RFC 7662, the answer is: immediately — stop signing new tokens, or flip the introspection response. Under the Bolyra construction, the answer is: the agent retains valid credentials until `expiryTimestamp`, which was baked into the credential commitment at enrollment (Section 2 G2: `Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiryTimestamp)`). The Merkle tree is append-only; leaves cannot be deleted. The nullifier registry only prevents replay of a *specific prior presentation* — it does not revoke the underlying credential.

- **Why it works**: Section 2 enrollment protocol specifies no revocation mechanism. Section 4 threat model does not model credential compromise. Section 7's SECU scenario mentions "NCUA examination" but does not mention the NCUA's incident response requirements (12 CFR Part 748: notify regulator within 72 hours, contain within hours). A compromised agent with a 90-day expiry operates with valid credentials for up to 90 days post-compromise. The construction's only mitigation would be a revocation list (nullifier blacklist keyed to `credentialCommitment`), but this is not specified and would require the RS to maintain and consult a growing revocation registry — exactly what the AS-blind property was designed to avoid.

- **In-threat-model?** No. The construction's threat model covers forgery and extraction, not credential lifecycle. This is not a cryptographic gap — it is a protocol completeness gap. The construction must specify: (a) a revocation Merkle tree or accumulator committed on-chain, (b) RS-side verification that `credentialCommitment` is not in the revocation set, and (c) the revocation latency SLA. Without this, SECU's CISO cannot sign off on the deployment regardless of cryptographic correctness.

---

### Attack 4: Honest-RS Assumption Collapses Against Realistic MCP Threat Model

- **Attack**: The PM pulls up the Anthropic MCP threat model and points out that in production MCP deployments, tool servers (resource servers) are third-party services, community-contributed plugins, or LLM-orchestrated sub-agents — none of which are "honest" in any meaningful sense. The PM cites the PermExtract game analysis in Section 3, which the construction itself concedes: "If the RS chooses adaptive masks, it can recover B in at most 64 queries." Then the PM reads the mitigation: "the RS is honest (threat model)." The PM says: "You've designed a construction whose entire privacy guarantee evaporates against the exact adversary that makes MCP auth dangerous."

- **Why it works**: The construction explicitly excludes adversarial RS from the threat model ("RS is honest"). But the MCP security problem is precisely that tool servers are the attack surface. A compromised MCP server issuing 64 sequentially crafted `requiredScopeMask` challenges — each a power of 2 — fully recovers `permissionBitmask` in 64 round trips with probability 1, no cryptographic assumptions required. This is not a theoretical attack; it is a trivial bit-extraction oracle that the construction's own Section 3 describes and then excludes from scope. Auth0's MCP auth and Cloudflare Access both authenticate the *client to the server* and the *server to the client* — mutual authentication. The Bolyra construction authenticates the agent to the RS but provides zero assurance about RS integrity. For a credit union deploying third-party fintech tool integrations via MCP, every RS is a potential adversary.

- **In-threat-model?** No. The construction must either (a) extend the threat model to include semi-honest RS and add rate-limiting / proof-of-work / noise injection to the bit-extraction oracle, (b) remove the privacy claim against adversarial RS entirely and clearly bound what "unlinkability" means when RS is not trusted, or (c) add RS authentication into the circuit (RS public key as a public input, RS signature over the session nonce verified outside the circuit). None of these are trivial changes — (c) in particular requires RS key management infrastructure that eliminates the AS-blind property for RS-keyed deployments.


## Persona: cryptographer

---

### Attack 1: scopeCommitment Is a Stable Linking Tag — Cross-RS Unlinkability is Broken by Construction

**Attack:** The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (G9, §2) is deterministic and session-independent. Any two observers — RS_1 and RS_2, or the AS — who see presentations from the same agent see *identical* `scopeCommitment` values across every session. No nonce is mixed in. A passive adversary (including the semi-honest AS, who sees all proof transcripts) trivially links every presentation by matching scopeCommitment values.

**Why it works:** The CrossLink game proof (§3, "Cross-RS Linkability") states: *"scopeCommitment is identical across sessions for the same agent…but this is true for BOTH agents from the adversary's view — the adversary cannot open the commitment without a preimage attack."* This argument is confused. Linkability does not require opening the commitment. The distinguishing event is `scopeComm_RS1 == scopeComm_RS2`, which the adversary observes directly without inverting anything. In the CrossLink game, if the AS has seen any prior presentation from α₀ and any prior presentation from α₁, it has their respective scopeCommitments. The adversary wins with probability 1 by table lookup, not by cryptographic inversion.

The nullifier scheme (G8) correctly mixes in `sessionNonce` to produce session-unique values, but this protection is not extended to the scope commitment. The two-hash design creates an asymmetry: nullifiers are unlinkable, but scopeCommitments are a perfect stable identity tag.

**In-threat-model?** No — the construction must address this. The Cross-RS unlinkability claim is falsified by the construction itself. The fix requires scoping the commitment: e.g., `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)` — but this conflicts with the §4.1 "delegation chain seed" use case, which relies on the commitment being stable across sessions. The construction must resolve this tension explicitly; it currently pretends it does not exist.

---

### Attack 2: Nullifier Preimage Computation — AS Identifies Any Agent from (nullifier, nonce)

**Attack:** The nullifier is `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` (G8, §2). Both inputs are public: `credentialCommitment` is an on-chain Merkle leaf (§2, Enrollment protocol: "Credential commitment is inserted as a leaf in the on-chain agent Merkle tree"); `sessionNonce` is a public input to the circuit (§2 public inputs table). The semi-honest AS knows every enrolled `credentialCommitment_i` by definition — it ran enrollment. Given any observed `(nullifierHash, sessionNonce)` pair, the AS computes `Poseidon2(C_i, sessionNonce)` for each enrolled credential and matches. This is O(N) Poseidon evaluations, where N is the number of enrolled agents.

**Why it works:** The CrossLink security proof (§3) argues: *"independent nonces yields computationally independent values (Poseidon PRF assumption)."* This is correct for cross-session unlinkability of the **same agent** (distinct nonces → distinct nullifiers), but it does not address cross-agent identification by the AS. The Poseidon PRF assumption says `Poseidon2(k, ·)` is pseudorandom when `k` is secret. Here `k = credentialCommitment` is **public** (it is a published Merkle leaf). There is no PRF security when the key is known to the adversary. Contrast with Semaphore, where the nullifier seed is a private signal (`identityNullifier`) committed inside a non-public identity commitment; the Merkle leaf is public but the nullifier seed is not.

**In-threat-model?** No — this is a structural failure against the stated semi-honest AS adversary. The AS wins CrossLink with probability 1. The fix requires a private nullifier secret that is not derivable from the public credentialCommitment: e.g., add a private `nullifierSecret` field to the credential and redefine `nullifierHash = Poseidon2(nullifierSecret, sessionNonce)`, with `nullifierSecret` committed inside `Poseidon5(...)` but never exposed. The current circuit has no such field.

---

### Attack 3: Subverted Universal SRS — PLONK Knowledge Soundness Collapses

**Attack:** The ScopeForge game (§3) begins with "Generate PLONK universal SRS." The construction is instantiated over KZG polynomial commitments on BN254 (§2, A1). KZG-based PLONK requires a structured reference string produced by a toxic-waste ceremony: the SRS is `(g, gˢ, gˢ², …, gˢᵈ)` for a secret `s`. Any party who knows `s` can forge opening proofs for arbitrary polynomials, breaking knowledge soundness entirely — the PLONK extractor fails. The ScopeForge reduction in §4 invokes knowledge soundness as Assumption A1 without specifying (a) who runs the ceremony, (b) whether the AS or operator participates, or (c) what the security model is under a subverted SRS.

**Why it works:** The threat model names the AS as the adversary with control over credential issuance and the operator signing key. In a practical deployment (§7, SECU), the entity deploying Bolyra infrastructure plausibly runs or participates in the SRS ceremony. If the AS is also the ceremony operator and retains `s`, it can forge PLONK proofs for *any* statement — including the ScopeForge forgery — without touching Poseidon or the Merkle tree. The reduction sketch in §4 ("Reduction sketch: ScopeForge → PLONK knowledge soundness") assumes the SRS is honestly generated and the extractor exists, but this assumption is vacuous if the adversary generated the SRS.

**In-threat-model?** Partially — if the adversary is defined as the semi-honest AS and the AS runs the ceremony, yes. The construction must: (a) formally define who generates the SRS and their trust assumption, (b) consider a transparent-setup variant (e.g., FRI-based PLONK / STARK) where no toxic waste exists, or (c) require a multi-party ceremony with at least one honest participant and bound the adversary accordingly. The current §4 reduction is circular: it assumes knowledge soundness but does not bound who can break it via the setup.

---

### Attack 4: Binary Accept/Reject as a Bit-Extraction Oracle Against PermExtract

**Attack:** The PermExtract game (§3) allows the adversary to observe "polynomially many `(requiredScopeMask_i, proof_i, scopeCommitment_i, nullifierHash_i)` tuples." The RS produces a binary verification result: accept if `(B & M_i) == M_i`, reject otherwise. An adversary controlling the RS (or observing RS access logs) can recover the full 64-bit bitmask `B` in exactly 64 adaptive queries: set `M_i = 1 << i` for `i ∈ [0, 63]` and observe accept/reject. The paper acknowledges this in §4: *"If the RS chooses adaptive masks, it can recover B in at most 64 queries. Mitigation: the RS is honest."*

**Why it fails against the construction as stated:** The mitigation — "RS is honest" — is not formalized. The threat model (§3) defines the adversary as the semi-honest AS, with "RS is honest" as an axiom. But §7 deploys across multiple independent resource servers (core banking API, loan origination, fraud detection, compliance reporting). A compromised RS is explicitly outside the threat model, yet the deployment scenario assumes per-RS isolation as a security property. The PermExtract game should be parameterized by the RS's query strategy; instead it admits adaptive masks with no bound on the RS's behavior other than informal honesty. Furthermore, the `scopeCommitment` (Attack 1) is stable: once the RS knows `scopeCommitment = Poseidon2(B, C)` and recovers `B` via 64 queries, it can prove to *other* RSes that the same agent has specific permissions by sharing `B` alongside the commitment — leaking beyond the extraction game's scope.

**In-threat-model?** Partially — the paper should define a formal "honest RS" predicate (e.g., RS does not choose adaptive masks; RS does not share derived information). Without this, the PermExtract security claim is vacuously true by assumption, not by construction. The construction provides no mechanism — rate limiting, proof of distinct RS identity, or per-RS scope blinding — to prevent a semi-malicious RS from conducting this attack. The gap between "RS is honest" as an axiom and "RS is honest" as a verified protocol property must be closed.


## Persona: cu_ciso

---

### Attack 1: The Examiner Readability Problem

**Attack:** The CISO walks into the NCUA examination with the audit log. The examiner asks: "Show me every action Agent-X took on October 14th, what permissions it had, and whether those permissions were appropriate for a member-authorized agent performing mortgage inquiries." The CISO produces a list of PLONK proofs and nullifier hashes anchored to a Solidity contract on an EVM-compatible chain.

The construction's Section 7 claims: *"The examiner can verify that every agent access was backed by a valid PLONK proof anchored to an on-chain root, providing a cryptographic audit trail without exposing member-agent permission details."*

That last clause is the problem. **The zero-knowledge property — the construction's core feature — is in direct conflict with the examiner's need to know what happened.**

- **NCUA Part 748 Appendix A** requires the credit union to maintain audit records of system access sufficient to reconstruct events during an incident investigation. A log entry that reads `nullifier: 0x4fa2...` and `scopeCommitment: 0x9b31...` cannot be used to determine whether the agent's permission scope was appropriate for the action taken.
- **GLBA Safeguards Rule § 314.4(e)** requires monitoring and testing of safeguards, which requires knowing *what* was accessed with *what* authority.
- **FFIEC CAT** Domain 3 (Cybersecurity Controls) expects detective controls — logs that support forensic investigation. A verifier that outputs only `accept/reject` against a required mask tells you the agent *claimed* to satisfy the mask, not whether the claimed permissions were appropriate to issue.

The construction offers a proof that Agent-X satisfied `requiredScopeMask = 0x0000_0000_0005_001F`. It does not offer a human-interpretable record that the compliance officer or examiner can review without running cryptographic verification tooling that NCUA examiners do not have.

- **Why it works:** The construction does not address the audit layer at all — it addresses the *authorization* layer. These are different regulatory requirements. The construction is silent on what the RS logs, how those logs are presented to auditors, and whether the ZK proof system produces human-readable attestations.
- **In-threat-model?** No — the construction must address this. The threat model covers scope forgery and permission extraction but not the examiner accountability requirement. A supplemental plaintext audit log defeats the ZK privacy property; omitting it fails the NCUA examination.

---

### Attack 2: Operator Key Custody is the Root of Trust and Is Unspecified

**Attack:** The CISO asks: *"Where does the operator's BabyJubjub private key live?"*

The enrollment protocol (Section 2, Enrollment Protocol) states:
> "Operator generates BabyJubjub keypair (sk, pk)."

Full stop. The construction is silent on:
- Whether `sk` is stored in an HSM, a software keystore, a KMS, a developer's laptop, or a CI/CD environment variable.
- The rotation policy for `sk`.
- What happens when `sk` is compromised.

This is not a theoretical concern. The operator key is the **sole root of trust** for permission bitmask integrity. Gadget G3 (`EdDSAPoseidonVerifier`) enforces that the enrolled bitmask was signed by `pk`. If `sk` is compromised, the attacker can enroll *any* agent with *any* permission bitmask — all properly signed, all correctly inserted into the on-chain Merkle tree. The on-chain anchor (Section 8, Property 3) does not protect against this: it only prevents retroactive alteration of *already-enrolled* credentials. A compromised `sk` allows forward issuance of fraudulent credentials that are indistinguishable from legitimate ones.

- **NCUA Part 748 Appendix A, Section III.C** requires encryption key management controls including generation, storage, distribution, retirement, and destruction — all of which are unaddressed.
- **GLBA Safeguards Rule § 314.4(c)(3)** requires appropriate access controls over customer information systems — if the operator key controls agent permissions over member accounts, its custody is in scope.
- **Third-party risk (NCUA examiner questionnaires):** If the key is managed by the Bolyra vendor, the CISO now has a critical vendor dependency to manage under their Vendor Management Policy.

The construction's adversarial-AS protection (Section 8, Property 3) is explicitly framed as protecting against a *compromised operator*. But the threat model (Section 3) lists the adversary as controlling "the operator signing key." If the AS is compromised *and* controls the operator key, the on-chain anchor provides no protection whatsoever — the attacker can enroll new fraudulent credentials going forward.

- **Why it works:** The construction conflates "the AS cannot alter past commitments" with "the operator key is secure." These are orthogonal claims.
- **In-threat-model?** No — the construction must address operator key lifecycle management, storage requirements (HSM mandate), rotation triggers, and compromise response procedures before any NCUA-regulated institution can deploy this.

---

### Attack 3: Revocation Is AS-Dependent — Directly Contradicting the Semi-Honest AS Threat Model

**Attack:** At 2am, a member calls to report that their authorized AI agent has been performing unauthorized transfers. The Tier 1 ops team needs to revoke the agent. The CISO asks: *"How do I revoke this credential within the next five minutes?"*

The presentation protocol (Section 2, Step 3) states:
> "RS verifies: (c) nullifierHash not revoked."

Who maintains the revocation list? The construction does not say. The only candidates are:
1. The AS/operator — but the entire construction is designed around not trusting the AS.
2. An on-chain revocation registry — but this requires a blockchain transaction (latency + gas cost).
3. The RS itself — but then every RS maintains independent revocation state, which creates consistency problems.

If revocation is AS-controlled (the most operationally practical option), then a compromised or malicious AS can:
- Refuse to revoke a compromised agent's credential (active attack, not just semi-honest).
- Selectively revoke legitimate agents (denial of service against honest agents).

The construction claims "operator-binding against a semi-honest AS" in the title, but revocation requires *active* AS cooperation. This is a contradiction in the threat model as stated.

Furthermore, the Lean Incremental Merkle Tree (Section 5, IMT depth 20) is **append-only by construction**. Removing a credential commitment from an IMT requires either rebuilding the tree or maintaining a separate exclusion list. The construction does not address this.

- **GLBA Safeguards Rule § 314.4(j)** requires an incident response plan that includes containment procedures. If credential revocation depends on a blockchain transaction that takes 12–30 seconds (or longer during congestion), this may not meet the response time requirements for an active fraud incident.
- **FFIEC CAT** Domain 5 (Cyber Incident Management) expects the ability to contain incidents rapidly.

- **Why it works:** The construction addresses enrollment and presentation but not revocation lifecycle. The on-chain anchor that prevents retroactive falsification also prevents rapid revocation without additional on-chain state management.
- **In-threat-model?** No — revocation is mentioned as a verification step but never specified. The construction must define who maintains the revocation list, the latency guarantee for revocation propagation, and how revocation interacts with the root history buffer (30-entry window means a credential may still be valid against cached roots even after revocation).

---

### Attack 4: scopeCommitment Is a Persistent Cross-RS Tracking Token Within the Institution

**Attack:** The CISO's fraud team correlates logs from the loan origination system, the fraud detection service, and the compliance reporting engine. They find that `scopeCommitment = 0x7c3e...` appears in all three logs for every session Agent-X has ever run — across six months of logs.

The construction explicitly acknowledges this in the CrossLink game analysis (Section 3):
> "scopeCommitment is identical across sessions for the same agent (it encodes the same bitmask and credential), but this is true for BOTH agents from the adversary's view — the adversary cannot open the commitment without a preimage attack."

The game definition (Section 3, CrossLink) considers an *external* adversary distinguishing between two agents. It does not model **internal log correlation across resource servers operated by the same institution.** Within SECU, all RS logs are accessible to the security team, compliance officers, and — during examination — NCUA examiners.

A constant `scopeCommitment` across all sessions means:
- Any internal party with access to multiple RS logs can trivially link all sessions belonging to the same agent credential.
- During an investigation (fraud, compliance audit, insider threat review), the `scopeCommitment` functions as a persistent pseudonymous identifier for the agent across all SECU systems.
- This is not "unlinkable across resource servers" in any operationally meaningful sense when all RS are operated by the same institution.

The construction's Section 1 Property 4 claims "Unlinkable across resource servers." The `nullifierHash` is indeed fresh per session. But the `scopeCommitment` — which is always published as a public output — directly contradicts this claim for the realistic deployment scenario described in Section 7 (all RS are internal SECU systems).

- **Member data privacy (state-level and federal):** If agents operate on behalf of specific members, and `scopeCommitment` is a stable identifier, this may constitute a persistent tracking token for member-authorized activity across the institution — with privacy implications under state GLBA-equivalent laws and NCUA member privacy requirements.
- **FFIEC CAT:** From a *security* standpoint, the `scopeCommitment` as a stable internal identifier is actually useful for audit correlation — but the construction claims it provides unlinkability, which is false in the threat model that matters for SECU's deployment.

- **Why it works:** The CrossLink game is defined over an external adversary who controls no RS logs. In a single-institution deployment (Section 7), the "resource servers" are internal systems with shared log infrastructure. The construction must either (a) abandon the unlinkability claim for single-operator deployments, (b) specify that `scopeCommitment` must not appear in logs (defeating its utility as an audit handle), or (c) rotate `scopeCommitment` per session (requiring circuit changes and breaking its role as a delegation chain seed per Section 5).
- **In-threat-model?** No — the threat model explicitly excludes the honest RS from the adversary, but does not account for correlated honest RSes operated by the same institution sharing a log infrastructure.


## Persona: rfc7662_advocate

---

### Attack 1: scopeCommitment is a Persistent Cross-RS Linkage Beacon

- **Attack:** Every presentation to every RS publishes `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output (§2, G9). Because both inputs are fixed at enrollment and never change, this value is **identical across every session** of the same agent. Any two RSes that log their received proofs can immediately correlate all sessions by comparing `scopeCommitment` values — even with fresh per-session `nullifierHash` values.

  Contrast with the baseline: RFC 7662 + Pairwise Pseudonymous Identifiers (OIDC PPID) has the AS derive `sub = PRF(RS_id ‖ user_id)` independently per RS. Two colluding RSes see different `sub` values for the same user and cannot link without the AS's cooperation. The construction's on-chain model does **strictly worse** on this axis.

- **Why it works against the construction:** The CrossLink game (§3) is structured to ask whether the adversary can determine *which* agent produced two presentations. But it concedes in the same paragraph: "scopeCommitment is identical across sessions for the same agent." If α₀ and α₁ have distinct permission sets (the common case), their `scopeCommitments` differ, and any two colluding RSes can link every session of α₀ — or distinguish α₀ from α₁ — just by comparing this field. The nullifier provides *session* unlinkability; `scopeCommitment` simultaneously provides a *permanent global agent identifier* to any RS that cares to share logs.

- **In-threat-model?** No — the construction claims "Unlinkable across resource servers" as a core property (§1, Property 4; §8). This attack shows the claim is false without an honest-RS assumption that is at least as strong as trusting the AS in RFC 7662. The construction must either (a) rotate `scopeCommitment` per RS using a RS-specific blinding factor while still binding it to the same credential, or (b) drop the cross-RS unlinkability claim and tighten the threat model.

---

### Attack 2: Enrollment-Time Bitmask Substitution is Indistinguishable From RFC 7662 Forgery

- **Attack:** The threat model (§3) explicitly grants the adversary AS control over "the credential issuance process (choosing what bitmask to encode)." The AS can enroll Agent-X with `permissionBitmask = B_lie` rather than the member-authorized `B_true`, sign the commitment, and insert it into the on-chain Merkle tree. The Merkle anchor then *cryptographically proves* the lie was committed. Every downstream RS verifies against this root and concludes Agent-X legitimately holds `B_lie`.

  §7 ("Adversarial-AS protection") claims the construction prevents a compromised operator from "claiming Agent-X has fewer permissions than enrolled." This is backwards: the construction only prevents *post-enrollment* forgery. The AS is fully capable of *enrollment-time* forgery, and the construction provides no mechanism for the member or RS to detect it — because `permissionBitmask` is a private input, never visible to any verifier.

  In the RFC 7662 world, a member can introspect their own token and read the `scope` claim. If the AS mis-issued, the member has an auditable artifact. In this construction, the member cannot verify what bitmask was committed on their behalf without running the preimage.

- **Why it works against the construction:** The security argument in §4 (ScopeForge → PLONK soundness) proves the *prover* cannot forge a proof for a bitmask not in the Merkle tree. It says nothing about whether the *enrolled* bitmask is correct. The chain of trust bottoms out at the operator's willingness to enroll truthfully — exactly the same trust assumption RFC 7662 makes about the AS issuing truthful introspection responses.

- **In-threat-model?** Borderline — the threat model allows AS to choose the bitmask, then claims "operator-binding against a semi-honest AS" (§1, Property 3). The construction must clarify that "operator-binding" means *consistency after enrollment*, not *correctness at enrollment*, and that protection against enrollment forgery requires an out-of-band member audit mechanism not present in the current spec.

---

### Attack 3: RFC 8693 + RFC 8707 Pre-Exchange Achieves AS-Blind Presentation for the Concrete Deployment Scenario

- **Attack:** §7 targets SECU with four named internal RSes (core banking API, loan origination, fraud detection, compliance reporting). This is a **closed, known RS set**. An agent can use RFC 8693 Token Exchange at enrollment time to obtain four audience-bound access tokens — one per RS, with resource indicators per RFC 8707. Each token is a self-contained, AS-signed JWT (draft-ietf-oauth-jwt-introspection-response) carrying only the scope subset authorized for that RS. The agent caches these four JWTs locally. At runtime, no AS roundtrip is needed — the agent presents the pre-issued JWT to the appropriate RS, which verifies offline using the AS's public key.

  Result: AS-blind at presentation time (Property 2, §1), scope filtered per RS (partial Property 1), no cross-RS scope leakage (partial Property 4), verifiable without blockchain (simpler trust model). The baseline matches three of four claimed properties for the concrete deployment scenario without ZK, Poseidon, or on-chain infrastructure.

- **Why it partially fails against the construction:** The remaining gap is real but narrow. Pre-issued JWTs cannot prove a runtime bitwise predicate over a *hidden* bitmask — they either reveal the scope subset (non-zero disclosure) or require the AS to enumerate every possible requiredScopeMask at issuance time. If SECU adds a fifth RS mid-lifecycle, the agent must contact the AS for a new token. The construction handles an open/dynamic RS set without any re-enrollment. The construction also provides the *constant-size predicate proof* property (Property 4, §8) which the JWT approach cannot match even for closed RS sets.

- **In-threat-model?** No — for the specific SECU scenario as written (§7), the baseline is competitive enough that the construction's superiority is not obvious. The paper must make explicit that the differentiating properties require either (a) a dynamic RS set, (b) an adversarial AS, or (c) a predicate proof over a hidden bitmask — and show that SECU's actual requirements include at least one of these. Otherwise the complexity cost of ZK is unjustified against an RFC 8693 deployment.

---

### Attack 4: The Adaptive-RS Bit-Extraction Attack Inverts the Zero-Knowledge Advantage

- **Attack:** §3 (PermExtract) concedes: "If the RS chooses adaptive masks, it can recover B in at most 64 queries." The mitigation offered is: "the RS is honest (threat model) and uses policy-fixed masks." This is precisely what RFC 7662 with AS-side per-RS policy already enforces — the AS returns only the scopes authorized for that RS, and the RS cannot query the AS adaptively to learn additional bits. The baseline's architecture enforces the scope filter at the AS, which is a trusted third party with an explicit policy enforcement role. In the ZK construction, the RS directly controls `requiredScopeMask`, and the agent is obligated to respond to any value presented — it has no circuit-level mechanism to detect or refuse an adaptive probing sequence.

  Concretely: a semi-honest fraud detection service at SECU sets `requiredScopeMask = 0x0000000000000001` (bit 0), observes accept/reject. Repeat for bits 1–63. After 64 requests (each legitimate from the agent's perspective), the RS has fully reconstructed `permissionBitmask` without breaking any cryptographic primitive. No Poseidon preimage was needed. PLONK zero-knowledge was not violated. The protocol itself is the oracle.

  In the RFC 7662 model, the AS-side policy prevents this: the fraud detection RS receives only the scopes the AS authorized for it, regardless of what it would *like* to query.

- **Why it works against the construction:** The G5 gadget (§2) hides the bitmask from the verifier in a single proof, but the *protocol interaction* over multiple proofs is an oracle for the bitmask. The §3 PermExtract game models a static A that observes sessions; it does not model an adaptive RS that *chooses* future requiredScopeMask values based on prior accept/reject responses. This adaptive game is not analyzed. The "honest RS" escape hatch transfers the trust requirement from the AS (where RFC 7662 places it) to every RS in the ecosystem — which is a strictly weaker assumption when the RS count grows.

- **In-threat-model?** No — the construction claims Property 1 (§1) that the RS learns "only the accept/reject decision, not which bits are set." This is true for a *single* proof. For a *session* with an adaptive RS, the property fails. The construction must either add a rate-limiting or session-binding mechanism at the RS interface, or expand the threat model to explicitly allow adaptive RS behavior and show that 64 queries are acceptable given the deployment context.


## Persona: spiffe_engineer

### Attack 1: AS-Blind Presentation is SVID Issuance with a ZK Attestor Plugin

- **Attack**: The construction's "AS-blind at presentation time" property (Section 2, Presentation Protocol) is operationally identical to how SPIRE already works. SPIRE agents do node attestation *once*, receive short-lived X.509 SVIDs from the SPIRE server, then serve those SVIDs to workloads via the Workload API with zero AS roundtrip per request. The "one-time enrollment → local credential bundle → per-RS proof generation" lifecycle in Section 2 is SVID issuance. The BabyJubjub keypair is a signing key. The on-chain Merkle tree is a distributed trust bundle. The PLONK proof is a predicate evaluation gadget. None of these require a new protocol — they require a SPIRE attestor plugin that (a) encodes the permission bitmask into a custom X.509 SAN extension or JWT claim at issuance, and (b) runs the PLONK prover locally when the workload needs to assert a scope predicate. SPIRE's plugin architecture explicitly supports custom node and workload attestors. The construction provides no argument for why the ZK layer cannot be a SPIRE plugin that sits inside the existing SPIFFE Workload API boundary.

- **Why it works / why it fails**: The construction's Section 8 distinguishes itself on "AS-blind presentation" but conflates AS-roundtrip-per-request with AS-involvement-at-all. SPIRE's SVID rotation (default: 1-hour TTL) is the only AS contact; between rotations the workload is autonomous. The construction cannot rebut this without pointing to a property that SVID issuance cannot carry. The author's real differentiator is the on-chain anchor (A6), but that is separable from the ZK layer — a SPIRE attestor could anchor SVIDs on-chain without a new proof system.

- **In-threat-model?**: No — the construction must address why a SPIRE ZK attestor plugin does not achieve the same property, and what specifically requires a layer *below* the SPIFFE Workload API rather than inside it.

---

### Attack 2: scopeCommitment is a Stable Cross-RS Tracking Oracle — CrossLink Game Proof is Wrong

- **Attack**: Section 3's CrossLink game claims |Pr[A wins] - 1/2| ≤ negl(λ) and attributes unlinkability to fresh per-session nullifiers. But `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` (G9) is a **deterministic, session-independent** function of the agent's enrolled credential. The construction itself acknowledges: "scopeCommitment is identical across sessions for the same agent." The security argument then claims "the adversary cannot open the commitment without a preimage attack" — but the adversary does not need to **open** the commitment to win the CrossLink game. They only need to **compare** values. If agent α_b visits RS_1 and RS_2, both sessions emit the same `scopeCommitment`. The adversary sees `(scopeComm_RS1, scopeComm_RS2)` and wins with probability 1 by equality check: if `scopeComm_RS1 == scopeComm_RS2`, b' = b. The nullifier is unlinkable; the scope commitment is not. The CrossLink proof conflates two different oracles.

- **Why it works**: This is a direct falsification of the security claim in Section 3. The construction outputs `scopeCommitment` as a **public output** in every proof. Any two colluding RSes — or a single RS that sees the agent twice under different `requiredScopeMask` values — can trivially link all sessions to the same agent by correlating `scopeCommitment` values. The 64-bit bitmask content is hidden (preimage resistance holds), but the *identity* of the agent is not. In SPIFFE terms, this is equivalent to embedding a static SPIFFE ID in every SVID — which is intentional in SPIFFE but the construction claims it is not present here.

- **In-threat-model?**: No — the construction must either (a) remove `scopeCommitment` from the public outputs, (b) rerandomize it per-session (destroying its utility as a delegation-chain seed), or (c) explicitly revise the CrossLink claim to exclude colluding RSes from the unlinkability guarantee. As written, Section 3's proof is incorrect.

---

### Attack 3: WIMSE Token Exchange Draft Already Scopes This Problem

- **Attack**: IETF WIMSE draft-ietf-wimse-arch (which I co-author) explicitly addresses the "agent needs resource-server-specific capabilities without full scope disclosure" problem in the context of workload identity. The WIMSE transaction token (TraT, draft-ietf-oauth-transaction-tokens) model chains workload SVIDs through a Transaction Token Service (TTS) that issues narrow, RS-scoped capability tokens bound to the initiating workload's SPIFFE ID. The TTS can be co-located with the agent host (making it "AS-blind" in the operational sense). WIMSE working group has scope in-charter for selective disclosure — the construction's authors should be contributing a ZK predicate attachment to WIMSE's TraT spec rather than defining a parallel protocol that will never be adopted by infrastructure that already runs SPIRE. Section 8 claims BBS+ "is not part of any standardized OAuth flow" — but neither is PLONK on BN254 over a smart-contract Merkle tree. The construction substitutes one non-standard dependency for a much heavier one.

- **Why it works / why it fails**: The construction's response would need to show a property that TraT cannot carry. The strongest candidate is "AS-blind with adversarial AS" (Property 3) — a TTS that is co-located with the AS inherits the AS's trust assumptions. But the construction's own Section 7 deployment scenario (SECU) assumes the operator/AS is the credit union itself, which is the same trust boundary as a TTS. If the threat model requires cryptographic independence from a potentially compromised credential issuer, the construction has a case — but it has not argued this is the relevant threat for SECU specifically, and it has not engaged with the WIMSE architecture document at all.

- **In-threat-model?**: Partially. The adversarial-AS property (Section 3, Game ScopeForge, Case 2 of the reduction) is the one property WIMSE TraT does not provide without an independent on-chain anchor. The construction should sharpen its claim to *exactly* this property and stop claiming novelty for AS-blind presentation or constant-size proofs.

---

### Attack 4: Adversarial RS Recovers Full Bitmask in 64 Queries — Threat Model Gap is Load-Bearing

- **Attack**: Section 4, PermExtract reduction, explicitly concedes: "If the RS is adversarial, this is outside our threat model — but even then, the RS learns at most the individual bit values queried, not the full bitmask in a single proof." This concession eliminates the construction's strongest differentiator. An adversarial RS (or a colluding set of RSes) issues 64 challenge probes with `requiredScopeMask = 1 << i` for `i ∈ [0, 63]`. Each probe is a valid scope check; the agent generates a valid proof or fails. After 64 probes, the RS has reconstructed `B` exactly. In a production SECU deployment (Section 7), each of the 4 resource servers (core banking, loan origination, fraud detection, compliance reporting) controls its own `requiredScopeMask`. Nothing in the construction prevents a misbehaving internal service from probing with singleton masks. SPIFFE's response to this threat is federation with domain-scoped SVIDs: the fraud detection service never receives an SVID that carries permissions relevant to compliance reporting, because the SPIFFE trust domain boundary enforces it at issuance, not at proof time. The ZK construction defers enforcement to proof generation but provides no issuance-time compartmentalization.

- **Why it works**: The construction's unlinkability and scope-hiding properties hold against an honest-but-curious RS. But the SECU deployment has 4 internal RSes with independent control planes. The threat model declares the RS honest without justification specific to the deployment scenario. In any real enterprise SPIFFE deployment, we do not assume all internal services are honest — that is why we use different trust domains for different blast radiuses. The construction provides no equivalent compartmentalization primitive.

- **In-threat-model?**: No — the construction must either (a) extend the threat model to adversarial RSes and show the extraction attack requires super-polynomial queries (it does not — it requires exactly 64), or (b) add an issuance-time scope compartmentalization mechanism analogous to SPIFFE trust domain federation that limits which `requiredScopeMask` values any given RS is authorized to present.
