# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The Adversarial-AS Threat Model Is a Threat Enterprises Don't Have

- **Attack:** The construction's lead differentiator — adversarial-AS soundness — assumes the Authorization Server can lie. But enterprise buyers *are* their AS. They've already paid Auth0/Okta/WorkOS to be their AS. The threat model is "what if your identity provider betrays you," which is a threat enterprises have contractually, legally, and operationally addressed by choosing a vendor with SOC 2 Type II, EU-US DPF, and a BAA. Section 8 Property 1 says "compromise AS → return true for unauthorized scope → RS has no recourse." The enterprise procurement reply: "We didn't compromise our AS. We pay $200K/yr for Auth0 Enterprise so that doesn't happen."

- **Why it works / why it fails:** The construction's formal ImplicationClosureForgery sub-game (Section 3) is cryptographically sound but economically irrelevant to >95% of enterprise buyers. The construction proves a property no one in the enterprise segment is purchasing against. It *fails* if the author can show a realistic scenario inside enterprise threat models — e.g., a *third-party* AS federated in (model provider's AS attesting agent scope to the enterprise RS) where the enterprise genuinely does not trust the AS. That is a real scenario — but the construction doesn't surface it; it uses abstract "semi-trusted AS."

- **In-threat-model?** No — construction must address. The construction needs a buyer-level threat narrative: "Here is the specific federated trust topology where your Auth0 cannot help you," not a cryptographic game.

---

### Attack 2: 15-Second Proving Latency Fails the Operator Acceptance Test

- **Attack:** The attack prompts cite ~15s Groth16/PLONK proving time. Auth0 issues an access token in <100ms. WorkOS in similar range. An AI agent that stalls for 15 seconds on every permission check before acting is not deployable in real-time agentic pipelines — think LangChain tool calls, MCP server requests, or streaming multi-step agent loops where latency compounds. The construction's Section 1 claims "constant-size proof regardless of bitmask width" as a property — but constant-size is useless if the constant is 15 seconds. The `bench_rapidsnark.js` benchmarks exist but the construction nowhere addresses the latency tradeoff at the scenario level.

- **Why it works / why it fails:** Partially works. The construction mentions `rapidsnark_prover` is production proving and snarkjs is dev/test only. Rapidsnark on modern hardware closes the gap significantly (sub-second for small circuits). But the construction doesn't commit to a concrete latency figure under the production stack, nor does it define "acceptable" for the regulated agent scenario. The attack lands until the construction states: "With rapidsnark on AWS c6i.xlarge, AgentPolicy Groth16 proves in X ms — here is the benchmark."

- **In-threat-model?** No — construction must address. Add a concrete latency claim benchmarked against the production prover. "Constant-size proof" is only a differentiator if the constant is operationally acceptable.

---

### Attack 3: `draft-ietf-oauth-attestation-based-client-auth` Partially Closes Your Core Gap

- **Attack:** The toolbox includes [Client Attestation (draft-ietf-oauth-attestation-based-client-auth)](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.txt). This draft allows an Attester (e.g., the model provider, a hardware enclave, a Trusted Platform Module) to issue a signed `client-attestation` JWT asserting properties of the agent client — independently of the AS. The RS can verify these attestation claims offline. Combined with DPoP (which the construction already acknowledges), you get: agent makes cryptographic claim about its own properties → RS verifies offline → AS not involved in that verification path. The construction's Section 7 says "boolean-return RFC 7662 still relies on the AS to evaluate the predicate." But Client Attestation moves the evaluator to an Attester, not the AS. The construction doesn't address this variant in Section 7's failure modes.

- **Why it works / why it fails:** This is the strongest technical attack. Client Attestation + DPoP approximates AS-blind presentation. The remaining gap is *circuit-enforced implication closure* — a JWT attestation can assert `permissions=0b00001111` but cannot prove the implication constraints were evaluated in a trusted computation rather than simply asserted. A lying Attester can issue a malformed bitmask. The ZK circuit's R1CS constraints *are* the enforcement. But the construction needs to make this explicit: "Client Attestation shifts trust from AS to Attester, but implication closure is still an assertion, not a constraint. Here is what forgery looks like against Client Attestation."

- **In-threat-model?** Yes, partially — construction survives on implication closure, but Section 7 must explicitly address Client Attestation as a baseline variant. Currently it only addresses RFC 7662 and RFC 8693.

---

### Attack 4: The 2^64 Permission Space Is a Scenario the Construction Manufactured to Win

- **Attack:** The construction's Section 1 scenario says "regulated agent with 2^64 permission space where AS-side policy tables do not scale." Real enterprise RBAC has hundreds of roles, not 2^64 permissions. Auth0's Policy Engine, WorkOS's Role management, and AWS IAM all handle thousands of policies without issue. The 8-bit cumulative encoding in Bolyra (`circuits/CLAUDE.md` documents 8 bits, not 64) means the production system has *8* permission bits — 256 possible values. WorkOS can trivially enumerate these in a policy table. The "scales to 2^64" argument is theoretical cover for a system that ships with 256 actual states.

- **Why it works / why it fails:** Works as a GTM attack. The construction's differentiation narrative depends on a scale argument that its current circuit doesn't demonstrate and its buyers don't need. It fails if the author reframes: the advantage isn't scale to 2^64, it's *implication closure as a mathematical invariant enforced at proof generation time, not at policy evaluation time* — which holds even at 8 bits, because no configuration of WorkOS can prevent a misconfigured policy from granting `FINANCIAL_MEDIUM` without `FINANCIAL_SMALL`. That property exists in 256-permission systems. But the construction currently leads with scale, not invariant enforcement.

- **In-threat-model?** No — construction must address. Drop the 2^64 scaling narrative as the lead. Replace it with "policy misconfiguration is cryptographically impossible" — that's the buyer-level reason that holds at current circuit width.


## Persona: cryptographer

---

### Attack 1: Threat-Model Conflation — "Adversarial AS" covers two distinct games, only one is formalized

**Attack:** The ImplicationClosureForgery sub-game (Section 3) bounds `Pr[A wins] ≤ Adv_PLONK_ks` where "A wins" means producing an accepting proof for an implication-violating bitmask. This is a **soundness** game: the adversary is trying to forge a proof. But the Section 8 "adversarial-AS soundness" claim implicitly requires a second property — **presentation privacy from the AS**. Concretely: a corrupt AS that issued the credential already knows the full bitmask at issuance time. It cannot forge a proof (soundness holds), but it *already knows* what the agent would be authorized to prove. The RS's predicate request goes through the agent, not the AS — but if the AS is logging which predicates the agent is querying *at the moment of credential issuance* or during any AS roundtrip, the "adversarial AS cannot observe selective disclosure" claim requires a separate **AS-blindness game**, not the ImplicationClosureForgery game.

**Why it matters:** These are two reducible but distinct properties: (a) AS cannot forge proofs for bits it didn't grant — covered by knowledge soundness; (b) AS cannot learn which bits the agent disclosed to which RS at what time — requires a separate indistinguishability game with a simulator that works even when the AS is a distinguisher. The construction Section 8 uses "adversarial-AS" to mean both, but only (a) is formalized.

**In-threat-model?** No — construction must define a separate AS-blindness game with explicit simulator. Without it, the lead differentiator claim ("adversarial-AS soundness") is conflating soundness with privacy.

---

### Attack 2: Subverted PLONK SRS Collapses the Knowledge Soundness Bound

**Attack:** The ImplicationClosureForgery game (Section 3) bounds the adversary's advantage against `Adv_PLONK_ks` — knowledge soundness of PLONK. PLONK knowledge soundness is proven in the **algebraic group model (AGM) + random oracle model (ROM)** under an *honestly generated* universal SRS. If the SRS generator is malicious (or the toxic waste is leaked), the AGM-based knowledge extractor fails: the adversary can produce valid-looking proofs for false statements with advantage 1, not `Adv_PLONK_ks`. 

This is especially acute for the adversarial-AS scenario. The AS controls or influences the deployment environment for Bolyra. If the AS also controls infrastructure used during the PLONK ceremony (e.g., a coordinator node, the MPC), a subverted AS can compromise the SRS and then produce proofs attesting to implication-compliant bitmasks it was never issued. The construction mentions Groth16 ceremony reuse (Section: Circuits) from Semaphore v4 for `HumanUniqueness` and correctly notes "don't regenerate it," but for `AgentPolicy` and `Delegation` using PLONK, the universal SRS is described only as `pot16.ptau` — a project-generated artifact. What is the ceremony for `pot16.ptau`? Who generated it? Under what model?

**Why it matters:** A subverted `pot16.ptau` means every `Adv_PLONK_ks` bound in the paper is vacuous. The construction's strongest claim — circuit-enforced implication closure no AS can bypass — falls to an AS that participated in a two-party `pot16.ptau` generation with no external verifier.

**In-threat-model?** No — the construction must either (a) state that the SRS is trusted-out-of-scope (and bound the adversary's scope accordingly), or (b) use a *updatable universal SRS* with a verifiable ceremony transcript, or (c) prove security under subverted setup (impossible for standard PLONK KS — would require a different primitive).

---

### Attack 3: Nullifier Stability Enables Cross-Session RS-Level Profiling — Missing RS-Adversary Game

**Attack:** `nullifierHash` is a stable public output of `HumanUniqueness` (per the CLAUDE.md: `humanMerkleRoot, nullifierHash, nonceBinding`). By design it prevents replay across the same RS. But because `nullifierHash` is *stable per scope_id per identity*, every presentation to the *same RS* reveals the same pseudonym. The construction's `sessionNonce` binding (Section architecture, "handshake nonce binding") prevents proof replay but does NOT re-randomize the nullifier. A resource server accumulates tuples `{nullifierHash, timestamp, predicate_result}` across sessions. Over time it builds a frequency profile: "this nullifier requests FINANCIAL_MEDIUM 40x/day." If two colluding RSes compare nullifier sets, they can identify the intersection — agents that authenticated to both. This is **cross-RS linkability via stable nullifier**, a known Semaphore attack vector. The adversary here is an **adversarial RS**, not covered by the AS-adversary game.

More precisely: the claim "no configuration of RFC 7662 can match" implies Bolyra provides *better* privacy than OAuth2. But a standard OIDC deployment with pairwise pseudonymous identifiers (`sub` per RP, RFC 8176 AMR) gives per-RS unlinkability by construction — no stable cross-RS identifier. Bolyra with a stable `nullifierHash` per scope_id is *worse* on this axis unless scope_id is RS-specific. The construction does not define whether `scope_id` is per-RS or per-application.

**Why it matters:** If `scope_id` is global (e.g., `bolyra://agent-policy/v1`), the nullifier is the same across all RSes and the adversary trivially links. If scope_id is RS-specific, who binds it? The AS? Then the AS controls linkability — an adversarial AS can assign the same scope_id to multiple colluding RSes to link sessions. This requires a formal unlinkability game (standard Semaphore paper has one) and a reduction showing scope_id freshness is adversary-independent.

**In-threat-model?** No — the construction must define a cross-RS unlinkability game and show that the scope_id binding prevents the above. Otherwise the privacy claim against an adversarial-AS is incomplete on the RS-linkability axis.

---

### Attack 4: ZK Claim Lacks a Simulator — HVZK ≠ Malicious-Verifier ZK for the Selective Disclosure Use Case

**Attack:** Section 8 (Property 1 and implied by the selective disclosure claim) asserts the RS learns only predicate satisfaction, not the full bitmask. For this to be a formal ZK statement, the construction must exhibit a **simulator** S that, given only the public inputs (RS's predicate description and the verification key), produces a transcript indistinguishable from a real proof — *without knowing the witness* (the full bitmask). PLONK is **honest-verifier ZK (HVZK)**: the simulator works when the verifier samples the challenge honestly (Fiat-Shamir: hash of the transcript prefix). But HVZK does not compose in general, and does not imply security when the RS is adversarial and can choose which predicate to query adaptively.

Concretely: the RS sends predicate `pred = "bit 3 set"`. The agent generates a PLONK proof with private input = full bitmask, public input = predicate. If the RS then sends a *different* predicate `pred' = "bit 4 NOT set"` (re-querying the agent with a different challenge), can it use the *pair* of proofs to triangulate the full bitmask? For a single-bit predicate each proof individually reveals only the queried bit, but adaptive multi-query ZK (simulation extractability under adaptive probing) is a stronger property than HVZK and is not referenced anywhere in the construction.

The relevant property is **simulation extractability (SE)** or **composable ZK** — required for the agent to be safe across multiple RS interactions. The construction cites `Adv_PLONK_ks` for soundness but never cites an SE or composable-ZK result for the privacy direction. Without this, an RS that can issue multiple predicate challenges (which is the normal operational model — a single RS session may require multiple capability checks) can potentially extract more than any single predicate reveals.

**Why it matters:** The differentiator claim "AS-blind presentation, agent chooses what to disclose at the moment of use" requires composable ZK or simulation extractability under adaptive multi-query. HVZK (what standard PLONK provides) is necessary but not sufficient. The construction must either (a) cite a simulation-extractable PLONK variant (e.g., Plonkish + Fiat-Shamir in the ROM provides this under specific conditions — cite the theorem), or (b) restrict the claim to single-predicate sessions only.

**In-threat-model?** No — the construction must either (a) prove that the Fiat-Shamir transform of PLONK in the ROM gives simulation extractability (the Kosba et al. / Chase-Lysyanskaya-style argument), or (b) constrain the adversarial RS to a single challenge per session and bound the information leakage explicitly across multi-session interactions.


## Persona: cu_ciso

### Attack 1: The Examiner Artifact Problem

- **Attack:** During NCUA exam prep, my VSE (Vendor Security Examination) packet requires me to demonstrate that member data access is logged, attributable, and reviewable by a non-technical auditor. The construction's lead differentiator — "adversarial-AS soundness with circuit-enforced implication closure" — produces a Groth16/PLONK proof object as the access artifact. When I hand an NCUA examiner a `nullifierHash` and a bitmask, they ask me which FFIEC CAT Baseline statement this satisfies. I have no answer. RFC 7662 introspection logs go into my SIEM as a structured JSON event with `sub`, `scope`, `iat`, `exp` — fields my existing tooling parses. The construction produces a proof that *verifies* but does not *narrate*. Section 8 Property 1 says the RS has cryptographic assurance independent of AS cooperation, but my examiner doesn't want cryptographic assurance — they want a human-readable access log tied to a member account number.
- **Why it works:** The construction nowhere specifies what artifact the RS writes to the audit log after `verifyHandshake` succeeds. A passing proof is not a log entry. NCUA Part 748 Appendix A requires the institution to maintain audit trails of access to member information systems. The circuit enforces structural invariants — it does not emit SIEM-compatible events.
- **In-threat-model?** No. The construction must address the post-verification logging layer: what structured record does the RS emit, what fields does it contain, and how does that record chain back to a member identity the examiner can cross-reference against your core processor?

---

### Attack 2: Trusted Setup as Unauditable Third-Party Risk

- **Attack:** The construction references `pot16.ptau` and project-specific `.zkey` artifacts for AgentPolicy and Delegation circuits. Under NCUA Part 748 Appendix B (Guidelines for Safeguarding Member Information) and my Vendor Management Policy, I must perform due diligence on any cryptographic material I rely on for access control decisions. I ask: who ran the trusted setup ceremony, what was the multi-party contribution audit trail, how do I validate it independently, and what is the remediation path if a contributor's entropy was compromised? RFC 7662 runs on TLS + standard PKI — my examiner has a framework for that (FFIEC IT Examination Handbook, Information Security Booklet, Section III.C). There is no FFIEC booklet section for "Groth16 powers-of-tau ceremony audit." I cannot satisfy my third-party risk questionnaire for a cryptographic artifact with no recognized audit standard.
- **Why it works:** Section 3's ImplicationClosureForgery sub-game bounds forgery probability to `Adv_PLONK_ks` — but that bound is only valid if the `.zkey` was generated honestly. A compromised ceremony collapses the entire security argument, and I have no contractual counterparty and no regulatory template for auditing it. This is a gap the construction does not address, because it treats the trusted setup as a solved problem. It is not solved from a vendor risk standpoint.
- **In-threat-model?** No. The construction must either (a) point to a recognized ceremony audit standard my examiner will accept, (b) justify why PLONK's universal SRS eliminates the per-circuit ceremony risk for AgentPolicy/Delegation (this is partially true and should be stated explicitly), or (c) acknowledge this as a residual risk with a compensating control narrative.

---

### Attack 3: AS-Blind Presentation Breaks My Access Log Completeness Requirement

- **Attack:** Section 8 Property 3 (formerly Property 1) advertises "AS-blind presentation" — the agent chooses what to disclose at the moment of use without an AS roundtrip. I read this as: the authorization server has no record of this access event. Under GLBA Safeguards Rule §314.4(h), I must monitor and test my access controls. Under FFIEC CAT Domain 3 (Cybersecurity Controls), I need a complete record of what accessed what, when. If the agent can present a valid proof to the RS without the AS knowing, my AS-side log has a gap. My core processor session log may show a transaction, but the authorization event — *who authorized this agent to act* — lives only in the ZK proof, which is a transient artifact unless I explicitly store it. RFC 7662 centralizes authorization events at the AS by design; every introspection call is a log entry. The construction's AS-blind property is a cryptographic feature and an operational liability.
- **Why it works:** The construction frames AS-blindness as strength (no AS cooperation needed for verification). From my seat, AS cooperation is a *feature*, not a bug — it's where my audit log lives. The construction does not specify where the authorization event log lives when the AS is not in the loop. My NCUA examiner will ask: "Show me every time this agent accessed member data in the last 90 days." If the answer requires reconstructing ZK proof objects from RS storage, that is not a defensible audit posture.
- **In-threat-model?** No. The construction should specify an explicit logging obligation at the RS: upon successful `verifyHandshake`, the RS must write a structured event (proof hash, disclosed permission predicate, timestamp, session nonce, member account reference) to the institution's audit log. Without this normative requirement, AS-blind presentation is an audit gap, not a feature.

---

### Attack 4: Incident Response — Who Do I Call at 2am?

- **Attack:** My Tier 1 ops team gets a call: an agent credential is suspected compromised. Under RFC 7662, I revoke the token at the AS — one API call, credential is dead within seconds, my SIEM shows the revocation event, and I can demonstrate to the examiner that I acted within the required timeframe. Under this construction, Section 8 advertises AS-blind verification. That means revocation requires either (a) on-chain registry update (Section 3 references an on-chain registry) or (b) waiting for credential expiry. The on-chain path introduces latency, gas costs, and dependency on Base Sepolia (or mainnet) liveness. If the chain has a 1% outage or my RPC provider is down, the compromised credential continues to verify locally at the RS. My Vendor Management Policy requires documented incident response procedures with RTOs. The construction does not specify the revocation latency SLA or the fallback when the on-chain registry is unavailable.
- **Why it works:** The construction is silent on revocation. The `nullifierHash` and nonce-binding prevent replay of the *same* proof, but a fresh proof generated from a compromised key before revocation is processed is valid. NCUA Part 748 requires me to have an information security incident response program. "Wait for on-chain confirmation" is not an RTO my board will accept for a compromised credential with access to `FINANCIAL_UNLIMITED` (bit 4). RFC 7662 revocation is synchronous and AS-controlled — the construction's AS-blind model defers revocation to a channel I do not control in real time.
- **In-threat-model?** No. The construction must specify: (1) the revocation mechanism and its worst-case latency, (2) the RS behavior when the on-chain registry is unreachable (fail-open vs. fail-closed, with the regulatory implication of each), and (3) whether the RS is required to check revocation status on every `verifyHandshake` or only at credential issuance. Without this, the CISO cannot sign off on deployment under any incident response policy that satisfies NCUA Part 748 Appendix B §III.C.


## Persona: rfc7662_advocate

### Attack 1: Signed JWT Introspection Reduces the Adversarial-AS Gap to a Key-Compromise Argument, Not a Structural One

- **Attack:** The construction's Section 7 dismisses boolean-return RFC 7662 because "a compromised AS returns the wrong boolean." But `draft-ietf-oauth-jwt-introspection-response` changes the threat model: the AS signs a JWT asserting `"scope_satisfies_predicate": true` with its long-term key. The RS caches the AS public key and verifies entirely offline — no live AS roundtrip, no man-in-the-middle window. Section 8 Property 1 ("who evaluates the predicate") now reduces to: *can a compromised AS forge a signature vs. can an adversarial prover forge a PLONK proof?* Both reduce to a cryptographic hardness assumption (ECDSA/RSA vs. KZG). The construction claims its advantage is "circuit constraint vs. AS assertion," but a signed JWT is a cryptographic binding too. The Section 3 "Critical distinction" paragraph does not address this equivalence.

- **Why it works / fails:** It works as a pressure point because the construction conflates "AS is online" with "AS is the trust anchor." It fails to fully break the construction if the adversarial-AS model allows the AS to mint tokens *at issuance* (not just at introspection time): a dishonest AS can embed a false bitmask in the access token and then sign a JWT asserting correct implication closure. The signed JWT proves the AS *claims* closure; the circuit proves closure *is* enforced. The gap is real but narrow, and Section 3 must state it precisely: the ZK proof is a proof *about the credential's bit-pattern*, not about the AS's assertion *that* the bit-pattern is correct.

- **In-threat-model?** Yes — construction survives if it tightens Section 3 to distinguish "AS certifies predicate evaluation" (JWT) from "circuit constrains witness to a valid bitmask" (ZK). The adversarial-AS must be defined as one that can mint a *malformed bitmask at issuance* and then sign a truthful JWT about that malformed credential. That is the gap JWT introspection cannot close.

---

### Attack 2: Pairwise Subject Identifiers + Per-RS Audience Binding Already Achieve AS-Blind Unlinkability at the RS Layer

- **Attack:** Section 8 Property 3 (formerly Property 1, now moved to third position) claims "AS-blind presentation." OIDC Pairwise Pseudonymous Identifiers (PPIDs) combined with RFC 8707 resource indicators give each RS a different `sub` and a different audience-scoped token. RS-A cannot correlate to RS-B because the `sub` values differ and the token is audience-locked. The AS issues tokens at issuance; the RS verifies offline via the AS's JWKS. No AS roundtrip per presentation, no cross-RS correlation. The construction moves AS-blind to Property 3 without explaining why PPID + RFC 8707 fails here.

- **Why it works / fails:** The attack is valid at the *linkability* layer. It fails at the *selective disclosure* layer: PPIDs hide *identity* across RSes, but the token still carries a fixed, fully-revealed scope claim. An RS sees the entire permission bitmask (or whatever claims the AS chose to include), not a zero-knowledge predicate evaluation. The agent cannot choose, at runtime, to prove only "bit 3 is set" without revealing bits 0–7. PPID breaks person-level linkability; it does not provide claim-level selective disclosure. The construction's Section 3 needs to make this crisp: AS-blind is a weaker property than agent-controlled selective disclosure over an arbitrary runtime predicate.

- **In-threat-model?** Yes — construction survives, but Property 3 currently reads like "AS is not in the loop," which PPID + RFC 8707 also achieves. The property needs renaming to "agent-controlled runtime selective disclosure over an arbitrary predicate, with AS-blind proof generation" to differentiate from PPID.

---

### Attack 3: RFC 8693 Token Exchange Implements One-Way Scope Narrowing Without a Delegation Circuit

- **Attack:** The construction's Delegation circuit enforces that delegated credentials can only narrow permissions. RFC 8693 §2.1 defines `scope` on the token exchange request: the exchange AS issues a new token with `scope` ⊆ original `scope`, enforced by AS policy. RFC 8693 also defines `may_act` for chained delegation. Combined with RFC 8707 audience restriction, a delegation chain produces: original token → exchange → narrowed-scope, audience-bound token, with each step AS-verified. The Delegation circuit claims to enforce this as an R1CS constraint, but if the AS is honest, RFC 8693 provides the same monotone narrowing property without any ZK machinery.

- **Why it works / fails:** The attack is precisely correct under an honest-AS assumption. It breaks under the adversarial-AS model: an adversarial AS running RFC 8693 can issue an exchange response with `scope` *wider* than the original token's scope — the AS controls both the original issuance and the exchange. The Delegation circuit, by contrast, takes the original credential's bitmask as a *public input* and proves in-circuit that `delegated_bits & ~original_bits == 0`. Even a lying prover cannot produce an accepting proof that violates this constraint. The construction's Section 8 ImplicationClosureForgery sub-game covers this, but it is never explicitly compared to RFC 8693's enforcement model. Section 3's "Critical distinction" paragraph should add: "RFC 8693 scope narrowing is a policy enforcement by the AS; Delegation circuit narrowing is a cryptographic constraint on the witness."

- **In-threat-model?** Yes — construction survives under adversarial-AS. The gap must be stated explicitly against RFC 8693 specifically; the current draft only mentions RFC 7662.

---

### Attack 4: The ImplicationClosureForgery Sub-Game Assumes the Prover Commits to the Honest Bitmask — But Who Checks the Input Credential?

- **Attack:** The Section 3 ImplicationClosureForgery sub-game proves `Pr[A wins] <= Adv_PLONK_ks` — no accepting proof can attest to an implication-violating bitmask. This is sound. But the sub-game is conditioned on the prover using *their actual credential's bitmask* as the witness. If an adversarial AS issued a credential whose bitmask is itself structurally invalid (e.g., bit 3 set without bit 2, violating the `FINANCIAL_MEDIUM` implies `FINANCIAL_SMALL` rule) *at issuance time*, and the circuit's G5/G6 constraints check implication closure only *over the witness*, then the circuit proves "this bitmask satisfies implication closure" — but it proves this about the *already-malformed credential*. The RS verifies the proof and concludes the presented credential is valid. The forgery happened at issuance, not at proof time. The ImplicationClosureForgery game needs to include a credential-issuance phase and prove that the enrollment circuit (or credential schema) also enforces implication closure, so a malformed credential cannot be issued in the first place.

- **Why it works / fails:** This is a genuine gap if the AgentPolicy circuit only checks the bitmask provided by the prover but does not independently re-derive or constrain how that bitmask was originally formed. The construction must show either (a) the credential issuance circuit also enforces G5/G6 closure, or (b) the proof system commits to the bitmask in a way that ties it to a verifiable issuance event. If the bitmask is a private witness with no linkage to a verifiable public commitment from the operator, the implication closure proof is only as strong as the prover's honesty about their own credential.

- **In-threat-model?** Partially — this is not an RFC 7662 baseline attack but an internal soundness gap. An adversarial *operator* (not AS) who issues malformed credentials to their own agent could exploit this. If the threat model includes adversarial operators, the construction must address it. If operators are trusted, the sub-game should say so explicitly.


## Persona: spiffe_engineer

### Attack 1: ZK Attestor Plugin — You Are Building at the Wrong Abstraction Layer

- **Attack:** SPIRE's node/workload attestation pipeline is explicitly pluggable (see `spire-api/plugin/agent/v1/`). A ZK attestor plugin could produce JWT-SVIDs carrying only the attested scope claim — no full bitmask disclosed to the RS. The SVID is self-contained; the RS validates the trust bundle signature offline. This directly matches the construction's Section 8 Property 3 ("AS-blind presentation") without a new protocol. The claim in Section 3 that "the RS has no recourse" against a lying AS does not apply here: SPIRE attestation is anchored to platform evidence (TPM, k8s SATs, IMDSv2) that a compromised SPIRE server *cannot* retroactively forge without also subverting the attestation chain. The adversarial-AS model that Section 3 uses as the lead differentiator does not hold against a hardened SPIRE deployment.

- **Why it works / why it fails:** The construction's reframe in Section 8 Property 1 rests on the claim that "who evaluates the predicate" matters — AS assertion vs. circuit constraint. A ZK attestor moves predicate evaluation into the attestation plugin, which is invoked at SVID issuance time under a hardware-rooted attestation chain. The output SVID is still a signed assertion, but the signing key is protected by the same HSM/TPM root that the construction would need to trust anyway for key custody. The construction does not show that its circuit constraint is strictly stronger than a hardware-rooted attestation assertion; it only shows it is stronger than a software AS with no platform anchor.

- **In-threat-model?** No — construction must address. Section 3's "Critical distinction" paragraph argues boolean-return RFC 7662 fails because the AS can lie, but does not distinguish between a software AS and a hardware-attested SPIRE server. The adversarial-AS sub-game in Section 3 (ImplicationClosureForgery) needs a corresponding sub-game for a *hardware-attested* AS variant before the lead differentiator holds.

---

### Attack 2: WIMSE WPoP Already Covers AS-Blind Presentation

- **Attack:** `draft-ietf-wimse-s2s-protocol` defines workload proof-of-possession (WPoP): the access token is cryptographically bound to the workload's SVID private key. The RS verifies the binding offline — no AS roundtrip, no AS cooperation needed at presentation time. The construction's Section 8 Property 3 ("AS-blind presentation — agent chooses what to disclose at the moment of use") is the stated differentiator, but WIMSE WPoP already satisfies "no AS roundtrip" and "RS verifies independently." The construction's claim that RFC 8693 + DPoP cannot match this applies to token-exchange-with-roundtrip deployments, but WIMSE explicitly moves past that. Why not contribute the ZK predicate evaluation as a WIMSE extension (e.g., a new `cnf` binding type carrying a PLONK proof) rather than standing up a parallel trust domain?

- **Why it works / why it fails:** The attack partially fails because WIMSE WPoP binds to a *fixed* scope claim embedded at issuance time — the agent cannot narrow the disclosed scope at presentation time without a new token. The construction's AgentPolicy circuit does allow runtime-adaptive predicate selection (the prover picks the predicate at prove-time, not issuance-time). However, the construction does not clearly separate these two properties in Section 8: Property 3 conflates "no AS roundtrip" (which WIMSE matches) with "runtime predicate selection" (which WIMSE does not match). As written, a WIMSE implementer reading Section 8 can correctly claim the AS-blind property is already met.

- **In-threat-model?** Partially. The "no AS roundtrip" axis is already covered by WIMSE and should be removed from Section 8 Property 3 or narrowed. The *runtime-adaptive predicate selection* property is the genuine gap and should be extracted as a standalone property with a concrete WIMSE counter-example showing why a new token is required there.

---

### Attack 3: Trusted Setup Is a Weaker Trust Anchor Than a CA Chain

- **Attack:** Section 3's ImplicationClosureForgery sub-game bounds `Pr[A wins] <= Adv_PLONK_ks`, which assumes the PLONK structured reference string (SRS) was generated honestly and the toxic waste was destroyed. In a poisoned ceremony — or a single-party SRS generation — an adversary holding the toxic waste can produce a valid proof for *any* statement, including an implication-violating bitmask (e.g., `FINANCIAL_MEDIUM` set without `FINANCIAL_SMALL`). The sub-game's probability bound collapses to 1. SPIFFE/SPIRE's trust anchor is an X.509 root CA: compromising it is operationally equivalent, but the operational security tooling (HSM ceremony procedures, RFC 5280 PKI audits, CT logs) is decades more mature than ZK trusted-setup ceremony audits. The construction trades a well-understood CA trust model for a younger, harder-to-audit trusted setup.

- **Why it works / why it fails:** The attack lands on Section 3 because the sub-game's bound is conditional on ceremony soundness, but the construction contains no section on trusted setup ceremony requirements, ceremony auditing, or universal SRS reuse (e.g., the Zcash perpetual powers-of-tau). The construction does note that `HumanUniqueness` reuses the public Semaphore v4 ceremony (CLAUDE.md), but AgentPolicy and Delegation use `pot16.ptau` generated per-project — the adversarial-AS soundness argument for those circuits depends entirely on that ceremony's integrity, which is not addressed in the security model.

- **In-threat-model?** Yes and no. Circuit soundness under an honest SRS is in-scope and the sub-game is correct for that regime. But the *ceremony threat model* is out of scope and the construction must either explicitly disclaim it or add a ceremony section showing it is at least as strong as SPIRE's CA ceremony requirements.

---

### Attack 4: The 8-Bit Implication Closure Is Expressible in X.509 Policy Extensions

- **Attack:** The permission bitmask's partial order (bit 3 implies bit 2, etc.) is a finite lattice with 8 elements. X.509 certificate policy OIDs under id-ce-certificatePolicies can encode a structured permission hierarchy; a SPIRE SVID with a custom extension carrying a bitmask validated at issuance by SPIRE's entry selector policy achieves the same implication closure at issuance time. The construction's Section 3 argument that "G5/G6/G4 are R1CS constraints, not assertions" is true at *verification* time — the RS verifies the circuit, not a SPIRE policy. But implication closure at *issuance* time (SPIRE entry policy) is functionally equivalent for any RS that only checks scope membership, not proof-of-correct-issuance. The construction must show a scenario where an RS *needs* to verify that implication closure was enforced at the circuit level rather than trusting the issuer.

- **Why it works / why it fails:** The attack fails when the RS itself is in an adversarial environment where it cannot trust the issuer's policy enforcement (the adversarial-AS model). If the SPIRE server's entry policy can be bypassed by an insider, an implication-violating SVID could be issued. A PLONK verifier embedded in the RS smart contract (or on-chain verifier) cannot be bypassed by the issuer post-issuance. The construction's on-chain verifier path (`contracts/` Hardhat Solidity verifiers) is where this argument is strongest — a Solidity `verifyProof` call enforces implication closure without trusting any off-chain party. This is not clearly stated in the current Section 3; the argument is framed as "circuit constraint vs. AS assertion" generically, but the *on-chain verifier* is the specific instantiation where the SPIFFE alternative has no equivalent.

- **In-threat-model?** No — construction must address. Section 3 should ground the "circuit constraint vs. assertion" argument specifically in the on-chain verifier path, where the RS is a smart contract that cannot make an AS roundtrip and cannot trust a SPIRE federation anchor. Off-chain RS deployments remain vulnerable to the issuer-policy-equivalence attack and the construction should scope its strongest claim to the on-chain context or provide a separate argument for off-chain RSes.
