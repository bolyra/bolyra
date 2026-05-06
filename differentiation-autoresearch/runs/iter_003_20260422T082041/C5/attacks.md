# Tier 3 Adversarial — C5 Bolyra as MCP auth, generally

## Persona: auth0_pm

---

### Attack 1: The Construction's Own §6 Falsifies "Strict Dominance"

- **Attack:** The claim is "Bolyra *strictly dominates* vanilla OAuth 2.1 + MCP in the general case." Strict dominance is a formal claim: Bolyra must be ≥ on every dimension and strictly > on at least one. §6 of the construction explicitly tables a "20–30× latency cost" vs OAuth DPoP across initial auth, per-hop delegation, and 3-hop chains. One acknowledged regression — latency — is sufficient to falsify strict dominance by definition. I don't need to find a cryptographic flaw. I quote the author's own benchmark table in the procurement meeting and we're done. WorkOS issues tokens in <100ms. If your first hop adds 2–15s on every agent-to-tool call in the general case, no SRE signs the runbook.

- **Why it works / why it fails:** It works because the construction never updated the top-level claim (C5: "strictly dominates") after accepting the Gap 4 remediation that admits the latency regression. The narrowed hypotheses and the "strictly dominates" headline are now in direct contradiction within the same document.

- **In-threat-model?** No — construction must address. Either retract "strictly dominates" and replace with a Pareto-dominance claim with explicit carve-outs, or show the latency is irrelevant to the general case (which would require re-arguing general case).

---

### Attack 2: SRS Concentration Is a Strict Regression on Enterprise Trust Architecture

- **Attack:** The construction states verbatim: *"OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS."* Enterprise procurement has a name for this: single point of cryptographic failure. Auth0's trust model has no universal ceremony whose compromise retroactively voids every token ever issued across every tenant. Bolyra's Game 4 "blast radius under H3 portability" analysis describes graceful degradation and re-ceremony mitigations — but those mitigations require operators to accept that a future unknown event invalidates their entire deployed auth infrastructure simultaneously. In the general case, the distributed trust property of OAuth isn't a weakness; it's load-bearing for enterprise risk management. The construction is offering a worse trust topology and calling it a feature (portability).

- **Why it works / why it fails:** The construction acknowledges the blast radius but frames it as an acceptable tradeoff for portability. This framing only holds if portability with unlinkability is a strong general-case requirement — which is what C5 is supposed to establish but hasn't proven outside regulated niches.

- **In-threat-model?** No — construction must address. The top-level claim requires showing that the SRS concentration risk is dominated by the H3 portability benefit in the *general* (non-regulated) case, not just that mitigations exist.

---

### Attack 3: H3 Portability Claim Is Already Closed by RFC 7591 + DPoP, and Unlinkability Is a Liability for General MCP Operators

- **Attack (two-part):** First, RFC 7591 Dynamic Client Registration ships today in Auth0, Okta, and Cloudflare Access. The H3 residual after narrowing is "unlinkable client\_id" — not portability per se, because dynamic registration already handles portability without a ceremony. Second, and more damaging: in the general MCP case, operators *want* to know what agent is calling their tool. Audit logs, rate limiting, abuse detection, billing attribution — all of these require a stable, linkable client identity. Unlinkability is a compliance *liability* for a generic SaaS tool. The construction's H3-narrowed claim trades a systemic SRS blast radius for a property that the majority of MCP operators actively don't want.

- **Why it works / why it fails:** This exposes that H3's residual value (unlinkability) is only useful in a privacy-preserving or regulated scenario — exactly the niche the construction was supposed to escape from. The "zero-config" framing obscures that the meaningful differentiation is unlinkability, not portability.

- **In-threat-model?** No — construction must address. H3 needs to be reframed to show that unlinkability (not just portability) is a general-case need, or it needs to be retired as a niche hypothesis.

---

### Attack 4: Post-Gap-1 Narrowing Collectively Converts Every Hypothesis into a Regulated-Niche Claim

- **Attack:** Read the five narrowed hypotheses together:
  - H1-narrowed: AS-blind binding — only matters if you distrust your own authorization server. General-case operators run Auth0 or WorkOS; they trust their AS by construction.
  - H2-narrowed: operator-credential binding — only matters if runtime model identity must be authenticated. General MCP deployments authenticate the *client application*, not the model weights.
  - H3-narrowed: unlinkable client\_id with SRS tradeoff — see Attack 3.
  - H4-narrowed: cross-epoch forward secrecy only, with explicit intra-epoch linkability caveat — OAuth DPoP + short-lived tokens already handles the practical forward-secrecy requirement for non-paranoid operators.
  - H5-narrowed: AS-blind delegation with explicit latency regression vs RFC 8693 *and* vs SPIRE/WIMSE — SPIRE issues SVIDs in milliseconds; the AS-blind property is only load-bearing when you distrust the workload identity infrastructure.

  Every hypothesis, after the author's own remediation, now reads "this matters only if you distrust [incumbent]." That is the definition of a regulated-niche claim, not a general-case claim. The Gap 1 remediation closed the overstatement gaps but in doing so collapsed the general-case argument. The target\_strength of 10 and the "strictly dominates" headline were not updated to reflect what the narrowed construction actually proves.

- **Why it works / why it fails:** This is the structural attack. The construction is internally consistent after remediation, but the top-level claim (C5) was written before the narrowing and was never revised. The gap\_to\_close field even states the requirement: find a primitive "needed by default in agent-economy MCP, not only in regulated scenarios." The narrowed hypotheses do not satisfy that requirement.

- **In-threat-model?** No — construction must address. The gap\_to\_close criterion is unmet by the narrowed construction. Either identify a new primitive that survives without the AS-distrust or paranoid-operator assumption, or lower C5's target\_strength and restate the claim as "Bolyra dominates in regulated/privacy-sensitive MCP deployments."


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. Let's test that.*

---

### Attack 1: Intra-Epoch Linkability Falsifies the H3 Unlinkability Game

**Attack:** The adversary is a semi-honest RS (or passive observer on the MCP transport). It collects public inputs from multiple proof verifications within a single epoch. The construction's own Gap 5 disclosure states: "constant `agentMerkleRoot` is explicitly called out" as a linkability vector within an epoch. `agentMerkleRoot` appears in the public inputs of every AgentPolicyV2-Ratcheted proof. The adversary computes: if `proof_i.agentMerkleRoot == proof_j.agentMerkleRoot`, then sessions `i` and `j` originate from the same agent. This is a trivial deterministic link — distinguishing advantage is exactly 1.

**Why it works / fails:** It works. There is no randomization of `agentMerkleRoot` within an epoch; per-session Pedersen re-randomization is explicitly deferred. The adversary wins the unlinkability game (formally: a session-linking game where Adv outputs `(i,j)` and wins if they share an agent identity and Adv's output is correct) with probability 1 against any RS that sees two proofs in the same epoch.

**In-threat-model?** No. H3-narrowed claims "unlinkable client_id." This claim cannot be sustained while `agentMerkleRoot` is constant public input per epoch. The construction must either (a) scope H3 to cross-epoch only and relabel it accordingly, or (b) close the gap with the deferred per-session re-randomization before asserting the claim. "Explicitly called out" is not the same as "game-bounded." A 2K-constraint fix that is deferred is not shipped.

---

### Attack 2: Nullifier Precomputation via Scope-Controlled AS

**Attack:** Consider Game 2 (the erasure/forward-secrecy game). The nullifier scheme computes a session tag as a function of agent secret and `scope_id`. The construction notes that `longTermSecret` was *removed from the circuit* to reduce constraints (Gap 4). If `longTermSecret` is now an out-of-circuit witness — supplied by the operator and only committed to via the Merkle root — the AS controlling `scope_id` assignment can mount the following: for each enrolled agent `k` with known enrollment commitment, the AS enumerates candidate `scope_id` values it controls, computes the expected nullifier `nul_k = PRF(secret_k, scope_id)` if it can observe or guess `secret_k`'s structure, or — more practically — it assigns *identical* `scope_id` values across two distinct RSes. When the same agent authenticates at both RSes in the same epoch, the AS observes identical nullifiers and confirms agent identity across RSes.

**Why it works / fails:** This works when the AS controls scope namespace and at least two colluding RSes. The Game 2 formalization adds `Session()`, `Reveal()`, and `Challenge()` oracles, but the threat model for the AS's scope-assignment power is unspecified. Is the AS assumed to assign scope_ids honestly? That is trust assumption A-unlisted. The Bellare-Yee style treatment of erasure does not bound what the AS learns about nullifiers before erasure completes.

**In-threat-model?** No. The attack prompt states this directly: "if AS knows the scope_id, can it precompute nullifiers for all enrolled agents?" The construction's Game 2 must explicitly bound the AS's scope_id control power, or H4's forward-secrecy claim is only proved in a model where the AS is semi-honest with respect to scope assignment — a restriction that should appear as a named trust assumption.

---

### Attack 3: Groth16 Is HVZK — Malicious RS Breaks the ZK Claim for H1

**Attack:** H1-narrowed claims "AS-blind binding": the AS learns nothing about the human identity beyond what the public inputs reveal. The proof system used is Groth16 (human leg) composed with PLONK (agent leg). Groth16 achieves *honest-verifier* zero-knowledge (HVZK) in the random oracle / generic group model. HVZK means the simulator works only when the verifier uses the prescribed verification algorithm with the correct verification key. A malicious RS (the verifier in MCP deployments) can deviate: it can present a malformed or adversarially chosen verification key, or it can replay proofs across contexts. Under malicious verifier, Groth16's ZK simulator fails — it requires the verifier's randomness to be honestly generated. The construction does not state whether it achieves MVZK (malicious-verifier ZK) or simulation-extractability (SE-NIZK), both of which require stronger assumptions (e.g., knowledge of exponent, or a shrewder proof system like Fiat-Shamir heuristic over a simulation-sound variant).

**Why it works / fails:** Without an explicit simulator construction for the malicious-verifier setting, the H1 ZK claim is unproven. The standard reduction for Groth16 security in the generic group model does not extend to malicious verifiers. The construction would need to either (a) prove MVZK via a non-black-box simulator, (b) switch to a simulation-extractable SNARK (e.g., Groth-Maller or a variant), or (c) explicitly bound the RS to honest verification behavior as a trust assumption.

**In-threat-model?** No. MCP deployments assume the RS is a third-party server that could be adversarial (the entire motivation for Bolyra). An RS that is simultaneously verifier and potential adversary is precisely the malicious-verifier setting. The construction must state which zero-knowledge notion it achieves and provide the corresponding simulator.

---

### Attack 4: Universal SRS Subversion Is Not "Detectable" — It's a Retroactive Catastrophic Failure

**Attack:** Gap 6 acknowledges: "OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS." The proposed mitigations are "graceful degradation, detection, and re-ceremony." The formal attack: an adversary who participates in the SRS ceremony and retains toxic waste can, *at any future time*, forge arbitrary proofs for any circuit over that SRS. In PLONK, knowing the secret `τ` (the SRS trapdoor) allows constructing a valid proof `π` for any false statement `x ∉ L`. Concretely: the adversary forges a proof that an arbitrary agent holds valid operator credentials and permission bitmask `0xFFFF` (all permissions). This forgery is computationally indistinguishable from a legitimate proof. "Detection" is not a cryptographic mitigation — you cannot detect a valid-looking forged proof without additional out-of-band trust anchors (which reintroduce the distributed trust the construction sought to eliminate).

**The comparison to OAuth is inverted in severity:** OAuth compromise of AS_i affects clients registered at AS_i. SRS subversion affects *every agent and every RS simultaneously, retroactively, including all past sessions if session transcripts are logged*. The construction's "blast radius" section in Game 4 correctly identifies this but offers only operational mitigations. There is no cryptographic bound on adversary advantage under subverted SRS — soundness fails with probability 1 for a computationally unbounded adversary holding τ.

**In-threat-model?** No. Game 4 must include a formal adversary class for the SRS subverter, state the security guarantee (which cannot be soundness — it fails entirely), and honestly characterize what the construction achieves as a *fallback*, not a *mitigation*. The claim that Bolyra "strictly dominates vanilla OAuth" must be conditioned on SRS integrity, and that condition must appear in the theorem statement, not buried in an appendix section on blast radius.

---

**Summary verdict:** The construction made real progress narrowing its claims, but four structural problems remain unaddressed at the formal level: (1) H3 unlinkability is falsified within any epoch by constant public input; (2) the nullifier game has an underspecified AS trust assumption that enables precomputation attacks; (3) the ZK claim is HVZK at best — malicious RS breaks it; (4) SRS subversion is a non-mitigable soundness failure, not a detectable operational incident. Until these have game definitions and reduction sketches, the construction's strength is not 10 — it is a well-organized collection of claims.


## Persona: cu_ciso

### Attack 1: Universal SRS = Single Cryptographic Point of Catastrophic Failure

- **Attack:** The construction's Gap 6 section explicitly concedes: *"OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS."* I pull out my Vendor Management Policy and FFIEC CAT inherent risk section. Under NCUA Part 748 Appendix A (security program), I am required to document and manage concentration risk in critical systems. A universal SRS means one ceremony compromise = every session I've ever issued is retroactively broken, across every member, every agent hop, every tool call — simultaneously. No OAuth deployment has that failure mode. My board narrative collapses: I cannot explain to the NCUA examiner why I voluntarily replaced N independent authorization servers (each with isolated blast radius) with a single cryptographic ceremony whose compromise is global and irreversible.
- **Why it works / fails:** The construction acknowledges this explicitly in Gap 6 and offers "per-domain SRS isolation as fallback" and re-ceremony mitigations — but re-ceremony is operationally undefined (who calls it, how long, what's the member impact?). The construction survives technically but not operationally: the fallback to per-domain SRS collapses H3's core claim (zero-config portability), which is the strongest differentiator.
- **In-threat-model?** No — the construction must address the operational SRS governance model: who owns ceremony scheduling, what's the RTO for re-ceremony, and how does per-domain isolation interact with H3-narrowed's portability claim?

---

### Attack 2: Forward Secrecy Breaks My Incident Response Audit Trail

- **Attack:** H4-narrowed claims cross-epoch forward secrecy: agent secret exfiltration does not retroactively deanonymize prior sessions. My NCUA examiner hands me the FFIEC CAT maturity question: *"Can you reconstruct the sequence of events in a security incident?"* My GLBA Safeguards Rule program (16 CFR §314.4(h)) requires I log and audit access to customer financial data. Bolyra's unlinkable nullifiers and AS-blind binding are architecturally designed so that prior sessions *cannot* be linked — that is the feature. But that feature is my audit failure. If a member's agent credential is compromised and I need to trace which MCP tool calls were made over the prior 90 days, the construction explicitly prevents that reconstruction. I cannot produce the forensic timeline the NCUA examiner expects.
- **Why it works / fails:** The construction treats "unlinkability" and "forward secrecy" as unqualified goods. For a credit union under examination, they are liabilities. Gap 3's erasure oracle formalization (Bellare-Yee style) proves the cryptographic property works — and simultaneously proves I cannot do post-incident forensics without a separate, linkable audit log layer that exists outside the ZK construction. That layer is not specified.
- **In-threat-model?** No — the construction must specify how audit logging coexists with unlinkability. If the answer is "maintain a parallel linkable log," then Bolyra's privacy guarantees are only as strong as that log's access controls, which is an operational problem, not a cryptographic one.

---

### Attack 3: Intra-Epoch Linkability via Constant `agentMerkleRoot` Is a GLBA PII Exposure

- **Attack:** Gap 5 explicitly states: *"Intra-epoch linkability via constant agentMerkleRoot is explicitly called out."* I open my state privacy counsel's memo on GLBA and the relevant state biometric/behavioral data statutes. Within any epoch, all sessions from the same agent share a constant `agentMerkleRoot`. That means every MCP tool call a member's agent makes — to a financial data API, a loan inquiry endpoint, a payment tool — is correlatable to a single identity handle for the duration of the epoch. If epochs are long (not defined in the construction), this is not forward secrecy; it is a rolling behavioral fingerprint. A subpoena, a breach of the proving infrastructure, or a compromised MCP server log correlates months of member financial behavior to a single pseudonym. My state AG's office has issued guidance that behavioral financial data is PII. I now have a privacy exposure the construction explicitly acknowledges and defers: *"Per-session Pedersen re-randomization identified as the close (~2K constraints) but deferred."*
- **Why it works / fails:** "Deferred" is not a risk control. The construction correctly identifies the fix and its cost (~2K additional constraints, modest). But shipping without it means the privacy claim in the general case is false for the duration of the epoch. The GLBA minimum-necessary and data minimization obligations are not satisfied by a construction that links all intra-epoch sessions.
- **In-threat-model?** No — the construction must either implement per-session re-randomization before claiming general-case privacy dominance, or explicitly bound epoch length and define what constitutes acceptable intra-epoch linkage exposure.

---

### Attack 4: 20–30× Auth Latency + ZK Proving Infrastructure = Unacceptable Third-Party Vendor Risk

- **Attack:** Gap 4 explicitly acknowledges a 20–30× latency regression on the auth path vs OAuth DPoP. I pull out my Tier 1 ops SLA matrix. My core processor (Symitar, FiServ) has a 99.95% uptime SLA contractually guaranteed. My members expect sub-second response on any interaction touching their account. The ZK proof generation for AgentPolicyV2-Ratcheted at ~12,483 constraints requires either (a) client-side proving (browser or mobile — which I cannot rely on for all member device profiles) or (b) a proving service. If it's a proving service, I now have a new critical vendor under NCUA's Third-Party Risk guidance (Letter to Credit Unions 07-CU-13 and the 2023 Interagency Guidance). I need a vendor management file: SOC 2 Type II, BCP/DR documentation, right-to-audit clause, SLA with financial penalties, and evidence the vendor has been examined under FFIEC standards. None of this exists for a ZK proving infrastructure vendor today. My examiner asks: *"Who is your proving service provider, and what is their NCUA-acceptable control environment?"* I have no answer.
- **Why it works / fails:** The construction benchmarks latency honestly and documents the tradeoff table. But it treats latency as an engineering concern, not an operational risk concern. For a credit union, a 3-hop chain at 20–30× baseline latency on an unproven third-party proving service is not an engineering decision — it is a board-level vendor risk acceptance that requires formal documentation, examiner review, and potentially NCUA notification. The construction does not address the vendor management stack that would need to exist around the proving infrastructure.
- **In-threat-model?** No — the construction must either specify a client-side proving path with acceptable device-profile coverage, or acknowledge that proving-service dependency creates a third-party risk management burden that adds 6–18 months of procurement and examination preparation before any credit union can deploy this in a regulated context.


## Persona: rfc7662_advocate

> "ZK is a proof system, not a feature. Before I accept 12,000 constraints of Groth16, show me the RFC I can't cite."

---

### Attack 1: Per-RS Introspection Policy Absorbs H1's "AS-Blind" Residual

**Attack:**
`draft-ietf-oauth-jwt-introspection-response` + AS-side policy already lets the AS issue *signed, RS-specific* introspection JWTs. The AS never sends cross-RS claims to any single RS. Each RS introspects and receives only the claims scoped to its audience. The AS is still in the hot path — but so what? OAuth's threat model treats the AS as trusted. "AS-blind" is only load-bearing if the AS itself is an adversary.

The construction's H1-narrowed claim (§ Gap 1) retreats to "AS-blind binding (not mutual binding generally)." Fine. But the entire value of AS-blindness is that the AS cannot correlate which RS an agent visited. A well-deployed introspection endpoint with per-RS policy filtering achieves the same *RS-level* isolation: RS-A never learns RS-B's introspection result. The AS sees both — but you've already trusted the AS.

**Why it works / fails against the construction:**
The construction *survives* if the threat model explicitly includes a *compromised or subpoenaed AS*. It *fails* to differentiate from OAuth if the AS is in-scope as a trusted party, which is the baseline assumption of every RFC in my toolbox. The construction §Gap 1 never states the AS-adversary assumption explicitly — it just says "AS-blind" as if that's inherently valuable.

**In-threat-model?** No — the construction must name "compromised AS" as an explicit threat in its security model, or H1-narrowed is vacuous against a vanilla AS with filtered introspection.

---

### Attack 2: PPID + RFC 8707 Audience Binding Kills H3 Without Touching ZK

**Attack:**
OIDC Pairwise Pseudonymous Identifiers (PPIDs) + RFC 8707 Resource Indicators already deliver H3-narrowed's "unlinkable client\_id" at the RS level, with zero ZK overhead and zero SRS blast radius. RS-A receives `sub = PPID_A`, RS-B receives `sub = PPID_B`. Neither RS can link the two. The `client_id` in the access token is scoped to the audience. Cross-RS linkage is broken at the RS layer — which is the *only* layer that matters if you trust the AS.

The construction acknowledges the SRS blast radius in §Gap 6 — "OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS." That's a self-inflicted wound. H3's portability claim trades away the trust distribution of the OAuth federation model for a single trusted setup. A PPID-based deployment has N independent AS trust anchors *and* RS-level unlinkability, with no ceremony risk.

**Why it works / fails against the construction:**
The construction survives only if unlinkability must hold even against the AS (same objection as Attack 1) *and* the SRS ceremony is operationally feasible. For general-case MCP (the C5 claim), neither precondition holds by default.

**In-threat-model?** No — H3's advantage over PPID+RFC 8707 is only the AS-adversary case. If that case is not in the default threat model, H3-narrowed adds no property vanilla OAuth cannot match.

---

### Attack 3: DPoP Key Rotation Matches H4's Cross-Epoch Claim, Cheaper

**Attack:**
RFC 9449 DPoP with short-lived key epochs achieves functional parity with H4-narrowed's "cross-epoch forward secrecy." Each epoch a fresh DPoP key pair is generated. Tokens bound to epoch-N keys cannot be replayed in epoch N+1. If the epoch-N private key is exfiltrated *after* epoch rotation, past tokens are still sender-constrained to the old key — and since those tokens are expired, no retroactive deanonymization occurs through the key material itself. Deanonymization via exfiltration requires the token *claims*, not the DPoP key, which are already in the AS log regardless of whether Bolyra is used.

The construction §Gap 5 explicitly concedes intra-epoch linkability via constant `agentMerkleRoot`. So H4-narrowed is: "ZK gives you cross-epoch forward secrecy." DPoP with epoch rotation gives you the same property, without a 20-30× latency cost (§Gap 4) and without the erasure oracle operational dependency (§Gap 3 — "whether erasure works is operational").

**Why it works / fails against the construction:**
The construction's Theorem 2 proves forward secrecy *conditional* on erasure working (§Gap 3). DPoP key rotation has no such conditional — the old private key is simply not persisted. The construction would need to show DPoP epoch rotation *fails* to achieve cross-epoch FS in some scenario Bolyra handles. It hasn't.

**In-threat-model?** No — H4-narrowed's residual is not a hard property gap over DPoP+epoch rotation unless the adversary is the AS, or the erasure oracle is strictly more reliable than key deletion. Neither is argued in the construction.

---

### Attack 4: RFC 8693 + SPIRE/WIMSE Already Does AS-Blind Delegation for Agent Chains

**Attack:**
H5-narrowed claims "AS-blind delegation" as its surviving primitive. But RFC 8693 with SPIRE-issued SVIDs already supports delegation without the AS needing to see the full hop topology. The delegating agent requests a token for the downstream audience; the AS validates the delegation policy and issues a scoped token. The AS sees `subject_token` and `requested_token_type` — it does *not* necessarily see the full N-hop chain unless the chain is embedded in claims. SPIRE's WIMSE draft (`draft-ietf-wimse-workload-identity`) binds workload identity to each hop independently.

The construction §Gap 1/H5 explicitly concedes latency regression vs RFC 8693 and SPIRE/WIMSE, and also concedes the one-AS-roundtrip-per-hop cost. The "AS-blind" residual assumes the AS learning the delegation graph is a threat. For a generic Claude-to-ChatGPT handoff (C5 scenario 2), the AS knowing the hop topology is fine — it's the authorization server's job to know.

**Why it works / fails against the construction:**
The construction survives only in the narrow case where the intermediate hop identities must be hidden from the AS (e.g., a regulated multi-tenant agent mesh where operator B cannot reveal its subcontractors to operator A's AS). That's not "general-case MCP" (C5's claim) — it's a specific enterprise topology. For the generic agent-economy scenario, RFC 8693 + SPIRE does AS-blind-enough delegation without ZK.

**In-threat-model?** No — H5-narrowed's "AS-blind delegation" is not a default requirement for the C5 general-case claim. It becomes a requirement only in multi-tenant topologies the construction has not established as the default.

---

### Summary Table

| Attack | Hypothesis Targeted | OAuth Countermeasure | Construction Survives If… |
|--------|--------------------|-----------------------|--------------------------|
| 1 | H1-narrowed (AS-blind) | RFC 7662 + per-RS policy + signed JWT introspection | AS is explicitly in-scope adversary |
| 2 | H3-narrowed (unlinkable client\_id) | OIDC PPID + RFC 8707 | AS is explicitly in-scope adversary AND SRS ceremony is feasible |
| 3 | H4-narrowed (cross-epoch FS) | DPoP RFC 9449 + epoch rotation | Erasure oracle is strictly more reliable than key deletion |
| 4 | H5-narrowed (AS-blind delegation) | RFC 8693 + SPIRE/WIMSE | Intermediate hop topology must be hidden from AS by default |

**Bottom line:** Every surviving property of Bolyra in Round 2 reduces to "AS adversary" or "erasure oracle reliability." Neither is a default assumption in the general-case MCP market C5 claims to dominate. The construction should either (a) elevate the AS-adversary assumption to a first-class threat model requirement and demonstrate it applies by default in agent-economy MCP, or (b) withdraw the "general case" claim and reframe around the regulated/multi-tenant niche where these assumptions hold.


## Persona: spiffe_engineer

> *"You're solving a coordination problem by introducing a cryptographic ceremony. SPIFFE solved coordination with a trust domain hierarchy. You've added a trusted setup and called it progress."*

---

### Attack 1: AS-Blind Binding Is Node Attestation — Already in SPIRE

**Attack:** H1-narrowed claims "AS-blind binding of human + agent identity to a session nonce" as a residual differentiator after the Round 2 retreat. But SPIRE node attestation already produces AS-blind workload identity: the SPIRE agent attests the workload (via TPM, k8s SAT, AWS IID, etc.) and issues an X.509 SVID *without any Authorization Server roundtrip*. The SVID is cryptographically bound to the workload, signed by the SPIRE CA, and valid for mTLS without the relying party needing to call back to an AS. The construction's §H1 never explains what "AS-blind" means in a world where SPIRE already provides AS-blind attestation at the workload layer.

The construction adds a Groth16 proof over a human credential and a PLONK proof over an agent credential, bound to a session nonce. But:
- The session nonce binding is achievable via TLS Finished message + certificate binding (RFC 8705 mTLS sender-constrained tokens).
- The human-in-the-loop binding is achievable via a JWT SVID carrying a `sub` claim attested by a human-facing OIDC flow — no ZK required.

**Why it works / fails:** The construction doesn't cite SPIRE node attestation anywhere. The narrowed H1 residual ("AS-blind") is satisfied by existing infrastructure. The construction must show what binding property the Groth16+PLONK pair provides that an X.509 SVID + mTLS does *not*. "Zero-knowledge" alone isn't an answer — SVIDs already don't reveal the attestation evidence chain to the relying party.

**In-threat-model?** No — the construction must address this gap. The narrowed H1 claim is currently indistinguishable from "SPIRE + mTLS with a human-issued SVID."

---

### Attack 2: H5 (AS-Blind Delegation) Is Exactly What WIMSE Defines

**Attack:** H5-narrowed concedes "latency regression vs RFC 8693 and SPIRE/WIMSE" — but that concession buries the real problem: WIMSE `draft-ietf-wimse-arch` §5.3 defines *workload-to-workload token exchange* that is structurally AS-blind in the relevant sense. A WIMSE-capable workload holds a bound token and can present it downstream without a new AS roundtrip, because the token is workload-scoped and the receiving workload validates it via the trust domain's JWKS. The "AS-blind delegation" Bolyra claims as its residual is already the WIMSE design goal.

The construction's §Gap 1 / H5 acknowledges the latency cost (20-30× for the ZK proof generation) but frames this as a "narrow-scope delegation primitive." WIMSE achieves narrow scope via token scope claims (`scope`, `resource`, audience binding) without proof generation latency. The WIMSE I-D explicitly adds `cnf` (confirmation) claims for workload binding — equivalent to Bolyra's `operator_pk` binding in H2.

Additionally, the construction's claim in Gap 6 — "OAuth distributes trust across N independent ASes; Bolyra concentrates in one SRS" — is even *worse* in the delegation case. Each delegation hop in Bolyra involves the same SRS, so a compromised SRS allows forging delegation proofs for the *entire agent graph*, not just one AS's token space.

**Why it works / fails:** The construction explicitly concedes the latency regression but doesn't engage with WIMSE's scope mechanism. The "AS-blind" property in H5 needs to be formalized against WIMSE's workload token exchange — otherwise the construction is claiming a property that WIMSE already provides, at 20-30× the cost, with a shared blast radius.

**In-threat-model?** No — H5's residual value is undemonstrated relative to WIMSE. The construction must either cite a gap in WIMSE's selective-disclosure or bound-delegation model, or withdraw H5.

---

### Attack 3: H3 Portability Is SPIFFE Federation — With a Worse Blast Radius

**Attack:** H3-narrowed claims "unlinkable client_id" across MCP servers via a single Bolyra credential, trading against "SRS blast-radius" which Gap 6 now documents. SPIFFE trust-domain federation (`spiffe://domainA/...` federating with `spiffe://domainB/...`) gives you cross-RS authentication without per-RS registration: a relying party in domain B accepts SVIDs from domain A by fetching domain A's bundle (a JWKS-equivalent). No ZK required. No shared SRS. Federation bundles are per-domain, so compromise of domain A's SVID CA does not affect domain B's trust anchor.

The construction's Gap 6 section states: "per-domain SRS isolation offered as fallback." But if you fragment the SRS per domain, you've reinvented SPIFFE federation — each domain now has its own trust root — while retaining the ZK proof overhead and the ceremony coordination cost. The unlinkability property (the actual residual of H3) is not provided by SPIFFE federation, but the construction needs to demonstrate that unlinkability is a *required* property in agent-economy MCP, not a regulated-niche property (which Round 2 already ruled out for the general case).

**Why it works / fails:** Gap 6 admits the SRS concentration problem and offers per-domain isolation as mitigation. That mitigation collapses H3's portability advantage (now you need per-domain credentials again) without eliminating the ZK overhead. The SPIFFE federation model achieves portability with distributed trust and no ceremony.

**In-threat-model?** Partially. The construction survives if it can demonstrate that **cross-domain unlinkability** (not just cross-domain authentication) is default-required in the general agent-economy MCP case. The construction currently does not make this argument — it only asserts it.

---

### Attack 4: The Erasure Oracle (Gap 3) Is a Trust Assumption Laundering SPIRE's Already-Solved Problem

**Attack:** Gap 3 adds a Bellare-Yee erasure oracle and correctly separates erasure trust (A8) from Theorem 2. The construction states: "Theorem 2 proves that IF erasure works, THEN cross-epoch linkage breaks Poseidon PRF. Whether erasure works is operational." This is honest — but it exposes a deeper problem: SPIRE's Workload API already provides *per-SVID short-lived credentials with automatic rotation*, where the "erasure" problem is solved by TTL expiry and SVID rotation, not by trusting a software erasure primitive.

An SVID with a 1-hour TTL is rotated by the SPIRE agent before expiry. The prior SVID is not retained by the agent. There is no "longTermSecret" analog in SPIRE's design — the construction removed `longTermSecret` from the circuit in Gap 4, but the erasure oracle is still needed for the session-epoch secret. SPIRE avoids this entirely by making secrets ephemerally-scoped by design. The construction's H4 (cross-epoch forward secrecy) is weaker than SPIRE's rotation model because:

1. SPIRE's rotation is externally enforced (TTL + SPIRE agent control loop), not dependent on the workload's software correctly erasing secrets.
2. The construction's A8 (erasure trust) is a trust assumption that SPIRE's architecture eliminates structurally.

The construction's theorem says "cross-epoch forward secrecy given erasure." SPIRE's architecture says "no erasure needed if you rotate." The construction must explain why ZK epoch-based secrecy is preferable to SVID rotation with short TTLs, especially given the 20-30× latency overhead for the proof generation.

**Why it works / fails:** The construction correctly flags A8 as an explicit assumption. But from an infrastructure-layer perspective, relying on software erasure when rotation-based expiry is available is a weaker security model, not a stronger one. The construction must argue why epoch-based ZK secrecy is architecturally superior to short-TTL SVID rotation for the agent-economy MCP case.

**In-threat-model?** Yes (construction survives the formal model) — but the engineering argument is not made. The construction needs a §"Why not SPIRE rotation?" section addressing this directly, or H4's value proposition collapses in practice even if it holds in the game-based proof.
