# Tier 3 Adversarial — C5 Bolyra as MCP auth, generally

## Persona: auth0_pm

---

### Attack 1: The "Pareto Retreat" Is a Concession of the Claim

- **Attack:** The construction explicitly retracted "strictly dominates" (§1) in favor of "Pareto-dominates on the privacy-sovereignty axis." From my chair, that is not a product claim — that is a niche acknowledgment dressed in category language. I sell to buyers. No buyer reads "Pareto-dominates on the privacy-sovereignty axis" and clicks Buy. They read "20-30x slower, works better if your AS is adversarial." The original gap-to-close requirement (C5) demanded a primitive "needed by default in agent-economy MCP, not only in regulated scenarios." The retreat to a named axis *is* the regulated-niche carveout the judges already rejected in Round 2.

- **Why it works:** The construction never shows the AS-adversary topology is the default for a generic Claude agent talking to a third-party MCP server (Scenario 1). It asserts it in §1. Assertion is not a proof of market topology. Auth0/WorkOS multi-tenant AS sharing is standard enterprise SaaS practice; enterprises do not typically treat the AS as an adversary — they contractually bind it via BAA/DPA. The claim that the AS-adversary is "the default topology in agent-economy MCP" needs citations from deployed production systems, not a threat-model argument.

- **In-threat-model?** No — the construction must operationally demonstrate (not assert) that generic agent deployments face an adversarial AS by default, or it remains a regulated-niche play with a fancier name.

---

### Attack 2: Latency Is Not a Tradeoff — It Is a Disqualifier

- **Attack:** I quote the construction directly: "20-30x" latency overhead is stated in §1 as an explicit carveout. WorkOS issues tokens in <100ms. If Bolyra prove time is ~2–15 seconds, the *median* agentic workflow — tool call fan-out, streaming responses, sub-second UX loops — is broken. I don't need to attack the cryptography. I just show the sequence diagram: agent calls MCP tool → waits 2-15s for ZK proof → user sees spinner → user churns. H5 (agent-economy-native delegation) claims narrow-scope delegation per hop as a primitive. Each hop now costs 2-15s. A 4-hop agent chain is 8-60 seconds of pure auth overhead. The construction does not bound or optimize proof latency per hop.

- **Why it works:** The construction acknowledges the latency tradeoff but treats it as acceptable without providing a concrete benchmark for the targeted scenarios (Scenario 1: generic Claude agent; Scenario 2: cross-vendor handoff). There is no SLA, no hardware target, no SNARK aggregation strategy that collapses multi-hop cost. The "single proof per hop" framing (H5) makes the latency problem *additive* — exactly backwards from what the agent economy needs.

- **In-threat-model?** No — the construction must provide a concrete latency budget per scenario and show the proof generation either (a) parallelizes with non-auth work or (b) is amortized across a session to avoid per-call cost. Otherwise this is a blocking objection, not a tradeoff.

---

### Attack 3: The Trust Assumption Stack Is Unsellable to Procurement

- **Attack:** The construction now carries at minimum A1–A10, with A4 (SRS integrity) explicitly conditioned in every theorem statement and A10 (RS-honest-verifier) added in §2.5. When a credit union's vendor risk team asks "what are your trust dependencies?", the Bolyra answer is a 10-item academic list culminating in "soundness fails with advantage 1 under SRS subversion" (Game 6). My answer — WorkOS, Auth0 — is: "SOC 2 Type II, ISO 27001, standard OAuth 2.1, no trusted setup required, audited by \[Big 4 firm\]." The construction's Game 6 honestly admits the blast radius, but honestly admitting a catastrophic failure mode is not the same as mitigating it. The SRS ceremony is a trust bootstrapping problem that the construction delegates to the reader.

- **Why it works:** The construction does not specify *who runs the SRS ceremony*, *how it is verified*, or *what the recovery path is if subversion is detected post-deployment*. For a solo-founder protocol, this is fatal: the SRS ceremony requires either (a) trusted third parties (which reintroduces centralization) or (b) a large MPC ceremony (which requires coordinating dozens of participants before the first enterprise customer can onboard). Neither is addressed. This is not a cryptographic attack — it is a deployment-readiness attack.

- **In-threat-model?** No — the construction must specify a concrete SRS instantiation plan (existing ceremony reuse, e.g., Hermez/Zcash Powers of Tau, or a new ceremony with a defined participant set) and a post-subversion remediation path before any enterprise procurement conversation can proceed.

---

### Attack 4: H3 (Zero-Config Portability) Is Defeated by Existing Standards

- **Attack:** H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS client registration" and contrasts this with RFC 7591 dynamic registration as a friction point. This is factually weak. RFC 7591 dynamic registration is a single automated roundtrip, not manual work — Cloudflare Access, Auth0, and WorkOS all support it transparently. The Bolyra construction requires *every RS to be Bolyra-compliant* — meaning the RS must implement a Groth16/PLONK verifier, maintain the Merkle tree, and speak the Bolyra wire format. That is not "zero-config" — that is "requires every server to adopt a new protocol." RFC 7591 works with every existing OAuth RS today, with no code changes on the RS side. The construction's portability claim inverts the actual integration burden.

- **Why it works:** The construction never states what a "compliant RS" must implement. If it requires verifier-side circuit changes, the cold-start problem is insurmountable: no RS supports Bolyra today, so zero portability exists at launch. The scenarios (Scenario 1: generic Claude agent to third-party MCP server; Scenario 2: cross-vendor handoff) both require the third-party RS to opt in to Bolyra. Neither Anthropic's MCP connector nor any current third-party MCP server does. H3 is a future-state claim, not a present differentiator.

- **In-threat-model?** No — the construction must specify the RS integration surface (what the RS must implement, minimum viable RS adapter, backward-compatibility with vanilla OAuth RSes) and demonstrate that portability is achievable before RS ecosystem adoption, or H3 is circular: "it's portable once everyone adopts it."


## Persona: cryptographer

*Reviewing construction C5 "Bolyra as MCP auth, generally" against its stated fixes. I'll accept the theorem headings at face value and look for what's still missing.*

---

### Attack 1: Groth16 Proof Malleability Breaks H1 Mutual Handshake Binding

- **Attack:** Groth16 proofs are algebraically malleable. Given a valid proof `π = (A, B, C)` for a statement `x`, an adversary can compute `π' = (A·δ, B, C·δ^{-1})` which still satisfies the pairing equation `e(A',B) = e(α,β)·e(x,γ)·e(C',δ)`. The human-identity leg of H1 uses Groth16. An adversary (a compromised RS or a MITM between RS and verifier) intercepts a valid human-identity proof for session `n₀`, mauls it into `π'`, and submits it bound to a different session nonce `n₁` — effectively replaying or forging the human-identity attestation for a session the human never authorized.

- **Why it works / fails:** §2.5 adds assumption A10 (RS-honest-verifier) and argues "Groth16 verification is deterministic with no verifier-chosen challenges." Deterministic verification does not preclude *proof malleability* — it only rules out HVZK attacks on the verifier. Malleability is a prover-side threat. Groth16 is *not* simulation-extractable (SE) — this is a known result (Libert et al., "Non-Malleability of the Fiat-Shamir Transform..." and Bowe et al.'s Sapling analysis). The PLONK leg uses SE-NIZK, which is correct, but the Groth16 leg is explicitly non-SE. A mauled Groth16 proof bound to an adversary-chosen nonce cannot be detected by the verifier. The construction offers no proof-of-knowledge that binds the Groth16 proof to the specific session context in a non-malleable way.

- **In-threat-model?** **No.** The construction must either (a) replace the Groth16 leg with an SE-NIZK (e.g., Groth16 + hash-of-proof binding, or PLONK for both legs), or (b) add a formal non-malleability game (NM-NIZK) for the human-identity component and prove the reduction. A10 as stated does not cover this.

---

### Attack 2: Forward-Secure Nullifier Claim (H4) Has No Key-Evolution Mechanism

- **Attack:** The adversary compromises an agent's long-term secret `sk` at time `T`. The AS has logged `{scope_id_i, session_nonce_i, nullifier_i}` for all sessions `i < T`. The AS now computes `nullifier_i' = PRF_{sk}(scope_id_i || session_nonce_i)` for each past session and checks `nullifier_i' == nullifier_i`. If any match, the session is linked to the identity, retroactively deanonymizing the agent's history.

- **Why it works / fails:** H4 claims "Agent secret exfiltration does not retroactively deanonymize prior sessions." True forward secrecy requires *key evolution* — a ratchet such that deriving `sk_T` from a compromise does not yield `sk_{T-1}, sk_{T-2}, ...`. The construction mentions "forward-secure nullifiers" but §2.2 describes only per-session Pedersen re-randomization of `agentMerkleRoot`, which provides *intra-epoch session unlinkability* (Game 4), not forward secrecy against a secret compromise. These are orthogonal properties. Game 4 (SESSION-LINK) bounds an adversary who observes transcripts without knowing `sk`. It says nothing about an adversary who later obtains `sk`. No key-evolution primitive (forward-secure PRF, puncturable PRF, or ratchet) is specified anywhere in the construction.

- **In-threat-model?** **No.** The AS-adversary is declared the "default topology" in §1 — meaning the AS is exactly the party most likely to accumulate `sk` (via registration, via compromise, via legal compulsion). H4 is the hypothesis with the strongest practical motivation and the weakest cryptographic support. The construction must specify a forward-secure PRF family (e.g., GGM tree with key puncturing) and prove a game FS-NULL: `Pr[Adv wins FS-NULL] ≤ negl(λ)` even given `sk_T`.

---

### Attack 3: Two-Leg NIZK Composition Lacks a Combined Knowledge Extractor

- **Attack (cross-leg witness confusion):** The construction binds a Groth16 proof (human identity over `Comm_H`) to a PLONK proof (agent identity over `Comm_A`) via a shared `session_nonce η`. The adversary generates a valid Groth16 proof for human `Alice` and a valid PLONK proof for agent `Bob`, both using the same `η`. The RS accepts the pair as "Alice authorized Bob for this session" — but no proof establishes that Alice *chose* Bob or that Bob's Merkle root is committed in the same witness as Alice's credential.

- **Why it works / fails:** Knowledge soundness in a two-leg construction requires a *combined extractor* `E` that, given an adversary making a bounded number of oracle queries, extracts *both* witnesses simultaneously and proves their relation. The construction states Game 4 bounds SESSION-LINK and mentions PLONK's SE-NIZK separately. But two individually sound NIZKs composed by sharing only a public nonce do not yield a sound *joint* statement — this requires either a UC-secure composition proof or a combined circuit that puts both witnesses in a single proof. Neither is provided. The UC framework is listed in my toolbox precisely because it is the correct tool here; the construction never invokes it. Under the ROM + GGM, a reduction from the combined extractor to either individual extractor requires specifying the joint language and showing the extractor's running time doesn't blow up — standard but non-trivial.

- **In-threat-model?** **No.** The construction must either (a) merge both legs into a single circuit with a joint knowledge extractor, or (b) formally prove composition security under UC with an explicit simulator for the combined `F_auth` functionality. "The PLONK leg uses SE-NIZK" (§2.5) is not a composition proof.

---

### Attack 4: Cross-Vendor Handoff — SRS Blast Radius Is Multiplicative Under Two Independent Setups

- **Attack:** The stated scenario includes "cross-vendor agent handoff (Claude → ChatGPT agent accessing same tool)." Claude's AS runs SRS₁ (Anthropic-generated); ChatGPT's AS runs SRS₂ (OpenAI-generated). The RS must verify proofs from *both* setups. An adversary who subverts *either* SRS₁ or SRS₂ can forge proofs for *all* cross-vendor sessions at that RS. The probability of *at least one* subversion across `n` independent setups is `1 - (1 - ε)^n ≥ nε` for small `ε` — linearly worse per additional vendor. Game 6 compares "blast radius to OAuth" for a single AS topology. It does not address multi-AS composition.

- **Why it works / fails:** §1 explicitly argues that "multi-tenant AS sharing, cross-vendor handoff, and subpoena surface make the AS-adversary assumption the default topology." This is correct — but it implies multiple ASes, each with independent SRS ceremonies. Game 6 honestly says soundness fails with advantage 1 under single-AS subversion. Under cross-vendor composition, the adversary only needs to compromise the *weakest* AS in the set. OAuth under cross-vendor federation uses standard PKI (ECDSA/RSA) with no per-circuit trusted setup — so its multi-AS blast radius scales with key compromise probability, not SRS ceremony integrity. In the cross-vendor scenario, Bolyra's trust assumption is *strictly worse* than OAuth unless all vendors are assumed to run their SRS with equal or greater integrity than a CA. The construction never models multi-AS SRS independence or provides a security bound for the cross-vendor scenario, which is listed as a primary target use case.

- **In-threat-model?** **No.** The cross-vendor scenario requires either (a) a universal SRS (e.g., KZG with a single MPC ceremony shared by all vendors — non-trivial coordination) or (b) an explicit multi-AS security game where the adversary corrupts one of `n` setups and the theorem states the resulting advantage as a function of `n`. Currently, Game 6 is written for `n=1`. The claimed "Pareto-dominance on the privacy-sovereignty axis" against OAuth is not supported in the multi-AS setting that the construction's own scenarios require.


## Persona: cu_ciso

---

### Attack 1: Audit Trail Opacity Violates GLBA Safeguards Rule §314.4(h) and NCUA Part 748 Incident Response

- **Attack:** I pull up §314.4(h) of the GLBA Safeguards Rule — I'm required to have an incident response plan that includes detecting, containing, and notifying members when their financial data is accessed. My examiner wants a human-readable audit trail: "Member #4471 authenticated from IP 10.x.x.x at 14:32 UTC and accessed account balance via MCP tool `get_balance`." The Bolyra construction's core value proposition — the privacy-sovereignty axis, the unlinkable nullifiers from H4, the Pedersen re-randomized `agentMerkleRoot` in §2.2 — is designed to make exactly this attribution impossible. Forward-secure nullifiers means I **cannot** reconstruct which member session accessed what resource after the fact, even with full system access. The construction closes the intra-epoch linkability game (Game 4, SESSION-LINK) and celebrates it. My examiner will see this as a destroyed audit log.

- **Why it works / why it fails against the construction:** The construction does not address this. It proves SESSION-LINK advantage ≤ negl(λ) as a feature, but offers no mechanism for lawful access reconstruction (court order, NCUA examination, member dispute). There is no mention of a selective disclosure or escrow path for regulated MCP deployments. The construction trades privacy for auditability at exactly the layer regulators inspect.

- **In-threat-model?** No — the construction must address this. Suggested patch: a §3.x carve-out describing a "compliance mode" where a regulated RS can require a linkable audit token alongside the unlinkable proof, with the dual-mode described in the security model.

---

### Attack 2: SRS Ceremony as Unvetted Vendor — FFIEC CAT and Vendor Management Policy Failure

- **Attack:** Game 6 in the construction honestly states: "soundness fails with advantage 1 under SRS subversion." Translation: if the Structured Reference String was generated by a malicious or compromised ceremony, any agent can forge any credential with probability 1. My Vendor Management Policy (required by NCUA Examination Guidance on Third-Party Relationships) requires documented risk assessment, SOC 2 Type II or equivalent, and a documented incident response procedure for every third-party component in the authentication chain. Who ran the SRS ceremony? Is there a verifiable record? Is there an independent audit? Is there a SOC 2 on the ceremony operator? The construction conditions every theorem on A4 (SRS integrity) but provides zero operational guidance on how a credit union evaluates A4's truth. Comparing blast radius to OAuth in Game 6 is cold comfort — OAuth's AS compromise is recoverable (rotate keys, reissue tokens); SRS subversion is permanent and retroactive.

- **Why it works / why it fails against the construction:** The construction surfaces the risk honestly but stops there. It does not map SRS custody to any recognized third-party risk framework. A CISO cannot answer an examiner's question "who is responsible for the SRS and how do you know it's clean?" with a theorem statement.

- **In-threat-model?** No — the construction must address this. Suggested patch: A4 needs an operational annex specifying what constitutes acceptable SRS ceremony evidence (multi-party computation transcript, independent audit, hash published to CT log) and how a deploying credit union evaluates it as a vendor control.

---

### Attack 3: Member Key Custody Lives in the Browser — H1/H2 Mutual Proof Collapses Under XSS

- **Attack:** H1 claims Bolyra "atomically proves human (Groth16) + agent (PLONK) identity." For the Groth16 leg to prove human identity, the member must hold a proving key or witness. Where? The construction is silent on key custody (§2.2, §2.5 discuss the proof structure but not storage). If the answer is browser storage (localStorage, IndexedDB, WebCrypto), then a single XSS vulnerability in any MCP client application gives an attacker the proving key — and because H4 forward-secure nullifiers mean prior sessions are unlinkable, the attacker gains **unlimited future credential generation** with no forensic trail back to the compromise event. This is categorically worse than a stolen OAuth bearer token, which is scoped and expires. The NCUA Part 748 security program requires me to protect member authentication credentials; I cannot do that if the answer is "it's in the browser."

- **Why it works / why it fails against the construction:** The construction does not address key custody at all. The mutual handshake (H1) and model-binding (H2) proofs assume the human witness is available and uncompromised, but provide no guidance on storage, rotation, or revocation of that witness. The forward-secrecy property (H4) that protects prior sessions also protects an attacker's future forgeries.

- **In-threat-model?** No — the construction must address this. At minimum, §2.5 (A10 trust assumptions) should include an explicit key custody assumption and reference hardware-backed storage (TPM, secure enclave, hardware wallet) as the intended deployment target, with browser-based deployment flagged as a degraded security mode.

---

### Attack 4: Nullifier Registry SLA is Not Core-Processor SLA — FFIEC BCP and NCUA Continuity Requirements

- **Attack:** H4 and §2.2 implement forward-secure nullifiers. A nullifier registry (on-chain or otherwise) must be available at authentication time to prevent replay. My core processor (Symitar, Corelation) contractually guarantees 99.95%+ availability with defined RTO/RPO. What is the SLA for the Bolyra nullifier registry? If it is on-chain (the construction implies this in §2.5 with "on-chain RS address" as an A7 enforcement mechanism), Ethereum mainnet has experienced extended periods of elevated gas costs and degraded throughput. A Layer 2 or custom chain has its own liveness assumptions. FFIEC Business Continuity guidance requires that authentication infrastructure have documented failover and that its availability is commensurate with the criticality of the protected resource. The construction provides no availability SLA, no failover path if the registry is unavailable, and no degraded-mode operation. The attack is simple: registry unavailable → all MCP authentication fails → members cannot access their financial tools.

- **Why it works / why it fails against the construction:** The construction does not address availability, RTO, RPO, or failover for the nullifier registry. The on-chain enforcement cited for A7 (§2.5) implicitly requires blockchain liveness, which is not equivalent to financial-services availability standards. A vanilla OAuth AS can be deployed in active-active HA with sub-second failover; the construction offers no equivalent.

- **In-threat-model?** No — the construction must address this. A §4.x deployment section should specify minimum registry availability requirements, define a failover mode (e.g., short-lived cached nullifier windows with reduced security guarantees), and map these to FFIEC BCP tiers so a deploying institution can document the residual risk.


## Persona: rfc7662_advocate

---

### Attack 1: Signed JWT Introspection Caching Collapses §1's AS-Adversary Argument

- **Attack:** The construction's entire §1 rationale for elevating the AS-adversary to "default topology" rests on the premise that the AS sits in the hot path — seeing every RS call, building a cross-RS usage graph, and presenting a centralized subpoena surface. But `draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) lets the AS issue a signed, RS-filtered JWT that the RS caches and verifies offline. Combined with RFC 8707 resource indicators, the RS presents its `resource` parameter at token-issuance time, receives an audience-bound signed introspection JWT, and never calls the AS again for that token's lifetime. The AS does not see which RS is actively using the token. The subpoena argument — "multi-tenant AS sharing creates cross-RS correlation" — assumes online introspection. It doesn't hold under the RFC 9701 + caching deployment model that any competent Auth0/WorkOS installation can configure today.

- **Why it works / fails:** The construction in §1 asserts the AS-adversary assumption is "the default topology in agent-economy MCP" without conditioning on introspection mode. If the adversary installs an RFC 9701-compliant AS with per-RS response filtering and a reasonable cache TTL, the AS's runtime visibility is bounded to token issuance — identical to Bolyra's AS trust surface. The "subpoena surface" argument does not distinguish issuance-time from runtime correlation.

- **In-threat-model?** No — construction must address. §1 must explicitly state why RFC 9701 offline introspection does not close the AS-adversary gap. Without this, the claim that "multi-tenant AS sharing makes AS-adversary the default" is an operational assumption, not a cryptographic one, and the Pareto-dominance framing on the privacy axis loses its load-bearing premise.

---

### Attack 2: PPIDs + RFC 8707 Already Break Cross-RS Linkability — Game 4 (SESSION-LINK) Strawmans the Baseline

- **Attack:** §2.2 closes intra-epoch linkability via per-session Pedersen re-randomization of `agentMerkleRoot` and blinded `scopeCommitment`, with Game 4 proving advantage ≤ negl(λ). But what is the baseline? H2 asserts "vanilla OAuth binds only `client_id`; runtime model identity is not authenticated." That is true for a naive deployment. It is not true for a deployment using OIDC Pairwise Pseudonymous Identifiers (PPIDs, §8 of OIDC Core), which issue a distinct `sub` per RS, combined with RFC 8707 audience binding. Under this configuration: RS-A gets `sub=pairwise-A` and RS-B gets `sub=pairwise-B`. The RS cannot correlate across RSes. The AS can, but per Attack 1, the AS's runtime visibility is bounded. The construction's SESSION-LINK game needs to be proven against a baseline that includes PPIDs + RFC 8707, not naive bearer tokens.

- **Why it works / fails:** The §2.2 re-randomization argument provides unlinkability even against a colluding set of RSes — which PPIDs do not, because the AS still maps both pairwise subjects to the same real identity. Against an AS-adversary, Bolyra wins. Against an RS-adversary (multiple colluding RSes), Bolyra wins. Against a passive RS-adversary with no AS collusion, PPIDs + RFC 8707 are equivalent. The construction must specify which adversary class Game 4 is closing against, because "SESSION-LINK advantage ≤ negl(λ)" means different things depending on whether the AS is in the adversary's oracle.

- **In-threat-model?** Partially. Construction survives against AS-adversary. But the Pareto claim on privacy-sovereignty requires demonstrating the gap persists against the PPID + RFC 8707 baseline, not just naive OAuth. §2.2 must state explicitly: "this closes a gap that PPIDs cannot close because PPIDs rely on AS honesty." That sentence is currently absent.

---

### Attack 3: DPoP with Per-Session Ephemeral Keys Partially Closes H4 — The Nullifier Uniqueness Property Is Not Established as MCP-Necessary

- **Attack:** H4 claims "agent secret exfiltration does not retroactively deanonymize prior sessions. Vanilla bearer tokens have no forward secrecy." RFC 9449 DPoP with per-session ephemeral key generation achieves partial forward secrecy: generate a fresh `ES256` keypair per session, bind the access token to that public key at issuance, discard the private key after the session completes. Post-exfiltration, the attacker has a DPoP-bound token but no private key to present proofs of possession for — the session is cryptographically closed. Cross-session linkability is also broken if each session uses a fresh ephemeral key, because no two sessions share a DPoP public key. The construction's H4 uniqueness claim — "nullifiers prevent retroactive deanonymization" — is specifically about the *anonymous* forward-secrecy property: proving "I have never used this credential" without revealing which credential. DPoP cannot do that. But the construction has not established that this non-interactive first-use proof is needed in generic agent-economy MCP (as opposed to regulated scenarios where double-spend prevention is legally required).

- **Why it works / fails:** The construction must answer: in which generic MCP scenario does an RS need to verify "this agent credential has never been presented before" without learning the credential's identity? The nullifier scheme is load-bearing only if that scenario is common in the general case. If the RS merely needs "this token hasn't been replayed" (i.e., replay prevention), DPoP + short token lifetimes suffice. H4's Pareto advantage over vanilla OAuth narrows to: unlinkable forward secrecy for anonymous credentials. That is a real gap — but it needs a concrete agent-economy scenario to become a general-case claim rather than a regulated-niche claim.

- **In-threat-model?** Partially in-threat-model — but H4's general-case framing is unsupported. The construction must exhibit a generic MCP scenario (not credit-union-specific, not HIPAA-gated) where non-interactive first-use proofs are the required primitive and DPoP + ephemeral keys are insufficient.

---

### Attack 4: RFC 8693 Structured JWT Delegation Eliminates the Per-Hop Roundtrip — H5's "Primitive" Claim Is Latency, Not Cryptography

- **Attack:** H5 claims "narrow-scope delegation is a primitive (single proof per hop). Vanilla OAuth uses RFC 8693 token exchange requiring full AS roundtrip per hop." RFC 8693 §4.3 defines the `act` claim for embedding delegation chains directly in JWT-structured access tokens. An AS can issue a token containing `{"sub": "claude-agent", "act": {"sub": "human-user"}, "scope": "mcp:tool:read"}` at the top of the delegation chain. Each downstream hop receives a narrowed JWT with an extended `act` chain, verified locally by the RS without any AS call. The "full AS roundtrip per hop" assertion is true only if the AS issues opaque tokens — it is false for JWT-structured tokens with embedded delegation chains, which every major provider (Auth0, WorkOS) supports today. The construction's H5 claim conflates "AS roundtrip required by the protocol" with "AS roundtrip required in practice."

- **Why it works / fails:** Bolyra's single-proof-per-hop delegation has a genuine cryptographic advantage: the proof binds `{model_hash, operator_pk, permission_bitmask}` to the hop without revealing the full delegation graph to intermediate RSes. RFC 8693 `act` chains are fully visible to every RS that receives the token — there is no selective disclosure. That is a real, non-trivial gap. But it is not framed that way in H5. H5's argument is "AS roundtrip per hop," which the RFC 8693 advocate defeats trivially with JWT tokens. H5 must be rewritten: the advantage is not "fewer roundtrips" but "selective disclosure of delegation graph to per-hop RSes" — which is a ZK primitive RFC 8693 genuinely cannot provide.

- **In-threat-model?** No, as currently written. The "full AS roundtrip" framing is technically incorrect for JWT-structured RFC 8693 deployments and will be dismissed by any OAuth implementer. The construction must restate H5's claim as "selective disclosure of delegation provenance" to survive adversarial review.


## Persona: spiffe_engineer

### Attack 1: SPIFFE ZK Attestor — Wrong Layer, Not Wrong Idea

- **Attack:** The `mutual ZK handshake` (§H1, §2) re-implements workload attestation at the application layer. SPIRE already has a pluggable attestor interface. A ZK attestor could emit an X.509 SVID whose SAN encodes `{model_hash, operator_pk}` as a SPIFFE ID path (`spiffe://anthropic.com/model/claude-3-7/operator/acme`). The SVID is issued by SPIRE after the node agent runs your Groth16 check. Every downstream RS already speaks mTLS — no new protocol surface. The construction's §H2 claim ("vanilla OAuth binds only client_id; runtime model identity is not authenticated") is true of OAuth but false of SPIFFE SVIDs, which are cryptographically attested to the workload at issuance time.
- **Why it works / fails:** It works because the construction never argues why the ZK proof must travel in the MCP token rather than be consumed once at SVID issuance. The Groth16 leg of the handshake is a one-time attestation — exactly what SPIRE's attestation flow does. The construction does not cite or rebut SPIRE's attestor plugin model.
- **In-threat-model?** No — construction must address. §H1 and §H2 survive only if Bolyra offers something SVID attestation cannot. The paper gives no argument for why the proof must be re-verified per-call rather than baked into a short-lived SVID.

---

### Attack 2: SPIFFE Federation Already Closes H3 (Identity Portability)

- **Attack:** §H3 claims "zero-config identity portability across MCP servers" as a primitive gap. SPIFFE trust-domain federation already does this: RS A and RS B each trust a federated SPIFFE bundle; any workload with a valid SVID from a federated domain authenticates without per-RS registration. RFC 7591 dynamic registration is an OAuth problem, not an identity-layer problem. The construction conflates the AS-registration ceremony with identity portability — these are separable. Fix: federate SPIFFE trust domains, use mTLS SVIDs at the transport layer, keep OAuth for scope/consent. H3 is fully addressed without Bolyra.
- **Why it works / fails:** The construction's counter would need to show that the *privacy* property (not mere portability) is the gap — i.e., that SVID-based federation reveals linkable identity to each RS. That argument exists but is not made in §H3; the section frames portability purely as a registration-roundtrip problem.
- **In-threat-model?** Partially. The construction survives if it reframes H3 as "unlinkable portability" rather than "no registration." As written, the claim is falsified by SPIFFE federation.

---

### Attack 3: WIMSE Token Binding Supersedes H5 Before Bolyra Ships

- **Attack:** §H5 ("agent-economy-native delegation, single proof per hop") competes directly with draft-ietf-wimse-arch §6 (workload-to-workload token binding) and the emerging `cnf`-based proof-of-possession extensions to WIMSE. WIMSE already targets multi-hop agent delegation with narrow-scope tokens bound to workload SVIDs. The construction's §§1–2 do not cite the WIMSE architecture draft. If WIMSE ships before Bolyra achieves ecosystem adoption, H5 is subsumed by an IETF standard that every cloud provider will implement. The competitive moat evaporates without needing to break the cryptography.
- **Why it works / fails:** This is an adoption-layer attack, not a cryptographic one. The construction has no §on ecosystem timing or standards-body engagement. A construction that is "strictly dominated" by a forthcoming IETF standard on its own best feature is not a viable general-case replacement for OAuth.
- **In-threat-model?** No — the construction must address WIMSE explicitly and either show it is out of scope for WIMSE's charter or argue Bolyra's ZK properties (H4 forward secrecy, H1 HVZK) are orthogonal to what WIMSE can express.

---

### Attack 4: §2.5 A10 (RS-Honest-Verifier) Collapses Under SPIFFE Threat Model

- **Attack:** §2.5 adds trust assumption A10: "RS is an honest verifier for Groth16." In SPIFFE production deployments, the RS is *any* workload — including third-party SaaS, multi-tenant platforms, or compromised services. The SPIFFE threat model explicitly does *not* trust the workload receiving the SVID; trust is established by the SPIRE server's attestation, not by assumptions on the verifier. A10 assumes away the most dangerous RS in the cross-vendor scenario (`generic Claude agent talking to third-party MCP server` — the paper's own §scenarios item 1). A malicious RS can run a non-standard Groth16 verifier that leaks the proof's witness through a covert channel — A10 forbids this attack by assumption, not by construction.
- **Why it works / fails:** §2.5 justifies A10 by noting "Groth16 verification is deterministic with no verifier-chosen challenges." Determinism does not prevent a malicious verifier from *logging* the proof and performing offline deanonymization or from choosing a verification key that makes the proof extractable. The honest-verifier assumption is doing real work here and is not merely cosmetic. PLONK's simulation-extractable NIZK (no assumption needed per §2.5) is stronger — the construction should explain why the Groth16 leg is retained at all rather than unifying on PLONK, since the mixed assumption profile is the weakest point.
- **In-threat-model?** Yes for the PLONK leg; No for the Groth16 leg. Construction survives on the PLONK path but must justify retaining Groth16 under A10 given that the RS-adversary is explicitly in scope in §1's AS-adversary argument.
