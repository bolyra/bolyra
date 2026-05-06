# Tier 3 Adversarial — C5 Bolyra as MCP auth, generally

## Persona: auth0_pm

---

### Attack 1: H3's "zero-config portability" re-introduces per-RS work through the manifest

- **Attack:** §2.2 defines `/.well-known/bolyra-model-manifest` — a JSON endpoint every RS must publish and maintain, containing `(model_hash, permission_bitmask)` tuples with TTL-based caching and rotation mechanics. The PM opens the WorkOS MCP docs and Auth0 Dynamic Client Registration docs side by side and asks: *How is maintaining a Bolyra manifest simpler than RFC 7591 DCR, which my infrastructure already supports?* H3 claims "no per-RS client registration," but the RS now owns a manifest with a schema, an issuer field, a revocation list, and optional Baby Jubjub signing for offline verification. That is per-RS work. You renamed the artifact, not eliminated it.

- **Why it works / why it fails:** It works because the construction concedes (§2.2) that RSes must actively publish and rotate manifests. The "zero-config" framing collapses to "client-side zero-config, RS-side non-trivial config." Auth0 already ships DCR with turnkey tooling; Bolyra ships a spec the RS operator must self-implement. The attack is partly blunted if Bolyra provides a reference RS library, but the construction does not mention one.

- **In-threat-model?** No — H3's claim of zero-config portability is not closed by §2.2; it shifts the config burden rather than removing it.

---

### Attack 2: Proof latency makes H5 multi-hop delegation commercially unviable

- **Attack:** The PM quotes the attack prompt directly: "WorkOS issues tokens in <100ms. Your circuits take ~15s to prove." H5 claims single-proof-per-hop delegation as a primitive advantage over RFC 8693 token exchange. But a three-hop agent workflow (Claude → specialized agent → tool) requires three sequential proof generations: conservatively 45 seconds of pure cryptographic overhead before the first tool call returns. The RFC 8693 roundtrip the construction criticizes costs one HTTPS RTT (~50ms). The PM asks the operator: *Which tradeoff do your users accept?*

- **Why it works / why it fails:** The construction does not address latency anywhere. §2.3 introduces `AgentPolicyV2-Ratcheted` as the production circuit and focuses on security reductions, not performance benchmarks. There is no mention of client-side proving acceleration, proof aggregation batching, or pre-computed proof caching tied to the ratcheted epoch secret. The attack is blunted only if Bolyra can prove sub-second on commodity hardware (e.g., via WASM + GPU), which the construction does not claim.

- **In-threat-model?** No — latency is not addressed, and the multi-hop delegation advantage in H5 inverts to a disadvantage at any non-trivial hop count.

---

### Attack 3: The SRS-CEREMONY assumption (A7) is a procurement blocker the construction defers rather than solves

- **Attack:** Game 4 and A7 require a 1-of-N honest MPC ceremony for the PLONK SRS. The PM is not attacking the cryptography — they are playing procurement. A credit union's vendor risk committee asks: *Who ran the ceremony? What is the audit trail? How do we verify the transcript?* Auth0 and WorkOS answer with SOC 2 Type II reports, FedRAMP-ready infrastructure, and named auditors. The construction's answer is "graceful degradation: EdDSA/Poseidon binding survives SRS compromise" — which the PM will read as "if our trust root is broken, we fall back to weaker security." That is not a procurement answer; that is a risk acknowledgment.

- **Why it works / why it fails:** The construction handles the cryptographic argument correctly (AGM + q-DLOG reduction, graceful degradation analysis). It does not handle the operational trust argument. There is no mention of a public ceremony, a third-party auditor, a verifiable transcript URL, or any analog to Auth0's compliance certifications. The attack is blunted only if Bolyra can point to a completed, publicly verifiable ceremony with named participants — which does not exist for a pre-commercial construction.

- **In-threat-model?** No — A7 is added as an assumption but the construction provides no operational path for an enterprise buyer to satisfy that assumption.

---

### Attack 4: H2's scope narrowing concedes the novel claim and converges on what Client Attestation already does

- **Attack:** The construction explicitly narrows H2 in §2.2: Game 1 covers "operator-issued model credential binding," not "runtime model identity binding." The construction then states runtime integrity requires "TEE/TPM attestation as an orthogonal layer." The PM opens `draft-ietf-oauth-attestation-based-client-auth` from the toolbox. That draft already defines client attestation: the AS receives a signed JWT containing device/software attestation claims (which can include a model hash or container digest) before issuing a token. Auth0 ships this today. After the narrowing, H2's primitive — *the operator registered this model hash, and the proof witnesses it* — is equivalent to a client assertion signed by the operator's key in the attestation draft. The ZK wrapper adds privacy for the operator's signing key, but §1 already concedes cross-RS linkability is not claimed, so the privacy gain is scoped only to AS-blindness. The PM asks: *What does the ZK layer buy the buyer that a signed client assertion doesn't, given your own scope narrowing?*

- **Why it works / why it fails:** The narrowing in §2.2 was necessary to close the MCP-FORGE gap, but it sacrifices the strongest form of H2. What remains is AS-blindness for the operator key — a real property, but one whose commercial value the construction does not articulate for the general case. The attack is blunted if Bolyra can argue AS-blindness is structurally necessary in multi-tenant MCP deployments (e.g., the AS learns nothing about which model operators are active). The construction does not make that argument in H2's framing.

- **In-threat-model?** Partial — the cryptographic property is real, but the construction has not established that AS-blindness for operator keys is a default requirement in general agent-economy MCP rather than a regulated-niche requirement. H2's "strictly dominates in the general case" claim (C5's target) is not closed.


## Persona: cryptographer

---

### Attack 1: H4 Forward-Secrecy Claim Conflates Unlinkability with Epoch Secrecy

**Attack:**
The adversary operates as a passive-then-active Authorization Server. In Phase 1 (passive), it records all proof transcripts, noting `agentMerkleRoot` and `scopeCommitment` in each. In Phase 2, it compromises the agent and obtains the current `epochSecret_e`. The adversary now asks: "Which of the transcripts I saw in Phase 1 belong to this agent?"

**Why it works:**
The construction explicitly concedes (Gap 1 fix) that `agentMerkleRoot` is a constant across sessions at the same AS. The AS is the verifier — it sees every proof. Therefore the AS already maintains a per-agent transcript partition indexed by `agentMerkleRoot`, **before** any compromise. "Agent secret exfiltration does not retroactively deanonymize prior sessions" (H4) is true only if deanonymization is defined as reconstructing the epoch secrets from session N-k. It is **false** if deanonymization means linking sessions to an agent identity — which the AS can do trivially from the `agentMerkleRoot` constant.

The Theorem 2 reduction is written against the ratchet's epoch-secret forward secrecy, but H4's prose claim is about **session deanonymization**, a strictly stronger privacy property. There is no game definition distinguishing these two notions — the reduction proves the weaker one while the claim asserts the stronger one.

**In-threat-model?**
No. The construction must either (a) define H4's "deanonymization" narrowly as epoch-key recovery (not session linkage) and update H4's prose accordingly, or (b) deploy per-session Pedersen re-randomization (identified as a "future extension") and make it non-future.

---

### Attack 2: Unsigned Model Manifest MITM Collapses H2

**Attack:**
The adversary controls a network position between the Resource Server and the `/.well-known/bolyra-model-manifest` endpoint — achievable via DNS cache poisoning, a compromised CDN edge node, or BGP hijack of the operator's ASN. The adversary substitutes a manifest response that replaces the legitimate `model_hash` with the hash of a malicious agent binary, paired with an elevated `permission_bitmask` (e.g., all bits set). The RS fetches the poisoned manifest, computes the expected `modelBindingTag` using the adversary's values, and accepts a proof from the malicious agent.

**Why it works:**
§2.2 describes Baby Jubjub manifest signing for offline verification as **optional**. Without a mandatory trust anchor — pinned key, DNSSEC + signed manifest, or CT-logged certificate — the RS's tag computation is only as trustworthy as the manifest HTTP response. The ZK proof proves consistency of the prover's private witness with a public tag; it does not prove the tag was derived from a legitimately issued manifest. H2's claim ("binds {model\_hash, operator\_pk, permission\_bitmask} to a specific RS invocation") depends entirely on the manifest channel's integrity, which is not formalized in any game.

**In-threat-model?**
No. The construction must define a `MANIFEST-INTEGRITY` game, mandate signature verification as a protocol requirement (not optional), and include the manifest signing key in the trust assumptions table (currently A1–A7). An attacker who can poison the manifest breaks H2 without touching any circuit.

---

### Attack 3: Universal SRS Catastrophic Scope Under H3 Portability

**Attack:**
H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS registration." For this to hold, every RS must accept proofs against a common SRS. The adversary targets the SRS MPC ceremony. Under the AGM + q-DLOG assumption added in Game 4, if **any single ceremony participant** retains the toxic waste, the adversary can construct accepting Groth16/PLONK proofs for arbitrary false statements — including false `model_hash`, false `permission_bitmask`, false `epochSecret_e` chain, and false human-binding.

**Why it works:**
The construction's "graceful degradation analysis" claims "EdDSA/Poseidon binding survives SRS compromise." But EdDSA binding authenticates the *agent keypair*, not any of the ZK-proven attributes. If the SRS is subverted, the adversary does not need to steal an agent key — they construct a proof asserting `agentMerkleRoot = H(adversary_leaf, ...)` for any leaf they choose, bind it to an EdDSA key they control, and authenticate to every RS in the H3 portability model. The "1-of-N honesty" guarantee in SRS-CEREMONY is a *ceremony* assumption, not a *post-ceremony* one — once the ceremony is done and the SRS is published, there is no revocation path if a participant is later found to have cheated.

More critically: a universal SRS that enables H3 cross-RS portability means **a single SRS compromise breaks every RS simultaneously**. This is a systemic failure mode with no analog in vanilla OAuth (where compromise of one AS does not compromise other ASes). The construction must compare blast radius, not just per-session properties.

**In-threat-model?**
Partially. SRS-FORGE (Game 4) acknowledges the assumption. But the construction does not analyze the global failure mode introduced by a **shared** SRS required by H3, nor does it provide a revocation or re-ceremony protocol. The graceful degradation claim overstates what survives.

---

### Attack 4: Ratchet Forward Secrecy Requires Unformalized Erasure Oracle

**Attack:**
Theorem 2's forward-secrecy reduction for `AgentPolicyV2-Ratcheted` proceeds as: "verifying the full ratchet chain requires the erased prior secret." The reduction implicitly treats erasure as an axiom — the adversary simply cannot obtain `epochSecret_{e-k}` for k > 0. The adversary does not need to break the ratchet cryptographically; they exploit implementation. They compromise the agent runtime environment (exfiltrate memory, snapshot the VM, clone the container image with prior state) and recover `epochSecret_{e-k}` directly. No cryptographic primitive is broken.

**Why it works:**
Forward secrecy in the Signal ratchet or TLS 1.3 key schedule is formalized via a **key erasure oracle** in the security game — the adversary may reveal any key *except* those explicitly erased, and the model formally excludes erased keys from the adversary's view. The construction's §2.3 mentions epoch monotonicity enforced on-chain but provides no formalization of what "erasure" means in the game. There is no `ERASE(epochSecret_e)` oracle. Without this, Theorem 2 is a reduction from "if the adversary cannot obtain prior epoch secrets" — which is a circular assumption, not a proven property.

Additionally, "on-chain epoch monotonicity" prevents replay of old nullifiers but does not enforce that the prover has actually erased `epochSecret_{e-1}`. A prover that retains all epoch secrets (e.g., a buggy agent runtime) silently degrades the entire H4 guarantee with no observable protocol violation.

**In-threat-model?**
No. The construction must introduce an explicit erasure model (following Bellare-Yee or the Signal formal model), define `ERASE` as a game oracle, and state that Theorem 2 holds in the ideal erasure model. It should then separately discuss trust in the agent runtime as an orthogonal assumption, as it does for TEE/TPM in H2. Without this separation, H4's reduction is not a proof — it is a circular argument dressed in game notation.


## Persona: cu_ciso

### Attack 1: Regulatory Vacuum — No Control Mapping Survives an NCUA Examiner

- **Attack:** I pull out my NCUA examination questionnaire for third-party technology risk and ask the vendor rep: "Map each Bolyra component to a specific NCUA Part 748 Appendix B safeguard or FFIEC CAT maturity domain. Show me the column in your SOC 2 Type II that covers this." The construction (§1 through §2.3) uses exclusively cryptographic vocabulary — Groth16, PLONK, Pedersen re-randomization, AGM reduction, q-DLOG. There is no sentence that reads "this control satisfies NCUA Part 748, Appendix B, §III.C (access controls) because…" or "Theorem 2 provides assurance equivalent to FFIEC CAT Evolving maturity level for Identity and Access Management." The model-hash discovery protocol in §2.2 defines a JSON schema with `issuer/models/revocation` but nowhere states which GLBA Safeguards Rule §314.4 element (encryption, access control, change management) it satisfies.

- **Why it works:** An examiner's job is to map vendor claims to enumerated controls. If I cannot produce that mapping in the exam room, the control does not exist from a regulatory standpoint. The construction's six gap-closures are all cryptographic — none translate to the examiner's vocabulary. My board narrative needs one slide that says "ZK proof replaces password → NCUA Part 748 §III.C satisfied → risk reduced." That slide cannot be built from this document.

- **In-threat-model?** No. The construction must add a regulatory control mapping annex: each hypothesis (H1–H5) linked to the specific NCUA Part 748 / GLBA §314.4 / FFIEC CAT control it satisfies or exceeds.

---

### Attack 2: Key Custody — Where Does `epochSecret_e` Live at 2am?

- **Attack:** §2.3 specifies `AgentPolicyV2-Ratcheted` takes `epochSecret_e` as a direct private input with "no `longTermSecret` in-circuit." Good — the long-term secret is erased. But I need to know: where is `epochSecret_e` stored between ratchet steps? The construction is silent. My four possible answers are (a) browser localStorage/IndexedDB, (b) device secure enclave, (c) HSM at the credit union, (d) vendor-managed KMS. If the answer is (a), I have a member secret in a browser — that is a GLBA Safeguards Rule §314.4(e) encryption failure and a NCUA examiner finding waiting to happen. If the answer is (b), I have no way to audit it under my Vendor Management Policy. If (c) or (d), the construction has not specified an HSM integration or key ceremony requirement. The SRS-CEREMONY requirement in A7 covers the proving key, not the per-member epoch secret. These are different secrets.

- **Why it works:** The construction conflates proving-key custody (covered by A7/SRS-CEREMONY) with member-credential custody (not covered anywhere). My Tier 1 ops team gets a 2am call: "Member can't authenticate." The runbook says what? "Check the epochSecret_e ratchet state" — stored where, managed by whom, recoverable how? There is no answer in this document.

- **In-threat-model?** No. The construction must specify a key custody model for `epochSecret_e` — storage medium, recovery procedure, and the NCUA/GLBA control satisfied — distinct from the SRS ceremony.

---

### Attack 3: Audit Trail Intelligibility — Nullifiers Are Not Evidence

- **Attack:** An incident occurs. A fraudulent tool call is made on behalf of a member. My incident response team pulls the audit trail to hand to the examiner. The construction's forward-secure nullifiers (H4, §2.3) mean that post-compromise, prior sessions cannot be deanonymized — which is a privacy feature, not an audit feature. What I actually need is the opposite: a way to prove, after the fact, that a specific member authorized a specific tool call at a specific time. The on-chain epoch nullifier proves a valid credential was used; it does not prove which member, which agent, or which specific RS call. The AS-blindness property (§1, cross-RS linkability note) explicitly says the AS cannot link sessions. So when the examiner asks "show me the authorization chain for this $50,000 wire transfer instruction that came through an MCP agent," I hand them a nullifier hash that proves *someone* with a valid credential did *something* — and that is the end of the trail.

- **Why it works:** NCUA Part 748 Appendix B §III.D requires audit trails sufficient to detect and respond to security incidents. FFIEC CAT Cybersecurity Controls domain requires logging and monitoring with attribution. The construction's privacy model is architecturally hostile to post-incident attribution. The gap-closure for H4 hardened the forward-secrecy claim but did not address the attributable audit trail that examiners require. These two properties are in direct tension and the construction does not resolve that tension.

- **In-threat-model?** No. The construction must specify a selective disclosure or escrow mechanism that allows court-ordered or examiner-required attribution without breaking the general privacy guarantee — or explicitly state that Bolyra is not suitable as the sole authorization layer for high-value transactions.

---

### Attack 4: SRS Ceremony as Unauditable Third-Party Vendor Risk

- **Attack:** A7 (SRS-CEREMONY) requires a multi-party computation ceremony with 1-of-N honesty. The construction adds a graceful degradation analysis showing EdDSA/Poseidon binding survives SRS compromise. I accept that. But my Vendor Management Policy requires that I perform due diligence on every third party with access to member data or authentication infrastructure — including cryptographic infrastructure. Questions: Who ran the SRS ceremony? When? What is the published transcript? What is the minimum N? Is there an independent audit of the ceremony? Can I include this in my annual third-party risk assessment? The construction defines the ceremony requirement operationally (§2.3, A7) but provides no answers to any of these questions. My examiner will ask for the due diligence file on the SRS ceremony operator the same way they ask for the due diligence file on my core processor.

- **Why it works:** NCUA examiners routinely cite inadequate third-party oversight (Part 748 §III.F, Appendix A). The SRS ceremony is a one-time, irreversible trust event. If the ceremony was run by the Bolyra team themselves, or by an informal group with no published transcript, that is a concentration risk and a vendor management finding. Graceful degradation to EdDSA helps availability but does not help the third-party risk finding — the examiner's question is not "what happens if the ceremony was compromised" but "how did you verify it wasn't."

- **In-threat-model?** No. The construction must specify minimum ceremony participant requirements (N ≥ ?), a published ceremony transcript standard, and a due-diligence checklist that satisfies NCUA third-party oversight expectations — or identify an existing audited ceremony (e.g., Zcash Powers of Tau) and explain the trust inheritance.


## Persona: rfc7662_advocate

### Attack 1: DPoP + mTLS Already Delivers H1's "Mutual Sender-Binding" Without ZK

- **Attack:** H1 claims Bolyra uniquely achieves "mutual identity proof" by atomically proving human + agent identity bound to a session nonce. But RFC 9449 DPoP already binds a token to an ephemeral key pair via a per-request proof-of-possession JWT containing `htu` (target URI) and `ath` (access token hash). Pair this with mTLS (RFC 8705) for the agent leg and an `acr`/`amr` claim from a step-up auth flow for the human leg, and the AS has issued a token that is: (a) sender-constrained to the agent's key, (b) bound to the specific request URI, and (c) attested to human presence via AMR. The AS can enforce all three at introspection time using per-RS policy (RFC 7662 §2.2, `active` + custom extension claims). No Groth16/PLONK required.

- **Why it works / why it fails against the construction:** The construction's actual advantage in H1 is *AS-blindness during resource access* — the RS can verify the proof without the AS learning which RS was called. DPoP does not provide this. However, the construction in §1 already narrowed its privacy claim to "AS-blindness and epoch-nullifier forward secrecy." H1 as stated in the candidate (`no human-in-the-loop binding`) is therefore the *wrong* differentiator — the binding is achievable; the *blind binding* is not. The construction must restate H1's claim as "AS-blind mutual binding" or concede the unqualified H1 framing is defeated by DPoP + mTLS.

- **In-threat-model?** Partially. The construction survives if it tightens H1 to claim only AS-blind binding. As currently written, H1 overstates by omitting the AS-blindness qualifier, leaving it exposed to this attack.

---

### Attack 2: JWT Introspection Response (draft-ietf-oauth-jwt-introspection-response) Removes the AS from the Hot Path — §1's AS-Blindness Advantage Is Already Provided

- **Attack:** §1 and §2.3 cite AS-blindness as a load-bearing property: the AS cannot observe which RS the agent calls. But the IETF draft `draft-ietf-oauth-jwt-introspection-response` (now in RFC queue) allows the AS to issue a *signed JWT introspection response* that the RS caches and verifies offline — the AS never receives the per-call introspection request. The AS sees token issuance, not resource access. This is architecturally equivalent to the ZK proof: the RS holds a verifiable assertion, the AS is off the critical path. Per-RS policy is baked into the signed JWT response at issuance time (different `aud`, different filtered claim sets). What does Bolyra provide that this draft does not?

- **Why it works / why it fails against the construction:** The JWT introspection response approach leaks *which RS the token was issued for* at issuance time — `aud` is bound to the RS at mint. Bolyra's ZK credential can be presented to any compliant RS without the AS knowing the target at issuance, which relates to H3 (zero-config portability). However, §2.3's own "Note on cross-RS linkability" concedes that `agentMerkleRoot` and `scopeCommitment` are constants across RS presentations — meaning an AS that collects multiple token issuance events can still profile which agent is targeting which class of RS. The AS-blindness claim in §1 is therefore epoch-scoped, not issuance-scoped. The construction must explicitly state that AS-blindness applies only to the *resource access phase*, and that issuance-phase correlation is not in scope — otherwise the JWT introspection draft closes the gap.

- **In-threat-model?** Yes, construction survives — but the paper must add a one-paragraph comparison against `draft-ietf-oauth-jwt-introspection-response` in §1 and explicitly scope AS-blindness to resource-access-phase only.

---

### Attack 3: RFC 7591 Dynamic Registration + RFC 8707 Resource Indicators Collapse H3's "Zero-Config Portability" Claim

- **Attack:** H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS client registration," contrasting with vanilla OAuth's "per-RS registration or RFC 7591 dynamic registration roundtrip." This framing is misleading. RFC 7591 dynamic registration allows a client to register with any AS in a single HTTPS POST — no human involvement, fully automated. RFC 8707 Resource Indicators allow the client to request an audience-bound token for any RS URI at token-request time, with no prior RS-side registration. The client presents its `software_statement` (a signed assertion about the client, per RFC 7591 §2.3) once at the AS, then requests audience-bound tokens for arbitrary RS URIs. The RS validates the `aud` claim and the token signature — no RS-side state needed. This is one AS interaction, zero RS-side registrations, unlimited RS targets. How is Bolyra's portability primitive distinct from RFC 7591 + 8707?

- **Why it works / why it fails against the construction:** Bolyra's portability is unlinkable across RS — the same credential does not expose a trackable `client_id` to each RS. Under RFC 7591 + 8707, the `client_id` is constant across all resource requests (it appears in the introspection response's `client_id` field). Pairwise Pseudonymous Identifiers (OIDC PPID) partially address this for the `sub` claim, but `client_id` remains correlatable. H3 must be reframed from "no per-RS registration roundtrip" (already solved) to "no per-RS correlatable client identifier" (genuinely novel). The current H3 text defeats itself by citing the RFC 7591 roundtrip as the burden — that roundtrip is a one-time AS event, not a per-RS event.

- **In-threat-model?** Yes, construction survives on unlinkability grounds — but H3 as written cites the wrong baseline. The construction must replace "per-RS client registration" framing with "per-RS correlatable client_id" to survive this attack.

---

### Attack 4: H4's Forward Secrecy Is Defeated by Short-Lived DPoP Tokens + Key Rotation; Construction's Residual Advantage Contradicts §2.3's Own Concession

- **Attack:** H4 claims "agent secret exfiltration does not retroactively deanonymize prior sessions" via forward-secure nullifiers, contrasting with bearer tokens having "no forward secrecy." DPoP with short-lived tokens (e.g., 60-second `exp`) and ephemeral per-request key pairs already provides forward secrecy at the token level: an exfiltrated long-term key does not compromise expired DPoP-bound tokens, which are already unreplayable. The construction's nullifier mechanism adds value only if the adversary's goal is not *replay* but *linkability* — linking a now-deanonymized agent to its prior anonymous sessions. But §2.3 explicitly concedes that `agentMerkleRoot` is a constant across sessions within an epoch, meaning any RS that logged multiple sessions can retrospectively link them to the deanonymized agent *within the epoch*. The forward secrecy advantage is thus scoped to: cross-epoch unlinkability after key compromise. This is a narrow, epoch-boundary-scoped property — not the broad "no retroactive deanonymization" that H4 claims.

- **Why it works / why it fails against the construction:** The construction survives if it scopes H4 precisely: "cross-epoch session unlinkability after secret exfiltration." Within an epoch, §2.3's own constant-root concession means logs at a single RS *do* enable retrospective linkage. The construction must either (a) close the intra-epoch linkability gap (the per-session re-randomization extension identified as future work in §2.3) before claiming H4, or (b) restate H4 as "cross-epoch forward secrecy" and explicitly disclaim intra-epoch forward secrecy. As currently written, H4's claim is stronger than what the construction actually achieves, and the §2.3 concession creates an internal contradiction that an opponent will use to discredit the broader construction.

- **In-threat-model?** Yes — but H4 overstates relative to §2.3. The construction must reconcile the intra-epoch linkability concession with the H4 claim, or ship the per-session Pedersen re-randomization extension before asserting full forward-secrecy dominance over DPoP.


## Persona: spiffe_engineer

---

### Attack 1: "Mutual ZK Handshake" is SPIRE node attestation + a ZK attestor plugin, not a new protocol

- **Attack:** H1 claims Bolyra "atomically proves human + agent identity bound to a session nonce" and that vanilla MCP has "no mutual identity proof." But SPIRE already supports pluggable node attestors (TPM, AWS IID, k8s PSAT). Adding a ZK attestor plugin to SPIRE that ingests the Groth16 human-proof and PLONK agent-proof as attestation evidence would produce an X.509 SVID with both identities embedded in SAN extensions — without inventing a new protocol. The "session nonce binding" maps to the SPIFFE `hint` field in the Workload API response. The construction's §2.1 never demonstrates why this composition cannot live inside the SPIRE attestor interface rather than as a standalone auth layer.

- **Why it works / why it fails:** The construction does not address the SPIRE plugin decomposition at all. It argues against "vanilla OAuth bearer tokens" but SPIFFE is not bearer-token-based — it provides short-lived, automatically-rotated SVIDs with cryptographic proof of possession. The attack partially fails if the human-circuit (Groth16) has no natural mapping to SPIRE's node/workload attestation surface, but the construction never explains this gap.

- **In-threat-model?** No — the construction must address why SPIRE + ZK attestor plugin is insufficient and what semantic gap remains.

---

### Attack 2: H3 portability is SPIFFE trust-domain federation, already shipped

- **Attack:** H3 claims "one Bolyra credential authenticates at every compliant RS without per-RS registration." Trust-domain federation in SPIFFE already provides this property: a SPIFFE ID `spiffe://trust-domain-A/agent/claude` is accepted by any RS that has fetched trust-domain-A's bundle endpoint (`/spiffe/bundle`). No per-RS registration. No RFC 7591 roundtrip. The RS validates the SVID chain against the federated bundle — same topology as Bolyra's model-manifest endpoint (`/.well-known/bolyra-model-manifest` in §2.2). The construction's §2.3 "zero-config portability" claim is operationally identical to SPIFFE federation with a Bolyra-specific trust anchor.

- **Why it works / why it fails:** The construction fails to distinguish the Bolyra trust anchor topology from SPIFFE bundle federation. It might survive if it can show that SPIFFE bundle federation requires bilateral configuration at both ends (trust domain A must explicitly federate with B), whereas Bolyra's manifest endpoint is unilaterally fetchable. But §2.2 and §2.3 never make this argument — they describe a pull-based manifest that any RS can fetch, which is structurally identical to SPIFFE's `FederationRefresh` mechanism.

- **In-threat-model?** No — §2.3 must justify why SPIFFE bundle federation does not close this gap.

---

### Attack 3: §2.2 model-hash discovery is SPIFFE trust bundle distribution with worse security properties

- **Attack:** The `/.well-known/bolyra-model-manifest` endpoint publishes `(model_hash, permission_bitmask)` tuples signed optionally with Baby Jubjub. SPIFFE trust bundles are distributed via the Bundle Endpoint Protocol (SPIFFE spec §6), which is already a signed, versioned, TTL-cached distribution mechanism with explicit sequence numbers and refresh semantics. The construction's §2.2 adds "optional Baby Jubjub manifest signing for offline verification" — but the bootstrap key for that signing key has the same TOFU problem as SPIFFE's initial bundle distribution, which the SPIFFE spec explicitly addresses via `spiffe_sequence` and out-of-band root pinning. The construction does not specify how the Baby Jubjub signing key is bootstrapped, how revocation is propagated faster than TTL expiry (§2.2 mentions TTL-based caching but not push revocation), or how split-brain between manifest versions at different RSes is resolved. SPIFFE's bundle protocol handles all three.

- **Why it works / why it fails:** This is a direct gap — §2.2 describes the happy path but omits the adversarial manifest rotation race. A compromised operator could serve a stale manifest with an un-revoked `(model_hash, bitmask)` pair to an RS that has cached it within TTL while the AS has already invalidated the epoch. SPIFFE sequence numbers prevent this class of downgrade. The construction has no equivalent mechanism.

- **In-threat-model?** No — §2.2 must specify manifest sequence numbers, push-revocation, and cache-invalidation under partial network partition.

---

### Attack 4: H5 delegation latency argument inverts under real SPIRE workload API SLAs

- **Attack:** H5 claims "narrow-scope delegation is a primitive (single proof per hop)" whereas "vanilla OAuth requires full AS roundtrip per hop via RFC 8693." WIMSE draft-ietf-wimse-arch §4.3 specifies workload-to-workload token exchange that piggybacks on the local SPIRE Workload API socket — a Unix domain socket call with sub-millisecond latency, no network roundtrip. In production SPIRE deployments the Workload API response time is under 1ms (cached SVID) or under 10ms (rotation). The Bolyra "single proof per hop" requires Groth16/PLONK proof generation, which on constrained agent hardware (serverless, edge) runs 200ms–2s per proof. The construction's §2.4 never benchmarks proof generation latency against the SPIRE Workload API baseline, and H5's "no AS roundtrip" claim is only a win if proof generation is faster than the roundtrip being replaced — which it is not in the common case.

- **Why it works / why it fails:** The construction may survive if it argues that the proof is generated once per session and reused across hops (amortized cost), and that the WIMSE token exchange still requires network calls at each hop even if each call is fast. But §2.4 and H5 make no amortization argument. As written, H5 is a latency regression presented as a latency improvement.

- **In-threat-model?** No — H5 must provide a latency comparison against SPIRE Workload API + WIMSE token exchange and articulate the amortization model, or the "agent-economy-native delegation" claim is weaker than the incumbent on the most common metric operators actually measure.
