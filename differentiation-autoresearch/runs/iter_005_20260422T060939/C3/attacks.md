# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Latency Math Kills the AI Pipeline Story

**Attack:** Mode B claims ~200ms/hop for "streaming AI" pipelines. A realistic multi-tool agent chain — orchestrator → retrieval → summarizer → action executor → logger — is 5 hops. That's **1 second of ZK overhead per pipeline invocation**, before the actual model inference or tool execution. WorkOS MCP auth issues a scoped delegation token in <50ms *total*, regardless of chain depth, via a standard OAuth token exchange. At scale (10k agent invocations/hour), the Bolyra prover cluster becomes the bottleneck and a cost center with no OAuth analog.

**Why it works / fails:** The construction's §6 (Proof Scheduling) addresses this with Mode C (~0.6s/chain amortized for batching), but batching assumes *post-hoc* audit, not real-time enforcement. If the proof is post-hoc, the pipeline already ran — you're not preventing over-delegation, you're detecting it after damage is done. Mode B's 200ms/hop figure also appears to assume a pre-warm prover; cold-start provisioning is unaddressed. The latency gap against OAuth is real and the construction does not close it for synchronous enforcement scenarios.

**In-threat-model?** No — the construction must address whether ZK enforcement is synchronous (high latency) or post-hoc (detection, not prevention), and be explicit about which threat it actually stops.

---

### Attack 2: The Auditor Can't Read Your Proof

**Attack:** §2.1 defines narrowing via `a AND b = a` over `{0,1}^64`, enforced by `C_narrow` (67 mults/hop). The auditor receives a SE-PLONK proof and a `blindedChainDigest`. In a real regulatory examination — say, a NCUA examiner or a federal court e-discovery request — the auditor's *legal* obligation is to produce human-readable records. A ZK proof is not a record. The examiner will ask for the underlying scope grants, the intermediate principals, and the timestamps. Your break-glass (§5, k-of-n threshold decryption) is the only escape valve, but now you need the NCUA key holders to be available *during* the audit window. Auth0's audit log exports a JSON blob any compliance officer can read in 30 seconds.

**Why it works / fails:** The construction correctly anticipates this via C11 (ElGamal escrow + `escrowDigest`), but the operational model for threshold decryption is underspecified. Who holds the k-of-n keys? How is key rotation handled when a key holder departs? What is the latency from "auditor requests" to "escrow decrypted"? If the answer is "days," no credit union compliance team will accept this over a conventional audit trail. The journalist scenario deliberately disables escrow (`escrowPubkey` = identity point), which means for that scenario there is *no* break-glass — a regulator cannot compel disclosure. That's not a feature in a credit union context; it's a regulatory liability.

**In-threat-model?** Partially — the construction survives the *cryptographic* attack but must address the operational and legal readability requirements that procurement and compliance will impose before §5 is acceptable.

---

### Attack 3: "Solo Founder" is a Disqualifier in Enterprise Procurement, Not a Footnote

**Attack:** WorkOS, Auth0, and Stytch all carry SOC 2 Type II, have enterprise MSAs with indemnification clauses, and have legal entities with multiple principals who can sign DPAs. A credit union's vendor risk management (VRM) process will ask: "What happens to our audit chain if the vendor disappears?" The construction is a cryptographic specification — it has no answer to: SLA guarantees, bug bounty program, CVE response SLO, liability cap, or business continuity plan. The `C_narrow` circuit could have a soundness bug (see: the Tornado Cash deposit circuit note-commitment collision, 2023). Who patches it? Who notifies relying parties? Who is on the hook contractually?

**Why it works / fails:** This attack is entirely outside the construction's scope — §2 through §6 are cryptography, not business. But the *claim* in C3 is "usable beyond narrow regulatory niches," and enterprise usability requires answering these questions. A cryptographic construction that cannot be deployed because no procurement team will sign off on it is not, in practice, usable. The construction must either (a) explicitly scope its claim to research/prototype use, or (b) address the operational trust surface that enterprises require.

**In-threat-model?** No — this is a gap the construction must address if it claims broad enterprise applicability. At minimum, the construction should enumerate the deployment assumptions (who runs the prover, who holds escrow keys, what the upgrade path is for circuit changes) so that an enterprise adopter can assess feasibility.

---

### Attack 4: The Narrowing Proof Doesn't Prevent the Attack It Claims To

**Attack:** The construction's core claim (§2.1, `C_narrow`) is that an auditor can verify monotonic narrowing without learning intermediate scopes. But consider the journalist scenario: intermediate nodes "must stay hidden from auditor." The `blindedChainDigest` (C10) hides participants. However, the *number of hops* is implicit in the proof structure — a Groth16 or PLONK proof for a 3-hop chain has a different verification key than a 5-hop chain, or requires a different circuit parameterization. An auditor observing proof sizes and verification keys across multiple sessions can *enumerate the hop count* and correlate it with known pipeline topologies to deanonymize intermediate nodes probabilistically. This is a traffic-analysis attack on the proof metadata, not the proof content — and SE-PLONK's ZK property does not cover proof *size* or *circuit identity* leakage.

**Why it works / fails:** The construction's Game 3 (EPOCH-UNLINK) addresses correlation of `blindedChainDigest` across epochs, but does not address circuit-identity leakage. If all chains use the same fixed-depth circuit (e.g., max 8 hops, padded), this attack is defeated — but the construction does not state whether circuits are fixed-depth with padding or variable-depth. If variable-depth, the attack stands and the journalist scenario's PARTICIPANT-HIDE guarantee (Game 2) is weaker than claimed because hop count is a participant-count proxy.

**In-threat-model?** No — this is an unaddressed metadata leakage vector. The construction must specify whether circuits are fixed-depth (with dummy hops for padding) or variable-depth, and if variable, must bound what hop-count leakage implies for PARTICIPANT-HIDE.


## Persona: cryptographer

*Construction under review: C3 "Delegation audit without exposure." All section/constraint references (C10–C12, §2.1, Game 2–3) are taken from the candidate description as written.*

---

### Attack 1: Nullifier Precomputation by Colluding AS

**Attack:**
The `rawChainNullifier` is derived from `seedScopeCommitment` and `finalScopeCommitment` (implied by §2.1 + Game 3). The AS *issued* every credential, so it holds (or can recompute) all `delegateeCredComm[i]` values. C12 derives `chainBlinding = Poseidon2(delegateeCredComm[last], sessionNonce)` — but `sessionNonce` uniqueness is asserted without a binding mechanism stated. If `sessionNonce` is a public timestamp or a counter visible to the AS, the AS can enumerate candidate nonces and batch-evaluate Poseidon2 over all enrolled agents' credential commitments. This maps `blindedChainDigest` back to a participant.

**Why it works / why it might fail:**
Game 3 (EPOCH-UNLINK) proves decorrelation under epoch blinding, but the proof appears to model a *passive* auditor, not an AS that holds the preimage dictionary of every issued credential. Without explicitly bounding the AS's knowledge in the game definition — stating what auxiliary input the AS receives — the reduction doesn't close this gap. Poseidon2 preimage resistance is a one-wayness claim, not a pseudorandomness claim under known-key conditions.

**In-threat-model?** **No.** The construction must define whether the AS is honest, semi-honest, or malicious-and-colluding, and must show that Game 3's reduction holds even when the adversary is given the credential issuance transcript as auxiliary input.

---

### Attack 2: Identity-Point Escrow as a Regime Distinguisher

**Attack:**
The journalist scenario sets `escrowPubkey` to the identity point on BabyJubjub to disable escrow. The identity point is a globally known constant. Any auditor (or passive network observer) who sees the proof's public inputs can check `escrowPubkey == O` and immediately conclude: *this proof is from a protected-source chain*. The construction treats this as a feature ("disabling escrow entirely"), but it is a public semantic tag.

**Why it works / why it might fail:**
Game 2 (PARTICIPANT-HIDE) reduces to SE-PLONK ZK, which hides witnesses. But the distinguisher here operates entirely on *public inputs*, not witnesses — ZK gives you nothing here. The adversary's advantage is 1 in distinguishing journalist-scenario proofs from enterprise-scenario proofs: `Pr[A wins Game 2] = 1` when `escrowPubkey` is deterministically set to a known constant. The construction conflates "the prover's identity is hidden" with "the proof regime is hidden." They are separate properties.

**In-threat-model?** **No.** The construction must either (a) route `escrowPubkey` into the witness (hiding it) and commit only to a hash in the public inputs, or (b) explicitly scope Game 2 to regime-aware adversaries and show the property still holds. Currently neither is done.

---

### Attack 3: SE-PLONK in the AGM Does Not Cover Subverted SRS

**Attack:**
The construction cites Ganesh-Orlandi-Tschudi (Crypto 2023) and relies on the Algebraic Group Model (AGM) + ROM for the SE-PLONK reduction. The AGM assumes every adversary-produced group element comes with an explicit linear combination over the SRS elements — this rules out adversaries who exploit relations *embedded in the SRS itself*. A subverted SRS (e.g., toxic waste not destroyed, or a malicious ceremony participant with a non-negligible contribution) yields a structured backdoor that the AGM explicitly cannot model: the backdoor is precisely a non-algebraic trapdoor relationship.

**Why it works / why it might fail:**
The break-glass mechanism (C11) uses ElGamal-on-BabyJubjub anchored via `escrowDigest`. If soundness is broken via a subverted SRS, an adversary can produce valid proofs for false narrowing claims without knowing valid witnesses. This is not a ZK failure — it's a soundness failure. The `escrowDigest` consistency check does not help because it only verifies ciphertexts are *consistent with the proof*, not that the proof itself is sound.

The construction says nothing about the SRS ceremony, trusted parties, or universal vs. per-circuit setup. PLONK's universal SRS reduces (but does not eliminate) this risk. For regulated contexts (NCUA, financial audits), a subverted-setup assumption is precisely what adversaries will exploit.

**In-threat-model?** **No.** The construction must either: (a) state explicitly that the SRS is generated by a trusted third party outside the threat model; (b) adopt a transparent setup (e.g., FRI-based STARK backend), eliminating the SRS entirely; or (c) add a game that models SRS subversion and show security degrades gracefully.

---

### Attack 4: C_narrow Arithmetic Soundness vs. Semantic Narrowing

**Attack:**
§2.1 defines `a ≤ b iff a AND b = a` over `{0,1}^64`. C_narrow enforces pairwise-adjacent hop comparisons with 67 multiplication gates per hop. The circuit checks `scope[i] AND scope[i-1] == scope[i]` for each `i`. But the *semantic claim* — "no hop exceeded its mandate" — requires that the *actual action taken at hop i* is bounded by `scope[i]`, not merely that the scope commitment is ordered.

Concretely: in the AI pipeline scenario (tool call per hop), `scope[i]` is a 64-bit capability bitmask committed by the delegatee. A malicious intermediate agent can commit to `scope[i] ⊆ scope[i-1]` (satisfying C_narrow) while *acting* on capabilities not reflected in the proof — the circuit has no binding between the scope commitment and the actual tool call log. The construction does not define an execution binding: there is no constraint that links `scope[i]` to any observable output or action hash.

**Why it works / why it might fail:**
This is not a cryptographic break of the ZK proof system — the proof is sound *for what it proves*. The attack is a soundness gap between the formal statement and the informal claim. "Monotonically narrowed scopes" is proven; "no hop exceeded its mandate" is not. The gap is the AI pipeline scenario's core requirement, which makes this the highest-severity finding for the stated target use cases.

**In-threat-model?** **No.** The construction must introduce an execution-binding constraint: either (a) include a commitment to the action log at each hop inside the circuit (linking `scope[i]` to `actionHash[i]`), or (b) formally restate the claim as "scope commitments narrow monotonically" and explicitly disclaim the execution-binding property, leaving that to a separate protocol layer.


## Persona: cu_ciso

### Attack 1: Break-Glass Is Theater Without an Operable Runbook

- **Attack:** Section C11 establishes ElGamal-on-BabyJubjub escrow with k-of-n "NCUA key holders" for post-incident scope recovery. The CISO asks: *who exactly holds these keys?* NCUA does not operate a key escrow service. That means the "k-of-n NCUA key holders" is either (a) internal staff who now hold cryptographic material creating insider risk, (b) a vendor who becomes a reportable third party under NCUA Part 748 Appendix A and GLBA §314.4(f), or (c) a governance fiction with no named custodians. At 2am during an incident, my Tier 1 ops team cannot invoke threshold decryption. They need a phone number. NCUA Part 748 Appendix B requires a written incident response plan with documented escalation paths. "Call the threshold decryption ceremony" is not a documented escalation path.
- **Why it works / why it fails:** The construction sidesteps operational custody entirely — it proves escrow *exists* (via `escrowDigest` in the circuit) but says nothing about who operates it, at what SLA, or what the incident procedure looks like. The journalist scenario sets `escrowPubkey` to the identity point and disables escrow entirely, which is fine cryptographically but means the examiner gets zero audit trail for that use case.
- **In-threat-model?** No. The construction must address: named key custodian role, documented recovery SLA, and how the break-glass procedure appears in the incident response plan an NCUA examiner reviews.

---

### Attack 2: The ScopeLattice Is Not Auditor-Readable

- **Attack:** §2.1 defines scope as a 64-bit vector over `{0,1}^64` with monotonic narrowing enforced via `a AND b = a`. In-circuit this is clean. On my board report, it is meaningless. NCUA examiners use the FFIEC CAT to assess access control maturity — they ask whether access is *role-based*, *least-privilege*, and *periodically reviewed* (Domain 2, Cybersecurity Controls). A 64-bit bitmask is none of those things to a non-cryptographer. More importantly, my SOC 2 Type II audit under CC6.3 requires that logical access restrictions are "communicated to appropriate personnel." An auditor who cannot map bit 37 to a named permission cannot sign off on access governance. The construction proves narrowing occurred; it proves nothing about whether the *initial* scope was appropriate — which is what my examiner actually cares about.
- **Why it works / why it fails:** The circuit enforces `C_narrow` correctly, but the claim is about auditability ("in a form usable beyond narrow regulatory niches"). The lattice representation is an internal encoding detail — it never surfaces a human-readable scope description, and the construction offers no binding between bit positions and named entitlements.
- **In-threat-model?** No. The construction must provide: a scope manifest that binds `{0,1}^64` bit positions to human-readable entitlements, committed on-chain, verifiable by an examiner without understanding BabyJubjub.

---

### Attack 3: Cross-Org Agent Handoff Is an Unregistered Third Party

- **Attack:** The gap-to-close explicitly targets "cross-org agent handoff." Under NCUA Part 748 and GLBA §314.4(f), any third party that receives, maintains, or processes member information must be subject to vendor due diligence and contractual data protection requirements. If an AI agent at Org B receives a delegated credential commitment from Org A — even without learning the underlying scope — that handoff is a data transfer event. My vendor management policy requires a signed BAA or data processing agreement before any such transfer. The construction proves the handoff *preserved monotonicity*; it does not prove the receiving org is a vetted vendor, is under contract, or has filed the requisite GLBA privacy notices. An NCUA examiner doing a third-party risk review would flag this as an undocumented data sharing relationship regardless of the ZK proof.
- **Why it works / why it fails:** The ZK proof is cryptographically sound but legally incomplete. "Delegation without exposure" means the receiving agent does not learn the scope — but they do receive a credential commitment and a blinded chain digest, both of which constitute data about the delegation relationship. The construction treats this as a pure cryptographic object; NCUA treats it as member-adjacent data.
- **In-threat-model?** No. The construction must address: what legal instrument governs cross-org handoff, and whether `delegateeCredComm` constitutes member data under GLBA or applicable state privacy law (e.g., California CCPA, Virginia CDPA).

---

### Attack 4: Mode A Forensics Arrives After the Examiner Has Already Filed

- **Attack:** Mode A (forensic, ~4.8s post-hoc) is described as the default for the AI pipeline scenario. NCUA Part 748 Appendix B and the FFIEC CAT both require *detective controls* — meaning anomalies must be detectable within a response window that allows intervention. A 4.8-second post-hoc proof on a per-chain basis means that during a streaming AI pipeline incident, potentially hundreds of hops execute before any proof is generated or verified. If an agent exceeds its mandate at hop 3 and the chain runs 40 hops before Mode A proof is computed, the construction has produced an excellent forensic artifact for an incident that already completed. NCUA examiners will ask: "At what point did your system *detect* the out-of-scope action?" The answer "after the chain terminated" is not a detective control — it is a log.
- **Why it works / why it fails:** Mode B (~200ms/hop) addresses this for pre-authorized pipelines, but pre-authorization requires knowing the pipeline topology in advance, which the gap-to-close explicitly says is not assumed ("each hop is a tool call, not an org"). For ad-hoc AI pipelines, Mode A is the only viable mode, and it is forensic by design.
- **In-threat-model?** No. The construction must address: for Mode A use cases, what is the real-time alerting mechanism (if any) when a chain-in-progress exceeds mandate, and how does this map to FFIEC CAT detective control requirements? If the answer is "Mode A is forensic only," that must be stated as a design limitation with explicit guidance that Mode A alone does not satisfy FFIEC detective control maturity.


## Persona: rfc7662_advocate

---

### Attack 1: AS-Side Monotonic Narrowing Check via Per-RS Filtered Introspection

**Attack:**
The AS already holds the full delegation chain. A properly-configured AS implementing per-RS introspection policy (RFC 7662 §2.1 "policy-controlled response") can:

1. Receive `POST /introspect` from the auditor
2. Internally walk the delegation graph, verify `scope[i+1] ⊆ scope[i]` at each hop
3. Return only `{ "active": true, "scope": "<final scope>", "delegation_valid": true }` — never exposing intermediate scopes or participants

The auditor receives a signed assertion of monotonic narrowing with zero intermediate scope exposure. Where does the construction (§2.1 `C_narrow`, 67 gates/hop) provide a property this does *not*?

**Why it works / why it fails against the construction:**
It fails on the journalist/whistleblower scenario (§ "journalist/source agent chain"). The AS is the policy engine — it *knows* all intermediate participants. Any subpoena, compelled disclosure, or insider at the AS can reconstruct the full chain. The construction's Game 2 (PARTICIPANT-HIDE) requires that the *credential issuer itself* cannot link participants to the auditor's view. RFC 7662 policy is a trust-based control; SE-PLONK ZK is a cryptographic one. The AS is the adversary in Game 2 — RFC 7662 has no model for that.

**In-threat-model?** Yes — construction survives, but the construction must state this explicitly. The paper must say: *the AS is an adversary in Game 2*. If it doesn't, reviewers will assume the AS is trusted and the entire journalist scenario collapses to "AS promises not to look."

---

### Attack 2: Signed JWT Introspection Response Removes AS from Hot Path

**Attack:**
`draft-ietf-oauth-jwt-introspection-response` (now published as RFC 9701) lets the AS pre-sign an introspection response JWT. The auditor receives a signed, cacheable, AS-offline-verifiable assertion. The AS can include exactly:

```json
{ "delegation_chain_valid": true, "final_scope": "read:balance", "chain_length": 4 }
```

No intermediate scopes. No participants. The AS signs once; the auditor verifies forever. This eliminates the AS from the verification hot path — one of the construction's stated Mode A advantages (~4.8s post-hoc). The signed JWT is also *non-repudiable* in a way a ZK proof transcript is not (auditor cannot prove to a third party the ZK verifier accepted).

**Why it works / why it fails against the construction:**
Fails for the same participant-hiding reason as Attack 1, and additionally: the signed JWT *proves the AS made a statement* — it doesn't prove the chain *structurally satisfied a predicate* without AS involvement at signing time. The construction's in-circuit `C_narrow` means the auditor can verify a proof that was generated by participants *without AS involvement at all* — the AS need never see the chain. For AI agent pipelines (§ "multi-tool AI pipeline"), the AS may not even exist in the classic sense; the credential issuer is the orchestrating system. Signed JWT introspection has no model for credential issuers that are themselves ephemeral agents.

**In-threat-model?** Yes — construction survives, but the construction needs a clearer statement distinguishing "AS-signed correctness assertion" from "prover-generated structural proof." Currently §2.1 does not draw this boundary.

---

### Attack 3: PPIDs + RFC 8707 Audience Binding Already Break Cross-RS Linkability

**Attack:**
RFC 8707 (Resource Indicators) binds each token to a specific `resource` URI. Combine with OIDC pairwise pseudonymous identifiers (PPIDs, §8 OIDC Core): each `(sub, resource)` pair produces a distinct `sub` in the issued token. Result: the auditor at RS-4 sees a `sub` that is cryptographically unlinkable to the `sub` the auditor at RS-1 would see — no ZK required.

The construction's Game 3 (EPOCH-UNLINK, §tree topology hiding) claims that chains sharing `seedScopeCommitment` but diverging produce different `blindedChainDigest`. This sounds structurally identical to what PPID derivation + audience binding already achieve: different identifier per audience, unlinkable without AS cooperation.

**Why it works / why it fails against the construction:**
PPIDs hide `sub` from *the RS*, but not from *the AS*. The AS derives the PPID and can trivially reverse it. EPOCH-UNLINK is a property about the *auditor* being unable to correlate across chains — but if the auditor *is* the AS or queries the AS, the PPID gives no protection. More critically: PPIDs bind participant identity, not *scope*. They provide no proof that hop N's scope was a subset of hop N-1's. The construction's `C_narrow` + `seedScopeCommitment`/`finalScopeCommitment` linkage proves a structural predicate (monotonic narrowing) that PPIDs have no analogue for. This is a different problem class.

**In-threat-model?** Yes — construction survives. But the paper must not *claim* EPOCH-UNLINK is novel unlinkability for participants; it must be scoped precisely to *scope-chain topology* unlinkability, which is the genuinely novel property. The current gap description ("too narrow") risks overselling.

---

### Attack 4: DPoP Sender-Constraint + Token Exchange Covers the Agent Pipeline Case

**Attack:**
RFC 9449 (DPoP) + RFC 8693 (Token Exchange) together handle multi-hop AI agent delegation without ZK:

- Each agent hop calls the AS's token exchange endpoint with `subject_token` (previous token) + `requested_scope` (narrowed)
- The AS issues a new DPoP-bound token with the narrowed scope to the next agent's ephemeral key
- Each token is sender-constrained (DPoP proof required) and scope-reduced by AS policy

An auditor can verify the chain by inspecting the token exchange audit log at the AS. No intermediate scope exposure beyond what the AS chooses to log. Mode B (~200ms/hop) isn't competitive — a token exchange round-trip to a local AS is under 10ms.

Name the property DPoP + Token Exchange *cannot* provide that the construction's Mode B provides.

**Why it works / why it fails against the construction:**
The attack completely fails on the journalist scenario and partially fails on the AI pipeline scenario. Three gaps: (1) DPoP + Token Exchange requires a *live AS call per hop* — in a streaming AI pipeline with 50+ tool calls, this is a hard dependency on AS availability and a latency budget the construction explicitly addresses. (2) The AS accumulates a complete audit log — the journalist source is fully exposed to AS forensics. (3) DPoP proves possession of the *current* key; it cannot prove that the holder's *scope* was derived from a predecessor's scope without the AS computing that — which requires the AS to know both. The construction's in-circuit `C_narrow` proves narrowing to the auditor without the AS having seen either scope value. That is the load-bearing property DPoP cannot provide.

**In-threat-model?** Yes — construction survives. The construction should add a comparison table making the DPoP + Token Exchange baseline explicit, since it is the strongest RFC-compliant alternative and the performance comparison (~200ms vs. <10ms) deserves honest treatment.


## Persona: spiffe_engineer

---

### Attack 1: ZK Attestor Plugin — You Are Reinventing at the Wrong Layer

- **Attack:** SPIFFE's attestor model is explicitly pluggable. Node attestors and workload attestors are loaded as gRPC plugins into SPIRE agents. I can write a `zk_scope_attestor` that (a) receives a delegation token, (b) runs `C_narrow` locally to verify scope narrowing, and (c) issues an X.509 SVID whose SAN encodes the narrowed scope as a URI claim (`spiffe://trust-domain/scope/<bitmask>`). The resulting SVID is short-lived (TTL ≤ 5min), SPIRE-rotated, and accepted by any mTLS-speaking workload with no new protocol surface. The construction's §2.1 ScopeLattice and §C12 circuit become an *implementation detail inside a plugin*, not a new protocol. The auditor plugs into SPIRE's audit log (already supported) rather than verifying a novel `blindedChainDigest`.
- **Why it works:** The construction never justifies why scope narrowing must live *below* the workload identity layer rather than *inside* it. SE-PLONK (§A2) is overkill if the SVID TTL already limits exposure — a compromised credential self-expires. The construction's Game 2 (PARTICIPANT-HIDE) is vacuous if the participant list is never transmitted to the auditor by design, as SPIRE's audit log only records SVID issuance events, not the requesting workload's peer graph.
- **In-threat-model?** No — construction must address why a plugin cannot close this gap and what property the construction provides that a pluggable ZK attestor inside SPIRE cannot.

---

### Attack 2: WIMSE Token Chain Already Covers `blindedChainDigest`

- **Attack:** `draft-ietf-wimse-arch` §6.2 defines a workload-to-workload token exchange pattern where each hop issues a DPoP-bound derived token. The `sub` claim narrows per hop; the `act` (actor) claim chain records delegation depth. This is token chaining with built-in audit trail. WIMSE §7 (on the roadmap, active WG discussion as of late 2024) explicitly lists selective disclosure of intermediate actors as an open problem the WG *intends to solve* via SD-JWT. The construction's `blindedChainDigest` (§C10) and epoch blinding (Game 3, EPOCH-UNLINK) are the *exact problem statement* in WIMSE's issue tracker. By building outside the WG, the construction produces a non-interoperable artifact that any WIMSE-compliant service will reject. Worse, it forks the ecosystem at the moment the standards body is closest to covering it.
- **Why it works:** The construction's §1 motivation ("usable beyond narrow regulatory niches") is undermined by the fact that WIMSE *is* the cross-org standard path. Contribution to WIMSE gets RFC status, browser/cloud vendor adoption, and formal IETF review — none of which the construction achieves by shipping `construction.md`.
- **In-threat-model?** No — construction must demonstrate a concrete property gap in WIMSE token chaining (not just "it's not done yet") that requires a ZK construction rather than an SD-JWT extension.

---

### Attack 3: Escrow Infrastructure as Legal Attack Surface (Journalist Scenario)

- **Attack:** §C11 adds ElGamal-on-BabyJubjub escrow with k-of-n NCUA key holders. The journalist scenario "disables" escrow by setting `escrowPubkey` to the identity point. This is a footgun. In any US federal subpoena or NSL proceeding, the existence of the escrow *infrastructure* — even when disabled for a specific chain — creates legal discovery risk. The government does not ask "was escrow used here?" It asks "does your system support escrow?" The answer is yes. A SPIFFE deployment with a ZK attestor plugin that *never* implements escrow has a cleaner legal posture: there is nothing to compel. The construction conflates "escrow disabled for this chain" with "no escrow capability exists," which are not equivalent in a legal threat model.
- **Why it works:** SPIFFE's design principle — workloads hold their own private key material, SPIRE never sees the private key — was chosen precisely to eliminate the "master key escrow" attack surface. The construction reintroduces it. The `escrowDigest` commitment in the proof (§C11) is a permanent on-chain/on-ledger artifact that attests escrow infrastructure exists, even for journalist chains where `escrowPubkey` is set to ∞.
- **In-threat-model?** No — the journalist scenario explicitly requires "intermediate nodes must stay hidden from auditor." Legal compellability of the escrow key holders is an out-of-band break of this property that §C11 does not address.

---

### Attack 4: Mode B Latency Claim Fails Against SPIRE Baseline

- **Attack:** §Proof Scheduling Mode B claims ~200ms/hop for streaming AI pipelines. SPIRE's workload API issues a fresh JWT-SVID in ~12–40ms on a warmed agent (measured in production clusters). A JWT-SVID with a `scope` claim narrowed per-hop via a custom attestor runs at SPIRE's native speed. Mode B is 5–15× slower than the system it replaces. For a 10-hop AI pipeline, Mode B accumulates ~2s of ZK overhead versus ~400ms for SPIRE-native chaining. The construction's §2.1 claims the lattice structure is "purely arithmetic" with 67 multiplication gates/hop, but that ignores proof aggregation, prover memory, and the SE-PLONK trusted setup amortization. These costs do not appear in the gate count.
- **Why it works:** The construction compares itself against an unstated baseline ("usable for streaming AI"). The actual competitor is not "no workload identity" but "SPIRE + a narrow attestor plugin." The 67 gates/hop figure is circuit complexity only; wall-clock latency in a deployed PLONK prover (even with Mode B pre-authorized commitments) must be benchmarked against SPIRE's existing SLA. Until that comparison exists, the 200ms claim is unfalsifiable.
- **In-threat-model?** No — construction must provide end-to-end latency benchmarks against a SPIRE JWT-SVID baseline with equivalent hop count, not just gate counts.
