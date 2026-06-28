# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: scopeId Is Deterministically Computable From Public RS Data

- **Attack:** Section 7 defines `scopeId = Poseidon2(RS_domain, RS_public_key)`. Both inputs are *public*. `RS_domain` is a well-known string (`"target.com"`). `RS_public_key` is a public key — by definition public, typically published in TLS certificates, JWKS endpoints, or DNS records. The DFCU AS doesn't need to observe the direct channel between the agent and Target's RS. DFCU can enumerate every RS it suspects the agent might contact, compute `Poseidon2("target.com", Target_RS_pubkey)` offline, and precompute a lookup table. The construction's claim that "the AS never sees `scopeId`" is only true for a passive, non-computing AS. A *computationally active* AS operating in the same ecosystem (which any OAuth AS by definition is) breaks this in O(|RS catalog|) Poseidon evaluations — trivial cost.

- **Why it works:** The construction's privacy argument in §4.5 explicitly says the AS cannot test candidates because "it does not know `scopeId_h`." This is false for any RS whose public key appears in a public directory, TLS cert transparency log, or API registry. The threat model requires the AS to be *computationally* honest about not precomputing scopeIds. That is not a standard adversary assumption.

- **In-threat-model?** No. The construction must either (a) derive `scopeId` from RS-side secret entropy not derivable from public metadata, or (b) acknowledge that unlinkability holds only against RSes *unknown* to the AS — which is not the DFCU deployment scenario described.

---

### Attack 2: The AS Enrolled Every Agent and Knows Every `credentialCommitment`

- **Attack:** Section 4 claims the adversary "must guess `cc` from the tree of size N" and bounds the advantage at `1/N`. But the AS *controls the Merkle tree* (stated explicitly in §3 threat model: "full read access to the agent Merkle tree"). The AS performed each enrollment — it computed or received each `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` when adding leaves. The AS knows all N values of `cc`. Combined with Attack 1, the AS can exhaustively compute `scopePseudonym_candidate = Poseidon2(cc_i, scopeId_j)` for every `(i, j)` pair in its enrollment log × RS catalog. For a tree of 400K agents and a RS catalog of 1,000 merchants, this is 400M Poseidon2 evaluations — feasible on commodity hardware in minutes. The anonymity set claim collapses from 400K to a complete de-anonymization.

- **Why it works:** The reduction sketch (§4) assumes `cc` is unknown to the adversary, treating it as a private key. It is not. The credential commitment is the *public leaf value* written to the Merkle tree by the AS during enrollment. The human nullifier in Semaphore gets away with a similar construction because the identity commitment uses a *user-supplied secret* (`identitySecret`) that the AS never sees. Bolyra's `credentialCommitment` uses only operator-controlled and AS-visible fields — there is no user-supplied blinding at enrollment time.

- **In-threat-model?** No. The IND-UNL-AS game as stated cannot bound this attack because it assumes `cc` is hidden from A, which contradicts the adversary capabilities in the same section. The construction needs either a fresh user-supplied blinding secret in `credentialCommitment` (analogous to Semaphore's `trapdoor`) or a redesigned enrollment protocol where the leaf value is not recoverable by the AS from its enrollment records.

---

### Attack 3: Proving Latency Kills the MCP Handshake in Practice

- **Attack:** Section 6 targets "< 3s on commodity hardware (M1/M2 Mac, 16 GB RAM)" for PLONK. MCP tool calls are synchronous — an LLM calls a tool and waits. WorkOS, Auth0, and Stytch issue tokens in < 100ms over a CDN edge. A 3s ZK proving step adds 30× latency to every tool invocation, compounded across multi-step agent workflows (10 tools × 3s = 30s overhead per task). For the DFCU scenario, a member agent doing price comparison across 5 merchants incurs 15s of proving overhead before a single merchant API call completes. At an enterprise procurement conversation, the question is not "is IND-UNL-AS formally proven?" — it's "will this make our member-facing app feel broken?" The construction defers proving-time optimization to "future work" without quantifying what hardware the agent is expected to run on (laptop? mobile? shared inference server?). Section 2's batch relay proposal (30s mixing window) compounds this further: the agent cannot complete a real-time lookup without either (a) breaking privacy by not batching, or (b) waiting 30+ seconds.

- **Why it fails against the construction (partially):** For batch/offline workflows — nightly financial reconciliation, medical record sync — 3s is tolerable. The construction survives in async contexts.

- **In-threat-model?** No, this is a product objection, not a cryptographic attack. But it is the reason the construction will lose every competitive evaluation against MCP auth incumbents in real-time agentic use cases, which is the primary adoption surface described in §7.

---

### Attack 4: The On-Chain Registry Is an AS-Controlled Correlation Surface

- **Attack:** Step 3 of the protocol flow (§2) says "agent submits proof to the on-chain registry" with public signals including `agentMerkleRoot`, `scopePseudonym`, `blindedScopeCommitment`, `sessionNullifier`, `scopeId`, `requiredScopeMask`, `currentTimestamp`, and `sessionNonce`. All of these land on a public ledger. The AS (DFCU) is a persistent on-chain observer. Even if individual proofs are cryptographically unlinkable, the AS can apply graph-theoretic analysis to the `requiredScopeMask` field: an agent requesting `0b00000101` (READ_DATA + FINANCIAL_SMALL) at 14:02 followed by the same bitmask at 14:07 is a strong behavioral fingerprint, especially combined with `currentTimestamp` granularity. If DFCU knows member #4821 typically shops between 14:00 and 15:00 on Fridays (from prior card transaction data), the AS narrows the anonymity set from 400K to the small cohort active in that window. The IND-UNL-AS game (§3) doesn't account for the AS combining ZK proof metadata with *external side-channel data* it already holds as a financial institution. WorkOS/Auth0 don't publish proof metadata to a public ledger — their token issuance is API-level and ephemeral.

- **Why it works:** The construction's threat model (§3) restricts the AS to "all proof submissions, all public signals" but doesn't model the AS as holding *correlated external data* (card history, login times, device fingerprints). A credit union AS has DFCU's complete member transaction history. The unlinkability game treats the AS as a cryptographic adversary, not as a data-rich financial institution. The combination of `requiredScopeMask + currentTimestamp` on a public ledger is a de-anonymization vector the formal game does not capture.

- **In-threat-model?** No. The construction must either (a) remove `currentTimestamp` and `requiredScopeMask` from public signals and prove them in-circuit against committed values, or (b) acknowledge that IND-UNL-AS holds only in the cryptographic model and provide a separate argument for the statistical-linkage threat from correlated external datasets — which is precisely the threat the DFCU and Kaiser scenarios are designed to address.


## Persona: cryptographer

---

### Attack 1: Enrollment Leaks the PRF Key — Scope Pseudonym Precomputation

- **Attack:** The AS manages the agent Merkle tree (stated in §3 threat model: "full read access to the agent Merkle tree"). To insert a leaf, the agent must submit `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` at enrollment time. The AS stores it. Separately, `scopeId = Poseidon2(RS_domain, RS_public_key)` is described in §7 as `Poseidon2("target.com", Target_RS_pubkey)` — both inputs are public registry metadata. The AS, knowing all RSes in its ecosystem, precomputes every `scopeId_j`. It now has every `cc_i` (from the Merkle tree it manages) and every `scopeId_j` (publicly derivable). It builds a complete lookup table: `pseudonym[i][j] = Poseidon2(cc_i, scopeId_j)`. Every on-chain `scopePseudonym` is immediately matched to `(agent_i, RS_j)` in O(N·K) offline work. The adversary does not need to break Poseidon — it has both inputs.

- **Why it works:** The reduction sketch in §4 states "keying Poseidon on `cc` (which is hidden as a private input)." But this is false with respect to the AS. The ZK proof hides `cc` from the *on-chain verifier*, not from the AS who wrote `cc` into the tree. The PRF security model requires the key to be unknown to the distinguisher; here the AS is the distinguisher *and* the one who enrolled each leaf. The Poseidon PRF assumption (A1) is inapplicable when the adversary holds the key.

- **In-threat-model?** **No — construction must address.** The §3 threat model explicitly grants the AS "full read access to the agent Merkle tree" without restricting it from learning individual leaf values. The claimed reduction is vacuous under this capability.

---

### Attack 2: scopeId Is Publicly Derivable — the "Private Input" Claim Is Unfounded

- **Attack:** Section 2 states `scopeId = Poseidon2(RS_domain, RS_public_key)` and that "The AS never sees scopeId." But no mechanism prevents the AS from computing it. RS discovery requires the RS to be publicly registered or at minimum TLS-reachable; its domain and public key are not secrets. A passive AS enumerates all RS endpoints it manages authorization for (which in OAuth-style deployments it necessarily knows), computes `scopeId_j = Poseidon2(RS_domain_j, RS_pubkey_j)` for each, and recovers the full mapping. The claim that `scopeId` is a private input to the circuit is true syntactically — it is not in the proof's public input list — but it is not semantically private from the AS, which is the relevant adversary.

- **Why it works:** The construction conflates "not listed as a circuit public input" with "computationally hidden from the adversary." These are different properties. The ZK circuit prevents the on-chain verifier from learning `scopeId`; it does not prevent a computationally unbounded adversary with side knowledge from recovering it. The §4 reduction sketch does not argue that `scopeId` is computationally hidden from the AS — it simply assumes it. For the unlinkability game to be meaningful, the construction must either (a) prove `scopeId` is indistinguishable from random to the AS, or (b) introduce a mechanism that prevents the AS from enumerating RS identities (e.g., RS keys never published, distributed via a private channel the AS is excluded from).

- **In-threat-model?** **No — construction must address.** The §3 adversary capability description says the AS "observes all proof submissions" but does not restrict its ability to compute `scopeId` from public RS metadata. Without bounding this, the attack in §1 remains operational.

---

### Attack 3: The IND-UNL-AS Game Restriction Conceals the Trivial Distinguisher It Claims Not to Need

- **Attack:** Game IND-UNL-AS (§3, step 4) imposes: "A may NOT query both agents on the same scopeId as the challenge scope." The construction calls this a "trivial distinguisher via Merkle root + known tree." But the Merkle root is *shared* across all 400K agents — this is stated explicitly in §4 ("every agent references the same tree"). The Merkle root is therefore NOT a per-agent fingerprint. So why is same-scope querying "trivial"? Because `scopePseudonym = Poseidon2(cc, scopeId)` is deterministic: for a fixed `(cc, scopeId)` pair, the pseudonym is the same in every proof. An adversary that can query agent `cred₀` on `scopeId_c` (the challenge scope) gets `Poseidon2(cc₀, scopeId_c)` and can directly compare it to the challenge proof. The restriction is not an edge-case exclusion — it is the only case where the AS attack works AND the game restriction is the only thing preventing it. The game has been designed to exclude the most natural attack by fiat rather than by construction.

- **Why it works:** A well-formed game should exclude only adversarial queries that make the game *information-theoretically* trivial (e.g., a direct decryption oracle in an IND-CPA game). Here the excluded query is excluded because the construction is actually broken in that regime. The correct fix would be to introduce per-proof randomization of `scopePseudonym` itself (not just `blindedScopeCommitment`) so that the same `(cc, scopeId)` pair produces a fresh unlinkable output in every proof. The current design produces a stable pseudonym per agent per scope — correct for pseudonymity within a scope, but insufficient for unlinkability claims across proofs.

- **In-threat-model?** **No — construction must address.** The stability of `scopePseudonym` across proofs for the same `(agent, RS)` pair means an AS that sees two proofs from the same scope can trivially confirm they are the same agent. The game restriction conceals this rather than fixing it.

---

### Attack 4: Subverted Groth16 Setup Retroactively Breaks All Unlinkability

- **Attack:** `ScopeBlindedAgent` uses Groth16 via a project-specific `.zkey` generated from `pot16.ptau`. Section 2 notes PLONK is "preferred for agents" but Groth16 remains available. Under a subverted trusted setup — where the toxic waste `τ` from the circuit-specific Phase 2 ceremony is retained — the adversary can produce a fake proof for any public input vector, including fabricated `(scopePseudonym, blindedScopeCommitment, sessionNullifier)` triples. More precisely: with knowledge of `τ`, one constructs a valid Groth16 proof for any (possibly inconsistent) assignment of public outputs without knowing a valid witness. The AS as ceremony participant (or ceremony subverter) can forge proofs for targeted agents, inject them on-chain with chosen `scopePseudonym` values, and use the resulting on-chain record to frame agents or to test whether a particular `cc` is present by observing verifier acceptance. No multi-party ceremony is described for the ScopeBlindedAgent circuit; §2 says pot16.ptau is "the universal SRS for project-specific Groth16 keys" but does not specify the Phase 2 ceremony participants or verification procedure. For PLONK: the universal CRS similarly requires a trusted setup; a single-party CRS generation (e.g., by Bolyra itself) exposes every deployed circuit to the same subversion.

- **Why it works:** Knowledge soundness of Groth16 (A2 in §4) holds only under an honest trusted setup. The construction's threat model grants the AS broad powers but does not bound its role in ceremony participation. If DFCU operates the AS *and* participated in (or ran) the Phase 2 ceremony for ScopeBlindedAgent, all cryptographic unlinkability is conditional on DFCU not retaining `τ`. The construction provides no ceremony transcript, no verifier checksum, and no argument that the setup was performed by parties independent of the AS. Without a verifiable multi-party ceremony (Powers of Tau + circuit-specific Phase 2 with published contributions), the subverted-setup attack is live and retroactive — any proofs already on-chain can be re-analyzed by the party who holds `τ`.

- **In-threat-model?** **No — construction must address.** The threat model bounds the AS at the protocol layer but not at the setup layer. A complete security argument must either (a) require a verifiable multi-party Phase 2 ceremony with AS exclusion, (b) switch exclusively to PLONK with a publicly verifiable universal CRS (e.g., Ethereum's KZG ceremony, where the AS is one of thousands of contributors and subversion requires all contributors to collude), or (c) explicitly state the setup trust assumption and bound the adversary accordingly.


## Persona: cu_ciso

---

### Attack 1: The Audit Trail Destruction Problem

**Attack:** The CISO points to NCUA Part 748 Appendix A §III.C (access controls and audit trails) and GLBA Safeguards Rule 16 CFR §314.4(c)(3) (monitoring and testing for unauthorized access). Both require the CU to maintain logs of *who accessed member data, when, and from where*. The construction explicitly states in §7: "DFCU cannot determine whether these are the same agent or two different agents." The CISO flips this around:

> "You've just told me my AS — the system I'm responsible for under Part 748 — cannot tell my examiners which of my 400,000 members' agents accessed CVS pharmacy data last Tuesday. That's not a privacy feature. That's a gap in my access control audit trail. My NCUA examiner will ask for an access log. What do I hand them?"

The construction treats AS-blindness as the *goal* (§8: "AS is reduced to a tree maintainer"). For NCUA examination purposes, the AS being unable to produce `(agent, RS, scope, timestamp)` tuples is a *deficiency finding*, not a capability.

**Why it works:** The IND-UNL-AS game (§3) and the deployment scenario (§7) are designed to prevent the AS from building a behavioral profile. But NCUA Part 748 and FFIEC CAT Domain 3 (Cybersecurity Controls, C3.f) require exactly that behavioral profile — in the form of access logs — to be retained for examination and incident response. The construction provides no mechanism for the CU to produce a regulatorily-defensible access log while simultaneously claiming unlinkability.

**In-threat-model?** No — construction must address. The construction needs a dual-mode design: either (a) a separate, CU-controlled audit log mechanism that the member can consent to (which reintroduces linkability), or (b) a compliance disclosure that clearly states this construction is incompatible with AS-side audit logging requirements, shifting the logging burden to the RS layer.

---

### Attack 2: Key Custody — Where Does `credentialCommitment` Actually Live?

**Attack:** Step 2 of the protocol flow (§2) reads: "Agent generates `ScopeBlindedAgent` proof with fresh `blindingScalar ← random(F_p)`." The CISO applies the attack prompt directly:

> "Where does the member's private input live? The `credentialCommitment` is `Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. The `blindingScalar` is fresh random. Who generates it? Where is `operatorPrivKey` stored — the key that signs the credential? If that key lives in a browser or a mobile app sandbox, I'm done here. If it lives in your infrastructure, then you're my custodian and I need a SOC 2 Type II audit."

The construction lists `sigR8x`, `sigR8y`, `sigS` as private inputs (the EdDSA signature over `credentialCommitment`) but says nothing about where the operator private key is stored, how it's rotated, what HSM or TPM backs it, or what happens when a member's agent device is lost or compromised. GLBA Safeguards Rule §314.4(f) requires the CU to implement multi-factor authentication and encryption for any system storing member credentials — "operator private key on a mobile device" is not a passing answer.

**Why it works:** The construction's cryptographic argument (§4) proves unlinkability *given* that private inputs remain private. But it defers entirely to implementation for how those inputs are protected. A browser-based `crypto.getRandomValues()` call for `blindingScalar` and a `localStorage`-stored operator key are within the construction's scope but violate GLBA key management requirements. The construction gives no guidance and no boundaries.

**In-threat-model?** No — construction must address. The security reduction (§4) explicitly scopes out "the agent's private key or `blindingScalar`" as adversary-inaccessible. But this assumption is only valid with specific key custody controls. The construction needs a key custody section specifying minimum acceptable storage (e.g., hardware-backed keystore, TEE, or HSM), or it must clearly disclaim that key custody is out of scope and the CU must supply it — in which case a NCUA examiner will find the gap in the vendor risk assessment.

---

### Attack 3: Incident Response Black Hole (FFIEC CAT / SOC 2 CC7)

**Attack:** The CISO posits a breach scenario: an agent credential is stolen (operator key exfiltrated via malware), and for 72 hours the attacker's agent submits valid `ScopeBlindedAgent` proofs — appearing on-chain as one of 400,000 agents in the shared tree. The NCUA notification rule (12 CFR §748.1) requires the CU to notify members of unauthorized access to their data. The CU must answer: *which members were affected?*

> "Under your construction, your on-chain registry sees `agentMerkleRoot` and `scopePseudonym` values, but cannot map them to Member #4821 without the `credentialCommitment`. The attacker used real credentials. Every proof is valid. My SOC team opens SIEM, finds 2,400 valid on-chain proofs over the weekend, and has no way to attribute them to the compromised credential — because your unlinkability construction worked exactly as designed. How do I scope my breach notification?"

The batch relay (§2) compounds this: if proofs were submitted in multicall transactions, even timing analysis is eliminated. The construction defends unlinkability so thoroughly that the CU cannot perform forensic attribution during incident response.

**Why it works:** The construction's threat model (§3) defines the adversary as the *AS trying to correlate traffic*. It does not define the CU's own security operations as a legitimate use case for linking proofs to members. SOC 2 Type II CC7.2 requires "the entity monitors system components and the operation of those controls" — which presupposes the entity can read its own audit log. FFIEC CAT Maturity Level 3 (Intermediate) requires anomaly detection tied to specific accounts. A construction where the CU cannot identify which member generated a given proof makes both requirements impossible to satisfy.

**In-threat-model?** No — construction must address. A credible deployment needs a *revocation and attribution* channel that is separate from the unlinkability proof path: for example, a CU-private mapping of `credentialCommitment → memberID` stored in an HSM-backed database, accessible only under dual-control for breach investigation. The construction's §7 scenario for DFCU never mentions this, and §8's comparison table lists "AS sees only unlinkable pseudonyms" as a pure win with no operational trade-off acknowledged.

---

### Attack 4: On-Chain Registry SLA and Third-Party Vendor Risk Under NCUA Part 748

**Attack:** Section 4 of the protocol flow specifies that the on-chain registry:
- verifies `sessionNonce` freshness
- checks `agentMerkleRoot` against the root history buffer
- records `sessionNullifier` to prevent replay

This registry is a smart contract. The construction maps to Base (§CLAUDE.md: "Deploy target chain: Base Sepolia"). The CISO applies NCUA Part 748 Appendix A §I (risk management for third-party services) and the FFIEC's IT Examination Handbook (Operations, Business Continuity):

> "My core processor has a contractual 99.95% uptime SLA with documented RTO/RPO. Your on-chain registry is a smart contract on an L2 that depends on Ethereum L1 for data availability. Base has had sequencer downtime events. If the registry is unavailable, can my members' agents get authorized? What's the RTO? Who do I call at 2am? Does your smart contract vendor have an incident notification obligation to me under NCUA guidance?"

The construction's §7 deployment scenario describes 400,000 DFCU member agents hitting this registry for every handshake. Each RS verification step (Step 5) depends on on-chain state. A sequencer outage, gas spike preventing nonce recording, or L1 congestion event blocking root history updates cascades into an authorization outage for all member agents across all merchants — with no fallback path described.

**Why it works:** NCUA examiners applying the FFIEC's vendor management guidance (FIL-44-2008 successor guidance) will ask: (1) What is the contractual SLA? (A public blockchain has none.) (2) What is the exit strategy if the vendor fails? (Smart contracts are immutable.) (3) Has the CU performed due diligence on the code? (A Circom circuit and Solidity verifier are not SOC 2 audited.) (4) Is the third party subject to NCUA supervisory authority? (No — it is a permissionless blockchain.) The construction provides no answers and does not acknowledge this regulatory surface at all.

**In-threat-model?** No — construction must address. The construction needs either (a) an availability section specifying fallback behavior when the on-chain registry is unavailable (circuit-breaker to a CU-operated off-chain registry? cached root acceptance window?), or (b) a vendor risk disclosure explicitly acknowledging that the CU's vendor management policy must classify the on-chain registry as a critical third party and perform NCUA-required due diligence — including the fact that no contractual SLA or right-to-audit exists with a permissionless L2.


## Persona: rfc7662_advocate

---

### Attack 1: `scopeId` Is a Public Signal — The "AS Never Sees It" Claim Is Internally Contradicted

**Attack:**
The adversary reads the circuit's own signal table. In §2 ("New circuit: `ScopeBlindedAgent`"), `scopeId` appears in the **Public inputs** table: *"RS-specific scope identifier (known to agent + RS, NOT to AS)."* Then in the Protocol Flow §2, step 3, the on-chain registry call explicitly enumerates `scopeId` among the values the registry receives:

> "The registry sees `(agentMerkleRoot, scopePseudonym, blindedScopeCommitment, sessionNullifier, **scopeId**, requiredScopeMask, currentTimestamp, sessionNonce)`"

A public input to a Groth16/PLONK circuit is part of the verification tuple — it is visible to anyone running the verifier, including the AS observing on-chain state. The parenthetical "NOT to AS" in the signal description has no cryptographic enforcement.

**Why it works / why it fails:**
This attack fully succeeds as stated. If `scopeId` is public, the AS trivially learns which RS each proof targets. `scopePseudonym = Poseidon2(credentialCommitment, scopeId)` is then a deterministic function of a known value (`scopeId`) and an unknown (`credentialCommitment`). Knowing `scopeId`, the AS can try all enrolled agents' credential commitments (which it holds as the enrollor — see Attack 2) and recover the agent identity. The entire §8 column "AS never learns which RS the proof targets" collapses. Making `scopeId` a *private* input and exposing only `scopePseudonym` as a public output would fix this, but requires a verifier-side mechanism for the RS to confirm the proof targets its scope without the AS seeing the scopeId — an unaddressed protocol design problem.

**In-threat-model?** No — the construction must address this. The signal classification is self-contradictory. Either `scopeId` is private (and the RS verification flow in step 5 must be redesigned) or `scopeId` is public (and §8's core claim is false as written).

---

### Attack 2: AS-as-Enrollor Destroys the Reduction's Anonymity-Set Assumption

**Attack:**
Section 4's reduction sketch claims: *"A must guess `cc` from the tree of size N, each guess requiring a Poseidon evaluation. For the honest RS (RS_h), A does not know `scopeId_h` and cannot test candidates."* This assumes `credentialCommitment = Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` is unknown to the adversary. But the adversary in this threat model **controls the AS**, and the AS is the **enrollor** — it generates or verifies the operator-signed credential at enrollment time.

Specifically: the AS holds a table `{agent_id → (modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)}` for every enrolled agent. Given this table, the AS can compute every `credentialCommitment` for every enrolled agent in O(N) Poseidon evaluations offline. When a proof arrives with public signal `scopePseudonym`, and the AS has guessed or observed `scopeId` (see Attack 1), it computes `Poseidon2(cc_i, scopeId)` for all i=1…N and looks for a match. This is not a brute-force over a keyspace — it is a lookup over the AS's own enrollment records.

The §4 reduction argument reduces to: *"The advantage is 1/N per corrupted RS."* That is only true if the AS does **not** know the mapping `{agent → cc}`. A real AS-as-enrollor **always** knows this mapping. The anonymity-set argument confuses syntactic circuit privacy (cc is a private input signal) with semantic privacy (the value is unknown to the AS). These are not the same when the AS computed or registered the value.

**Why it works / why it fails:**
The reduction is unsound for an AS that has enrollment records. The fix requires either (a) a commitment scheme where the agent self-generates `cc` without AS visibility during enrollment (e.g., a blind enrollment flow), or (b) the security claim must be restated to exclude AS adversaries who hold enrollment state — which is a dramatic narrowing of the claimed threat model. The §3 threat model says A "controls the AS" and has "full read access to the agent Merkle tree" — this necessarily includes the enrollment inputs.

**In-threat-model?** No — the construction's formal threat model explicitly grants the AS control over the Merkle tree. The reduction sketch does not account for the AS's knowledge of `(agent_id, cc)` pairs derived from enrollment. The IND-UNL-AS game in §3 must be revised to address this.

---

### Attack 3: JWT Introspection Response Already Removes the AS from the Per-Session Hot Path

**Attack (citing RFC toolbox):**
Section 8 anchors the baseline comparison on: *"every token is AS-issued, AS logs `(agent, RS, scope, time)`."* This is accurate for RFC 7662 active introspection. However, **draft-ietf-oauth-jwt-introspection-response** (structured JWT introspection) combined with **RFC 9449 DPoP** removes the AS from the per-request path:

1. The AS issues a signed JWT introspection response at token issuance time.  
2. The RS caches this JWT for the token lifetime (e.g., 5 minutes).  
3. Subsequent requests within the token lifetime are verified offline by the RS against the cached JWT + DPoP proof binding.  
4. The AS sees one event per token issuance, not per API call.

Combined with **RFC 8707 resource indicators** (audience-bound tokens) and OIDC **PPID/pairwise identifiers**, the AS sees: `(pairwise_sub_for_RS_j, RS_j, scope_j)` at issuance — a different pairwise subject per RS. The RS never sees the central identity. The AS sees the full graph but only at issuance granularity, not session granularity.

The construction's §8 "AS sees per-session authorization events" does not hold for the JWT introspection path, only for active introspection. The comparison table must distinguish these two baselines.

**Why it works / why it fails:**
The attack partially works: it weakens the §8 "categorical separation" argument for the per-session correlation claim. JWT introspection achieves session-level hiding for individual API calls within a token lifetime. However, it fails to achieve **issuance-time unlinkability**: the AS still sees which RS the agent is targeting when the token is first issued, including the `resource` parameter per RFC 8707. Bolyra's construction (if Attack 1 is fixed) genuinely eliminates issuance-time visibility of the target RS. The AS in Bolyra sees only `agentMerkleRoot` and `requiredScopeMask` — not the target RS identity. This is a real, non-incremental distinction, but it is narrower than the construction claims.

**In-threat-model?** Yes — the construction survives for the specific claim of issuance-time AS blindness. But §8 overstates the baseline weakness by ignoring JWT introspection's session-level hiding. The comparison must be corrected to say: *"Bolyra eliminates issuance-time AS visibility of the target RS; JWT introspection eliminates per-call AS visibility but not issuance-time visibility."*

---

### Attack 4: `requiredScopeMask` + `agentMerkleRoot` Collapses Anonymity Under Real Deployment Conditions

**Attack:**
The construction's anonymity argument rests on the agent tree containing N=400,000 agents (the DFCU scenario in §7). But `requiredScopeMask` is a **public input** — every proof reveals which permission bits are being asserted. In the DFCU healthcare sub-scenario: an agent requesting `permissionBitmask = 0b10000101` (READ_DATA + FINANCIAL_SMALL + ACCESS_PII, bit 7) is a strict subset of the enrolled population. If only 500 of 400,000 DFCU member agents carry ACCESS_PII credentials, the anonymity set for that proof is 500, not 400,000.

Further, `agentMerkleRoot` pins the proof to a specific tree state. If the AS controls tree updates (it does — it is the enrollor), it can time a root update to narrow the anonymity set. The AS adds one agent, updates the root, then observes which proofs arrive using the new root. All such proofs must be from agents enrolled *after* the last update — potentially a set of size 1.

This is a traffic-analysis attack, not a cryptographic one. The §4 security argument is purely cryptographic (Poseidon PRF). It does not bound information leakage from public inputs across multiple proofs. The IND-UNL-AS game in §3 asks the adversary to distinguish *which* of two agents (cred₀ vs cred₁) generated a proof — but it does not model the adversary learning set membership from metadata leakage narrowing the anonymity set below the stated bound.

**Why it works / why it fails:**
The attack succeeds at the operational level for permission-sparse deployments. The cryptographic IND-UNL-AS game does not capture this because the game constructs both agents with "identical permission bitmasks" (§3 step 1) — the game is designed to preclude exactly this distinguisher. But real-world deployments violate the game's identical-bitmask assumption: agents have heterogeneous permissions, and that heterogeneity is public. The construction should either (a) add a `requiredScopeMask` hiding gadget (prove the bitmask satisfies requirements in zero knowledge without revealing its exact value), or (b) explicitly scope the security claim to uniform-permission deployments and document the anonymity-set bound as deployment-dependent.

**In-threat-model?** Partially. The *cryptographic* construction survives — the Poseidon PRF reduction holds. But the *operational privacy claim* (anonymity set = N) does not hold without uniform permission distribution. The gap-to-close in C2 ("empirical test showing colluding AS+RS cannot de-anonymize") must account for permission-sparse populations.


## Persona: spiffe_engineer

---

### Attack 1: `scopeId` Is a Public Input — The Core Unlinkability Claim Is Self-Contradicting

**Attack:**
The construction's own table (§2, Public inputs) lists `scopeId` as a public input with the annotation "known to agent + RS, NOT to AS." Then §2 Protocol flow Step 3 states the on-chain registry sees `(agentMerkleRoot, scopePseudonym, blindedScopeCommitment, sessionNullifier, **scopeId**, requiredScopeMask, currentTimestamp, sessionNonce)`.

The adversary AS is defined (§3) as having full read access to "all proof submissions." If the AS can read the chain, it reads `scopeId` directly from every proof submission. The annotation "NOT to AS" is simply wrong.

Consequence: the AS precomputes a directory `{ Poseidon2(domain, RS_pubkey) → merchant }` for any known RS (Target, CVS, LabCorp, Walgreens). For each proof on-chain, it looks up `scopeId` in its directory and reconstructs exactly the merchant graph that §7 claims is hidden. The DFCU scenario collapses entirely — DFCU sees "agent visited Target at 14:02, CVS at 14:07" because it reads `scopeId_Target` and `scopeId_CVS` from the chain.

The security argument in §4 explicitly assumes "For the honest RS (RS_h), A does not know `scopeId_h` and cannot test candidates." This is false under the stated protocol.

**Why it works:** Public input is public. The ZK proof hides the *witness* (private inputs). It does not hide public inputs. If `scopeId` must be hidden from the AS, it must be a private input — but then the RS cannot verify that the `scopeId` in the proof matches its own identity without a separate sub-protocol. The construction never defines that sub-protocol.

**In-threat-model?** Yes — this is a direct break of the stated claim. The construction must either (a) make `scopeId` a private input and define a verifier-local consistency check, or (b) accept that the AS learns the RS identity and limit the claim to pseudonym unlinkability only. Neither option is handled.

---

### Attack 2: Adversarial Merkle Tree Management — Canary Root Attack

**Attack:**
The AS "controls the agent Merkle tree" (§3, Adversary capabilities). The construction relies on the shared tree providing a large anonymity set (400K agents for DFCU). But the AS controls *when* the tree updates — it controls insertions and therefore controls root transitions.

**Canary attack:**
1. AS adds a dummy agent entry at time T, producing new root `R_new`. It records which proofs arrive referencing `R_new` versus `R_old`.
2. For any agent that generates a proof between time T and T+Δ (before the next honest batch), the proof references `R_new`. If the agent is the only one to prove in that window, it is uniquely identified by root alone.
3. The 30-entry root history buffer (§4, Merkle root correlation) mitigates stale roots but does not prevent the AS from timing canary insertions to coincide with targeted agent activity.

This is exactly how SPIRE handles revocation: the server schedules CRL/OCSP updates and can observe which workloads re-attest after a CRL rotation. Bolyra exposes the same surface because the tree maintainer is the adversary.

**Why the construction's mitigation fails:** The batch relay (§2, Batched submission) shuffles proof *submission* timing but does not shuffle which Merkle root a proof uses. A proof's `agentMerkleRoot` is determined at witness generation time, not submission time. If the AS times canary insertions with millisecond precision (it controls the chain), the root itself leaks timing even if the relay shuffles submission order.

**In-threat-model?** Partially. §4 notes "Merkle root correlation" as a side-channel and mentions the history buffer as mitigation. But the active adversary case — where the AS *induces* root transitions to de-anonymize — is not modeled. The IND-UNL-AS game (§3) does not give the adversary the power to time tree insertions. The threat model must either exclude this capability explicitly or extend the game to bound the adversary's tree-write cadence.

---

### Attack 3: The WIMSE Token Exchange Already Solves This at the Right Layer

**Attack:**
This is not a cryptographic break — it is a protocol layering objection, which is the right objection to make before investing in new circuits.

WIMSE draft-ietf-wimse-arch (currently in IETF WIMSE WG) defines a workload token exchange where a workload presents a *sender-constrained* service token to a target service without the issuer seeing the per-request (workload, service) pair. The WIMSE WG has explicit scope for selective disclosure. SPIRE already issues short-lived X.509 SVIDs and JWT SVIDs without the SPIRE server logging "workload A talked to service B" — it issues credentials, not authorizations.

The construction's §8 ("The structural impossibility") claims OAuth 2.0 requires AS-observed token issuance, which is true. But WIMSE is explicitly designed to break this pattern at the IETF layer, not the ZK layer. A ZK attestor plugged into SPIRE's node attestation pipeline could produce SPIFFE IDs with ZK-backed provenance claims, using the existing SVID delivery path and federation model.

The specific gap: the construction never demonstrates what the ZK layer provides that a WIMSE token exchange + audience-bound JWT SVID does not. WIMSE's sender-constrained tokens already prevent an AS from correlating `(agent, RS, scope)` at issuance because the exchange is service-to-service, not AS-mediated. The privacy property being claimed in §1 is a subset of what WIMSE's architecture aims to provide.

**In-threat-model?** No — this is an architectural objection, not a break of the stated security game. But the construction must justify why it creates a new ZKP circuit stack rather than writing a SPIRE attestor plugin that issues SPIFFE IDs with ZK-backed `sub` claims and contributing the token exchange privacy extensions to WIMSE. The justification in §8 only compares against OAuth 2.0 baselines, not WIMSE.

---

### Attack 4: `requiredScopeMask` as a Capability Fingerprint Across Proofs

**Attack:**
`requiredScopeMask` is a **public input** (§2). It reflects the RS's required permission bits. For a given RS, this value is stable (Target always requires `READ_DATA | FINANCIAL_SMALL` = `0b00000101`). A sophisticated AS with a directory of RS scope profiles can:

1. Build a table: `{ requiredScopeMask_value → {RS candidates} }`.
2. Observe proofs with matching `requiredScopeMask` values — these are visits to the same *class* of RS (e.g., all pharmacies requiring `READ_DATA + ACCESS_PII`).
3. Cross-correlate with timing and `sessionNonce` freshness to narrow the anonymity set.

More critically for the IND-UNL-AS game (§3): the game gives A adaptive oracle access and allows A to observe "all public signals." Two agents with *different* enrolled permission bitmasks may generate proofs satisfying different `requiredScopeMask` values for the same RS. The restriction in §3 Step 4 only prevents querying both agents on the *same scopeId as the challenge scope*. It does not prevent A from querying both agents on *other RSes* with distinctive `requiredScopeMask` values, building a per-agent capability fingerprint, then matching against the challenge proof's `requiredScopeMask`.

**Why the reduction sketch (§4) misses this:** The reduction only argues unlinkability through `scopePseudonym` and `blindedScopeCommitment`. It does not argue that public inputs (`requiredScopeMask`, `currentTimestamp`) are unlinkable. If agents have heterogeneous permission bitmasks — which they will in any real deployment where some agents have `FINANCIAL_MEDIUM` and others have only `READ_DATA` — the `requiredScopeMask` leaks which tier the agent satisfies, reducing the effective anonymity set from 400K to the much smaller set of agents with that exact tier.

**In-threat-model?** Yes, this is within the stated threat model (AS observes all public signals). The construction should either (a) make `requiredScopeMask` private and prove satisfaction without revealing it, or (b) bound the anonymity set analysis by permission tier, not by total agent count. Claiming a 400K anonymity set while leaking a 3-bit tier indicator that partitions the population into ~8 cohorts overstates the privacy guarantee by 3 orders of magnitude.
