# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Adversarial-AS Threat Model Is Not a Buyer's Problem

**Attack:** I pull up the construction's Gap 5 scenario — "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation" — and I ask the CISO: *When did your AS become adversarial?* In every enterprise deployment we run, the AS **is** the trust root by design. Auth0, WorkOS, and Stytch are SOC 2 Type II, ISO 27001, and sit behind your SSO. The buyer selected us *because* they trust us. The construction's strongest differentiator — AS-blind presentation — is solving a problem the buyer actively doesn't want to have. If the AS can't see scope assertions, your audit log is blind. Examiners at NCUA will ask: "Show me every permission granted to every agent last quarter." Gap 6's member audit receipts and `AgentEnrolled` on-chain events don't answer that — they show enrollment, not runtime assertion.

**Why it works:** The construction conflates cryptographic trust minimization with enterprise compliance. Regulated buyers (credit unions, specifically) need the AS in the loop for BSA/AML audit trails, not out of it. The adversarial-AS scenario is a valid cryptographic threat model that has no corresponding line item in a credit union's vendor risk assessment.

**In-threat-model?** No — construction must address: for buyers where AS cooperation is *required* by regulation, what is the residual value of the ZK layer?

---

### Attack 2: One Block Is Slower Than Redis

**Attack:** Gap 4 claims revocation propagates in "one block. Immediate propagation." I ask: which chain, what finality? Ethereum mainnet is ~12 seconds to inclusion, ~3 minutes to finality under current conditions. Our Auth0 token revocation (backchannel logout + token blacklist) propagates in under 200ms via Redis Pub/Sub across all edge nodes globally. The construction's `revokedTags` mapping requires every RS to either (a) call an RPC node on every proof verification, reintroducing the roundtrip the ZK was meant to eliminate, or (b) cache the on-chain state locally, in which case the freshness guarantee degrades to the RS's polling interval. Neither path beats our SLA. For a compromised agent credential — which is the hot revocation path that keeps security teams up at night — "one block" is not a latency you can sell.

**Why it works:** The construction specifies the mechanism (`revokedTags` mapping, Poseidon2 revocation tag, orthogonal to Merkle tree) but gives no latency bound, no RPC dependency analysis, and no freshness guarantee under network partition. Section Gap 4 reads as cryptographically correct but operationally unspecified.

**In-threat-model?** No — construction must address: revocation latency SLA with concrete numbers, RPC dependency model, and behavior under chain congestion or L2 sequencer downtime.

---

### Attack 3: Agent-Local Enforcement Is Not Security

**Attack:** Gap 5 offers three RS compartmentalization enforcement options, the first being "agent-local." I stop the demo there. If the agent enforces its own `relevantBits(RS)` mask, then the agent is both the prover *and* the enforcer of the disclosure bound. That is not a security property — that is policy. WorkOS's MCP auth implementation enforces scope at the AS before token issuance; the RS verifies offline via signed JWT. The trust doesn't depend on the agent being honest about what it discloses. In the Bolyra construction, a compromised agent can select a wider mask than `authorizedMasks[RS_id]` permits and generate a valid proof against the broader bitmask. The circuit (as described) constrains bit-extraction to the presented mask width — but nothing in the construction prevents a malicious agent from presenting a mask wider than its RS authorization. Gap 5 says the mask is "bounded by mask width" but doesn't say *who sets the mask at proof time*.

**Why it works:** The construction conflates "RS learns only the relevant bits" (privacy) with "RS can only receive its authorized bits" (security). These require different enforcement points. The "agent-local" option solves the former, not the latter. The on-chain and hybrid options would solve it, but they're listed as alternatives, not requirements, and add gas cost and latency.

**In-threat-model?** No — construction must specify that agent-local enforcement is privacy-only, and that security-grade RS compartmentalization requires the on-chain or hybrid path, with that path's cost and latency characterized.

---

### Attack 4: The MPC Ceremony Is a Solo-Founder Liability

**Attack:** This is the procurement kill shot. Gap 3 specifies "MPC ceremony (Hermez/Ethereum KZG, 1-of-N honest)" as the SRS trust model. My procurement team asks three questions: (1) Who were the N participants? (2) Who audited the circuit against the ceremony output? (3) If the ceremony is compromised, who is liable? For Hermez, the answers are public, well-documented, and backed by the Polygon Foundation. For a solo-founder ZK construction, the answer to all three is: *the founder*. The construction's STARK fallback "for regulators requiring transparent setup" is an acknowledgment that the KZG path has an unresolved trust dependency. A STARK-based system is a different construction — different proof sizes, different verifier costs, different tooling. Listing it as a fallback doesn't close the gap; it opens a second procurement conversation about which path the buyer is actually getting. Auth0 doesn't ask customers to choose their cryptographic setup ceremony.

**Why it works:** The construction is technically sound in specifying 1-of-N honesty, but it doesn't specify *who performs the ceremony*, *how participants are selected*, *what the audit artifact looks like*, or *what contractual recourse exists* if the ceremony is later found compromised. These are not cryptography questions — they are vendor risk questions, and they block enterprise procurement regardless of the math being correct.

**In-threat-model?** No — construction must address: named ceremony governance (even if deferred), circuit audit provenance, and the contractual / liability model for SRS compromise. The STARK fallback must be a first-class specified path, not an escape hatch.


## Persona: cryptographer

No simulator definition, no game, no reduction. What follows are four structural attacks derived from the construction as described. I will be precise about which component I am targeting.

---

### Attack 1: Cross-RS Bitmask Reconstruction via Mask Union

- **Attack:** The construction bounds per-RS leakage to `relevantBits(RS)` via `authorizedMasks[RS_id]`. However, the threat model is not stated as a game. Define adversary **A** as a set of *k* colluding RSes whose masks partition (or cover) the full bitmask width *n*. A queries the agent once per RS with disjoint mask windows. By the union of the *k* proof transcripts — each revealing a sub-bitmask consistent with the agent's credential commitment `credComm` — A reconstructs the complete bitmask with probability 1. The circuit constraint is `(bitmask & relevantBits(RS)) == claimedBits`, which is *locally* sound but does not prevent global reconstruction across verifiers.

- **Why it works:** The `credComm` appears in the randomized commitment `Poseidon3(bitmask, credComm, sessionNonce)` and is constant for the agent's credential lifetime. A can index transcripts by `credComm` to stitch presentations together. Even with fresh `sessionNonce` per session, the revealed `claimedBits` per RS are *plaintext* — the ZK proof hides nothing beyond the unrevealed bits, and colluding RSes see all bits collectively.

- **In-threat-model?** **No.** The construction defines RS compartmentalization as a single-RS bound ("max per-RS leakage bounded by mask width"). It does not define a multi-RS collusion game, does not require RSes to be mutually distrusting, and provides no cryptographic mechanism (e.g., re-randomized masked proofs, per-RS blinding factors) to prevent cross-RS aggregation. **The construction must state whether colluding RSes are in-model and, if not, add a formal composition theorem or restructure the disclosure to be blinded per-RS.**

---

### Attack 2: Revocation Authority Paradox — nullifierSecret Custody Contradiction

- **Attack:** The revocation tag is defined as `revocationTag = Poseidon2(nullifierSecret, REVOCATION_DOMAIN)`. The revocation mechanism requires that this tag appear in `revokedTags` on-chain to invalidate the credential. For revocation to be *operator-initiated* (the operationally necessary case — an agent goes rogue, a key is compromised), the operator must either (a) know `nullifierSecret` to compute the tag, or (b) rely on the agent to compute and submit the tag cooperatively. Both branches are fatal:

  - Branch (a): operator knows `nullifierSecret` → contradicts Section 2 ("nullifierSecret is generated by the agent and never disclosed to the operator"). The enrollment protocol must have a secret transmission step that the construction omits.
  - Branch (b): agent computes revocation tag cooperatively → a compromised or adversarial agent simply refuses. Revocation is not live without agent cooperation, destroying the security guarantee.

  A third path — deriving `revocationTag` from data the operator *does* know — requires `nullifierSecret` to be operator-known at some point (e.g., during enrollment), which collapses back to branch (a) and makes the nullifier scheme equivalent to the known-pitfall case: AS can precompute `Poseidon2(nullifierSecret, sessionNonce)` for all future session nonces.

- **Why it works:** The construction explicitly uses `nullifierSecret` as the revocation key *and* claims it is agent-only. These two properties are mutually exclusive unless there is a threshold custody scheme, a commitment-based revelation protocol, or a separate revocation credential — none of which are specified.

- **In-threat-model?** **No.** The construction asserts "immediate propagation (one block)" but does not provide a protocol for *how* the revocation tag reaches the chain without operator access to the secret. This is an incomplete specification, not a minor gap. **The construction must define the revocation key custody model and prove liveness under an adversarial agent.**

---

### Attack 3: Delegation Chain Linkability via Deterministic Commitment Reuse

- **Attack:** For delegation, the construction uses `Poseidon2(bitmask, credComm)` — a *deterministic* function of the agent's credential. Every delegation proof emitted by the same agent, for the same bitmask, produces an identical commitment value. An adversary — including the AS that sees delegation initiation events — can index all delegation transcripts by this value and build a cross-session activity graph for the agent. Session unlinkability (provided by `sessionNonce` in the randomized commitment) is entirely bypassed for any session in which delegation occurs.

- **Why it works:** The construction explicitly states the deterministic commitment is "used only when delegation is initiated." This is presented as a feature (enabling chain-linking), but it is simultaneously a covert linkability channel. The AS does not need to break the ZK proof; it observes the deterministic commitment in cleartext as part of the delegation protocol. Formally: for any two delegation sessions *i* and *j* from the same agent with the same bitmask, `C_i = C_j = Poseidon2(bitmask, credComm)`. A passive AS achieves session linkage with advantage 1.

- **In-threat-model?** **No, if unlinkability against a passive AS is claimed for all sessions.** The construction claims "per-session unlinkability" via the randomized commitment, but delegates this guarantee away for the delegation case without a formal reduction that bounds the information leaked. A UC-style treatment would require the delegation functionality to simulate unlinkable transcripts; the deterministic commitment makes this impossible without a refresh mechanism. **The construction must either exclude delegation sessions from the unlinkability claim (and state this explicitly) or replace the deterministic commitment with a linkable ring signature or re-randomizable accumulator.**

---

### Attack 4: Bitmask Inflation via Adversarial Enrollment — Missing Authoritative Binding

- **Attack:** The enrollment leaf is `Poseidon2(credentialCommitment, Poseidon1(nullifierSecret))`. The circuit verifies that the agent knows a valid Merkle witness for this leaf and that `bitmask & relevantBits(RS) == claimedBits`. Critically, **there is no circuit constraint that binds `bitmask` to an authoritative permission registry**. The operator enrolls the agent with an arbitrary bitmask; "member audit receipts" and "optional dual-operator co-signing" are off-chain social controls. An adversarial or compromised operator can enroll an agent with `bitmask = ~0` (all bits set), and the agent can then construct valid proofs for any permission predicate. The ZK proof is sound relative to the Merkle tree, but the Merkle tree root itself carries no binding to a ground-truth permission authority.

- **Why it works:** Soundness in Groth16 (or PLONK) means: given a valid proof, the prover knows a witness satisfying the circuit. The circuit does not express "bitmask was issued by a trusted authority with the correct permission value." It only expresses "I know a bitmask such that the Merkle path is valid and the predicate holds." If the Merkle tree is operator-controlled, operator corruption collapses all permission guarantees. The construction's "adversarial-AS model where AS cannot lie about scope membership" is listed as a *gap to close* in the candidate spec — the construction does not close it.

- **In-threat-model?** **No.** The claim explicitly includes the scenario "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." But the Merkle root is operator-controlled. Cryptographic assurance independent of AS cooperation requires either (a) a verifiable credential from an authority the AS cannot forge (e.g., a hardware-rooted attestation), or (b) a dual-control enrollment with a second independent party who co-signs the bitmask value. "Optional dual-operator co-signing" is not a cryptographic binding — it is a process control. **The construction must define an enrollment game, specify which party is trusted to set bitmask values, and provide a reduction showing that bitmask inflation requires breaking a defined hardness assumption.**


## Persona: cu_ciso

### Attack 1: Revocation Latency vs. Incident Response SLA

- **Attack:** Section 4 claims revocation propagates in "one block" via on-chain `revokedTags`. The CISO pulls up NCUA Part 748 Appendix B (§III.C, incident response) and asks: what is the contractual SLA for block finality under network congestion, a reorg, or an L1 halt? The core processor contract says 99.95% uptime with 15-minute RTO. "One block" on Ethereum mainnet averages ~12 seconds under normal conditions but has no guaranteed upper bound. During a credential compromise incident, the NCUA examiner will ask for a timestamped audit trail showing when revocation was effective — not when it was submitted to mempool.
- **Why it works / fails:** The construction specifies the mechanism but not the SLA envelope or the incident-response runbook. It does not address: (a) what happens if the on-chain call is stuck in mempool during high gas, (b) who is the on-call operator with signing authority at 2am, (c) how the examiner gets a human-readable incident report that maps to Part 748 §III.C timelines.
- **In-threat-model?** No — construction must address. Add a maximum revocation latency bound (e.g., "revocation effective within N blocks under X gas price; emergency operator key held in HSM with documented custodian"). Map to NCUA Part 748 §III.C and provide an incident-response runbook template.

---

### Attack 2: Examiner Audit Trail Legibility (GLBA + SOC 2 Gap)

- **Attack:** Section 6 says "member audit receipts, optional dual-operator co-signing, on-chain `AgentEnrolled` events for examiner replay." The CISO hands this to the NCUA field examiner, who pulls up the FFIEC CAT Domain 3 (Cybersecurity Controls) and asks: show me the audit log for member enrollment. The examiner gets an Ethereum transaction hash and a Poseidon hash preimage. The GLBA Safeguards Rule (16 CFR §314.4(h)) requires "monitor and test" controls with documented evidence. SOC 2 CC7.2 requires audit logs in human-readable form retained per policy. Neither control is satisfied by a cryptographic event on a public chain that requires a ZK verifier to interpret.
- **Why it works / fails:** The construction solves the *cryptographic* audit problem but not the *regulatory* audit problem. An examiner cannot independently verify a Poseidon hash or replay a Groth16 proof without tooling that does not exist in any NCUA-standard examination toolkit.
- **In-threat-model?** No — construction must address. Specify a human-readable audit export format (JSON with plain-English field descriptions), a SOC 2 Type II control mapping table, and a designated "examiner replay tool" that translates on-chain events into NCUA-legible incident timelines.

---

### Attack 3: nullifierSecret Key Custody and Member Key Loss

- **Attack:** Section 2 states `nullifierSecret` is "generated by the agent and never disclosed to the operator." The CISO asks: where does this secret live at rest? If it lives in the browser (localStorage, IndexedDB), it violates NCUA Part 748 Appendix A guidance on multi-factor authentication and GLBA §314.4(c)(2) on access controls — browser storage is not a hardened credential store. If it lives in an HSM, who manages the HSM, under what FIPS 140-2/3 level, and what is the key recovery procedure when a member loses their device? The construction's enrollment leaf `Poseidon2(credentialCommitment, Poseidon1(nullifierSecret))` binds the secret permanently — there is no recovery path described.
- **Why it works / fails:** The construction deliberately keeps `nullifierSecret` agent-side to prevent operator compromise, but this creates an unaddressed operational failure mode: member key loss = permanent identity loss. For a credit union, this means a member cannot access their account after a device wipe. The NCUA examiner will ask for the member dispute resolution procedure under Regulation E and state consumer protection law.
- **In-threat-model?** No — construction must address. Define the key custody model explicitly (browser vs. HSM vs. cloud KMS), specify the recovery ceremony (e.g., social recovery via operator co-signing with identity re-verification), and map to FIPS 140-2 Level 2+ requirements for credential storage.

---

### Attack 4: SRS/MPC Ceremony as Unexamined Third-Party Vendor

- **Attack:** Section 3 delegates SRS trust to "Hermez/Ethereum KZG MPC ceremony, 1-of-N honest." The CISO opens the Vendor Management Policy and NCUA Letter 07-CU-13 on third-party relationships. Questions: (1) Is the MPC ceremony a "critical third-party service provider" under NCUA definitions? (2) Who are the N ceremony participants — are any NCUA-supervised entities? (3) If the KZG parameters are later found compromised (as happened with early Zcash ceremonies), what is the remediation path? The construction mentions a "STARK fallback path for regulators requiring transparent setup" but does not operationalize it — there is no migration procedure, no client notification plan, and no timeline. The CISO cannot sign a vendor contract with a hash of a 2019 Ethereum ceremony.
- **Why it works / fails:** The construction correctly identifies the trust assumption (A7, 1-of-N honest) but does not translate it into a vendor risk artifact. The NCUA examiner performing a third-party risk review will ask for: vendor due diligence documentation, a right-to-audit clause, an exit strategy, and evidence of ongoing monitoring. None of these exist for a decentralized MPC ceremony.
- **In-threat-model?** No — construction must address. Either (a) publish a formal "SRS Trust Artifact" document that can be attached to a vendor management file, describing the ceremony participants, the transcript hash, the verification procedure, and the STARK fallback migration path with a concrete timeline; or (b) default to the transparent STARK setup as the primary path for regulated deployments and treat KZG as an optional performance optimization with explicit operator opt-in.


## Persona: rfc7662_advocate

I've been shipping OAuth introspection endpoints since before most of these ZK library authors had GitHub accounts. Let me show you what this construction actually claims versus what the RFC stack already handles.

---

### Attack 1: JWT Introspection with Per-RS Policy Already Achieves Selective Disclosure

- **Attack:** The AS implements an `allowed_scopes[RS_id]` policy table. At introspection time, it returns a signed JWT (per `draft-ietf-oauth-jwt-introspection-response`) containing only the intersection of the token's full scope set and what that RS is permitted to see. The RS verifies the JWT offline — no AS hot-path on subsequent requests. This is structurally identical to the construction's `authorizedMasks[RS_id]` formalized in Section 5. The RS sees only relevant bits; it never touches the full bitmask. Where is the gap?

- **Why it works / why it fails:** It *almost* works. The RFC 7662 baseline achieves per-RS scope filtering. The construction's surviving advantage is **AS-blind presentation**: the agent presents to an RS without the AS ever learning *which* RS is being visited at presentation time. With JWT introspection, the AS sees every introspection request — it learns the RS's identity at each call. Even with cached signed JWTs (issued at token-issuance time via RFC 8707), the AS knows the RS at issuance. The construction's `Poseidon3(bitmask, credComm, sessionNonce)` commitment allows the agent to derive a fresh per-RS proof from a single credential with zero AS involvement. **The baseline cannot replicate AS-blind presentation from a single credential.**

- **In-threat-model?** Yes — construction survives, but it must make this property *explicit* as the load-bearing claim. Section 5 currently frames this as a compartmentalization feature; it should be elevated to the primary differentiator or the attack surface is invisible to reviewers.

---

### Attack 2: PPIDs + Audience Binding Already Break Cross-RS Linkability at the RS Level

- **Attack:** OIDC Pairwise Pseudonymous Identifiers give each RS a distinct `sub` claim — RS_A and RS_B cannot correlate by subject. RFC 8707 Resource Indicators issue audience-bound tokens, so RS_A's token is cryptographically invalid at RS_B. The construction's unlinkability argument (Section 1, randomized `scopeCommitment`) claims to prevent cross-RS linkability. The baseline already does this without ZK.

- **Why it works / why it fails:** Partial match only. PPIDs + audience binding prevent *subject* correlation across RSes. They do *not* prevent temporal/behavioral correlation if the same token or credential handle appears in multiple RS audit logs. The construction's `sessionNonce` randomizes `scopeCommitment` per session, producing a fresh unlinkable proof each time from the same underlying credential. The RFC baseline has no equivalent: a DPoP-bound token still carries a stable `jti` and `iat` that RSes could use to correlate sessions if they collude or are breached. The construction is strictly stronger here — but only for the collusion/breach threat model.

- **In-threat-model?** Yes — construction survives for the collusion model. However, the construction does **not** address timing correlation (proof generation latency is distinctive) or proof-size fingerprinting. These side-channels exist independently of what's inside the proof.

---

### Attack 3: Adversarial AS Can Corrupt the Enrollment Bitmask Before On-Chain Commitment

- **Attack:** Scenario 2 claims "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." The construction's Section 6 moves bitmask correctness on-chain via `AgentEnrolled` events and optional dual-operator co-signing. But who *sets* the initial bitmask bits at enrollment? If the operator (acting as or colluding with the AS) constructs the bitmask, an adversarial operator can set `bit[i] = 1` for permissions the agent never earned, then commit that lie to the chain. The `AgentEnrolled` event faithfully records the lie. RFC 7662 has exactly the same problem — an adversarial AS returns false scopes — so the construction provides no advantage in the adversarial-AS enrollment model.

- **Why it works / why it fails:** This is a **genuine gap**. The construction resolves post-enrollment correctness (Section 6: audit receipts, dual co-signing) but leaves enrollment-time bitmask integrity underspecified. "Member audit receipts" and "optional dual-operator co-signing" are procedural, not cryptographic. A compromised operator that co-signs a false bitmask nullifies both controls simultaneously. The STARK fallback (Section 3) is transparent-setup but doesn't constrain *who* writes the witness. The construction must specify either (a) a threshold-signed enrollment from *k* independent verifiers, or (b) a separate ZK proof that the bitmask was derived correctly from a signed membership record (e.g., an existing KYC credential). Without this, Scenario 2's claim of AS-independence holds only after enrollment, not during it.

- **In-threat-model?** No — **construction must address this.** The adversarial-AS scenario (Scenario 2) currently has no cryptographic defense at enrollment time. The baseline and the construction are equivalent under this attack.

---

### Attack 4: DPoP Already Prevents Operator Replay — Nullifier Secret Provides No Surplus

- **Attack:** RFC 9449 DPoP binds a token to an ephemeral client keypair via a proof-of-possession header. The operator who issued the DPoP key cannot reuse the token without the corresponding private key. The construction's Section 2 (private `nullifierSecret`) claims to prevent operator-side replay by deriving the nullifier from a secret the operator never sees. Name the concrete attack DPoP cannot prevent that the private nullifier resolves.

- **Why it works / why it fails:** DPoP prevents *token theft* replay — it assumes the client holds its own DPoP key. In an agentic deployment, the *operator* provisions the agent runtime and may hold or export the DPoP private key, giving it full replay capability. The construction's `nullifierSecret` is generated inside the agent (per Section 2: "never disclosed to the operator") and the enrollment leaf commits to `Poseidon1(nullifierSecret)` — the operator cannot derive it even with full access to the enrollment record. This is the correct threat model for operator-as-adversary (not user-as-adversary), which DPoP was never designed for. **Construction survives**, but it must explicitly name "operator-as-adversary" as the threat model. Currently Section 2 presents this as a privacy feature; it is more precisely a trust-boundary enforcement mechanism.

- **In-threat-model?** Yes — construction survives. The claim is valid but the framing in Section 2 undersells the threat model. Reviewers steeped in DPoP will dismiss the nullifier as redundant unless the operator threat model is foregrounded.


## Persona: spiffe_engineer

---

### Attack 1: SD-JWT + JWT-SVID Already Buys You AS-Blind Selective Disclosure

- **Attack:** The construction's headline property — "AS-blind presentation, agent chooses what to disclose at the moment of use" — is already achievable by composing SPIFFE JWT-SVIDs with SD-JWT (RFC 9278 / draft-ietf-oauth-selective-disclosure-jwt). The SPIRE Workload API issues credentials *locally* to workloads via a Unix-domain socket with no AS roundtrip at presentation time. The agent receives a JWT-SVID with hashed disclosure frames for each permission group; it selects which frames to open at call time. The RS verifies against the SPIFFE trust bundle (no AS call). Section 5 of your construction ("RS compartmentalization via `authorizedMasks[RS_id]`") maps exactly onto SD-JWT's per-RS selective disclosure model — but SD-JWT uses SHA-256 salted hashes, not a Poseidon circuit, and is already shipping in production identity stacks. Name a property your construction provides that SD-JWT over JWT-SVID does not.

- **Why it works / why it fails:** It works because the construction never explicitly argues why hash-based selective disclosure (SD-JWT) is insufficient and ZK proofs are *necessary*. The gap-to-close text in the candidate (§ "AS-blind presentation") is the closest it gets, but it doesn't rule out SD-JWT. It would fail if the construction can show a predicate class — e.g., "prove membership in a boolean expression over the bitmask without revealing *which* bits are set, even under a chosen-disclosure attack" — that SD-JWT cannot express. SD-JWT discloses full claim values; it cannot prove a threshold or boolean function over hidden claims without revealing them. If the construction formalizes that predicate class, this attack is blunted.

- **In-threat-model?** No — construction must address. Section 1 (claim) and the gap-to-close text must explicitly rule out SD-JWT + JWT-SVID as a composition, or the novelty claim collapses.

---

### Attack 2: The 2^64 Bitmask Scenario Defeats the Construction, Not the Alternative

- **Attack:** The construction cites a "regulated agent with 2^64 permission space where AS-side policy tables do not scale" as a motivating scenario. But the construction commits to the full bitmask: `Poseidon3(bitmask, credComm, sessionNonce)`. A 2^64-bit bitmask is 8 exabytes of witness material. The Poseidon hash is constant-size; the *witness* the prover must hold and process in the circuit is not. Circom/snarkjs circuits must enumerate all constrained bits. At 2^64 permissions, this is not a circuit — it is a fantasy. SPIFFE + ABAC (OPA policy bundles evaluated at the SPIRE server, Cedar for structured authorization) handles sparse permission spaces with O(1) policy tokens and no monolithic bitmask: the workload presents a JWT-SVID, the policy engine evaluates the predicate server-side, returns a scoped authorization token. Section 6 (enrollment bitmask correctness) doubles down on the bitmask as the source of truth. The construction's scalability argument attacks the AS-side table but ignores that its own witness is the same table encoded differently.

- **Why it works / why it fails:** It works unless the construction bounds bitmask width in a concrete, realistic deployment scenario (e.g., "at most 2^20 permissions, covering all known regulatory permission classes for stablecoin agents") and explains why that width is manageable in a Circom circuit. The 2^64 figure appears to be rhetorical cover for the ZK construction's existence, not an actual deployment target.

- **In-threat-model?** No — construction must address. It should either (a) drop the 2^64 scenario and cite a realistic bitmask width with circuit benchmarks, or (b) describe a sparse-witness encoding (e.g., Merkle set membership over a permission identifier universe) that avoids enumerating all bits.

---

### Attack 3: Your Revocation Is Strictly Worse Than Short-Lived SVIDs

- **Attack:** The construction's revocation mechanism (§4: on-chain `revokedTags` mapping, `Poseidon2(nullifierSecret, REVOCATION_DOMAIN)`, "immediate propagation — one block") introduces a blockchain dependency with ~12-second Ethereum block latency (or equivalent L2 latency), a new trusted component (the chain), and an always-on connectivity requirement. SPIRE's answer to revocation is TTL: issue SVIDs with a 1-hour (or shorter) TTL, push renewals via gRPC streaming on the Workload API. There is no revocation infrastructure to build, no on-chain state to query, and no block-confirmation latency. A revoked workload stops receiving renewals; existing credentials expire. For the adversarial-AS scenario the construction targets, the on-chain revocation is still AS-influenced: if the AS controls enrollment (which issues the bitmask and `nullifierSecret`), it also controls whether a revocation tag is posted. You have not moved trust — you have relocated it to a new component with worse latency properties.

- **Why it works / why it fails:** It works unless the construction can show a revocation scenario where short-lived SVIDs fail — specifically, where the revocation window (TTL) is unacceptably long and the chain-latency window is acceptable. For regulated agents, that window comparison is a legitimate argument. It fails if the construction specifies: "TTL-based revocation provides at-most-X-minute exposure; on-chain revocation provides at-most-one-block (~12s) exposure; for regulated agents under SAR/AML obligations, 12s > X-min is a requirement." That would be a concrete, checkable claim.

- **In-threat-model?** Partial — construction survives the AS-trust framing but must justify why on-chain latency beats TTL-based expiry for the specific regulated-agent deployment scenario, and must address the new trust assumption introduced by chain dependency.

---

### Attack 4: WIMSE W2W Token Chaining Covers Your Agent-Delegation Scenario

- **Attack:** The construction's delegation chain (implied by the deterministic `Poseidon2(bitmask, credComm)` used "only when delegation is initiated," §1) targets the agent-to-subagent identity propagation scenario. WIMSE `draft-ietf-wimse-w2w-authn` (workload-to-workload authentication) defines a token chaining model where a workload presents its WIMSE identity token and requests a derived token scoped to a downstream service, with cryptographic binding between hops. This is exactly the delegation scenario. WIMSE is an active IETF WG with multiple implementations (SPIFFE-native, mTLS-native). Contributing a ZK attestor plugin to SPIRE (the SPIFFE reference implementation) — one that generates a ZK proof of scope predicate as part of the SVID issuance extension points — would integrate this construction into a deployed stack rather than requiring operators to adopt a new protocol, new on-chain infrastructure, and a new trust model simultaneously. The construction does not cite WIMSE at all.

- **Why it works / why it fails:** It works as a deployment-cost argument: operators running SPIFFE + WIMSE do not need to adopt a new protocol. It partially fails as a cryptographic argument — WIMSE does not currently specify ZK-based predicate proofs and the WG scope may not accommodate them. If the construction argued that the ZK predicate is the atomic contribution and positioned the rest of the system as a SPIFFE/WIMSE extension rather than a competing protocol, the attack loses most of its force. As written, the construction presents itself as a standalone protocol, making it a harder sell to operators who already run SPIRE.

- **In-threat-model?** No — construction must address. At minimum, add a "Relation to SPIFFE/WIMSE" section that either (a) positions this as a SPIRE attestor plugin + WIMSE extension, or (b) explicitly names the gap in WIMSE that forecloses that path. Failure to do so leaves the largest practical objection unanswered.
