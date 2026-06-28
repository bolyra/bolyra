# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The On-Chain Root Is Just Another Authorization Server With Extra Steps

**Attack:** The construction's core "adversarial-AS-resilient" claim rests on the agent Merkle root being maintained by a smart contract with its own access control (§2, Merkle membership gadget; §3, threat model). But the threat model never names who controls enrollment into that tree. Someone calls `enrollAgent(credentialCommitment)` on-chain. That entity is the new AS. A compromised smart contract owner can enroll a fraudulent `credentialCommitment` for any `permissionBitmask` they choose — they just need to produce a matching EdDSA signature, which they can do if they also control the operator key issuance flow.

In the NFCU deployment scenario (§7), NFCU controls both the smart contract and the operator key signing. That makes NFCU the AS. The construction has not eliminated AS trust — it has replaced a hosted identity provider with a smart contract wallet, shifted liability to the enterprise, and added gas costs and block finality delays to every enrollment.

**Why it works:** The security argument (§4, SSS reduction, step 3-4) assumes the Merkle tree "reflects ground truth via smart contract access control" but treats that as a given, not a modeled assumption. The game definition gives the adversary a corrupt AS but not a corrupt smart contract operator. These are the same entity in most real deployments.

**In-threat-model?** No — the construction must explicitly model the smart contract operator as a potential adversary and define the access control policy on `enrollAgent`. Otherwise the "adversarial-AS-resilient" claim is a rebranding, not a property.

---

### Attack 2: No Real-Time Revocation — Financial Operations Require It

**Attack:** The construction's verification path (§2, verification step 1) checks that `agentMerkleRoot` appears in a 30-entry circular root history buffer. The agent's credential commitment is a leaf that persists until the tree is rebuilt or a separate revocation path is invoked — neither of which is described. When NFCU's CISO discovers a compromised agent at 2:47 AM, they can call the AS revoke endpoint and the agent's token is dead within seconds. With this construction, the agent holds a locally-cached Merkle witness and EdDSA signature. It can continue generating valid proofs against any of the 30 buffered roots until the entire tree rotates past that leaf — a window that depends entirely on how fast new enrollments push the buffer, which could be hours or days.

Auth0's real-time token revocation is synchronous. This construction has no revocation primitive at all.

**Why it works:** The expiry check (§2, gadget 7) only handles time-based expiry. There is no nullifier, no revocation list, and no on-chain tombstone for compromised credentials. The threat model (§3) models a compromised AS but not a compromised agent key — which is the realistic revocation trigger. The NFCU scenario (§7) specifically mentions "account closure" as a permission bit but gives no mechanism to revoke a credential between issuance and natural expiry.

**In-threat-model?** No — the construction claims adversarial-AS resilience but introduces a new unaddressed risk: time-to-revoke for a compromised operator key. This must be specified (e.g., a revocation nullifier registry, a credentialCommitment tombstone list on-chain, or a maximum credential TTL that bounds the window).

---

### Attack 3: The Latency Claim Collapses in Real Deployment Infrastructure

**Attack:** The construction claims "Groth16 (rapidsnark, native): ~0.8–1.5 seconds" (§6). The NFCU deployment scenario has agents performing financial operations against a bill-payment RS. In practice NFCU's agents run in managed cloud environments — AWS Lambda, GCP Cloud Run, Azure Container Apps. These environments do not support arbitrary native binaries without custom container layers and cold-start penalties. The rapidsnark prover is a native C++ binary that requires a container build, CPU allocation tuning, and warm instances to hit sub-2s. Lambda's default 128MB memory limit makes this unreachable. snarkjs at 8–12 seconds is the realistic fallback, and that is per API call — not per session.

WorkOS issues a token in <100ms. A financial agent making 50 API calls per workflow adds 400–600 seconds of proof generation time with snarkjs, or 40–75 seconds with a correctly-provisioned rapidsnark container. Neither is acceptable for interactive financial operations.

**Why it works:** §6 presents proving times as a single benchmark without specifying the hardware target or acknowledging infrastructure constraints. The construction notes "PLONK (snarkjs): ~3–4 seconds" as the fallback — but snarkjs PLONK at 3-4s is still 30-40× slower than JWT verification, and requires a Node runtime in every agent execution environment. The presentation-per-call model is what kills this: JWT bearer tokens are cached and reused across multiple RS calls within a session. The construction's `blindingNonce` freshness requirement (§2, presentation tag) means you cannot cache and reuse proofs — every RS contact requires a new proof.

**In-threat-model?** No (this is a product gap, not a security gap) — but it is the purchase blocker for the NFCU scenario. The construction should specify a session-scoped proof model: generate one proof per session (caching `credentialCommitment` and the Merkle witness), derive per-RS presentation tags from a session key, and update the threat model to bound the session window. This would reduce proof generation to once per auth flow, not once per API call.

---

### Attack 4: The Comparison Table Strawmans BBS+; Bulletproofs Already Solve the Predicate

**Attack:** Section 8's comparison table claims BBS+ "cannot evaluate bitwise AND with cumulative-bit implication closure over a bitmask" and that this requires circuit-level evaluation. This is accurate for vanilla BBS+ selective disclosure — but the baseline the construction is competing against is not vanilla BBS+. Credential issuers pairing BBS+ with Bulletproofs (or Sigma protocol range proofs) can have the holder prove arithmetic relations over hidden attributes without revealing them. Specifically: issue a BBS+ credential with a single hidden attribute `permissionBitmask` (a 64-bit integer), and use a Bulletproof range proof or an arithmetic circuit commitment to prove `permissionBitmask & requiredMask == requiredMask` over the hidden attribute.

This is not hypothetical — the W3C VC Data Integrity spec (BBS cryptosuite) is actively being extended with predicate proofs. The Internet Identity Foundation's work on ZKP-based VCs (AnonCreds v2, SD-JWT + ZKP) goes in this direction. The claim in §8 that "there is no BBS+ gadget for bitwise AND" is true today but is a race against an open standards body with Auth0/Okta/Microsoft engineering resources, not a fundamental impossibility.

**Why it works:** The construction's differentiation claim in §1 and §8 is predicated on BBS+ being structurally incapable. A PM at Auth0 would immediately identify this as a time-bounded moat: "We'll ship this in the VC extension track in 18 months with W3C backing, no solo founder required." The construction must either (a) demonstrate a formal impossibility result showing that BBS+ + Bulletproofs cannot achieve the cumulative-bit implication constraint without revealing bits, or (b) reframe the differentiator around the AS-blind / on-chain enrollment model (a deployment model difference, not a cryptography difference), or (c) acknowledge this as a time-bounded window and make the case for why Bolyra's deployment track is faster than the W3C standards track.

**In-threat-model?** No — the construction survives on cryptographic soundness grounds, but the differentiation claim in §8 overstates the structural gap. It should be narrowed to: "BBS+ + predicate proofs require a separate proof system alongside BBS+, adding complexity and a second trusted setup; Bolyra integrates the predicate natively into the credential circuit with a single verifier." That's a weaker but defensible claim.


## Persona: cryptographer

Applied cryptographer. Publications in CRYPTO/EUROCRYPT/S&P. My stance: a proof sketch is not a proof, and a threat model that excludes its own trust anchors is not a threat model.

---

### Attack 1: Trusted Setup Subversion Collapses the Adversarial-AS Claim

- **Attack:** The adversary compromises the Groth16 per-circuit trusted setup for `SelectiveScopeProof`. With access to the toxic waste `τ` (the trapdoor from the ceremony), the adversary constructs a simulated proof `π*` for any public signal tuple `(agentMerkleRoot, presentationTag, requiredScopeMask, currentTimestamp, resourceIdentifier)` without possessing a valid witness — no EdDSA key, no Merkle path, no permission bitmask satisfying the predicate. The Groth16 verifier accepts `π*` because the simulation trapdoor satisfies the bilinear pairing equation by construction.

- **Why it matters:** §3 (Threat Model) lists the adversary capabilities as controlling the AS, the network, and colluding RSes. It explicitly excludes "the BN128 pairing or Baby Jubjub discrete log problems." But it says nothing about the party who ran `Setup(1^λ)`. The Game SSS preamble states "Challenger runs Setup" — i.e., the game assumes an honest setup. In the NFCU deployment scenario in §7, *who* runs the `SelectiveScopeProof` trusted setup? If it is Bolyra (single-party), then Bolyra holds `τ` and is fully in the trust path. The claim "a compromised AS cannot forge a valid proof because it lacks the agent's EdDSA private key" is technically true under the AS threat, but a party with `τ` forges proofs without needing any key at all. The structural separation from the AS is cosmetic if you simply relocate trust to a less-scrutinized ceremony.

- **Formal gap:** The reduction sketch in §4 invokes Groth16 knowledge soundness but knowledge soundness holds only when the setup is honestly generated. Under a subverted CRS, the knowledge extractor cannot be instantiated because the simulated extractor is parametrized by `τ`, which the adversary holds. The Game SSS reduction breaks at step 1.

- **In-threat-model?** **No.** The construction must add a fifth property to the table in §8: *Setup trust*. Either (a) commit to a multi-party ceremony with public transcripts (Zcash Sapling-style), (b) consider PLONK with a universal SRS (already mentioned as optional), noting that PLONK's trusted setup is universal but still requires a ceremony for the structured reference string, or (c) explicitly bound the claim: "adversarial-AS-resilient *conditional on an honest Groth16 trusted setup*."

---

### Attack 2: Presentation Unlinkability Game Is Stated for an Adversary Weaker Than Deployment Requires

- **Attack:** The PU game in §3 is an HVZK (honest-verifier zero-knowledge) indistinguishability game: A is given two finished transcripts and must distinguish them. But the construction is used in concurrent, multi-session settings where A controls `n-1` RSes *actively* — they can supply chosen `requiredScopeMask` and `resourceIdentifier` values, observe multiple presentations, and potentially interleave sessions. Groth16 is **not simulation-extractable (SE)** in the standard model. Specifically, Groth16 HVZK does not imply zero-knowledge under a *malicious verifier* who chooses public inputs adversarially across concurrent sessions.

- **Concrete distinguishing strategy:** A colluding RS_1 sends `requiredScopeMask_1 = 0xFF` (all bits required). Only a narrow set of agents can satisfy this. An agent that successfully presents to RS_1 is thereby identified as holding full permissions. RS_1 then shares this information with RS_2. RS_2 now has a refined candidate set. Even with fresh `blindingNonce`, the *fact of successful proof verification* leaks which predicate the agent satisfied, and under the PU game's formulation this side-channel is not modeled. The PU game assumes A sees transcripts for a *fixed* `requiredScopeMask` — it does not model adaptive chosen-mask attacks across colluding RSes.

- **Second linkage vector:** `agentMerkleRoot` is a public output in every proof (§2, Verification). The 30-entry root history buffer is finite and epoch-indexed. A proof generated during epoch `k` carries a root `R_k`. If two presentations carry the same `R_k`, both were generated within the same Merkle epoch — a temporal correlation. For a small deployment (e.g., NFCU's first 1,000 agent enrollments), each epoch covers a bounded time interval, and a colluding pair of RSes can reconstruct "this agent enrolled before time T." This is not prevented by the fresh `blindingNonce`.

- **In-threat-model?** **No.** The PU game must be upgraded to a *chosen-mask adaptive distinguishability* game, and the proof must invoke UC-ZK or SE-NIZK rather than HVZK. The current reduction sketch ("by the zero-knowledge property of Groth16") invokes only HVZK, which is insufficient for the active adversary described in the same threat model.

---

### Attack 3: Nullifier-Free Design Creates Epoch-Bounded Replay and Revocation Void

- **Attack:** The construction explicitly strips the session-nonce nullifier from `AgentPolicy` (§2, Circuit description: "stripped of the session-nonce nullifier"). Consequently, there is no on-chain or RS-local mechanism to detect that the *same credential commitment* was used to generate two presentations to the same RS within the same time window. Furthermore, the on-chain Merkle tree is described as an *incremental* (append-only) structure. Credential leaves cannot be removed. Revocation of an operator key or a compromised credential has no in-circuit representation.

- **Two sub-attacks:**

  1. **Time-window replay.** `currentTimestamp` is a public input. The RS verifies `currentTimestamp` is "within an acceptable window" (§2, check 4) — but this window is unspecified. A captured proof `π` with `presentationTag = T` is replayed to the same RS at any time within the validity window. The RS has no obligation to cache seen tags (the spec does not require this), and with fresh-nonce semantics each "presentation" looks new. The RS cannot detect that `π` was originally generated by the agent 4 minutes ago and is being submitted by an interceptor now.

  2. **Revocation void.** If the operator's EdDSA private key is compromised, the attacker generates fresh proofs with the stolen key (satisfying the EdDSA constraint in gadget 3). There is no on-chain revocation list. The Merkle tree cannot remove the compromised leaf. The 30-entry root history buffer means the compromised credential's Merkle witnesses remain valid for 30 full Merkle epochs after the compromise is detected. The adversary model in §3 does not state what `n` epochs correspond to in wall-clock time, nor does it commit to a maximum epoch duration.

- **In-threat-model?** **Partially.** Replay within a time window is outside the threat model as stated (§3 does not list "man-in-the-middle proof capture" as an adversary capability). Key revocation void is entirely unaddressed. The construction must either (a) specify a mandatory RS-side nullifier cache for `presentationTag` values within the validity window, (b) define an on-chain revocation list and add a non-membership proof gadget (adding ~10,000 constraints), or (c) explicitly document the revocation model and its epoch-duration bound.

---

### Attack 4: `presentationTag` Binding Is Semantically Weak — `credentialCommitment` Is Derivable From On-Chain State

- **Attack:** The presentation tag is `Poseidon3(credentialCommitment, resourceIdentifier, blindingNonce)`. The construction claims that the `blindingNonce` makes this unlinkable. However, `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiryTimestamp)` is a leaf in the on-chain incremental Merkle tree. In a publicly readable smart contract, **all enrolled leaf values are observable on-chain** (they are emitted during enrollment transactions). An adversary who knows the full set of enrolled `{cc_1, ..., cc_n}` from chain state can build a precomputation table: for each `cc_i` and each known RS `rsId_j`, compute `Poseidon3(cc_i, rsId_j, *)` for all feasible nonce values.

- **Feasibility:** If `blindingNonce` is 128 bits (strong RNG), this is infeasible: 2^128 evaluations per `(cc, rsId)` pair. But the spec does not specify the required entropy for `blindingNonce`. It says only "fresh random value for presentation unlinkability." If an implementation uses a 32-bit counter, a 64-bit timestamp, or a deterministic derivation from an unseeded source, the adversary precomputes `Poseidon3(cc_i, rsId_j, nonce)` for nonce ∈ [0, 2^32) — roughly 4 billion Poseidon evaluations, feasible in hours on a GPU — and matches against observed `presentationTag` values. This recovers `credentialCommitment` and breaks unlinkability.

- **Formal gap:** The PU reduction sketch (§4) invokes "Poseidon PRF assumption (keyed by `blindingNonce`)." A PRF assumption requires the key to be uniformly random over its full domain. If the key space is reduced by implementation (short nonce), the PRF assumption does not hold, and the reduction fails. The spec must commit to a minimum nonce entropy (≥ 128 bits, drawn from a CSPRNG) and this requirement must be enforced in the circuit (e.g., range-check `blindingNonce` to prevent 0 or trivially short values) or stated as an explicit deployment requirement with a security loss quantification when violated.

- **In-threat-model?** **Conditionally.** The on-chain observability of `credentialCommitment` values is an inherent property of the append-only Merkle tree and is not acknowledged in §3. The attack is in-threat-model (passive chain observer) but the construction's unlinkability claim survives only if nonce entropy is enforced. Since the spec leaves nonce size unspecified, this is an unaddressed deployment vulnerability. Add a note to §3: "The security of Presentation Unlinkability assumes `blindingNonce` is drawn uniformly from {0,1}^128. Reduced-entropy implementations degrade to a precomputation attack with work 2^(nonce_bits) Poseidon evaluations per enrolled credential."


## Persona: cu_ciso

---

### Attack 1: The Revocation Clock Is Ticking and My Examiner Is Watching

**Attack:** A member calls at 9am to report that the AI agent they authorized for bill payments was used fraudulently overnight. Under NCUA Part 748.2(b)(2), I must demonstrate controls to "detect, prevent, and respond to attacks." I need to revoke that agent's access *right now*. I read §7: the Merkle tree is described as "append-only." I read §2 (root history buffer): 30 entries, circular. The credential commitment is already a leaf in the tree. There is no revocation path described anywhere in this construction.

The agent's proof is valid as long as:
1. Its credential commitment is a leaf under *any* root in the 30-entry buffer, and
2. `currentTimestamp < expiryTimestamp`

If `expiryTimestamp` is 90 days out, and my ops team cannot force-expire or tombstone a leaf in an append-only structure, this agent's proofs remain valid against historical roots for the entire 30-root window — potentially hours to days depending on how frequently the tree is updated. No RFC 7662 deployment leaves me without a revoke button. This construction does.

**Why it works against the construction:** The construction's threat model (§3) treats revocation as out of scope. The adversary model explicitly assumes the Merkle tree "reflects ground truth via smart contract access control" but provides no mechanism for the CU operator to write to that contract to invalidate a specific leaf. The root history buffer's 30-entry window is a revocation-latency floor with no upper bound defined.

**In-threat-model?** No — this is a gap the construction must address. A time-bounded nullifier registry or an on-chain revocation set that the RS checks alongside the root would close it. As written, the construction cannot satisfy NCUA incident response requirements.

---

### Attack 2: Operator Key Custody — You Buried the AS Problem, You Didn't Solve It

**Attack:** The construction's entire adversarial-AS-resilience property rests on one assumption (§3): "A does not control the agent's EdDSA private key (operator key)." My first question to any vendor: *where does that key live and who holds it?*

If the operator is NFCU itself, the EdDSA private key is held on NFCU's key management infrastructure. That infrastructure is now in my NCUA third-party risk inventory — except it's first-party, so it's in scope for every GLBA Safeguards Rule audit (16 CFR §314.4(c): "access controls on customer information systems"). If the key is browser-held (WebCrypto / localStorage / IndexedDB), XSS attacks on any NFCU web property steal the key and defeat the construction's soundness entirely. If the key is held by a cloud HSM, I've just re-introduced a central trusted party — functionally equivalent to the AS I eliminated.

The construction in §8 claims "the operator signs" as a structural difference from BBS+, but provides zero guidance on operator key lifecycle: generation ceremony, rotation policy, escrow for member estate scenarios, compromise response. My SOC 2 Type II auditor will ask for the key management policy. The ZK circuit says nothing about it.

**Why it works against the construction:** The security reduction in §4 reduces EdDSA forgery to Baby Jubjub DLP — formally correct — but the reduction assumes the private key is secret. Key custody is entirely out of scope in the construction. A construction that shifts trust from the AS to an unspecified operator key has not eliminated trust; it has deferred it to an unspecified layer that I, the CISO, now own with no tooling.

**In-threat-model?** No — the adversary model grants the adversary control over the AS while treating operator key custody as assumption, not engineering. The construction must specify a key management architecture (HSM class, rotation schedule, escrow policy) to be deployable in a regulated institution.

---

### Attack 3: Zero-Knowledge to Regulators Is Not a Feature

**Attack:** §7 claims: "NCUA examiners reviewing NFCU's agent authorization infrastructure can verify that the on-chain Merkle tree is append-only and that proof verification is deterministic." My examiner's questionnaire does not have a checkbox for "append-only Merkle tree." It has checkboxes for:

- User access logs with timestamp, identity, resource accessed (FFIEC CAT: Cybersecurity Controls Domain, Access Management)
- Audit trails sufficient to reconstruct who accessed what and when (NCUA Part 748 Appendix A, III.C)
- Session records tied to authenticated identities (GLBA Safeguards Rule §314.4(e))

A `presentationTag = Poseidon3(credentialCommitment, resourceIdentifier, blindingNonce)` is not an audit trail. It is a 256-bit pseudorandom field element that is *by design* unlinkable across presentations (§3, Game PU). The zero-knowledge property that protects member privacy simultaneously prevents me from producing a coherent log entry that says "Agent A accessed bill-payment service at 03:14 UTC for member M." My SOC 2 auditor needs exactly that.

The construction cannot simultaneously satisfy Presentation Unlinkability (Game PU — prevents cross-RS correlation) and FFIEC audit trail requirements (requires cross-RS correlation for incident reconstruction). This is not a configuration problem. It is a fundamental tension the construction does not acknowledge.

**Why it works against the construction:** The construction treats unlinkability as a pure win (§3, §7). For privacy-preserving member auth between a human and an RS it might be. For regulated financial institutions, the CU's *own* audit infrastructure needs to be able to correlate events. The construction provides no privileged audit mode, no revealable audit tag, no examiner-accessible log path.

**In-threat-model?** No — the construction must address the audit trail gap. A plausible fix: a separate `auditTag = Poseidon2(credentialCommitment, CU_audit_key)` exposed only to the institution's SIEM, computed in the same proof, unlinkable across RSes but linkable to the CU's internal audit record. Without this, the CISO cannot close the FFIEC audit trail finding.

---

### Attack 4: On-Chain SLA Is Not a Core Processor SLA

**Attack:** Step 4 of the deployment scenario (§7): "The RS verifies the Groth16 proof against the on-chain root." This requires the RS to check `agentMerkleRoot` against the 30-entry root history buffer — which lives in a smart contract on Base Sepolia.

My core processor (Fiserv/Jack Henry/Symitar) has a contractual 99.99% uptime SLA with financial penalties. Base Sepolia is a public testnet. The production target is presumably Base mainnet, which has no contractual SLA with NFCU, no financial liability for downtime, and has experienced outages (Base sequencer downtime events in 2023-2024). If the RS cannot reach the on-chain root to verify, what happens? The construction does not specify a fallback. If the fallback is "deny access," every member's agent is locked out during a blockchain event. If the fallback is "accept anyway," the adversarial-AS-resilience property evaporates.

Under NCUA Part 748 and FFIEC Business Continuity Management booklet, third-party dependencies require documented SLAs, business continuity plans, and concentration risk assessments. "The smart contract is the source of truth" is not a vendor contract. My vendor management policy requires a legal entity, a contract, and a right to audit.

**Why it works against the construction:** The construction frames blockchain dependency as a feature (decentralized, AS-independent) but does not address the operational SLA gap. RFC 7662 introspection, for all its faults, runs on infrastructure I control and have SLAs for. The 30-entry root history buffer could theoretically be cached, but the construction does not specify cache staleness policy, cache invalidation on root update, or RS behavior during network partition.

**In-threat-model?** No — the construction must specify the RS's behavior when the on-chain root is unavailable, document the SLA properties of the root update mechanism, and provide a path for institutions to satisfy NCUA third-party risk management requirements for the blockchain dependency. A CU CISO cannot accept "Base Sepolia" as a load-bearing component of member data access control.


## Persona: rfc7662_advocate

---

### Attack 1: The Operator-Key Trust Equivalence ("AS-Rebrand") Attack

**Attack:** The construction claims "adversarial-AS resilience" because a compromised AS cannot forge proofs — it lacks the agent's EdDSA operator key and Merkle witness (§2, §8). But the trust root has simply been relocated, not eliminated. In Bolyra, the trust anchor is: **(a)** the operator's EdDSA private key that signed the credential commitment, and **(b)** whoever controls the smart contract write path that enrolls commitments into the Merkle tree.

In the NFCU deployment (§7), NFCU is simultaneously the "operator" and the de-facto AS. If NFCU's credential-issuance infrastructure is compromised, an attacker can sign fraudulent credential commitments with inflated permissions and enroll them into the on-chain tree. The RS verifies the Groth16 proof against the on-chain root — the fraudulent credential passes. This is structurally identical to the RFC 7662 threat where a compromised AS returns a lying introspection response.

The RFC 7662 baseline can be hardened to the same structural position: replace the AS's HMAC-signed introspection response with an AS-controlled HSM signing key (RFC 9701 JWT introspection response), and run the AS on the same smart contract–controlled on-chain registry. The trust hierarchy is isomorphic:

| Bolyra | RFC 7662 hardened |
|--------|------------------|
| Operator EdDSA signing key | AS HSM signing key |
| On-chain Merkle tree (smart contract ACL) | On-chain token registry (smart contract ACL) |
| Agent generates ZK proof from operator-signed credential | Agent presents AS-signed JWT introspection response |

**Why it fails against the construction / why it lands:** The construction's reduction (§4) is sound *within its threat model* — the adversary controls the AS but not the operator key or Merkle tree. The claim survives if "AS" and "operator" are distinct parties. But §7 conflates them: NFCU is the operator. The "adversarial-AS" property is load-bearing only in a multi-party deployment where the operator and the AS are genuinely separate legal entities with separate key custody. For the self-hosted enterprise case (the construction's headline example), this property collapses. The construction must either (a) clarify that AS and operator must be separate, or (b) acknowledge that the adversarial-AS claim applies only in federated deployments, not the NFCU self-hosted scenario.

**In-threat-model?** Partially. The construction survives the cryptographic claim, but the §7 deployment narrative undermines the claimed property.

---

### Attack 2: RFC 9701 + RFC 8707 Already Achieves AS-Blind Offline Verification

**Attack:** The construction's first claimed differentiator is "AS-blind: no Authorization Server roundtrip or cooperation is needed at presentation time" (§1). But RFC 9701 (formerly draft-ietf-oauth-jwt-introspection-response) already provides this. The AS pre-signs the introspection response as a JWT (JWS). The agent caches this signed JWT. At presentation time, the agent presents the JWT and the RS verifies it offline against the AS's public key — zero AS contact at verification time.

Combine with RFC 8707 resource indicators: the AS issues a separate signed introspection JWT per `(agent, RS)` pair, with scopes filtered to only those the RS is authorized to see. The agent presents the RS-specific JWT to each RS. Cross-RS linkability is broken via pairwise subject identifiers (OIDC PPID, §5 of OpenID Connect Core). The RS verifies offline. No AS roundtrip.

The construction must argue that this is NOT equivalent to its AS-blind property. Its actual distinguishing claim (§8, column 2) is the *runtime-adaptive* predicate — the RS can change `requiredScopeMask` without triggering AS re-issuance. That is a real gap. But the AS-blind framing in §1 and §8 overstates the uniqueness: the RFC 9701 approach is also AS-blind at verification time.

**Why it lands:** The construction's table in §8 labels the baseline's best attempt as "BBS+ allows holder-driven disclosure" — entirely ignoring RFC 9701. That signed JWT approach is offline-verifiable with zero AS roundtrip. The correct comparison for the AS-blind row is "RFC 9701 pre-signed JWT" not "BBS+ disclosure." The baseline CAN achieve offline AS-blind verification for a pre-specified scope set.

**Why the construction still survives on the *distinct* claim:** RFC 9701 requires AS cooperation to produce a new JWT if the RS changes its required scope. The circuit accepts `requiredScopeMask` as a runtime public input, so the same credential works for any mask without re-issuance. But the construction must separate "AS-blind" from "runtime-adaptive" — they're conflated in §1 and §8.

**In-threat-model?** Yes — the construction survives if it cleanly reframes: the unique property is runtime-adaptive predicate evaluation, not AS-blindness per se. RFC 9701 closes the AS-blind gap; the runtime-adaptive gap is what remains genuinely novel.

---

### Attack 3: BBS+ with Pre-Committed Conjunction Claims Covers Realistic Predicate Sets

**Attack:** The construction argues (§8, row 2) that BBS+ "cannot evaluate bitwise AND with cumulative-bit implication closure over a bitmask" and that pre-issuing a credential for every possible mask value causes "combinatorial explosion for 64 bits." True for a 64-bit open-ended space. But the deployment scenario (§7, NFCU) immediately contradicts this premise.

NFCU defines a **finite, known permission taxonomy** extending the 8-bit Bolyra base "to include domain-specific bits for loan origination, wire transfers, account closure, PII access, etc." For any real-world credit union deployment, the set of distinct RS-side `requiredScopeMask` values is not 2^64 — it is the number of *distinct resource server types* NFCU operates. A credit union with 20 distinct resource server types has 20 distinct required masks. That is well within BBS+ pre-commitment range.

The operator issues a BBS+ credential with 20 derived conjunction claims: `"satisfies_bill_pay_policy": true`, `"satisfies_loan_origination_policy": true`, etc. At presentation, the agent discloses only the claim relevant to the RS. No combinatorial explosion. No runtime circuit evaluation needed. The RS verifies the BBS+ derived proof offline.

The "2^64 permission space where AS-side policy tables do not scale" (§1 scenario 1) is stated as a scenario but never instantiated as a concrete deployment. The only concrete deployment is NFCU (§7), which has bounded RS policy vocabulary.

**Why the construction can survive:** The construction needs to commit to which scenario it is actually proving. If the claim is for an *open, unbounded*, runtime-specified predicate (truly adversarially chosen mask at presentation time), then BBS+ pre-commitment fails and the ZK approach is strictly necessary. But §7 undermines this by describing a bounded taxonomy. The construction should either (a) drop §7 and argue for the open-ended case, or (b) add a scenario where the RS is adversarial and supplies masks from an unpredictable distribution.

**In-threat-model?** Partially. The construction is correct for unbounded predicate spaces. The NFCU deployment example is inadvertently giving the RFC 7662 baseline a gift — it fits squarely in the BBS+ pre-commitment range.

---

### Attack 4: blindingNonce Freshness Is Unenforced — PU Security Depends on a Client-Side Guarantee

**Attack:** The Presentation Unlinkability (PU) game in §3 and the reduction in §4 depend critically on `blindingNonce` being "freshly sampled per presentation" and uniformly random. The circuit, however, imposes no constraint on `blindingNonce`. It is an unconstrained private input — any field element, including zero, a hardcoded constant, or a deterministic function of the credential, satisfies the circuit.

If the agent implementation uses a weak RNG, deterministic nonce derivation, or a monotonic counter, the `presentationTag = Poseidon3(credentialCommitment, resourceIdentifier, blindingNonce)` becomes effectively deterministic for a fixed `(credential, RS)` pair. Two RSes that collude and observe the same `presentationTag` value across two sessions can link presentations to the same agent — a direct break of PU.

Compare DPoP (RFC 9449): the server supplies a fresh server-chosen nonce (`dpop_nonce`), and the DPoP proof binds to that nonce. Nonce freshness is *enforced by the protocol*, not delegated to the client's RNG. An agent implementation cannot accidentally replay a stale DPoP proof because the server rejects mismatched nonces. 

The Bolyra construction has no equivalent server-side nonce injection. The RS supplies `requiredScopeMask`, `currentTimestamp`, and `resourceIdentifier` as public inputs — but not a per-session nonce that would prevent nonce reuse. A server-supplied nonce would close this gap and is straightforward to add (`RS_nonce` as an additional public input to the circuit, committed into `presentationTag`).

**Why it lands:** This is an in-protocol design gap, not just an implementation concern. The PU game proof (§4, reduction for PU) states "the `blindingNonce` is freshly random per presentation" as an assumption, but the protocol does not *enforce* this. The circuit should include `RS_nonce` (server-chosen, included in `resourceIdentifier` commitment or as a separate public input) to make unlinkability protocol-enforced rather than implementation-dependent.

**In-threat-model?** Yes — the construction must address this. The fix is to add a server-supplied nonce as a circuit public input. Without it, the PU property is a liveness assumption on the client, not a cryptographic guarantee, and a determined adversary (who can probe agent implementations for weak RNG) can break it without breaking any cryptographic assumption.


## Persona: spiffe_engineer

---

### Attack 1: "You built a SPIRE attestor plugin and called it a protocol"

- **Attack:** The construction's `SelectiveScopeProof` circuit is structurally isomorphic to a SPIRE custom attestor plugin. In SPIFFE, a node attestor produces a SPIFFE ID; a workload attestor produces SVID scope. I could write a ZK workload attestor that: (a) accepts an EdDSA-signed operator credential, (b) runs the bitwise-AND predicate proof off-SVID, (c) stuffs the result into a JWT-SVID claim `x-bolyra-scope-proof`. The RS verifies the SVID via the SPIRE Workload API. I haven't changed the SPIFFE wire format — I've just added a ZK-verified custom claim. Where in Section 1's four properties does this fail?

- **Why it works / fails:** The attack breaks the "new protocol" framing but does not break the construction's formal claims. It fails specifically on **adversarial-AS resilience**: the JWT-SVID is still signed by the SPIRE server. Even if the attestor plugin ran the ZK verifier, the SPIRE server is still the entity that issues (and can lie about) the SVID's claims. The construction's operator EdDSA key is held by the agent, not the server — this is structurally different. A compromised SPIRE server issues a malicious JWT-SVID regardless of what the attestor plugin proved. The on-chain Merkle root in Section 2 cuts the SPIRE server out of the signing trust path entirely; a ZK SPIRE attestor plugin does not.

- **In-threat-model?** Yes — the adversarial-AS game (Section 3, Game SSS, step 3) explicitly grants the adversary AS control. The construction survives because the RS verifies against the on-chain root, not SPIRE's attestation. **But**: the construction must explicitly address this in its "why baseline cannot match" table (Section 8), which it does, but *only for RFC 7662/BBS+*. It does not address SPIFFE SVIDs with a ZK attestor. Add a column.

---

### Attack 2: "WIMSE cached token exchange already gives you AS-blind presentation"

- **Attack:** The WIMSE architecture draft (draft-ietf-wimse-arch §5.3) and the BCP companion specify that workload access tokens SHOULD be cached for their full lifetime and reused without AS contact. A workload obtains a scoped `aud`-restricted token, caches it, and presents it to the RS 10,000 times with no roundtrip. The RS verifies the token offline using a cached JWKS. This satisfies "no AS roundtrip at presentation time." The construction's AS-blind property conflates **operational AS-independence** (no roundtrip) with **cryptographic AS-independence** (AS cannot forge). WIMSE achieves the former; Section 1's claim is about the latter, but the abstract says "AS-blind" without this distinction. An RS operator reading the claim before reaching Section 3 will think WIMSE is categorically weaker. Is that true?

- **Why it works / fails:** The attack is partially correct as a framing attack. The construction's *actual* differentiating property is adversarial-AS *forgery* resilience, not merely roundtrip-free presentation. WIMSE cached tokens still carry the AS's signature; a malicious AS can issue a token with inflated scopes and the RS has no recourse except JWKS trust. The Bolyra construction's forgery resilience is real and WIMSE does not match it. However, WIMSE's selective disclosure scope is explicitly in-charter (draft-ietf-wimse-arch §4.2 mentions "minimal disclosure" as a design goal). The construction does not engage with WIMSE's evolving scope at all — it argues only against RFC 7662 + BBS+. If WIMSE ships a ZK-based minimal-disclosure extension (which is actively being discussed), the differentiation claim narrows.

- **In-threat-model?** Partially **no** — the construction must sharpen its language in Section 1 to distinguish operational AS-blindness (WIMSE already achieves this) from cryptographic AS-forgery resilience (WIMSE does not). Failing to do so is a specification defect, not a circuit defect.

---

### Attack 3: "Your PU game leaks via `agentMerkleRoot` epoch fingerprinting"

- **Attack:** The public output `agentMerkleRoot` (Section 2, Public Outputs) is the same value for every agent enrolled in the same Merkle tree epoch. The RS logs it. Two colluding RSes — which the PU Game explicitly grants to the adversary ("up to n-1 colluding RSes," Section 3) — compare their logs. Any two presentations that share the same `agentMerkleRoot` were generated from credentials enrolled before the same tree rotation. If the root history buffer rotates every T seconds and the anonymity set in epoch E is k agents, the adversary reduces the agent identity space from "all enrolled agents" to "agents enrolled in epoch E." For the NFCU deployment described in Section 7 with 13M+ members this may still be large, but the construction makes no quantitative claim about minimum anonymity-set size. For the "regulated fintech with 20 registered agents" scenario in Section 2, k=20 and timing correlation trivially breaks unlinkability. The PU game's `negl(λ)` bound implicitly assumes the anonymity set grows with λ — but the construction never states this.

- **Why it works / fails:** This is a concrete gap. The formal PU game in Section 3 does not bind the adversary's advantage to the epoch anonymity set size. The security argument in Section 4 argues only about the pseudorandomness of `presentationTag` — it does not account for the fact that `agentMerkleRoot` is a *deterministic, publicly observable epoch fingerprint*. Two presentations with identical `agentMerkleRoot` are observably from the same epoch. SPIFFE SVIDs have an analogous vulnerability (the trust domain leaks organizational identity) but SPIFFE doesn't claim unlinkability — Bolyra explicitly does.

- **In-threat-model?** **No** — the PU game must either (a) remove `agentMerkleRoot` from the public outputs and replace it with a root-knowledge proof (a separate ZK proof that the Merkle root matches one of the on-chain history entries without revealing *which* one), or (b) add a minimum-anonymity-set assumption to the PU security theorem. The current reduction sketch in Section 4 for PU does not address epoch fingerprinting at all.

---

### Attack 4: "Trust-domain federation — SPIFFE solved this; Bolyra has no answer"

- **Attack:** SPIFFE Federation (the SPIFFE Federation spec and draft-ietf-spiffe-federation) allows `spiffe://nfcu.org/agent/foo` to present to an RS registered under `spiffe://visa.com/` via pre-shared bundle endpoints and trust domain maps. This gives portable workload identity across organizational boundaries. The NFCU scenario in Section 7 uses a single operator's Merkle tree. What happens when NFCU's agent needs to call a Visa RS that runs its own Bolyra deployment with a different on-chain Merkle root? The RS in Section 2 checks `agentMerkleRoot` against its *own* on-chain root history buffer. An agent enrolled in NFCU's tree cannot produce a proof that verifies against Visa's root. Cross-operator presentation requires either (a) dual enrollment in both trees, (b) a cross-operator Merkle root composition mechanism, or (c) a federation protocol analogous to SPIFFE bundle exchange. None of these appear in the construction or spec references in Section 5.

- **Why it works / fails:** This is a genuine architectural gap. The construction is scoped to a single-operator deployment. The "portable identity" property claimed in the broader Bolyra materials (CLAUDE.md: "unified ZKP identity protocol for humans and AI agents") implies cross-operator portability, but the `SelectiveScopeProof` circuit hardcodes verification against a single `agentMerkleRoot`. SPIFFE Federation is a solved, deployed mechanism for this exact problem. The construction must either (a) explicitly scope the claim to single-operator deployments and remove "portable" from the framing, or (b) define a cross-operator root aggregation mechanism (e.g., a registry-of-roots Merkle tree whose root is the public parameter, with operator-specific sub-trees as leaves). The latter is architecturally non-trivial and would require a new circuit gadget.

- **In-threat-model?** **No** — this is an unaddressed architectural scope gap. The single-RS verification assumption in Section 2 ("`agentMerkleRoot` is in the on-chain root history buffer") implicitly ties the construction to a single operator's chain deployment. Section 7's NFCU scenario is intra-operator only. The claim in Section 1 does not restrict itself this way.
