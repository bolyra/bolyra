# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0\_pm

> *Senior PM owning MCP auth at Auth0/WorkOS/Stytch. GTM-first, cost-sensitive, cites incumbents, demands buyer-level reasons.*

---

### Attack 1: Revocation Is Not Real-Time — And Your Buyers Are Regulated

**Attack:**
The construction's "AS-blind" property (§8, Gap 1) is framed as an advantage: "No AS is contacted." In a credit union deployment, this is a compliance liability. NCUA 12 CFR Part 748 requires prompt response to credential compromise events. Under the construction, revocation means rotating the operator's EdDSA key and waiting for a new Merkle root to propagate to the on-chain 30-entry history buffer (§5: "root history buffer is append-only"). Until the compromised credential ages out of the buffer window, any proof generated against a valid historical root is still accepted by RSes caching that root.

WorkOS and Auth0 revoke a token in <1 second via the AS. The construction's revocation latency is bounded by *however many root rotations it takes to push the old root out of the 30-entry buffer* — which is undefined in the spec and controlled by the operator's enrollment cadence, not by an incident response timeline.

**Why it works:**
The construction never states how quickly the history buffer rotates under an adversarial enrollment freeze. If the operator stops enrolling new agents (because it's the incident — the operator key is compromised), the buffer never advances. §3's threat model explicitly says "A does not control the on-chain Merkle tree state (immutable once committed; root history buffer is append-only)." Immutability here is the attacker's friend during a compromise window.

**In-threat-model?** No — the construction must address how a regulated operator achieves sub-minute revocation without AS coordination. The AS-blind property, uncaveated, is a feature that turns into a liability at the first NCUA examination after a breach.

---

### Attack 2: The Onboarding Cliff Kills Enterprise Sales Before the Demo Ends

**Attack:**
The §7 deployment scenario quietly requires:
1. A blockchain operator key (Baby Jubjub EdDSA) with production HSM custody
2. On-chain Merkle tree enrollment transactions (gas, RPC infrastructure, key rotation tooling)
3. A `rapidsnark` native binary on the agent's execution environment ("production path" per §6)
4. A 30-entry root history buffer synchronized between the agent and the RS
5. A deployed Solidity verifier contract keyed to the specific `pot16.ptau` + per-circuit `.zkey` artifacts
6. RS-side nullifier state (nullifierHash tracking per sessionNonce)

None of this is "paste an API key." The rs-side verification alone requires either a live blockchain RPC call to read the root history buffer, or a cached copy the RS trusts to be current. §2 verification step 5 says "read from contract or cached" — that's a new infrastructure dependency for every RS that wants to accept a Bolyra proof.

Auth0 MCP auth, WorkOS MCP, and Stytch Connected Apps all onboard in an afternoon: register a client, get a client secret, configure scopes in a dashboard. The credential is a JWT or an opaque token. The RS validates it against a JWKS endpoint. Zero on-chain state.

**Why it works:**
The construction benchmarks *proving time* (§6: "< 1s with rapidsnark") but never benchmarks *integration time*. For an enterprise buying in a 90-day procurement cycle, the proof latency is irrelevant if the integration requires deploying Solidity contracts, managing ptau ceremonies, and running a native binary in a regulated production environment. The 64-constraint scope satisfaction gadget is elegant; the operational surface around it is not.

**In-threat-model?** No — this is GTM risk, not cryptographic risk. The construction must quantify the integration surface and compare it against the incumbent's, not just the cryptographic properties. A 320-byte constant-size proof that takes 6 months to integrate loses to a 2KB JWT that takes 2 hours.

---

### Attack 3: scopeCommitment Is a Permanent Cross-Session Tracking Token

**Attack:**
§2 defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output. §6's own ASI reduction (step 6) states: *"All Q proofs emit the same `scopeCommitment` value (since the credential doesn't change)."*

This means any RS that receives more than one proof from the same agent sees an identical `scopeCommitment` across every session, every RS, every `requiredScopeMask`. It is a stable, deterministic, cross-RS tracking identifier — more durable than a cookie because it is cryptographically derived from the credential and cannot be rotated without re-enrollment.

The adversary modeled in §3 is "colluding RSes that compare notes." The construction's defense in §4 (step 6) is that recovering `permBitmask` from `scopeCommitment` requires a Poseidon preimage — true. But the colluding RSes don't need to recover the bitmask to build a behavioral profile; they only need to correlate that Agent X (identified by stable `scopeCommitment`) hit RS-A at 09:00 and RS-B at 09:01. The construction defends the *content* of the bitmask but not the *linkability* of the agent identity across RSes.

The `ASI-Minimal` variant (§3, "Standalone Mode") drops `scopeCommitment` — but §7's deployment scenario uses the full construction with `scopeCommitment` as the "chain-linking anchor," and the construction never advises operators when to use ASI-Minimal vs. full.

**Why it works:**
The construction's §8 Gap 6 argues BBS+ "leaks claim values per disclosure." True. But BBS+ holder-binding uses per-presentation randomization — the same BBS+ credential produces unlinkable derived proofs. The Bolyra construction's `scopeCommitment` is the *opposite* of unlinkable: it is explicitly designed as a "chain-linking anchor" (§2), which is exactly what privacy-conscious enterprise buyers will flag in a privacy review. GDPR Article 4(1) defines a persistent cross-site identifier as personal data; `scopeCommitment` is a stable pseudonym for every agent across every RS that accepts Bolyra proofs.

**In-threat-model?** Partially — §3 models colluding RSes but only analyzes bitmask *recovery*, not agent *linkability*. The construction must either prove that linkability via `scopeCommitment` is acceptable (it is for some use cases) or provide a per-session randomized commitment scheme that preserves the chain-linking utility without the cross-RS correlation property. As written, this is an unaddressed privacy gap that will block enterprise deployments with a GDPR/CCPA surface.

---

### Attack 4: The Adversarial-AS Threat Model Has No Buyers

**Attack:**
The construction's headline differentiator in §8 Gap 3 is "Adversarial-AS Soundness" — the proof is sound even if the AS lies about scope membership. This is a real cryptographic property. It is not a real procurement criterion.

The construction's target buyer (§7) is a NCUA-regulated credit union using AI agents. This institution already has an identity provider — likely Okta, Azure AD, or a CUSO-managed Auth0 tenant. That AS is *their own AS*. The threat model implicitly assumes the credit union's own AS will lie to its own RSes about agent permissions. No procurement committee in a regulated institution approves a product whose pitch is "your own AS might betray you."

The practical threat model for a credit union is: (a) a third-party core banking API partner's RS should not over-claim the agent's permissions (addressed by the construction), and (b) the agent should not be able to claim permissions its operator never granted (also addressed). But *both* of these threats are addressed by the simpler model of "operator-signed JWTs with the partner RS's public key" — which Auth0 already supports via resource indicators (RFC 8707) and audience-restricted access tokens. The partner RS validates the JWT signature against the credit union's JWKS. No on-chain Merkle tree required.

The adversarial-AS scenario that actually requires ZK — where the AS is a third party who can lie — maps to federated AI agent marketplaces, not credit union partner integrations. The construction's §7 scenario uses the wrong threat model to justify the wrong product for the wrong buyer.

**Why it works:**
§8's five gaps are real gaps against the RFC 7662 baseline. But the construction conflates *technical differentiation* with *buyer motivation*. A credit union procurement team asking "why not WorkOS?" does not respond to "Groth16 knowledge soundness reduces to the algebraic group model." They respond to "your partner's compromised AS cannot forge your agent's permissions." The construction must answer: *what specific incident, reportable to NCUA, would have been prevented by Bolyra that WorkOS would have missed?* Without a named breach scenario or a named regulatory requirement that mandates AS-blind proofs, Gap 3 is a solution looking for a customer.

**In-threat-model?** No — this is a positioning gap, not a cryptographic one. The construction's threat model (§3) is technically coherent but does not map to the buyer's threat model (§7). The construction must either (a) identify a concrete buyer segment where the AS *is* adversarial by design (agent marketplaces, cross-operator delegation, third-party AI service brokers) and build the §7 scenario around that segment, or (b) reframe the AS-blind property as an operational simplification (no AS dependency = no AS SLA, no rate limits, no AS outage risk) rather than a security property against an adversarial AS. The current framing will lose the procurement conversation.


## Persona: cryptographer

I will assess the `AgentSelectiveScope` construction against four attacks drawn from my toolbox. The construction is technically interesting — the gap analysis in §8 is substantively correct — but several formal gaps matter for the claimed security levels.

---

### Attack 1: Subverted Trusted Setup — Universal Proof Forgery

- **Attack**: Groth16 requires a per-circuit trusted setup ceremony producing CRS `(pk, vk)`. During `Setup(1^λ)`, the generator samples toxic waste `τ`. A party in possession of `τ` can compute valid proofs for **any** public input vector, without a witness. Concretely: forge a proof with `requiredScopeMask = 0xFF` and `agentMerkleRoot` pointing to a valid on-chain root, for an agent with `permissionBitmask = 0x00`. The Groth16 verifier accepts.

- **Why it works**: Knowledge soundness (A1) holds only in the generic group model **assuming** the CRS was generated honestly. Once `τ` is known, the reduction breaks entirely: the extractor cannot extract a witness because none exists, but the forged proof still satisfies the bilinear pairing equations. The SSU game in §3 states "Challenger runs `Setup(1^λ)`" with no qualification about ceremony integrity, toxic waste destruction, or multi-party computation. The construction offers PLONK as an alternative with universal setup, but the primary recommendation (§6, §7) is Groth16 with rapidsnark. There is no trusted setup plan, no reference to a multi-party ceremony, and no audit trail specified.

- **In-threat-model?** **No.** The adversary capabilities in §3 exclude attacks on BN128 pairing and Poseidon hash, but say nothing about CRS integrity. The adversarial-AS claim in §1 ("even a compromised AS cannot forge a proof") is vacuously false if the AS also participated in — or compromised — the trusted setup ceremony. This is the single most critical unaddressed gap. The construction must either commit to a specific MPC ceremony (with participant list and attestations), use PLONK exclusively, or explicitly bound the claim to an honest-setup assumption and call it out as a deployment prerequisite.

---

### Attack 2: `scopeCommitment` Trivially Breaks ASI — Proof Sketch Has a Gap

- **Attack**: The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a **constant** public output across all sessions for the same credential. In the ASI game (§3), the adversary A submits or observes C₀ and C₁. The Merkle tree is on-chain and its leaves are the `credentialCommitment` values — public. From the tree, A can enumerate all leaves. Given B₀ (known from the game) and each candidate leaf `credComm`, A precomputes `Poseidon2(B₀, credComm)` and `Poseidon2(B₁, credComm)` for every leaf. After the **first** query, A observes `scopeCommitment` in the public signals and compares it against both precomputed sets. The match immediately reveals b.

- **Why it works / why the reduction fails**: The §4 proof sketch (step 6) claims: "Recovering `permBitmask_b` from `scopeCommitment = Poseidon2(permBitmask_b, credComm_b)` without knowing `credComm_b` requires a preimage attack." This is the flaw. A **does** know `credComm_b` in any realistic instantiation: `credentialCommitment` is a Merkle leaf inserted into the on-chain tree, which is public by construction. A queries the tree, enumerates leaves, and computes the two candidate `scopeCommitment` values in O(leaves) Poseidon evaluations. No preimage attack required. The Poseidon PRF assumption A3 provides no protection when the alleged "key" `credComm_b` is publicly readable from the chain.

  The construction partially acknowledges this by introducing `ASI-Minimal` (omit `scopeCommitment`). But the main variant's ASI claim is overstated — the proof sketch is incorrect as written.

- **In-threat-model?** **No.** The main construction retains `scopeCommitment` and asserts ASI security for it. The adversary the construction is supposed to defeat — a coalition of RSes comparing notes — trivially links all proofs from the same agent via the constant `scopeCommitment`. Either (a) the main construction must drop `scopeCommitment` and unconditionally adopt `ASI-Minimal`, or (b) the game definition must restrict A from querying the Merkle tree (which contradicts the claimed AS-blind, on-chain enrollment model).

---

### Attack 3: Colluding AS+RS Nullifier Preimage Enumeration — Pseudonymity Breaks

- **Attack**: The nullifier is `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`. All enrolled `credentialCommitment` values are Merkle leaves — on-chain, public. The RS generates `sessionNonce` and sees it plaintext. A colluding AS+RS proceeds as follows: RS collects `(sessionNonce, nullifierHash)` from the proof transcript; AS enumerates all n enrolled `credentialCommitments`; jointly they compute `Poseidon2(credComm_i, sessionNonce)` for i = 1, …, n and find the unique i where the result equals `nullifierHash`. They have now identified which specific agent generated the proof, linking it to the operator's enrollment record — breaking pseudonymity.

- **Why it works**: The nullifier is designed to prevent replay, not to provide unlinkability. Its construction `Poseidon2(credComm, nonce)` is essentially a PRF keyed by `credComm` evaluated at `nonce`. But the PRF key (credComm) is public. The privacy claim in §1 — "the RS never sees... the full permission set" — addresses only bitmask leakage, not identity linkability. With n agents enrolled under a single operator, the colluding AS+RS needs n Poseidon evaluations per proof to de-anonymize the proving agent. For n = 100 agents, this is trivial. The attack succeeds without breaking any cryptographic assumption.

- **In-threat-model?** **Partially, but not fully addressed.** The threat model lists "Colluding Resource Servers" and separately lists "The Authorization Server." It does not explicitly address the **joint** (AS ∩ RS) coalition against nullifier deanonymization. The claim "a compromised AS cannot... forge a proof" (§1) is correct for forgery but says nothing about deanonymization. For the credit union scenario in §7, the core banking RS and the credit union's own AS are separate entities — but a regulatory subpoena or a supply-chain compromise of either could expose both. The fix is to bind the nullifier to a blinded commitment: e.g., `nullifierHash = Poseidon2(credComm, sessionNonce, agentBlindingFactor)` where `agentBlindingFactor` is private witness data not derivable from the tree — but this requires circuit changes and a new privacy argument.

---

### Attack 4: Groth16 is HVZK, Not Simulation-Extractable — UC Composition Breaks

- **Attack**: The ASI reduction in §4 step 2 invokes the Groth16 "zero-knowledge simulator Sim" to answer A's adaptive queries. This assumes the simulator can produce indistinguishable proofs for **adaptively** chosen public inputs without the witness. Groth16 provides **honest-verifier** zero-knowledge (HVZK) in the CRS model: given the simulation trapdoor, Sim can produce valid-looking proofs. However, Groth16 is **not** simulation-extractable (SE-ZK). This has two consequences:

  1. **Malleability in the presence of real proofs**: Given a valid proof π for `(requiredScopeMask_1, sessionNonce_1)`, an adversary who sees π can, via linear algebra on BN128, produce a fresh-looking proof π' that also verifies for the same public inputs. π and π' have identical public outputs (same nullifier), so nullifier-based replay detection blocks re-use. But if the RS accepts π' as "a different session" via any non-nullifier bookkeeping, the agent's ZK property degrades — the adversary has generated a proof they could not have generated without observing π, which leaks interaction.

  2. **Adaptive simulation across sessions requires a non-standard argument**: The ASI game allows A to observe Q real proofs (not simulated) and then adaptively choose masks. The §4 proof constructs a simulator that "answers queries without knowing b" using Sim. But in the reduction, the simulator must work in a **hybrid** world where some proofs are real and some are simulated — standard Groth16 ZK only guarantees indistinguishability in a fully simulated world. A formal hybrid argument is needed, and it requires Groth16 ZK to compose across sequential proof observations, which holds under the standard CRS model but the paper provides no hybrid lemma or citation.

  For **UC composition** (relevant if Bolyra is embedded in a larger protocol stack, e.g., combined with the mutual handshake), simulation-extractable ZK is typically required to argue that the ZK subprotocol remains secure when composed with other protocols. Groth16 is not SE-ZK; PLONK variants with specific hash instantiations can achieve it, but neither is claimed here.

- **In-threat-model?** **Partially.** For the standalone `AgentSelectiveScope` use case, HVZK likely suffices in practice — the malleability attack requires observing a real proof and the only consequence is creating an alternative valid transcript for the same statement, which the nullifier blocks for replay. But the §8 comparison to BBS+ cites "simulation-extractable soundness" as implicitly superior, and the UC argument — implicit in any claim that the construction composes securely with the mutual handshake from `draft-bolyra-mutual-zkp-auth-01` — requires SE-ZK and is not established. The construction should either (a) restrict composition claims or (b) specify that PLONK with a simulation-extractable instantiation is required for the composed protocol.


## Persona: cu\_ciso

### Attack 1: Trusted Setup Toxic Waste — Catastrophic Undetectable Forgery

- **Attack:** The AgentPolicy and Delegation Groth16 keys were generated from a project-specific ceremony using `pot16.ptau`. The construction references this ceremony but provides zero attestation chain: no list of participants, no multi-party computation transcript, no BIP-style attestation log. A single colluding participant who retained the "toxic waste" (the secret randomness τ used to generate the CRS) can produce valid proofs for any `permissionBitmask` without possessing a credential or operator key. Unlike a compromised AS — which leaves logs, anomalous introspection calls, and revocable signing keys — a ceremony backdoor is silent, produces cryptographically valid proofs, and cannot be detected from the proof transcript alone.

- **Why it works against the construction:** §4 (SSU theorem) reduces unforgeability to Groth16 knowledge soundness (A1). But knowledge soundness holds only if the CRS was honestly generated. A toxic-waste holder does not need to extract a witness — they construct a forged proof directly in the CRS's structure. The reduction sketch in §4 does not address CRS integrity; it assumes it. The construction is silent on ceremony provenance, participant attestations, and what a credit union operator does if a compromise is discovered post-deployment. §8 Gap 3 claims the trust anchor moved from AS to operator EdDSA key — but the actual trust anchor also includes the integrity of the proving/verification key pair. The operator key is auditable (it's a keypair the CU controls); the ceremony transcript is not mentioned anywhere in the construction.

- **Regulatory framing:** NCUA Part 748 Appendix B §II.C requires documented controls over cryptographic key material for systems accessing member information. GLBA § 314.4(c)(1) requires access controls on information systems. The CU's vendor management policy (FFIEC IT Examination Handbook, Outsourcing Technology Services) requires the CU to assess third-party security controls — in this case, the ceremony operator's controls over toxic waste destruction. None of this is addressed.

- **In-threat-model?** No. The threat model explicitly assumes "no subgroup attacks" and "no Poseidon preimage attacks" (§3) but does not bound CRS integrity. The construction must address ceremony provenance or adopt PLONK universally (no per-circuit ceremony) and make that the default, not the optional path.

---

### Attack 2: Operator EdDSA Key Compromise — Trust Anchor Is Same Shape as AS Key, Harder to Rotate

- **Attack:** The construction's §8 Gap 3 positions the operator EdDSA key as superior to an AS signing key because "a compromised AS cannot forge an operator signature." But this replaces one single-point-of-compromise with another. The construction never specifies: where the operator key lives (HSM, software keystore, browser?), who has access, how key rotation works, and what the blast radius of compromise is.

  Concretely: if the operator EdDSA private key is exfiltrated, the attacker can sign new `credentialCommitment` values and enroll them into the Merkle tree — issuing themselves arbitrary permissions. Unlike AS compromise, where the AS can be taken offline and tokens invalidated, the Merkle tree is append-only and immutable once committed (§3). Enrolled fraudulent credentials cannot be removed from history — only future roots exclude them. Any proof generated against a historical root (within the 30-entry buffer) using a fraudulently enrolled credential is valid.

- **Why it works against the construction:** §3 states "root history buffer is append-only." §4's SSU theorem game does not model key compromise — the "enrollment oracle" in the game gives A the Merkle root but not the operator key (§3 game step 2). The actual deployment gives the operator key to the CU's operations team. If that key leaks, the game's assumption is violated. The construction provides no key rotation path that doesn't require re-enrolling every agent (since `credentialCommitment` binds `operatorPubkeyAx/Ay` — changing the key invalidates all existing commitments). During the re-enrollment window, the compromised key and the new key are both valid against historical roots in the buffer.

- **Regulatory framing:** GLBA § 314.4(c)(3) requires monitoring for unauthorized access to customer information. NCUA Part 748 Appendix B requires multi-factor authentication and least-privilege access for systems touching member data. FFIEC CAT Domain 2 (Threat Intelligence) requires controls to detect credential compromise. The construction provides no monitoring surface — proof verification is pass/fail against a circuit; it cannot distinguish "valid proof from authorized agent" from "valid proof from compromised-key-enrolled fraudulent agent."

- **In-threat-model?** No. The threat model (§3) explicitly excludes "operator's EdDSA private key" from adversary capabilities. This is the construction's axiom, not a justified assumption. For a credit union, the operator key is held by humans with laptops, VPNs, and phishing inboxes. The construction must specify key custody requirements (HSM class, split custody, ceremony for key generation) or the trust anchor claim in §8 is hollow.

---

### Attack 3: On-Chain Registry SLA and Credential Revocation Gap — 90-Day Blast Radius

- **Attack:** RS verification requires checking `agentMerkleRoot ∈ on-chain root history buffer` (§2, verification step 5). This creates two failure modes the construction does not address:

  1. **Availability:** A live on-chain query ties RS authorization availability to blockchain network availability. Base Sepolia (the specified deploy target per CLAUDE.md) is a testnet; Base mainnet has experienced degraded performance during high-congestion periods. The construction offers a "cached" alternative (RS caches the root locally) but does not specify cache invalidation semantics, TTL, or what happens during a chain reorg that reverts a root update.

  2. **Revocation:** The only revocation mechanism is credential expiry. A compromised loan agent with a 90-day credential cannot be revoked before expiry — the proof will verify against any historical root in the 30-entry buffer for the duration. The nullifier prevents *replay* of the same `(proof, sessionNonce)` pair, but the agent can generate a fresh proof with a new `sessionNonce` every time. True revocation would require removing the `credentialCommitment` leaf from the tree, but §3 specifies the buffer is append-only and tree state is immutable once committed.

- **Why it works against the construction:** §2's root history buffer is explicitly a 30-entry circular buffer for usability (prevents proofs from failing during root updates). This is the right engineering tradeoff, but it means a revoked credential remains provable for up to 30 root-update cycles. The construction does not define the rate of root updates (daily? per-enrollment?), so the revocation window is unbounded in time. §7's concrete scenario describes a "fraud-detection agent" with `READ_DATA | WRITE_DATA` — precisely the agent whose compromise requires immediate revocation, not wait-for-expiry.

- **Regulatory framing:** NCUA Part 748.0(b)(2) requires controls to "detect actual and attempted attacks." GLBA § 314.4(b)(3) requires procedures to detect and respond to unauthorized access to member information. FFIEC Business Continuity Management requires RTOs for critical systems. A credit union cannot tell its examiner "we can revoke an agent in 90 days." The examiner will ask for the incident response playbook — it does not exist in this construction.

- **In-threat-model?** No. The threat model §3 does not define a revocation adversary or bound the revocation latency. The construction must specify a revocation mechanism (e.g., a revocation Merkle tree whose root is a public input, so proofs against revoked credentials fail) or define an operational SLA for credential expiry that is acceptable for NCUA incident response requirements.

---

### Attack 4: Examiner Legibility Gap — The Groth16 Black Box Fails NCUA Part 748 Audit Requirements

- **Attack:** §7 claims: "Under NCUA examination, the credit union can replay the proof transcript to demonstrate that the agent was authorized for exactly the requested scope at the time of the transaction, with cryptographic assurance independent of the partner's attestation." This claim does not survive contact with an actual NCUA examination.

  A proof transcript contains 128 bytes of Groth16 elliptic curve points and 192 bytes of field elements in BN128 format. The examiner's questionnaire asks: "Show me the access log. Who accessed what, when, and why?" The construction's answer is a hex blob. There is no human-readable mapping from `requiredScopeMask = 0b00000110` to "this agent was authorized to disburse a $45,000 loan to member account #XXXX." The semantic layer — which bit maps to which business action — is entirely off-chain policy that the construction explicitly does not address.

  Worse: the proof proves the agent *could have* performed the action (had the permission), not that it *did* perform it or that the specific transaction was authorized. The audit trail the construction provides is a capability attestation, not an action audit log. NCUA examiners and GLBA safeguards require the latter.

- **Why it works against the construction:** §7 conflates "cryptographic assurance of authorization" with "audit defensibility." These are different requirements. The proof answers "did the agent have the right permission?" not "what did the agent do with it?" The `nullifierHash` prevents replay but does not record action semantics. The `scopeCommitment` anchors the proof to a bitmask but does not link to a transaction ID, member account, amount, or timestamp in any human-readable form.

  The construction also does not address who can *verify* the proof in an examination context. Running `snarkjs groth16 verify` requires: the circuit verification key (a 100KB+ JSON artifact), the proof JSON, and the public signals JSON. If Bolyra's infrastructure is unavailable during examination, the examiner cannot independently verify the transcript. This is a third-party dependency the CU's vendor management policy must address.

- **Regulatory framing:** NCUA Part 748 Appendix B §IV requires audit logs that document access to member information and support after-the-fact investigation. GLBA § 314.4(b)(1) requires the safeguards program to identify risks to customer information — the examiner will ask how the CU knows the agent used its authorization appropriately, not just that it was authorized. SOC 2 Type II CC6 (logical access controls) and CC7 (system monitoring) require both access control evidence AND activity monitoring evidence. The construction provides the former; the latter is absent.

- **In-threat-model?** No. The threat model §3 does not mention examiners, audit requirements, or the distinction between capability proof and action audit. The construction must define a companion audit log format that: translates `requiredScopeMask` bitmask values to named permissions and business actions, links each proof to a transaction ID and member context, and is independently verifiable without Bolyra infrastructure. Without this, the §7 exam-defensibility claim is marketing, not a security property.


## Persona: rfc7662_advocate

---

### Attack 1: `scopeCommitment` Is a Permanent Cross-RS Tracking Beacon

- **Attack**: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a deterministic, constant value for a given credential. It never changes across sessions. Any two RSes that compare notes can trivially determine "is this the same agent?" by comparing a single field element — no predicate reasoning required, no preimage attack needed.

  The RFC 7662 baseline with OIDC Pairwise Pseudonymous Identifiers (PPIDs) does the *opposite*: the sub claim is different per RS. Cross-RS linkage is architecturally prevented at the identity layer.

  The construction's ASI game in §3 does not defend against this. The game models a *single* challenger generating proofs for one adversary. It does not model two independent RSes, RS₁ and RS₂, who meet out-of-band and compare their `publicSignals` transcripts. The reduction in §4 (step 6) says "Recovering `permBitmask_b` requires a preimage attack" — but RS₁ and RS₂ do not need to recover the bitmask. They need only assert `scopeCommitment_1 == scopeCommitment_2` to establish that the same agent credential appeared at both. This is a free equality check on a public output.

  The construction acknowledges "All Q proofs emit the same `scopeCommitment` value" and calls this "no additional information beyond a single observation." That framing is backwards: one observation *permanently brands* the credential. The `ASI-Minimal` variant (§3, final subsection) fixes this by omitting `scopeCommitment`, but §2 and §7 deploy the full construction with `scopeCommitment` present.

- **Why it fails against the construction**: Partially. The `scopeCommitment` is load-bearing for chain-linking audit trails (§7, NCUA replay argument). Removing it (ASI-Minimal) eliminates cross-RS linkage but removes the audit anchor. The construction has not reconciled these two goals — it cannot simultaneously have an auditable scope commitment and cross-RS unlinkability.

- **In-threat-model?** Yes, and the construction must address it. The threat model in §3 explicitly lists "colluding resource servers" as an adversary. The ASI game does not capture the `scopeCommitment` tracking attack because the game models a single challenger, not independent RSes comparing transcripts. The construction needs either (a) a per-session `scopeCommitment` (e.g., bound to `sessionNonce`), which breaks the audit chain, or (b) explicit acknowledgment that colluding RSes can link sessions via `scopeCommitment` without any cryptographic attack.

---

### Attack 2: Offline JWT Introspection Already Removes the AS from the Hot Path

- **Attack**: The construction's Gap 1 ("AS-Blind Presentation") rests on the claim that RFC 7662 requires an AS roundtrip at proof time. This is false for draft-ietf-oauth-jwt-introspection-response (cited in my toolbox). Under that draft:

  1. The AS pre-issues a signed JWT introspection response bound to the specific RS audience (RFC 8707 `resource` parameter).
  2. The agent holds this JWT and presents it directly to the RS.
  3. The RS verifies offline against the AS's cached JWK Set — no AS call at authorization time.

  The structural analogy to the Bolyra construction is exact: agent holds a pre-issued artifact (JWT vs. Groth16 witness), presents it to the RS, RS verifies offline against a cached key (JWK Set vs. `vk`). The AS is not in the hot path in either case.

  Gap 1's specific phrasing — "Even with BBS+ holder-driven selective disclosure, the AS issued the BBS+ credential and chose which claims to include" — applies equally to Bolyra. The operator issued the `credentialCommitment` and chose what `permissionBitmask` to encode. The construction cannot simultaneously claim "operator key = secure trust anchor" (Gap 3) and "AS key = single point of compromise" (Gap 1) without explaining why one offline signing key is more trustworthy than the other.

- **Why it fails against the construction**: Gap 2 (Runtime-Adaptive Predicate) survives this attack. The pre-issued JWT introspection response encodes a fixed scope at issuance time. If the RS changes `requiredScopeMask` at request time, a new AS roundtrip is required to get a freshly-scoped JWT or a Token Exchange (RFC 8693). Bolyra's `requiredScopeMask` is genuinely a runtime circuit input — the same enrolled credential proves any satisfiable mask without re-issuance.

- **In-threat-model?** Partial. The construction overstates Gap 1 as a *fundamental architectural incompatibility* (§8 header language), when it is really a *latency and issuance policy* difference. The correct framing: "JWT introspection with pre-issued responses removes the AS from the hot path but not from the issuance path; Bolyra removes the AS from both." The current §8 Gap 1 text conflates these two properties and does not respond to offline JWT introspection specifically. The construction should be tightened to distinguish hot-path AS-blindness (partially matched by offline JWT) from issuance-independence (not matched).

---

### Attack 3: The Groth16 CRS Is a Systemic Trust Anchor the Construction Does Not Analyze

- **Attack**: Gap 3 ("Adversarial-AS Soundness") argues that a compromised AS cannot forge proofs because "the trust anchor is the operator's EdDSA key and the on-chain Merkle tree." This is true — *conditioned on an honest Groth16 CRS*.

  The Groth16 `(pk, vk)` is generated in a trusted setup ceremony. The toxic waste (a set of trapdoor values) allows anyone who holds it to generate a valid proof for *any* public input vector — including `requiredScopeMask` values the agent never satisfied. This is not a theoretical concern: it is the explicit failure mode of Groth16 ceremonies, addressed in production by multi-party computation (Zcash's Powers of Tau, Hermez, etc.).

  The construction's threat model (§3) states the adversary "does not control the BN128 pairing." It does not address the CRS trapdoor. The security game `SSU(λ)` (§3) begins with "Challenger runs `Setup(1^λ)`" — implicitly assuming an honest setup. But in deployment, the CRS is a shared, irrevocable artifact. Unlike an RFC 7662 AS signing key (which can be rotated, revoked, and re-keyed per operator), the Groth16 proving key cannot be revoked without redeploying the circuit and verifier contract, invalidating all existing proofs and requiring all agents to re-enroll.

  The construction asserts in §8 Gap 3: "A compromised AS cannot forge an operator signature." True. But a compromised CRS ceremony *can* forge a circuit proof, bypassing the operator EdDSA check entirely — the adversary generates a SNARK proof for the statement "I know a witness satisfying all constraints" without knowing any valid witness.

- **Why it fails against the construction**: The construction partially addresses this by noting that PLONK uses a universal setup (Powers of Tau, not circuit-specific), which is auditable and widely attested. However: (1) the PLONK path is labeled "optional," not the production path; (2) the Groth16 CRS is circuit-specific and the construction does not specify what ceremony was used for `AgentPolicy`; (3) the 30-entry root history buffer and on-chain verifier are separate trust anchors from the CRS, but the CRS compromise subsumes them.

- **In-threat-model?** No — the construction must address this. §3 defines adversary capabilities as not controlling the BN128 pairing, but the CRS trapdoor is distinct from the pairing itself. The `SSU` game assumes an honest setup challenger. The construction should either: (a) specify the ceremony used (multi-party, public, verifiable), (b) recommend PLONK as the production path precisely because its universal setup is more auditable, or (c) explicitly add CRS compromise to the threat model and bound the damage (circuit re-deploy, no key rotation at AS level).

---

### Attack 4: RFC 8693 Token Exchange + Per-RS Introspection Policy Already Provides Runtime Scope Narrowing

- **Attack**: Gap 2 ("Runtime-Adaptive Predicate") claims "the baseline's scope is fixed at token issuance. If the RS needs a different scope combination, a new token exchange (RFC 8693) or re-introspection is required." This conflates two distinct operations and understates what RFC 8693 provides.

  Under RFC 8693 Token Exchange:
  - The *agent* (acting as the token exchange client) presents its original broad-scope token to the AS with a `scope` parameter requesting a narrowed scope for a specific `resource` (RFC 8707).
  - The AS returns a downscoped token valid only for that `resource` and `scope`.
  - This exchange can be done by the agent *at the moment of the request*, before calling the RS.
  - The RS receives a token with exactly the requested scope, verifies it offline via jwt-introspection-response or standard JWT validation.

  The round-trip to the AS occurs *at request time, initiated by the agent* — structurally analogous to the agent running `proveHandshake()` locally. The latency difference (RFC 8693 AS roundtrip vs. Groth16 local proof generation) is empirical, not architectural. The construction's constraint table in §6 shows Groth16 (snarkjs/WASM) at "<8s" and rapidsnark at "<1s" — a well-deployed AS handles token exchange at comparable or lower latency.

  The construction's claim that "the RS chooses `requiredScopeMask` at the moment of the request" and "no re-issuance needed" is correct for the ZK path, but RFC 8693 allows the RS to communicate required scope in a `WWW-Authenticate` challenge, the agent exchanges for a narrowed token, and the RS accepts it — all within one request cycle. The AS is involved, but so is the Bolyra on-chain Merkle root read and nullifier check (§2, step 5). Both involve external dependencies at request time.

  The *genuine* remaining advantage is Gap 3 (AS compromise) and the predicate privacy of the ZK construction — not runtime adaptability per se.

- **Why it fails against the construction**: The construction's Gap 2 advantage narrows but does not disappear. The RFC 8693 path requires the AS to be available and cooperative at exchange time (latency + availability dependency). More importantly, the RS in RFC 8693 receives a token encoding the disclosed scope as a plain string claim — it learns the agent holds exactly that scope. The Bolyra construction reveals only the predicate outcome. For an RS that queries `WRITE_DATA | FINANCIAL_SMALL`, Bolyra proves the agent satisfies the mask without revealing whether it also holds `FINANCIAL_UNLIMITED`. RFC 8693 returns a token with the *requested* scope, but the agent's original broad-scope token (from which the downscoped token was derived) is known to the AS — who can log and correlate.

- **In-threat-model?** Partial. The construction should be rewritten to sharpen Gap 2's surviving claim: the runtime-adaptive advantage is not "no AS roundtrip" (the RFC 8693 path also allows agent-initiated narrowing at request time) but "the RS learns only pass/fail, not the disclosed scope string." The current §8 Gap 2 text frames the advantage as re-issuance cost — which RFC 8693 Token Exchange directly addresses. The stronger and surviving argument is the *predicate privacy* of the ZK proof vs. the *scope disclosure* of the token exchange response.


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE in production at Fortune 500, WIMSE draft co-author. Core stance: workload identity is solved at the right layer. The question is whether Bolyra's properties are new, or whether you're building a ZK superstructure on top of a problem the runtime platform already owns.*

---

### Attack 1: modelHash is an unattested claim, not a workload attestation

**Attack:** The circuit binds the proof to `modelHash = Poseidon(model_identifier)` as a private input (§2 private inputs table). The credential commitment seals model identity, operator key, and permissions. But the circuit has no mechanism to verify that the *current prover* — the process generating the witness — is actually executing the model identified by `modelHash`. The operator signed a credential that *says* modelHash X. Any party that obtains the credential private fields (sigR8x, sigR8y, sigS, permissionBitmask) can generate a valid proof for any `requiredScopeMask` the bitmask covers, while identifying itself as modelHash X. The operator EdDSA signature proves the *credential* was authorized, not that the *prover* is the authorized model.

SPIFFE's node attestation addresses this directly. A SPIRE agent running on a k8s node presents a projected service account token (OIDC-bound to the pod's identity) to obtain an SVID. An AWS workload uses the IID and instance attestation. A hardware-anchored workload uses TPM quotes. In each case, the credential is only issued *to* the attested platform — exfiltrating the SVID to another machine causes attestation to fail at renewal (SVIDs are short-lived for exactly this reason).

**Why it works / why it fails:** The construction's §3 threat model states A cannot "generate proofs with credentials it does not hold" but the harder, omitted case is: what happens when a legitimate agent's credential fields are exfiltrated? The operator's EdDSA signature verifies the credential was authorized, but the circuit does nothing about who is *holding* the credential at runtime. There is no platform binding, no hardware attestation, no OS-level isolation guarantee. The commitment `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` is a cryptographic hash of a policy document — it does not certify the prover's execution environment.

**In-threat-model?** No. The construction must address this. Either (a) the threat model explicitly scopes out credential theft from a compromised agent process (a significant real-world gap), or (b) the construction needs a platform-attestation layer that binds proof generation to a hardware/OS root of trust, similar to SPIFFE node attestation. Claiming Gap 3 (adversarial AS soundness) while being silent on adversarial prover isolation is incomplete.

---

### Attack 2: WIMSE transaction tokens + pre-issued JWT-SVID partially replicate Gap 1

**Attack:** §8 Gap 1 states: "In the baseline, every credential and every introspection response originates from the AS." This is only true of online AS flows. WIMSE `draft-ietf-wimse-arch` defines *transaction tokens* (TrATs): a workload holding a SPIFFE JWT-SVID (pre-issued by SPIRE, cached locally for the SVID's lifetime) presents it directly to an RS without any AS roundtrip. The RS verifies the JWT-SVID's SVID signature against the trust bundle (also cached). No AS is contacted at proof time. The scope in the JWT-SVID is fixed at issuance — but WIMSE explicitly allows the workload to include a `scope` claim scoped to the target RS in the TrAT, chosen at runtime from claims the SPIRE agent pre-authorized.

Concretely: a SPIRE agent issues a JWT-SVID with `"scope": ["READ_DATA", "WRITE_DATA", "FINANCIAL_SMALL", "FINANCIAL_MEDIUM"]` and an audience binding to the RS. The workload presents a derived TrAT with `"scope": ["WRITE_DATA", "FINANCIAL_SMALL"]` — exactly the requiredScopeMask in your scenario 7. The RS verifies the TrAT's parent JWT-SVID signature against the cached trust bundle. No AS roundtrip.

**Why it works / why it fails:** This does not achieve Gap 1 fully — the SPIRE server (which is the AS analog) chose the scope set at SVID issuance; the workload can only narrow it via TrAT presentation, not prove arbitrary predicates over a private bitmask. But it does achieve: (a) no AS roundtrip at proof time, and (b) some scope narrowing. The construction §8's framing of "every credential … originates from the AS" overstates the gap. Gap 1 should be refined to: *the private predicate evaluation over a credential the AS has never seen*. That is new — but the construction doesn't clearly distinguish this from the more modest "no AS roundtrip" claim that WIMSE already provides.

More importantly: Gap 2 (runtime-adaptive predicate) is **partially** addressed by WIMSE TrAT. The workload can choose which subset of pre-authorized scopes to present at runtime. The genuine gap the construction has is *predicates over a bitmask that the AS never learned* — not runtime scope narrowing per se.

**In-threat-model?** Partially. The construction must tighten §8 Gap 1 and Gap 2 to clearly state: the novel property is *private bitmask evaluation where neither the AS nor the RS ever learns the full bitmask* — not merely "no AS roundtrip." The current framing conflates the weaker WIMSE property with its own strictly stronger one, making the differentiation argument weaker than it needs to be.

---

### Attack 3: Constant scopeCommitment enables permanent cross-RS agent linkability

**Attack:** The public output `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is deterministic and constant for the entire lifetime of a credential (§2, public outputs table; §4 step 6 multi-query analysis). Every proof this agent ever generates emits the same `scopeCommitment`. Two colluding RSes that receive proofs from the same agent on different sessions, with different nonces and different `requiredScopeMask` values, immediately link the sessions as the same agent via `scopeCommitment`. The construction acknowledges this in §4 ("All Q proofs emit the same scopeCommitment value") and frames it as non-information. But that framing only holds for bitmask recovery — not for agent identity linkability.

In a SPIFFE deployment, X.509 SVIDs rotate on a configurable interval (default 1 hour in production SPIRE deployments). JWT-SVIDs are typically issued with 5-minute lifetimes. Each renewal produces a fresh certificate/JWT. Cross-session linkability requires the attacker to correlate across SVID rotations, which they cannot do without access to the SPIRE server's issuance log (the exact adversarial-AS scenario you defend against, but here it's the RS doing the linking without needing the AS).

**Why it works / why it fails:** The ASI game (§3) deliberately excludes this concern: its indistinguishability game asks whether two credentials with the same predicate outcomes produce distinguishable proofs. The constant `scopeCommitment` is excluded from the game by construction. But in any real deployment, a federated credit union partner (§7) that receives 50 proofs over a year from "some agent" can permanently build a behavioral profile keyed on `scopeCommitment` — without learning any bitmask bits. The construction's §3 operational mitigations (rate limiting, mask policy) don't address cross-session identity tracking at all.

The `ASI-Minimal` variant (§3, Standalone Mode) removes `scopeCommitment` from public outputs, which tightens the privacy bound — but it's presented as an optional variant, not the recommended deployment. The construction should either (a) make the minimal variant the default, or (b) explicitly acknowledge that credential-lifetime identity linkability is a design choice with a documented privacy cost.

**In-threat-model?** No, by the construction's own game definition (ASI game excludes session linkability). But it is a real deployment threat, especially in the §7 credit union scenario where the "CUSO or fintech partner" is explicitly a separate entity with potentially adversarial interests. The construction should address this in the threat model, not leave it to the operational mitigation section.

---

### Attack 4: The 30-entry root history buffer has no revocation primitive

**Attack:** The construction's Merkle enrollment model (§5, root history buffer: "30-entry circular buffer, on-chain") creates a credential validity window tied entirely to tree update cadence. Once a credential is enrolled and its `credentialCommitment` is a leaf, it is valid until (a) the operator-signed expiry timestamp is reached, or (b) the Merkle root that includes that leaf falls off the 30-entry buffer. There is no revocation mechanism. If the operator's EdDSA private key is compromised, the operator cannot invalidate existing credential commitments — they can only stop signing new ones. All proofs generated by the attacker using the stolen key and existing leaf are valid for the full expiry window.

SPIFFE addresses revocation via short-lived SVIDs with mandatory Workload API refresh. If a workload's SVID needs to be revoked, the SPIRE server simply stops renewing it. The workload's identity expires within the SVID lifetime (typically 1 hour). For zero-downtime security response, SPIRE supports SVID revocation via CRL and OCSP for the X.509 case. There is no analog in the Bolyra construction: the on-chain Merkle tree is append-only (§3 threat model: "root history buffer is append-only"), so removing a compromised leaf requires a new tree root, but old roots remain in the 30-entry buffer and old proofs against those roots remain valid.

**Why it works / why it fails:** The construction's §3 game definition (`SSU`) only asks whether an adversary can forge proofs for permissions not enrolled. It does not ask whether an enrolled-but-compromised credential can be revoked before expiry. The reduction sketch (§4) proves forgery requires breaking EdDSA/Poseidon — but a stolen key with a live credential doesn't require any forgery. The attacker has the witness fields and generates valid proofs legitimately.

The root history buffer of 30 entries means revocation requires (a) the operator issuing a new tree with the compromised leaf omitted, (b) waiting for 30 tree updates to flush the compromised root from the buffer. During that window — which could span weeks or months in a low-update-rate deployment — any party with the stolen credential can generate valid proofs. The construction does not specify the root history buffer update rate, nor does it provide an emergency revocation path.

**In-threat-model?** No. The threat model explicitly excludes key compromise: "A does not control … the Baby Jubjub discrete log (no key recovery)." But in practice, EdDSA private keys are stored on servers, in HSMs, or in hardware wallets — all of which can be compromised through side channels, supply chain attacks, or operational failures. The construction needs either (a) an explicit scope statement that key compromise is out of model (and an operational recommendation for key rotation + short expiry), or (b) an on-chain credential revocation primitive (a nullifier registry, a revocation Merkle tree, or a time-locked burn mechanism).
