# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

### Attack 1: The Provider Co-Dependency Is a GTM Veto

- **Attack:** Your entire root-of-trust requires Anthropic to generate a BJJ keypair in an HSM, run a key ceremony, insert the public key commitment into an on-chain governance-controlled registry, and then issue a bespoke `deploymentAuthorization` tuple per operator × model deployment. That is not a Bolyra product decision — it is a new operational burden you are imposing on Anthropic as a prerequisite for any enterprise to use your system. When a SECU procurement team asks "what happens if Anthropic declines to participate or changes its key management policy?", the honest answer is "nothing works." Auth0 MCP auth and WorkOS ship today without asking any model provider to run HSM ceremonies or insert keys into a DAO-controlled on-chain registry. We own the issuance chain end-to-end. You don't — you own only the prover/verifier, and the most critical piece (the provider signing key) belongs to a third party with no contractual obligation to you or your customers.

- **Why it works:** Section 2 (Enrollment protocol) states the provider key is "HSM-held" and the registry is "governance-multisig or DAO-controlled." Section 7 says "Anthropic generates a BJJ keypair in an HSM" as Step 1 of deployment. The construction is technically sound *conditional on Anthropic's participation*, but says nothing about how Bolyra obtains that participation or what the fallback is if Anthropic issues provider attestations in a different format, delays key ceremony, rotates keys on a schedule that diverges from Bolyra's archival assumptions, or simply doesn't do it.

- **In-threat-model?** No — the construction's threat model explicitly assumes an honest provider key. It does not address provider non-participation, provider operational error, or the contractual/business mechanics of obtaining Anthropic's cooperation. This is a **must-address gap**: the construction needs either a fallback trust model (operator self-attestation with degraded claims, disclosed as such) or a concrete mechanism by which Bolyra onboards model providers as signatories.

---

### Attack 2: Proving Latency Destroys the Agentic Use Case

- **Attack:** Section 6 targets "<5s" proving time and benchmarks against "Semaphore's 30K-constraint circuits which prove in ~3s." But Semaphore proofs are generated offline or asynchronously — they prove set membership for a pre-existing identity, not per-call authorization. MCP tool calls are synchronous: the client calls a tool, the server must authorize and respond before the agent proceeds. If every tool call requires a 3–5s PLONK proof generation step, a ten-step agentic workflow takes 30–50s in ZK overhead alone, before any actual computation. WorkOS issues a signed token in under 100ms. The latency gap is not 50× — it is 50× per hop in a multi-hop agent chain. Your Section 7 FINRA scenario involves agents generating "a PLONK proof binding the messageHash (order routing recommendation)" — a latency-sensitive, high-frequency operation where 5s is commercially unacceptable and would place your customer out of compliance with SEC Rule 15c3-5's real-time market access controls.

- **Why it works:** The construction's circuit cost estimate (§6) is honest: ~23,550 constraints, targeting <5s. But it does not address (a) where in the MCP call stack proof generation occurs, (b) whether proofs can be batched or precomputed, or (c) what happens in the synchronous path when a proof takes 8s on an under-provisioned edge node. The "comparable to Semaphore" benchmark is misleading because Semaphore proofs are never on the synchronous auth critical path.

- **In-threat-model?** No — the threat model (§3) addresses cryptographic adversaries, not latency adversaries. This is a **must-address gap**: the construction needs a concrete async/precomputation architecture — e.g., proofs are generated per session credential (not per tool call), the `messageHash` is bound post-hoc via a separate lightweight commitment, or proving is offloaded to a trusted enclave running ahead of the call — with honest latency numbers for each design point.

---

### Attack 3: Authorization Binding Is Not What the Auditor Buys

- **Attack:** Section 1 explicitly disclaims: "Bolyra proves AUTHORIZATION binding... it does NOT attest that the authorized model was the one that ACTUALLY executed the inference." Yet the construction's own buyer scenarios (§7) are precisely about proving to NCUA and FINRA examiners that *specific models processed specific data*. The NCUA examiner wants to know that Claude Sonnet 4.6 — not an unapproved model, not a shadow deployment — *actually ran* on member PII. Your construction proves that someone enrolled a credential saying they were authorized to use Sonnet 4.6. A rogue SECU engineer can enroll a valid Sonnet credential, then route inference calls to a locally-running open-source model, generate a valid Bolyra proof (because the credential is legitimately enrolled), and satisfy the NCUA auditor. The examiner's conclusion — "only approved models touched PII" — would be false, and Bolyra's proof would have enabled that false conclusion. Auth0's MCP auth makes no claim about model identity at all, which is honest; your construction makes a model identity claim that collapses under the execution-authorization gap you yourself disclosed.

- **Why it works:** The construction's threat model (§3) explicitly carves out "out of scope: runtime execution binding." Section 8's "why the baseline cannot match" argues for authorization binding as the differentiator, but the deployment scenarios (§7, SECU, FINRA) sell auditors on *execution* assurance. This is not a cryptographic attack — it is a product scope misalignment that procurement and compliance counsel will catch in due diligence.

- **In-threat-model?** No — the construction does not define what auditor claim is actually being made and verified, leaving the gap between "authorized" and "executed" unexplained to the buyer. This is a **must-address gap**: the construction needs a honest scope statement in each scenario that says "Bolyra proves the operator was authorized to use model M; proving model M actually ran requires [TEE/hardware attestation product X], which Bolyra complements but does not replace." Selling authorization-binding as execution-assurance to regulated entities is a compliance liability for the customer.

---

### Attack 4: modelHash Has No Verifiable Referent

- **Attack:** The construction treats `modelHash` as "Hash of model weights/identifier (field element)" — but Anthropic does not publish model weights. There is no public corpus from which a verifier can independently compute `Poseidon(claude-sonnet-4-6-weights)` and confirm it matches the enrolled `modelHash`. In practice, `modelHash` is whatever string or identifier Anthropic chooses to sign — functionally equivalent to a claim value in a signed JWT. The construction's non-malleability argument (§3, §4) proves that an adversary cannot swap Opus-authorized credentials for Sonnet-authorized credentials. But it does not prove that "Sonnet" means anything beyond "the identifier Anthropic labeled as Sonnet in an attestation tuple." If Anthropic issues `modelHash_sonnet` for a model instance that is actually Opus serving as Sonnet (re-billing scenario), no party in the Bolyra construction can detect this — the proof verifies correctly. The tiered pricing scenario in §1 ("Anthropic wants to prove to a tenant that their Opus usage was actually Opus") collapses for exactly this reason: Bolyra proves Anthropic signed the modelHash, not that the weights correspond to Opus.

- **Why it works:** Section 2 defines `modelHash` as a private input with no constraint tying it to a public, independently verifiable commitment of model weights. Section 7's enrollment flow says Anthropic computes `deploymentAuthorization = Poseidon3(modelHash_sonnet, ...)` — but the mapping from "modelHash_sonnet" to actual inference behavior is entirely Anthropic's assertion, unverifiable by any third party. The construction's security argument (§4) reduces forgery to A1/A2/A3 but never addresses the semantic gap between the hash and the model.

- **In-threat-model?** No — the construction defines the threat model against *cryptographic* forgery (producing a valid proof claiming a wrong modelHash) but not against *semantic* forgery (Anthropic or operator mislabeling). This is a **must-address gap**: the construction should either (a) scope the claim to "Anthropic-asserted model identifier binding" (honest but weaker — equivalent to a signed claim in a JWT issued by Anthropic), or (b) describe how modelHash is anchored to a verifiable artifact (e.g., a publicly committed weights hash, a TEE measurement, or a transparency log entry that maps modelHash to a reproducible build).


## Persona: cryptographer

Applied cryptographer. My stance: unless I see a complete threat model, a game definition, and a reduction that closes against all roots of trust, it's a sketch, not a construction. C7 is technically interesting but has four structural problems.

---

### Attack 1: Universal SRS as an unaddressed third root of trust

**Attack:** PLONK's universal setup requires a structured reference string (SRS) of the form {g, τg, τ²g, …, τⁿg}. If the SRS ceremony retains toxic waste τ, any party holding τ can produce a valid proof for any statement — including proving `(modelHash_target, adversaryPk, bitmask)` as a valid witness — without knowing the provider BJJ key, the operator BJJ key, or any enrolled credential.

**Why it works / why it fails against the construction:** The construction's entire threat model (Section 3) lists two roots of trust: the provider BJJ signing key (HSM-held) and the on-chain registry (governance-multisig). There is a third root of trust: the PLONK SRS. The reduction sketch in Section 4 conditions on "knowledge soundness of PLONK in the AGM+ROM" (assumption A3), but AGM knowledge soundness itself presupposes the SRS was generated honestly. With a subverted SRS, A3 collapses entirely — the extractor breaks down because the adversary can produce group elements non-algebraically relative to the SRS. Critically, unlike Groth16 (per-circuit toxic waste), PLONK's universal SRS is a single shared parameter. One SRS compromise breaks all Bolyra circuits across all operators and all models simultaneously — the blast radius is wider than what the construction acknowledges. There is no SRS ceremony specified, no MPC transcript, no ceremony auditor. The provider HSM is described in detail; the SRS is mentioned in passing in Section 5 ("PLONK with universal setup, Section 3.3") with no trust analysis.

**In-threat-model?** No. The threat model must include a game for SRS subversion: either (a) posit a trusted SRS ceremony (describe it, name who runs it, what the adversary controls), or (b) reduce to a falsifiable assumption that doesn't require the SRS to be honest (e.g., argue under polynomial commitment binding without requiring τ to be discarded). Until one of these is provided, the security argument has a hole large enough to drive a proof through.

---

### Attack 2: Nullifier enumeration collapses credential-level privacy

**Attack:** Given the on-chain Merkle tree (permissionless, publicly enumerable — established by the enrollment protocol in Section 2) and the public input sessionNonce (signal index 7, Section 2), any observer computes `Poseidon2(cc_i, sessionNonce)` for every leaf `cc_i` in the credential tree and matches against the nullifierHash public output (signal index 1). This identifies exactly which credentialCommitment — and therefore which specific enrollment instance, including expiry timestamp — produced each proof.

**Why it works / why it fails against the construction:** The construction states "verifier learns ONLY {model_hash, operator_pk, permission_bitmask, message_hash}" (Section 1 gap analysis, claim c). The nullifier enumeration reveals the full credentialCommitment preimage structure: `Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)`. While modelHash, opPkAx, and permBitmask are already leaked via `modelOperatorFingerprint`, the expiry timestamp is NOT in the intended verifier knowledge set. More concretely: an operator who rotates credentials (new expiry, same model and key) produces a new credentialCommitment. The construction describes this rotation as privacy-preserving ("historical proofs remain valid against old Merkle roots"). But nullifier enumeration allows any observer to correlate the old and new credentials — both are in the public tree, and the fingerprint match is exact. The construction addresses cross-operator attestation reuse (Section 3, "Why the public attestation oracle does not help") but nowhere addresses this passive enumeration by an observer with a full copy of the Merkle tree.

**In-threat-model?** No (if any form of credential-level privacy is claimed). The construction must either (a) acknowledge the enumeration and tighten the "verifier learns ONLY" claim accordingly, or (b) make credentialCommitments private (submit a blinded commitment to the tree instead of the raw Poseidon5 output, and prove Merkle membership against the blinded value). Currently the circuit proves Merkle membership of `credentialCommitment` directly, which is the same value that can be enumerated.

---

### Attack 3: Permission bitmask self-issue — provider attestation does not bind scope

**Attack:** The provider attestation covers `deploymentAuthorization = Poseidon3(modelHash, operatorPkAx, operatorPkAy)` — no bitmask. The credentialCommitment is `Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiry)` — bitmask is present. The circuit verifies both signatures but only the operator signature covers the bitmask; the provider signature covers only the (model, operator) pair. An operator with a legitimately-enrolled credential for model M uses the same provider attestation tuple to enroll additional credentials with arbitrary bitmask values — no new provider attestation required, since the provider signature is not bitmask-bound.

**Why it works / why it fails against the construction:** In the NCUA scenario (Section 7): "Anthropic issues a second attestation for Opus if SECU licenses Opus." This correctly captures the model-class binding. But the permission bitmask — which in the regulatory use cases represents access level (PII_ACCESS, ORDER_FLOW_ACCESS, etc.) — is entirely self-asserted by the operator. SECU can enroll a Sonnet credential with bitmask 0x01 (basic queries) and a separate Sonnet credential with bitmask 0xFF (all permissions including PII) using the same Anthropic attestation tuple. The FINRA examiner (Section 7, Scenario 2) sees `scopeCommitment = Poseidon2(0xFF_bitmask, cc)` and `modelOperatorFingerprint = Poseidon3(modelHash_sonnet, secuPkAx, 0xFF)` — but Anthropic never approved SECU for PII-level Sonnet access; SECU self-granted it. The reduction in Section 4 correctly handles model-hash forgery (Cases 1–5) but the game definition (MODEL-BIND-FORGE v2) asks only whether the adversary can forge the model hash. There is no game asking whether an operator can forge an elevated permission level. The gap analysis claim (a) says "attacker with an Opus key cannot forge a proof saying Sonnet made this call" — this holds. But no game asks "can operator with basic-access Sonnet credentials forge a PII-access Sonnet proof?" The answer is yes, trivially, by self-enrolling a new bitmask.

**In-threat-model?** No. Either (a) define a PERMISSION-FORGE game and show the bitmask is provider-attested (by adding the bitmask to deploymentAuthorization: `Poseidon4(modelHash, opPkAx, opPkAy, permBitmask)` — though this makes attestation issuance more granular), or (b) explicitly scope the claim to model-class binding only and remove permission attestation from the regulatory value proposition.

---

### Attack 4: HVZK insufficient for adversarially-chosen public inputs in the on-chain verifier

**Attack:** The verifier is described as an on-chain contract (Section 7 references on-chain PLONK verification, ~300K gas). The `sessionNonce` is a public input that the verifier supplies (signal index 7). A malicious on-chain verifier requests multiple proofs from the same operator for the same credential, supplying adaptively chosen sessionNonces `n₁, n₂, …`. It observes `{Poseidon2(cc, n₁), Poseidon2(cc, n₂), …}` as nullifier outputs. Combined with the enumerable Merkle tree (Attack 2), it can confirm `cc` matches a specific leaf. But more subtly: PLONK achieves HVZK — zero knowledge against a verifier that chooses the challenge coins *honestly* (specifically, the Fiat-Shamir challenges are computed from a random oracle). The ZK property says the proof transcript is simulatable. However, HVZK does not prevent a malicious verifier from using the public inputs themselves (which are NOT hidden) to run inference attacks across multiple proofs. The zero-knowledge guarantee is over the *proof transcript*; it says nothing about information extractable from the *combination of public inputs and public outputs across multiple proofs*. The construction uses the same `credentialCommitment` as a stable private input across all proofs — exactly the secret that multi-proof correlation targets.

**Why it works / why it fails against the construction:** The formal ZK property in the reduction sketch (Section 4, A3) is stated as "knowledge soundness of PLONK in the AGM+ROM" — this is a soundness assumption, not a ZK assumption. The ZK property is asserted implicitly ("verifier learns ONLY…") but no simulator is exhibited and no ZK game is defined. The construction needs simulation-extractability (SE-ZK) or at minimum non-adaptive simulation soundness for the on-chain use case, where the verifier is untrusted. PLONK achieves simulation extractability in the AGM+ROM (Fuchsbauer et al., 2022), but this requires the adversary to be algebraic — which excludes adaptive public-input attacks where the adversary uses the public signals themselves, not the proof transcript. No reference is given, no game is defined for the ZK property, and the simulator is never exhibited. Per the construction's own preamble, the ZK claim is hand-waving until a simulator is specified.

**In-threat-model?** No. The paper needs: (1) an explicit ZK game (IND-ZK or simulation soundness), (2) a simulator that takes `(modelHash, operatorFingerprint, scopeCommitment, messageHash)` as public outputs and produces an indistinguishable transcript without knowing the private witness, and (3) an argument that the multi-proof correlation via public inputs does not undermine this simulator. The nullifier construction `Poseidon2(cc, sessionNonce)` with public sessionNonce is the primary surface — a nonce-diversified commitment to a stable secret under an adversarially-controlled nonce is not a standard ZK building block.


## Persona: cu_ciso

---

### Attack 1: The Proof Doesn't Prove What My Board Presentation Says It Proves

**Attack:** I read Section 7 to my board: *"NCUA examiners require proof that only approved model instances… were authorized to process member data."* Then I read Section 3: *"Out of scope: runtime execution binding… requires TEE or hardware attestation."* These two sentences cannot coexist in the same audit memo. The construction proves authorization binding — which model was *permitted* to run — not which model *actually executed* the inference. A rogue deployment running Llama-3 under a Sonnet-authorized credential produces a valid Bolyra proof. The proof attests the *permission slip*, not the *employee who showed up*.

**Why it works / why it fails:** The construction is internally consistent. It explicitly disclaims execution binding. But the NCUA examination scenario in Section 7 says the examiner "can confirm 'this PII operation was authorized for Opus.'" An examiner who asks *"does this mean Opus actually ran?"* gets an answer that collapses the entire audit narrative. GLBA Safeguards Rule §314.4(c)(2) requires the credit union to demonstrate *actual* controls over data processing, not just authorization records. The authorization-execution gap is not a cryptographic weakness — it is a regulatory representation gap that the construction never resolves.

**In-threat-model?** No — the construction must address this. Either (a) the NCUA deployment scenario must be rewritten to accurately describe authorization-only binding and identify the complementary execution-layer control the CU must operate, or (b) the claim scope must be narrowed everywhere to match what the proof actually proves. The board narrative and the threat model cannot use different definitions of "prove."

---

### Attack 2: Permissionless Merkle Insertion Fails My Vendor Management Exam

**Attack:** Section 2 (Enrollment Protocol) states explicitly: *"Tree insertion contract requires no additional authorization check… The Merkle tree is append-only and permissionless; the circuit is the gatekeeper."* My NCUA examiner runs through FFIEC CAT Domain 2 (Threat Intelligence) and NCUA Part 748 Appendix A §II(B), which require documented access controls on *every* system that is in the data chain for member records. I submit this on-chain contract to my vendor management team for third-party risk assessment. The assessment comes back: open-write access to a data store used in member PII authorization flows, no access control at the boundary, security enforced by a ZK circuit that has never been audited by AICPA standards.

**Why it works / why it fails:** The construction's security argument is correct *cryptographically* — a spurious insertion cannot produce a valid proof. But "the circuit is the gatekeeper" is not a control that maps to any line in NCUA's examiner questionnaires or the FFIEC CAT. The examiner does not have a "ZK soundness" checkbox. They have "access control to systems handling member data" and "audit log of who wrote what." A permissionless append-only contract produces an audit log where anyone on-chain can insert data, and the examiner sees a log full of entries from unknown actors. The CU's incident response team cannot answer "who inserted this leaf and why" for non-CU entries.

**In-threat-model?** No — the construction must address this. Options: (a) add a permissioned insertion wrapper contract (only whitelisted operator keys can submit `credentialCommitment`) that satisfies FFIEC access-control requirements while preserving the circuit-level enforcement for actual proof validity, or (b) provide a compliance mapping that explains how "permissionless insertion + circuit enforcement" satisfies NCUA Part 748 and FFIEC CAT access-control domains without a boundary access control.

---

### Attack 3: Anthropic's HSM Is an Unauditable Third-Party Single Point of Trust

**Attack:** The entire construction's root of trust is `providerRegistryRoot` — which depends on Anthropic's BJJ keypair generated in "an HSM" with "public key published in a transparency log." I pull NCUA Letter 07-CU-13 (Third-Party Vendor Risk) and my board-approved Vendor Management Policy. I need: (1) SOC 2 Type II covering the key generation ceremony and HSM management, (2) contractual audit rights, (3) incident notification SLA if the HSM is compromised, (4) defined RTO/RPO if Anthropic revokes and re-enrolls its provider key. Section 2 says revocation means "new root excluding the compromised key" — but what is the SLA for that? How long is the window where an attacker holding the compromised provider key can issue fraudulent deployment authorizations before the registry root updates?

**Why it works / why it fails:** The construction correctly identifies that the provider key is governance-controlled and HSM-held. But it provides zero operational content around that governance: no audit regime, no compromise notification timeline, no SLA on revocation propagation, no definition of what "transparency log" means (Certificate Transparency? A bespoke append-only log? An Ethereum event?). For a $2B–$10B credit union, NCUA's examination of third-party risk requires these specifics in the vendor contract. If I cannot get a SOC 2 report covering the key ceremony, I cannot satisfy NCUA Part 748 Appendix B's third-party oversight requirement — regardless of how sound the ZK proof is.

**In-threat-model?** No — this is operational and regulatory, not cryptographic. The construction must specify: the transparency log format, the revocation SLA (time from detection to new registry root), the audit artifact that the CU can present to an NCUA examiner to demonstrate oversight of the provider key lifecycle, and the incident response obligation on the provider's side.

---

### Attack 4: The 30-Entry Root History Buffer Is Not a Compliance Audit Trail

**Attack:** Section 4 (Key Rotation Survival) says: *"For long-term archival, the verifier stores the `agentMerkleRoot` from the proof at verification time."* Section 2 describes a 30-entry root history buffer. My NCUA examination covers a 12-month look-back on member data access events. If I process 10,000 agent calls per day and rotate credentials quarterly, the root history buffer at the smart contract level covers a window that is completely inadequate for annual examination. The construction's answer is "the verifier stores the root" — meaning my credit union's internal systems must archive `agentMerkleRoot` per transaction for 12 months, and those archives become the audit trail. Now I need: storage SLA, integrity controls on the CU-side archive (who can modify it?), and a chain-of-custody argument for the NCUA examiner explaining why the CU's self-maintained archive of Merkle roots constitutes an independent audit trail rather than a self-certified log.

**Why it works / why it fails:** The construction correctly handles the cryptographic question (old proofs verify against archived roots). It does not handle the regulatory question: an audit trail that the CU maintains, controls, and presents to its own examiner is not independent. NCUA examination standards expect audit artifacts that cannot be unilaterally altered by the institution under examination. If the CU archives the `agentMerkleRoot` values itself, the examiner must trust the CU's own database — which is precisely what ZK is supposed to replace with cryptographic independence. The on-chain root history buffer (30 entries) is too shallow to serve as the independent audit anchor for multi-year retention requirements.

**In-threat-model?** No — the construction must address this. Options: (a) specify a durable on-chain audit log (e.g., emit `(agentMerkleRoot, blockTimestamp, proofHash)` events that survive beyond the 30-entry buffer and are immutable on-chain), (b) define a third-party archival service with SOC 2 coverage that stores root-proof pairs, or (c) explain the chain-of-custody argument for how CU-side archival satisfies NCUA examination independence requirements.


## Persona: rfc7662_advocate

I have shipped production token introspection for a decade. Every time someone shows me a ZK construction for authorization binding, I ask the same question: show me the property that my stack — RFC 7662, the JWT introspection response draft, RFC 9449 DPoP, RFC 8707 resource indicators, and pairwise subject identifiers — cannot produce. Let's see if C7 survives.

---

### Attack 1: Signed JWT Introspection Response Eliminates the AS from the Hot Path

**Attack:**

Section 8(c) asserts: *"Adding an AS to enforce the model-identity claim re-introduces the correlation problem (AS sees every call)."* This is factually wrong for the RFC stack I carry. `draft-ietf-oauth-jwt-introspection-response` (now progressing toward RFC) decouples issuance from verification: the AS signs a JWT containing `model_id`, `operator_sub`, and a `scope` bitmap at credential-issuance time; the resource server (verifier) validates offline against the AS's published JWK. The AS participates once — at enrollment — exactly as Anthropic participates once when it signs `deploymentAuthorization = Poseidon3(modelHash, operatorPkAx, operatorPkAy)` per (operator, model) pair.

Add DPoP (RFC 9449): the signed JWT is bound to the operator's proof-of-possession key. Now you have:

- Offline-verifiable model-identity claim (`model_id: "claude-sonnet-4-6"`)
- Operator key binding (DPoP `jkt` thumb-print in the JWT)
- Permission scope (OAuth `scope` or a structured claim)
- No per-call AS participation

This is structurally isomorphic to the Bolyra enrollment path: provider signs once, operator presents offline, verifier checks against a known provider public key — except it runs on hardware RSA/ECDSA, not Baby Jubjub, and requires zero circuit constraints.

**Why it works / why it fails against the construction:**

The construction's Section 8(c) objection collapses. The only surviving delta is: (i) the JWT body is visible to the verifier (no selective disclosure of `permissionBitmask` sub-bits), and (ii) the JWT subject is stable across verifiers (see Attack 2). For the FINRA/NCUA audit scenarios in Section 7, (i) is irrelevant — the auditor is entitled to see the full claim set. The construction would need to show that bitmask sub-bit confidentiality is a load-bearing requirement, not merely a nice-to-have.

**In-threat-model?** Partially — the construction survives only if it can articulate a concrete adversary advantage from hiding the full `permissionBitmask` body. As written, Section 8(d) claims BBS+ has no bitwise-AND predicate, not that hiding individual bits is required. This is an unforced argument: the construction conflates *proving a predicate on a bitmask* with *hiding the bitmask itself*, and the NCUA audit scenario requires neither.

---

### Attack 2: `modelOperatorFingerprint` Is More Linkable Than OIDC PPIDs

**Attack:**

Section 8 highlights "cross-operator attestation reuse is impossible" as a privacy win. But it ignores the inverse problem: `modelOperatorFingerprint = Poseidon3(modelHash, operatorPkAx, permissionBitmask)` is **deterministic and stable** across every proof the same operator produces for the same (model, bitmask) tuple. Every verifier who receives a proof — NCUA, FINRA, an internal compliance tool, a third-party audit firm — can correlate all transactions to the same operator fingerprint globally.

OIDC pairwise pseudonymous identifiers (PPID) solve exactly this: the AS issues a distinct `sub` value per relying party, making cross-RP operator linkage impossible by construction. RFC 8707 resource indicators allow the AS to further scope the token to a named audience, so a token presented to Verifier A cannot even be structurally compared with a token at Verifier B.

In the Section 7 SECU scenario: the NCUA examiner, the internal risk committee, and a contracted third-party auditor each get different PPID-derived `sub` values — they cannot pool observations. Under Bolyra, all three observers share the same `modelOperatorFingerprint` and can collude to reconstruct a cross-context usage profile for SECU's AI operations.

**Why it works / why it fails against the construction:**

The construction offers `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` for session-level unlinkability, but `modelOperatorFingerprint` is session-stable and verifier-stable. The construction does not address multi-verifier correlation. Section 8 mentions SPIFFE/WIMSE but never engages with PPID as a baseline privacy mechanism. This is a gap.

**In-threat-model?** No — the construction's threat model (MODEL-BIND-FORGE, PROVIDER-FORGE) is entirely about *forgery*, not about *cross-verifier correlation*. The construction does not define "verifier-unlinkability" as a security goal, so a cross-verifier linking attack is **outside the stated threat model**, meaning the construction must either add it as a goal or concede it is not achieved and that PPID-based OAuth provides stronger unlinkability in multi-verifier deployments.

---

### Attack 3: `modelHash` Is a Label — Making the Construction Semantically Equivalent to a Signed OAuth Claim

**Attack:**

Section 2 defines `modelHash` as *"Hash of model weights/identifier (field element)"* and Section 3 explicitly carves out execution binding as out of scope: *"Bolyra proves AUTHORIZATION binding … it does NOT attest that the authorized model was the one that ACTUALLY executed the inference."*

This means `modelHash` can be — and in practice will be — a hash of a published string identifier like `"claude-sonnet-4-6-20250514"`, not a commitment over actual model weights. Anthropic signs `deploymentAuthorization = Poseidon3(hash("claude-sonnet-4-6"), operatorPkAx, operatorPkAy)`. The semantic content of this attestation is: **"Anthropic authorized this operator to deploy the product they call claude-sonnet-4-6."**

This is identical to what Anthropic's OAuth AS can assert by issuing a DPoP-bound signed JWT with claim `"model_id": "claude-sonnet-4-6"` to the operator's registered key. Both constructions prove authorization of a label by the same issuer. The ZK circuit proves: (a) the operator holds a private key whose public counterpart Anthropic authorized, (b) the label committed in the credential matches the label Anthropic attested. A DPoP-bound signed JWT proves the same two properties with zero circuit constraints and standard RFC library support.

The only escape is if `modelHash` is a hash of verifiable model weights published in a trusted transparency log, making it a commitment to execution behavior. But the construction does not specify this, and the NCUA/FINRA scenarios do not demonstrate it. Section 8(a) says a SPIRE server is operator-controlled — but if Anthropic is the provider and the AS, neither is operator-controlled. The construction's argument against the baseline applies to *self-operated* trust roots, not to the scenario where the model provider operates both the attestation oracle and the OAuth AS.

**Why it works / why it fails against the construction:**

The construction survives this attack only if it defines `modelHash` as a commitment to a verifiably reproducible model artifact (e.g., a hash over ONNX weights in a transparency log, verifiable by a third party). As written, `modelHash` is an opaque field element — the circuit enforces that a signature over it verifies, but says nothing about what the element commits to. Without that definition, the "cryptographic binding to a named model instance" claim reduces to "cryptographic binding to a string Anthropic chose to sign," which is exactly what a signed JWT achieves.

**In-threat-model?** No — the construction's gap-to-close states it "must prove RFC 8693 token exchange and DPoP cannot achieve (a)+(c) simultaneously." Section 8 does not demonstrate this for the case where the provider is the AS issuing DPoP-bound signed JWTs. The construction must either define `modelHash` rigorously (commit to verifiable artifacts, not string identifiers) or concede that for authorization-only claims, the baseline achieves the same semantic guarantee at lower complexity.

---

### Attack 4: RFC 8693 Token Exchange Covers the Delegation Chain Without ZK

**Attack:**

The Section 7 FINRA scenario implies agent chains: an orchestrator agent delegates to a sub-agent for order-routing recommendations. The construction provides `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a delegation-chain linking primitive (referenced in Section 5 as connecting to Section 5 of the Bolyra spec). But RFC 8693 OAuth 2.0 Token Exchange already supports verifiable delegation chains through `actor` and `may_act` claims in exchanged tokens.

A FINRA examiner could verify: original token issued to principal P with `model_id: sonnet`, exchanged for delegation token naming sub-agent A as `actor`, with `scope: order_flow_access`. The chain is fully auditable. With signed JWT introspection response, the entire chain is offline-verifiable. With DPoP, each hop is sender-constrained to the agent's key. The AS sees each exchange — but in the FINRA model, the broker-dealer's internal AS IS the authority; regulator visibility into the AS logs is a feature, not a bug (FINRA 3110 requires supervisory records).

The construction's `scopeCommitment` is a hash that hides the bitmask behind a commitment, but in the regulated broker-dealer context, the examiner is entitled to see the full scope. Hiding it from the examiner is not a design goal of the FINRA scenario; the scenario requires proving the scope was authorized, which a signed JWT achieves directly.

**Why it works / why it fails against the construction:**

The construction's delegation chain design (Section 5 of the broader Bolyra spec) may have stronger privacy properties for multi-hop delegation where intermediate hops should not be visible to end verifiers. But the Section 7 FINRA scenario does not require hidden intermediate delegation — it requires proving authorization at the transaction level. RFC 8693 is sufficient for that scenario, and invoking it here exposes that the construction's complexity (23,550 constraints, PLONK prover, on-chain registry, HSM key ceremony) may not be load-bearing for the stated regulatory use cases.

**In-threat-model?** No — the construction's stated gap-to-close requires proving "RFC 8693 token exchange and DPoP cannot achieve (a)+(c) simultaneously." For the FINRA scenario, the construction does not demonstrate that (c) — verifier learns ONLY `{model_hash, operator_pk, permission_bitmask, message_hash}` — is a regulatory requirement rather than a design preference. If (c) is optional in regulated contexts, the RFC 8693 baseline is sufficient and the ZK overhead is unjustified.


## Persona: spiffe_engineer

### Attack 1: SPIFFE Federation Already Closes Your Root-of-Trust Gap

**Attack:** Section 8(a) claims SPIFFE fails because "the SPIRE server is operator-controlled" and an operator can register `spiffe://anthropic.com/models/sonnet-4-6` for a process running Opus. This is only true if you collapse the trust domain onto the operator. With SPIFFE federation, Anthropic operates its own trust domain (`spiffe://anthropic.com/`). Only Anthropic's SPIRE server issues SVIDs under that path. An operator SPIRE instance at `spiffe://acme.com/` cannot mint SVIDs claiming Anthropic-namespace identity — that requires explicit federation with Anthropic's bundle endpoint, which Anthropic controls. The operator-bound deployment authorization you describe in Section 2 is exactly what federation already provides: Anthropic vouches for `(model, operator)` pairs by issuing federated SVIDs scoped to `spiffe://anthropic.com/models/sonnet-4-6/operators/acme`. A WIMSE workload token carrying this SVID as the subject, DPoP-bound to the operator's ephemeral key, gives you non-malleability at the protocol layer — no ZK circuit required.

**Why it works / why it fails against the construction:** The construction never distinguishes between a SPIFFE single-trust-domain deployment (where this attack holds) and a properly federated multi-domain deployment (where it does not). The construction's refutation in Section 8(a) is aimed at the weak deployment. Against a federated Anthropic trust domain, the argument collapses: the Bolyra construction's provider registry + provider EdDSA key (Section 2, constraint 2) is isomorphic to a SPIFFE bundle endpoint — it's just a different encoding of "Anthropic's key is the root of trust for model identity claims." The ZK layer adds proof-of-knowledge of a private witness, but WIMSE already has selective disclosure of SVID attributes in scope via BBS+ signatures on VC payloads.

**In-threat-model?** No — the construction must explain why a federated Anthropic SPIFFE trust domain (with Anthropic-operated bundle endpoint) fails to provide the `providerRegistryRoot` equivalent, and why BBS+ selective disclosure over a federated SVID fails to match property (c) (verifier learns only the fingerprint tuple). Currently the construction refutes only the naive single-trust-domain straw man.

---

### Attack 2: `modelHash` Is a Provider-Attested Label, Not a Weight Binding — The Title Is Misleading

**Attack:** The circuit title is "Cryptographic model-instance binding." The `modelHash` is declared as "Hash of model weights/identifier" in Section 2, private inputs. But:

1. `modelHash` is a private input — **the operator supplies it**. The circuit does not derive `modelHash` from weights; it takes it as given.
2. The provider signs `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` at deployment-agreement time (Section 2, enrollment protocol). The provider is signing whatever value the operator presented as `modelHash` during the deployment agreement — nothing in the protocol requires that value to equal `SHA256(actual_weights_blob)`.
3. If Anthropic's deployment-authorization signing oracle accepts arbitrary `modelHash` labels (e.g., the string `"sonnet-4-6"` hashed to a field element), then `modelHash_sonnet` is semantically a version label, not a cryptographic hash of specific weights. Two different Sonnet 4.6 checkpoint versions with different fine-tuning would share the same `modelHash` if Anthropic doesn't re-issue attestations per checkpoint.

The non-malleability argument in Section 3 (MODEL-BIND-FORGE) holds cryptographically — an Opus key cannot produce a proof claiming Sonnet's `modelHash`. But the security property is: "the right label was used," not "the right model ran." The title's claim of "model-instance binding" is overstated; it is "provider-label binding." A SPIFFE SVID URI `spiffe://anthropic.com/models/sonnet-4-6` carries exactly the same semantic content and makes no stronger execution claims.

**Why it works / why it fails:** The construction explicitly disclaims execution binding in Section 1 ("does NOT attest that the authorized model was the one that ACTUALLY executed the inference"). But the scenarios in Section 7 (NCUA audit: "only approved models touched PII files") and the title imply weight-level instance binding. The regulatory scenarios require the auditor to trust that `modelHash_sonnet` maps injectively to a specific set of weights — a mapping that lives entirely outside the ZK construction, in Anthropic's operational procedures. The ZK circuit proves nothing about this mapping.

**In-threat-model?** Yes (the construction survives on its own stated scope) — but only if the claim is narrowed to "authorization-label binding" rather than "model-instance binding." The current title and several scenario descriptions overstate the cryptographic guarantee. A SPIFFE engineer reading the NCUA scenario would implement this with a federated SVID carrying `x-model-hash` as a verified claim, which is operationally equivalent and doesn't require a new protocol.

---

### Attack 3: 30-Entry Root History Buffer Creates an Unspecified Revocation Window

**Attack:** Section 4 (Key Rotation Survival) states: "Old proofs remain valid against old Merkle roots stored in the 30-entry root history buffer." The construction does not specify:

- How frequently the Merkle root is updated (required to bound the revocation window).
- Whether revocation of a credential requires waiting for the buffer to flush (30 root updates).
- Who controls root update cadence and whether this is an on-chain parameter that an operator could slow to extend revocation bypass.

Concretely: SECU (Section 7) discovers that a compromised agent credential was enrolled. SECU removes the credential from the Merkle tree. But the adversary holds the credential commitment and a valid proof against one of the 30 buffered historical roots. Until 30 subsequent root updates occur — which, in a low-activity deployment, might take days — the revoked credential generates valid proofs. The nullifier mechanism (`nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`) prevents nullifier reuse only if a nullifier registry is maintained on-chain. The construction does not specify this registry, its cost, or its liveness requirements.

By contrast, SPIFFE SVIDs have a well-specified TTL (typically 1 hour for X.509 SVIDs, configurable per-workload via SPIRE server policy). Revocation is synchronous: an expired SVID fails verification without historical buffer semantics. The WIMSE architecture inherits this. Bolyra's 30-root buffer trades revocation liveness for proof validity across root updates — but without bounding the update cadence, the revocation window is unbounded.

**Why it works / why it fails:** This is not a cryptographic attack on the ZK construction. It is a protocol-completeness attack. The circuit is correct; the deployment specification is incomplete. A FINRA examiner (Section 7, Scenario 2) discovering a compromised credential would ask: "How long after revocation does that credential remain usable?" The construction has no answer.

**In-threat-model?** No — the construction must specify root update cadence (e.g., "root updated at minimum every T minutes"), nullifier registry architecture, and the maximum revocation window as a function of T and buffer size 30.

---

### Attack 4: `sessionNonce` Source Is Unspecified — Prover-Chosen Nonces Enable Selective Replay

**Attack:** `sessionNonce` is listed as a public input (signal index 7, Section 2). The nullifier `Poseidon2(credentialCommitment, sessionNonce)` is unique per `(credential, nonce)` pair and is output as `nullifierHash`. The construction requires nullifiers to be checked to prevent double-spend. But:

1. **Who generates `sessionNonce`?** If the prover (agent) chooses the nonce, they can select any nonce to produce a fresh nullifier for a replayed credential. Nullifier uniqueness does not prevent replay if the nonce space is prover-controlled.
2. **If the verifier generates the nonce (challenge-response):** Proof generation is now interactive. Async audit log scenarios (NCUA examiner receives proofs days after generation, Section 7) require non-interactive proofs. A verifier-supplied nonce breaks this.
3. **No nullifier registry is specified.** Where are nullifiers stored? If on-chain, at what gas cost per proof? Who pays? If off-chain (verifier-maintained), what happens when the verifier DB is lost or a new verifier joins?

DPoP (RFC 9449) solves this for HTTP: the `jti` claim is verifier-checked against a short-term cache, the `htm`/`htu` bind to the specific request, and the nonce is verifier-issued per-session via `DPoP-Nonce` header. The anti-replay protocol is fully specified. WIMSE inherits this for workload token binding. Bolyra specifies the math for anti-replay (the nullifier hash) but not the protocol (nonce generation, nullifier storage, replay detection).

**Why it works / why it fails:** The construction's non-malleability proof in Section 4 assumes nullifiers are checked — but never specifies the checking mechanism. A correct implementation might handle this, but the construction as written leaves the protocol gap open. An implementation that uses a monotonic timestamp as `sessionNonce` would allow replay within the same timestamp granularity. An implementation that uses a random prover-chosen nonce has no replay protection.

**In-threat-model?** No — the construction must specify the nonce generation protocol (verifier-issued challenge vs. globally unique prover-chosen value), the nullifier registry architecture, and the anti-replay guarantee in terms of bounded time or bounded replay window. Without this, the `nullifierHash` output is a well-defined hash of undefined inputs.
