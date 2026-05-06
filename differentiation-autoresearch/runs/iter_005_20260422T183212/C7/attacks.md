# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

### Attack 1: "Authorization ≠ Execution" Is a Regulatory Non-Starter

- **Attack:** Section 3 openly concedes: "The construction does not prove that the physical process generating the tool-call output actually loaded the weights corresponding to modelHash at inference time." The construction then reframes this as "authorization binding, not runtime execution binding." But the SECU/NCUA scenario in Section 7 claims to solve *exactly the problem* the construction just said it can't solve: "NCUA examiners require proof that only operators authorized for approved model tiers... processed member data." What NCUA actually cares about — and what "processed member data" means — is *which model ran*, not *which paper license existed*. A credit union's CISO will ask: "So your proof tells me SECU was allowed to run Sonnet, but not that Sonnet actually ran?" The answer is yes. WorkOS + AWS Nitro Enclave attestation (available today, NIST-approved, no ZK) answers the harder question: the Nitro attestation PCR measurement proves the model binary loaded in the enclave. Bolyra answers a weaker question and dresses it in cryptographic language that will confuse, not persuade, a compliance officer.

- **Why it works / why it fails against the construction:** The construction explicitly scopes this out as "outside the threat model," which is honest but fatal for the regulatory narrative. The claim is that authorization binding is "the operative security property" for billing disputes and contractual compliance — but Section 7's concrete scenario (NCUA audit) describes a runtime compliance question. The construction's own use case doesn't fit its own threat model scope.

- **In-threat-model?** No. The construction must either (a) drop the NCUA/runtime scenario from Section 7 or (b) close the gap with a TEE attestation layer and specify how it composes with the ZK circuit. Leaving both in the document is contradictory.

---

### Attack 2: Provider Cooperation Is a Chicken-and-Egg Blocker, Not a Design Detail

- **Attack:** Section 2 (Enrollment protocol) requires Anthropic to: generate a Baby Jubjub keypair in an HSM; run a key ceremony; publish a transparency log entry; and sign per-operator `deploymentAuthorization = Poseidon3(modelHash, operatorPkAx, operatorPkAy)` for every credit union that licenses a model. Anthropic currently issues OAuth client credentials and API keys — standard RFC 6749 flows. Baby Jubjub and Poseidon3 are not in Anthropic's production signing stack. Auth0 and WorkOS work with the OAuth infrastructure Anthropic already operates. Bolyra requires Anthropic to adopt a non-standard cryptographic protocol, instrument every deployment agreement with a new signing ceremony, maintain an HSM-backed BJJ key, and respond to per-operator revocation events. The construction's "concrete deployment scenario" (Section 7, step 2) reads: "Anthropic computes Poseidon3(modelHash_sonnet, secuPkAx, secuPkAy) and signs it." Who tells Anthropic to do this? How does this get into Anthropic's API dashboard? What SLA does SECU get for attestation issuance? The construction treats provider cooperation as an enrollment detail when it is actually the core distribution question. If Anthropic won't run the ceremony, the construction has zero deployable operators — solo founder or not.

- **Why it works / why it fails against the construction:** The construction gives no answer. Section 7 describes a complete deployment flow as if Anthropic's participation is assumed. The threat model (Section 3) correctly notes the provider BJJ key is HSM-held and governance-controlled — but this assumes the HSM exists. There is no mention of provider incentive, API surface, or integration agreement. WorkOS requires zero changes from Anthropic.

- **In-threat-model?** No. The construction must specify a realistic provider onboarding path or acknowledge that it is currently a paper protocol requiring a bilateral ecosystem change the author does not control.

---

### Attack 3: Non-NIST Cryptography Fails the Compliance Test the Construction Claims to Solve

- **Attack:** Baby Jubjub (a=168700, d=168696), Poseidon2/3/5, and PLONK are not in any NIST publication, FIPS 140-3 module, or FFIEC guidance. Credit unions subject to NCUA examination (Section 7's exact scenario) must follow FFIEC IT Examination Handbook guidance, which requires NIST-approved cryptographic algorithms for protecting member data. NCUA's Information Security examination procedures explicitly reference NIST SP 800-57 key management and FIPS-approved algorithms. A CISO presenting a ZK attestation circuit built on Poseidon and Baby Jubjub to an NCUA examiner will be asked: "Where is the FIPS 140-3 validation for your hash function?" There is none. Poseidon is designed for ZK-circuit efficiency, not for NIST compliance. Auth0 and WorkOS use RS256/ES256 (NIST P-256, FIPS 186-5) and HMAC-SHA256 — all FIPS-validated. The construction's primary regulatory selling point (Section 7: NCUA audit) collapses because the cryptographic primitives fail NCUA's own compliance framework.

- **Why it works / why it fails against the construction:** The construction never mentions FIPS compliance or NIST alignment. It optimizes for ZK-circuit constraint count (Section 6) rather than regulatory cryptographic certification. The gap is structural: ZK-friendly hash functions (Poseidon, Rescue) are not FIPS-validated, and Baby Jubjub is not a NIST-approved curve. The construction cannot claim regulatory compliance while using non-compliant primitives.

- **In-threat-model?** No. The construction must either (a) identify a FIPS-validated ZK stack (currently none exists for PLONK + Poseidon), (b) scope out regulated financial institutions as target customers, or (c) acknowledge the regulatory cryptography gap and provide a migration path to NIST-approved primitives when they become available in ZK contexts.

---

### Attack 4: The Fingerprint Lookup Problem Undoes Verifier Privacy

- **Attack:** The public output `modelOperatorFingerprint = Poseidon3(modelHash, operatorPkAx, permissionBitmask)` (Section 2, constraint 12) is a hash — it proves a model class was used, but the verifier cannot read it. For the NCUA examiner to confirm "this PII operation was authorized under Opus" (Section 7, step 5), they need a mapping from `modelOperatorFingerprint` → `"Claude Opus 4.6"`. That mapping must be published somewhere: either Anthropic publishes `{modelHash → model_name}` as a public registry, or SECU publishes it, or the proof system includes a range proof over known model hashes. The construction is silent on this. If Anthropic publishes `modelHash → model_name`, an adversary can enumerate all enrolled model hashes by querying the registry — partially deanonymizing the construction. If SECU publishes it, the privacy argument weakens (verifier now trusts SECU's mapping, which is operator-asserted). If no mapping is published, the NCUA examiner receives an opaque Poseidon3 value and cannot perform the audit the construction promises. WorkOS puts `"claude-sonnet-4-6"` in a JWT `model_id` claim — human-readable, auditable, no translation layer, no privacy/lookup tradeoff.

- **Why it works / why it fails against the construction:** The construction describes the fingerprint as a "public binding tuple" (Section 2) and says the examiner "confirms the authorized model class (Sonnet vs Opus)" (Section 7, step 5) but never explains how the examiner performs this confirmation from an opaque hash. This is a usability gap that becomes a compliance gap when the examiner cannot distinguish Sonnet from Opus without a trusted external registry.

- **In-threat-model?** No. The construction must specify the fingerprint resolution mechanism — including its trust model, who publishes the mapping, and how it avoids reintroducing the operator self-assertion problem it claims to have eliminated.


## Persona: cryptographer

*Stance: Authorization binding claims without a simulation-extractability proof, a provider-namespace binding, or a pinned-SRS assumption are marketing dressed in Poseidon.*

---

### Attack 1: Knowledge Soundness ≠ Non-Malleability — The Simulation-Extractability Gap

**Attack:**
The adversary receives a corpus of valid proofs `{π_i}` for legitimately enrolled Opus credentials (oracle access to the prover is permitted by the MODEL-BIND-FORGE v2 game — the adversary "observes arbitrary valid proofs for other models"). They then attempt to produce a fresh valid proof `π*` for a related public-signal vector, e.g. one where `modelOperatorFingerprint` has been substituted or `scopeCommitment` has been zeroed, without knowing any valid witness for the new statement.

**Why it matters:**
The security argument (Section 4) cites only **A3: knowledge soundness of PLONK in the AGM + ROM**. Knowledge soundness is an existential property: *given a prover that outputs a valid proof, an extractor can recover the witness*. It says nothing about what a computationally bounded adversary can do *given oracle access to valid proofs*. That property is **simulation extractability (SE)**, and standard PLONK does not achieve it. Groth and Maller ("Snarky Signatures," 2019) and Lipmaa et al. ("Simulation-Extractable SNARKs," 2021) both demonstrate that PLONK-style systems require an explicit SE transformation (e.g., a non-interactive Fiat-Shamir composition with domain-separated challenges and a trapdoor-free commitment) to achieve SE. The standard Fiat-Shamir-instantiated PLONK shipped in most circuit frameworks (circom+snarkjs, gnark, noir) is **not SE by default**.

Requirement (a) in `gap_to_close` reads: *"binding is non-malleable — attacker with an Opus key cannot forge a proof saying 'Sonnet made this call'"*. Non-malleability of proofs requires SE, not knowledge soundness. The reduction sketch in Section 4 reduces only to A1/A2/A3; it never invokes a simulation-extractability assumption, because the construction as written does not have one. The gap: a proof-mauling adversary who sees valid Sonnet proofs from other operators (permitted by the game) might transform one into a fresh proof accepted by the verifier, without triggering the extractor that knowledge soundness guarantees.

**In-threat-model?** **No.** The game model in Section 3 permits the adversary to observe valid proofs, and the non-malleability claim (requirement a) requires SE-PLONK or a non-malleability compiler on top of PLONK. The construction must either (a) cite a concrete SE instantiation (e.g., use a simulation-extractable variant such as Plonky2 with an SE Fiat-Shamir transform, or Groth16 with simulation-extractable recursive composition), (b) add SE as a named assumption A4, and (c) modify the reduction to invoke A4 explicitly when handling the case where the adversary's proof was derived from observed proofs rather than from scratch.

---

### Attack 2: Provider Namespace Confusion — Cross-Certifier Impersonation

**Attack:**
A second legitimately enrolled model provider — call them Provider B (e.g., a different AI lab with on-chain key `providerPkB`) — signs a `deploymentAuthorization = Poseidon3(modelHash_sonnet, adversaryPkAx, adversaryPkAy)` where `modelHash_sonnet` is Anthropic's published model hash for Claude Sonnet 4.6. Provider B is enrolled in the `providerRegistryRoot` tree (depth-8, up to 256 providers). The adversary, authorized by Provider B, enrolls a valid credential with `modelHash_sonnet` and generates a valid PLONK proof. The verifier confirms the proof against `providerRegistryRoot` — which includes Provider B's key — and the proof verifies.

**Why it works:**
The circuit (constraint 2) verifies:
1. `providerKeyCommitment = Poseidon2(providerPkAx, providerPkAy)` is a leaf in the tree rooted at `providerRegistryRoot`.
2. `EdDSA.Verify(providerPk, Poseidon3(modelHash, operatorPkAx, operatorPkAy), providerSig) = 1`.

The circuit does **not** verify that `providerPk` is the *authoritative issuer* for the `modelHash` namespace. The provider registry is a flat set of enrolled public keys, not a mapping `(providerPk) → (authorized modelHash namespace)`. Any enrolled provider can sign a deployment authorization for any `modelHash`, including one published by a different provider.

Section 2.e explicitly frames this as a feature: *"the verifier confirms 'an enrolled provider authorized this model' without learning which provider."* But this is precisely the attack surface. The verifier learns only `providerRegistryRoot` — a hash of the set of enrolled keys. They cannot distinguish "Anthropic authorized Sonnet" from "Provider B authorized Sonnet." For the SECU/NCUA scenario in Section 7, an NCUA examiner accepting `modelOperatorFingerprint` as proof of "Anthropic-authorized Sonnet" is trusting that only Anthropic can sign over `modelHash_sonnet` — but the circuit has no such constraint.

The threat model in Section 3 (PROVIDER-FORGE game) assumes the adversary *does not control the provider BJJ key* and *does not control the registry*. Provider B is neither of those — they legitimately enrolled. The PROVIDER-FORGE game does not model a scenario where a legitimately enrolled but wrong-namespace provider issues cross-certifications.

**In-threat-model?** **No.** The construction needs a namespace binding constraint: the registry should map `providerPk → authorizedModelHashPrefix` (or a range check, or an explicit `(providerPk, modelHash)` enrollment) so the circuit can verify `this providerPk is the designated authority for this modelHash`. Without it, the provider registry is a weak Sybil-resistance mechanism, not an authorization root of trust. This could be addressed by changing the registry leaf from `Poseidon2(providerPkAx, providerPkAy)` to `Poseidon3(providerPkAx, providerPkAy, modelNamespaceHash)` and adding constraint 2.5: `BinaryMerkleRoot(8)` on the combined leaf.

---

### Attack 3: modelHash Semantic Opacity — Verifier Cannot Distinguish Claimed Models

**Attack:**
The verifier receives public output `modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask)`. All three inputs are **private witnesses** — the verifier sees only the Poseidon3 hash, not the pre-images. The adversary enrolls a credential using `modelHash_opus` (Opus) but sets `permissionBitmask` to a value such that `Poseidon3(modelHash_opus, adversaryPkAx, bitmask_crafted) = Poseidon3(modelHash_sonnet, victimPkAx, bitmask_legit)`. Short of a Poseidon3 collision (breaks A1), this cannot happen — but the underlying issue is that the verifier *has no independent way to interpret the fingerprint's semantics* without a pre-image registry.

**Why it works as a system-level attack (not a cryptographic break):**
Section 7 states: *"The `modelOperatorFingerprint` confirms the authorized model class (Sonnet vs Opus) without revealing SECU's session tokens."* For this to hold operationally, the NCUA examiner must be able to check "fingerprint X corresponds to Sonnet." But the examiner can only do this if they have access to the expected values `(modelHash_sonnet, secuPkAx, permBitmask_target)` to recompute `Poseidon3(...)` and compare. The construction provides no mechanism for this:

- `modelHash` is never published on-chain (the provider attestation tuples are "NOT published to a public registry" — Section 2, enrollment protocol).
- `operatorPubkeyAx` is private.
- `permissionBitmask` is private.

Without a separate out-of-band registry binding fingerprint values to model identities, the verifier's statement is "an enrolled provider authorized some model for some operator under some permission tier" — not "Anthropic authorized Sonnet 4.6." The construction presents a complete ZK argument for authorization binding but then relies on implicit semantic resolution that is outside the cryptographic model and unspecified.

**In-threat-model?** **Partially.** The cryptographic binding is sound; the semantic resolution is a protocol gap rather than a cryptographic break. The construction must specify a public fingerprint directory (a signed mapping `modelOperatorFingerprint → (modelName, operatorIdentity)` published by the provider) or change the circuit to take `modelHash` as a public input with the constraint that it matches an expected value supplied by the verifier. The latter would break privacy for the model; the former requires the provider to publish a lookup table that partially deanonymizes the fingerprint. Neither path is trivial, and neither is described.

---

### Attack 4: Subverted Universal SRS — Complete Security Collapse Absent from Threat Model

**Attack:**
The PLONK universal SRS is generated in a powers-of-tau ceremony. If any single participant in the ceremony retains the secret `τ` (the "toxic waste"), they can:
- Produce a valid PLONK proof for *any* public-signal vector, including any `modelOperatorFingerprint` and `agentMerkleRoot`, without knowing any valid witness.
- This breaks A3 entirely, defeating all three reductions simultaneously.

**Why it is in-scope:**
The threat model in Section 3 enumerates adversary capabilities and exclusions: adversary does not control `providerPk`, does not control the registry. It never enumerates who ran the SRS ceremony or what trust assumptions apply to it. The named assumptions in Section 4 state A3 as "Knowledge soundness of PLONK in the AGM + ROM" — but this assumption holds only under an honestly generated SRS. If `τ` is compromised, knowledge soundness fails unconditionally.

This is not a theoretical concern. For the SECU enterprise deployment in Section 7, the question "who ran the powers-of-tau?" has a concrete answer: either Bolyra, Anthropic, or a public MPC ceremony (e.g., Hermez or the Ethereum KZG ceremony). Each choice carries different trust assumptions. The PROVIDER-FORGE and MODEL-BIND-FORGE games define adversary capabilities only over the application layer; they are silent on setup compromise, which is a separate and stronger adversary class.

The construction should either (a) add A4: *"The PLONK SRS was generated by an MPC in which at least one participant was honest (standard trusted-setup assumption)"* with a citation to the specific ceremony used, or (b) reference a transparent setup variant (e.g., STARK-based or FRI-based proving) that eliminates the SRS entirely. As written, the construction inherits the entire trust model of a centralized or under-specified key generation ceremony without disclosing it, which is precisely the "marketing without a threat model" failure mode.

**In-threat-model?** **No — absent from threat model entirely.** A subverted SRS adversary breaks all named security properties in a single move and is not captured by any game in Section 3. The construction must make the SRS trust assumption explicit, name the ceremony (or specify that a transparent proving system is used), and include SRS compromise as a named exclusion from the threat model with justification.


## Persona: cu_ciso

---

### Attack 1: The NCUA Mapping Black Hole

**Attack:** I walk into my next Part 748 examination and the examiner pulls up the FFIEC CAT questionnaire, Domain 3 (Cybersecurity Controls), and asks me to demonstrate my access controls for AI systems processing member PII. I hand them a PLONK proof with public signals `{agentMerkleRoot, nullifierHash, scopeCommitment, messageHash, modelOperatorFingerprint}`. Every one of those signals is an opaque field element — a 254-bit integer. The examiner has no idea what they're looking at. My board has no idea what they're looking at. My vendor management officer needs to map this to a named control in my Information Security Program (NCUA Part 748 Appendix B) and my GLBA Safeguards Rule §314.4 documentation. The construction never does this mapping.

**Why it works / why it fails:** The construction is technically precise about what it proves but operationally silent about how that proof maps to any regulatory artifact an examiner will accept. Section 7 (SECU scenario) says "the examiner can confirm 'this PII operation was authorized under Opus'" but does not identify: (a) which Part 748 control this satisfies, (b) what the examiner's workpaper entry looks like, (c) whether this constitutes a "detective control" or "preventive control" under FFIEC CAT. The construction calls the NCUA examiner's concern "was the operator contractually and cryptographically authorized to use this model for this call?" — but no NCUA examination question is framed that way. Real exam questions are framed as: "Do you have a process to ensure third-party systems accessing member data are authorized?" This is an institutional answer, not a proof system.

**In-threat-model?** No — the construction must address this. It needs a one-to-one mapping table: `modelOperatorFingerprint` → satisfies NCUA Part 748 §II(B)(1) (access controls); `permissionBitmask` + `scopeCommitment` → maps to GLBA §314.4(c)(3) (access controls for customer information); `nullifierHash` audit log → satisfies FFIEC CAT IL3 logging requirement. Without this, no credit union CISO can justify the integration cost to their board or survive an exam. The cryptography is sound; the regulatory translation layer is missing entirely.

---

### Attack 2: The Operator Key Custody Problem

**Attack:** Section 2 (Enrollment Protocol) specifies that the provider (Anthropic) generates their BJJ keypair "in an HSM" with a key ceremony. The operator — SECU in Section 7 — "generates operator BJJ keypairs per deployment environment." No HSM requirement. No key ceremony requirement. No specification of where the private key material lives: software keystore, cloud KMS, developer laptop, CI/CD secrets manager. I ask: where does the member secret live? The construction's answer for the operator is: wherever the operator puts it.

**Why it works / why it fails:** The construction's non-malleability guarantee (Section 4, MODEL-BIND-FORGE) is only as strong as the operator's key custody. If the operator BJJ private key is stored in an AWS Secrets Manager without HSM backing, or worse in a `.env` file, then the "authorization binding" can be forged by anyone who exfiltrates that key — they can enroll credentials and sign `credentialCommitment` for any attested model without being the authorized operator. The construction explicitly relies on EdDSA unforgeability (A2), but A2 holds only if the signing key is not compromised. NCUA Part 748 requires that encryption keys used to protect member data be managed with controls equivalent to the sensitivity of the data. GLBA Safeguards Rule §314.4(f) requires a "process for managing and overseeing service provider arrangements" — which includes key management for cryptographic controls. The construction never specifies minimum key custody requirements for the operator credential signing key, creating a gap that turns a cryptographic guarantee into an operational assumption.

**In-threat-model?** No — the construction must specify minimum operator key custody requirements as a deployment prerequisite. Specifically: (a) the operator BJJ private key MUST be generated and stored in a FIPS 140-2 Level 2 (or higher) HSM or equivalent; (b) key access must be audited; (c) key rotation procedures must be defined. Without this, an examiner reviewing the deployment will find no compensating control for the "what if the operator key leaks" scenario, and the authorization binding guarantee collapses.

---

### Attack 3: The 2am Incident Response Failure

**Attack:** It's 2am. My SOC gets an alert: member accounts show unauthorized transfers. My Tier 1 ops team opens the incident runbook. They need to answer: which AI agent made which calls, against which member accounts, in the last 4 hours. They have a database of PLONK proofs with `messageHash` values. `messageHash = Poseidon(messagePlaintext)` — the plaintext is a private witness, never stored by the verifier. My ops team cannot reverse a Poseidon hash. The `messagePlaintext` was known only to the prover at proof generation time.

**Why it works / why it fails:** The construction is architecturally designed to prevent the verifier from learning message content — Section 2 explicitly states that `messagePlaintext` is a private input and the verifier learns only `messageHash`. This is correct for privacy-preserving audits. But it creates an irreconcilable tension with NCUA's incident response requirements under Part 748 Appendix B §III(C) (response program must include "procedures for notifying appropriate personnel" and "determining the nature and scope of a compromise"). At incident time, I need to reconstruct which calls touched which member accounts. If the prover (the agent infrastructure) is also compromised, or if the operator's plaintext logs are unavailable, the `messageHash` values in my audit database are forensically useless. I cannot satisfy a breach notification requirement or a post-incident examiner review with a Poseidon hash. The construction says in Section 7 that the examiner "can confirm 'this PII operation was authorized under Opus' without learning which member's data was involved" — which is the privacy goal — but this same property makes incident triage impossible without a separate, parallel plaintext logging system, which the construction never specifies.

**In-threat-model?** No — the construction must specify a complementary plaintext audit log architecture that is (a) maintained by the operator separate from the proof system, (b) correlated to `messageHash` values so that operators can de-anonymize at incident time under authorization, and (c) protected under GLBA Safeguards Rule §314.4(i) (encryption of customer information). The ZK layer provides regulatory reporting privacy; the plaintext layer provides incident response capability. These must coexist, and the construction currently offers no guidance on this, leaving a gap that any NCUA examiner will find immediately.

---

### Attack 4: Third-Party Vendor Risk — Anthropic as Unaudited Root of Trust

**Attack:** My vendor management policy, required under NCUA Letter to Credit Unions 07-CU-13 and FFIEC IT Examination Handbook (Outsourcing Technology Services), requires that any third-party providing critical services be subject to due diligence including: (a) SOC 2 Type II report or equivalent; (b) business continuity and disaster recovery documentation; (c) incident notification agreements; (d) sub-contractor disclosure. Anthropic's HSM-held BJJ signing key is the root of trust for the entire construction. If Anthropic's HSM is compromised, every `modelOperatorFingerprint` ever produced is forgeable retroactively — an attacker with the provider private key can issue `deploymentAuthorization` signatures for any `(modelHash, operatorPk)` pair. The construction acknowledges revocation (new Merkle root excluding the compromised key) but explicitly notes that "archival verifiers store the `providerRegistryRoot` alongside the proof" — meaning historical proofs validated against a root that included the compromised key cannot be retroactively invalidated.

**Why it works / why it fails:** The construction says the provider key ceremony involves "an HSM" and publication in "a transparency log" but specifies no audit requirements, no SOC 2 scope, no uptime SLA for the on-chain `providerRegistryRoot`, and no incident notification procedure for provider key compromise. My NCUA examiner will ask: "What is your due diligence documentation for the cryptographic root of trust provider?" I have none. The smart contract holding `providerRegistryRoot` is on an unspecified blockchain — what is the uptime SLA? What is the governance multisig structure? Who are the keyholders and what are their background check requirements? The construction mentions "governance-multisig or DAO-controlled" insertion but does not specify which, leaving a material gap in my vendor risk assessment. Additionally, the on-chain proof verification step (Section 2, "On-chain PLONK verification remains ~300K gas") introduces a dependency on blockchain availability and gas cost predictability that my core processor SLA of 99.99% availability will not tolerate without a formal BCP addendum.

**In-threat-model?** No — the construction must provide: (a) a defined SLA for the on-chain registry (uptime, finality guarantees, chain selection criteria); (b) a specification of what audit documentation (SOC 2 scope, key ceremony transcript) the provider must furnish to operator credit unions for their vendor management programs; (c) a defined incident notification procedure for provider key compromise; (d) an explicit statement of retroactive proof validity under key compromise — the current construction's "archival verifiers store the root" approach means historical binding guarantees are not absolute, and this needs to be disclosed to examiners as a residual risk.


## Persona: rfc7662_advocate

### Attack 1: AS-as-Provider Collapses the Security Gap in §8(c1)

- **Attack:** The construction's §8(c1) presents two sub-cases for how the AS knows the `model_id` claim: (i) operator self-declaration, or (ii) "AS is itself the model provider." It then dismisses case (ii) as "institutional trust, not cryptographic non-malleability." But this dismissal is incorrect. When Anthropic *is* the AS — which is the realistic deployment for every Anthropic-hosted API — the signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response §5) is **an EdDSA/ECDSA signature by Anthropic's key over `{model_id, client_id, scope}`**. The verifier independently checks this signature against Anthropic's published JWKS. No operator can alter `model_id` without breaking Anthropic's signature. The root of trust is identical: Anthropic's signing key. The construction's reduction in §4 argues "the adversary must forge an EdDSA signature to fake modelHash" — but the AS-as-provider JWT baseline makes exactly the same claim. Both constructions ultimately ask: *can the adversary forge a signature under Anthropic's key?* The answer is no in both cases. The gap the construction identifies — "the circuit enforces that a provider key enrolled on-chain signed the specific (model, operator) binding" — is also what the AS's JWKS-signed JWT achieves, just through a different serialization.

- **Why it works / why it partially fails:** The construction's counter in §8(c2)–(c4) is about **privacy** (issuance-time correlation, cleartext claim exposure), not **security** (forgery resistance). Those are real differentiators, but they are not the same property as the MODEL-BIND-FORGE game defined in §3, which has **no privacy win condition** — it only asks whether the adversary can forge a valid proof for an unauthorized model. For the narrow game defined, the AS-as-provider baseline achieves equivalent forgery resistance. The construction conflates security properties (non-malleability) with privacy properties (zero-knowledge) throughout §8 without separating the games.

- **In-threat-model?** **No — construction must address.** The MODEL-BIND-FORGE game does not include a privacy adversary. The construction must either (a) narrow its claim to "ZK privacy for an authorized verifier" and stop claiming superiority on *security* grounds over the AS-as-provider baseline, or (b) define a separate PRIVACY-LEAK game and prove the baseline fails it. As written, §8(c1)'s dismissal of case (ii) does not hold.

---

### Attack 2: `modelHash` Specification Ambiguity — the Verifier's Root of Trust Is Still Assertion-Based

- **Attack:** The private input `modelHash` is described in §2 as "Hash of model weights/identifier (field element)." This is underspecified in a way that matters cryptographically. There are two interpretations: **(A) Hash of model weights** — the hash of actual deployed parameters. **(B) Hash of an identifier string** — e.g., `Poseidon("claude-sonnet-4-6")`. In case (A): the verifier receives `modelOperatorFingerprint = Poseidon3(modelHash, opPkAx, permBitmask)` but has no way to independently compute `modelHash` without access to the weights — which are proprietary. The verifier must therefore consult an external lookup table mapping `modelHash` values to human-readable model names. That lookup table is Anthropic-maintained. The verifier's conclusion "this was Sonnet" rests entirely on Anthropic's out-of-band assertion that `modelHash_X` corresponds to Sonnet 4.6 — the same institutional trust the construction accuses the JWT baseline of requiring. In case (B): `Poseidon("claude-sonnet-4-6")` is publicly computable by anyone. The security of the binding then reduces entirely to the provider EdDSA signature over `deploymentAuthorization`, which is equivalent to a JWT claim `model_id=claude-sonnet-4-6` signed by Anthropic — indistinguishable in root-of-trust from the baseline. Neither case produces a verifier who can independently confirm model identity without either trusting Anthropic's lookup table or trusting Anthropic's signature, which is what the JWT baseline provides.

- **Why it works / why it fails against the construction:** The construction partially addresses this in §3 by scoping to "authorization binding, not runtime execution binding." But §1's claim — "proves 'this call was made by Claude Sonnet 4.6'" — implies the verifier can identify the model. If the verifier needs an Anthropic-maintained mapping from `modelHash` to "Sonnet 4.6" to interpret the fingerprint, then the claim title is misleading: the construction proves "the provider authorized the operator for some committed hash," not "the provider authorized the operator for Sonnet 4.6" in any sense the verifier can independently verify. The §7 SECU deployment scenario has the NCUA examiner confirming "the authorized model class (Sonnet vs Opus)" from `modelOperatorFingerprint` — but this requires the examiner to already know which `modelHash` values correspond to which tier. That knowledge is an out-of-band Anthropic assertion.

- **In-threat-model?** **No — construction must address.** The construction must specify whether `modelHash` is weights-based or identifier-based, and explain how the verifier maps fingerprint to model name without requiring an Anthropic-controlled lookup table. If weights-based, explain how the verifier obtains the preimage to verify the mapping. If identifier-based, the security argument collapses to "Anthropic signed this identifier string," which is what a JWT does.

---

### Attack 3: RFC 9449 DPoP Cannot Provide — but the Construction's Privacy Claim Is Weaker Than Stated

- **Attack:** Per the persona's prompt — "DPoP provides sender-constraint without any ZK. Name the property DPoP cannot provide." I name it: DPoP cannot prove a bitwise permission predicate over a hidden bitmask (§2 constraint 6, `requiredBits[i] * (1 - permBits[i]) === 0`). This is a genuine differentiator. **However**, the construction then overclaims what this buys. The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a public output, but it reveals no bits of the bitmask to the verifier. The verifier only learns "the hidden bitmask satisfied the required mask." But RFC 8693 + per-RS introspection policy achieves a functionally equivalent property: the AS filters the introspection response per RS, returning only `active: true` and the RS-specific scope subset, without revealing the full token scope to any single RS. An RS that needs to know "does this token have PII-read permission?" can ask the AS for a filtered introspection response scoped to that RS — it never sees the operator's full permission set. The AS's per-RS policy enforces "you only learn what you need to verify." This is weaker than Bolyra's predicate proof (the AS still sees the full bitmask and the RS trusts the AS's filtering), but for the stated enterprise use case (§7: NCUA examiner verifying Sonnet vs Opus tier authorization), the examiner is the verifier — and the examiner in the ZK construction also learns the `requiredScopeMask` public input, so the required bits are not hidden from them either.

- **Why it works / why it fails against the construction:** The construction's genuine advantage is that the verifier learns only a commitment to the bitmask, not its value, while still being able to verify predicate satisfaction. RFC 8693 + per-RS policy cannot hide the bitmask from the AS. This is a real ZK-specific property. But the construction's deployment scenarios don't clearly require hiding the bitmask from the verifier — the NCUA examiner needs to know "was Opus authorized for PII ops?" which requires knowing at minimum that bit. The privacy advantage is real but the scenarios don't stress-test it.

- **In-threat-model?** **Yes — construction survives** on this specific sub-property. The bitwise predicate over hidden witness is a legitimate ZK advantage. But the construction should scope this more precisely: the advantage is "verifier learns predicate result without learning bitmask," not "verifier cannot learn model identity" (which is weakened by the modelHash lookup problem in Attack 2).

---

### Attack 4: The PROVIDER-FORGE Game Ignores the On-Chain Registry as a Central Authority

- **Attack:** The construction eliminates self-attestation by requiring the provider key to be Merkle-enrolled in `providerRegistryRoot`, which is "governance-multisig or DAO-controlled" (§3). This creates a new central authority: whoever controls the registry governance can insert arbitrary provider keys. If the governance multisig is Anthropic (as it would be in the SECU deployment scenario), then the security model reduces to: "trust Anthropic not to insert rogue provider keys." This is identical to: "trust Anthropic's AS not to issue rogue `model_id` claims." Both reduce to the same institutional assumption. The construction explicitly introduces the registry as a "deployment assumption" but does not include registry governance compromise in the adversary's capabilities. An adversary who compromises the multisig (or obtains a key from it via social engineering, a compromised HSM, or a governance attack on a DAO) can insert a new provider key and then self-issue attestations for any model-operator binding. The ZK machinery then proves, with full cryptographic validity, a false claim. This attack surface does not exist in the JWT baseline because there is no on-chain registry to compromise — the AS's JWKS endpoint serves the same function but is not a shared smart contract with a governance attack surface.

- **Why it works / why it fails against the construction:** The construction acknowledges the provider key registry but frames key compromise only as "revocation = new root excluding the compromised key" (§2 enrollment protocol). It does not address the threat of malicious insertion. The PROVIDER-FORGE game (§3) only considers an adversary who "does NOT control the on-chain provider registry" — explicitly excluding this attack. But the realistic threat model for enterprise deployments includes supply-chain attacks on governance multisigs (cf. several documented DAO governance attacks in 2022–2024). The AS-as-provider JWT baseline has no equivalent on-chain attack surface.

- **In-threat-model?** **No — construction must address.** The threat model explicitly excludes registry governance compromise, but for a construction that claims to eliminate the need for AS-level trust, shifting trust to an on-chain governance multisig is not an improvement in trust surface — it is a substitution. The construction should either (a) acknowledge that the trust model requires trusting the registry governance operator (Anthropic) equivalently to trusting the OAuth AS, which narrows the privacy claim to the issuance-correlation advantage identified in §8(c2), or (b) specify a registry governance model with demonstrably stronger security properties than an OAuth AS's JWKS endpoint under the same threat model.


## Persona: spiffe_engineer

---

### Attack 1: Federated Trust-Domain Attribution — The "Operator-Controlled SPIRE" Premise Is False

**Attack:**

Section 8(a) argues that "the SPIRE server is operator-controlled. An operator running their own SPIRE deployment can register `spiffe://anthropic.com/models/sonnet-4-6` for a process actually running Opus." This is only true for self-issued SVIDs in a non-federated deployment. In the SPIFFE federation model:

- Anthropic operates the SPIRE server for trust domain `spiffe://anthropic.com/`.
- ACME Corp federates with Anthropic's bundle endpoint. Anthropic's SPIRE issues an X.509 SVID with SPIFFE ID `spiffe://anthropic.com/models/sonnet-4-6/operator/acme-corp` only after ACME authenticates and Anthropic registers the entry.
- ACME's SPIRE **cannot issue SVIDs in the `spiffe://anthropic.com/` namespace** — namespace ownership is enforced by trust bundle control.
- Cross-operator replay is structurally impossible: X.509 SVIDs are key-bound (mTLS requires possession of the corresponding private key). Observing ACME's SVID does not let Rogue Corp authenticate as ACME.

This is structurally identical to Bolyra's deployment authorization: Anthropic issues a (model, operator) binding, the operator presents it for verification. The difference is that SPIFFE does it with an X.509 SVID from a federated SPIRE server rather than an EdDSA signature over a Poseidon3 hash. The construction's Section 8(a) critique only applies to SPIFFE used without federation, which is not how you run it in production for cross-organizational model authorization.

**Why it works:** The construction does not address federated SPIFFE. Section 8 compares Bolyra against a degraded "operator runs their own SPIRE" deployment. The correct baseline is: Anthropic operates the authoritative SPIRE for `spiffe://anthropic.com/`, operators receive model-identity SVIDs from Anthropic's SPIRE, and verifiers check against Anthropic's published trust bundle.

**In-threat-model?** No — the construction must address federated SPIFFE explicitly. Section 8(a) is the load-bearing non-malleability argument; if federated SPIFFE closes the malleability gap, the differentiator collapses to privacy (claim-set hiding), not the broader set of properties claimed.

---

### Attack 2: WIMSE Transaction Tokens Are Exactly This — Contribute a Claim, Don't Fork the Stack

**Attack:**

`draft-ietf-wimse-arch` Section 5 defines **Transaction Tokens (TxTokens)**: short-lived, sender-constrained tokens that carry workload identity and request context through a call chain. The WIMSE architecture explicitly supports:

- Propagating caller identity (`sub` = SPIFFE ID of the originating workload) across service-to-service hops.
- Binding per-hop context (what the workload was doing, under what authorization).
- Sender-constraining via `cnf` (DPoP thumbprint or mTLS certificate hash).

The Bolyra `modelOperatorFingerprint` is a structured tuple `{modelHash, operatorPk, permissionBitmask}`. This maps directly to a set of TxToken claims: `model_id`, `operator_id`, `permission_tier`. The WIMSE transaction context propagation mechanism already binds these claims to the request chain.

The construction's Section 2 public signal layout — `{agentMerkleRoot, scopeCommitment, messageHash, modelOperatorFingerprint}` — is a privacy-preserving encoding of exactly what a WIMSE TxToken carries in cleartext. The appropriate contribution is: define a WIMSE extension claim `model_authorization_proof` that embeds a compact ZK commitment (a Poseidon3 fingerprint) instead of a cleartext `model_id`, and contribute the binding semantics to draft-ietf-wimse-workload-identity-bcp. Instead, the construction builds a parallel enrollment registry, a parallel proof system, and a parallel on-chain trust root — none of which is necessary if the goal is to add privacy to an existing standard.

**Why it works:** The construction never engages with WIMSE transaction token semantics. It dismisses "RFC 8693 token exchange" (Section 8, gap requirement), but RFC 8693 is not the WIMSE architecture — it's a 2019 RFC that predates the WIMSE working group. The actual WIMSE threat model is structurally equivalent to what the construction is solving.

**In-threat-model?** No — the construction must justify why a WIMSE TxToken extension (adding a ZK commitment claim to an Anthropic-issued SVID chain) is insufficient before claiming a new protocol is warranted.

---

### Attack 3: `modelHash` Is a Name, Not a Weight-Binding — It's a SPIFFE ID in Disguise

**Attack:**

Section 3 explicitly concedes: "The construction does not prove that the physical process generating the tool-call output actually loaded the weights corresponding to `modelHash` at inference time." Section 7 reinforces this: the NCUA examiner can confirm "this operator was authorized under Opus" but not that the GPU executed Opus weights.

Given this concession, `modelHash` is semantically equivalent to `spiffe://anthropic.com/models/claude-opus-4-6`. It is a name — a string identifying a model tier — whose authenticity is guaranteed by the issuing authority (Anthropic), not by a cryptographic measurement of the weights. The Poseidon3 commitment over this name (`modelOperatorFingerprint`) is a privacy-preserving encoding of a SPIFFE ID. The EdDSA provider signature over `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` is a key-bound SVID issuance in algebraic form.

The construction's privacy advantage is real — the verifier sees a hash rather than a cleartext model identifier. But the security advantage (non-malleability over the baseline) reduces to: the verifier cannot learn `modelHash` from `modelOperatorFingerprint` without breaking Poseidon collision resistance, and the binding cannot be forged without breaking EdDSA. SPIFFE with a JWT SVID carrying `model_hash` as a claim achieves the same non-malleability (Anthropic-signed JWT, verifier checks JWKS); the only delta is that Bolyra hides the claim value from the verifier.

The claim in Section 1 — "proves 'this call was made by Claude Sonnet 4.6'" — is overstated. The proof establishes "Anthropic authorized operator O to use a model identified by the string `modelHash`." Whether `modelHash` corresponds to Sonnet 4.6 is only as meaningful as the name itself. A SPIFFE ID `spiffe://anthropic.com/models/sonnet-4-6` makes the same guarantee with the same caveat.

**Why it works:** The construction's threat model (Section 3) explicitly scopes out runtime execution binding. With that scope-out, the remaining security property is name-binding with operator specificity and claim-set privacy. The first two are achievable with federated SPIFFE + JWT SVID. Only the third requires ZK. The construction should scope its claim accordingly — it is a privacy layer over workload identity, not a new identity primitive.

**In-threat-model?** Yes — the construction survives because the privacy property (hiding `modelHash` from the verifier behind a Poseidon3 commitment) is genuine and SPIFFE/WIMSE do not provide it. But the construction over-claims: it presents authorization binding as a new security property when it is an existing SPIFFE property; the novel contribution is ZK hiding of claim values. The construction should make this precise.

---

### Attack 4: One-Time Attestation Issuance Is a SPIRE Registration Entry — The On-Chain Registry Is Unnecessary Complexity

**Attack:**

The enrollment protocol (Section 2, "Model attestation per model × operator") describes:

1. When ACME signs a deployment agreement for Sonnet, Anthropic computes `deploymentAuthorization = Poseidon3(modelHash, secuPkAx, secuPkAy)` and signs it.
2. The tuple is delivered to SECU via Anthropic's authenticated API dashboard.
3. SECU embeds it in a credential commitment and inserts into a permissionless on-chain Merkle tree.

This is isomorphic to a SPIRE registration entry workflow:

1. Operator authenticates to Anthropic's SPIRE admin API.
2. Anthropic creates a registration entry: `selector: operator_id:secu; spiffe_id: spiffe://anthropic.com/models/sonnet/operator/secu`.
3. SECU's SPIRE agent receives the SVID via the Workload API.

The on-chain Merkle tree (Section 2) serves as a public credential accumulator. But the construction's own security argument (Section 2, "Why permissionless tree insertion is safe") states: "the tree is a data structure, not an access control boundary. Authorization is enforced at proof time." This means the tree provides no additional security property beyond a publicly verifiable set membership — which a certificate transparency log (RFC 9162) already provides for X.509 SVIDs, and which the SPIFFE federation bundle endpoint already provides for trust bundle distribution.

The depth-8 provider key registry supporting "up to 256 providers" is a hard-coded cap embedded in the circuit. SPIFFE trust domain federation has no such cap — trust bundles are distributed as JWKS/X.509 bundles over HTTPS with no protocol limit on enrolled keys. Adding provider #257 in Bolyra requires a circuit change. Adding a new SPIFFE trust domain requires a bundle endpoint configuration update.

**Why it works:** The on-chain registry introduces a governance dependency (Section 2: "on-chain governance controls insertion") and a circuit scalability ceiling with no operational benefit over a certificate transparency log for the non-privacy use cases. The construction must justify why on-chain accumulation is necessary rather than a signed provider key bundle published at a well-known HTTPS endpoint (which is what SPIFFE's bundle endpoint does).

**In-threat-model?** No — the construction must address why the on-chain accumulator is preferable to a transparency log + SPIFFE bundle endpoint for provider key publication. The 256-provider ceiling is a concrete operational constraint that SPIFFE federation does not impose, and the construction does not acknowledge it as a limitation.
