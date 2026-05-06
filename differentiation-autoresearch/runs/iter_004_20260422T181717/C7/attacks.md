# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

---

### Attack 1: "Authorization ≠ Execution" Concession Guts the Regulatory Use Cases

- **Attack:** The construction's own Section 3 explicitly concedes: *"This construction does not prove that the physical process generating the tool-call output actually loaded the weights corresponding to modelHash at inference time."* The adversary reads this sentence to SECU's NCUA examiner and the FDA AI Act compliance officer. C7 Scenario 4 claims "FDA/EU AI Act demands provable chain from deployed model weights to each inference output" — but Section 3 concedes Bolyra cannot provide this chain. The attack is to quote C7's own scenario list against Section 3's own scope limitation in the same procurement meeting.

- **Why it works / why it fails:** It lands because the gap is real and the construction admits it. A legitimate Opus operator can hold a valid Bolyra proof claiming "authorized for Opus" while routing every call through Llama 3. The proof is cryptographically valid. The construction's rebuttal (Section 3: "detecting runtime substitution requires hardware attestation, a complementary layer") is correct but damaging — it means Bolyra is a necessary-but-not-sufficient component, and the enterprise still needs a TEE attestation layer that Bolyra doesn't ship. The pharmacy analogy in Section 7 is honest but turns into a sales objection: "you're selling me the prescription, not the pill."

  The construction partially survives for billing and contractual compliance (SECU Scenario, tiered pricing Scenario 3), where "was the operator licensed for Opus?" is the operative question. It fails for Scenario 4 (EU AI Act, FDA) as stated. The construction never narrows its scenario list to match its actual security property.

- **In-threat-model?** No — the construction must either (a) remove Scenarios 4 and the FDA/EU AI Act framing from C7's scenario list, or (b) ship a TEE complement and describe how it composes. As written, the scenario list overclaims relative to the proof's stated scope.

---

### Attack 2: The Root of Trust Is Just PKI — And Requires Anthropic to Change Its Infrastructure

- **Attack:** Strip away the ZK layer and describe what the construction *actually* requires: Anthropic must generate a new BJJ keypair in an HSM, publish it to a transparency log, enroll it in an on-chain Merkle tree that Bolyra controls, and sign per-operator×model deployment authorization tokens in Poseidon3 hash format for every credit union customer. Auth0 already has OAuth/OIDC infrastructure that Anthropic supports today. WorkOS's MCP auth ships now and requires zero Anthropic infrastructure changes. The adversary asks in a procurement call: "Has Anthropic committed to issuing BJJ deployment authorizations? Who maintains the provider registry contract? What happens if Anthropic declines to participate?"

- **Why it works / why it fails:** The construction's entire non-malleability argument in Section 3 (Cases 2a/2b in the reduction sketch) collapses if Anthropic never issues provider attestation tuples in this format. Without provider participation, constraint 2 in the circuit cannot be satisfied with a real Anthropic key — operators would substitute their own key as "provider," which Section 8(a) correctly labels insecure (a SPIRE-style self-attestation). The construction is not a standalone protocol; it is a bilateral agreement requiring the model provider to adopt Bolyra's signing format. Auth0/WorkOS have existing distribution relationships with Anthropic. A solo founder does not.

  The construction partially survives as a design: *if* Anthropic participates, the binding is non-malleable. But the construction nowhere addresses provider onboarding — there is no Section on how Bolyra gets Anthropic to run a key ceremony. Section 2's enrollment protocol says "Anthropic generates a BJJ keypair in an HSM" as though this is a given.

- **In-threat-model?** No — the construction must address provider onboarding as a live dependency. The threat is not cryptographic forgery; it is commercial and operational: the construction's security property is conditional on a bilateral infrastructure commitment that does not exist.

---

### Attack 3: The Prover Is On the Critical Path and the Construction Does Not Say Who Runs It

- **Attack:** Section 6 estimates ~23,550 constraints and a "<5s proving target." The adversary concedes this is plausible on an Apple M-series laptop but asks: in the SECU deployment (Section 7), who runs the prover? Three options, all bad. **(a) The agent runs the prover inline** — every member loan inquiry adds 5s of CPU-bound proving to the response latency. SECU's members wait. **(b) A Bolyra proving service runs it** — SECU sends `messagePlaintext` (the private input containing the tool-call payload) to an external service, which is now a correlation oracle. This violates Section 2's privacy guarantee: the verifier learns only public outputs, but the prover service sees everything. **(c) SECU runs a proving sidecar** — SECU must operate ZK proving infrastructure at scale, add it to their SOC 2 scope, and maintain it. WorkOS issues tokens in <100ms with no infrastructure burden on SECU.

- **Why it works / why it fails:** The construction's privacy argument depends on the prover being local to the operator (so `messagePlaintext` never leaves SECU's environment). But a 5s CPU-bound proof per call is operationally untenable for high-throughput loan servicing. The construction does not address batching, async proving, or prover delegation. The attack is not about cryptography — it is about the gap between "proving time target" and "deployed production system."

  The construction partially survives if SECU only proves a sample of calls for audits (not every call), which is a plausible architecture. But Section 7 describes per-transaction proofs for NCUA audit purposes, implying every audited transaction needs a proof. The construction should specify whether proofs are generated at call time or retroactively from logs, and who holds the private inputs during retroactive proving.

- **In-threat-model?** No — the construction must specify the proving topology (inline vs. async vs. audit-sample) and address the privacy implications of prover delegation. The current text sidesteps the most operationally critical deployment question.

---

### Attack 4: The `modelHash` Is Operator-Declared and Anthropic Has No Commitment Mechanism Today

- **Attack:** The construction requires a `modelHash` — described as "hash of model weights/identifier (field element)." The adversary asks: what is this hash, concretely? Is it a hash of the model weights (billions of parameters)? A hash of a model identifier string like `"claude-sonnet-4-6"`? Who computes it? Section 2 says Anthropic computes `deploymentAuthorization = Poseidon3(modelHash, operatorPkAx, operatorPkAy)` and signs it — but if `modelHash` is just a hash of the string `"claude-sonnet-4-6"`, then the binding is to a name, not to weights. Any operator can claim any name string to Anthropic for signing. Anthropic's existing API already has a `model` parameter that the operator sets. The construction does not specify how `modelHash` is derived or how Anthropic verifies that the hash corresponds to the model the operator is actually licensed to use, prior to signing.

- **Why it works / why it fails:** If `modelHash = Hash("claude-sonnet-4-6")`, then the construction proves "this operator holds a provider-signed commitment to the string 'claude-sonnet-4-6'" — which is indistinguishable from what OAuth's `model` claim already does, except inside a ZK circuit. The construction's non-malleability argument depends on the `modelHash` having semantic meaning (binding to specific weights) that Anthropic enforces at attestation time. But Anthropic's current infrastructure does not hash model weights and sign them per-operator. The construction quietly assumes a weight-level commitment exists when Anthropic's actual attestation would likely be string-based.

  The construction survives if Anthropic publishes canonical Poseidon hashes of each model version's weights (or a commitment to their API's version identifier that is cryptographically tied to a specific deployment), but this requires Anthropic to build and maintain that commitment infrastructure. Auth0's MCP auth works with Anthropic's existing OAuth AS without any provider infrastructure changes.

- **In-threat-model?** No — the construction must specify exactly what `modelHash` is and whether it binds to weights, a deployment identifier, or a version string. The security argument in Section 3 (Cases 1–5) treats `modelHash` as a well-defined, provider-verified value, but Section 2's enrollment protocol does not establish how this value is derived or verified prior to the provider signature.


## Persona: cryptographer

Applied cryptographer, IACR community. I've reviewed Groth16, PLONK, and nullifier-based systems (Tornado Cash, Semaphore, Zcash Sapling). Unless I see a threat model with a game definition, a simulator, and a reduction sketch, it's marketing. The construction provides a game definition and a reduction sketch, so let me attack those directly.

---

### Attack 1: Deterministic public outputs destroy unlinkability — no simulator is given

**Attack:** The adversary (passive verifier, or any party that accumulates proofs) collects proofs `π₁, π₂, …, πₙ` across calls and observes the public signal layout:

- `agentMerkleRoot` — same for every proof from the same enrolled credential until a re-enrollment.
- `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` — deterministic; identical across every proof using the same credential.
- `modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask)` — deterministic; identical for every proof from the same (operator, model) pair.

All three are public outputs. Given these three values, a passive verifier trivially links every proof from the same operator-model pair into a session graph, counting calls, measuring inter-call timing, and correlating with external events. The entire call history of an operator is public to any proof accumulator.

**Why it works / why it fails against the construction:** The construction's `gap_to_close` requirement (c) states: *"verifier learns ONLY {model_hash, operator_pk, permission_bitmask, message_hash} and nothing else."* But the construction violates its own stated requirement. The `scopeCommitment` and `modelOperatorFingerprint` are not ephemeral or session-randomized — they're stable identifiers. The SECU scenario (Section 7) says the examiner can confirm "this PII operation was authorized under Opus without learning which member's data was involved or how many total calls SECU made." The second half of that sentence is false: every Opus credential proof from SECU produces the same `modelOperatorFingerprint`, so an accumulator counts exactly how many Opus calls SECU made.

Formally, the construction provides **no simulator**. Section 3 gives a threat model and a game for MODEL-BIND-FORGE (authorization forgery), but never states a ZK game: it does not define the simulator `S`, the distinguishing game, or whether the achieved property is honest-verifier ZK, malicious-verifier ZK, or simulation-extractability. Without a simulator, the zero-knowledge claim is hand-waving. The PLONK zero-knowledge proof for the circuit is HVZK for the circuit's witness — but that's about hiding `messagePlaintext`, not about hiding cross-proof linkability induced by deterministic public outputs chosen by the protocol designer.

**In-threat-model?** No. The construction must either:
- Rerandomize `scopeCommitment` and `modelOperatorFingerprint` per proof (e.g., by including a fresh blinding factor as a private input, producing a commitment rather than a deterministic hash), or
- Formally define a weaker ZK property (e.g., "single-verifier unlinkability") that acknowledges multi-proof correlation, and scope all privacy claims accordingly.

---

### Attack 2: PLONK universal setup subversion — toxic waste persists

**Attack:** The adversary participates in (or compromises one participant of) the PLONK universal SRS generation ceremony. The SRS for PLONK is a structured reference string of the form `{[xⁱ]₁, [xⁱ]₂}` for secret `x` (the "toxic waste"). If any single participant in the ceremony retains `x`, they can produce a valid PLONK proof `π` for any circuit and any public signals — including `modelOperatorFingerprint` encoding `modelHash_target` for an operator who was never authorized for that model — without possessing any valid witnesses. This fully breaks MODEL-BIND-FORGE v2 without touching EdDSA (A2) or Poseidon (A1).

**Why it works / why it fails against the construction:** The construction opens Section 2 by noting it uses "PLONK, universal setup" specifically as an improvement over Groth16's per-circuit setup requirement. This is accurate: a universal setup amortizes ceremony cost across circuits. However, a universal setup still requires a trusted MPC ceremony; it is not trustless. The construction provides no SRS ceremony specification — no participant count, no adversarial threshold, no transcript verification procedure, no on-chain commitment to the SRS. Section 2's "Bolyra primitive mapping" lists PLONK with universal setup but gives no spec reference for how the SRS is generated or audited.

The reduction sketch in Section 4 explicitly assumes A3: *"Knowledge soundness of PLONK in the algebraic group model + ROM."* Knowledge soundness in the AGM assumes the SRS is honestly generated. Under a subverted SRS, the AGM extractor fails — the adversary can produce group elements that are not computable as AGM-algebraic combinations of the SRS elements, breaking the extraction argument in Cases 2a/2b/3 of the reduction sketch. The entire reduction collapses.

This is not a marginal attack surface. The SRS for a universal PLONK setup covering ~23,550 constraints is large (degree ~50K+ CRS elements). The ceremony requires careful coordination. Projects with real ceremony infrastructure (Hermez, Aztec, Zcash Powers of Tau) dedicate significant engineering to this. The construction is silent on it.

**In-threat-model?** No. The construction's adversary model (PROVIDER-FORGE, MODEL-BIND-FORGE) does not include an adversary who corrupts the SRS ceremony. The construction must either: (a) specify the SRS ceremony and include ceremony participants in the trust assumptions, or (b) move to a transparent setup (STARKs, or PLONK with a hash-based commitment scheme like Plonky2), and update assumption A3 accordingly.

---

### Attack 3: Nullifier replay — sessionNonce binding is unspecified and PLONK is not simulation-extractable

**Attack:** The nullifier `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` is intended as a double-spend prevention mechanism. The adversary intercepts a valid proof `(π, {nullifierHash = N, sessionNonce = s, …})` and attempts to submit it again to a different verifier V₂ who has not seen nullifier `N`. The attack succeeds if: (1) `sessionNonce` is not verifier-bound, or (2) the nullifier registry is per-verifier rather than global.

More precisely: `sessionNonce` appears as a public input (signal index 7) described only as "session binding value." The construction does not specify:
- Who generates `sessionNonce` — prover or verifier?
- How the verifier authenticates that `sessionNonce` was fresh and verifier-chosen before the proof was generated?
- Whether the nullifier registry is global (on-chain) or per-verifier (off-chain)?

If the prover generates `sessionNonce`, the prover can precompute a proof for a self-chosen nonce `s`, then submit it to any verifier who accepts that nonce — including replaying the same proof to a verifier who never saw it, bypassing double-spend detection. If the nullifier registry is per-verifier, an adversary can submit a stolen proof to a verifier that lacks the nullifier in its local registry.

Separately: PLONK in the random oracle model is **not simulation-extractable** (SE). SE is a stronger property than knowledge soundness: it requires that even after seeing polynomially many simulated proofs, the adversary cannot produce a new valid proof without knowing a witness. Standard PLONK achieves HVZK + knowledge soundness (under AGM + ROM), but not SE. For the nullifier to serve as a cryptographic binding that cannot be replayed or duplicated even given access to a proof oracle, the proving system must be SE. The construction does not cite SE — and cannot, without additional machinery (e.g., a signature-of-knowledge wrapper, or a hash-to-field commitment to the nonce). Without SE, an adversary with oracle access to a PLONK prover for their own credentials (explicitly granted in MODEL-BIND-FORGE) could potentially produce malleated proofs sharing the same nullifier with altered `messageHash` — a proof malleability attack not addressed in the reduction.

**Why it works / why it fails against the construction:** The MODEL-BIND-FORGE game grants the adversary "oracle access to the PLONK prover for their own enrolled credentials." Under non-SE PLONK, this oracle could in principle be exploited to produce proofs with adversary-controlled public signals. The reduction sketch in Section 4 does not analyze this oracle; it treats A3 as a monolithic "knowledge soundness" assumption, which is insufficient if the oracle enables simulation.

**In-threat-model?** No. The construction must specify (a) the nonce-generation protocol (verifier-chosen, committed before proof generation), (b) the nullifier registry model (global on-chain vs. per-verifier), and (c) whether simulation-extractability is required and how it is achieved (or formally justify why standard knowledge soundness suffices for the nullifier application).

---

### Attack 4: Authorization binding ≠ runtime identity — the claimed scenarios require the stronger property

**Attack:** This is a semantic attack, not a cryptographic forgery. An adversary who is legitimately authorized for model M (e.g., Claude Opus 4.6) but operates a system running model M' (e.g., a fine-tuned or quantized variant, or a completely different model) produces valid Bolyra proofs claiming Opus authorization while never executing Opus at inference time. The adversary wins the *business scenario* while losing no cryptographic game defined in the construction.

**Why it works:** Section 3's threat model correctly disclaims runtime execution binding as "out of scope." But the four named scenarios in the candidate claim all require runtime binding:
- *"bank claims agent drained account; Bolyra proves which specific model+operator made the transaction"* — the liability question is **which model actually generated the output**, not which model the operator was licensed for. Authorization binding cannot establish this.
- *"Anthropic wants to prove to a tenant that their Opus usage was actually Opus (not re-billed Sonnet)"* — this is a runtime identity question, not an authorization question. Bolyra's proof confirms authorization for Opus; it cannot prevent Anthropic from serving Sonnet responses while billing for Opus.
- *"FDA/EU AI Act demands provable chain from deployed model weights to each inference output"* — Article 16 obligations explicitly target the model-to-output chain, which requires hardware attestation of weight loading.

The construction explicitly acknowledges this gap and frames it as an operational compliance matter: *"Detecting runtime substitution requires hardware attestation (TEE measurement of loaded weights bound to the proving key) and is a complementary layer."* This acknowledgment is technically accurate. However, the gap between the claimed scenario and the construction's guarantee is not merely "complementary" — it is the primary claim in three of the four scenarios.

**In-threat-model?** The runtime attack is explicitly out-of-scope. **But the claim itself is in-threat-model:** if the construction's claim is that it solves the stated scenarios, and three of four scenarios require runtime binding that the construction does not provide, then the claim is overstated. The construction must either (a) restrict its claimed scenarios to authorization-only use cases (billing disputes, contractual compliance), or (b) define a companion TEE attestation protocol and show how the two layers compose — ideally under the UC composition framework — to achieve full runtime binding, and specify the hybrid threat model for the composed system.


## Persona: cu_ciso

### Attack 1: Authorization ≠ Execution Under GLBA Safeguards Rule

- **Attack:** Section 3 of the construction explicitly disclaims: "This construction does **not** prove that the physical process generating the tool-call output actually loaded the weights corresponding to `modelHash` at inference time." Yet Section 7 (the SECU deployment scenario) tells my NCUA examiner that the proof confirms "this PII operation was authorized under Opus." I'm going to hand my examiner this document, and she is going to ask: "So your proof tells me SECU had a contract to use Opus, not that Opus touched the member data?" Under 16 CFR Part 314.4(c)(2) (GLBA Safeguards — monitoring and testing safeguards), I need audit evidence of what **actually processed** customer financial records, not what the operator had a license to run. The construction's "pharmacy analogy" (Section 7, final paragraph) makes the problem explicit: the proof is the prescription, not the dispensing record. NCUA doesn't examine prescriptions; they examine dispensing records.

- **Why it works / fails:** This is not a cryptographic attack — it is a scope mismatch the construction **explicitly acknowledges**. It fails against the construction's stated security claim (authorization binding is proven). But it succeeds as a regulatory objection: the gap between authorization binding and execution binding is exactly the gap a NCUA examiner will park on. The construction correctly identifies that closing this gap requires TEE attestation, but provides no roadmap for integrating TEE into the SECU deployment scenario. A credit union cannot present a proof that by design cannot confirm what ran to an examiner asking what ran.

- **In-threat-model?** No. The construction must address: (a) either scope the SECU scenario to regulatory regimes where authorization binding is sufficient, or (b) define the TEE attestation composition layer so the deployment scenario is complete, not aspirational.

---

### Attack 2: Anthropic's HSM Is My Third-Party Vendor — Who Audited It?

- **Attack:** The entire trust root of this construction is a Baby Jubjub keypair that "Anthropic generates... in an HSM; public key is published in a transparency log" (Section 2, Enrollment Protocol). Under NCUA Part 748 Appendix A (Information Security Program) and the FFIEC Third-Party Risk Management guidance, I am required to assess, monitor, and obtain independent assurance of every third-party system that sits in a critical path for member data. If Anthropic's HSM is compromised, every `modelOperatorFingerprint` in my audit trail becomes suspect retroactively. My question to the construction: what is the **auditable evidence** that Anthropic's provider signing key was generated and is held in an HSM? A transparency log entry is not a SOC 2 report. My vendor due diligence packet for Anthropic needs to include: HSM model and FIPS 140-2/3 certification, key ceremony documentation, HSM access audit logs, and a contact for incident notification. None of this exists in the deployment scenario. My board risk committee will not approve a construction whose root of trust is "trust Anthropic's blog post about HSMs."

- **Why it works / fails:** The construction addresses *cryptographic* assumptions (A1, A2, A3) rigorously but treats the HSM operational trust as out of scope. From a CISO perspective, the cryptographic reduction is only as strong as the trust anchor. The adversary model (Section 3) explicitly assumes the adversary "does NOT control the model provider's BJJ signing key." If the HSM is the boundary, the boundary needs an audit. The construction does not fail on cryptographic grounds, but it fails on third-party risk grounds that NCUA examiners test directly via questionnaire.

- **In-threat-model?** No. Must address: what SOC 2 Type II controls (CC6.6, CC6.7, CC6.8 covering logical access and cryptographic key management) does Anthropic commit to for the HSM? What is the notification SLA to enrolled operators if the provider key is compromised? The SECU deployment scenario (Section 7, Step 1) says "Anthropic publishes the provider public key in a transparency log" — this is a detection mechanism, not a control.

---

### Attack 3: The Audit Trail Is Nine BN254 Field Elements — My Examiner Speaks English

- **Attack:** Section 7 describes the NCUA audit flow: "The examiner receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per audited transaction." These are Poseidon hashes over the BN254 scalar field. The examiner must then "verify each PLONK proof against the on-chain roots." Who runs the PLONK verifier? On what infrastructure? How does the examiner map `messageHash = Poseidon(messagePlaintext)` back to the actual member transaction in my core processor (Symitar, Corelation, etc.)? My Tier 1 ops team and my NCUA field examiner do not speak PLONK. There is no described tooling, no audit dashboard, no bridge between `modelOperatorFingerprint` and a human-readable description of the call. Under FFIEC CAT (Domain 3, Cybersecurity Controls — Incident Management and Resilience), I need audit trails that are interpretable by non-cryptographers during an incident. At 2am during a member data breach investigation, I need my ops team to be able to pull transaction records, not verify zero-knowledge proofs against on-chain Merkle roots.

- **Why it works / fails:** The construction proves what it claims to prove cryptographically. It does not describe the tooling layer that makes these proofs auditable within a credit union's existing compliance workflows (NCUA Report of Examination, SAR filing to FinCEN, state regulator requests). There is no described mapping from `messageHash` to a member account or transaction ID, no role-based access interface for examiners, and no described process for what happens when the PLONK verifier returns `false` — who gets paged, what's the escalation path?

- **In-threat-model?** No. The construction must address the tooling gap between proof outputs and the credit union's existing audit trail infrastructure. Even if the cryptography is sound, regulatory defensibility requires human-interpretable evidence chains. The construction needs either: (a) a defined mapping from `messageHash` to a transaction identifier in the credit union's system of record, or (b) an explicit acknowledgment that operational tooling is a deployment layer outside the protocol, with a reference architecture for how it is built.

---

### Attack 4: The 30-Entry Root History Buffer vs. NCUA's 7-Year Retention Requirement

- **Attack:** Section 4 (Key Rotation Survival) states: "Old proofs remain valid against old Merkle roots stored in the 30-entry root history buffer." The construction also states "For long-term archival, the verifier stores the `agentMerkleRoot` from the proof at verification time." Under NCUA Record Retention Policy (12 CFR Part 749) and GLBA Safeguards, member account records must be retained for 7 years. The 30-entry buffer means that after 30 new credential enrollments, the on-chain state no longer contains historical roots. Long-term proof verification then depends entirely on the credit union's own archived `agentMerkleRoot` values. The construction has offloaded historical verifiability to **me** — the credit union. NCUA's examination standard for electronic records (NCUA Letter to Credit Unions 01-CU-09) requires that records be accessible and verifiable by examiners, not just by the institution. If I'm the only party holding the archived `agentMerkleRoot` needed to verify a 3-year-old proof, and I'm also the party under examination, I've become the sole auditor of my own compliance evidence. That's not risk transfer — that's self-attestation with cryptographic theater.

- **Why it works / fails:** The construction's security argument is sound at proof time, but the archival model creates a long-term verifiability gap that is operationally equivalent to "trust the credit union's own records." The examiner cannot independently verify a 3-year-old proof without the archived root that only I hold. This breaks the third-party verifiability property that makes the construction valuable for regulatory purposes in the first place. Increasing the buffer size doesn't fix this — it just delays the rollover.

- **In-threat-model?** No. Must address: either define an on-chain archival contract that retains root history indefinitely (with gas cost implications), or define a third-party archival scheme (e.g., anchoring root history to a notarized log with independent custody) that allows an NCUA examiner to verify historical proofs without relying solely on the credit union's archived state.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + extensions.*

---

### Attack 1: JWT Introspection Response Removes the AS from the Hot Path — Section 8(c)'s Premise Is False

**Attack:**
Section 8(c) argues: *"Adding an AS to enforce [the model-identity claim] re-introduces the correlation problem (AS sees every call)."* This is a false dichotomy that ignores `draft-ietf-oauth-jwt-introspection-response` (the signed JWT introspection response spec). Under that draft:

1. Anthropic (AS) issues a **signed JWT introspection response** per token: `{"active": true, "model_id": "sonnet-4-6", "operator": "ACME", "permission_bitmask": X, "aud": "<verifier-RS>", "exp": ...}`.
2. The operator caches this JWT and presents it to verifiers **offline**. The AS is not contacted at verification time.
3. The verifier checks the AS public key (published in JWK Set) locally. No AS correlation.

This directly contradicts Section 8(c)'s load-bearing claim. The AS participates **once** at token issuance — equivalent to the one-time enrollment in Bolyra's provider attestation — then disappears from the verification path entirely. The "AS sees every call" critique applies only to classical reference-token introspection (RFC 7662 §2), not to its JWT-response extension.

**Why it fails against the construction (partial):**
The construction still has a residual advantage: the JWT introspection response reveals cleartext claims (`model_id`, `operator`, `exp`) to the verifier with no selective-disclosure boundary. Section 8(e) is correct that BBS+ selective disclosure from an AS-issued credential requires the AS to either know the per-call attribute set (correlation) or issue a maximally-disclosed credential (leakage). ZK beats this.

But the construction must **retract or narrow** the claim in 8(c). Saying "adding an AS re-introduces the correlation problem" is simply wrong for JWT introspection + caching. The correct claim is weaker: *"the AS-signed JWT reveals cleartext fields; Bolyra's fingerprint is a hash commitment that reveals less to the verifier."*

**In-threat-model?** No — the construction must address this. Section 8(c) as written is factually incorrect about JWT introspection response behavior, and the entire baseline comparison rests partly on this false premise.

---

### Attack 2: RFC 8693 Delegation Chain Is the Real Closest Baseline — The Construction Doesn't Face It

**Attack:**
Section 8 dismisses RFC 8693 in one sentence. Let me construct the actual token-exchange baseline the construction should fear:

1. Anthropic (AS) pre-issues a **model authorization grant** (RFC 8693 `urn:ietf:params:oauth:token-type:access_token` exchange): a structured JWT containing `{sub: "sonnet-4-6", authorized_operator_jwk_thumbprint: "<jkt of ACME's DPoP key>", permission_bitmask: X}` — signed by Anthropic, issued offline once per (operator × model).
2. ACME Corp retains this grant and presents it alongside each API call. The verifier receives `{act: {sub: "anthropic.com/sonnet-4-6", jkt: "<ACME-DPoP-thumbprint>"}}` in the delegation chain.
3. DPoP (RFC 9449) binds the bearer token to ACME's key, proving the key holder presented this delegation. The DPoP proof includes `htu`/`htm` per spec; body-hash binding for the tool-call payload is achievable via the `ath` claim (RFC 9449 §4.2) or the forthcoming `body_hash` extension.

This constructs:
- **(a) Non-malleability:** Anthropic signs the delegation; Opus operator cannot forge a Sonnet delegation JWT without breaking RS256/ES256. ✓
- **(b) Key rotation:** DPoP key is the ephemeral proof key. The underlying authorization grant references the long-term `jkt`. New grants issued on rotation; old ones remain verifiable via published JWK history. ✓  
- **(c) Verifier learns:** `{model_id, operator_jkt, permission_bitmask, message_body_hash}` — nothing more, if the JWT is appropriately scoped. ✓

The construction's gap-to-close requires proving RFC 8693 + DPoP cannot achieve (a)+(c) simultaneously, but Section 8 never constructs this explicit baseline and refutes it. Instead it generalizes about "AS sees every hop" (which Attack 1 shows is wrong for cached grants).

**Why it fails against the construction (partial — three genuine gaps remain):**
1. **On-chain non-revocability:** Bolyra's `providerRegistryRoot` is governance-controlled on-chain. Anthropic cannot silently re-issue a "sonnet" grant for an Opus deployment and backdate it. The RFC 8693 grant is an off-chain JWT — Anthropic can issue any `model_id` string. For a regulatory audit, the verifier must trust Anthropic's JWT issuance honesty. Bolyra's on-chain registry adds a transparency property the delegation chain lacks.
2. **Selective disclosure of the identity:** The RFC 8693 `act` chain reveals `operator_jkt` as a cleartext JWK thumbprint. Bolyra's `modelOperatorFingerprint` is a Poseidon3 commitment — the verifier cannot reverse-engineer the operator's public key from it (though see Attack 3 for why this matters less than claimed).
3. **Native bitwise predicate:** The `permission_bitmask` in an RFC 8693 JWT is a claim, not a proven predicate. There is no in-band proof that `requiredBits ⊆ permBits`.

**In-threat-model?** Yes — the construction survives, but barely and only for specific sub-properties. The construction must produce an explicit head-to-head comparison with RFC 8693 + DPoP + JWT introspection and explain *precisely* which sub-property each baseline fails, instead of the current hand-wave.

---

### Attack 3: `modelOperatorFingerprint` Is a Stable Pseudonym — Equivalent to PPID, Not Superior

**Attack:**
The construction implies Bolyra provides better correlation resistance than PPID-based OAuth. Inspect the public output at index 4:

```
modelOperatorFingerprint = Poseidon3(modelHash, operatorPkAx, permissionBitmask)
```

This value is **deterministic and stable** across all calls from the same operator using the same model and same bitmask. An NCUA examiner (or any passive verifier) receiving 10,000 proofs can trivially partition them by `modelOperatorFingerprint` and link every call back to a single operator-model deployment. The construction explicitly *relies* on this property — Section 7 states the examiner uses the fingerprint to confirm "this PII operation was authorized under Opus."

Now compare to RFC 8707 (Resource Indicators) + OIDC Pairwise Pseudonymous Identifiers: a per-RS `sub` value is also deterministic and stable for a given (user, RS) pair. The PPID `sub` serves exactly the function of `modelOperatorFingerprint`: it lets the RS confirm identity without revealing the global subject. Section 8 claims "Audience-bound tokens + PPIDs already break cross-RS linkability at the RS level" — the construction agrees this is true but never explains why its fingerprint is strictly better than a PPID for the audit use case.

The construction cannot simultaneously claim:
- (i) The ZK construction provides stronger unlinkability than PPID/OAuth, **and**
- (ii) The verifier can reliably identify "this is SECU's Sonnet deployment" from the fingerprint across sessions.

These are in tension. If (ii) holds, the fingerprint is as linkable as a PPID. If (i) holds, (ii) is weakened.

**Why it fails against the construction (partial):**
The construction does have a genuine advantage: the `operatorPkAx` is a Baby Jubjub key, not the API bearer token or billing identifier. An observer of `modelOperatorFingerprint` cannot immediately correlate it to SECU's Anthropic account without the operator revealing the key-to-account mapping. A PPID `sub`, by contrast, is computed from the user's master identity at the AS — Anthropic knows the mapping. However, the construction's *enrollment* step (Section 2, Enrollment Protocol) requires SECU to submit `credentialCommitment` to the Merkle tree, which is observable on-chain, linked to SECU's registered BJJ key, which SECU disclosed to Anthropic when obtaining the deployment authorization.

**In-threat-model?** Yes — the construction should explicitly acknowledge that `modelOperatorFingerprint` is a stable pseudonym that provides within-operator call linkability, and that this is functionally equivalent to OIDC PPIDs for the audit use case. The claim of superior privacy is overclaimed.

---

### Attack 4: Message Binding Without ZK — RFC 9449 `ath` Claim Closes the Gap the Construction Identifies

**Attack:**
The construction's clearest advantage over pure OAuth is `messageHash` — a public output binding the specific tool-call payload to the credential. RFC 9449 §4.2 defines the `ath` claim in DPoP proofs: a base64url-encoded SHA-256 hash of the **Authorization header** value. While `ath` binds to the authorization header specifically, not an arbitrary payload, the RFC 9449 design space already supports payload binding:

- The `nonce`-based freshness in RFC 9449 §8 prevents replay without per-request AS involvement.
- The `body_hash` mechanism being discussed in OAuth working group sessions (building on JAdES/RFC 7515 header parameters) would bind the DPoP proof to a hash of the HTTP body — exactly the `messageHash` role in Bolyra.
- Combined with a cached JWT introspection response (Attack 1) containing `model_id`, the resulting artifact `{JWT_introspection_response + DPoP_proof_with_body_hash}` gives a verifier: model identity (signed by AS), operator key (JWK thumbprint in `jkt`), permission bitmask (JWT claim), and message hash (DPoP `body_hash`).

The construction must explain why `DPoP + body_hash + JWT introspection` does not satisfy the claim. Currently Section 8 only mentions DPoP in the context of "sender-constraint without ZK" without engaging the specific body-binding extension.

**Why it fails against the construction (genuine residual gap):**
1. **Atomicity:** Bolyra binds all four outputs — `{model_hash, operator_fingerprint, bitmask, message_hash}` — in a **single PLONK proof**. The DPoP baseline is two separate artifacts (JWT + DPoP proof) that can be split: an attacker who captures both can present the JWT with a different DPoP proof, or vice versa, depending on what the verifier checks. In Bolyra, the `messageHash` is a circuit output computed over private `messagePlaintext` with `credentialCommitment` — both must be consistent for the proof to verify. This is a genuine binding property the two-artifact baseline cannot replicate without further cryptographic glue.
2. **Credential non-transferability:** The DPoP key (`jkt`) in the introspection JWT is a public JWK. Any party holding the private DPoP key can generate valid proofs for arbitrary body hashes — there is no binding between the body_hash and the specific message content being claimed. Bolyra's circuit enforces `messageHash = Poseidon(messagePlaintext)` as a constraint over the private plaintext, making the binding circuit-enforced, not convention-enforced.
3. **Body hash extension is not yet standardized.** The claim must be evaluated against deployed RFC 9449, not aspirational extensions. As of current RFC 9449, `ath` does not bind to arbitrary payloads. The construction should note this explicitly.

**In-threat-model?** Yes — the construction survives on the atomicity argument, but this is not currently articulated in Section 8. The response to the DPoP baseline must be: "two-artifact binding is not cryptographically atomic; the circuit-enforced single proof is the differentiator" — not the current framing which overstates DPoP's limitations.


## Persona: spiffe_engineer

---

### Attack 1: You Built a SPIRE Attestor Plugin With Extra Steps

**Attack:** SPIRE's attestation architecture is pluggable. I write a custom node attestor that calls Anthropic's signed deployment authorization API — the same `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` issuance endpoint the construction assumes exists — and encodes the attested model identity in the SVID path: `spiffe://anthropic.com/models/sonnet-4-6/operators/acme-corp`. The SVID is issued by SPIRE after the attestor verifies the Anthropic-signed deployment authorization. The SVID is short-lived (1h TTL), mTLS-pinned, and the entire flow is inside the Workload API. I've just implemented your "enrollment protocol" in §2 as a SPIRE plugin in ~300 lines of Go.

**Why it works / why it fails:** The construction's Section 8(a) response is that "the SPIRE server is operator-controlled" and an operator could register an arbitrary model path. True. But the plugin I'm describing calls *Anthropic's* attestation endpoint — not the operator's — to validate `deploymentAuthorization` before issuing the SVID. The SPIRE server cannot fabricate that signature any more than Bolyra's operator can. The only property the construction has that my plugin lacks is Section 2's property (c): the verifier in the ZK construction never sees the raw provider attestation. In the SPIRE flow, the Workload API receiver sees the SVID chain. But in enterprise deployments where the verifier is the NCUA examiner and is *explicitly permitted* to see that SECU is running Sonnet — as described in §7 — there is no privacy gain from (c). The ZK layer is justified only by (c), but the deployment scenario in §7 does not require (c).

**In-threat-model?** No — the construction must address why property (c) is *required* for the stated scenarios, not just available. The SECU scenario in §7 has the examiner learning `{model_class, operator}` from the proof. A SPIFFE SVID reveals the same thing. The privacy argument for ZK is undermined by the construction's own deployment example.

---

### Attack 2: WIMSE Token Exchange Closes (a)+(b); You Only Have (c) Left to Defend

**Attack:** draft-ietf-wimse-arch §5 defines workload-to-workload token exchange (RFC 8693 profile) with sender-constrained tokens (DPoP proof-of-possession). I configure an Anthropic-operated Token Exchange Service (TES) that: (1) receives an operator's DPoP-bound access token, (2) verifies the operator's deployment contract for the requested model, (3) issues a sender-constrained model-scoped token `{sub: "acme-corp", model: "sonnet-4-6", scope: "pii-read", iat, exp}` bound to the operator's DPoP key. Non-malleability (a): an Opus operator cannot obtain a Sonnet token — the TES checks the deployment contract. Key rotation (b): DPoP ephemeral keys are per-request; the deployment contract persists. The construction's §8 claim that "AS sees every hop (violates (c)) or binding is not cryptographic (violates (a))" is a false dilemma — DPoP binding *is* cryptographic, and the AS seeing usage metadata is acceptable in regulated environments with a compliance SLA with Anthropic.

**Why it works / why it fails:** The construction's gap-to-close in the candidate description says "Must prove RFC 8693 token exchange and DPoP cannot achieve (a)+(c) simultaneously." Section 8(c) attempts this: "Adding an AS to enforce the model-identity claim at issuance re-introduces the correlation problem." But the construction conflates two distinct privacy properties: (c1) *verifier* doesn't learn the full session history, and (c2) *Anthropic* doesn't learn per-call metadata. WIMSE violates (c2) — the TES sees issuance events. It does not automatically violate (c1): a verifier receiving a DPoP-bound model token with BBS+ selective disclosure does not learn the full session log. The construction does not prove that (c2) — Anthropic call-metadata privacy — is a required property for any of its four scenarios. The §7 SECU deployment explicitly has Anthropic as the root-of-trust issuer; Anthropic *already* has per-call billing telemetry.

**In-threat-model?** No — the construction has not proven that WIMSE + DPoP + BBS+ fails to achieve (a)+(c1) simultaneously. The "AS sees every hop" argument defeats (c2), not (c1). The construction must either prove (c2) is load-bearing for the stated scenarios or demonstrate a concrete WIMSE failure on (a) or (c1).

---

### Attack 3: `modelHash` Is a SPIFFE ID With a Poseidon Wrapper

**Attack:** Examine the private input spec in §2: `modelHash: Hash of model weights/identifier (field element)`. The `/identifier` alternative means `modelHash` may be computed as `Poseidon("claude-sonnet-4-6")` — a hash of a string label chosen by Anthropic. The `modelOperatorFingerprint` output is then `Poseidon3(Poseidon("claude-sonnet-4-6"), operatorPkAx, permissionBitmask)`. This is semantically identical to `spiffe://anthropic.com/models/claude-sonnet-4-6` encoded as a field element. SPIFFE trust domain + path encodes the same information. The binding is nominal: it proves "Anthropic called this thing 'claude-sonnet-4-6' when they signed your deployment contract," not anything about the computational behavior of the model. From a SPIFFE perspective, the SVID path IS the model identifier, and Anthropic's intermediate CA IS the deployment authorization. The ZK construction wraps a naming scheme in a proof system but does not advance the semantic content of the claim.

**Why it works / why it fails:** The construction partially acknowledges this in §3: "The construction does not prove that the physical process generating the tool-call output actually loaded the weights corresponding to `modelHash` at inference time." But the acknowledgment applies even when `modelHash` IS a weights hash: unless the hash is computed inside a TEE that seals the signing key to the measurement, the operator can compute `Poseidon(correct_weights_hash)` and present it without running those weights. So whether `modelHash` is a name or a weights hash, the construction's security claim is identical: "Anthropic signed a piece of data that includes this value, and that value is bound to this operator key." SPIFFE's SVID chain conveys the same claim with a different encoding. The construction's Section 8(a) differentiation — "no component of the baseline stack has a mechanism for operator-bound third-party attestation verified inside a selective-disclosure proof" — is the only surviving claim, and it depends entirely on property (c) being required (see Attack 2).

**In-threat-model?** Partially. The `modelHash` ambiguity (`weights/identifier`) is a specification gap the construction must close. If `modelHash` is an identifier, the construction must explain what it provides beyond SPIFFE path encoding. If it is a weights hash, the construction must explain how the hash is computed and bound to the signing key in a way that prevents an authorized-but-cheating operator from submitting the correct hash while running different weights — which leads directly back to the TEE layer the construction explicitly defers to §3.

---

### Attack 4: Provider Registry Governance Is a Stronger Trust Assumption Than SPIFFE Root CA, Unjustified

**Attack:** The construction's §2 enrollment protocol places `providerRegistryRoot` on-chain, controlled by "governance-multisig or DAO-controlled." The threat model §3 explicitly excludes adversaries who "control the on-chain provider registry." SPIFFE's equivalent exclusion is: the adversary does not control the SPIRE server's root CA. Both constructions have a root-of-trust assumption. But the construction's assumption is *stronger* in practice for three reasons: (1) A governance multisig has a small compromise threshold (e.g., 3-of-5 keyholders) with no equivalent of Certificate Transparency — a malicious registry insertion is invisible until someone checks the root history. SPIFFE's root CA operates under CT, OCSP, and browser/OS vendor auditing. (2) The on-chain registry introduces liveness dependency on a specific blockchain. SPIRE bundles are served over HTTPS with DNSSEC and degrade gracefully. (3) The construction says provider revocation is "new root excluding the compromised key" — this invalidates all historical proofs that used the old `providerRegistryRoot` unless verifiers cached the root at proof time. The 30-entry root history buffer in §4 is a fixed-size window; proofs outside it are unverifiable, creating a hard archival deadline. SPIFFE's CRL/OCSP model does not invalidate historical records of authenticated sessions.

**Why it works / why it fails:** The construction's §4 "Key rotation survival" section addresses operator BJJ rotation and provider BJJ rotation, but does not address the root history buffer expiration problem. If a verifier (NCUA examiner) attempts to verify a 2-year-old proof and the Merkle root is no longer in the 30-entry buffer, verification fails unless the verifier archived the root at proof time — an operational requirement the construction mentions but does not enforce or specify. The SPIFFE model's equivalent archival story (store the SVID chain and CRL snapshot at signing time) is well-specified in RFC 5755 and OCSP stapling. The construction has a weaker archival story for a system claiming to support long-term regulatory audit in §7.

**In-threat-model?** No — the root history buffer expiration gap is not addressed in the threat model and represents a concrete verifier failure mode for the §7 NCUA audit scenario. The construction must either specify a root archival protocol (e.g., append-only log of historical roots, analogous to CT) or eliminate the fixed-size buffer in favor of an unbounded history with pruning governance. As written, a 2-year-old Bolyra proof is unverifiable by default unless the verifier implemented out-of-band root caching — which is an operational burden the baseline (SVID chain + CRL snapshot) does not impose.
