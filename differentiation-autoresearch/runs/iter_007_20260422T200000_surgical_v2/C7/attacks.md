# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

### Attack 1: Provider Participation Is an Unproven Business Assumption, Not a Technical Property

- **Attack:** The entire security argument collapses without Anthropic (or another model provider) actually running the BJJ HSM ceremony, computing `Poseidon3(modelHash, operatorPkAx, operatorPkAy)` per-operator, and issuing deployment authorization tuples through their API dashboard. Section 2's enrollment protocol describes Anthropic performing these steps as if it is already agreed. It is not. Anthropic currently has no cryptographic key infrastructure for Baby Jubjub, no HSM-held EdDSA signing service, and no enrollment API issuing per-operator Poseidon tuples. Auth0 and WorkOS ship MCP auth *today* against OAuth 2.0 endpoints that model providers already operate. Getting Anthropic to adopt a bespoke ZK enrollment protocol requires: (a) Anthropic product agreement, (b) key ceremony with Trail of Bits or equivalent, (c) new API surface, (d) HSM procurement and provisioning. Without provider participation, `modelHash` is operator-self-declared — which is exactly the weakness Section 8(a) claims to eliminate.

- **Why it works / why it fails:** The construction is technically sound *conditional* on provider participation. But the security proof in Section 4 begins from "Challenger enrolls provider key" — the Challenger is Anthropic. If Anthropic does not participate, there is no Challenger, and `providerRegistryRoot` is either empty or self-populated by the operator. The construction has no fallback. Auth0/WorkOS can achieve their current binding guarantees with zero provider cryptographic ceremony because OAuth client_id registration is already a normal business operation.

- **In-threat-model?** No — the construction must address the business precondition: what is the concrete plan to get Anthropic (or any model provider) to run this infrastructure? Without that, the threat model game is unplayable.

---

### Attack 2: Latency Makes This Non-Deployable for Synchronous MCP Tool Calls

- **Attack:** Section 6 estimates ~5s proving time for Halo2/IPA, ~11.5s with the SE-PLONK overhead (~25K constraints). The construction asserts the authorization path is "not latency-critical." In MCP, tool calls are synchronous and blocking — the model waits for the tool result before continuing. An MCP server that blocks for 5–11.5s on *every authorized tool call* cannot be deployed in any interactive agent loop. WorkOS issues tokens in <100ms. A loan-servicing agent making 20 tool calls per member session adds 100–230 seconds of proof-generation latency. Section 7 (SECU scenario) describes agents "processing member loan servicing" — a session that takes 4 minutes longer than a competitor's is not a product, it is a liability. The "not latency-critical" claim requires justification: which specific deployment architectures batch tool calls, and at what granularity is a proof generated?

- **Why it works / why it fails:** The construction partially addresses this by noting proving is on the authorization path, not per-inference. But the construction does not specify *when* a proof is generated: at session start (once per session, acceptable) or per tool call (once per call, unacceptable). Section 2's message binding (`messageHash = Poseidon(messagePlaintext)`) implies per-call proving — the `messageHash` is a public output binding the *specific* tool-call payload. If this is per-call, the latency objection is fatal for interactive use. If proofs are batched or session-level, the message binding claim weakens (a session-level proof does not prove "this specific call" was authorized).

- **In-threat-model?** No — the construction must clarify the proof granularity and provide a concrete latency budget for the SECU deployment scenario. If per-call, it must explain how 5–11.5s is acceptable. If session-level, it must reconcile this with the per-`messageHash` binding claim.

---

### Attack 3: The Core CISO Use Case Is Overstated — No Runtime Execution Binding

- **Attack:** Section 7 claims NCUA examiners can confirm "this PII operation used Opus" and Section 1 claims to prove "this call was made by Claude Sonnet 4.6." Section 8(g) then explicitly disclaims: "Binding proof of which model weights were actually loaded into GPU memory at inference time requires a TEE or secure enclave attestation and is not claimed by this construction." These two claims are in direct tension. A proof that `credentialCommitment` encodes `modelHash_sonnet` and the operator holds a provider attestation for Sonnet proves only that the *operator is authorized to use Sonnet* — not that Sonnet weights actually ran the inference. An operator can enroll legitimate Sonnet credentials from Anthropic, then route all calls to a fine-tuned Llama 3 locally, and generate valid Bolyra proofs using the enrolled Sonnet credential. The NCUA examiner auditing under Section 7 would receive proofs attesting to Sonnet authorization on every call — while every inference was actually Llama 3. The examiner has no recourse within the construction.

- **Why it works / why it fails:** The construction is internally consistent — it disclaims runtime execution binding explicitly. But the marketing claim ("proves 'this call was made by Claude Sonnet 4.6'") and the SECU audit scenario overstate what is actually proven. The correct claim is "this call was made by an operator authorized to use Sonnet." WorkOS and Auth0 can make the same claim — they attest that the registered application is authorized to call a specific API endpoint. The delta between Bolyra and OAuth in this regime is *privacy of the proof*, not *strength of the model identity binding*. A CISO who understands the disclaimer will ask: "If you can't prove the weights actually ran, what am I paying for that WorkOS doesn't give me?"

- **In-threat-model?** No — the construction must either (a) narrow the claim to "authorization binding only, not execution binding" consistently throughout Sections 1 and 7, or (b) specify how a TEE integration closes the gap, and at what cost to the constraint count and latency.

---

### Attack 4: Procurement Death — Solo Founder vs. SOC 2 Type II

- **Attack:** A credit union's procurement process for a new vendor requires: SOC 2 Type II audit report, vendor security questionnaire, legal review of the service agreement, NCUA examiner-accepted control evidence, and often a 6–18 month trial period. WorkOS, Auth0, and Cloudflare Access have all of these. Bolyra has a whitepaper with a PLONK circuit. The attack prompts ask: "How do you answer procurement's 'you are a solo founder' question?" The construction has no answer. The SECU scenario in Section 7 assumes SECU's NCUA examiner will accept PLONK verification as audit evidence — but NCUA examiners currently accept: SAML logs, OAuth access logs, API gateway audit trails, SOC 2 reports from vendors, and SSAE 18 attestations. No NCUA examiner has ever reviewed a Baby Jubjub EdDSA signature as part of a safety and soundness examination. Introducing a ZK circuit as a compliance control requires the examiner to understand, and accept, a cryptographic primitive that is not in any existing NCUA examination manual. The construction treats "NCUA examiners verify PLONK proofs" as an assumption, not a problem to solve.

- **Why it works / why it fails:** This is a pure GTM/distribution attack, not a cryptographic one. The construction is technically sound. But in the buyer's decision process, technical soundness of the ZK construction is evaluated last, after vendor risk, operational support, legal review, and examiner acceptability. Auth0 wins the SECU account not because its cryptography is better but because its procurement package (SOC 2 Type II, 24/7 support SLA, documented examiner response templates) is complete. The construction does not address any of these. Specifically, the construction should specify: what audit artifact does a verifier export for an NCUA examiner who does not run a PLONK verifier? Is there a human-readable attestation? Is there a third-party auditor who will sign off on Bolyra proofs as equivalent to a SOC 2 access log entry?

- **In-threat-model?** No — the construction is a cryptographic specification, but the SECU scenario frames adoption as already solved. The construction must either (a) remove the concrete enterprise scenario and stay at the protocol level, or (b) add a section on examiner-facing audit artifacts, third-party circuit audits, and the vendor onboarding path that makes procurement tractable for a solo founder.


## Persona: cryptographer

> Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The document provides all three — which is why what follows is more specific than usual.

---

### Attack 1: Honest-but-cheating operator — the core binding claim is not established

**Attack:**
An operator legitimately licensed for Claude Sonnet 4.6 obtains a valid Anthropic deployment authorization: `providerSig` over `Poseidon3(modelHash_sonnet, adversaryPkAx, adversaryPkAy)`. The operator then runs *any* model — a fine-tuned derivative, Claude Opus, an open-source LLM, even a random number generator — and at proof time supplies the valid `providerSig`, their enrolled `credentialCommitment`, and a `messagePlaintext` (the tool-call output from the impostor model). All circuit constraints (1–12) are satisfied. The PLONK verifier outputs 1. The NCUA examiner sees `modelOperatorFingerprint` confirming "Sonnet" and signs off.

**Why it works:**
The circuit verifies *authorization* binding — "Anthropic authorized this operator for Sonnet" — but the construction section §2.g explicitly concedes: "Binding proof of *which model weights were actually loaded into GPU memory at inference time* requires a TEE or secure enclave attestation and is not claimed." This admission is technically honest, but the stated claim in §1 is *not* honest: "proves 'this call was **made by** Claude Sonnet 4.6.'" The word "made by" asserts runtime execution, which the construction explicitly cannot prove. The threat model (MODEL-BIND-FORGE v2) only models an adversary forging credentials *without* a legitimate attestation. The adversary here has a legitimate attestation and simply lies about what model is running.

**Game form:** Define MODEL-EXEC-BIND: adversary wins if they produce a valid proof π for a tool-call payload `m` that was *not* generated by the attested model, while holding a legitimately enrolled credential for that model. The construction has *no reduction* for this game. There is no game definition, no winning condition, no reduction sketch for MODEL-EXEC-BIND.

**In-threat-model?** No. The stated marketing claim ("this call was made by Claude Sonnet 4.6") is not established by the construction. The construction proves authorization binding, not execution binding. Every deployment scenario in §7 (NCUA, FDA/EU AI Act, liability dispute) depends on the stronger claim.

---

### Attack 2: Nullifier precomputation — verifier de-anonymizes which credential produced each proof

**Attack:**
The verifier observes public chain state. The agent Merkle tree is explicitly *permissionless and public*: "Operator submits `credentialCommitment` for insertion into the agent Merkle tree." Every `credentialCommitment` is therefore on-chain and enumerable. The `sessionNonce` is also a public input (signal index 7). The verifier, after seeing proof π, computes:

```
nullifier_i = Poseidon2(credentialCommitment_i, sessionNonce)
```

for each enrolled `credentialCommitment_i` and checks which matches the public output `nullifierHash`. Since Poseidon is deterministic and both inputs are public, this is a brute-force lookup over the (small, indexed) set of enrolled credentials. The matching `credentialCommitment` was enrolled by a specific operator during §2 Enrollment, linking the proof to that operator's exact credential.

**Why it works:**
The construction's privacy claim is that the verifier learns only `{model_hash, operator_pk, permission_bitmask, message_hash}` via the fingerprint. But since `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)` is *already public on-chain*, the verifier learns the full pre-image by finding the matching nullifier, including `expiryTimestamp` (not in the fingerprint) and confirmation of the exact `operatorPubkeyAx` — i.e., the operator's actual public key, not a one-way hash. More critically, the verifier can now correlate *all proofs using the same credentialCommitment* across sessions — `agentMerkleRoot` is fixed per tree state, and `Poseidon2(credentialCommitment, ·)` maps each sessionNonce to a distinct but attributable nullifier. The NCUA scenario claim "without learning how many total calls SECU made" fails: the examiner counts nullifier hits for SECU's `credentialCommitment`.

**Formal gap:** The simulation requires hiding `credentialCommitment`, but the commitment is a public leaf in a public append-only tree. There is no formal zero-knowledge statement — no simulator is defined in the document. The "ZK" in the construction applies to the circuit witness, but the witness includes values that the construction itself publishes elsewhere. This is a leakage via composition, not via the circuit.

**In-threat-model?** No. The construction does not model an adversary (or honest-but-curious verifier) with access to on-chain enrollment data. The verifier is treated as seeing only the proof's public signals, but on-chain data is public by construction.

---

### Attack 3: SE-PLONK citation does not cover the default proving backend

**Attack:**
The construction specifies in §3.1(e): "The agent-class circuit upgrades from standard PLONK to simulation-extractable PLONK (SE-PLONK) per Ganesh–Khoshakhlagh–Kohlweiss (Eurocrypt 2022)." However, the *default* proving backend stated in §3.1(c) is **Halo2 with inner-product argument (IPA) commitment scheme**, explicitly chosen to be "fully transparent" (no trusted setup). The GKK 2022 result (SE-PLONK) is proven in the algebraic group model (AGM) + random oracle model for *KZG polynomial commitments*. IPA-based Halo2 uses a *different* commitment scheme with a fundamentally different extractor: IPA requires rewinding (the extractor runs the prover multiple times with the same randomness prefix), which breaks down in protocols where the prover is stateful or where the reduction needs to be tight. The simulation-extractability result for GKK 2022 does not transfer to IPA without re-proving it for that commitment scheme — no such proof is cited or sketched.

**Why it works:**
Assumption A3 ("knowledge soundness of PLONK in the algebraic group model + ROM") is cited but the AGM applies to KZG-based polynomial protocols, not IPA. Halo2's IPA accumulator construction has knowledge soundness arguments (from Bünz–Bootle–Boneh–Fischlin–Fischlin–Maller, S&P 2020), but these do not include simulation-extractability as defined in GKK 2022 Definition 3. If the construction is using Halo2 + IPA as default and the SE-PLONK upgrade is applied, the combined system has no published security proof. The "+15% constraint overhead" for the SE transformation layer (§3.1(e)) suggests a concrete circuit modification, but if the underlying commitment scheme doesn't support the simulation-extractability proof, those constraints are cosmetic.

**Concretely:** A verifier using `sessionNonce` as a verifier-chosen challenge can, in an IPA-based system, potentially extract reusable proof components (the IPA inner product proof is a multi-round Σ-protocol transcript, and selective abort attacks apply differently than in KZG). The document claims SE-PLONK prevents this, but cites a result that covers a different proof system.

**In-threat-model?** No. The combination of Halo2+IPA+SE layer is not proven secure; the cited paper's result requires KZG. The construction must either: (a) default to KZG-backed PLONK with the mandatory ceremony parameters, and prove the SE transformation applies; or (b) provide an independent simulation-extractability proof for Halo2+IPA.

---

### Attack 4: The fingerprint registry de-anonymizes operators at lookup time

**Attack:**
Section §3.1(b) states: "the model provider publishes a fingerprint registry mapping `(model_family_id → expected_fingerprint_set)` ... the verifier confirms that a presented `modelOperatorFingerprint` appears in the registry for the claimed `model_family_id`, confirming the model class, but cannot determine which specific operator produced it." This is false if the registry is enumerable and the per-operator fingerprint is deterministic.

`modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask)`.

Each enrolled operator has a distinct `operatorPubkeyAx`. Since Poseidon3 is collision-resistant (assumption A1), distinct operators produce distinct fingerprints. The registry is a *set* of these fingerprints — one per enrolled operator. Any verifier who has ever seen a proof from SECU (and knows SECU's `operatorPubkeyAx` from, say, the Merkle tree enrollment transaction) can compute SECU's fingerprint directly and confirm it against the registry. From that point forward, every proof with that fingerprint is attributable to SECU. The set-membership check does not hide which element matched; it identifies it.

**Formal gap:** The privacy property stated in §3.1(b) is not formalized as a game. There is no simulator defined for what the verifier is and is not permitted to learn. The informal claim "cannot determine which specific operator" contradicts the fact that `operatorPubkeyAx` appears verbatim as a Poseidon3 input and the operator's public key is observable from enrollment transactions. The document does not distinguish between "the fingerprint hides the operator" (false — the input is observable) and "the hash output is pseudonymous" (true but useless if the pre-image is known).

**In-threat-model?** No. The construction's ZK property for operator identity is not formally stated and is defeated by on-chain observability of `operatorPubkeyAx`. An active verifier — including the model provider who runs the registry — can de-anonymize every proof.


## Persona: cu_ciso

---

### Attack 1: The Examiner Can't Run a PLONK Verifier

**Attack:** Section 7 states the NCUA examiner "verifies each PLONK proof against on-chain roots." My examiner is not a cryptographer. She runs through the FFIEC CAT questionnaire and asks me to produce a readable audit log and demonstrate effective third-party oversight per NCUA Part 748 Appendix A §I.B. I cannot hand her a batch of `{agentMerkleRoot, nullifierHash, scopeCommitment, messageHash}` tuples and say "verify the PLONK." Who operates the verifier? If it's SECU-operated tooling, the examiner is trusting my own infrastructure — the same thing she'd be trusting if I just ran `SELECT * FROM agent_logs`. If it's a third-party verification service, that's another unexamined vendor. The construction never specifies the verification stack, its operator, or its audit posture.

**Why it works / why it fails:** The construction is cryptographically sound but operationally silent on examiner-facing tooling. There is no SOC 2 Type II report for the verifier. There is no NCUA-recognized mapping of "valid PLONK proof" to a control in the FFIEC CAT. A proof system that requires specialized software to interpret does not constitute an "audit trail they understand" under standard examination practice.

**In-threat-model?** No. The construction defines its security game in §3 but never defines how a non-cryptographer regulator consumes proof outputs. The construction must specify: (a) who operates the canonical verifier, (b) what that party's examination posture is, and (c) what human-readable artifact accompanies each proof so an examiner can correlate it to a member transaction without running elliptic curve arithmetic.

---

### Attack 2: Anthropic's HSM + the On-Chain Registry Are Unexamined Third Parties

**Attack:** My Vendor Management Policy requires documented SLAs, right-to-audit clauses, business continuity assessments, and NCUA-compatible oversight for every critical service provider. The construction chains my entire credential enrollment on two dependencies I cannot examine: (1) Anthropic's HSM-held BJJ signing key (§3, enrollment protocol — "provider generates key in an HSM"), and (2) whatever blockchain hosts the provider registry ("governance-multisig or DAO-controlled," §3). The construction even acknowledges that new credentials cannot be enrolled without a new deployment authorization from Anthropic. If Anthropic's attestation service is down, I cannot onboard a new model or rotate my BJJ key. If the on-chain registry suffers a governance failure or a chain reorganization, `providerRegistryRoot` is undefined. Neither entity is a supervised financial institution. Neither can sign a right-to-audit addendum that satisfies NCUA's third-party risk guidance (Letter to Credit Unions 07-CU-13).

**Why it works / why it fails:** The construction's key rotation section (§4) correctly notes that historical proofs survive API key rotation. But it never addresses availability SLAs for the attestation issuance path. A "DAO-controlled" registry has no legal entity to contract with, no incident response SLA, and no examination-ready documentation. The GLBA Safeguards Rule (16 CFR §314.4(f)) requires me to oversee service provider arrangements — I cannot oversee a multisig DAO.

**In-threat-model?** No. The threat model in §3 treats the provider registry as a trusted on-chain state and out-of-scope for the cryptographic game. For a regulated credit union, availability and governance of that registry are in-scope for NCUA examination. The construction must define: (a) the SLA for `providerRegistryRoot` availability, (b) the legal entity responsible for the registry and attestation service, and (c) an off-chain fallback or pre-issued attestation cache for continuity.

---

### Attack 3: The Operator BJJ Key Is a Live Runtime Secret in the PII Environment

**Attack:** Section 7 runtime proving states: "When a Sonnet agent processes a member inquiry, the agent generates a PLONK proof." Generating that proof requires the operator BJJ private key as a signer over `credentialCommitment` (constraint 4). That means the BJJ private key must be accessible to the agent process at inference time — in the same environment that touches member PII. The construction's enrollment section (§3) says "SECU generates operator BJJ keypairs per deployment environment" but says nothing about key custody — HSM? software key store? environment variable? The key rotation section (§4) correctly notes that BJJ keypairs are independent of API bearer tokens, but independence from API keys does not mean the BJJ key is safe.

**Why it works / why it fails:** If the agent runtime is compromised — container escape, SSRF to instance metadata, supply chain attack on the agent library — the attacker exfiltrates the BJJ private key. Now they can produce valid PLONK proofs claiming to be SECU's authorized Sonnet agent for any `messagePlaintext` they choose. The nullifier does prevent double-use of a specific session, but the adversary can generate fresh sessions using the stolen key. The construction's threat model (§3) explicitly excludes adversaries who "control the on-chain provider registry" and "control the model provider's BJJ signing key" — but it says nothing about adversaries who exfiltrate the *operator's* BJJ private key, which is a far lower bar for a real attacker targeting a credit union.

**In-threat-model?** No. The construction's security game defines an adversary who has enrolled credentials for a different model but never considers an adversary who steals the operator's signing key from a runtime environment. GLBA §314.4(c) requires access controls for systems containing member data. If the BJJ key is a software secret co-located with the PII agent, it is effectively member-data-adjacent. The construction must address operator key custody — HSM requirement, key isolation from agent runtime, and what happens when the operator key is compromised (revocation path, proof invalidation).

---

### Attack 4: The Message Hash Is Not an Audit Record — I Cannot Dispute a Member Claim

**Attack:** Section 7 claims the examiner can confirm "this PII operation used Opus" from the proof. True. But the construction makes `messagePlaintext` a **private input** (§2, private inputs list). The public output is `messageHash = Poseidon(messagePlaintext)` — a hash, not the content. When a member calls at 2am saying the AI agent denied their loan for discriminatory reasons, my Tier 1 ops team has `messageHash`. They cannot reverse a Poseidon hash. The construction has no specified mechanism to recover `messagePlaintext` from `messageHash` for a legitimate dispute — no log correlation spec, no complementary plaintext store, nothing. For UDAP compliance (12 CFR Part 1031) and NCUA's consumer financial protection examination, I need to produce the actual interaction, not its preimage-hiding hash.

**Why it works / why it fails:** The construction is designed to protect operator privacy from the verifier, which is appropriate for the audit use case described. But the credit union is both prover *and* the party legally obligated to produce records for member disputes and regulatory examination. The zero-knowledge property that protects SECU from revealing call history to the examiner *also* prevents SECU's own ops team from using the proof artifacts to retrieve the interaction plaintext. A separate, non-ZK audit log must exist — but the construction neither mandates it nor specifies how `messageHash` correlates to entries in that log. If the ZK layer and the plaintext log drift (log deleted, session ID mapping lost), SECU has a cryptographic receipt for something it cannot explain in English.

**In-threat-model?** No. This is out of the cryptographic threat model by design, but it is squarely in SECU's operational risk. The construction must specify: (a) the complementary audit log architecture (what plaintext store, access controls, retention policy), (b) the indexing scheme mapping `nullifierHash` or `sessionNonce` to a retrievable member interaction record, and (c) who at SECU can access that log under what authorization policy — because the NCUA examiner, the member, and SECU's compliance team all have legitimate but distinct retrieval rights.


## Persona: rfc7662_advocate

---

### Attack 1: Signed JWT Introspection Response Removes AS From the Hot Path — §3.1(d) Overstates the Gap

**Attack:**
The construction's central differentiator in §3.1(d) and §8(c) is "AS-blindness": *"the AS never learns which model or operator produced a given proof."* The dismissal of WIMSE rests on this claim. But the construction conflates *RFC 7662 active introspection* (AS queried per-call) with all OAuth token validation paths. `draft-ietf-oauth-jwt-introspection-response` changes the threat model entirely: the AS issues a **signed JWT introspection response** containing `model_id`, `operator_id`, and `permission_bitmask` claims, cached at the RS. Subsequent requests are verified locally against the provider's public key — the AS is out of the real-time path after initial issuance. The AS sees one event per deployment window, not per call. §8(c) says *"Bolyra's provider attestation is offline — the provider signs a deployment authorization once per (operator, model) pair, not per call"* — but this is precisely what a long-lived signed JWT introspection response provides: one issuance event, unlimited offline verifications. The construction has not shown that per-deployment AS visibility is the threat being neutralized; it has only shown that per-call introspection introduces correlation, which the JWT introspection response draft already solves without ZK.

**Why it works / why it fails:**
The construction fails to engage with the JWT introspection response draft by name. The claim "the AS sees every call" is only true for the base RFC 7662 active introspection flow. Against signed JWT introspection with RS-side caching, the construction would need to argue that *initial issuance* (one event per deployment, not per call) constitutes an unacceptable linkage — a much weaker claim that applies equally to Bolyra's enrollment protocol, where Anthropic learns `(modelHash, operatorPk)` pairs at deployment agreement time.

**In-threat-model?** No — construction must address. The gap-to-close in §8(c) explicitly lists this as a required proof and provides only the per-call introspection argument, not the JWT introspection response argument.

---

### Attack 2: The §3.1(b) Fingerprint Registry Partially Deanonymizes Operators — Privacy Claim Is Self-Defeating

**Attack:**
Section 3.1(b) introduces the `modelOperatorFingerprint` public signal and states the model provider publishes a *public* registry mapping `{model_family_id → expected_fingerprint_set}`, where each entry is `Poseidon3(modelHash, operator_pk, permissionBitmask)` for all enrolled operators. The stated privacy property is: *"the verifier confirms that a presented fingerprint appears in the registry… but cannot determine which specific operator produced it — the registry contains fingerprints for all enrolled operators and the mapping from fingerprint to operator identity is not published."* But the fingerprint formula is `Poseidon3(modelHash, operatorPkAx, permissionBitmask)` — a deterministic hash of *public* inputs. `operatorPkAx` is the operator's BJJ public key, which is submitted to the agent Merkle tree (§2 enrollment protocol: "Operator submits `credentialCommitment` for insertion into the agent Merkle tree"). The Merkle tree is described as *permissionless and append-only*. A monitoring adversary who observes all Merkle tree insertions over time can enumerate the set of enrolled operator public keys. Given that set, they can reconstruct every possible fingerprint by computing `Poseidon3(modelHash_i, operatorPk_j, permBitmask_k)` for all combinations and match against the registry. In a realistic deployment (e.g., SECU is one of a small number of NCUA-regulated credit unions with Anthropic agreements), the operator set is small and enumerable. The "operator anonymity" property collapses to *k*-anonymity where *k* ≤ number of enrolled operators — not selective disclosure of a single bit.

**Why it works / why it fails:**
This attack is within the threat model because the Merkle tree is permissionless. The construction does not claim the operator public key is secret — it is a public input to the credential enrollment. The fingerprint registry's privacy guarantee is only as strong as the operator key pseudonymity, which the append-only public Merkle tree defeats. A baseline system using RFC 8707 audience-bound tokens with pairwise pseudonymous identifiers achieves equivalent or stronger unlinkability without this registry exposure.

**In-threat-model?** Yes — construction survives if (and only if) operator public keys are kept off-chain and the Merkle tree is a commitment-only structure without revealing leaf preimages publicly. The construction does not currently specify this constraint; §2 implies the tree is observable.

---

### Attack 3: RFC 8693 Token Exchange With Provider-as-Exchange-Participant Achieves Operator-Bound Model Attestation

**Attack:**
The gap-to-close demands the construction prove *"RFC 8693 token exchange and DPoP cannot achieve (a)+(c) simultaneously."* The construction's §8(a) dismissal targets only self-asserted `model_id` claims (operator-controlled SPIRE/SVID). But RFC 8693 supports a three-party exchange where Anthropic acts as an *intermediate Authorization Server*, not just an identity provider. Concretely: (1) SECU operator presents API credentials to Anthropic's AS; (2) Anthropic's AS validates SECU's deployment agreement for Sonnet 4.6 and issues a **DPoP-bound** structured access token (RFC 9449) containing `model_id=sha256(sonnet-weights)`, `operator_sub=SECU-ppid`, `permission_bitmask=0x...`, bound to SECU's ephemeral DPoP key; (3) SECU presents this token to the RS with a DPoP proof covering the request `htu`+`htm`+nonce — binding the specific HTTP request to the token. The RS verifies offline: Anthropic's token signature (model_id is Anthropic-asserted, not operator-asserted) + DPoP proof (sender-constraint, equivalent to operator EdDSA over `credentialCommitment`). This achieves: (a) non-malleability — Anthropic's AS signature over `(model_id, operator_sub)` cannot be forged by an operator with wrong model credentials; (c) the RS sees only `{model_id, operator_sub, permission_bitmask, request_hash}` from the DPoP proof. The "AS sees every hop" concern from the gap-to-close applies only to *introspection-based* RFC 8693 — a JWT-assertion grant (RFC 7523 subject_token) with DPoP binding avoids any AS involvement per call.

**Why it works / why it fails:**
The construction's §8(a) argues only that SPIFFE/WIMSE is operator-controlled. It does not address the case where the model provider (Anthropic) is the token exchange participant asserting `model_id`. In that configuration, the `model_id` claim has the same root of trust as Bolyra's `providerSig` over `deploymentAuthorization` — both originate from Anthropic, both are offline-verifiable. The remaining difference is: Bolyra hides the provider's signature from the RS (§8(e)), whereas RFC 8693 reveals Anthropic's token signature. Whether this differential privacy — provider key privacy to the RS — is load-bearing for the stated threat model (NCUA auditor scenario, §7) is not argued in the construction. The construction must either (a) show that provider-key privacy to the RS is required by the threat model, or (b) acknowledge this gap and scope the claim to that privacy property specifically.

**In-threat-model?** No — construction must address. The explicit proof obligation in the gap-to-close is not met by the current §8, which targets a weaker adversary (operator-controlled SPIRE) rather than provider-as-exchange-participant.

---

### Attack 4: modelHash Binds Authorization Agreements, Not Runtime Inference — Equivalent to an X.509 Custom OID

**Attack:**
Section §3.1(a) specifies `modelHash := Poseidon2(keccak256(weights_blob), model_family_id)` where `weights_blob` is *"the canonical byte representation of the served weight tensor, post-quantization and pre-inference."* The construction explicitly disclaims runtime-execution binding in §8(g): *"Binding proof of which model weights were actually loaded into GPU memory at inference time requires a TEE or secure enclave attestation and is not claimed by this construction."* So what does the PLONK proof actually bind? It binds an **authorization credential** — a Poseidon5 commitment that embeds a `modelHash` which Anthropic included in a deployment authorization, signed offline per deployment agreement. The `modelHash` in the signed attestation is Anthropic's *declaration* of what they agreed to deploy; it is not derived from or verified against actual runtime memory. This is structurally identical to: Anthropic issuing an X.509 certificate to SECU with a custom OID extension `1.3.6.1.4.1.ANTHROPIC.1.1 = sha256(sonnet-4-6-weights)`, signed by Anthropic's intermediate CA. SECU presents this certificate in a TLS mutual-auth handshake; the RS verifies offline against Anthropic's published CA. The ZK proof adds: (1) hiding of the certificate itself (the X.509 chain is not revealed to the RS), and (2) the permission bitmask predicate. Property (1) is achievable with BBS+ selective disclosure over a JSON-LD credential containing the same `model_id` claim signed by Anthropic. Property (2) is a bitwise-AND predicate — implementable in BBS+ via `msg_i * (1 - required_i) = 0` analogues in BBS+ CL-style proofs or via range proofs over bitmask values. The construction's scenario §7 ("NCUA examiners require proof that only approved model instances processed member data") is satisfied by presenting a BBS+ derived proof over an Anthropic-issued credential revealing only `{model_family_id, permission_class}` — no ZK arithmetic circuit required.

**Why it works / why it fails:**
This attack is strengthened, not weakened, by §8(g)'s explicit disclaimer of runtime-execution binding. If `modelHash` is an authorization-agreement hash (not a runtime-execution hash), then all downstream ZK machinery proves only that a credential containing this hash was enrolled and signed — a property BBS+ selective disclosure achieves without PLONK. The construction would need to identify a specific property of the PLONK circuit that BBS+ cannot provide over the same input set. The current §8(d) identifies only the permission bitmask predicate as a distinguishing feature — but does not explain why BBS+ CL-style range proofs over the bitmask are insufficient for the 64-bit `permissionBitmask` field.

**In-threat-model?** No — construction must address. The runtime-execution disclaimer in §8(g) concedes the strongest form of the claim; the remaining authorization-binding claim must be defended against BBS+ + Anthropic-as-issuer, not just against SPIFFE/WIMSE.


## Persona: spiffe_engineer

Staff engineer running SPIFFE/SPIRE in production at a Fortune 500, co-author of WIMSE drafts. Thesis: workload identity is a solved problem — you are rebuilding infrastructure that already exists, at the wrong layer, with weaker runtime guarantees.

---

### Attack 1: The modelHash Oracle Problem — Who Measures the Weights?

**Attack:** §3.1(a) defines `modelHash := Poseidon2(keccak256(weights_blob), model_family_id)` and says the provider issues `deploymentAuthorization = Poseidon3(modelHash, operatorPkAx, operatorPkAy)`. But the threat model never addresses how Anthropic learns what `keccak256(weights_blob)` to sign. The enrollment flow (§7, step 2) describes Anthropic computing `deploymentAuthorization` when SECU "signs a deployment agreement" — this means the operator-supplied hash is taken on faith. Anthropic signs a hash that SECU claims corresponds to Sonnet 4.6 weights, but Anthropic has no in-band mechanism to verify SECU is actually running those weights at inference time. The operator in the liability scenario (scenario 2: "bank claims agent drained account") is precisely the adversary who might want to run fine-tuned or cheaper weights while claiming a premium, audited model.

**Why it works / why it fails:** The construction concedes this in §8(g): "Binding proof of which model weights were actually loaded into GPU memory at inference time requires a TEE or secure enclave attestation and is not claimed by this construction." This is an honest admission, but it is fatal to scenarios 1 and 2. Scenario 1 ("only approved models touched PII files, never unapproved deployments") and scenario 2 ("proves which specific model+operator made the transaction") both require that the `modelHash` in the proof corresponds to the weights actually executed — not the hash the operator told Anthropic to sign six months ago when they signed the deployment agreement. An operator who rotates their serving infrastructure to a cheaper distilled model retains a valid deployment authorization signed against the original `modelHash`. Every proof they generate is cryptographically valid. The NCUA examiner sees `modelOperatorFingerprint` matching Sonnet 4.6 and is satisfied, while the actual compute was something else entirely. SPIFFE with SGX node attestation at least binds the SVID to a measured enclave image at node registration time — not at deployment agreement signing time.

**In-threat-model?** No. The adversary class "authorized operator who asserts a false modelHash at enrollment" is not in MODEL-BIND-FORGE v2. The game explicitly assumes the operator receives a legitimate deployment authorization for model M_adv and cannot forge one for M_target. But the threat model does not include the case where the operator is M_target's legitimate authorized operator and lies about what they serve. This class needs explicit treatment or the liability and regulatory scenarios collapse to "the operator told us they ran Sonnet, and we have proof they told us."

---

### Attack 2: The SPIFFE ZK Attestor Extension — Wrong Abstraction Layer

**Attack:** SPIRE supports custom node attestors via a plugin interface. You can write a ZK attestor that, at SVID issuance time, requires the workload node to produce a ZK proof of model weight hash inclusion in a provider-maintained registry — essentially embedding the `BinaryMerkleRoot(8)` + `EdDSAPoseidonVerifier` gadget from §2 constraint 2 as a SPIRE attestor plugin. The SVID is then only issued to nodes that pass this attestation. The resulting SVID path is: `spiffe://anthropic.com/models/sonnet-4-6/secu` — a first-class SPIFFE identity with all the federation, revocation, and short-lived credential tooling that already exists. §3.1(d) dismisses WIMSE by saying "the AS learns which workload identity is requesting which model capability," but this is architectural, not fundamental — the ZK attestor keeps the weight-hash proof inside SPIRE; the SVID itself is opaque to downstream services.

**Why it works / why it fails:** The construction's WIMSE rebuttal in §3.1(d) pivots entirely to "AS-blindness": the claim that neither the AS nor any intermediary should learn which model produced a given proof. But look at the concrete scenarios: scenario 1 (CISO proving approved models touched PII), scenario 3 (tiered pricing verification), scenario 4 (FDA/EU AI Act chain of custody) — none of these require AS-blindness. They require *third-party-verifiable* model identity binding, not *AS-invisible* model identity binding. The NCUA examiner in §7 receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per transaction — the examiner is a third-party verifier, not an AS. If the examiner can verify a SPIFFE SVID chain from Anthropic's trust domain to SECU's deployment SVID, the requirement is met without a 25K-constraint ZK circuit. The AS-blindness property is not required by the stated scenarios; it is an engineering preference being sold as a necessity. The WIMSE gap argument in §8(c) depends on "AS sees every call" being a problem — but for regulated audit trails, the AS seeing the call is often a *feature* (it is a compliance log).

**In-threat-model?** No. The gap analysis in §3.1(d) and §8 never addresses the combination: SPIFFE federation (Anthropic as root trust domain) + ZK attestor plugin + BBS+ selective disclosure on the SVID. This combination satisfies the verifier's lookup requirements without a new protocol. The construction must either (a) demonstrate a concrete property that this stack cannot achieve, or (b) acknowledge that the ZK construction is an optimization choice, not a necessity.

---

### Attack 3: The Permissionless Merkle Tree Is a Liveness Attack Surface

**Attack:** §2 (enrollment protocol, credential enrollment) and §3 (why permissionless tree insertion is safe) establish that the agent Merkle tree is append-only and accepts any `credentialCommitment` without authorization checks. The argument is that invalid commitments are harmless because no valid proof can be produced without a matching provider signature. This is correct for soundness but ignores liveness. An adversary who wants to prevent legitimate provers from generating valid proofs can flood the tree with garbage commitments until the depth-20 Incremental Merkle Tree (max ~1M leaves) is full. At that point, no new legitimate credentials can be enrolled. The attack costs approximately 1M on-chain insertions — expensive but not economically infeasible for a nation-state adversary or a competitor attempting to block a specific operator's regulatory compliance filings.

**Why it works / why it fails:** The construction has no rate limiting, spam filtering, or staking mechanism on tree insertion. §2 explicitly says "the tree accepts any `credentialCommitment`." The circuit-as-gatekeeper argument is valid for preventing *fraudulent proofs* but provides zero protection against *tree exhaustion*. SPIRE's agent registration has built-in authorization: an agent must pass node attestation before it can register a workload — the SPIRE server is the gatekeeper at insertion time, not at proof time. The "circuit is the sole gatekeeper" design transfers all authorization to proof time, which is correct for privacy but creates a liveness vulnerability. The depth-20 tree holds ~1M leaves at ~32 bytes each = ~32MB of leaf data; on-chain insertion via a typical Merkle tree contract costs ~50K gas per insertion; 1M insertions × 50K gas × (current gas price) = a quantifiable DoS budget. The construction must either (a) add a minimum-stake requirement for tree insertion, (b) move to a dynamic-depth or forest structure, or (c) acknowledge the liveness bound and characterize it as acceptable.

**In-threat-model?** No. The adversary in MODEL-BIND-FORGE v2 attempts to produce a valid *proof* for a false statement. A liveness adversary does not attempt to forge a proof — they attempt to prevent tree insertions, which is outside the game definition entirely. The threat model needs a separate liveness game.

---

### Attack 4: The Fingerprint Registry Breaks AS-Blindness for the Verifier

**Attack:** §3.1(b) introduces a "fingerprint registry" where the model provider publishes `Poseidon3(modelHash, operator_pk, permissionBitmask)` for all enrolled operators, indexed by `model_family_id`. The stated purpose is to allow verifiers to confirm that a `modelOperatorFingerprint` output corresponds to a legitimate model class without revealing operator identity. But this registry is published by the provider and contains one entry per enrolled `(model, operator, bitmask)` triple. A verifier who receives a proof from an operator can scan the fingerprint registry to narrow down which operator produced it: if the registry for `model_family_id = sonnet-4-6` contains 47 entries and the verifier observes the same `modelOperatorFingerprint` repeatedly in proofs from the same API endpoint, they can correlate fingerprint → operator identity through traffic analysis. This is not EdDSA forgery — it is a metadata correlation attack that the circuit provides no protection against.

**Why it works / why it fails:** The construction claims in §3.1(b) that "the verifier confirms that a presented `modelOperatorFingerprint` appears in the registry for the claimed `model_family_id`, confirming the model class, but cannot determine which specific operator produced it." This is only true if the fingerprint registry is large enough to provide anonymity — i.e., if many operators share the same `(modelHash, permissionBitmask)` and their fingerprints are indistinguishable. But `Poseidon3(modelHash, operatorPkAx, permissionBitmask)` is unique per operator (different `operatorPkAx`), so each entry in the fingerprint registry maps 1:1 to a specific operator's public key. The "mapping from fingerprint to operator identity is not published" — but the fingerprint registry *is* published, and the operator's public key is the unique differentiator. If the operator's public key is ever correlated with their real identity (e.g., through the enrollment transaction, the deployment agreement, or the authenticated API dashboard delivery in §7 step 2), the fingerprint is permanently deanonymized. WIMSE with BBS+ derived proofs has the same per-issuance unlinkability problem, but at least BBS+ link secrets prevent correlation across multiple presentations of the same credential. Bolyra's `modelOperatorFingerprint` is deterministic and stable across all proofs from the same operator — making it a long-lived correlation handle that appears in every public output of every proof.

**In-threat-model?** No. The game definition specifies what the verifier learns as `{model_hash, operator_pk, permission_bitmask, message_hash}` (from the gap-to-close statement), and the circuit's privacy property is that the verifier sees only `modelOperatorFingerprint` (not the raw `operatorPk`). But the fingerprint registry in §3.1(b) effectively publishes the mapping from fingerprint to a unique per-operator tag, defeating the privacy claim for any verifier with access to the published registry and the ability to correlate enrollment transactions. The construction needs either (a) a blinded fingerprint scheme where the operator randomizes their fingerprint per proof (breaking verifier lookup) or (b) a k-anonymity requirement on the registry (no fingerprint is unique to fewer than k operators) — neither of which is currently specified.
