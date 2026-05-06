# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

---

### Attack 1: The Anthropic Bootstrapping Problem — Your Trust Root Doesn't Exist Yet

**Attack:**
Section 7 of the construction describes a "one-time setup" where "Anthropic generates a BJJ keypair in an HSM" and inserts a public key commitment into the on-chain provider registry. I'll call procurement and ask one question: *Has Anthropic agreed to this?* The construction assumes a cooperative model provider who runs a key ceremony, maintains an HSM, signs per-model `modelHash` tuples, and publishes them to an attestation registry. Until Anthropic does that, no SECU enrollment is possible — no credential, no proof, no product.

**Why it works:**
This is a distribution attack, not a cryptography attack. Auth0, WorkOS, and Stytch work *today* with zero cooperation from Anthropic. SECU's IT team can paste a WorkOS client_id into their AI agent config this afternoon. Bolyra requires Anthropic to:
1. Run an HSM key ceremony (they haven't said they will)
2. Publish `(modelHash, providerSig)` per model release (new operational process)
3. Maintain the provider registry on-chain (operational dependency forever)
4. Sign `modelHash = Poseidon("claude-sonnet-4-6:sha256:ab3f...")` — a hash of a name string and weight checksum they compute

The construction addresses key rotation (Section 4, Provider key rotation) and historical proof validity, but never addresses Day 0: who runs the first key ceremony and why would Anthropic do it for a solo-founder protocol?

**In-threat-model?** No. The construction's security argument (Section 4) is airtight *given* that `providerRegistryRoot` is populated with Anthropic's real key. But the go-to-market gap — getting Anthropic to participate — is not addressed anywhere. A CISO cannot buy a product whose root of trust requires a third party's operational cooperation that hasn't been secured. **Construction must address this.**

---

### Attack 2: Proving Latency Makes High-Frequency Agent Calls Impractical

**Attack:**
Section 6 claims "<5s proving time target" for ~23,100 constraints. I'll grant that number. Now let me describe a real SECU deployment: a loan servicing agent handling 500 concurrent member inquiries, each requiring 3–8 tool calls (lookup member record, check balance, pull credit score, draft response). That's 1,500–4,000 proofs per minute *per agent instance*. At 5s/proof, a single agent thread can generate 12 proofs/minute. To serve 500 concurrent users, SECU needs ~125 parallel proving threads — dedicated GPU/CPU hardware running continuously.

WorkOS issues OAuth tokens in <100ms. Auth0 issues in <50ms. The construction's Section 6 note that "PLONK proving on a modern CPU remains well under 5s" is true for *one proof*. It says nothing about proof throughput, infrastructure cost, or operational complexity at scale. The construction also claims the proving time is "comparable to Semaphore's 30K-constraint circuits which prove in ~3s on similar hardware" — Semaphore is used for *one-time human uniqueness proofs*, not for every tool call.

**Why it works:**
The construction is designed for audit scenarios (Section 7: "NCUA examiners require proof..."). But the `messageHash` in the public outputs is described as binding "the tool-call payload being bound" (Section 2, Circuit). If every tool call requires a fresh proof (different `messagePlaintext`, different `sessionNonce`, different `nullifierHash`), then proving latency is *per call*, not per session. The construction never specifies whether proving happens synchronously in the request path or asynchronously as an attestation log — a critical omission that procurement will catch.

**In-threat-model?** No. The threat model (Section 3) addresses adversary capabilities but not operational deployment constraints. A CISO at a regulated institution cannot adopt a protocol with undefined throughput characteristics and unbounded infrastructure cost. **Construction must specify: synchronous vs. asynchronous proving mode, proof batching strategy, and infrastructure requirements for the SECU scenario.**

---

### Attack 3: modelHash Binds an Identifier, Not a Running Model

**Attack:**
Section 2 defines `modelHash = Poseidon(model_identifier_canonical)` where `model_identifier_canonical` is "a deterministic encoding of the model name, version, and weight checksum (e.g. `claude-sonnet-4-6:sha256:ab3f...`)." The construction then argues this proves "this call was made by Claude Sonnet 4.6" (Section 1 claim).

It doesn't. It proves Anthropic signed a *string* that contains a weight checksum. The string is a claim by Anthropic about what they shipped. The circuit verifies that the operator enrolled against that string and that their tool call is bound to a credential referencing it. But between "Anthropic signs `sha256:ab3f...`" and "the inference that generated this tool call ran those exact weights," there is no cryptographic link whatsoever.

What actually runs in Anthropic's inference cluster is:
- Quantized or distilled variants (GPTQ, AWQ, bfloat16 vs float32)
- Speculative decoding models layered on top
- Routing layers that may serve different backend shards
- Fine-tuned versions for specific customers

The weight checksum in `model_identifier_canonical` is whatever Anthropic *claims* it is. The construction conflates "Anthropic attested this identifier" with "the model running at inference time matches these weights." The Section 8 argument correctly notes that SPIFFE SVIDs certify process identity but not model weights — but Bolyra's `modelHash` has the same problem at the provider level: it's a hash of a name+checksum tuple that Anthropic writes, not a cryptographic measurement of running computation (like a TPM PCR quote or an SGX measurement register).

**Why it works:**
Section 4 (Security argument) addresses MODEL-BIND-FORGE — proving that an adversary with Opus credentials cannot claim Sonnet identity. This is sound. But the construction's Section 1 claim — that the proof attests "which specific model+operator made the transaction" (scenario 2) or that it satisfies "FDA/EU AI Act demands provable chain from deployed model weights to each inference output" (scenario 4) — overstates what the construction achieves. An auditor who asks "prove Claude Sonnet 4.6's actual weights processed this PII" gets a proof that Anthropic signed a string containing a weight checksum. That is not a chain from weights to inference output.

**In-threat-model?** Partially. The MODEL-BIND-FORGE game is correctly specified for the narrow claim of "Opus key cannot forge Sonnet proof." But the broader claims in Section 1 scenarios go beyond what the construction cryptographically establishes. **Construction must either scope down its claims (C7 proves model-class credential binding, not weight-level inference attestation) or add a TEE/remote attestation layer that links the provider-signed modelHash to an actual measurement of running weights.**

---

### Attack 4: Client Attestation + DPoP Already Provides Third-Party Model Binding

**Attack:**
Section 8 of the construction argues "No vanilla OAuth/MCP auth can bind runtime model identity to the message, because OAuth `client_id` identifies only the registered application." This is true of vanilla OAuth. But the construction's own gap analysis cites `draft-ietf-oauth-attestation-based-client-auth` as a known baseline — and the draft does exactly what the construction claims OAuth cannot do.

Under Client Attestation (draft-ietf-oauth-attestation-based-client-auth §4): the Attester (e.g., Anthropic) issues a signed Client Attestation JWT bound to the client's DPoP key. The JWT can carry arbitrary claims — including `model_id`, `model_hash`, and `permission_bitmask`. At token request time, the AS verifies the Attester's signature over these claims. The resulting access token is DPoP-bound (non-transferable, proof-of-possession). The message binding can be achieved via DPoP proof's `htm`/`htu` claims or via a signed request object.

This achieves:
- **(a) Non-malleability**: Attester signature is over `model_id` — operator with Opus credentials cannot produce a valid Attester JWT claiming Sonnet without Anthropic's signing key. Identical assumption to Bolyra's A2.
- **(b) Key rotation**: DPoP keys are ephemeral; the Attester JWT contains a `cnf` binding the current DPoP key. Rotation is a new DPoP key + new Client Attestation exchange.
- **(c) Selective disclosure**: The verifier (RS) sees the access token with the attested claims. If the AS is in the path, it sees the attestation — but the RS verifying the DPoP proof offline sees only the bound claims, not the full session history.

Section 8's rebuttal to BBS+ is that "the operator cannot write any `model_id` claim" if "an AS enforces the model-identity claim at issuance" because that "re-introduces the correlation problem (AS sees every call)." But Client Attestation with a short-lived Attester JWT (issued per model release, not per call) achieves the same offline-ness that Bolyra claims. Anthropic issues the Client Attestation JWT for Sonnet once; operators present it at token time; the AS validates Anthropic's signature and issues a short-lived, DPoP-bound access token. Per-call: the RS verifies DPoP offline. Anthropic is not in the per-call path.

**Why it works:**
The construction's Section 8 argument against BBS+ and SPIFFE is sound, but it does not directly address the Client Attestation draft with DPoP + short-lived Attester JWTs. The gap — "AS sees every call" — does not apply when the Attester JWT has a lifetime of hours/days (per model release cadence) and the per-call verification is a DPoP check at the RS. The construction needs to show either (1) Client Attestation + DPoP cannot achieve simultaneous (a)+(c), or (2) what Bolyra's ZK layer adds over and above that baseline.

The ZK layer does add something real: the verifier in Bolyra does not learn the operator's public key or the provider's public key — only the `modelOperatorFingerprint` (Section 2, public outputs). In Client Attestation, the RS sees the full attested `model_id` claim and the operator's DPoP key. But whether that differential privacy is worth the 5s proving overhead and the provider bootstrapping requirement is the buyer-level question the construction never answers.

**In-threat-model?** No. The construction's Section 8 baseline comparison skips Client Attestation + DPoP, which is the closest existing mechanism to its core claim. **Construction must either formally show Client Attestation + DPoP fails property (a) or (c), or reframe its differentiation as "ZK unlocks operator-pubkey unlinkability that Client Attestation cannot provide" and argue why that property is worth the tradeoffs.**


## Persona: cryptographer

The construction is more rigorous than most ZK identity papers I see submitted to EUROCRYPT, but it confuses three things: *credential possession*, *computation attestation*, and *linkability properties*. Four attacks below, in decreasing severity.

---

### Attack 1: Credential Possession ≠ Computation Attestation

**Attack:** Operator ACME holds a legitimate Sonnet credential (validly enrolled, Anthropic-signed `modelHash_sonnet`). ACME actually routes the inference to Opus (cheaper, or Sonnet is unavailable). ACME generates a PLONK proof using their Sonnet credential and the Opus-generated response as `messagePlaintext`.

**Why it works against the construction:** The circuit (Section 2, constraint 9) enforces `messageHash = Poseidon(messagePlaintext)` — binding the payload to the hash. But there is **zero constraint linking `messagePlaintext` to the model that produced it**. The proof establishes: "I possess a credential where Anthropic attested `modelHash_sonnet`, and this credential is Merkle-enrolled, and the operator signed it." It does not establish: "the bytes in `messagePlaintext` were produced by forward-passing through weights identified by `modelHash_sonnet`."

The game MODEL-BIND-FORGE (Section 3) asks whether an adversary with `M_adv` credentials can forge a proof claiming `M_target`. It never asks the dual question: **can an operator with `M_target` credentials falsely attest that `M_target` produced a specific output?** That question is entirely outside the threat model.

**Why it fails against the construction:** It doesn't. No cryptographic binding exists between inference computation and the proof. A TEE attestation (e.g., TDX `RTMR` measurement) or a verifiable inference mechanism (e.g., SNARK-based forward pass, or a signed hash of activations from a trusted runtime) would be required in the TCB for this claim to hold.

**In-threat-model?** No. The threat model game must be extended. The FDA/EU AI Act scenario (Section 2, deployment scenario, step 4) requires exactly this — "provable chain from deployed model weights to each inference output" — which the construction cannot provide as specified.

---

### Attack 2: Agent Merkle Tree Self-Enrollment (Missing Authorization Invariant)

**Attack:** Adversary B holds only Opus credentials. The provider attestation tuples `(modelHash_sonnet, providerSig_sonnet, providerPk)` are published in the public attestation registry (Section 2, enrollment protocol). Adversary B:
1. Reads `(modelHash_sonnet, providerSig_sonnet)` from the public log.
2. Constructs `credentialCommitment_fake = Poseidon5(modelHash_sonnet, opPkAx_B, opPkAy_B, perm_B, expiry_B)`.
3. Signs `credentialCommitment_fake` with their own operator BJJ key.
4. Submits `credentialCommitment_fake` for insertion into the agent Merkle tree.

If step 4 succeeds, adversary B can prove "Sonnet made this call" while running Opus, using publicly available provider signatures as private witnesses.

**Why it works / why it fails:** The construction (Section 3, PROVIDER-FORGE reduction) assumes "the adversary does not control any enrolled provider key" and reduces forgery to EdDSA unforgeability. This is correct *if tree insertion is guarded*. But Section 2 only says: "Operator submits `credentialCommitment` for insertion into the agent Merkle tree." No authorization predicate is specified for the smart contract insertion function.

The circuit (constraint 4) verifies the operator signed `credentialCommitment`. This proves the operator knows the credential contents but **does not prove the operator is authorized to deploy `modelHash_sonnet`**. The provider signature verifies inside the circuit — but it's a PUBLIC registry entry, accessible to any adversary. The circuit cannot distinguish "operator who actually runs Sonnet" from "operator who read the public log."

**In-threat-model?** No. The Merkle tree insertion contract must enforce: insertion of a `credentialCommitment` embedding `modelHash_X` requires a separate authorization proof that the operator has a deployment agreement with the provider for model X. As written, the enrollment protocol's off-chain policy is the entire security boundary, and it is unspecified.

---

### Attack 3: PLONK is HVZK + Knowledge Sound, Not Simulation-Extractable — Non-Malleability Claim is Unsubstantiated

**Attack:** The non-malleability claim (gap-to-close item (a)) requires that an adversary seeing valid proofs cannot forge a related proof for a modified statement. This requires **simulation extractability (SE)**, not merely knowledge soundness.

**Game:** Adversary A queries a proof oracle polynomially many times, receiving valid PLONK proofs `{π_i}` for statements `{(publicSignals_i)}`. A then produces a fresh `(π*, publicSignals*)` with `π* ∉ {π_i}` and `PLONK.Verify(vk, publicSignals*, π*) = 1`.

**Why it matters here:** The security argument (Section 4) invokes A3 (PLONK knowledge soundness in AGM+ROM) to extract the witness from any cheating prover. Knowledge soundness gives extraction from a *single proof* in isolation. It does not guarantee that seeing prior proofs from the signing oracle provides no advantage for forging a *new* proof for a *related* statement. Concretely:

- PLONK (Gabizon-Williamson-Ciobotaru, 2019) is proven honest-verifier ZK and knowledge sound in the AGM+ROM. It is **not** proven simulation-extractable in the standard formulation.
- Fiat-Shamir'd PLONK is non-interactive ZK (NIZK) in the ROM, but NIZK ≠ simulation-sound NIZK. SE-SNARKs require additional techniques (e.g., Groth-Maller16, or simulation-extractable wrappers like those in LegoSNARK/Lunar).
- The reduction sketch Case 1/2/3 only works if the extractor can extract a witness from `π*` without using the oracle transcripts. Under SE this is guaranteed; under plain KS, the adversary may exploit oracle transcripts to craft `π*` such that extraction fails or yields a witness inconsistent with the claimed security property.

**Why it fails against the construction:** It may not fail in practice for *this specific circuit* if the public signals uniquely determine the witness up to negligible slack. But no argument is given. The claim "(a) binding is non-malleable" requires a formal SE argument or a proof that the specific public signal layout prevents malleability without SE.

**In-threat-model?** Partially. The reduction sketch is incomplete: it needs to either (a) prove the circuit is SE, (b) use an SE-SNARK variant, or (c) argue why the public signal layout makes malleability impossible without SE. The construction's reference to "PLONK, universal setup" in the spec table (Section 5) is insufficient.

---

### Attack 4: scopeCommitment is a Session-Independent Linkability Tag

**Attack:** A passive observer (e.g., the on-chain verifier, or any party watching the proof stream) collects `{nullifierHash_i, scopeCommitment_i, modelOperatorFingerprint_i}` across all proofs. Define `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. Since `permissionBitmask` and `credentialCommitment` are fixed for a given enrolled credential, **`scopeCommitment` is the same value across every proof from the same operator+model+permission combination.**

**Why it works:** The construction provides per-session unlinkability via `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` — different nonces yield different nullifiers. But `scopeCommitment` does not include `sessionNonce`. Any observer who sees N proofs from the same SECU Sonnet deployment sees the same `scopeCommitment` in all N proofs, trivially linking them as same-credential. If `credentialCommitment` is unique per operator×model×env, this reveals "all these calls came from the same SECU Sonnet deployment" — which may be the intended behavior for the NCUA audit scenario but breaks any unlinkability property across the audit boundary.

More precisely: the NCUA audit scenario (Section 2, step 4) states "The examiner can confirm 'this PII operation used Opus' without learning which member's data was involved or how many total calls SECU made." The second clause — "how many total calls" — is falsified by `scopeCommitment` linkability. An observer counting distinct `nullifierHash` values sharing the same `scopeCommitment` counts exactly how many calls that deployment made.

**Why it fails against the construction:** The construction never formally claims cross-session unlinkability (the claim is operator-identity hiding, not call-count hiding). But the NCUA scenario explicitly asserts it, and the deployment description is misleading if this property fails.

**In-threat-model?** Depends on whether call-count hiding is in scope. The formal claim in Section 1 does not include it; the deployment prose in Section 2 implicitly does. The construction must either (a) add `sessionNonce` to `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment, sessionNonce)` at the cost of losing cross-session scope aggregation, or (b) explicitly strike the call-count-hiding claim from the NCUA scenario.

---

**Summary table:**

| Attack | Severity | Status |
|--------|----------|--------|
| 1: Credential ≠ computation | Critical | Not in threat model; requires TEE/verifiable inference extension |
| 2: Self-enrollment via public provider sigs | High | Not in threat model; tree insertion contract unspecified |
| 3: SE vs. KS conflation | Medium | Proof sketch incomplete; needs SE argument for non-malleability |
| 4: scopeCommitment linkability | Low | Claim mismatch between formal spec and deployment prose |


## Persona: cu_ciso

---

### Attack 1: Operator BJJ Key Custody Is Undefined — GLBA §314.4(c) Violation

- **Attack:** Section 2 (Enrollment Protocol) says "Operator generates their own BJJ keypair" and Section 7.2 says SECU generates "operator BJJ keypairs per deployment environment." The construction specifies HSM custody only for the *provider* (Anthropic) key. It is silent on where the operator's BJJ private key lives: file system, secrets manager, HSM, browser — it is never stated. Under GLBA Safeguards Rule §314.4(c), SECU must implement access controls for credentials that protect member financial data. Under NCUA Part 748 Appendix B §II.C, SECU's information security program must address key management for cryptographic systems protecting member information. If the BJJ private key lives in a software keystore on the same host as the agent process, a server compromise gives an attacker the ability to sign arbitrary `credentialCommitments` for any `modelHash` — including ones attested by Anthropic for approved models. The construction's non-malleability argument (Section 4) holds only if the operator key is not compromised. **The construction delegates the hardest security problem — key custody — to the operator with zero implementation guidance.**

- **Why it works / why it fails:** The construction's security argument in Section 4 (Case 3) explicitly assumes the adversary does not control operator keys. If SECU stores BJJ keys without HSM discipline, that assumption fails in practice. The construction survives its own formal game definition but fails the real deployment scenario in Section 7, where SECU is a named $2B+ regulated institution. The examiner will ask: "Show me your key management policy for the signing keys that generate these proofs." No answer is provided.

- **In-threat-model?** No — the construction must address operator key custody: specify HSM or FIPS 140-2 Level 3 requirement, address key backup/recovery, and map to NCUA Part 748 Appendix B §II.C.

---

### Attack 2: The Audit Trail Is Cryptographic Gibberish — Examiner Defensibility Fails

- **Attack:** Section 7.4 describes the NCUA audit flow: the examiner receives `{agentMerkleRoot, messageHash, modelOperatorFingerprint, scopeCommitment}` per audited transaction and "verifies each PLONK proof against the on-chain roots." I will now describe what actually happens when my NCUA IT examiner sits down with this: she opens her examination workpaper, goes to the IT-SEC questionnaire (derived from FFIEC CAT Domain 3 — Cybersecurity Controls), and asks for a human-readable log of which AI model accessed which member record and when. She does not run a PLONK verifier. She asks my Tier 1 ops team to pull the log. My Tier 1 ops team opens Splunk. `modelOperatorFingerprint = Poseidon3(modelHash, operatorPkAx, permBitmask)` is a 254-bit field element. It maps to nothing in my SIEM. `messageHash` is a Poseidon hash of a tool-call payload — it does not say "member account #4471, loan inquiry, 2026-04-22T02:14Z." **The construction provides cryptographic verifiability for a sophisticated verifier running the exact protocol. It provides zero audit defensibility for a human examiner using standard examination tools.** This is not the same thing. The `nullifierHash` prevents double-use but does not produce a timeline. The `scopeCommitment` proves permissions were satisfied but does not produce a record of *what* was decided.

- **Why it works / why it fails:** The construction is technically correct that the examiner can *verify* a proof. But NCUA examination is not a verification ceremony — it is a narrative conversation backed by evidence. "Here is a ZK proof" is not a defensible answer to "show me your audit log under 12 C.F.R. Part 748.0(a)." The construction has no answer to: how does the on-chain proof get indexed, searched, and rendered in human-readable form? Who runs the PLONK verifier in the examination room?

- **In-threat-model?** No — the construction must specify an off-chain audit index that maps proof outputs to human-readable event records, and address how SECU satisfies NCUA Part 748's "audit trail" requirement alongside the ZK layer.

---

### Attack 3: On-Chain Provider Registry Is an Unvetted Critical Third-Party Dependency

- **Attack:** Section 2 (Enrollment Protocol) requires a smart contract holding `providerRegistryRoot` that is "governance-multisig or DAO-controlled." Section 7.3 requires the agent to retrieve `(modelHash, providerSig)` from an "attestation registry (append-only log, or IPFS CID pinned on-chain)." Under NCUA's 2023 Third-Party Risk Management guidance and Letter to Credit Unions 01-CU-20, any critical service provider to a federally insured credit union must be subject to due diligence, contract review, and ongoing monitoring. My vendor management policy requires: SLA with defined uptime, incident notification within 72 hours, right-to-audit, data residency confirmation, and exit plan. **None of these exist for a DAO-governed on-chain registry.** Who do I call when the chain has a 4-hour finality delay? What is the SLA for Anthropic inserting a new `modelHash` attestation after a model release? What happens during an Ethereum reorg that reverts the provider key insertion? Section 3.4 (Key Rotation) says "historical proofs remain valid: at verification time, the `providerRegistryRoot` public input matched the on-chain root." This assumes the verifier stored the historical root — where? By whom? Under what retention policy? My examiners will ask for a Business Continuity Plan (BCP) for this dependency under FFIEC BCP booklet requirements.

- **Why it works / why it fails:** The construction's technical architecture is sound given a live, consistent chain. The attack is operational: the construction provides no fallback for chain unavailability, no SLA, no vendor contract template, and no BCP for the registry dependency. A DAO is not a BSA-covered financial institution and cannot sign the third-party risk contract my board requires.

- **In-threat-model?** No — the construction must specify: (a) the legal entity responsible for the provider registry, (b) minimum SLA requirements, (c) a fallback verification path when the chain is unavailable, and (d) data residency guarantees if the registry stores any information that could be PII-adjacent under state privacy laws.

---

### Attack 4: modelHash Binds a String to a Call, Not a Computation to a Call

- **Attack:** Section 2 defines `modelHash = Poseidon(model_identifier_canonical)` where `model_identifier_canonical` is `"claude-sonnet-4-6:sha256:ab3f..."` — a *string* encoding a name and a weight checksum. The circuit (Constraint 2) verifies that this string was signed by an enrolled provider key. What the circuit does **not** verify is that the *inference that produced the tool call* was actually computed by the model with those weights. Anthropic signs the hash of a canonical identifier string, not a hash of inference outputs, activations, or any runtime evidence of model execution. An operator running a fine-tuned derivative of Sonnet 4.6, or a quantized distillation, or a cached response from a different model, can still present a valid `modelHash` attestation for the official Sonnet weights — as long as they obtained Anthropic's signature over the identifier (which is public) and enrolled a credential with that `modelHash`. The `messagePlaintext` is bound to the proof (Constraint 9), but the binding is: "this operator, who enrolled a credential referencing Anthropic's Sonnet attestation, produced this tool call." It is not: "the Sonnet 4.6 model weights were the computational process that generated this output." For the FDA/EU AI Act provenance scenario (Section 1, Scenario 4), and for SECU's NCUA examination claim that "only approved model instances processed member data," this is a material gap. Approved model identity is about *computation*, not *credential enrollment*.

- **Why it works / why it fails:** The construction correctly addresses the defined threat model (MODEL-BIND-FORGE: prevent Opus key from forging Sonnet fingerprint). It does not address a different and harder problem: *runtime model execution attestation*. The construction proves "an operator who enrolled credentials referencing Sonnet's modelHash made this call." It does not prove "Sonnet's weights computed this output." For a CISO defending against an examiner who asks "how do you know the agent that ran was actually the approved model and not a modified version your vendor deployed?" — the answer is "trust the operator's enrollment" — which is exactly what the construction claims to improve over.

- **In-threat-model?** No — the construction's claim in Section 1 ("proves 'this call was made by Claude Sonnet 4.6'") overstates what is proven. The construction must either (a) scope the claim to "an operator with Sonnet-attested credentials made this call," or (b) address runtime attestation (e.g., TEE measurement, weight-hash verification at load time) as a complementary requirement out of scope of the ZK layer alone. The current framing will not survive an examiner who asks the right follow-up question.


## Persona: rfc7662_advocate

*Ten years shipping token introspection in production. Every ZK claim is suspect until proven unreachable by RFC 7662 and its extension stack. Let's stress-test C7.*

---

### Attack 1: Signed JWT Introspection Removes the AS from the Hot Path (draft-ietf-oauth-jwt-introspection-response)

- **Attack:** Section 8(c) asserts "no AS in the verification path" as a distinguishing property. But `draft-ietf-oauth-jwt-introspection-response` decouples issuance from verification: the AS pre-signs a JWT introspection response containing verified claims — including a provider-attested `model_id` — and the RS verifies that signed JWT entirely offline. Concretely: the AS requires the operator to submit Anthropic's `(modelHash, providerSig)` at token issuance time, verifies the provider signature, and embeds `model_id` in the signed introspection JWT. The RS caches and re-verifies that JWT for the token's lifetime. No call-time AS participation. The AS is in the loop *once per credential issuance*, not per call.

- **Why it works / why it fails:** The attack correctly removes the AS from the call-time verification path, matching Section 8(c)'s claimed advantage. It fails against the construction for one reason: **message binding**. Section 2, constraint 9 computes `messageHash = Poseidon(messagePlaintext)` and includes it in the public signal set. A signed JWT introspection response is issued before any specific tool call is known — it binds identity to a token, not identity to a specific message payload. To achieve per-call message binding, the AS must either (a) issue a new signed response per call (reintroducing the correlation the attack avoids) or (b) leave message binding out entirely (failing to match the construction's auditable `messageHash`). The construction's SECU scenario (Section 7, step 4) explicitly requires per-transaction `messageHash` attestation for NCUA audit. This is where the attack collapses.

- **In-threat-model?** Partially. The construction must explicitly address why per-call `messageHash` binding — not just credential binding — is the required property. Section 8(c) is currently argued only at the credential granularity. The construction should add: *"a signed JWT introspection response achieves offline credential verification but cannot commit to the specific tool-call payload without per-call AS involvement; Bolyra's circuit commits to both simultaneously."*

---

### Attack 2: DPoP + PPID + Resource Indicators Achieves Both (a) and (c) Simultaneously

- **Attack:** The construction's core thesis (Section 8, paragraph after (a)) claims RFC 8693 + DPoP cannot achieve non-malleability (a) and verifier privacy (c) simultaneously: "either AS sees every hop (violates (c)) or binding is not cryptographic (violates (a))." This is a false dilemma. Assemble:
  - **RFC 8693** token exchange for delegation chain
  - **RFC 9449 DPoP** sender-constraining the token to the operator's ephemeral key — an Opus-key holder cannot present a Sonnet-bound token (satisfies (a))
  - **OIDC Pairwise Pseudonymous Identifiers** issued per-RS — different RS gets a different `sub` for the same operator, breaking cross-RS linkability
  - **RFC 8707 Resource Indicators** audience-binding each token to a specific RS

  The AS only participates at token issuance (one event per session), not at verification time. The RS verifies the DPoP-bound JWT offline. The operator's real identity is hidden behind per-RS PPIDs. This satisfies (c) at the RS level. Non-malleability is enforced by the AS having verified the provider attestation at issuance — satisfies (a). The claimed tension dissolves.

- **Why it works / why it fails:** The attack exposes a gap in Section 8's argument: it conflates "AS sees every **call**" with "AS sees every **issuance event**." DPoP with long-lived credentials reduces AS correlation to session-issuance granularity. The attack fails because:
  1. **PPID operator pseudonymity requires trusting the AS to maintain the pairwise mapping** and not deanonymize on demand. In Bolyra, `modelOperatorFingerprint = Poseidon3(modelHash, operatorPkAx, permissionBitmask)` — the mapping from fingerprint to operator identity exists only in the operator's possession of the BJJ private key. No trusted party can reverse it. A PPID requires the AS to be a trusted third party for the privacy guarantee; Bolyra does not.
  2. **Message-level binding** (same collapse as Attack 1).
  3. **Cross-session unlinkability**: if the AS issues different tokens per session, the PPID sub-values can still be linked across sessions at the AS. Bolyra's `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` makes session unlinkability verifiable without trusting the AS.

- **In-threat-model?** Yes — the construction survives, but Section 8 must be sharpened. The argument currently states DPoP cannot achieve (a)+(c) without naming *why* PPID-based operator privacy falls short. Add: *"PPID privacy is conditionally AS-trust-dependent; Bolyra's operator anonymity is unconditional — no party can link `modelOperatorFingerprint` to the operator without the BJJ private key, even under compulsion of the AS."*

---

### Attack 3: The Runtime Inference Gap — Credential Binding ≠ Execution Binding

- **Attack:** This is the most structurally damaging attack. The construction proves: *"an operator enrolled a credential referencing a provider-attested `modelHash`."* It does **not** prove: *"the model identified by `modelHash` actually processed this tool call."* The `modelHash` is a **private input** supplied by the operator's proving code at proof-generation time (Section 2, private inputs). An operator who legitimately holds credentials for **both** Sonnet 4.6 and Opus 4.6 — both enrolled in the agent Merkle tree — can route all inference traffic to Opus while selectively using the Sonnet `modelHash` private input when generating proofs. Nothing in the circuit checks that `messagePlaintext` was produced by the model identified by `modelHash`. The circuit verifies internal consistency of the credential; it says nothing about the actual runtime inference process. The threat model game (Section 3, MODEL-BIND-FORGE) restricts the adversary to credentials for `M_adv ≠ M_target` — it explicitly does not model an adversary with legitimate multi-model enrollment who lies about which model ran.

- **Why it works / why it fails:** This attack is not answered anywhere in the construction. Section 8(a) rebuts self-attestation of `model_id` via SPIFFE by noting an operator could register any SVID. But Bolyra's construction has the same problem: the operator chooses which enrolled credential (and therefore which `modelHash`) to use when calling the prover. The provider attestation binds `modelHash` to Anthropic's signing key, not to the actual inference execution environment. Closing this gap requires **runtime attestation** — e.g., the model provider generating the proof inside a TEE, or the prover receiving a nonce from the model's runtime that is verifiable against the model hash. No such mechanism exists in the current construction.

- **In-threat-model?** **No — the construction must address this.** The SECU/NCUA scenario (Section 7) requires proving "only approved models touched PII files." The current construction proves only "an operator with approved-model credentials made this call" — an important but weaker property. The construction should either (a) explicitly scope the claim to credential-binding rather than execution-binding, (b) introduce a TEE attestation hook where the prover is invoked inside a provider-controlled enclave, or (c) add a provider-issued per-inference nonce that becomes part of `messagePlaintext`.

---

### Attack 4: The Per-RS Introspection Policy Replicates the Scope Predicate

- **Attack:** Section 2, constraints 6–7 implement the permission bitmask predicate. Section 8(d) claims BBS+ has no native bitwise-AND predicate and that OAuth cannot enforce `requiredBits[i] * (1 - permBits[i]) === 0`. But RFC 7662 introspection responses carry a `scope` claim — a space-delimited string of OAuth scopes — and the AS can enforce per-RS scope filtering via policy. Specifically: RFC 7662 §2.2 allows the AS to return an introspection response tailored to the requesting RS, omitting scopes the RS is not entitled to see. The RS's authorization logic checks whether the required scope is present. This is semantically equivalent to the bitmask predicate: "required scope X is present in this token." The JWA `scope` claim + per-RS AS policy replicates the predicate without ZK.

- **Why it works / why it fails:** The attack is correct that scope enforcement via AS policy is functionally equivalent for simple allow/deny decisions at call time. It fails for two distinct reasons. First, **scope privacy**: in Bolyra, the verifier receives `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` — a binding to the permission set without revealing the specific bitmask value. An AS introspection response reveals the full scope string to the RS, leaking the permission configuration. In the SECU scenario, the NCUA auditor learns only that "required scopes were satisfied," not the full permission matrix of SECU's deployment. Second, **offline verifiability of the predicate**: the bitmask predicate is enforced inside the ZK circuit and its satisfaction is proven to any verifier holding the verification key, without any AS involvement. The AS-policy approach requires the auditor to trust that the AS correctly enforced the policy at issuance — it cannot verify the enforcement independently. For regulatory audits where the auditor cannot trust the operator's AS, this distinction is load-bearing.

- **In-threat-model?** Yes — construction survives. But Section 8(d) currently argues only from BBS+ missing bitwise predicates. It should be extended to address why AS-side scope policy is insufficient: *"AS scope enforcement is opaque to the verifier; the verifier must trust the AS implemented policy correctly. Bolyra's circuit constraint is verifiable by anyone holding the verification key — the enforcement proof is public, not operator-asserted."*


## Persona: spiffe_engineer

---

### Attack 1: The Public Attestation Oracle — Non-Malleability Breaks at the Enrollment Protocol

- **Attack:** The enrollment protocol (Section 2, "Model attestation (per model release)") states that Anthropic publishes `(modelHash, providerSig, providerPk)` to an append-only registry or IPFS CID. These tuples are public. Any enrolled operator — including one whose legitimate credential is for Opus — can download Sonnet's `(modelHash_sonnet, providerSig_sonnet)` from this registry and supply them as private witness inputs to the ModelInstanceBinding circuit. The circuit enforces that `providerSig` verifies over `modelHash` under an enrolled provider key (Constraint 2), and that `credentialCommitment = Poseidon5(modelHash, opPkAx, opPkAy, permissionBitmask, expiry)` is Merkle-included. Nothing prevents the Opus operator from constructing a new `credentialCommitment` using `modelHash_sonnet` and their own `opPk`, enrolling it in the agent Merkle tree, and generating a valid proof asserting "Sonnet made this call" while running Opus for inference.

- **Why it works:** The threat model (Section 3) restricts the adversary to possessing credentials "for model M_adv" but does not restrict their ability to read the public attestation registry. The adversary does not need to forge `providerSig_sonnet` — it is published. They need only enroll a new credential commitment that includes `modelHash_sonnet`. The circuit has no constraint linking `credentialCommitment` to a specific API call path or inference runtime. The construction's security argument in Section 4 (Case 2a) assumes the adversary must forge an EdDSA signature to pass provider attestation — but if the signature is public, there is no forgery. The reduction sketch does not address this case.

- **In-threat-model?** **No.** The MODEL-BIND-FORGE game gives the adversary "enrolled credentials for model M_adv" and assumes they cannot get provider attestations for M_target. But nothing in the enrollment protocol restricts access to `(modelHash_target, providerSig_target)` — it is explicitly published. The game definition must either (a) treat the public attestation registry as a restricted oracle with per-operator access control, or (b) add a runtime measurement step that cryptographically links proof generation to the actual inference execution. Without one of these, the non-malleability claim in gap (a) is unproven.

---

### Attack 2: Inference-Execution Gap — The Circuit Proves Credential Possession, Not Model Execution

- **Attack:** Independently of Attack 1, even if attestation tuples were kept private (distributed per-operator under NDA), the circuit has no mechanism to bind the proof to an actual inference execution. `messageHash = Poseidon(messagePlaintext)` binds a tool-call payload to the proof, but the prover supplies `messagePlaintext` as a private input (Section 2, private inputs). There is no hardware measurement — no PCR, no TEE quote, no remote attestation challenge — that proves the inference producing `messagePlaintext` was performed by a process whose memory image matches `modelHash`. The construction's root of trust terminates at "Anthropic signed this hash at model packaging time" (Section 2, "Model attestation"), not "this hash ran during inference." A SPIRE deployment using TPM node attestation or a Nitro Enclave attestor actually measures the running process image and PCR state at workload registration time. The workload API issues SVIDs only to processes whose measurements match registered policies. That is the layer where execution identity lives.

- **Why it works:** Section 8(a) dismisses SPIFFE by noting "the SPIRE server is operator-controlled." That is only true for the default join-token or x509pop attestors. SPIRE's plugin architecture has production-grade node attestors for AWS Nitro Enclaves (`aws_iid` + enclave attestation), GCP Confidential VMs, and Azure CVM. A custom attestor can measure model weights into PCR8 at load time and report them to a SPIRE server whose attestation policy is enforced by the cloud provider's HSM — not the operator. This closes the inference-execution gap that Bolyra cannot close from inside a ZK circuit. The circuit runs after inference; it cannot retroactively attest what weights were loaded.

- **In-threat-model?** **No.** The threat model does not define what "made by Claude Sonnet 4.6" means operationally. If it means "a process whose loaded weights match Sonnet's hash produced this output," then the construction provides no mechanism to establish this — the prover is free to compute `messageHash` from any output and supply `modelHash_sonnet` as private witness. This is not a cryptographic weakness in Poseidon or EdDSA; it is a semantic gap between "credential possession" and "execution attestation" that the construction conflates throughout Sections 1, 3, and 7.

---

### Attack 3: `modelOperatorFingerprint` Is a Persistent Cross-Session Correlation Handle

- **Attack:** Public output index 4 is `modelOperatorFingerprint = Poseidon3(modelHash, operatorPubkeyAx, permissionBitmask)`. This value is deterministic across all proofs generated by the same operator for the same model class. A verifier — or any party who observes multiple proofs — can correlate every tool call by SECU's Sonnet deployment across all sessions, all members, all dates, simply by matching `modelOperatorFingerprint`. The construction claims in Section 7 that "the examiner can confirm 'this PII operation used Opus' without learning which member's data was involved or how many total calls SECU made." The second half of that claim is false: the examiner can count exactly how many proofs share the same `modelOperatorFingerprint`, reconstructing SECU's per-model call volume. In a regulated context where call volume is commercially sensitive or subject to subpoena, this is a privacy failure.

- **Why it works:** The `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` provides per-session unlinkability, but `modelOperatorFingerprint` is explicitly session-independent and appears in every proof. A BBS+ derived proof with `model_id` as a disclosed attribute has the same issue — but WIMSE's SD-JWT profile with per-presentation randomization or a SPIFFE JWT-SVID with a per-request `jti` claim at least does not expose a static fingerprint. The construction introduces a linkage handle that vanilla OAuth bearer tokens — ironically — do not have, since bearer tokens are opaque to the verifier.

- **In-threat-model?** **No** (not addressed). The construction's privacy goal in Section 1 states the verifier learns only `{model_hash, operator_pk, permission_bitmask, message_hash}` — but `operator_pk` is embedded in `modelOperatorFingerprint` as a static public output, making operator linkability trivial. Either the fingerprint must be randomized (breaking auditability of model class) or `operatorPubkeyAx` must be removed from the public output computation and replaced with a commitment, analogous to how `nullifierHash` provides session-scoped non-double-spend rather than a permanent identifier.

---

### Attack 4: WIMSE Token Exchange Already Closes the Gap You Claim Is Unclosable

- **Attack:** Section 8(c) argues: "Adding an AS to enforce [model-identity] re-introduces the correlation problem (AS sees every call)." This is a strawman against `draft-ietf-wimse-arch`. WIMSE's workload-to-workload token exchange profile (Section 6 of the draft) explicitly supports delegated token exchange where the intermediary AS is not in the verification path for downstream calls. The flow is: Workload A (the model process) obtains a WIMSE workload token from its local SPIRE agent (Workload API, Unix domain socket, zero network hop). That token is exchanged once for a scoped downstream token using RFC 8693 with a `subject_token_type` of `urn:ietf:params:oauth:token-type:jwt-svid`. The downstream verifier checks the token's `act` (actor) claim chain without contacting the AS. DPoP (RFC 9449) binds each HTTP request to an ephemeral key, giving per-request non-transferability. SD-JWT (RFC 9278) on top of a WIMSE workload token gives selective disclosure of `model_id`, `operator_id`, and `permission_bitmask` without revealing the full claim set. The AS does not see downstream calls — only the initial exchange. This is exactly the architecture WIMSE was designed for.

- **Why it works / why it partially fails:** The WIMSE stack genuinely does not close the inference-execution gap (Attack 2 above) — WIMSE tokens are issued by SPIRE to workloads that passed node attestation, not to specific model weight hashes. However, the construction's claim that WIMSE+DPoP+BBS+ "fails on the enrollment root-of-trust" (Section 8) applies equally to Bolyra — as Attack 1 establishes, Bolyra's root-of-trust terminates at a public attestation tuple, not a hardware measurement. Both stacks prove "a credentialed workload made this call," not "Sonnet's weights ran this inference." The correct characterization is: Bolyra and WIMSE have the same inference-execution gap; Bolyra adds ZK privacy properties that WIMSE lacks; WIMSE is an IETF-standardized path that Bolyra is duplicating at the infrastructure layer.

- **In-threat-model?** **Partial.** The "AS sees every hop" objection in Section 8(c) is factually incorrect for the WIMSE workload-to-workload profile and should be corrected. The construction's differentiation from WIMSE should rest solely on (1) the privacy properties of ZK proofs vs. SD-JWT, and (2) the permission bitmask predicate (Section 8(d)) — both of which are real and defensible differences. The overstated dismissal of WIMSE weakens the construction's framing without adding technical content.
