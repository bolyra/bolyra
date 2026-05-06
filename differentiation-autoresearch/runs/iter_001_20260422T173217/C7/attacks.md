# Tier 3 Adversarial — C7 Cryptographic model-instance binding

## Persona: auth0_pm

---

### Attack 1: The modelHash Root-of-Trust Vacuum

- **Attack:** The construction binds `messageHash` to `modelHash` via a Poseidon5 commitment and proves correct circuit evaluation — but *who vouches that `modelHash` actually corresponds to Claude Sonnet 4.6 weights?* The construction says credentials are "enrolled" (§ ModelInstanceBinding circuit), but enrollment is operator-initiated. There is no Anthropic signature over `modelHash`, no hardware attestation, no third-party oracle. The operator self-asserts "this hash is Sonnet." The verifier accepts the proof that *someone holding the enrolled BJJ keypair* committed to *some* hash — not that the hash is what the operator claims. An operator running Haiku can enroll its weights under a Sonnet label and produce a valid proof. The circuit is sound; the claim is hollow.

  WorkOS Client Attestation (RFC draft-ietf-oauth-attestation-based-client-auth) anchors software identity to a platform attestation — Apple App Attest, Android Play Integrity, or a cloud HSM root — signed by a *third party the verifier already trusts*. Bolyra has no equivalent trust anchor. The CISO scenario in §Scenarios asks "prove only approved models touched PII." The construction proves only "the operator *said* this was an approved model."

- **Why it works / fails against the construction:** The construction does not address this at all. Section claiming non-malleability (MODEL-BIND-FORGE game) reduces to Poseidon CR + PLONK soundness — that proves the *commitment* can't be forged given a fixed `modelHash` input. It says nothing about how `modelHash` is authoritatively assigned. The cryptography is sound; the semantic binding is absent.

- **In-threat-model?** No — construction must address how `modelHash` is anchored to a trusted attestor (Anthropic HSM signature, hardware TEE quote, or equivalent). Without this, the claim collapses to "operator self-certified model identity," which is exactly what OAuth `client_id` already does.

---

### Attack 2: 5-Second Proof Latency Fails Synchronous MCP

- **Attack:** MCP tool calls are synchronous request-response. The client is blocked waiting. The construction states `<5s proving` for a ~14,750-constraint PLONK circuit. Auth0, WorkOS, and Stytch issue signed JWTs or opaque tokens in under 100ms at the 99th percentile — often under 10ms on cached sessions. A 5-second proof-generation step inserted into the MCP auth path means:

  1. **User-visible latency:** any agentic workflow making 10 tool calls blocks for up to 50 cumulative seconds in proof generation alone.
  2. **Timeout cascades:** enterprise API gateways (Kong, Apigee, AWS API Gateway) default to 29-30s hard timeouts. A bursty agent hitting 6+ concurrent tool calls can exhaust that budget purely on proof gen.
  3. **No caching story:** the construction does not specify whether proofs are pre-computed, cached, or reused across calls with the same `(modelHash, operatorPk, permissionBitmask)`. If `messageHash` changes per-call (which it must for binding to be meaningful), every call requires a fresh proof. Pre-computation is not possible.

  The construction claims to beat the baseline on all five gaps but gap (d) — latency — is conspicuously absent from the stated gaps (a)–(c)/(e).

- **Why it works / fails against the construction:** The construction acknowledges `<5s proving` as a positive result but does not compare it to incumbent latency profiles or provide a mitigation for synchronous MCP flows. There is no batching, streaming, or optimistic-verification design presented.

- **In-threat-model?** No — construction must address latency in synchronous MCP context, either with a proof-caching scheme that preserves binding semantics or an argument that the verifier can run async with an optimistic-proceed model. Neither is present.

---

### Attack 3: "No AS in Verification Path" Eliminates Revocation — A Compliance Killer

- **Attack:** The construction advertises "requires no Authorization Server in the verification path" as a feature. For a regulated enterprise (credit union under NCUA, bank under OCC), this is a disqualifying defect, not a selling point.

  Specifically:
  - **Real-time revocation is impossible.** If the operator's BJJ keypair is compromised, previously issued proofs remain cryptographically valid. There is no CRL, no OCSP, no token introspection endpoint. A verifier receiving a proof from a compromised keypair has no mechanism to reject it without re-contacting some authority — at which point you've re-introduced the AS.
  - **GDPR Article 17 / CCPA right to deletion.** If a proof attests that a specific model+operator processed a user's data, that proof may itself constitute personal data linkage. Without a centralized log (which the construction explicitly excludes from the verifier's view), the operator cannot demonstrate deletion compliance.
  - **FFIEC and SOC 2 CC6.8** require logging of all privileged access, including AI model access to sensitive data. The construction's ZK proof reveals only `{model_hash, operator_pk, permission_bitmask, message_hash}` to the verifier — which is by design. But the auditor needs more than a hash; they need a human-readable event log with timestamps, user IDs, and system context. Bolyra produces a proof; it does not produce an audit log.

  Auth0 ships native SIEM integration (Splunk, Datadog, Sumo Logic), real-time log streaming, and a compliance export API. WorkOS has built-in audit log APIs required by enterprise procurement. Stytch offers session revocation with sub-second propagation. The AS is not a weakness of OAuth — it is the compliance surface that regulated buyers require.

- **Why it works / fails against the construction:** The construction explicitly positions AS-free verification as superior to RFC 8693 token exchange. It does not provide any substitute for revocation, real-time audit logging, or deletion compliance. The CISO and bank liability scenarios in §Scenarios require these capabilities by regulatory mandate, not by preference.

- **In-threat-model?** No — construction must either (a) specify a revocation mechanism compatible with the ZK binding (e.g., on-chain nullifier set, rotating epoch commitments) or (b) define an audit log architecture that satisfies FFIEC/SOC 2 without compromising the verifier's privacy guarantees. Currently neither exists.

---

### Attack 4: The Merkle Enrollment Registry Is an Unaddressed Centralization Point

- **Attack:** The circuit uses Merkle inclusion to prove that `(modelHash, operatorPk, permissionBitmask)` is in an enrolled credential set (§ ModelInstanceBinding: "Merkle inclusion"). Someone must maintain this Merkle tree — add leaves when operators onboard, update roots when credentials rotate, and distribute the current root to verifiers. This entity is a centralized registry. The construction does not specify:

  1. Who operates the registry (Bolyra Inc.? On-chain smart contract? Federated?).
  2. How verifiers obtain a trusted, current Merkle root — if Bolyra serves it, verifiers are trusting Bolyra's honesty about root freshness.
  3. What happens during registry downtime — proofs reference a stale root; verifiers must either reject all proofs or cache roots with unknown staleness.
  4. What the SLA is for root updates when an operator rotates their BJJ keypair (which the construction claims is key-rotation-safe).

  This is isomorphic to the Auth0 JWKS endpoint problem — except Auth0's JWKS endpoint is battle-hardened, has 99.99% SLA, is cached via CDN, and has a documented rotation protocol (RFC 7517 `kid` matching). Bolyra's Merkle root distribution has none of these properties specified. For a solo founder, this registry is a single point of operational failure and a procurement red flag ("what happens if you go out of business?").

- **Why it works / fails against the construction:** The construction's non-malleability proof holds *given* a trusted Merkle root. It does not prove the root distribution mechanism is trustworthy or available. The gap between "cryptographic proof is sound given trusted inputs" and "trusted inputs are reliably available in production" is precisely where enterprise buyers defect to incumbents.

- **In-threat-model?** No — construction must specify the registry architecture (on-chain with a known contract address, or Bolyra-operated with an explicit trust model), the root distribution protocol, the SLA, and the behavior under partial outage. Until this is specified, the verifier's trust in any proof is contingent on trusting Bolyra operationally — which negates the "no AS required" claim.


## Persona: cryptographer

*The construction description is sparse — no circuit constraint listing, no formal game definitions, no simulator, no reduction sketch with tightness. What follows treats the claims at face value and probes each one.*

---

### Attack 1: The Zero-Knowledge Claim Has No Simulator

**Attack:** I ask the author: write down the simulator S. The verifier sees a proof π over public inputs `{model_hash, operator_pk, permission_bitmask, message_hash}`. For ZK to hold, there must exist a PPT simulator S that, given only the public inputs and no witness, produces a distribution over transcripts (or proofs) computationally indistinguishable from real proofs. The construction says "verifier learns ONLY {…} and nothing else" — that *is* a ZK claim. PLONK is honest-verifier zero-knowledge (HVZK) in the random oracle model, but HVZK means the simulator gets the verifier's challenge *in advance*. Against a malicious verifier who can adaptively choose challenges (or in a non-interactive setting where the Fiat-Shamir hash is over adversarially chosen context), HVZK does not compose.

**Why it works / fails:** If the proving system is Fiat-Shamir PLONK in the ROM, the simulator can program the RO — so NIZK ZK holds. But the construction never states this. If the prover embeds any non-public value that is *correlated* with the secret witness (e.g., a deterministic nonce derived from the API key "for convenience"), the ZK argument breaks regardless of the circuit. The construction mentions a BJJ EdDSA signature inside the circuit — BJJ signing with a deterministic nonce (RFC 8032 style) is safe, but if the nonce leaks through the proof's public output in any field, the simulator cannot reproduce it.

**In-threat-model?** **No — construction must address.** The author must (a) specify the ZK notion (HVZK, malicious-verifier ZK, simulation-extractable ZK), (b) exhibit the simulator explicitly, and (c) prove the Fiat-Shamir application is in the ROM with no co-routine leakage.

---

### Attack 2: Subverted SRS Collapses the Non-Malleability Reduction

**Attack:** The non-malleability claim is reduced to "Poseidon CR + PLONK soundness." PLONK requires a universal SRS (powers-of-tau ceremony or equivalent). PLONK soundness is *computational* and holds only when the SRS was generated honestly — i.e., the toxic waste `τ` was discarded. An adversary who controls or subverts the ceremony (or obtains `τ` after the fact from a single-party setup) can produce a valid proof for *any* statement, including `(opus_model_hash → sonnet_model_hash)` substitutions. The construction asserts non-malleability but specifies no ceremony, no updateable SRS, and no multi-party setup.

**Why it works:** The reduction sketch goes:

> Forger F wins MODEL-BIND-FORGE ⟹ F breaks Poseidon collision-resistance OR PLONK soundness.

This reduction is vacuously true under a subverted SRS because "PLONK soundness" no longer holds — F can break it trivially. The reduction does not survive SRS compromise because there is no sub-protocol to detect a bad SRS. Groth16 has the same problem but is circuit-specific; PLONK's universal SRS means a single compromise breaks every circuit that uses it, including future circuits the operator hasn't deployed yet.

**In-threat-model?** **No — construction must address.** The construction must specify: (a) what SRS ceremony was used, (b) whether the SRS is updateable (Kate et al. 2023 style), and (c) what the security model is when the SRS is compromised — does the system fail open (any proof verifies) or fail closed (proofs are rejected)?

---

### Attack 3: Trusted Enrollment Is the Actual Trust Boundary — and the Construction Is Silent on It

**Attack:** The construction binds `messageHash` to a Merkle leaf containing `(modelHash, operatorPk, permissionBitmask)`. The circuit proves Merkle inclusion — but *who inserted that leaf?* The enrollment step is where `modelHash = H(model_weights)` gets associated with `operatorPk`. If the enrollment oracle is controlled by the operator themselves, an operator running Sonnet 4.5 can register `modelHash = H(Sonnet_4.6_weights)` and produce valid proofs claiming to be 4.6. The circuit is satisfied — the Merkle proof is valid, the EdDSA signature verifies — but the binding to actual model identity is broken at the enrollment layer, not the proof layer.

Concretely: the CISO scenario claims "proves only approved models touched PII files." But the proof only shows *a credential in the Merkle tree* was used. If Anthropic does not co-sign enrollment leaves (i.e., attest that `modelHash` was computed from authentic weights), the binding is operator self-attestation dressed in ZK clothing.

**Why it works:** This is not a cryptographic attack on the circuit — it is a protocol-level gap. The circuit is sound with respect to its witness, but the witness itself is not anchored to physical model identity. It is equivalent to a passport ZK proof that proves "this passport was issued" without proving the passport authority is legitimate.

**In-threat-model?** **No — construction must address.** The enrollment protocol requires a root of trust: either Anthropic co-signs each `(modelHash, operatorPk)` pair with a long-lived key (creating a PKI), or model weights are attested via a hardware measurement (TEE/TPM quote), or both. Without this, the non-malleability game is played at the wrong layer.

---

### Attack 4: Unlinkability Is Not Claimed, But the Merkle Root Is a Correlator

**Attack:** The public inputs include `operator_pk` and `model_hash`. A verifier who sees multiple proofs from the same operator can trivially link all calls to the same operator — `operator_pk` is a persistent identifier. The construction's scenario 2 (liability dispute) says "proves which specific model+operator made the transaction without revealing the operator's full session history." But the verifier *does* see `operator_pk` in every proof. If the verifier is also the Authorization Server or a colluding third party, they can reconstruct the operator's complete call graph across sessions by correlating `(operator_pk, message_hash, timestamp)` tuples from the verification log.

More acutely: if `permissionBitmask` is fine-grained (e.g., bit 7 = "can access PII table X"), a verifier who sees many proofs can profile which operators have which permissions and when they exercised them, even if the underlying session tokens are never revealed. This is a traffic-analysis attack on the public proof inputs, not on the circuit internals.

**Why it works / fails:** The construction does not claim unlinkability — but scenarios 1 and 2 implicitly require it ("without revealing which call was which model," "without revealing the operator's full session history"). If `operator_pk` is a persistent key, these properties are not delivered. A session-scoped ephemeral key (derived via a VRF or HKDF from the long-term key) would prevent cross-session linking but would require the verifier to have a separate channel for key freshness — reintroducing the Authorization Server the construction claims to eliminate.

**In-threat-model?** **Partial.** The binding property survives (correct), but the stated scenarios 1 and 2 are not achieved unless the construction adds: (a) a formal unlinkability game definition, (b) an ephemeral `operator_pk` scheme with a freshness proof, or (c) an explicit acknowledgment that cross-session operator linkability is an accepted limitation. Right now the scenarios over-promise relative to what the circuit delivers.


## Persona: cu\_ciso

---

### Attack 1: Regulatory Mapping Void — "Name the Part"

- **Attack:** I open the NCUA examiner's questionnaire for third-party AI vendors (IT Examination Booklet, Appendix J). Question 14: "Describe how the vendor's authentication and access controls map to FFIEC CAT Domain 2 (Threat Intelligence) and NCUA Part 748.0(b)(3) (access controls over member data)." I hand the Bolyra vendor sheet to my examiner. It says "PLONK soundness" and "Poseidon5 commitment." My examiner has a Community Development Specialist certification, not a cryptography PhD. He marks it **Needs Improvement**. My board presentation is in two weeks.

- **Why it works / fails:** The construction (§ "Non-malleability" and § "Verification") demonstrates cryptographic rigor but contains **zero control-framework crosswalks**. There is no sentence of the form: *"MODEL-BIND-FORGE game → FFIEC CAT Maturity Level 3, Domain 2, Control 2.4 (Identity and Access Management)."* Without that sentence, the construction produces a proof that satisfies a cryptographer but fails a regulatory artifacts checklist. The construction doesn't even claim to address this — its gap-to-close list (a)–(e) is entirely cryptographic.

- **In-threat-model?** **No.** Construction must add a regulatory control crosswalk table mapping each proof property to a named NCUA/FFIEC/GLBA control. Absence of this isn't a crypto weakness — it's an adoption blocker that makes the construction irrelevant to the buyer persona.

---

### Attack 2: Audit Trail Opacity at Incident Time — "2am Call, Regulator on Hold"

- **Attack:** An AI agent drains a member's HELOC at 3:47am. I invoke my incident response plan (NCUA Part 748, Appendix B, Step 4: "preserve evidence"). My Tier 1 ops team pulls the Bolyra proof artifact from the event log. It is a 2.8 KB binary PLONK proof and a `{modelHash, operatorPk, permissionBitmask, messageHash}` tuple. My ops team cannot read it. My forensics vendor (a Big 4 firm my board approved) cannot read it without a custom verifier binary that isn't in their standard toolkit. I need to hand the NCUA examiner **something they can interpret within 72 hours** under Part 748 breach notification requirements. The ZK proof is legally non-self-authenticating — it requires the verifier software to mean anything, and that software itself becomes an unaudited dependency.

- **Why it works / fails:** The construction correctly proves *that* a specific `(model, operator, bitmask)` tuple signed a message. But it proves this in a form legible only to software. NCUA examiners operate on PDF exports, Excel pivot tables, and signed attestation letters. The construction's verification path — run the PLONK verifier, check the public inputs — requires operational infrastructure my team doesn't have and my examiner won't trust without *its own* SOC 2. The construction has no § on "human-readable attestation export" or "legally admissible evidence packaging." The proof exists; the evidence chain for a regulator does not.

- **In-threat-model?** **No.** Construction must address the evidence packaging layer: how does a ZK proof become a court-admissible, examiner-legible artifact? Timestamped, verifier-signed PDFs? A third-party notarization service? Without this, the construction solves the cryptographic problem and creates a new operational one.

---

### Attack 3: BJJ Keypair Custody — GLBA Safeguards Rule § 314.4(c)

- **Attack:** The construction states the BJJ keypair is "orthogonal to bearer tokens" and survives API key rotation. But **where does the BJJ signing key live at inference time?** My GLBA Safeguards Rule inventory (§ 314.4(c)) requires me to map every system that touches member data to a custodian with a defined key management lifecycle. If the BJJ keypair is in the model operator's runtime memory (Anthropic's inference cluster), I don't control it — I've outsourced signing authority to the vendor with no contractual SLA. If it's in an HSM I own, who loaded it, what's the rotation schedule, and what's the revocation path if the operator is compromised? The construction claims key rotation is solved ("operator can rotate API keys without breaking historical attestations") but conflates *bearer token rotation* with *BJJ keypair lifecycle*. These are different secrets with different custody requirements.

- **Why it works / fails:** The construction's § "Survives key rotation" addresses only the bearer token → BJJ keypair independence. It is silent on: (1) who generates the BJJ keypair, (2) where it is stored, (3) what the revocation ceremony looks like, (4) whether Anthropic or the operator has access to it. For my GLBA exam, "the key is orthogonal" is not an answer — "the key is in a FIPS 140-2 Level 3 HSM controlled by the operator, rotated annually under dual-control ceremony, with revocation propagated to the Merkle registry within 24 hours" is an answer.

- **In-threat-model?** **No.** The construction must specify a concrete key custody model: who holds the BJJ keypair, what HSM/enclave, what rotation and revocation SLA, and whether Anthropic has escrow access. Without this, the "survives rotation" claim is incomplete and my vendor management policy will flag it as an unresolved third-party dependency.

---

### Attack 4: On-Chain Registry as Single Point of Regulatory Failure

- **Attack:** The construction requires Merkle inclusion proof against an on-chain registry of enrolled `(modelHash, operatorPk, permissionBitmask)` credentials. My core processor (Symitar/Episys) has a contractual 99.97% uptime SLA. NCUA examiners, under the Business Continuity booklet, will ask: *"What is your RTO/RPO for this dependency, and what is your fallback procedure if the registry is unavailable?"* If the on-chain registry experiences a 30-minute outage (1% monthly downtime = ~7 hours/month), all Bolyra proofs fail to verify during that window. Worse: if the smart contract governing the registry has a bug and is paused for an emergency upgrade, **I cannot prove compliance for any AI call made during the pause window** — even if the calls were legitimate. This is a new category of audit gap the construction creates rather than closes.

- **Why it works / fails:** The construction is silent on registry availability, RTO/RPO, and fallback verification. It also does not address chain reorganization: if the registry is on a chain that reorganizes, historical Merkle roots may be invalidated, potentially voiding historical proofs. For a credit union that must produce a complete audit trail for any 5-year lookback window (BSA/AML retention requirements), chain reorgs are not a theoretical concern — they're an exam finding waiting to happen.

- **In-threat-model?** **No.** The construction must specify: (a) registry availability SLA and incident response procedure, (b) an offline/cached verification path for outage windows, (c) chain reorg handling for historical proof validity, and (d) the regulatory classification of the on-chain registry itself — is it a "critical service provider" under NCUA Supervision Letter 07-01, requiring its own vendor due diligence?


## Persona: rfc7662_advocate

---

### Attack 1: AS-Side `model_id` Policy + Signed JWT Introspection Response

- **Attack:** RFC 7662 permits arbitrary custom claims in the introspection response. The draft `draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) makes that response a signed JWT the RS can verify offline — AS is not on the hot path. A well-configured AS can enforce: "client `acme-prod` may only bind `model_id=claude-sonnet-4-6`; any token request asserting a different model_id is rejected." The RS receives `{ client_id, model_id, operator_id, permission_bitmask }` as cryptographically signed claims, verifiable without re-contacting the AS. Where exactly does this fall short of the construction's claim in §gap-to-close (a)–(c)?

- **Why it works / fails:** It fails on **(a) non-malleability** in a subtle but critical way. The `model_id` in the introspection response is an AS policy assertion, not a cryptographic binding derived from the model artifact itself. The AS trusts the client's self-declaration at registration time. An operator who registers `client_id=acme-prod` with `model_id=claude-sonnet-4-6` and then actually routes calls through Opus has no cryptographic check — the AS cannot distinguish calls made by different weight checkpoints behind the same API key. The Bolyra `modelHash` (Poseidon over enrolled weight commitment) is derived from the artifact; the RFC 9701 `model_id` is a string the operator typed into a registration form.

- **In-threat-model?** Yes — construction survives **if and only if** Section §ModelInstanceBinding defines enrollment as a commitment over verifiable model artifacts (e.g., hash of ONNX weights or a vendor-attested digest), not over a vendor-supplied string. If enrollment accepts an opaque `model_id` string from the operator without artifact binding, this attack breaks the construction. The paper must address this enrollment root-of-trust.

---

### Attack 2: DPoP (RFC 9449) with Model-Weight-Derived Keypair

- **Attack:** RFC 9449 DPoP binds an access token to a client-held private key via a proof-of-possession JWT on every request. Now extend: derive the DPoP keypair deterministically from the model weights (`sk = KDF(weights, operator_salt)`). Every inference request carries a DPoP JWT signed by this key. The AS binds the token to the DPoP public key at issuance; the RS verifies the DPoP proof per-request. This achieves per-request binding (not just per-session), key rotation works by issuing new tokens bound to the new key, and the operator can prove `dpop_jkt` matches the enrolled model's derived key. The claim in §gap-to-close that "DPoP cannot achieve (a)+(c) simultaneously" needs to be specific.

- **Why it works / fails:** DPoP fails on **(c) verifier data minimization** in a way the construction does not. To verify a DPoP proof, the RS must either contact the AS (violating offline verification) or hold a cached introspection response binding `dpop_jkt` to `model_id` — which means the AS was in the path during token issuance and saw `{ client, model, timestamp, resource }`. More critically, DPoP fails on **the message-binding gap**: the DPoP JWT binds to `{ htm, htu, iat, nonce }` — the HTTP method and URI — not to `messageHash` (the content of the tool call). Two different tool calls to the same endpoint produce indistinguishable DPoP proofs. The Bolyra construction binds `messageHash` inside the PLONK circuit; DPoP cannot bind application-layer content without stepping outside the spec.

- **In-threat-model?** Yes — construction survives. But the paper must explicitly state in §Comparison that DPoP's `htu` binding is transport-layer, not message-layer, and quantify that gap. An auditor reading only the abstract could incorrectly conclude "DPoP + model key = same thing."

---

### Attack 3: RFC 8693 Token Exchange `act` Claim as Delegation Chain

- **Attack:** RFC 8693 §4.1 defines the `act` (actor) claim to represent a delegation chain: `{ sub: user, act: { sub: model_hash } }`. An orchestration layer can exchange a user token for a model-scoped token where `act.sub` encodes the model's identity. Combined with RFC 8707 resource indicators (audience-bound to the specific RS), the exchanged token cryptographically binds `{ user, model_hash, resource }` and is signed by the AS. The AS's signature is the non-malleability anchor — an attacker cannot forge `act.sub=sonnet` without compromising the AS signing key. How does the construction demonstrate this doesn't satisfy (a)?

- **Why it works / fails:** The RFC 8693 chain fails on **(c)** — specifically the "AS sees every hop" property. Every token exchange call hits the AS token endpoint with the full context: which model, which user, which resource, at what time. For the enterprise CISO scenario (§scenarios[0]), where "only approved models touched PII files," the AS accumulates a complete audit log of every `(model, user, resource, timestamp)` tuple. The construction's proof reveals only `{ model_hash, operator_pk, permission_bitmask, message_hash }` to the verifier with no AS intermediary and no session linkage. Additionally, `act.sub` in RFC 8693 is an assertion by the token exchanger, not by the model artifact — same enrollment root-of-trust gap as Attack 1.

- **In-threat-model?** Yes — construction survives. However, §gap-to-close should be sharpened: the claim "AS sees every hop" must distinguish between (i) AS involvement at issuance time vs. (ii) AS involvement at verification time. Signed JWT introspection + token exchange can remove AS from *verification*; Bolyra removes AS from *both* issuance and verification. This distinction is load-bearing and is currently implicit.

---

### Attack 4: Pairwise Subject Identifiers (PPID) + RFC 8707 Already Break Cross-RS Linkability

- **Attack:** The §scenarios cite cross-operator and cross-RS linkability as a threat. OIDC PPIDs (pairwise pseudonymous identifiers, OIDC Core §8.1) already ensure that RS-A and RS-B see different `sub` values for the same user+model pair — they cannot correlate by subject. Add RFC 8707 resource indicators so each token is audience-bound to a single RS. An attacker observing tokens at RS-A learns nothing about the subject at RS-B. The construction's §claim that "no vanilla OAuth/MCP auth can bind runtime model identity to the message" conflates *model identity binding* with *cross-RS unlinkability* — PPID already handles the latter. What is the residual gap?

- **Why it works / fails:** PPID solves unlinkability at the **RS-to-RS** level but deliberately does not apply to the **AS**, which holds the pairwise mapping table and can trivially re-link any PPID to the real subject. For the liability dispute scenario (§scenarios[1]) — "bank claims agent drained account; prove which model made the transaction" — the AS is a required witness and a legal discovery target. A subpoena to the AS breaks PPID unlinkability entirely. Bolyra's construction places zero trust in the AS: the PLONK proof is self-contained, the AS holds no mapping, and there is no party to subpoena who can link `model_hash` back to the operator's full session history. PPID is also inapplicable to the model-identity problem: it pseudonymizes *users*, not *model instances*.

- **In-threat-model?** Yes — construction survives. The paper should add an explicit AS-as-adversary threat (§threat model likely omits "honest-but-subpoenable AS") and call out that PPID's unlinkability guarantee collapses under AS compromise or legal compulsion, while Bolyra's guarantee is cryptographic and AS-free.


## Persona: spiffe_engineer

> *"You have built a very elaborate SVID with a ZK hat on. Let me show you where the seams are."*

---

### Attack 1: Wrong Layer — Just Write a SPIRE Attestor

- **Attack:** SPIRE's attestor plugin interface already accepts arbitrary attestation evidence and produces X.509 SVIDs whose URI SAN encodes workload identity as a structured path: `spiffe://anthropic.com/model/claude-sonnet-4-6/operator/acme-corp/permission/0b101`. A ZK attestor plugin could accept a hash of model weights at workload startup, verify it against an enrollment registry, and mint an SVID binding `modelHash` into the path — all within the existing SPIFFE trust hierarchy and CA chain. The verifier gets a short-lived, auto-rotated X.509 cert, not a PLONK proof. No new protocol, no new circuit.

- **Why it works / why it fails:** The construction (§ Non-malleability, MODEL-BIND-FORGE) reduces security to Poseidon CR + PLONK soundness. But the SPIRE ZK attestor path reduces to the SPIFFE CA's certificate transparency + attestor plugin trust — which Fortune 500s already audit. The construction does not demonstrate that its trust model is *strictly stronger*, only that it is *different*. The SPIRE path has 8 years of production hardening; the construction has a circuit with no deployment history.

- **In-threat-model?** **No.** The construction must explicitly argue why a ZK attestor within SPIRE is insufficient. If the answer is "Anthropic does not control the SPIRE server," that is a deployment assumption, not a cryptographic gap, and must be stated in the threat model.

---

### Attack 2: WIMSE Token Exchange Already Disputes (a)+(c)

- **Attack:** The gap-to-close states "prove RFC 8693 token exchange and DPoP cannot achieve (a)+(c) simultaneously." This is a strawman. `draft-ietf-wimse-arch` (Section 5, workload-to-workload token exchange) introduces a transaction token (`Txn-Token`) that carries caller-context through a call chain *without* the AS seeing every hop after initial issuance. Combined with DPoP (RFC 9449), the workload proof-of-possession key can be bound to a model-specific keypair enrolled at startup. The AS sees the enrollment; it does not see each downstream call. Selective disclosure of the caller-context fields (model version, operator) is already in scope for WIMSE's structured token claims — no ZK required, just standard JWT claim omission with a PoP binding on what is disclosed.

- **Why it works / why it fails:** The construction's §"Beats the Baseline" section dismisses OAuth without engaging WIMSE specifically. WIMSE is an active IETF WG product (not vanilla OAuth), and the Txn-Token design was explicitly motivated by multi-hop agent identity — the exact scenario C7 targets. The construction must show a *concrete* disclosure attack on WIMSE Txn-Token + DPoP that its PLONK circuit prevents. "AS sees every hop" is false for Txn-Token after the first issuance.

- **In-threat-model?** **No.** The construction's baseline comparison must be updated to address WIMSE draft-ietf-wimse-arch §5 directly, or the "beats the baseline" claim is unfounded.

---

### Attack 3: Enrollment Bootstrap is an Unexamined Root of Trust

- **Attack:** The construction states the BJJ keypair is "orthogonal to bearer tokens" for key rotation (§ Key Rotation). But the keypair must be enrolled somewhere — the circuit checks Merkle inclusion of `Poseidon(modelHash, operatorPk, permissionBitmask)` against an `enrollmentRoot`. *Who updates that Merkle tree? How is the first enrollment authenticated?* If enrollment is gated by an API key, we have not escaped the API-key trust problem — we have only pushed it one level up. If enrollment requires an out-of-band ceremony (e.g., Anthropic signs a JWK), then the construction has a TOFU (trust-on-first-use) ceremony that SPIFFE explicitly solves via node attestation: AWS IID, TPM 2.0 quote, or k8s projected service account tokens. SPIRE bootstraps zero-touch with hardware attestation; the construction's bootstrap is unspecified.

- **Why it works / why it fails:** Without specifying the enrollment ceremony, the MODEL-BIND-FORGE game reduction is incomplete. An adversary who can pollute the enrollment Merkle tree (e.g., via a compromised enrollment API) can forge proofs without breaking Poseidon or PLONK. The circuit is sound; the surrounding enrollment protocol is not analyzed.

- **In-threat-model?** **No.** The construction must specify the enrollment trust anchor and demonstrate it does not re-introduce the API-key dependency it claims to eliminate.

---

### Attack 4: modelHash is Not a Stable or Auditable Commitment

- **Attack:** The construction binds `modelHash` (§ Circuit, Poseidon5 commitment). In practice, "Claude Sonnet 4.6" is not a static artifact. Anthropic ships continuous safety patches, RLHF updates, and system-prompt-layer changes without version bumps visible to operators. If `modelHash` is a hash of the deployed weights, it changes on every silent update and historical attestations break. If it is a symbolic version string (`"claude-sonnet-4-6"`), it is *not* a cryptographic commitment to actual computation — an operator could relabel Haiku weights as Sonnet and produce a valid proof. SPIFFE sidesteps this entirely: the SVID attests to the *running process* (binary hash + node attestation), not a semantic version label, and the attestor is re-run on each SVID renewal (default TTL: 1h), catching silent replacements.

- **Why it works / why it fails:** The tiered-pricing scenario (§ Scenarios: "Anthropic wants to prove to a tenant that their Opus usage was actually Opus") requires that `modelHash` is unforgeable by the operator. But the construction does not specify who computes `modelHash` or how it is witnessed. If Anthropic does not attest to `modelHash` at inference time (e.g., via a TEE measurement), the operator can self-report any hash and the circuit will happily prove it. The non-malleability reduction (MODEL-BIND-FORGE) assumes `modelHash` is a trusted input — it does not model the adversarial operator who controls the enrollment pipeline.

- **In-threat-model?** **No.** The construction must specify the attestation source for `modelHash` (TEE quote? Anthropic-signed manifest?) and prove the operator cannot substitute an alternative value. Without this, the tiered-pricing and FDA/EU AI Act scenarios are not achieved by the construction.
