# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Adversarial-AS Threat Model Is Not a Buyer-Level Concern

- **Attack:** Section 8 leads with "adversarial-AS + implication closure" as the primary differentiator, and Section 3's `Game_ImplicationClosureForgery` sub-game formalizes protection against an AS that could "lie about scope membership." But in every enterprise deployment I sell into, the AS is either Auth0 (our managed infrastructure) or the customer's own IdP federated through us. The customer *is* the AS. No CISO at a credit union is going to adopt a ZK ceremony to protect against *their own authorization server* misbehaving. The threat model in Section 8 Property 1 is real in a multi-party cryptographic protocol paper; it is not real in a WorkOS sales cycle.
- **Why it works:** The construction correctly proves that circuit-enforced implication closure is unconditional, while AS-side assertion can lie. This is a valid cryptographic distinction. But the buyer never asked for this property. The CIO's threat model is credential theft, phishing, and audit failures — not a malicious AS. Sections 3 and 8 are written for a cryptographer, not for the enterprise security buyer who signs the PO.
- **In-threat-model?** No — the construction must address *why a buyer needs AS-blindness*, not just prove it's achievable. One concrete enterprise scenario where the AS is semi-trusted and cannot be given the full permission set (e.g., federated agent credentials across org boundaries where neither party trusts the other's AS) would convert this from a theorem into a sales argument.

---

### Attack 2: Latency Makes the Selective Disclosure Property Moot

- **Attack:** The attack prompt is explicit: "Your circuits take ~15s to prove. WorkOS issues tokens in <100ms." The construction's claim (Section 1, preserved verbatim) is about *what the agent proves*. It says nothing about *when*. Even if rapidsnark brings this to 2–3 seconds, no resource server in an interactive MCP tool-call chain will accept a blocking ZK proof generation step. Auth0 + RAR (RFC 9396) returns a structured authorization detail object in <100ms with per-resource granularity. The latency argument doesn't just affect UX — it affects whether the selective disclosure even gets invoked, because operators will cache the full-scope token to avoid the proving cost, which defeats the entire point.
- **Why it works:** The construction addresses *what is provable* but not the *operational deployment model*. If agents pre-compute proofs at credential issuance time (not at request time), the "AS-blind, agent-chooses-at-moment-of-use" property described in the gap-to-close disappears — the proof is fixed at issuance, making it structurally equivalent to a scoped JWT. If proofs are generated at request time, the latency makes it undeployable in any synchronous tool-call path.
- **In-threat-model?** No — the construction must specify the proof lifecycle (issuance-time vs. request-time) and show that the interactive latency is acceptable, or define an offline pre-compute model that preserves the "moment of use" disclosure property.

---

### Attack 3: Rich Authorization Requests (RFC 9396) + FGA Closes the "2^64 Permission Space" Scenario Without ZK

- **Attack:** Scenario 1 in the construction posits "regulated agent with 2^64 permission space where AS-side policy tables do not scale." Section 7 carefully addresses RFC 7662, Client Attestation, WIMSE WPoP, and SPIRE — but does not address RFC 9396 (Rich Authorization Requests) combined with a relationship-based access control engine (Auth0 FGA, Google Zanzibar, AWS Verified Permissions). With RAR, the RS specifies a structured `authorization_details` object with arbitrary nesting; the AS evaluates it and returns only what's authorized. Auth0 FGA handles tuple-based permission graphs that trivially express implication chains (FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM → FINANCIAL_SMALL) as relationship tuples, evaluated server-side with sub-millisecond latency. The AS-side policy table scaling concern only applies to flat scope strings — not to graph-structured authorization backends.
- **Why it works:** The construction's Section 7 comparison table covers five baselines but all five are identity/attestation mechanisms. The authorization layer (RAR + FGA) is a different product category and a different section of the OAuth stack. The "policy tables do not scale" claim needs to be made against FGA-class systems, not against RFC 7662 introspection endpoints.
- **In-threat-model?** No — the construction must add RAR + FGA as a baseline in Section 7. The differentiator argument may still hold (AS-blind presentation remains impossible in RAR + FGA since the AS must evaluate the relationship query), but this needs to be stated explicitly against this specific baseline.

---

### Attack 4: The "Constant-Size Proof" Claim Is Vacuous Against an 8-Bit Bitmask

- **Attack:** The gap-to-close mentions "constant-size proof regardless of bitmask width" as a candidate differentiator. But the Bolyra permission model (documented in `CLAUDE.md` and the construction's own Section 3) uses an 8-bit cumulative encoding with bits 0–7. An 8-bit bitmask fits in a single JWT claim field. A JWT with `"permissions": 28` (binary `00011100`) is constant-size and requires no ZK machinery. The "bitmask width" argument has force at 2^64 or for dynamically extensible permission namespaces — but the construction's own permission model is bounded by spec. If Bolyra ever extends to wider bitmasks, the Groth16 circuit must be re-trusted-setup. The incumbent doesn't have that problem: add a column to FGA and redeploy.
- **Why it works:** This is an internal consistency attack. The construction's theoretical claim (constant-size proofs over arbitrary-width bitmasks) does not match the construction's own deployed permission model (8 fixed bits). The differentiator only holds if the permission space is large enough that ZK compression is cheaper than transmitting the raw bitmask — which it isn't at 8 bits. Section 8's Property 1 list should either restrict the "constant-size" claim to the large-bitmask scenario or acknowledge that for the current 8-bit model, this property provides no practical advantage over a bitwise JWT claim verified locally.
- **In-threat-model?** Partial — the cryptographic construction is sound, but the claim overreaches the current deployment scope. The construction should either expand the permission model to justify the claim or narrow the claim to future-proofing against permission space growth.


## Persona: cryptographer

---

### Attack 1: Subverted Setup Destroys the Adversarial-AS Claim

- **Attack:** The construction's most advertised property (Section 8, Property 1) is "adversarial-AS model where AS cannot lie about scope membership." But both `AgentPolicy` and `Delegation` circuits use **Groth16 with project-specific keys derived from `pot16.ptau`**. Groth16 soundness holds only if the toxic waste from the trusted setup ceremony is destroyed. Whoever ran that ceremony — if it is ZKProva Inc. itself, or any single party — retains the ability to forge arbitrary proofs for any permission bitmask, including ones that pass `Game_ImplicationClosureForgery`. PLONK avoids per-circuit ceremony but still requires a trustworthy universal SRS; a subverted `pot16.ptau` breaks PLONK too, since the SRS feeds the PLONK CRS derivation. The construction does not define a threat model for the setup phase. "Adversarial AS" must mean adversarial *at runtime*, but it is silent on whether the AS participated in the ceremony.

- **Why it works / fails:** It works because there is no multi-party ceremony described, no attestation of ceremony integrity (e.g., public transcript with randomness beacons), and no UC-ideal functionality for the CRS. It fails to be addressed by adding more comparison rows to Section 7 — those rows compare *runtime* mechanisms. The attack is a *setup-time* break.

- **In-threat-model?** **No.** The paper must either (a) specify that the CRS is produced by a publicly verifiable MPC ceremony with at least one honest party, or (b) prove security in a model where the CRS itself is adversarially chosen (which Groth16 cannot satisfy — knowledge soundness collapses under a subverted CRS).

---

### Attack 2: Honest-Verifier ZK ≠ Malicious-Verifier ZK — No Simulator Given

- **Attack:** Section 3 adds a `Game_ImplicationClosureForgery` sub-game but never provides a **simulator** for the zero-knowledge property. Groth16 achieves *honest-verifier zero-knowledge* (HVZK) in the CRS model: the proof is simulatable only when the verifier uses the prescribed verification key and does not deviate. If the resource server (RS) is semi-malicious — e.g., it sends a non-standard challenge, replays proof components across verification transcripts, or participates in a side-channel with a colluding AS — HVZK gives no guarantee. The construction conflates "the proof does not reveal which bits are set" with "the proof is zero-knowledge." Without writing `Sim(vk, x)` explicitly and proving indistinguishability from `Prove(pk, x, w)`, this is a claim, not a proof. Additionally, Groth16 is **not simulation-extractable (SE)**: a valid proof `π` can be re-randomized to `π'` by any party who knows `vk`, producing a new accepting proof for the same statement without knowledge of the witness. In a composed protocol (e.g., nonce-bound handshake), lack of SE can enable proof-forwarding attacks.

- **Why it works / fails:** The re-randomization attack on Groth16 is textbook (Groth 2016, Remark 1). The construction binds to `sessionNonce` as a public input, which prevents naive replay of the same nonce. But if a man-in-the-middle captures `(π, sessionNonce)` and the verifier does not authenticate the prover's identity independently, re-randomizing `π` to `π'` still satisfies `verifyProof(vk, [sessionNonce, ...], π')` because the public inputs are unchanged. The nonce is public — it is not a secret the MitM lacks.

- **In-threat-model?** **No.** The construction must either (a) switch to a SE-Groth16 variant (e.g., Groth–Maller, or Groth16 + Fiat-Shamir binding), (b) prove that nonce-binding closes the re-randomization gap in the specific handshake protocol, or (c) formally provide the HVZK simulator and scope the ZK claim to honest verifiers only.

---

### Attack 3: modelHash Is a Persistent Cross-Session Linkability Vector

- **Attack:** `AgentPolicy` takes `modelHash` as a **public input** (visible in the proof's public signals). A resource server observing multiple proof presentations sees `modelHash` in every transcript. If an agent model — say, a specific Claude Sonnet deployment identified by its hash — interacts with 1000 RSes, every RS can cross-reference and build a full interaction graph for that agent across all sessions, scopes, and operators. This is not addressed anywhere in Section 7 or Section 8. The selective-disclosure claim covers *permission bits*, not *agent identity*. The construction thus achieves predicate privacy but not agent unlinkability.

- **Why it works / fails:** It works because `modelHash` is semantically equivalent to a long-term pseudonym. Unlike the human nullifier (which is scope-scoped: `H(secret, scope_id)`, different per RS), `modelHash` is fixed by the model's weights and is the same across all operators and RSes that deploy the same model. A colluding set of RSes can trivially de-anonymize agent behavior. This matters in the "regulated agent with 2^64 permission space" scenario (Candidate C1, Scenario 1): if the agent operates across many RSes under the same `modelHash`, operator-level unlinkability is gone.

- **In-threat-model?** **No** (for any unlinkability claim). The fix requires either (a) a per-session commitment to `modelHash` (e.g., `H(modelHash, operatorPrivKey, nonce)` as the public signal, with the circuit proving knowledge of a preimage that satisfies the credential signature), or (b) explicitly scoping the claim to *permission-predicate privacy only*, not agent-session unlinkability.

---

### Attack 4: Transitive Implication Closure Is Not Equivalent to Constraint Completeness

- **Attack:** The `Game_ImplicationClosureForgery` sub-game (Section 3) states "no accepting proof can attest to an implication-violating bitmask." The construction enforces implications via R1CS constraints in `AgentPolicy.circom`. The implication chain is:

  ```
  FINANCIAL_UNLIMITED (bit 4) → FINANCIAL_MEDIUM (bit 3) → FINANCIAL_SMALL (bit 2)
  ```

  The natural R1CS encoding checks *direct* implication: `bit4 * (1 - bit3) === 0` and `bit3 * (1 - bit2) === 0`. Transitivity is then a *derived property* — but only if both constraints are simultaneously enforced and the bit signals are range-checked to `{0, 1}`. The attack: if the bit signals are field elements and the range check `bit_i * (1 - bit_i) === 0` is omitted for even one bit, a witness can set `bit4 = 1, bit3 = 2, bit2 = 0` in the field. The constraint `bit4 * (1 - bit3) === 1 * (1-2) = -1 ≠ 0` fails — but if `bit3` is unconstrained to be binary, an adversary can pick `bit3` such that `bit4 * (1 - bit3) = 0` with `bit3 ≠ 1`. For example, `bit3 = 1 + field_element_p/bit4` in a large field. This is the underconstrained witness class that the `tier2_004_formal_verifier_underconstrained_merkle_depth` and `tier2_005_formal_verifier_cumulative_bit_completeness` experiments appear to be investigating — but whether they *prove completeness* or merely *test specific cases* is not established.

- **Why it works / fails:** It works if any bit signal lacks a `boolean()` constraint and the implication check is an equality gate over non-boolean inputs. It fails if `validateCumulativeBitEncoding()` in the SDK mirrors the circuit constraints exactly AND the circuit includes 8 boolean range checks as non-optional constraints. The sub-game soundness proof must exhibit an extractor that, given any accepting proof, extracts a witness with all 8 bits in `{0,1}` satisfying all implications — this extractor argument is absent from Section 3 as described.

- **In-threat-model?** **Conditional.** If the circuit includes explicit `component bits[8]; bits[i] = Num2Bits(1)` decomposition for all 8 permission bits (standard Circom pattern), the attack is closed and the construction survives. But the paper must *cite* this, not assume it. Soundness of `Game_ImplicationClosureForgery` requires a knowledge extractor proof, not just a game definition. Without the extractor, the sub-game proves nothing about the actual circuit.


## Persona: cu\_ciso

---

### Attack 1: Audit Trail Opacity — My Examiner Can't Read a Groth16 Proof

**Attack:** The construction proves predicate satisfaction via R1CS witness and produces a Groth16/PLONK proof. The resource server accepts `verifyProof() == true`. That's it — that's the audit record. When my NCUA examiner asks for evidence that agent `acct-servicing-bot` had only `READ_DATA | FINANCIAL_SMALL` when it accessed member loan records on March 14, I hand them a 192-byte elliptic curve element and a bitmask. They walk out.

**Why it works / why it fails:**
The construction addresses the *cryptographic* audit property ("no accepting proof can attest to an implication-violating bitmask") but says nothing about the *regulatory audit* property. NCUA Part 748 § 748.0(b) requires the credit union to maintain a security program with controls that produce reviewable records. FFIEC CAT Domain 3 (Cybersecurity Controls) requires logging at the application layer that maps to identifiable actors and authorized actions. A ZK proof satisfies neither: it is a succinct argument, not a human-readable audit log of who authorized what scope for which session. The Section 8 Property 1 summary — "who evaluates the predicate" — is entirely irrelevant to an examiner questionnaire.

**In-threat-model?** No. The construction must address how `(proof, public_signals, sessionNonce)` gets translated into a durable, examiner-readable access log that maps to the credit union's existing SIEM and satisfies 748 Appendix A logging requirements.

---

### Attack 2: Credential Revocation Latency vs. NCUA 72-Hour Breach Clock

**Attack:** An agent credential is compromised — exfiltrated EdDSA private key, rogue model update, operator breach. NCUA Part 748 Appendix B requires notifying NCUA within 72 hours of discovering a reportable cyber incident and requires the credit union to demonstrate it could *contain* the incident. Under GLBA Safeguards Rule (16 CFR § 314.4(h)), the incident response plan must include procedures to prevent further unauthorized access. I need to revoke that agent's permissions *now*.

The construction's on-chain registry is the revocation surface. Section 3's `Game_ImplicationClosureForgery` proves no proof can be forged — but a *validly issued* credential with a compromised key can still produce valid proofs until the registry is updated and the on-chain nullifier set is checked. If the chain (Base Sepolia / Base mainnet) has congestion, L1 finality lag, or the registry contract owner key is in a hardware wallet in a drawer, revocation SLA is undefined.

**Why it works / why it fails:**
The construction's differentiation argument is entirely about *issuance integrity* (implication closure) and *presentation privacy* (AS-blind). It has no Section addressing revocation latency, key-compromise response time, or what happens to in-flight sessions between compromise discovery and on-chain nullifier registration. RFC 7662 introspection gives me a centralized AS I can kill in under one second. The construction's decentralized model trades that operational handle for the ZK property — a trade my board risk committee did not approve.

**In-threat-model?** No. The construction must bound revocation latency, define the custody of the registry admin key, and show it integrates with the credit union's existing incident response runbook timeline.

---

### Attack 3: Member Secret Key Custody — GLBA Safeguards Rule § 314.4(c)

**Attack:** `createHumanIdentity(secret)` — where does `secret` live? The SDK quickstart (`sdk/QUICKSTART.md`) implies a browser-generated entropy value committed into the Semaphore-style Merkle tree. If that's localStorage or a session variable, I've already lost: GLBA Safeguards Rule § 314.4(c)(3) requires the credit union to implement multi-factor authentication for member access and to protect authentication credentials. A browser-resident secret with no hardware binding fails both.

If the answer is "use a hardware token," then: (a) what's the member recovery path when they lose it? (b) Who owns the enrollment ceremony? (c) Does re-enrollment invalidate the old nullifier and how long does that take? The construction's Section 3 `nonceBinding` and `nullifierHash` design means a lost secret = lost identity with no recovery unless the credit union runs an out-of-band re-enrollment flow — which is now *my* operational burden, not the protocol's.

**Why it works / why it fails:**
The comparison table in Section 7 benchmarks against WIMSE WPoP and hardware-attested SPIRE on the *authorization* layer, correctly noting those mechanisms don't enforce permission-structure invariants. But SPIRE's SVID is issued to a workload with a defined rotation lifecycle and a SPIRE server I control. The Semaphore-style secret has no defined rotation, no issuer I control, and no recovery mechanism documented in the construction. From my GLBA exam posture, this is a credential management gap, not a ZK gap.

**In-threat-model?** No. The construction must specify secret custody options (hardware-bound vs. software), document the re-enrollment flow, and show it does not require the credit union to own an out-of-band identity recovery program that isn't scoped in the vendor relationship.

---

### Attack 4: Third-Party Risk — On-Chain Registry as Unvetted Vendor

**Attack:** The on-chain registry (Base / Base Sepolia) is a dependency for `verifyHandshake()`. My Vendor Management Policy — required under NCUA Letter to Credit Unions 07-CU-13 and reaffirmed in the third-party risk guidance — requires me to assess availability SLAs, business continuity, and exit strategies for every critical vendor. Base mainnet had a sequencer outage in January 2024. The construction's "constant-size proof regardless of bitmask width" is irrelevant if the verifier contract is unreachable.

The Section 8 property list ("adversarial-AS + implication closure") assumes the on-chain verifier is *available*. My core processor (Symitar, Corelation) contractually guarantees 99.95% uptime. Base does not offer me a signed SLA, an MSA, or indemnification. My examiner will ask: "What's your BCP if the blockchain is unavailable?" The correct answer is not "we fail open" and not "we fail closed and block all member-facing agents" — neither is in the construction.

**Why it works / why it fails:**
The construction is technically correct that no RFC 7662 configuration can produce AS-blind implication-closed proofs. That's a real cryptographic property. But "my AS is a smart contract on a public L2" is a vendor risk my board hasn't approved and my examiner hasn't seen a category for. The comparison table in Section 7 should include a row: *who signs the SLA and who do I call at 2am* — and for on-chain verifiers, that row is empty.

**In-threat-model?** No. The construction must provide a hybrid deployment option (off-chain verifier with on-chain anchoring for auditability only) and document the availability model, BCP fallback, and how it maps to the credit union's existing third-party risk tiering framework.


## Persona: rfc7662_advocate

---

### Attack 1: SD-JWT Selective Disclosure — The Construction's Blind Spot

- **Attack:** The construction benchmarks against RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, Client Attestation, WIMSE WPoP, and SPIRE. It does not address **draft-ietf-oauth-selective-disclosure-jwt (SD-JWT, now RFC 9635)**. In SD-JWT, each permission bit is an individual salted hash disclosure. The AS issues once; the agent at runtime chooses which disclosures to present to the RS. The RS verifies the AS signature and the disclosed claims — no AS roundtrip, no full permission set revealed, agent-controlled at presentation time. The "AS-blind presentation" property in the candidate's gap-to-close is precisely what SD-JWT delivers, without circuits.

- **Why it works / fails:** The construction's Section 8 Property 1 claims "adversarial-AS + implication closure" as the differentiator. SD-JWT doesn't break the adversarial-AS attack (the AS still signs the disclosures — if the AS lies at issuance, RS is compromised). But for the *selective disclosure* sub-claim specifically — which is framed as the agent choosing what to disclose at the moment of use — SD-JWT matches it. The construction needs to show that SD-JWT cannot express `prove(bitmask satisfies predicate P)` without revealing a disclosure for each bit in P. That argument is absent.

- **In-threat-model?** **No** — construction must address SD-JWT as a baseline. If the only surviving differentiator post-SD-JWT is the adversarial-AS model, that needs to be stated explicitly and that threat model needs to be defended as in-scope.

---

### Attack 2: Adversarial-AS Is Special-Pleading Outside the OAuth Trust Boundary

- **Attack:** The construction's load-bearing differentiator in Section 8 is the adversarial-AS model: the AS cannot lie about scope membership because the R1CS constraint is enforced independently. I accept this is cryptographically true. But this is not a property OAuth is designed to provide — **it's explicitly outside the OAuth threat model**. RFC 7662 §7 (Security Considerations) explicitly notes that AS trust is a prerequisite of the protocol. If you don't trust your AS, you don't use OAuth. The construction is claiming ZK superiority by invoking a threat model that the baseline is architecturally forbidden from addressing — then counting that as a gap.

- **Why it works:** This is a definitional sleight-of-hand. A construction that wins by changing the threat model hasn't beaten the baseline — it's answered a different question. Show me a *deployed* RS that distrusts its own AS on scope claims. If that scenario is the claimed differentiator, the construction should lead with it and bound the claim to "in deployments with semi-trusted AS" — not position it as a general ZK advantage.

- **Why it partially fails against the construction:** The regulated-agent scenario (2^64 permission space) does motivate a semi-trusted AS where scale prevents the AS from evaluating every implication at introspection time. That's a real operational constraint. But this is an argument about AS *scalability*, not AS *adversariality* — and those are different arguments that need different framing.

- **In-threat-model?** **Partially.** The construction survives in the regulated-agent / scale scenario, but the adversarial-AS framing overstates what that scenario requires and will be dismissed by any OAuth reviewer on first read. Section 8 should split "semi-trusted AS due to scale" from "malicious AS" — only the former is defensible in a standards context.

---

### Attack 3: Implication Closure Is Trivially Enforceable by the AS at Issuance — R1CS Adds Nothing in the Normal Trust Model

- **Attack:** Section 3 adds a `Game_ImplicationClosureForgery` sub-game and calls R1CS enforcement the differentiator over "issuer assertion." But consider: the AS receives a credential request, runs the same bit-arithmetic implication check (`FINANCIAL_UNLIMITED` requires bits 2 and 3 set), and refuses to issue a structurally invalid JWT. The RS receives a signed JWT with `permissions: 0b00010000` (bit 4 set, bits 2-3 absent) — it also runs the same 3-line bit-mask check locally before accepting. **No ZK circuit required.** The implication rules are public, deterministic, and cheap. The RS can re-verify the AS's structural claim without trusting the AS's *evaluation* — it trusts the AS's *signature* on the raw bits, then checks the bits itself.

- **Why it works:** R1CS constraint enforcement proves the *witness* (full bitmask) satisfies the predicate while hiding the witness. But if the disclosed claim IS the full bitmask (the RS gets `permissions: 0b11110111`), the RS checks implication locally and the ZK adds no information-theoretic value. The hiding property only matters if the RS must not see the full bitmask — which is the selective disclosure problem (covered by SD-JWT in Attack 1, not by the implication closure game).

- **Why it fails:** The construction's genuine contribution is combining implication closure WITH hiding: the RS learns only `satisfies(P)`, not the bitmask. But Section 3 conflates these two properties. The sub-game formalizes forgery resistance, not the combination of forgery resistance + hiding. A clean separation would strengthen the claim: "RS learns only the predicate result; implication closure is enforced in the witness, not in the disclosed claim."

- **In-threat-model?** **Yes** — but the construction must tighten Section 3 to separate "hiding the bitmask while proving implication closure" from "preventing structural forgery." The latter is achievable without ZK; the former is the genuine gap.

---

### Attack 4: RFC 8693 Token Exchange With Scope Downscoping Matches "Runtime-Adaptive Predicate"

- **Attack:** The candidate's gap-to-close lists "runtime-adaptive predicate over permissions (not fixed at issuance)" as a candidate differentiator. I challenge this. **RFC 8693 Token Exchange** allows an agent to present a wide-scope token and exchange it at a delegation AS for a narrow-scope token targeting a specific RS and audience (RFC 8707). The narrow-scope token is issued at runtime, not at the original issuance. Combined with RFC 9449 DPoP, the exchange token is sender-constrained. The final RS-specific token expresses exactly the predicate the agent needs for that interaction, derived at runtime from the original wide-scope credential, without revealing the original token's full scope to the RS.

- **Why it works:** This is a real operational pattern used in large-scale enterprise OAuth deployments. The construction does not cite RFC 8693 in Section 7's baseline expansion (which added Client Attestation, WIMSE WPoP, SPIRE — all identity-layer mechanisms). RFC 8693 is an *authorization-layer* mechanism that directly competes with the runtime-adaptive predicate claim.

- **Why it partially fails:** The RFC 8693 exchange requires a roundtrip to the delegation AS at runtime — which reintroduces the AS into the hot path. The ZK construction allows the agent to compute a fresh proof at presentation time with no network call. In latency-sensitive or offline environments, this is a genuine advantage. But the construction hasn't made this argument — it doesn't mention RFC 8693 at all, so it hasn't earned the win.

- **In-threat-model?** **No** — Section 7 must add RFC 8693 to the baseline comparison table and show explicitly that the roundtrip-to-delegation-AS requirement is a load-bearing distinction (not just an incidental one). Otherwise a reviewer will note the omission and reject the differential claim as incomplete.


## Persona: spiffe_engineer

### Attack 1: The ZK Attestor Plugin — Implication Closure at Issuance, Not Presentation

- **Attack:** SPIRE's plugin architecture accepts custom node attestors and workload attestors. I write a `ZKImplicationAttestor` plugin that refuses to issue an X.509 SVID or JWT SVID unless the permission bitmask presented by the workload satisfies the implication closure rules (FINANCIAL_MEDIUM ⊇ FINANCIAL_SMALL, etc.) as a local constraint check before issuance. The SPIRE agent rejects structurally invalid bitmasks at enrollment time. Section 7's new subsection argues attestation certifies "identity and platform state, not algebraic satisfaction of permission-structure invariants" — but a custom attestor *can* evaluate algebraic invariants before issuing the credential. The construction conflates the current state of SPIRE attestors with what attestors are capable of.

- **Why it works / fails:** It lands a partial hit. Implication closure can be pushed into the attestor, making the point in Section 3 ("boolean-return RFC 7662 relies on the AS to evaluate the predicate") less distinguishing. **However**, the construction's remaining differentiator is *presentation-time selective disclosure*: the JWT SVID still carries the full bitmask claim in the token body. The RS sees `"permissions": 0b00011100` regardless. The construction's `Game_ImplicationClosureForgery` sub-game is about the prover not being able to *forge* a proof — but the SPIRE path's forgery protection is at issuance, after which the full set is leaked at every presentation. The ZK path lets the agent prove `bit_3 = 1` without leaking bits 0–7. This residual gap is real, but the construction's Section 3 should explicitly frame it as *post-issuance leakage at presentation*, not just predicate evaluation location.

- **In-threat-model?** Partially. Construction survives on selective disclosure; does **not** survive on the claim that "no attestor can enforce implication closure." Section 7 must be corrected to read: "hardware-attested SPIRE *today* does not ship this plugin, but the architecture permits it — the gap that remains is presentation-layer leakage, not issuance-layer enforcement."

---

### Attack 2: WIMSE WPoP + BBS+ Collapses the AS-Blind Presentation Claim

- **Attack:** The WIMSE S2S protocol (`draft-ietf-wimse-s2s-protocol`) defines Workload Proof-of-Possession tokens. I pair this with a BBS+ multi-message signature over individual permission bits: the AS issues a BBS+ credential with one message per permission bit, and the workload presents a BBS+ selective disclosure proof to the RS at call time — revealing only the bits the RS requires, no AS roundtrip, constant-size derivation proof (48 bytes per Pairing-based BBS+ scheme). The construction's Section 8 Property 1 claims "AS-blind presentation" as a differentiator. BBS+ over WIMSE WPoP achieves exactly this.

- **Why it works / fails:** This is the sharpest attack. BBS+ gives AS-blind selective disclosure of individual attributes. **Where it fails** against the construction: BBS+ proves "I have a credential where bit_3 was signed" but does not prove "my full bitmask satisfies the implication closure invariant." A workload could hold a BBS+ credential with bit_3 signed and bit_2 *absent* (FINANCIAL_MEDIUM without FINANCIAL_SMALL), derive a selective-disclosure proof for bit_3, present it, and the RS cannot detect the structural violation without seeing the full set — which defeats the privacy goal. The R1CS constraint in the construction proves both selective disclosure *and* global structural integrity in a single constant-size proof. BBS+ cannot combine these without leaking all bits or requiring a separate ZKP of the implication rules, which is exactly what the construction provides.

- **In-threat-model?** Yes — construction survives, but only if Section 7's comparison table adds a BBS+ row explicitly. The current table lists RFC 7662 variants and hardware-attested SPIRE but misses BBS+ over WIMSE WPoP. Omitting this leaves the most credible standards-track alternative unaddressed, and a reviewer familiar with WIMSE will notice.

---

### Attack 3: Trust-Domain Federation Already Gives You Portable Identity

- **Attack:** Section 8 asserts "portable identity across trust domains" as a property of the construction. SPIFFE trust-domain federation (`spiffe://domain-a/workload` accepted by `domain-b`'s SPIRE server via a federated bundle) already provides this. I stand up two SPIRE servers with mutual bundle exchange. An agent from trust domain A presents its X.509 SVID to a resource server in trust domain B; domain B's RS validates against domain A's CA bundle. This is production-grade, deployed at scale at multiple Fortune 500s today. The construction's claim in this dimension is not novel.

- **Why it works / fails:** Lands a hit on the *portability* sub-claim. **The construction's actual differentiator** is not portability per se — it is *nullifier-based uniqueness binding* (the `nullifierHash` output of HumanUniqueness prevents double-enrollment across domains without linking individual sessions). SPIFFE federation is portable but provides no Sybil resistance: one human can enroll 10,000 SVID identities across federated domains with no cryptographic linkage. The construction's human-root circuit enforces one-enrollment-per-human-secret across all trust domains simultaneously. This is a genuinely different property. But the construction's Section 8 does not foreground this distinction — it lists "portable identity" generically, which invites exactly this attack.

- **In-threat-model?** No — the construction must address this. Section 8 Property 1 should rename "portable identity" to "Sybil-resistant portable identity" and add a one-paragraph contrast with SPIFFE federation explaining that federation is portable but not Sybil-resistant at the human layer.

---

### Attack 4: The 2^64 Permission Space Is a Paper Tiger — The Real Scaling Axis Is Organizational

- **Attack:** Section 7's "regulated agent with 2^64 permission space where AS-side policy tables do not scale" is used to justify constant-size proof as a differentiator. In production workload identity, we never enumerate permissions as a flat bitmask. We model permissions as SPIFFE paths: `spiffe://corp/svc/payments/read`, `spiffe://corp/svc/payments/write`, enforced by OPA or Cedar policy engines that scale to millions of rules. The 2^64 bitmask is an artificial framing — real enterprises use structured hierarchies, not flat bit vectors. The construction's 8-bit permission model with cumulative implication is adequate for a demo but does not represent how enterprise authorization actually works.

- **Why it works / fails:** Partially lands. The 8-bit model *is* a simplification, and the 2^64 scenario is strawman-ish. **However**, the deeper argument is not about scale of the permission space but about *who enforces the structure*. OPA and Cedar evaluate policy at the RS — they are AS-side evaluators accessible via network call or local daemon. In the adversarial-AS model (Section 7, scenario 2: "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation"), OPA/Cedar running at the RS still consume a JWT issued by the potentially-compromised AS. The AS can issue a JWT with `"permissions": ["payments.write"]` even if the human principal never authorized that scope. The R1CS constraint is enforced by the circuit, not the AS, so a compromised AS cannot issue an accepting proof for permissions the human-root never granted. This adversarial-AS argument is buried in Section 7 scenario 2 and needs to be elevated to the primary framing.

- **In-threat-model?** Partially. Construction survives on adversarial-AS model, but Section 7 must drop or heavily qualify the "2^64 permission space" scaling argument, which is weakly supported, and lead instead with the adversarial-AS model as the primary motivation. Failing to do so gives WIMSE/SPIFFE reviewers an easy dismissal handle.
