# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: Latency Kills Synchronous MCP Tool Calls — There Is No Session Token Layer

**Attack:**

The construction advertises "< 4 seconds with snarkjs, ~0.8s with rapidsnark" (§6, Proving time targets). I pull up [Auth0 MCP auth](https://auth0.com/ai/docs/mcp/intro/overview) and [Stytch Connected Apps](https://stytch.com/docs/connected-apps/guides/mcp-auth-overview): after initial OAuth, MCP tool calls authenticate via bearer token — round-trip < 5ms on cached tokens, < 500ms for Dynamic Client Registration (RFC 7591) on first call. WorkOS is the same pattern.

Now trace what happens in Bolyra when a PenFed agent calls a partner credit union's MCP tool for a loan pricing query. The agent must generate a fresh IssuerBlindPredicate proof because **the construction mandates a fresh `credentialSalt` and fresh `sessionNonce` per proof** to achieve cross-session unlinkability (§3, IND-ISS game, Phase 3; §4, Key step). There is no proof-caching mechanism defined anywhere in the construction. The `blindNullifier = Poseidon2(credentialCommitment, sessionNonce)` is session-bound; reusing it would be flagged as a replay. So every session cold-starts at 0.8–4 seconds.

The MCP protocol has no standard for async credential presentation. The agent call blocks. In a multi-step loan origination workflow with 12 tool calls across 3 partner CUs, the credential layer alone adds 10–48 seconds of wall-clock latency per workflow. No credit union operations team accepts this.

The construction has no session token layer — no mechanism to issue a short-lived bearer token from a verified proof that downstream MCP servers can check in < 5ms. The on-chain verifier (§7, Verification steps) requires the full PLONK proof every time.

**Why it works / why it fails against the construction:** The construction deliberately does not define a session token derived from a verified proof, because introducing one would require an issuer of that token — reintroducing the very AS-equivalent it claims to eliminate. The tradeoff is real and unaddressed. Every session-level auth event pays the full proving cost.

**In-threat-model?** No — the construction must address a proof-once / verify-many pattern (e.g., a short-lived on-chain session commitment derived from a single proof that multiple MCP calls reference within a TTL window) or benchmark the real-world latency impact on multi-call workflows and show it is acceptable to operators.

---

### Attack 2: Issuer Registry Governance Reintroduces the Trusted Party the Construction Claims to Eliminate

**Attack:**

The construction's headline claim is AS-blind issuer hiding: "no party in the protocol — not the verifier, not the relay, not the registry operator, not the on-chain indexer — ever possesses the issuer identity in cleartext" (§3, Property 2; §8, Gap 6). This claim rests entirely on the assumption that the issuer registry Merkle root is a neutral, uncontrolled public artifact.

But the construction's own deployment scenario (§7) states: "The NCUA publishes an **issuer registry Merkle tree** containing EdDSA public keys of all 4,600+ federally insured credit unions … The root `issuerRegistryRoot` is published on-chain and **updated quarterly**."

Here is the governance attack:

1. **Who enrolls issuer keys?** The construction is silent. Key enrollment requires a trusted process: someone with write access to the Merkle tree accepts, validates, and inserts `(Ax_j, Ay_j)`. That party knows every issuer key at enrollment time — full visibility, pre-proof.
2. **If NCUA operates the registry**, NCUA must adopt Bolyra's EdDSA key format, Merkle tree construction, on-chain publishing cadence, and revocation tree management. NCUA currently operates no such infrastructure. Convincing a federal regulator to deploy ZK-circuit-compatible key infrastructure is not a 2026 GTM problem; it's a 5-year standards-body problem. Auth0 connects to existing LDAP/SAML/OIDC directories today, without regulatory adoption overhead.
3. **If Bolyra operates the registry**, Bolyra is the new AS. Bolyra knows which issuer keys are enrolled, when they were added, and can trivially correlate proof-submission times against enrollment records to probabilistically identify which credit union is transacting. The AS-blind hiding claim fails: the registry operator is the AS-equivalent, and it is Bolyra (a solo founder with no SOC 2).
4. **"Updated quarterly" is a revocation liability.** A compromised issuer key remains valid for up to 90 days. Auth0 and WorkOS revoke tokens in < 1 second via OIDC back-channel logout. The construction's revocation model for the *issuer registry* (not the credential revocation tree, which is separate) has no emergency path.

The construction compares against RFC 7662 and correctly notes that the AS "inherently knows the issuer" (§8, Gap 6). But the construction replaces the AS with a registry operator who also inherently knows every issuer — unless the registry is decentralized, permissionless, and verifiable, which it is not specified to be.

**Why it works / why it fails against the construction:** The construction formally proves that a verifier cannot extract the issuer from the proof. It does not prove — and cannot prove — anything about the information held by the registry operator who enrolled the issuers in the first place. The IND-ISS game (§3) models the adversary's view of protocol messages, not the adversary's out-of-band access to the enrollment database. Enrollment is entirely outside the game.

**In-threat-model?** No — the construction must specify registry governance (permissioned vs. permissionless enrollment, who holds write keys, how key rotation works) and must either (a) formally bound the registry operator's knowledge to the game or (b) acknowledge that AS-blind hiding is only achieved relative to verifiers and intermediaries, not relative to the registry operator.

---

### Attack 3: The Procurement Question — A Formal Security Proof Is Not a Vendor Risk Assessment

**Attack:**

I am the procurement officer at a $4B credit union. My vendor risk management policy requires any third-party software vendor handling identity or authentication to provide: SOC 2 Type II (last 12 months), penetration test by an approved firm, cyber liability insurance with a minimum coverage threshold, a signed MSA with indemnification clauses, an SLA with defined uptime and incident response SLAs, and a completed vendor security questionnaire (our template runs 200+ questions).

The construction (all 8 sections) contains a formal IND-ISS security proof, a circuit constraint table, and a Bolyra primitive mapping. It contains zero of the above.

Auth0 (Okta): SOC 2 Type II, ISO 27001, FedRAMP Moderate In Process, HIPAA BAA available, enterprise SLA at 99.99%, legal team that signs MSAs same-week. WorkOS: SOC 2 Type II, enterprise support, dedicated CSM for deals > $100K ARR. Stytch: SOC 2 Type II, HIPAA, enterprise tier with SLA. Cloudflare Access: FedRAMP High authorized, global infrastructure with 99.99% SLA backed by a public company.

The construction's author is a solo founder. The IND-ISS game reduction (§4) proves PLONK knowledge soundness implies credential unforgeability. It does not prove that a solo founder can respond to a security incident at 3am, will be in business in 18 months, carries adequate insurance if a breach occurs, or can produce evidence of an independent security audit. My board will not approve a vendor that cannot pass this checklist regardless of how elegant the cryptography is.

This is not a gap the construction can close with more sections. It is a go-to-market problem: the construction exists; the product does not.

**Why it works / why it fails against the construction:** Completely outside the construction's scope, which is purely cryptographic. The author has not addressed this gap anywhere — not in §7 (deployment scenarios) and not in §8 (baseline comparison). The comparison table in §8 compares cryptographic properties. Procurement does not buy cryptographic properties.

**In-threat-model?** No — the construction is a specification, not a product. To be actionable, a deployment section must address the vendor trust gap: either (a) position as open-source infrastructure that enterprises self-host (eliminating vendor risk but requiring internal ZK expertise no credit union has), or (b) acknowledge the go-to-market path requires operating entity maturity the solo founder does not currently possess, and outline a concrete path (e.g., CUSO partnership, white-label with an Auth0 competitor, standards-body submission to NCUA).

---

### Attack 4: The 8-Clause Predicate Cap Breaks the FINRA and Cross-Jurisdiction KYB Scenarios

**Attack:**

The construction's Predicate Evaluation Engine (§2, Gadget 4) supports "up to 8 clauses, each is `(attrIndex, comparator, threshold)`, comparator ∈ {EQ, NEQ, LT, GT, LTE, GTE}, combined with AND/OR/NOT via a 3-level Boolean tree."

Take the construction's own claimed scenario: "cross-firm regulated-professional proof (e.g., FINRA-licensed agent)" (§1, Scenarios). A realistic FINRA Series 65 verification predicate for an AI investment-advisory agent operating across state lines requires:

```
licensed_by_FINRA == 1
AND license_type IN {65, 66}              ← SET MEMBERSHIP (not in comparator set)
AND license_expiry_epoch > now_epoch      ← TEMPORAL (requires trusted timestamp input)
AND disciplinary_actions_count == 0
AND exam_passed == 1
AND states_licensed_bitmask & NY_BIT != 0 ← BITWISE AND (not in comparator set)
AND exam_score >= passing_threshold
AND sponsoring_firm_crd IN allowed_firms  ← SET MEMBERSHIP over 50K+ CRD numbers
```

That is 8 clauses, hitting the cap exactly — but two of the required comparator types (set membership, bitwise AND) are not in the supported comparator set `{EQ, NEQ, LT, GT, LTE, GTE}`. Temporal predicates require the current timestamp as a public input (who provides a trusted on-chain timestamp? The construction does not specify an oracle). Set membership over a large set (50K+ FINRA-registered firms) requires either encoding as a Merkle proof (a different circuit gadget entirely, not included) or pre-expanding all allowed values into clauses (blowing past 8).

The cross-country KYB scenario is harder. The construction's example (§7, Extension) says "predicate: `kyb_verified == 1 AND incorporation_year < 2025`." A real cross-border KYB predicate for a fintech serving US + EU + UK + Singapore requires jurisdiction-specific clauses (UBO threshold varies by jurisdiction: 25% in US, 10% in UK) with conditional logic: `IF jurisdiction == EU THEN ubo_threshold <= 25 ELSE IF jurisdiction == UK THEN ubo_threshold <= 10`. This requires nested conditionals across more than 3 Boolean tree levels.

The construction acknowledges the cap (§2, Gadget 4: "max 8 clauses") but presents it as a feature ("no per-schema circuit work — only a new predicateHash"). For the scenarios it claims to support, 8 clauses with {EQ, NEQ, LT, GT, LTE, GTE} is insufficient. The gap is not a performance issue; it is a correctness issue — certain predicates are inexpressible in the current template.

**Why it works / why it fails against the construction:** The construction's §8, Gap 3 correctly notes BBS+ cannot handle arbitrary Boolean predicates. But the construction's own predicate engine is not "arbitrary" — it is bounded at 8 clauses with 6 comparator types and 3 tree levels. The comparison against BBS+ is fair, but the comparison against what real compliance predicates require is not made. The construction would need additional gadgets (set membership via auxiliary Merkle proof, bitwise operations, timestamp oracle integration) to support the FINRA and KYB scenarios it claims.

**In-threat-model?** Partially — the cryptographic construction survives (PLONK and Poseidon are sound), but the claim of "arbitrary-schema support" (§1, claim statement) is overstated. The construction must either (a) expand the predicate engine to support set membership and bitwise comparators with a revised constraint count, (b) specify a timestamp oracle (with trust model), or (c) retract "arbitrary-schema" and replace with a precise characterization of the expressible predicate class.


## Persona: cryptographer

---

### Attack 1: Subverted Universal SRS — Soundness Collapses Entirely

- **Attack:** The IND-ISS game (§3) states "Challenger generates PLONK CRS" and the threat model explicitly carves out "Does NOT control the proving key." In deployment, however, `pot16.ptau` must be generated by *someone* — a multi-party ceremony, Bolyra, or the NCUA registry operator. An adversary who holds the toxic waste `τ` from the powers-of-tau ceremony can construct a backdoored SRS. Under a subverted SRS, PLONK knowledge soundness breaks unconditionally: the adversary can produce a valid PLONK proof `π` for *any* public input tuple `(issuerRegistryRoot, predicateHash, revocationRoot, sessionNonce, predicateResult=1)` with *no* valid witness whatsoever. Concretely: they can claim membership in an issuer registry for a key that was never enrolled, satisfy the predicate for attributes that don't exist, and pass the revocation non-membership check for a revoked credential.

- **Why the construction doesn't address it:** The IND-ISS game definition and the reduction sketch in §4 both assume an honestly generated CRS. The security argument reduces to `ε_ZK + ε_CR`, neither of which bounds the subverted-setup case. The construction discusses "universal setup, no per-circuit ceremony" as a *feature* (§2.3, Bolyra primitive mapping), but this is an availability benefit, not a security benefit — universality does not eliminate the need to trust the ceremony. The threat model §3 makes no mention of the trusted-setup trust assumption or what happens if it is violated.

- **In-threat-model?** No. The construction must address this — either by (a) specifying a concrete multi-party ceremony with honest-majority assumption and citing a UC-composable security model for the SRS, (b) moving to a transparent setup (STARK-based accumulator, or Halo2/IPA), or (c) explicitly stating "we assume an honestly generated SRS from a ceremony with ≥ 1 honest participant" as a named assumption alongside the other four in §4.

---

### Attack 2: Revocation–Unlinkability Contradiction — One Kills the Other

- **Attack:** The construction asserts two properties simultaneously that are structurally incompatible as specified.

  **Unlinkability claim:** The security argument (§4, step 3) depends on `credentialSalt` being "fresh uniform randomness per proof," making `credentialCommitment = Poseidon4(credentialDigest, Ax, Ay, salt)` computationally unlinkable across sessions.

  **Revocation claim:** Gadget 5 proves non-membership of `credentialCommitment` in a sparse Merkle revocation tree. For an issuer to revoke credential `(credentialDigest, Ax, Ay)`, the issuer must insert the credential's commitment into the revocation tree. But the commitment includes `credentialSalt`, which is a *private input chosen by the prover at proof time*. The issuer who signed the credential at issuance time does not know what salt the prover will choose for future proofs.

  **Consequence:** Either (a) the salt is fixed at issuance time (issuer knows it and can populate the revocation tree), in which case `credentialCommitment` is *stable across sessions* and the cross-session linkage attack the construction claims to defeat is back in play; or (b) the salt is genuinely fresh per proof, in which case the issuer cannot revoke — they cannot construct the Merkle leaf for the revocation tree — and Gadget 5 becomes a no-op.

  A concrete adversary strategy: in scenario (a), `A_AS` collects `credentialCommitment` values across multiple sessions; since the commitment is stable (issuer-time salt), the same `(issuer, credential)` produces the same commitment, breaking unlinkability across sessions despite the construction's claim.

- **In-threat-model?** No. This is a design-level contradiction the construction must resolve — most likely by splitting into (i) a stable *credential identifier* for revocation (e.g., `Poseidon3(credentialDigest, issuerPubkeyAx, issuerPubkeyAy)` using a separate, issuer-known nullifier) and (ii) a per-proof blinded commitment using fresh salt. These serve different purposes and cannot be the same field.

---

### Attack 3: The Reduction Invokes a Non-Existent Assumption (CR ≢ PRF)

- **Attack:** The security argument (§4, step 3) states:

  > *"credentialCommitment is computationally indistinguishable from random **under Poseidon's PRF assumption (a consequence of collision resistance in the ROM)**"*

  This is a formal error. Collision resistance and PRF security are *incomparable* properties:
  - **CR** says: hard to find `(x, x')` with `H(x) = H(x')`.
  - **PRF security** says: for a secret key `k`, `H(k, ·)` is indistinguishable from a random function.

  CR does not imply PRF. A standard counterexample: `H'(x) = H(x) ‖ 0` is CR if `H` is, but immediately leaks a distinguishing bit. The ROM does not close this gap — invoking the ROM gives you a *random oracle*, which has PRF-like properties, but the ROM and the CR assumption are distinct hypotheses. Claiming the PRF property is "a consequence of CR in the ROM" conflates the two.

  The IND-ISS argument actually *needs* the PRF property for the following reason: the adversary in Phase 1 can query proofs for issuer `j_0` and `j_1` and observe their respective `credentialCommitment` values. For a given `(credentialDigest, salt)`, the outputs `Poseidon4(d, Ax_{j_0}, Ay_{j_0}, salt)` and `Poseidon4(d, Ax_{j_1}, Ay_{j_1}, salt)` are *deterministically different*. The only reason these are indistinguishable is that `salt` is hidden. Formalizing *why* hiding the salt makes the commitment indistinguishable from random requires either the ROM (model Poseidon as a random oracle) or an explicit **Poseidon-PRF assumption** (treating `Poseidon4(d, Ax, Ay, ·)` as a PRF keyed on `(d, Ax, Ay)`). Neither is stated in the named assumptions list (§4), and the text misattributes the needed property to a weaker one.

- **In-threat-model?** Yes, the proof intent is correct — but the assumption list (§4) must be extended with "Poseidon is a PRF (or: we work in the ROM modeling Poseidon as a random oracle)" and the reduction step 3 must be rewritten to invoke this assumption explicitly rather than deriving it from CR.

---

### Attack 4: Standard PLONK is HVZK, Not Simulation-Extractable — the Multi-Query Game Requires More

- **Attack:** The construction lists as Assumption 4 (§4): *"Zero-knowledge property of PLONK (simulation extractability): The proof reveals nothing about the witness beyond the public outputs."*

  This conflates two distinct ZK notions:
  - **HVZK (honest-verifier zero-knowledge):** The proof is zero-knowledge when the verifier's randomness (in the interactive protocol, or Fiat-Shamir hash queries in the non-interactive version) is generated honestly. Standard PLONK (KZG-based, Fiat-Shamir) is proven HVZK in the AGM + ROM.
  - **Simulation-extractability (SE-ZK):** Even after seeing polynomially many honestly generated proofs, no adversary can produce a *new* valid proof for a false statement. This is a much stronger property needed for UC composition and for non-malleability in multi-prover settings.

  The IND-ISS game (§3) grants the adversary adaptive proof queries in both Phase 1 and Phase 2 — a multi-oracle setting. For the reduction to work, we need that after seeing `q` proofs for various issuers, the adversary cannot distinguish the challenge proof — i.e., ZK must hold against an adversary who already holds a polynomial number of related proofs. This is precisely the simulation-extractability / non-malleable ZK setting.

  Standard PLONK is **not** known to be simulation-extractable without additional assumptions. Ganesh et al. (CCS 2022) and Baghery et al. show SE-ZK for PLONK requires either the knowledge of exponent assumption (a non-falsifiable assumption) or a modified PLONK construction. The construction's security proof inherits a gap here: it asserts "PLONK ZK (simulation extractability)" as though this is a standard result, but it is not — it requires separate justification or an explicit assumption that was not named.

  Concretely, a malicious verifier `A_RS` who makes `q = poly(λ)` adaptive queries in Phase 1 and receives proofs `π_1, …, π_q` might be able to construct a *malleable* proof from the oracle's transcripts that links the challenge's `credentialCommitment` to a specific issuer's Phase 1 observations, breaking the reduction's indistinguishability step.

- **In-threat-model?** No. The construction must either (a) explicitly add "PLONK is simulation-extractable under [named assumption]" as a separate, named assumption with a citation (e.g., Fuchsbauer–Kiltz–Loss 2018 for simulation-extractability of Fiat-Shamir SNARKs, or the PLONK-specific SE result); or (b) restrict the adversary's Phase 1/Phase 2 queries so that the standard HVZK property suffices — which would require disallowing adaptive queries and substantially weakening the game.


## Persona: cu_ciso

### Attack 1: AS-Blind Hiding Is a BSA/AML Violation, Not a Feature

- **Attack:** Section 7 (Concrete Deployment Scenario) explicitly states that "the verifier learns nothing else — not which credit union." The construction markets AS-blind issuer hiding as its strictly novel property. But 31 U.S.C. §5318(g) and FinCEN's SAR filing requirements obligate the receiving CU to identify counterparties in financial transactions. If PenFed's AI loan origination agent is interacting with my CU's systems and I cryptographically *cannot* determine which institution I'm transacting with, I cannot file an accurate SAR. NCUA Part 748 Appendix A (GLBA Safeguards, Guideline III.C) requires the institution to "identify reasonably foreseeable internal and external threats" — you cannot identify a threat from a counterparty you've been cryptographically blinded to. The construction's core differentiator — the very property it claims RFC 7662 cannot achieve — directly conflicts with regulatory due diligence requirements. FFIEC BSA/AML Examination Manual §4 (Customer Due Diligence) requires CDD on beneficial owners for institutional counterparties. "An NCUA-chartered CU, but we can't say which one" fails this control.

- **Why it works:** The construction provides no carve-out, no secondary channel, no regulatory disclosure mode. The gap between "cryptographically blind to issuer" and "regulatorily obligated to know issuer" is unaddressed. The construction assumes the verifier *wants* issuer anonymity; in a regulated CU-to-CU transaction, that anonymity is a liability.

- **In-threat-model?** No — construction must address. A conformance mode or "selective de-anonymization for BSA purposes" disclosure path is needed, with a clear statement of which regulatory obligations require issuer disclosure and how the construction accommodates them without collapsing the IND-ISS guarantee.

---

### Attack 2: The NCUA EdDSA Key Registry Is a Non-Existent Third Party with Zero Vendor Management Story

- **Attack:** Section 7 states "the NCUA publishes an issuer registry Merkle tree containing the EdDSA public keys of all 4,600+ federally insured credit unions." NCUA has no such infrastructure. It does not operate an EdDSA PKI. It does not publish on-chain data. This is not a minor implementation detail — it is a load-bearing assumption. From my vendor management policy and NCUA 12 CFR Part 741 / Letter to Credit Unions 01-CU-20 (third-party relationships), I am required to vet *every* third party that touches financial transactions. The construction requires me to trust: (1) whoever stands up and operates this NCUA Merkle registry, (2) the on-chain settlement layer for root publication, (3) the quarterly update cadence, and (4) NCUA's EdDSA key management hygiene. None of these vendors exist, have SOC 2 reports, or appear in my Vendor Management Policy. The `issuerRegistryRoot` is a public input to every proof — if NCUA's signing key is compromised, every proof against that root is suspect, and I have no recourse because NCUA is not my vendor, I did not perform due diligence on them, and I cannot contractually compel an SLA.

- **Why it works:** The construction treats "NCUA publishes a root quarterly" as a deployment detail. From a regulatory risk posture, it is a critical vendor dependency with no governance model, no contract, no business continuity clause, and no examiner-facing audit artifact. My NCUA examiner will ask: "Who manages the issuer registry? What is their SOC 2 Type II? What is the contingency if the registry is unavailable or corrupted?" The construction has no answer.

- **In-threat-model?** No — construction must address. A governance model for the issuer registry operator (whether NCUA, a CUSO, or a neutral third party) is required, including: who controls key rotation, what happens during a registry outage, how CUs are enrolled and removed, and what the examiner-facing evidence package looks like.

---

### Attack 3: Revocation Is a Governance Black Hole with No 2am Story

- **Attack:** Section 2 (Gadget 5) specifies a sparse Merkle revocation tree with a `revocationRoot` public input. The construction does not specify: who updates this tree, on what SLA, via what access control, with what on-call escalation path. The deployment scenario says the issuer registry is "updated quarterly" — but revocation must be near-real-time. If my AI loan agent's credential is stolen at 11pm on a Friday and is being used to initiate fraudulent loan applications against partner CUs, I need that credential revoked *now*. NCUA Part 748, Appendix B §III.D.4 requires incident response procedures to "contain and control the incident." If revocation requires a Merkle tree update and an on-chain transaction from a key held by some registry operator, my Tier 1 ops team at 2am is calling a number that goes to no one. Section 5 maps revocation to "Sparse Merkle Tree with Poseidon2, depth 20 — extends existing tree infrastructure." Who has write access to this tree? What is the key custody model for the registry update key? If that key requires a hardware HSM and a two-person rule (standard for financial key management), the 2am revocation window could stretch to hours. Meanwhile, proofs against a stale `revocationRoot` are still valid.

- **Why it works:** The construction proves non-revocation against whatever `revocationRoot` is passed as a public input. If the root is stale because no one updated the tree, a revoked credential produces a valid proof. The construction's security argument assumes the `revocationRoot` is current — but the operational model for keeping it current under incident conditions is entirely absent.

- **In-threat-model?** No — construction must address. An SLA commitment for revocation propagation, an access control model for the revocation tree update key, and an incident response playbook (who calls whom at 2am, what is the maximum window between credential compromise and valid-proof rejection) are required for any regulated deployment.

---

### Attack 4: The Audit Trail Is a Black Box — My SOC 2 Auditor and NCUA Examiner Will Reject It

- **Attack:** Section 8 (Gap 6) argues that AS-blind hiding is superior because "no party in the protocol — not the verifier, not the relay, not the registry operator, not the on-chain indexer — ever possesses the issuer identity in cleartext." To my NCUA examiner and my SOC 2 Type II auditor, this is the problem statement, not the solution. SOC 2 Trust Service Criteria CC6.1 requires "logical access controls" and an evidence trail showing *which* principals performed *which* operations. My auditor will ask for a sample of AI agent transactions and want to trace each one to an authenticated, identified counterparty. The construction's output is: `predicateResult = 1`, `credentialCommitment` (opaque hash), `blindNullifier` (opaque hash). There is no human-readable, examiner-legible record that maps a transaction to a counterparty institution. FFIEC CAT Domain 1 (Cyber Risk Management and Oversight) requires the board to understand and approve the risk associated with third-party relationships. My board narrative is: "We allow AI agents from unidentified NCUA-chartered institutions to transact with us, and by cryptographic design we cannot tell you which institutions." That narrative does not pass a board risk committee or an NCUA exam.

- **Why it works:** The construction provides cryptographic assurance that the counterparty is NCUA-chartered. It provides zero operational infrastructure for regulatory record-keeping, examiner-facing audit artifact generation, or board-level risk reporting. The `credentialCommitment` and `blindNullifier` are not interpretable by compliance staff, cannot be cross-referenced against NCUA's charter database, and produce no BSA-compliant transaction record.

- **In-threat-model?** No — construction must address. A regulatory disclosure layer is required: either (a) a conformance mode where the issuer identity is escrowed to a designated regulatory intermediary (e.g., a CUSO acting as a regulated custodian) accessible under subpoena but not in normal protocol flow, or (b) explicit documentation of which transaction types are out of scope for this construction because regulatory record-keeping requirements override the issuer-hiding property.


## Persona: rfc7662_advocate

I've shipped token introspection for Ping Identity, ForgeRock, and two CUSO deployments. Every time someone shows me a ZK credential system, the first question is: *does the property you're proving actually matter for the problem you claim to solve?* Let's find out.

---

### Attack 1: Schema-Predicate Correlation Collapses the Anonymity Set Before the Proof Is Even Verified

**Attack:** The `predicateHash` is a public input encoding `(attrIndex, comparator, threshold)` per clause (§2, Gadget 4). Attribute indices are not random — they map to a schema. In any standards-based deployment (W3C VC Data Model 2.0, IETF SD-JWT, or a sector schema like the NCUA's planned machine-readable charter data format), schemas are public documents. The mapping `attrIndex=1 → chartered_by_NCUA` is published. A verifier who knows the issuer registry (§3, Class 1 adversary: "knows the full issuer registry") also knows which issuers use which schema version, because schema adoption is observable from public issuer metadata.

So: `predicateHash` leaks the schema (via the attrIndex vector), and schema version correlates with issuer type, issuer generation, or issuer category. If only 312 of 4,600 NCUA-registered CUs have adopted the v2 schema that places `chartered_by_NCUA` at `attrIndex=1`, the anonymity set is not 4,600 — it is 312. The IND-ISS game (§3) is defined over the full registry but the practical anonymity set is the intersection of (issuers in registry) ∩ (issuers whose schema produces this `predicateHash`). The construction never bounds this intersection.

**Why it works against the construction:** The reduction sketch (§4) assumes `predicateHash` is "identical across both issuers by construction" (step 5). This is only true if both challenge issuers share the same `attrIndex` assignment for the predicate attribute — i.e., the same schema. The game setup (§3, step 3) says the adversary selects `attrs*` satisfying φ under both issuers, but does not require the two issuers to share the same schema. If `j_0` uses `attrIndex=1` for `chartered_by_NCUA` and `j_1` uses `attrIndex=4`, they produce *different* `predicateHash` values — meaning they are trivially distinguishable without breaking any cryptographic assumption. The construction is only IND-ISS secure under the implicit assumption of a universal standardized schema, which is never stated as a requirement and is empirically false in current VC ecosystems.

**RFC 7662 comparison:** Per-RS filtered introspection returns a policy-evaluated boolean. The AS evaluates `chartered_by_NCUA == true` against the credential record using whatever internal field name the issuer uses — the verifier receives only `"authorized": true` with no structural signal about schema version, attribute index, or clause layout.

**In-threat-model?** No — the construction must address this. Either (a) require a universal canonical schema as a named assumption, (b) redefine the IND-ISS game to require both challenge issuers to share the same `predicateHash`, explicitly acknowledging the narrowed anonymity bound, or (c) argue that schema diversity is negligible in the target sector and bound the anonymity set reduction.

---

### Attack 2: AS-Blind Hiding Is a Regulatory Non-Starter in All Three Named Deployment Scenarios

**Attack:** The entire differentiation argument for IssuerBlindPredicate rests on Property 2 (§3): AS-blind issuer hiding — "no party in the protocol ever possesses the issuer identity in cleartext." This is presented as the property that RFC 7662 cannot match, and the construction explicitly names its deployment scenarios as NCUA-regulated credit unions, FINRA-licensed agents, and KYB-verified entities across jurisdictions.

Every single named scenario is in a regulatory environment that legally *requires* a responsible party to possess issuer identity:

- **NCUA:** 12 U.S.C. § 1784 grants NCUA examination authority over federally chartered CUs. NCUA Letter to Credit Unions 22-CU-03 (guidance on third-party vendor oversight) requires that AI agent activity be attributable to a specific CU for examination purposes. A system where NCUA itself cannot determine which CU's agent is transacting is not a compliance feature — it is an examination obstruction.
- **FINRA:** FINRA Rule 4511 (Books and Records) requires broker-dealers to maintain records sufficient for regulatory examination. An issuer-blind agent credential means the issuer (broker-dealer) cannot be identified from a transaction record, which violates Rule 4511 by design.
- **KYB / AML:** FinCEN's BSA/AML regulations (31 U.S.C. § 5318) require financial institutions to maintain records linking transactions to identified parties. FATF Recommendation 16 (wire transfer rules) requires originator identification that survives the transaction. A KYB proof where "jurisdiction must stay hidden" (§7, Extension) is not a compliance tool — it is an AML evasion mechanism under FATF standards.

**Why it works against the construction:** Section 7 presents the PenFed NCUA scenario and explicitly states that "the NCUA learns real-time transaction patterns of individual credit unions" is a problem the construction solves. But in the regulatory context, NCUA *should* have this supervisory visibility — that is its statutory mandate. The construction solves a problem (regulatory surveillance) that is not a problem to solve in a compliance context; it is a requirement.

RFC 7662 with an NCUA-operated AS provides exactly the right accountability architecture: the AS (NCUA) has full visibility for supervisory purposes; the RS (partner CU) sees only the filtered authorization decision. This is a feature of RFC 7662, not a limitation.

**In-threat-model?** No — the construction must address this. Either (a) drop or substantially reframe the NCUA/FINRA/KYB deployment scenarios, restricting to contexts where regulatory accountability is not required, (b) introduce a regulatory escrow mechanism (a designated party who can de-anonymize under lawful order) and prove this does not undermine the AS-blind hiding claim, or (c) explicitly characterize the target deployment as one that operates *outside* regulated financial activity (which contradicts the stated scenarios entirely).

---

### Attack 3: RFC 9449 DPoP + OIDC PPID Achieves the Practical RS-Level Goal; the Construction Never Proves AS-Blind Hiding Is Required

**Attack:** Section 8 (Gap 6) argues that RFC 7662 filtered introspection achieves only RS-blind hiding (trust-based, AS policy), while IssuerBlindPredicate achieves AS-blind hiding (cryptographic). This is accurate. But the construction never establishes that AS-blind hiding is *necessary* for any of its three deployment scenarios. The attack is: the composition RFC 9449 DPoP + OIDC pairwise pseudonymous identifiers (PPIDs) + RFC 7662 per-RS filtered introspection achieves every practical security goal the construction claims, without ZK.

Concretely:
- **RFC 9449 DPoP** binds the access token to the agent's proof-of-possession key (`dpop_jkt`), preventing token theft and providing sender-constraint — directly analogous to the `blindNullifier` replay prevention (§2, Gadget 6), but without a proof system.
- **OIDC PPIDs** (OIDC Core §8.1, RFC 8176) give each RS a different pseudonymous subject identifier derived from `Pairwise(issuer, sector_identifier)`. Two RSs cannot correlate the same agent across verifiers — directly analogous to the cross-session unlinkability claim in §4 step 4.
- **RFC 7662 per-RS filtered introspection** strips `iss`, `client_id`, and any issuer-correlated fields before returning to the RS. This is AS policy (§8 Gap 6 acknowledges this), but in the claimed deployment scenarios, the AS is the regulatory authority (NCUA), and that authority is *trusted by design* — the RS (partner CU) is choosing to federate with NCUA's AS.

After DPoP + PPID + filtered introspection: the RS (verifier) sees only an authorized predicate result, a sender-constrained token, and a per-RS pseudonym. The residual gap is the AS-blind property. The construction must demonstrate a concrete attack scenario where an adversary who can compromise the AS (but not the prover's private inputs) causes a practical security failure in the NCUA/FINRA/KYB context. Section 3 defines `A_AS` as "honest-but-curious" — meaning the AS follows the protocol. An honest AS with per-RS filtering already provides the RS-level property. The IND-ISS game never models a *malicious* AS who actively leaks issuer identity; it models one who passively observes. In the named scenarios, active AS compromise requires compromise of the regulatory authority itself (NCUA, FINRA, FinCEN), which is outside the threat model for any deployed financial system.

**In-threat-model?** Partially. The construction should add a concrete adversarial scenario where an honest-but-curious AS's passive observation leads to a measurable harm (e.g., discrimination, competitive disadvantage, targeted examination) that would not occur with DPoP + PPID. Without this, the AS-blind property is a theoretical improvement that has no corresponding practical attack it defeats — and it carries the regulatory cost identified in Attack 2.

---

### Attack 4: The "Arbitrary Boolean Expression" Claim Is a Fixed 8-Clause Bounded Template, Not Arbitrary

**Attack:** Section 8 (Gap 3) claims: "IssuerBlindPredicate circuit compiles *any* Boolean expression over up to 8 clauses into the same circuit." Section 2 (Gadget 4) defines the predicate language: up to 8 clauses, each of form `(attrIndex, comparator, threshold)` with `comparator ∈ {EQ, NEQ, LT, GT, LTE, GTE}`, combined with "a 3-level Boolean tree." This is not an arbitrary Boolean expression engine — it is a fixed schema with hard-coded limits:

1. **Maximum 8 clauses.** Real compliance predicates often require more: FINRA Rule 4370 (Business Continuity) involves 14+ distinct conditions; KYC/AML typology rules (FinCEN FIN-2020-A001) involve branching logic exceeding 8 conditions.
2. **Only atomic comparisons.** The predicate language cannot express: computed attributes (`age = current_year - birth_year`), multi-field aggregations (`net_assets = total_assets - total_liabilities`), or cross-credential joins (`credential_A.issuer_tier == credential_B.requester_tier`).
3. **Only 3 levels of Boolean nesting.** Three levels of AND/OR/NOT support 8 leaf conditions, but regulatory predicates with nested exception clauses (e.g., OFAC sanctions screening with jurisdiction exceptions) routinely exceed this depth.
4. **Static thresholds.** `threshold` is a circuit-compile-time constant embedded in `predicateHash`. If a regulatory threshold changes (e.g., NCUA raises the "large CU" asset threshold from $10B to $15B), the `predicateHash` changes, requiring all holders to re-obtain proofs against the new predicate. RFC 7662 AS-side policy is a program that can be updated without credential reissuance.

The claim "supports arbitrary-schema support" (from the C4 candidate metadata) directly contradicts the circuit's actual capability. RFC 7662 with AS-side policy evaluation is genuinely arbitrary: the AS can execute any program (SQL, Python, ML model) against the full credential record, with no constraint count limit, no clause limit, and no nesting limit.

**Why it works against the construction:** The comparison table (§8, Summary) claims "Yes (8-clause template, single circuit)" against "Arbitrary Boolean predicates." This characterization is misleading. The construction should either (a) accurately describe the predicate language as "bounded 8-clause template with 3-level Boolean tree" and acknowledge that complex predicates require multiple proof compositions or a different predicate compilation approach, or (b) extend the circuit to support a richer predicate IR (e.g., a simple bytecode VM with a larger constraint budget) and benchmark whether it stays within `pot16.ptau` at `2^16` constraints.

**In-threat-model?** No — the construction must address this. The "Gap 3" argument in §8 claims BBS+ cannot handle the NCUA example predicate `(chartered_by_NCUA == 1) AND (enforcement_actions == 0) AND (total_assets_tier >= 3)`. This is a 3-clause predicate — well within both the circuit limit and BBS+ range-proof composition. The argument does not demonstrate a predicate that the construction handles and BBS+ cannot; it demonstrates a predicate both handle. A genuine gap argument requires a predicate that exceeds the composition capabilities of BBS+ while remaining within the 8-clause limit of IssuerBlindPredicate — and that boundary has not been drawn.


## Persona: spiffe_engineer

---

### Attack 1: SPIFFE Trust-Domain Federation Already Gives You RS-Blind Issuer Hiding — So What Are You Proving?

**Attack:**
A SPIFFE trust-domain federation bundle aggregates multiple sub-authority CA certificates under a single federation root. When a JWT-SVID from `spiffe://penfed.example/loan-agent` is presented to a verifier that only trusts the NCUA federation root, the verifier validates the SVID against the root bundle — it sees a valid credential from *some* NCUA-federated member, not specifically PenFed. In a properly scoped federation (NCUA operates the bundle endpoint, members enroll sub-CAs), the RS never sees the originating trust domain. You get RS-blind issuer hiding out of SPIFFE federation, for free, using mTLS and X.509 SVIDs.

**Why it works / fails:**
The attack is valid against the RS-blind hiding property (§3, Property 1) and the comparison row "RS-blind issuer hiding" in §8's summary table. The construction admits RFC 7662 filtered introspection achieves RS-blind hiding; SPIFFE federation achieves the same thing at the TLS layer without any ZK machinery, and arguably with stronger operational tooling (rotation, SPIRE attestation plugins, audit logs).

The attack *fails* on the construction's core novel claim: **AS-blind issuer hiding** (§3, Property 2). SPIFFE federation requires a bundle endpoint operated by the federation authority (here, the NCUA). That bundle operator necessarily knows which sub-CA (which member CU) issued the SVID — the full chain is in its bundle store. An honest-but-curious NCUA bundle operator watching SVID verification events has exactly the `A_AS` view the construction defines: it knows which issuer is transacting with which verifier, at what frequency. The ZK construction eliminates this structural advantage; SPIFFE federation cannot.

**In-threat-model?** Partially. The RS-blind argument is in-threat-model and the construction survives it via §8 Gap 6. However, the construction's comparative table should *explicitly name SPIFFE federation* as the mechanism achieving RS-blind hiding via mTLS, not just RFC 7662 — otherwise the "cryptographic vs. trust-based" framing undersells how mature the SPIFFE alternative is. The construction currently only cites RFC 7662; omitting SPIFFE federation makes §8 look like it is fighting the weakest version of the baseline. **Verdict: construction survives but should strengthen §8's comparative analysis to name SPIFFE federation directly.**

---

### Attack 2: Your "Arbitrary Boolean Expressions" Claim Contradicts Your Circuit

**Attack:**
Section 8, Gap 3 states: "It cannot evaluate *arbitrary Boolean expressions* like `(chartered_by_NCUA == 1) AND (enforcement_actions == 0) AND (total_assets_tier >= 3)` in a single atomic proof." Then the construction presents this as something its own circuit *does* support. But Section 2's predicate evaluation engine defines a rigid fixed-width template: **up to 8 clauses × up to 3 levels of AND/OR/NOT**. A SPIFFE engineer deploying real-world attribute policies immediately asks for:

```
(chartered_by_NCUA == 1)
AND (
  (enforcement_actions_federal == 0)
  OR (enforcement_waiver == 1 AND waiver_jurisdiction IN {CA, NY, TX})
)
AND (total_assets_tier >= 3 OR charter_type == "federal")
```

This expression has a 4-level Boolean tree and requires set-membership (`IN`) as a comparator not listed in the circuit's `comparator ∈ {EQ, NEQ, LT, GT, LTE, GTE}` enum. It exceeds the template. The only options are: (a) split into multiple IssuerBlindPredicate proofs and compose them — which breaks the single-proof constant-size claim; or (b) recompile the circuit with a larger template — which requires a new ceremony-equivalent setup step for the predicate engine itself, contradicting "no per-schema circuit work."

The claim "arbitrary Boolean expressions" is not true; the claim "arbitrary Boolean expressions over up to 8 clauses using the listed comparators with a 3-level combination tree" is true. These are very different claims, and the gap matters operationally — SPIFFE/OPA attribute policies routinely exceed 8 clauses.

**Why it works:**
This is a direct internal contradiction between §2 (circuit specification) and §8 Gap 3 (baseline comparison). The baseline comparison attacks BBS+ for requiring "a separate composition layer… with distinct setup and proof-size overhead" for new predicates — but the same critique applies to the construction when the predicate exceeds the 8-clause template. The construction cannot simultaneously claim "arbitrary" expressiveness and define a fixed-width template.

**In-threat-model?** No. The construction must either (a) rename the claim to "bounded-complexity Boolean expressions" and define the exact expressive boundary in §2, or (b) extend the predicate engine to a universal circuit (e.g., a ZK-EVM-style predicate VM) and account for the constraint overhead and setup implications. **This is an unclosed gap.**

---

### Attack 3: You Have Credential Revocation But No Issuer Key Revocation — SPIRE Doesn't Have This Problem

**Attack:**
SPIRE issues short-lived SVIDs (default TTL: 1 hour, configurable to minutes). Issuer key compromise is handled by rotating the CA in the SPIRE server; all existing SVIDs expire within their TTL, new SVIDs are issued from the new key, and the window of exposure is bounded by the SVID lifetime — which can be as short as the deployment requires.

The IssuerBlindPredicate construction has two revocation mechanisms:

1. **Credential revocation** — Gadget 5, sparse Merkle non-membership against `revocationRoot`. Works well.
2. **Issuer key revocation** — **absent**.

The deployment scenario (§7) states the NCUA registry is "updated quarterly." If an issuer's EdDSA signing key is compromised:

- The NCUA must update `issuerRegistryRoot` on-chain (removing the compromised leaf)
- Until that update lands, any attacker holding the compromised key can generate valid IssuerBlindPredicate proofs — and these proofs will verify against the stale `issuerRegistryRoot` used by verifiers who haven't refreshed
- The construction's `credentialSalt` ensures unlinkability across sessions, but it also means there is *no way to retroactively revoke* a proof generated with a valid-at-time-of-generation `issuerRegistryRoot`. The `blindNullifier` prevents replay but not fresh forgeries from a compromised key.

A quarterly registry update window is a 90-day key-compromise exposure window for any credential issued by the compromised member. In SPIFFE, this window is the SVID TTL (hours). In the construction, it is the registry update cadence (months).

The construction's §3 threat model defines two adversary classes — malicious verifier and honest-but-curious intermediary — but does not model a **malicious issuer with a compromised key**. The IND-ISS game (§3) assumes the challenger's issuer keys are honest; it does not address an adversary `A_KEY` who obtains a leaf key from the registry.

**Why it works:**
The construction's security argument in §4 establishes soundness: "a valid proof implies the prover knows an issuer key that is a leaf in the registry." If the adversary *is* the issuer (or has obtained the issuer's key), all soundness properties hold — the proof is valid, and no mechanism in the construction can distinguish a legitimate from an illegitimate use of a live registry leaf. The revocation tree (Gadget 5) covers credential-level revocation (a specific `credentialCommitment`), not key-level revocation. Removing the compromised issuer from the tree requires an on-chain registry update.

**In-threat-model?** No. The IND-ISS game does not model key compromise. The construction should either (a) bound the issuer-key revocation latency explicitly (and not describe quarterly updates as acceptable for high-stakes deployments), or (b) add an **issuer key revocation tree** as a second non-membership gadget, proving the issuer key is *not* revoked at the time of proof generation. This is a genuine gap that would exist in production NCUA deployments. **This is an unclosed gap.**

---

### Attack 4: WIMSE Already Has a Slot for This — Why Are You Not Contributing There?

**Attack:**
`draft-ietf-wimse-arch` (WIMSE, Workload Identity in Multi-System Environments) defines a layered architecture for workload identity token exchange, including:

- Section 5: Workload-to-workload authentication with token binding
- Section 6: Selective disclosure of workload attributes in the token exchange flow
- Section 7: Cross-domain federation with explicit trust anchor management

The WIMSE WG explicitly has open issues on ZK-based attestation extensions. The correct engineering move is: propose an **IssuerBlindAttestation** extension to the WIMSE token exchange format — specifically, replace the JWT-based credential assertion with a PLONK proof over the same credential schema. This would give you all of C4's properties inside an IETF-standardized wire format that already has adoption in major cloud providers (AWS ROLESANYWHERE, GCP Workload Identity Federation, Spiffe-aware service meshes).

The construction instead defines a new `IssuerBlindPredicate` circuit, a new `predicateHash` public signal, a new `credentialCommitment` format, a new `blindNullifier` scheme — none of which is interoperable with any deployed WIMSE, SPIFFE, or OAuth 2.0 infrastructure. Every new verifier must integrate `bolyra/spec/` rather than dropping in a PLONK verifier module into an existing WIMSE-compliant AS.

**Why it works / fails:**
This is primarily an *ecosystem* and *standardization* attack, not a cryptographic one — the construction's security properties are not broken. The legitimate technical kernel is: the construction's §5 (Bolyra primitive mapping) and §7 (deployment scenario) assume a greenfield deployment where the NCUA operates a Bolyra-native issuer registry and all verifiers integrate the Bolyra spec. In practice, PenFed's counterparties are running SPIRE or cloud-managed workload identity — the "constant-size 768-byte PLONK proof" has zero value if the verifier's identity middleware cannot accept it.

The attack *fails* as a cryptographic critique: the IND-ISS game and the AS-blind hiding property are genuine contributions that WIMSE's current architecture cannot provide (WIMSE's AS still sees the issuer). The construction is right that no existing WIMSE extension achieves AS-blind hiding. But the attack surfaces a real deployment gap: the construction's §7 deployment scenario assumes infrastructure that does not exist and must be built from scratch by the NCUA.

**In-threat-model?** Yes — the construction survives the core cryptographic claim. However, the gap to close (stated in the candidate's `gap_to_close` field) does not include an interoperability argument with WIMSE/SPIFFE. The construction reaching **strength 10** requires explicitly addressing why a WIMSE ZK extension (contributed upstream) would not achieve the same properties, or providing a WIMSE-compatible wire format for `IssuerBlindPredicate` proofs. A standalone protocol that cannot interoperate with deployed SPIFFE infrastructure will see zero adoption in the credit union sector, regardless of its cryptographic superiority. **Verdict: survives cryptographically, but the strength ceiling is limited by deployment architecture unless WIMSE interop is addressed.**
