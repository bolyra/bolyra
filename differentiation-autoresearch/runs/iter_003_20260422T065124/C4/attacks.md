# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: The Proof-Latency SLA Killer

- **Attack:** The construction benchmarks ~42K PLONK constraints but never states wall-clock proving time on member hardware (a $300 Chromebook at a credit union teller). Auth0/WorkOS MCP auth issues a signed JWT in <100ms over a TLS round-trip. At the CO-OP Shared Branch deployment scenario (§ "Deployment scenario"), a member walks up to a Navy Federal teller and must wait while their device runs the IssuerBlindPredicate circuit. Even at a generous 2–3s on mobile, tellers will override to manual ID check after the third queue backup. No operator accepts that tradeoff without a concrete SLA commitment backed by hardware benchmarks on the actual endpoint devices credit unions deploy.
- **Why it works / fails:** The construction provides no benchmark on end-user hardware, only a constraint count. The "constant-size proof" claim addresses *verifier* time (fast), not *prover* time (slow). This is a real gap the construction must address with numbers, not cryptographic claims.
- **In-threat-model?** No — construction must address with concrete prover benchmarks on representative hardware and a mitigation path (e.g., server-side proving with a trusted enclave, pre-computed proof tokens).

---

### Attack 2: The Issuer Registry Centralization Trap

- **Attack:** The IND-ISS game (§ "IND-ISS game") hides which issuer signed by treating the issuer key as a private witness committed to a Merkle tree. But the Merkle tree root is a public parameter. *Someone* must maintain the canonical tree of valid NCUA-chartered issuers. If that's Bolyra (solo founder, no SOC 2, no 99.9% SLA), then every relying party's proof validity depends on your uptime. If you go dark, Navy Federal cannot verify any member credential — not degraded, *broken*. WorkOS has enterprise SLAs, a 24/7 ops team, and contractual liability. When the procurement team at a $10B credit union asks "what happens if your issuer registry goes stale or you get acquired," the construction has no answer. A decentralized registry (on-chain) trades the latency problem for a gas/finality problem. Neither is addressed.
- **Why it works / fails:** The construction describes the cryptographic structure of the Merkle tree but is silent on governance, update cadence, and availability guarantees. The IND-ISS security reduction assumes the tree is correct and current — it says nothing about who ensures that.
- **In-threat-model?** No — construction must specify issuer registry governance (who can add/remove issuers, at what latency, with what availability guarantee).

---

### Attack 3: The BSA/AML Auditability Paradox

- **Attack:** The IND-ISS game's core property — the verifier *cannot* learn which issuer signed — is the exact property that triggers a Bank Secrecy Act red flag. Under 31 U.S.C. § 5318(h) and FinCEN's CDD rule, a covered financial institution accepting a member credential must be able to document the source of that credential for examination. When a Navy Federal BSA officer asks "who issued this NCUA membership proof," the legally correct answer under Bolyra is "unknowable by design." That is not a feature to a compliance officer; it is a finding. Auth0 and WorkOS issue credentials with full issuer provenance visible to the relying party — exactly what regulators require. The construction's § "cross-CU NCUA membership proof" scenario is the highest-risk scenario for this attack: two federally regulated institutions, BSA obligations on both sides, and Bolyra's core privacy guarantee is structurally incompatible with examiner auditability.
- **Why it works / fails:** The construction argues issuer-hiding is the value proposition. It does not address selective disclosure to regulators or a compliance carve-out (e.g., a regulator-accessible audit log). Without this, the construction is self-disqualifying in its own target market.
- **In-threat-model?** No — this is a category blocker. The construction must specify a compliance mode: either a selective-reveal escape hatch for regulators, or a legal argument that issuer-hiding satisfies BSA (which would require outside counsel opinion, not a cryptographic proof).

---

### Attack 4: The "32-Gate Boolean Evaluator" Is Not Arbitrary Schema

- **Attack:** The construction claims "arbitrary-schema support" via a "32-gate Boolean predicate evaluator over hidden attributes." But the FINRA-licensed agent scenario (§ "cross-firm regulated-professional proof") requires predicates like: `license_type IN ["Series 7", "Series 63"] AND expiry_date > 2026-04-22 AND NOT suspended`. That requires string set membership, date arithmetic, and negation — none of which are naturally 32-gate Boolean gates over field elements. A fixed-gate Boolean evaluator is a *fixed-depth propositional circuit*, not arbitrary-schema support. The gap between "Boolean gates over pre-committed field encodings" and "real enterprise credential schema predicates" is exactly where BBS+ selective disclosure (which Bolyra dismisses) is actually competitive: BBS+ handles arbitrary attribute selection natively without a circuit rewrite per schema. The construction's "4 structural impossibilities" argument against BBS+ (§ "Why BBS+ cannot match") does not address this: the question is not whether BBS+ is weaker on IND-ISS, but whether Bolyra's circuit is *expressive enough* to replace it in practice without a new circuit compilation per credential schema.
- **Why it works / fails:** The construction conflates "constant-size proof" with "arbitrary predicate expressiveness." These are orthogonal properties. The 32-gate evaluator is a concrete expressiveness ceiling the construction must either raise (with a general-purpose predicate compiler) or honestly scope (listing what predicate classes are and are not supported).
- **In-threat-model?** No — construction must either provide a predicate compiler that maps real schema predicates (dates, strings, set membership) to circuit gates, or explicitly bound the supported predicate language and acknowledge that enterprise schemas outside that bound require schema-specific circuit compilation.


## Persona: cryptographer

> *"Unless I see a threat model, a game definition, and a reduction sketch, it's marketing."*

---

### Attack 1: Attribute-Issuer Correlation — IND-ISS Does Not Cover Semantic Leakage

**Attack:** The IND-ISS game as stated hides the *issuer key* — it asks whether the adversary can distinguish which of two issuers `(ISS₀, ISS₁)` signed the credential, given a proof. Fine. But the **attribute values themselves** are inputs to the Boolean predicate evaluator and may be partially revealed or statistically correlated with the issuer.

Concretely: Mountain America (Utah, ~1M members) and Navy Federal (Virginia, federal employees) both issue `chartered_by_NCUA == true`. But Mountain America never issues `employer_type = DOD`, and Navy Federal issues it on ~40% of credentials. A predicate that touches `employer_type` leaks the issuer distribution even when the key is perfectly hidden. More sharply: if the predicate circuit exposes *which gates fired* via the proof's witness commitments, an auxiliary-input adversary with issuer attribute statistics wins IND-ISS with non-negligible advantage that scales with the KL divergence between the two issuers' attribute distributions.

**Why it works:** The IND-ISS game defined in Section A4 conditions only on the circuit output (`predicate = 1`) and the PLONK proof, not on the marginal distribution of witness values seen by a computationally bounded adversary with side information. The reduction "IND-ISS from PLONK ZK" only guarantees zero-knowledge of the *witness transcript*, not semantic unlinkability of the attribute vector to real-world issuer populations.

**In-threat-model?** No. The construction must extend IND-ISS to a **distributional* variant: the adversary chooses two issuers *and* a challenge attribute vector drawn from each issuer's realistic distribution, and the game must account for leakage via the predicate's satisfying instantiation. Without this, the CO-OP Shared Branch deployment scenario (Section 6) is not covered.

---

### Attack 2: Subverted SRS Collapses the Reduction

**Attack:** The security reduction is: IND-ISS ← PLONK zero-knowledge. PLONK's ZK property is stated relative to an *honestly generated* universal SRS. The construction does not specify the SRS ceremony used, the number of participants, or what happens if the discrete-log of the SRS toxic waste `τ` is known to a single colluding party.

If `τ` is known, the PLONK prover's witness polynomial evaluations are algebraically invertible — the extractor in the knowledge-soundness proof becomes an *actual* extractor for any verifier who also knows `τ`. Concretely: an adversary who participated in (or corrupted) the setup ceremony can, given a proof π, recover the private witness `isk` (the issuer key) from the commitment `[W(τ)]₁`. IND-ISS breaks completely and unconditionally.

The construction claims "UNF-CRED from knowledge soundness + Poseidon CR + DLP on Baby Jubjub." This chain is only as strong as the DLP assumption *and* the SRS honesty assumption. The second is not listed as an explicit assumption anywhere in the security statement as described.

**Why it works:** PLONK does not have a transparent setup. The reduction silently inherits an assumption — SRS honesty — that is not formalized in the security game and cannot be reduced to a standard hardness assumption. This is the exact pitfall that distinguishes STARK-based constructions (transparent) from SNARK-based ones.

**In-threat-model?** No. The construction must either (a) specify a verifiable MPC ceremony with `n ≥ 1` honest participant sufficiency and prove security under `t < n` corruption, or (b) substitute a transparent proof system (FRI-based STARK, or Halo2 with IPA) and re-derive the IND-ISS reduction. The issuer-blinding argument does not survive a corrupted SRS.

---

### Attack 3: Under-Constrained Boolean Predicate Evaluator — Completeness Failure Enables Credential Forgery

**Attack:** The construction specifies a "32-gate Boolean predicate evaluator over hidden attributes." A fixed-gate-count evaluator for *arbitrary* Boolean expressions has a hard boundary: any expression requiring more than 32 gates either (a) cannot be encoded (completeness failure — honest provers cannot prove true statements) or (b) must be truncated/padded in a way the circuit description does not specify.

More critically: if the gate evaluator is implemented as a lookup-table or conditional-select gadget over the attribute vector, each gate must be *range-checked and boolean-constrained* independently. A PLONK circuit with under-constrained intermediate wires allows a malicious prover to set `gate_i_output = 1` even when the gate semantics would yield `0`. If even one gate in the predicate evaluator is under-constrained, a prover can forge a proof for `chartered_by_NCUA == true` against a credential that does not carry that attribute.

This breaks UNF-CRED. Knowledge soundness only tells us the prover "knows a witness" — but if the circuit relation `R` does not correctly encode the predicate semantics, knowledge of a *circuit* witness does not imply knowledge of a *credential* witness satisfying the predicate.

**Formal statement:** The claimed reduction `UNF-CRED ← knowledge-soundness(PLONK) + Poseidon-CR + DLP` requires the circuit `C_{predicate}` to be *semantically complete and sound* for the Boolean language. The construction provides no formal proof of this for the 32-gate evaluator. A circuit audit or formal verification (e.g., via Lean + o1js) is a prerequisite to the reduction being meaningful.

**In-threat-model?** Conditionally no. If the 32-gate evaluator is independently verified to be sound and complete for the claimed expression class, this attack is mitigated. As stated, with "arbitrary Boolean expressions" and a fixed gate budget, the claim is not self-consistent and must address the overflow behavior and gate-level soundness explicitly.

---

### Attack 4: Merkle Root Staleness Enables Differential Timing De-Anonymization

**Attack:** The issuer key set is committed as a Merkle root `rt` over all valid issuer public keys. This root is public (the verifier checks membership). NCUA membership is not static — credit unions are chartered, merged, and liquidated. Each time the issuer set changes, a new root `rt'` is published.

An adversary observing `(proof π, timestamp t, root rt)` can compute the *diff* of the issuer set between `rt_{t-1}` and `rt_t`. If a proof is generated in a window where only `k` issuer keys changed, and the proof is valid under `rt_t` but invalid under `rt_{t-1}`, then the issuer key is in the set `Δ = issuers(rt_t) \ issuers(rt_{t-1})` — an anonymity set of size `|Δ|`, which may be 1.

This is not covered by IND-ISS as stated. IND-ISS is a static game: the adversary picks two issuers, and the root is fixed. It does not model an adversary who observes *multiple proofs across multiple root epochs* and correlates them to narrow the anonymity set.

**Why it works:** The construction's deployment scenario (CO-OP Shared Branch, cross-CU NCUA proof) is inherently long-lived. A verifier (or passive network observer) accumulating proofs over months has a differential-privacy adversary's advantage that grows with the number of root updates observed. The IND-ISS game is a one-shot indistinguishability game and does not compose to multi-proof unlinkability.

**In-threat-model?** No. The construction requires either (a) a formal multi-proof unlinkability game (analogous to unlinkability in anonymous credential schemes per Camenisch–Lysyanskaya 2004) with a reduction to IND-ISS under root-update composability, or (b) a root-update policy (e.g., epoch pinning with minimum anonymity set size `k`) specified as a protocol parameter with a corresponding security parameter. Without this, the cross-CU scenario in Section 6 is vulnerable to a passive network adversary performing root-epoch differential analysis.


## Persona: cu_ciso

---

### Attack 1: Anonymity Set Collapse via Network Enumeration

- **Attack:** The IND-ISS game proves issuer-hiding against a *computationally bounded* adversary who cannot enumerate the Merkle tree leaves. But CO-OP Shared Branch is a known, finite network. I run NCUA's public charter database (ncua.gov/analysis/Pages/credit-union-data.aspx) and cross-reference with CO-OP's published participant list. If the Merkle tree contains 80 participating CUs, the verifier at Navy Federal doesn't need to break the ZK proof — they enumerate all 80 candidate issuers, re-run the predicate check offline, and narrow the issuer identity probabilistically. With geographic filtering (Mountain America operates in UT/ID/NV), the anonymity set collapses to 3–5 candidates. The IND-ISS game assumes a *closed-world adversary* who doesn't hold the participant list. Navy Federal's BSA officer holds exactly that list.

- **Why it works:** The construction's IND-ISS reduction (§ "Security reductions") is sound against an adversary who chooses two issuers *without auxiliary input*. Real deployment violates this — the verifier is a regulated entity with access to public NCUA data and contractual CO-OP membership rosters. The circuit hides the issuer key; it does not hide the issuer *identity* against an adversary with out-of-band enumeration capability.

- **In-threat-model?** **No.** The construction must address the real anonymity set size, define an honest-participant policy (e.g., minimum Merkle tree depth / minimum participating issuers), and bound the information leaked by the verifier's auxiliary knowledge. Without this, the IND-ISS claim is technically correct and operationally meaningless.

---

### Attack 2: Revocation Latency Violates NCUA Part 748 § 748.1(c) Incident Response

- **Attack:** Mountain America gets breached. Their EdDSA issuer key is compromised. Under NCUA Part 748 § 748.1(c) and the GLBA Safeguards Rule § 314.4(h), I have a notification obligation within 72 hours and an immediate duty to contain the compromise. The construction's Merkle tree is the revocation mechanism — a compromised issuer key must be removed. But the construction says nothing about: (a) who holds write authority to the Merkle tree, (b) what the latency is between compromise discovery and tree update, (c) whether proofs issued *before* revocation remain valid, or (d) how Navy Federal's verifier knows to reject stale proofs after revocation. I will ask my NCUA examiner: "Show me the revocation SLA and the audit log proving the compromised issuer was removed within the required window." There is no answer in this construction.

- **Why it works:** The construction treats the Merkle tree as append-only for the IND-ISS proof. Revocation requires deletion or nullification — a structurally different operation. If the tree uses Poseidon hashing for inclusion proofs, a revoked-issuer proof remains locally valid until the verifier re-fetches the updated root. In an offline or degraded network scenario (the construction mentions 1% on-chain outage budget), a revoked issuer can still generate valid proofs. My examiner will call this a control gap under FFIEC CAT Domain 3 (Cybersecurity Controls) — specifically the "Access and Data Management" maturity indicator.

- **In-threat-model?** **No.** The construction must specify a revocation commitment scheme, define a maximum staleness window for Merkle root refresh, and provide an examiner-readable audit log of issuer key lifecycle events.

---

### Attack 3: Issuer Hiding Breaks GLBA Data Provenance and BSA Audit Trail

- **Attack:** My NCUA examiner sits across the table and asks: "Member Jane Doe authenticated at Navy Federal using a credential. Who issued it, when, and under what due diligence?" The construction's design goal — issuer hiding from the verifier — is architecturally incompatible with this question. Navy Federal's BSA officer cannot produce a SAR with a complete data provenance chain if the credential issuer is cryptographically hidden. GLBA § 314.4(a) requires I maintain a complete record of data flows involving member nonpublic personal information (NPI). The credential attributes (NCUA membership, possibly member ID derivation) are NPI. I cannot satisfy § 314.4(a) with a proof that deliberately hides who attested to that NPI.

- **Why it works:** The construction correctly frames issuer-hiding as a *privacy* property. But in a regulated financial context, the verifier's privacy interests are subordinate to their supervisory obligations. The construction's deployment scenario (§ "CO-OP Shared Branch") puts Navy Federal as verifier — a federally insured institution with its own NCUA examination obligations. Navy Federal cannot argue to its examiner that "we don't know who issued the credential" as a feature. Examiners will classify this as a third-party risk management failure under NCUA Part 748 Appendix B and the FFIEC IT Examination Handbook (Third-Party Relationships).

- **In-threat-model?** **No.** The construction must define a *dual-channel disclosure* protocol: issuer identity is hidden from the verifier in the ZK proof layer but disclosed to a regulated audit escrow (e.g., a CUSO acting as the trust anchor) that can respond to NCUA/FinCEN subpoenas. Without this, the construction cannot be deployed in any NCUA-examined institution.

---

### Attack 4: Member EdDSA Key Custody — Where Does the Witness Live?

- **Attack:** The circuit takes the member's EdDSA private key as a private witness (§ "IssuerBlindPredicate circuit"). I call my Tier 1 ops team lead at 2am: "Member says she can't prove her NCUA membership at the shared branch kiosk. What do we do?" The answer depends entirely on where the private key lives. If it's browser-side (localStorage, IndexedDB, WebCrypto non-extractable key), I have: XSS exposure violating FFIEC Authentication Guidance; no recovery path if the browser storage is cleared; no HSM or hardware binding that satisfies NCUA Part 748 § 748.0(a) "appropriate safeguards." If it's a mobile wallet, I have a different problem: device loss = credential loss, and re-issuance requires the original issuer (Mountain America) to be online and willing to re-sign — adding a dependency the construction doesn't account for. The construction benchmarks the circuit at ~42K constraints but is silent on the key management architecture that must surround it.

- **Why it works:** FFIEC CAT Declarative Statements under "Innovative Technology" require that novel authentication mechanisms meet or exceed existing control baselines. Browser-held private keys fail the baseline. Hardware wallet custody (YubiKey, Secure Enclave) solves the security problem but creates a new operational problem: device provisioning, replacement, and member support at 350+ shared branch locations. The construction's SOC 2 gap (noted in the candidate's gap-to-close) is downstream of this — you cannot get SOC 2 Type II coverage for a key management architecture that isn't specified.

- **In-threat-model?** **No.** The construction must specify a key custody architecture with explicit mapping to FFIEC Authentication Guidance (2011 supplement, updated 2023 expectations), define a re-issuance / recovery procedure, and bound the operational surface area for Tier 1 support. Without this, the construction is a cryptographic result in search of a deployable product.


## Persona: rfc7662_advocate

*Ten years shipping token introspection at scale. Show me what ZK gives me that a well-run AS cannot.*

---

### Attack 1: Federation AS as Introspection Hub Already Achieves Issuer-Hiding at the RS

**Attack:**
Deploy CO-OP Financial Services as a federation Authorization Server. Each member CU (Mountain America, Navy Federal, etc.) registers with CO-OP's AS. When a Mountain America member needs to prove NCUA membership at Navy Federal:

1. Member authenticates to CO-OP's AS (out-of-band, session-bound).
2. CO-OP's AS issues a signed JWT introspection response (per **draft-ietf-oauth-jwt-introspection-response**, now **RFC 9701**) asserting `ncua_member: true`, signed with **CO-OP's key only**.
3. Navy Federal verifies against CO-OP's well-known JWKS. The JWT contains no home-CU identifier — only the CO-OP AS signature.

The RS (Navy Federal) sees exactly `{sub: <PPID>, ncua_member: true, iss: co-op.example}`. It learns nothing about Mountain America. The construction's §3.2 IND-ISS adversary — given the verifier's view — cannot distinguish Mountain America from Redwood Credit Union.

**Why it works / why it fails:**
It works at the RS layer: the verifier's view is identical to what the ZK construction produces. It fails at the AS layer: CO-OP's AS learns (a) which home CU authenticated the member and (b) the exact timestamp of every Navy Federal verification. The construction is strictly stronger on AS-side privacy — but the construction must make this explicit. Section C4 currently frames IND-ISS as a game between verifier and adversary, not between AS and adversary. If the threat model excludes a curious-but-honest CO-OP AS, this attack is outside the model. If it doesn't, the construction must extend IND-ISS to cover AS-side leakage.

**In-threat-model?** Partially. The construction survives verifier-side issuer-hiding but **must address AS-side timing correlation explicitly in the threat model or the IND-ISS reduction is incomplete.**

---

### Attack 2: PPID + RFC 8707 Audience Binding Already Breaks Cross-RS Linkability Without Any ZK

**Attack:**
Use **OIDC Pairwise Pseudonymous Identifiers (PPIDs)** combined with **RFC 8707 Resource Indicators**. Each resource server gets a different `sub` value for the same user. Combined with **RFC 9449 DPoP** sender-constraining the token to the holder's keypair:

- Navy Federal receives a token with `sub: ppid-navyfed-abc123`, `aud: https://navyfed.example`, `ncua_member: true`.
- Redwood CU (a different RS) receives `sub: ppid-redwood-xyz789` for the same user.
- The two RSes cannot correlate the member across institutions.

This directly addresses the construction's §1 scenario: "cross-CU NCUA membership proof." The ZK construction claims to prevent cross-RS linkability — but PPID + audience binding already achieves this at the RS level with zero circuit overhead and zero trusted setup.

**Why it works / why it fails:**
It fully replicates the cross-RS unlinkability property at the RS layer. It fails to replicate issuer-hiding (Mountain America's AS is still the issuer of record in the `iss` claim — unless using the federation hub pattern from Attack 1). More critically: DPoP cannot provide **selective disclosure of a hidden attribute set**. If the proof requires proving `age_over_18 AND ncua_member AND NOT sanctioned_entity` over attributes the verifier is not permitted to see in cleartext, DPoP + introspection necessarily returns all attributes to the introspection caller or pre-commits to a fixed claim set. The construction's §4 Boolean predicate evaluator over hidden attributes has no RFC 7662 equivalent.

**In-threat-model?** No — this attack **fails** against the predicate-hiding property. But the construction must benchmark this explicitly. Right now the BBS+ comparison in the gap-to-close section does not address why PPID+DPoP cannot replicate predicate hiding. **Add a row in the comparison table: "Predicate over hidden attributes" → PPID+DPoP: ✗ (requires cleartext attribute disclosure at introspection endpoint).**

---

### Attack 3: AS-Side Per-RS Policy Filtering Replicates Attribute-Level Issuer-Hiding Without ZK Overhead

**Attack:**
RFC 7662 §2.2 explicitly permits the AS to return different `active` response bodies to different RSes. A well-configured AS implementing per-RS introspection policy:

- Returns `{active: true, ncua_member: true}` to Navy Federal.
- Returns `{active: true, finra_licensed: true}` to a broker-dealer.
- Returns nothing about home-CU identity to either.

The AS enforces this through policy — effectively acting as a selective-disclosure oracle. Combined with RFC 9701 signed responses (offline verifiable), the RS never calls home after the initial token issuance. **From the verifier's perspective, this is functionally identical to the construction's predicate proof.**

The specific attack on §3.1 (the IND-ISS game): the adversary's view in the game is just the verifier's transcript. If the verifier only ever receives `ncua_member: true` from the AS — regardless of which of the two challenge issuers signed — the adversary has zero advantage. IND-ISS is trivially satisfied by per-RS policy filtering, making the ZK construction's IND-ISS proof a theorem about a property the OAuth stack already delivers.

**Why it works / why it fails:**
It fails on two axes. First, **the AS is still a trusted third party**; the construction removes the AS from the verification path entirely (the Merkle root is public, the proof is self-contained). Second, per-RS policy filtering requires the AS to *know* the user's home CU in order to apply the right policy — the AS must hold the mapping `{user → home_CU}`, which is precisely the sensitive data the construction keeps out of any party's hands except the prover. The construction's §2.3 private witness (issuer key in Merkle path) means not even the AS learns *which specific issuer credential* is being presented at verification time.

**In-threat-model?** Yes — the construction **survives**, but §1 (Introduction) does not articulate the AS-blindness advantage clearly enough. The attack surface is: a reader can argue AS-side policy is equivalent. The construction needs a paragraph explicitly stating: *"Unlike per-RS introspection policy, the verifier receives no issuer information even from the AS's perspective — the AS is not in the verification path."*

---

### Attack 4: Merkle Issuer Registry Requires Governance Equivalent to OAuth Federation Trust Lists — "Arbitrary Schema Support" Is Overstated

**Attack:**
The IssuerBlindPredicate circuit (§4, ~42K constraints) commits to a Merkle root over known issuer keys. Adding a new issuer (e.g., a new NCUA-chartered CU) requires:

1. Updating the Merkle tree, producing a new root.
2. Distributing the new root to all verifiers — either through a new trusted setup or a hardcoded constant update in deployed circuits.
3. Re-generating proving keys if the tree depth changes.

Compare to **RFC 8414 (OAuth Authorization Server Metadata)** + **OpenID Federation 1.0**: adding a new issuer to a federation requires publishing new federation metadata at a well-known endpoint. Verifiers poll the endpoint. No circuit recompilation, no trusted setup ceremony.

The "arbitrary-schema support" claim in the gap-to-close section is further weakened: adding a new claim type (e.g., `finra_licensed`) to the 32-gate Boolean predicate evaluator requires circuit modification if the claim is not already in the schema registry embedded in the circuit. OAuth introspection handles this dynamically — the AS adds a new claim to the response, RSes opt-in by reading it.

**Why it works / why it fails:**
This is a **deployment friction attack**, not a cryptographic break. The construction is not wrong — it's complete for a fixed issuer set and fixed schema. But the claim of "arbitrary-schema support" is operationally false in the same sense that "arbitrary SQL schema support" would be false for a fixed-layout ZK-SNARK. The BBS+ comparison benchmark the gap-to-close requests should also include **operational schema evolution cost**, not just proof-size and IND-ISS reducibility.

The construction survives on security grounds but **overstates flexibility**. Recommend scoping the claim to: *"predicate-hiding over a governed issuer registry and a declared claim schema"* — and add a §6 deployment note on registry governance cadence versus OAuth federation metadata refresh.

**In-threat-model?** No — this is an operational/claim-accuracy issue, not a cryptographic attack. But it will surface in peer review and should be addressed in the paper before submission.


## Persona: spiffe_engineer

---

### Attack 1: SPIFFE ZK Attestor — Wrong Layer, Not Wrong Technology

- **Attack:** SPIFFE's node attestation is a plugin architecture. A `ZKNodeAttestor` plugin could accept a ZK proof of credential attribute satisfaction during workload registration, and SPIRE issues an SVID whose `path` component encodes the attested predicate (e.g., `spiffe://ncua.gov/chartered_member`). The verifier checks the SVID — constant-size X.509, existing PKI tooling, no new proof system. The CO-OP Shared Branch scenario (§ Deployment) becomes: member workload presents SVID to Navy Federal's SPIRE federation endpoint. Done.

- **Why it fails against the construction:** The SPIFFE SVID's `trust-domain` component **is** the issuer identity — `spiffe://mountain-america.coop/…` leaks the home CU immediately. Even if the predicate value is hidden inside the path, the trust-domain is plaintext in the X.509 SAN. To get IND-ISS (§ Security reductions), you would have to strip the trust-domain from the SVID, which breaks SPIFFE's entire chain-of-custody model: the verifier's bundle endpoint lookup keyed on trust-domain fails. The ZK attestor plugin idea collapses into "re-issue a de-branded SVID," which is just C4's circuit pushed one hop earlier and loses SPIFFE's non-repudiation guarantees.

- **In-threat-model?** Yes — construction survives. The IND-ISS property is structurally incompatible with SPIFFE's trust-domain-as-issuer identity model. The construction must cite this explicitly (currently the gap-to-close section §4 does not acknowledge the SPIFFE attestor alternative at all, which leaves reviewers unconvinced the design space was searched).

---

### Attack 2: WIMSE Already Has Selective Disclosure — Contribute, Don't Fork

- **Attack:** `draft-ietf-wimse-arch` §6 ("Workload Identity in Multi-System Environments") scopes token exchange with selective attribute disclosure across trust domains. The cross-CU scenario is textbook WIMSE: Mountain America's SPIRE is a WIMSE subject workload; Navy Federal's gateway is the WIMSE resource workload; a WIMSE token exchange with a `token_claims_requested` filter strips PII. WIMSE WG is actively soliciting ZK-based disclosure extensions. Filing an I-D there gets RFC track, not a bespoke construction.

- **Why it fails against the construction:** WIMSE selective disclosure operates at the **claim level** — the verifier knows the issuer trust domain but sees only the disclosed claims. The IND-ISS game (§ IND-ISS game) requires the verifier to be unable to distinguish *which issuer signed*, not merely which claims are revealed. WIMSE's token exchange exposes the `iss` field by design; the resource workload must validate the token against a known JWKS endpoint identified by issuer. Hiding `iss` while still allowing the verifier to check signature validity is exactly the circuit's job (issuer key as private Merkle witness, §IssuerBlindPredicate circuit). WIMSE has no mechanism for this — it is out of scope in the current charter.

- **In-threat-model?** Yes — construction survives. However, the construction **must** include a WIMSE alignment section. Reviewers who know the WIMSE draft will ask "why not there?" and the current write-up does not answer it. Recommended addition: one paragraph stating that C4's IND-ISS property is orthogonal to WIMSE's disclosure layer and that C4 output tokens could be wrapped as WIMSE assertions downstream.

---

### Attack 3: "Arbitrary Schema" Contradicts "Constant-Size Circuit" — Pick One

- **Attack:** The construction claims both "arbitrary-schema support" and a "constant-size predicate circuit" (~42K constraints, 32-gate Boolean evaluator). These are in direct tension. A 32-gate evaluator is a **fixed-topology** circuit compiled against a specific schema (attribute names, types, positions in the witness vector). Adding a new claim type — say, `finra_series_65_licensed == true` for the regulated-professional scenario (§ Scenarios) — requires recompiling the circuit, regenerating the trusted setup (if using a non-universal SRS), and re-deploying verifier contracts. That is not "arbitrary schema." A truly arbitrary-schema predicate engine requires a universal circuit (e.g., zkVM execution trace), which is not constant-size — Risc0's Groth16 wrapper is ~500K constraints minimum. The construction is claiming the benefits of both designs without paying the cost of either.

- **Why it works / why it partially fails:** The construction does not define what "arbitrary" means in §claim. If "arbitrary" means "any 32-gate Boolean expression over a fixed attribute schema negotiated at enrollment time," then it is internally consistent but the marketing claim is misleading. If it means "any schema, any time, without recompilation," the 42K constraint count is impossible without a zkVM backend, and the BBS+ comparison (§Why BBS+ cannot match) is no longer apples-to-apples since BBS+ supports dynamic attribute sets natively.

- **In-threat-model?** **No — construction must address.** The formal proof of constant-size (§ Security reductions) needs to state the schema-fixity assumption explicitly. The benchmark comparison against BBS+ is invalid unless both systems operate under the same schema-flexibility constraint. Recommend: define "schema" as a versioned artifact, prove constant-size for any schema of bounded attribute count N (parametric in N), show constraint growth is O(N) not O(2^N), and table the N=32 benchmark explicitly.

---

### Attack 4: Small Issuer Set Leaks IND-ISS in Practice (CO-OP Network)

- **Attack:** The IND-ISS game (§ IND-ISS game) models a polynomial-time adversary who picks two issuers and tries to distinguish which signed. This is a standard cryptographic game and the reduction to PLONK zero-knowledge is sound *in isolation*. But the CO-OP Shared Branch deployment has ~1,800 credit unions, all of whose public keys must be in the Merkle tree (root is a public verification input). An adversary operating the Navy Federal gateway observes: (a) the Merkle root used, (b) the Merkle path length (reveals tree depth, constrains issuer set size), (c) timing of root updates (SPIRE-style bundle rotation leaks issuer churn). In a network where Mountain America and Desert Financial are the only two CUs with shared-branch agreements in a specific ZIP code, the effective issuer anonymity set is 2, not 1,800. The IND-ISS game collapses to a coin flip with negligible adversary advantage — but the adversary's advantage is not negligible against the deployed system, only against the abstract game.

- **Why it works:** The construction's IND-ISS proof (§ Security reductions) does not bound the anonymity set size or the information leaked by auxiliary network observables (Merkle path, root version, branch-network topology). This is a standard ZK anonymity set degradation attack — the same attack that breaks Zcash shielded pools when the shielded pool is small.

- **In-threat-model?** **No — construction must address.** Required additions: (1) a minimum anonymity set parameter `k` (e.g., k ≥ 32 issuers in the tree), (2) a proof that Merkle path reveals only `O(log N)` bits and that those bits do not reduce the adversary's distinguishing advantage below a stated bound, (3) an operational requirement that the tree be padded with dummy issuer keys to enforce `k`. The BBS+ comparison section is silent on this; BBS+ has the same weakness, so a fair comparison should note both systems require anonymity set management.
