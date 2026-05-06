# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: The Latency Claim Is a TEE Tax, Not a ZK Win

**Attack:** Section 6 advertises a <2s teller flow benchmark, but buries the requirement: it assumes delegated TEE proving. I pull up the Auth0 MCP auth docs and show procurement: Auth0 issues an MTLS-bound token in <100ms, no TEE required, deploys via CDN in every region credit unions already use. Your <2s number requires the credit union to (a) provision a TEE server, (b) trust that server with the member's attributes, and (c) maintain it. That is not "2 seconds"; that is a six-figure infrastructure project before you get to proving time.

**Why it works / why it fails:** The construction benchmarks the proof, not the deployment. Section 6 has six platform benchmarks but none of them model the operational steady-state cost of running TEE infrastructure for a 12-person IT team at a community credit union. The TEE delegation mitigation is a latency optimization that shifts the bottleneck from compute to ops complexity. The attack succeeds because the construction presents TEE as a mitigation without pricing the mitigation.

**In-threat-model?** No — the construction must address the total cost of ownership of the TEE path, not just its wall-clock time. A benchmark without a deployment model is a lab result, not a procurement answer.

---

### Attack 2: "Arbitrary Schema Support" Hides an Exponential Circuit Compilation Problem

**Attack:** The claim in C4 is "constant-size proof and arbitrary-schema support." I ask the technical champion at the credit union: show me the circuit for a Boolean expression over a W3C VC schema you haven't seen before. With WorkOS, arbitrary OIDC claims work today with zero circuit changes — you just map the claim in the dashboard. With Bolyra, "arbitrary Boolean expressions over claim schemas" requires either (a) a universal circuit large enough to handle any expression, which is not constant-size in any practical sense, or (b) a per-schema circuit compilation step, which requires a Circom/Halo2 dev and a new trusted setup contribution for each new schema. Neither is described in Sections 2–6.

**Why it works / why it fails:** The construction formalizes the dIND-ISS game (Section 3.2) and the MUNL game (Section 3.3) over abstract predicates, but says nothing about how the predicate circuit is generated for a schema the system has not seen. The gap-to-close text acknowledges needing a "constant-size predicate circuit that handles arbitrary Boolean expressions" but does not show the mechanism. The attack exposes that "arbitrary" in the claim and "arbitrary" in the implementation are different things.

**In-threat-model?** No — the construction needs to specify the circuit compilation pipeline (universal circuit, SNARK-friendly IR compiler, or something else) and show that constant proof size holds as schema complexity grows. Without this, the claim is aspirational.

---

### Attack 3: The Small-Universe Disclosure Attack Survives the dIND-ISS Formalization

**Attack:** There are approximately 4,800 active NCUA-chartered credit unions. The dIND-ISS game (Section 3.2) lets the adversary choose attribute distributions per issuer, which sounds strong. But in the real deployment, the verifier (e.g., a mortgage servicer running an MCP server) sees thousands of proofs over months. Each proof asserts `chartered_by_NCUA == true` plus some predicate over other attributes. The verifier builds an empirical fingerprint: which attribute combinations appear together, at what frequency, with what epoch parameters. With k≥32 anonymity set (Section 3.3) and a 6-hour epoch, the effective anonymity set against a long-term verifier with auxiliary knowledge of each credit union's membership demographics is far smaller than 32. The formal game gives the adversary one shot; the production verifier gets millions of shots across correlated attribute distributions.

**Why it works / why it fails:** The MUNL game (Section 3.3) adds epoch pinning and a churn bound to prevent linkability across proofs from the *same* user. It does not bound the information leaked about the *issuer* across many users from the same issuer presenting to the same verifier. The dIND-ISS game (Section 3.2) models issuer hiding per proof, not issuer hiding under repeated observation with correlated auxiliary input. For large issuers (Navy Federal, ~14M members) the anonymity set is fine. For a 900-member community credit union, the attribute distribution is a fingerprint. The construction needs an issuer-size-conditioned lower bound or an explicit small-issuer threat model carve-out.

**In-threat-model?** No — Section 3.2 must be extended or explicitly scoped. The dIND-ISS game as described does not cover the adaptive multi-proof issuer inference attack available to a persistent verifier.

---

### Attack 4: The NCUA Escrow Is a Legal De-Anonymization Channel, and You Advertised It

**Attack:** Section 2.5 is the BSA/AML dual-channel: issuer identity is hidden from the verifier but disclosed to NCUA escrow via ECIES. I hand this to the credit union's BSA officer and their outside counsel. Counsel's read: NCUA escrow is a federal agency. 12 U.S.C. § 1790d gives NCUA examination authority. A grand jury subpoena or a FinCEN Section 314(a) request compels NCUA to produce the escrow plaintext. This is not a cryptographic break — it is a legal one, and it is cheaper than breaking the ZK circuit. Worse, you disclosed this channel in the construction. Auth0 and WorkOS don't have an escrow channel because they don't make issuer-hiding claims; they just federate identity. The issuer-hiding property is the differentiator, and you built a mandatory de-anonymization backdoor into it and called it a compliance feature.

**Why it works / why it fails:** The construction correctly maps the dual-channel to 31 U.S.C. § 5318(h) and NCUA Part 748 (Section 2.5) — this is necessary for BSA compliance and not a design error. But the threat model does not characterize the legal attack surface created by the escrow. A regulator with examination authority, a law enforcement agency with a subpoena, or a foreign government using mutual legal assistance treaties can de-anonymize any proof retrospectively. The construction should bound the escrow's threat surface: who can query it, under what legal standard, with what audit trail visible to the credit union, and whether a credit union can opt into a higher-latency proof path that avoids escrow for non-regulated contexts.

**In-threat-model?** No — Section 2.5 maps statutes but does not model the legal adversary who compels the escrow. The issuer-hiding security claim (Section 3.2) is cryptographic; its effective guarantee against a legally-empowered adversary is not analyzed. A buyer's legal team will raise this in week one of procurement.


## Persona: cryptographer

---

### Attack 1: ECIES Escrow Collusion Breaks dIND-ISS (Sections 2.5 × 3.2)

- **Attack:** The dIND-ISS game (§3.2) models the *verifier* as the issuer-hiding adversary. But §2.5 attaches an ECIES ciphertext — encrypting the issuer identity to the NCUA escrow key — to every proof. A colluding (NCUA escrow, verifier) pair is trivial: the verifier forwards the ciphertext to NCUA, NCUA decrypts and returns the issuer. The adversary wins dIND-ISS with advantage 1, using only one proof query.

- **Why it works / fails:** The construction nowhere specifies whether NCUA is modeled as honest, semi-honest, or adversarial in the dIND-ISS game. The escrow ciphertext is presumably part of the proof transcript the verifier receives (or is derivable from it); otherwise the AML channel is broken. Either way, the issuer-hiding reduction must account for a corrupt escrow oracle. The ECIES layer provides regulatory disclosure *or* issuer-hiding, not both, unless the escrow authority is cryptographically separated from the verifier's view — which requires a designated-verifier proof or an oblivious escrow design not described.

- **In-threat-model?** **No.** The dIND-ISS game must be amended to include a corrupt-escrow oracle query and a proof that one ciphertext cannot leak issuer identity to the verifier *even when the escrow key is known to the verifier*. Without this, §3.2 is incomplete.

---

### Attack 2: Issuer Registry as Timing Oracle (Sections 2.9 × 3.3)

- **Attack:** §2.9 specifies a weekly write cadence and a 4-hour revocation SLA. Revocations are issuer-specific (an issuer revokes its own credentials). A verifier who watches the registry over time can build a *revocation fingerprint* per issuer: each issuer has a characteristic revocation rate, batch timing skew, and churn signature. When a proof is presented, the verifier correlates the epoch-pinning parameter (§3.3, 6-hour min epoch) with the registry's last-write timestamp per issuer. Even with k≥32 anonymity set, the anonymity set shrinks to issuers whose revocation state changed within the current epoch — often a small subset. This is a membership-inference attack that is not captured by the MUNL game.

- **Why it works / fails:** The MUNL game (§3.3) treats the issuer registry as a static public parameter. It does not model the adversary's ability to issue `RevocationQuery(issuer_id, epoch)` calls. With a 4-hour SLA and weekly batches, the registry's update pattern partitions the issuer set across time. The construction's k≥32 bound is a static lower bound on set size, not a dynamic bound on distinguishability under adaptive registry queries.

- **In-threat-model?** **No.** The MUNL game needs a `RevocationOracle` that the adversary can query adaptively, and the epoch-pinning parameter must provably prevent narrowing the anonymity set via registry timing. The 4-hour SLA is in direct tension with 6-hour epochs — the adversary gets at least one registry-state transition within a single epoch window.

---

### Attack 3: "Constant-Size Proof / Arbitrary Schema" Is an Impossibility Without a Fixed Universal Circuit (Section 1 claim × Section 6 benchmarks)

- **Attack:** The construction claims "constant-size proof and arbitrary-schema support" simultaneously. For any fixed Groth16 or PLONK circuit, the circuit is compiled once and handles exactly the predicate it encodes. "Arbitrary Boolean expressions over claim schemas" requires either (a) a universal circuit of fixed depth *D* encoding any Boolean formula up to *D* gates, or (b) a recursive/folding scheme (Nova, Sangria, HyperNova). The construction specifies neither the depth parameter *D* nor a folding protocol. The benchmark in §6 is presumably for a specific predicate (chartered_by_NCUA == true); it does not establish that the same proof size holds for a disjunction over 12 issuers with range checks on three numeric attributes.

- **Why it works / fails:** This is a *completeness* gap, not a soundness gap. The adversary's role here is the implementer: supply a credential schema complex enough (e.g., a FINRA-licensed agent proof requiring 5-attribute conjunctions with range checks) to exceed the universal circuit's capacity. The prover either rejects or silently truncates the predicate, producing a proof that the verifier accepts for a *weaker* statement than intended. The §6 benchmarks provide no evidence this cannot happen.

- **In-threat-model?** **No (completeness gap, not a security game violation per se, but fatal for the claim).** The construction must specify: the maximum supported predicate depth/width, the circuit structure for universal Boolean evaluation, and benchmarks for the *worst-case* predicate, not the single-attribute demo case.

---

### Attack 4: Nullifier Precomputation by a Colluding Authorization Server (Section 3.3 × §2.5 scope_id)

- **Attack:** Drawn from the standard Camenisch-Lysyanskaya pitfall: the MUNL game (§3.3) uses epoch-pinning with parameters (epoch, scope_id). If the Authorization Server (AS) knows scope_id — which it must in the BSA/AML dual-channel (§2.5) to route the ECIES ciphertext — and if the nullifier is derived as `H(credential_commitment, scope_id, epoch)`, then a corrupt AS can precompute the nullifier table for all enrolled agents within an epoch. With k≥32 anonymity set and 10% max churn, the enrolled set is at most ~360 credentials after one churn cycle. Precomputation cost: 360 hash evaluations per epoch. The AS then deanonymizes any proof by nullifier lookup.

- **Why it works / fails:** The MUNL game adversary in §3.3 is not specified to include a corrupt AS. For the cross-CU scenario (the primary use case), the AS is operated by the *sending* credit union, which has incentive to deanonymize proofs presented to the *receiving* credit union. The construction's ECIES channel gives AS exactly the scope_id linkage needed. The epoch-pinning mitigates cross-epoch linkability but does nothing against within-epoch nullifier precomputation when the AS controls the scope_id assignment.

- **In-threat-model?** **No.** The MUNL game must model a corrupt AS as an adversarial oracle. The nullifier derivation must include a per-user secret not known to AS (e.g., a blinding factor committed to in the credential but not revealed in the ECIES ciphertext). Otherwise, the 10% churn bound and k≥32 set size are decorative.


## Persona: cu_ciso

---

### Attack 1: ECIES Escrow Key Custody is Itself an Unresolved Third-Party Risk

- **Attack:** Section 2.5 claims BSA/AML compliance by routing issuer identity through an ECIES escrow channel to "NCUA escrow." My NCUA examiner will immediately ask: *who holds the escrow private key?* Is it ZKProva? A custodian? The NCUA itself? If ZKProva holds it, I now have a third-party with privileged access to a decryption capability that can de-anonymize every member proof ever generated. My Vendor Management Policy requires a SOC 2 Type II, business continuity plan, and contractual SLA from any vendor that touches member data. The construction cites 31 U.S.C. § 5318(h) and NCUA Part 748 as *coverage*, but never specifies the key management ceremony, the custodian's regulatory status, or the access-control audit trail for escrow decryption events. GLBA § 314.4(b) requires me to oversee service provider arrangements — this escrow relationship is exactly that, and it's undefined.

- **Why it works:** Section 2.5 maps the *disclosure obligation* but leaves the *key custody architecture* as an implementation detail. That gap is where my exam finding lives. The examiner won't credit a cryptographic construction; they'll ask for the vendor contract and the key-access log.

- **In-threat-model?** No — the construction must address who custodies the escrow key, under what contractual and regulatory framework, with what audit trail for each decryption event, before Section 2.5's BSA claim is defensible.

---

### Attack 2: MPC Ceremony Participants are Unvetted Third Parties Under NCUA Third-Party Risk Rules

- **Attack:** Section 2.10 specifies a verifiable MPC ceremony with n≥7 participants and a 1-of-n honest assumption. My examiner will ask me to produce due diligence on every participant. Under NCUA's third-party risk guidance (Letter to Credit Unions 07-CU-13, reinforced by the interagency guidance on third-party relationships finalized in 2023), I need to know: Who are the n≥7 participants? Are any of them foreign nationals or entities subject to OFAC jurisdiction? Do they have SOC 2 Type II reports? What contractual controls bind them post-ceremony? The Halo2/IPA transparent fallback eliminates the *ongoing* trusted setup risk, but the initial ceremony already happened. If any participant was compromised or coerced, the entire soundness assumption collapses — and I have no forensic mechanism to detect that retroactively.

- **Why it works:** The construction treats the SRS ceremony as a one-time cryptographic event, but from my regulatory posture it is a third-party engagement that required vendor due diligence *before* it occurred. "Verifiable MPC" is a technical property; it does not substitute for contractual risk transfer and examiner-legible documentation of participant vetting.

- **In-threat-model?** No — Section 2.10 formalizes the *cryptographic* honesty assumption (A5) but provides no governance wrapper. The construction must specify participant eligibility criteria, the vetting record, and what examiner-legible artifact proves ceremony integrity after the fact.

---

### Attack 3: Member Secret Lives in the Browser — Member Data Privacy Fails at 2 AM

- **Attack:** Section 6 benchmarks client-side proving on a Chromebook and an iPhone. That means the member's private key material lives in browser storage or a mobile keychain. When a member calls my contact center at 2 AM saying they cannot authenticate at a partner credit union, my Tier 1 agent has three problems: (1) they cannot inspect or reset the member's key without the member physically recovering it, (2) if the member lost their device, there is no credential recovery path described anywhere in the construction, and (3) if the browser secret is exfiltrated via malware, the member's issuer-blind proofs can be replayed indefinitely — epoch-pinning (Section 3.3) limits linkability between honest parties but does not revoke a stolen key. The TEE delegated-proving path in Section 6 is offered as a mitigation "for teller flows," but the member-facing path is not addressed.

- **Why it works:** GLBA § 314.4(a) requires my safeguards program to cover customer information *in all forms*. A browser-resident member secret is customer information. The construction's performance section acknowledges the client-side proving model without specifying key storage security, backup, or recovery — three things my examiners and my board will ask about after the first member incident.

- **In-threat-model?** No — the construction must define key storage requirements (e.g., WebAuthn-bound, Secure Enclave, or TEE-only), a recovery ceremony that does not require re-issuance by the original credential issuer, and an operational runbook my Tier 1 team can execute.

---

### Attack 4: The Revocation SLA and Batch Cadence Create a Compliance Window My Examiner Will Mark as a Finding

- **Attack:** Section 2.9 specifies a 4-hour revocation SLA and a *weekly batch cadence* for registry updates. Suppose a member's credential is compromised Monday morning. For up to 4 hours, a relying-party credit union will accept proofs derived from that credential — but worse, the weekly batch means new issuers or revoked issuers may not propagate for up to 7 days. NCUA Part 748 Appendix B requires my incident response program to contain and notify within defined windows. My core processor has a contractual 99.95% uptime SLA with a 15-minute failover; I can compare that to a regulator. A 4-hour revocation window backed by an on-chain registry with an unspecified uptime SLA (the construction gives no availability target for the registry in Section 2.9) is not a comparable control. Additionally, FFIEC CAT Domain 3 (Cyber Risk Management) requires me to demonstrate that third-party dependencies have tested continuity plans — the construction's on-chain registry has no stated DR/BCP posture.

- **Why it works:** The construction frames the 4-hour revocation SLA and weekly batch as *features* (Section 2.9: "4-hour revocation SLA, on-chain audit trail, examiner-readable API"). From my seat they are *liabilities*: a bounded but non-zero window of post-compromise credential validity, a registry freshness lag that could leave my loan officer approving a regulated-professional proof based on week-old issuer state, and no SLA for the registry itself. The "examiner-readable API" is described without an availability commitment.

- **In-threat-model?** No — the construction must publish a registry uptime SLA (with contractual teeth), reduce or justify the revocation window against NCUA Part 748 incident response standards, address the batch cadence risk with an emergency out-of-band revocation path, and provide a BCP/DR summary suitable for FFIEC CAT Domain 3 evidence.


## Persona: rfc7662_advocate

---

### Attack 1: Per-RS Introspection Policy Already Achieves Issuer-Hiding at the Verifier Layer

**Attack:** RFC 7662 §2.1 mandates that "the authorization server SHOULD determine whether or not to honor the request depending on which protected resource is making the request." A production AS deploys a claim-filtering policy table: for RS_verifier, the introspection response omits `iss`, `azp`, and any issuer-correlated claims. The RS receives `{ "active": true, "chartered_by_NCUA": true }` — no issuer in sight. Combine with OIDC PPIDs (sector-specific `sub`) and cross-RS linkability is gone too. The AS knows the issuer; the RS does not. That is exactly the construction's C4 threat model (Section 2, verifier-side hiding).

**Why it fails against the construction / why it partially works:** The construction's rejoinder is that the AS is an online trusted third party with full issuer knowledge and a subpoena surface. The NCUA escrow (Section 2.5) plays the same structural role, so the construction does *not* eliminate a TTP — it merely relocates it from the AS to the ECIES escrow channel. The adversary therefore presses: **the construction's issuer-hiding property is a trust-topology rearrangement, not a qualitative cryptographic advance over filtered introspection.** Unless Section 2.5 explicitly argues why an ECIES-encrypted escrow has strictly smaller subpoena surface than an AS, the claim is undefended.

**In-threat-model?** Partially yes — the construction survives if (and only if) Section 2.5 argues the escrow's disclosure surface is strictly smaller than an AS's. As written, this is not established. Construction must address.

---

### Attack 2: Signed JWT Introspection Response Removes the AS from the Hot Path Without ZK

**Attack:** `draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) allows the AS to pre-sign a JWT that the RS verifies offline against the AS's JWKS. The AS strips the `iss` claim before signing. The RS verifies the JWT signature — proving the token is valid and `chartered_by_NCUA == true` — without the AS being present and without the RS ever seeing which underlying issuer signed the original credential. Proof freshness is handled by `iat`/`exp` in the signed response. This is constant-size (one JWT), supports arbitrary claim predicates via AS-side evaluation, and is widely deployed today.

**Why it partially fails:** The AS must still evaluate the predicate from raw credential data, meaning it holds issuer-correlated state. An insider or compelled disclosure reveals the issuer-to-subject mapping. The ZK construction (Section 3.2, dIND-ISS game) claims the *prover's own issuer is hidden from the verifying party with no intermediary learning it either.* The construction's distinction is zero-knowledge at the *credential layer*, not policy-filter at the *token layer*. However, the construction must then answer: **does dIND-ISS security hold when the NCUA escrow (Section 2.5) receives the issuer identity via ECIES?** If the escrow's decryption key is a single key held by NCUA, the AS-equivalent trust is just renamed. The benchmark comparison against "BBS+/W3C VC" (gap-to-close) does not address this equivalence to signed JWT introspection.

**In-threat-model?** Yes — the construction survives this if Section 3.2's dIND-ISS game explicitly excludes the escrow as an adversarial oracle. It currently does not appear to do so.

---

### Attack 3: DPoP + RFC 8707 Audience Binding Already Provides Cross-Proof Unlinkability Without ZK

**Attack:** RFC 9449 DPoP binds each token to a per-request proof-of-possession JWK. RFC 8707 resource indicators bind each token to a specific RS audience. The combination means token T₁ used at RS_A and token T₂ used at RS_B cannot be linked: different DPoP keys, different `aud` values, different `sub` PPIDs. A verifier at RS_B sees no correlation to RS_A. This directly addresses the MUNL threat (Section 3.3) without ZK, without epoch pinning, and without the k≥32 anonymity-set machinery.

**Where the construction's MUNL game adds something:** Section 3.3's MUNL game covers the case where the *same RS* sees multiple proofs from the same user across epoch boundaries and attempts to link them (long-term correlation by a single verifier). DPoP does not prevent this: the verifier sees the same DPoP JWK across sessions (DPoP keys are stable per client). Epoch pinning (6hr min, 10% max churn) is the construction's answer. **The adversary's challenge:** the construction must show that epoch churn parameters are calibrated against a concrete linkability attack, not just asserted. A motivated RS can fingerprint circuits — constant-size proofs from the same circuit version are trivially linkable by circuit digest, independent of epoch rotation. Section 3.3 does not appear to address circuit-version fingerprinting as a side channel.

**In-threat-model?** Yes — construction survives DPoP comparison on long-term RS-side linkability, but must address circuit-version fingerprinting as an out-of-band linkage vector not covered by the MUNL game.

---

### Attack 4: The IND-ISS Game is Vacuous Over a Public On-Chain Registry with Small Issuer Cardinality

**Attack:** Section 2.9 specifies an on-chain issuer registry with a public "examiner-readable API" and weekly batch cadence. The dIND-ISS game (Section 3.2) claims security "with full auxiliary input" — but the adversary's auxiliary input now *includes* the public registry. In the cross-CU NCUA membership proof scenario, the NCUA charter registry is a matter of public record: approximately 4,600 federally insured credit unions. Once the verifier knows the prover's approximate geography (inferred from claimed membership scope), the effective issuer set is O(10–50). **Issuer-hiding in a set of cardinality 15 is not IND-ISS security — it is 4-bit anonymity.** The formal game does not distinguish between semantic security over a large issuer universe and near-trivial guessing over a small public set. RFC 7662 with per-RS policy faces the same problem, but it does not claim a formal IND-ISS proof — the construction does.

**Why this is a gap not just a limitation:** The dIND-ISS game as described (Section 3.2) lets the adversary "choose attribute distributions per issuer" but presumably the issuer set size |I| is a parameter. If |I| is small and the registry is public, the game's advantage bound is trivially large. The construction needs either (a) a composability argument that geographic auxiliary info is out-of-scope, or (b) a k-anonymity lower bound on how many issuers must be plausible for the game to be non-trivial. Neither appears in the current construction.

**In-threat-model?** Yes — the construction survives if Section 3.2 explicitly parameterizes the game by |I| and establishes a minimum anonymity-set size (analogous to the k≥32 bound in MUNL). As written, the dIND-ISS claim overstates security for real-world issuer registry cardinalities. **This is the highest-priority gap: a formal proof that fails on its own auxiliary-input assumption is worse than no formal proof.**


## Persona: spiffe_engineer

---

### Attack 1: SPIRE Pluggable Attestor Sufficiency

- **Attack:** SPIRE's node attestation is plugin-extensible. A ZK attestor plugin (implementing the `NodeAttestor` gRPC interface) can verify "this workload belongs to an NCUA-chartered CU" at attestation time, then mint a standard X.509 SVID with trust domain `spiffe://ncua-members.trust/chartered`. The verifier checks the SVID against the trust bundle — issuer hidden, predicate proven, portable across any SPIFFE-aware relying party. The construction (Section 2.9, issuer registry governance) duplicates what SPIRE's upstream bundle authority + federation already provides: trust bundle propagation, revocation via bundle rotation, and write-authority governance. The 2-of-3 multisig you describe is a re-implementation of SPIRE's federated bundle endpoint with a governance overlay. **Why are you not a SPIRE plugin?**

- **Why it works / fails:** It works in pointing out a missing comparison: the construction never shows why a ZK attestor inside SPIRE is insufficient. It partially fails because SPIRE attestation is node-scoped (attests the workload's execution environment) not claim-scoped (attests a specific credential attribute predicate). A ZK attestor in SPIRE can prove *membership in a trust domain* but cannot prove arbitrary Boolean predicates over credential schemas (e.g., `chartered_by_NCUA == true AND license_type IN {FCU, SCU}`) without embedding circuit logic into the attestor itself — at which point you've rebuilt C4 inside a plugin wrapper.

- **In-threat-model?** Partially. The construction must add an explicit paragraph in Section 1 (or a new Section 2.0 "Why not SPIFFE?") that draws the node-attestation vs. claim-predicate distinction and shows the SPIRE plugin approach cannot match arbitrary-schema predicates without circuit logic. Without this, a standards body will redirect the paper to the SPIRE working group.

---

### Attack 2: WIMSE Selective Disclosure Already In Scope

- **Attack:** WIMSE `draft-ietf-wimse-arch` §5 (token exchange) combined with SD-JWT (`RFC 9449`) or BBS+ selective disclosure gives you issuer-hiding attribute proofs within an IETF-standardized envelope. A WIMSE token exchange where the upstream token is a BBS+ credential and the downstream token is a derived proof with `chartered_by_NCUA` disclosed satisfies the cross-CU membership scenario (Section C4 scenario 1) and the FINRA-licensed agent scenario (scenario 2) without a new protocol. The BSA/AML dual-channel (Section 2.5) maps cleanly to a WIMSE compliance token exchange leg. **Why are you not a WIMSE profile?**

- **Why it works / fails:** It works because BBS+ selective disclosure is IETF-tracked and issuer-hiding by construction (the verifier sees a derived proof, not the original credential). It fails on the *constant-size* claim: BBS+ proof size scales with the number of disclosed attributes (O(n) group elements), while C4 claims constant-size via a Groth16/Halo2 circuit regardless of schema complexity. If the construction's circuit actually achieves O(1) proof size for arbitrary Boolean expressions over claim schemas — which the construction asserts but doesn't prove for the general case — that is the differentiator. Section 6 benchmarks cite proof generation time but do not compare proof *size* against BBS+/SD-JWT for equivalent predicate complexity.

- **In-threat-model?** Yes, but incompletely addressed. The gap in Section 6 (gap 5, benchmarks) was closed for *generation time* not *proof size*. The construction must add a column to the Section 6 benchmark table: "Proof size (bytes) vs. BBS+ baseline for equivalent predicate." Without it, the claim "BBS+/W3C VC cannot match without comparable circuit" (from gap_to_close) is asserted, not demonstrated.

---

### Attack 3: Issuer Registry Timing as Side Channel Outside MUNL Model

- **Attack:** The issuer registry (Section 2.9) operates on a weekly batch cadence with a 4-hour revocation SLA and an on-chain audit trail. The MUNL game (Section 3.3, gap 4) models a Camenisch-Lysyanskaya-style adversary who sees a sequence of proofs. But the MUNL game's adversary is implicitly assumed to *not* observe registry write timing. In a real deployment, the on-chain audit trail timestamps every registry update. An adversary who monitors the chain sees: (a) which epoch parameters changed, (b) when (weekly batch), and (c) which issuers were added/rotated/revoked. If the set of active issuers at epoch T has k=32 members (per Section 3.3 minimum) but 3 were rotated in the batch 6 hours before a proof was generated, the effective anonymity set is k=29 or smaller. The epoch-pinning (6hr minimum epoch) doesn't prevent this correlation — it only prevents proofs from straddling epoch boundaries. A determined adversary correlates proof timestamps with batch update timestamps and narrows the issuer set, defeating the dIND-ISS guarantee (Section 3.2) in practice even if it holds in the game.

- **Why it works / fails:** It works because the on-chain audit trail (required for examiner-readable API, Section 2.9) is structurally in tension with issuer-hiding. The construction cannot both have a public audit trail and claim the MUNL adversary cannot see registry state. It partially fails if the construction argues the audit trail reveals only aggregate registry state (number of issuers, not which credentials correspond to which issuer) — but Section 2.9's "examiner-readable API" suggests per-issuer visibility for regulatory access, which an adversary with examiner-level access can exploit.

- **In-threat-model?** No — this attack is not addressed. Section 3.3 (MUNL) and Section 2.9 (registry governance) are designed independently and their interaction is not analyzed. The construction must either: (a) extend the MUNL adversary's capability to include registry timing observations and prove the bound still holds, or (b) move to a private on-chain registry (e.g., Merkle-tree commitment with ZK membership proof) that hides per-batch deltas while preserving the examiner-readable audit path via selective disclosure to NCUA only.

---

### Attack 4: Trust Domain Federation Closes the "Portable Identity" Gap Without ZK

- **Attack:** SPIFFE trust domain federation (`spiffe-trust-domain-and-bundle`, §6) allows CU-A's SPIRE server to federate with CU-B's SPIRE server. A member's workload identity `spiffe://cu-a.org/member/account` is valid at CU-B because CU-B trusts CU-A's bundle. Cross-CU NCUA membership proof (scenario 1) becomes: each NCUA-chartered CU joins a federated SPIFFE domain `spiffe://ncua.gov/chartered/`. The "portable identity" property is delivered by federation, not by ZK. **Name the gap that federation does not close.**

- **Why it works / fails:** It works as a challenge because the construction never explicitly enumerates what federation cannot do. It fails as a full attack because SPIFFE federation reveals the originating trust domain (`cu-a.org`) to CU-B — it is not issuer-blind. In the cross-country KYB scenario (scenario 3) where jurisdiction must stay hidden, revealing the trust domain (`spiffe://us.jurisdiction/kyb/`) to a foreign verifier is precisely the threat. The construction's dIND-ISS game (Section 3.2) formalizes exactly this: the verifier must not learn which issuer (trust domain, in SPIFFE terms) signed the credential. SPIFFE federation explicitly propagates trust domain identity — it is issuer-*visible* by design.

- **In-threat-model?** Yes — the construction survives this attack, but only for the jurisdiction-hiding scenario (scenario 3). For scenario 1 (cross-CU NCUA membership) and scenario 2 (cross-firm FINRA), a reviewer will ask whether issuer-hiding is actually required or merely nice-to-have, since federation would suffice for those cases and is already standardized. The construction should add a one-paragraph "threat model scope" clarifying *which* scenarios require strict issuer-hiding vs. which could use federation, and justify why a unified construction covering all three is preferable to federation + ZK only where needed.
