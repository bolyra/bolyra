# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: NCUA Already Issues the Token — You Solved a Problem That OAuth Federation Solves for Free

**Attack:** The deployment scenario is "PenFed verifies a SECU member without learning their home CU." But NCUA already has an organizational infrastructure. An NCUA-operated OIDC/SAML federation — or even a simple Auth0 organization with NCUA as the upstream IdP — issues a JWT asserting `chartered_by_NCUA=true` without revealing the member's home CU. The verifier (PenFed) validates the NCUA-signed token. No circuit, no Merkle tree, no constraint counts. WorkOS has this deployed for exactly this pattern: multi-org federation with attribute release policies. Auth0 AI docs cover the MCP layer on top.

**Why it works / why it fails against the construction:** The construction assumes the issuer identity *must* be cryptographically hidden because issuers are independent signers (not under a shared root). But the CUNA/NCUA deployment scenario explicitly posits a "CUNA-managed issuer registry" — meaning there *is* a central coordinator. If CUNA is already the coordinator, they can be the OAuth AS. The ZK layer adds complexity without adding trust assumptions that matter here. The construction doesn't address why a centrally-coordinated registry can't just be a standard federation hub.

**In-threat-model?** No — construction must address this. Section on deployment scenario needs to explain what threat the central-coordinator alternative fails to address (e.g., CUNA seeing all auth events, or CUNA being offline blocking all verifications).

---

### Attack 2: The Merkle Root Is a Static Artifact — Credit Union Mergers Break Every Issued Credential

**Attack:** The depth-16 tree encodes ~65,536 issuer public keys at circuit-compile time (or at proof time with a pinned root). NCUA-chartered CUs merge at a rate of ~200–300 per year. Each merger changes the issuer set, changing the Merkle root. Every credential issued against the old root produces an inclusion proof that no longer validates against the new root. Either (a) you re-issue all credentials on every merger event, or (b) you maintain a version history of roots and the circuit must accept any valid historical root — which opens a replay window where credentials from defunct CUs still verify.

**Why it works / why it fails against the construction:** The construction is silent on root rotation. It states depth-16 as a design parameter but doesn't address the operational lifecycle. Auth0's Dynamic Client Registration (RFC 7591) handles client lifecycle automatically. WorkOS federation handles IdP key rotation transparently. The construction needs an explicit root-rotation protocol, a credential re-issuance SLA, and a revocation mechanism for credentials tied to merged/dissolved CUs — none of which appear in the gap-to-close section.

**In-threat-model?** No — construction must address this. This is a liveness/operational correctness gap, not a cryptographic one, and it's the first question a credit union's IT ops team will ask.

---

### Attack 3: "Arbitrary Boolean Expressions" Is a Marketing Claim — 8 Slots Breaks FINRA Licensing

**Attack:** The FINRA-licensed agent scenario requires proving attributes like: license type (Series 7, 63, 65...), exam date, CRD number range, firm affiliation status, U4 disclosure flags, state registration bitmap. That's already 6–8 attributes before you touch the predicate logic. The "8 credential attribute slots" with fixed opcodes is not arbitrary — it's a fixed-width schema that tops out at the complexity the author chose to benchmark. Real W3C VC credentials for regulated professionals (FINRA, BrokerCheck, ACAMS) carry 50–200 fields. The circuit cannot express "license_type ∈ {7, 63, 65} AND exam_date > 2020-01-01 AND disclosure_count == 0" without blowing the slot budget or requiring a custom circuit per schema.

**Why it works / why it fails against the construction:** The claim says "arbitrary-schema support" but the construction describes "8 credential attribute slots." These are in direct contradiction. BBS+ with selective disclosure handles variable-length attribute sets natively without a fixed slot budget. The gap-to-close mentions "arbitrary Boolean expressions over claim schemas" but the circuit design doesn't deliver that — it delivers a fixed-width predicate evaluator. Enterprise procurement for FINRA compliance will benchmark this against the actual credential schema, not a synthetic 8-field test.

**In-threat-model?** No — construction must address this. Either drop the "arbitrary-schema" claim and scope to fixed schemas, or redesign the circuit to handle variable-length attribute vectors (which will blow the 46,500 constraint count).

---

### Attack 4: The Auth Flow Is Invisible — What Does Onboarding Look Like for a Credit Union IT Admin?

**Attack:** WorkOS MCP auth onboarding: IT admin pastes a WorkOS org ID, enables the MCP connector, done. Stytch: paste Connected Apps credentials, configure scopes. Auth0 AI: add the MCP server to the Auth0 dashboard, inherit existing enterprise SSO. For Bolyra C4: the issuer must (1) generate an EdDSA keypair, (2) register it with the CUNA Merkle registry, (3) wait for a root update, (4) issue credentials against that root, (5) deploy a prover service that generates 3–8s proofs per authentication event, (6) integrate the verifier circuit into their MCP server or proxy. Step 5 alone requires infrastructure the credit union doesn't have. There is no onboarding flow described anywhere in the construction.

**Why it works / why it fails against the construction:** The construction is entirely cryptography-layer. There is no API, no SDK call, no "paste your key here" equivalent. The gap-to-close lists formal proofs and benchmarks — but the actual adoption blocker for credit unions is not "can you prove IND-ISS" it's "can my one IT generalist deploy this without a ZK engineer on staff." The construction's strength-9 rating is cryptographic; the GTM strength is approximately 2.

**In-threat-model?** No — construction must address this. Add a concrete onboarding sequence (issuer registration API, credential issuance SDK, verifier plugin for popular MCP frameworks) or acknowledge that this is a protocol spec that requires a deployment layer not yet built.


## Persona: cryptographer

*Reviewing C4: "Issuer-blind attribute predicates" — IssuerBlindPredicate circuit, Bolyra ZK construction*

---

### Attack 1: Predicate-Policy Binding Gap — Verifier Cannot Enforce Its Own Policy

- **Attack:** The public output of the circuit is a single bit `predicateSatisfied`. The predicate parameters — op codes, attribute slot indices, comparison values, conjunction mask — are all **private witness inputs chosen by the prover**. A verifier who wants to enforce "chartered_by_NCUA == true AND jurisdiction == 'US'" has no mechanism to bind the circuit evaluation to *that specific predicate* versus any satisfiable predicate the prover substitutes. Concretely: prover sets mask to vacuously-true (empty conjunction), gets `predicateSatisfied = 1`, verifier accepts. No public commitment to predicate semantics appears in the proof's public signals.
- **Why it works:** The construction states "arbitrary Boolean expressions over 8 credential attribute slots using a fixed-size predicate encoding (op codes + values + conjunction mask), outputting a single `predicateSatisfied` bit." The op codes and mask are witness-side. The ZK property then actively hides them from the verifier. This is a standard **verifier-side policy enforcement** failure — the verifier proves nothing about *which* predicate was evaluated, only that *some* predicate was satisfied.
- **In-threat-model?** **No.** This is a soundness failure in the application layer. The construction must either (a) hash the predicate descriptor into a public signal committed to by both parties out-of-band, or (b) define a separate predicate-specification protocol. Without this, the IND-ISS game definition is irrelevant — an adversary wins trivially by submitting vacuous predicates.

---

### Attack 2: IND-ISS Reduction is Incomplete — Merkle Root as a Temporal Issuer Oracle

- **Attack:** The reduction sketch claims: "since the issuer key only appears in private witness positions and all public signals are identical between any two issuers signing the same attributes, the ZK property of Groth16/PLONK directly implies issuer indistinguishability." But the Merkle root over the issuer registry **is** (or must be) a public signal — the verifier needs to anchor which registry state the membership proof is against. The CUNA-managed registry of ~4,700 CUs is dynamic: CUs are chartered and dissolved. An adversary (the verifier, or a passive network observer) who records `(proof, Merkle_root, timestamp)` tuples can intersect proofs against known registry diffs. If CU X joins the registry at time T and a prover produces a valid proof under root R_T where CU X is newly included, the issuer set is narrowed.
- **Why it works:** The IND-ISS game as sketched treats the Merkle root as a static parameter. Real CUNA registry updates are public (NCUA publishes charter changes). A sub-exponential distinguisher exists: observe proofs over registry epochs, intersect with public NCUA charter records. This is not a computational break of ZK — it is an *auxiliary-input* attack outside the stated game definition.
- **In-threat-model?** **Partially.** If the threat model explicitly scopes to a static registry, the construction survives. But the scenario "CUNA-managed issuer registry of ~4,700 NCUA credit unions" implies a live, mutable registry. The IND-ISS game definition must explicitly model registry updates, verifier auxiliary input (NCUA public records), and time-indexed proofs, or the reduction is incomplete. The construction must address this.

---

### Attack 3: Groth16 Subverted Setup — Human Path Proof Forgery

- **Attack:** The Groth16 human path uses a **per-circuit trusted setup** (~50,100 constraints). A party who retains the toxic waste `(α, β, γ, δ, τ)` from the setup ceremony can compute a simulated proof for any false statement — specifically, prove `predicateSatisfied = 1` for a credential where the predicate is *not* satisfied, and prove Merkle membership for an issuer key *not* in the registry. The construction does not specify who ran the setup ceremony, what multi-party ceremony protocol was used, or what happens under setup compromise.
- **Why it works:** This is a well-understood Groth16 property. The knowledge soundness argument holds only under the assumption that the SRS is honestly generated. For a fintech deployment (cross-CU NCUA membership, FINRA-licensed agent proofs) where forged proofs carry material liability, "we ran a setup ceremony" is not a security claim — it is a trust assumption that must be modeled. In the UC framework, a subverted SRS trivially breaks any ideal functionality the construction claims to realize.
- **In-threat-model?** **No, and it's unaddressed.** The construction should either (a) specify a transparent-setup proof system (PLONK with KZG requires a universal SRS, not per-circuit — but KZG still requires a trusted setup for the SRS itself), (b) use a transparent system like STARK or FRI-based PLONK where no trusted setup is needed, or (c) explicitly bound the threat model to exclude setup compromise and justify why that is acceptable for the deployment scenario. A Groth16 human path for regulated financial proofs with no ceremony documentation is a liability.

---

### Attack 4: Nullifier Precomputation Under Colluding AS + Verifier

- **Attack:** The conjunction of (scope_id, agent_identity) produces nullifiers to prevent double-use or linking across sessions. If `scope_id` is known to the verifier (Relying Service / RS) — which it must be, since it parameterizes what proof the RS is requesting — and the RS colludes with or IS the Attribute Server (AS), then for every enrolled agent the AS has issued credentials to, the colluding party can precompute the full nullifier table: `nullifier_i = H(scope_id, identity_i)` for all `identity_i` in the issued-credential set. A new proof arrives with nullifier N; a linear scan over 4,700 CU member sets identifies the prover. This is the classic **nullifier-as-pseudonym** deanonymization attack.
- **Why it works:** The construction does not state whether scope_id is AS-private, RS-private, holder-chosen, or public. For "cross-CU shared branching where PenFed verifies a SECU member," PenFed (RS) obviously knows the scope_id of its own session. If PenFed has access to SECU's member list (plausible via data-sharing agreements or regulatory disclosure), precomputation is trivial. The unlinkability claim must specify: *unlinkable against whom?* A passive verifier with no issuer data? A colluding AS+RS? Each is a different game and a different reduction.
- **In-threat-model?** **Not addressed.** The construction must formally define the unlinkability adversary as one of: (a) passive verifier with no issuer-side data, (b) active verifier with partial issuer knowledge, or (c) colluding AS+RS. Claims (b) and (c) require fundamentally different nullifier constructions — e.g., holder-blinded nullifiers using a verifiable oblivious PRF (VOPRF) so the scope_id is unknown to the RS until after the proof is verified, preventing precomputation.


## Persona: cu_ciso

---

### Attack 1: Incident Response Attribution Void

- **Attack:** A fraudulent credential is accepted at my shared-branching terminal — a member withdraws $50K they're not entitled to. My incident response team opens a ticket. I call the construction author and ask: "Which issuer signed the credential that was accepted?" The answer, by design, is: **unknowable to the verifier.** The construction (§ IND-ISS game reduction) explicitly proves that "all public signals are identical between any two issuers signing the same attributes." That's the cryptographic win. It's my forensic nightmare. NCUA Part 748 Appendix B requires a documented incident response program with containment and attribution steps. FFIEC CAT Domain 3 (Cyber Incident Management) requires my IR plan to trace the attack vector. I cannot hand my examiner a proof that was designed to destroy its own provenance.

- **Why it works / why it fails:** The construction does not address a selective-reveal or escrow mechanism for post-hoc issuer disclosure to a regulated authority (e.g., NCUA, law enforcement subpoena). It optimizes for verifier-time hiding without providing a break-glass attribution path. A hash-of-issuer-key encrypted to a regulator escrow key in the public signal would address this, but it's absent.

- **In-threat-model?** No — construction must address. Add a regulated-authority disclosure channel (e.g., escrowed issuer commitment visible only to NCUA-designated key) without breaking issuer-blindness for the verifier.

---

### Attack 2: CUNA Merkle Registry is Unvetted Third-Party Infrastructure

- **Attack:** The construction's deployment scenario names a "CUNA-managed issuer registry of ~4,700 NCUA credit unions" as the source of the Merkle root. I pull out my Vendor Management Policy. CUNA is now a critical infrastructure provider for every credential verification event at my CU. Questions my next NCUA examiner will ask me verbatim: Does CUNA have a SOC 2 Type II covering the Merkle root publication process? What's the RTO/RPO if CUNA's registry is unavailable? What is the staleness tolerance — if CUNA publishes a new Merkle root after a CU's charter is revoked, how long can a revoked-CU credential still verify successfully at my terminal? The construction cites no SLA, no latency bound on Merkle root updates, and no fallback if the root is stale.

- **Why it works / why it fails:** The construction treats the issuer Merkle tree as a static artifact but doesn't model the lifecycle — CU charters are revoked (involuntary liquidations happen; NCUA liquidated 8 CUs in 2023 alone). A revoked CU's key remains valid in the tree until a new root is published and all provers regenerate proofs. The window of invalid-but-verifying credentials is unaddressed and maps directly to GLBA Safeguards Rule §314.4(f) (service provider oversight) and NCUA Part 748 third-party risk.

- **In-threat-model?** No — construction must address. Needs a defined root-update SLA, a revocation bitmap or nullifier set for revoked issuers, and explicit vendor risk language for whoever operates the registry.

---

### Attack 3: Key Compromise is Silent and Uncontainable

- **Attack:** One of the 4,700 CUs in the Merkle tree suffers a signing key compromise — their HSM is exfiltrated in a ransomware incident. The attacker now mints unlimited fraudulent credentials that satisfy `chartered_by_NCUA == true`. Because the issuer is hidden from the verifier, **I cannot add the compromised key to a blocklist at my verification endpoint.** The construction proves constant-size proofs "regardless of issuer-set size," but says nothing about exclusion sets. To revoke that one key, the registry operator must remove it from the tree, publish a new root, and **every existing proof** generated against the old root is now invalid — forcing re-issuance for all 4,699 remaining legitimate CUs' members. NCUA Part 748 requires containment of a breach to limit exposure. This construction, as written, makes surgical revocation architecturally impossible without a mass re-issuance event.

- **Why it works / why it fails:** The IND-ISS security reduction in the construction addresses issuer indistinguishability but does not model the revocation game. The Merkle inclusion proof is irrevocable for any proof generated before a root rotation. The construction needs either (a) a nullifier registry for compromised issuers checked at verification time, or (b) a proof-of-non-revocation witness that references a live, append-only revocation accumulator — neither of which is constant-size without additional argument.

- **In-threat-model?** No — construction must address. The 128B / 600B constant-size claim likely breaks if a non-revocation proof is added honestly.

---

### Attack 4: The Predicate Has No Regulatory Standing

- **Attack:** My examiner asks me to demonstrate how I verified that the member presenting credentials is affiliated with an NCUA-chartered institution. I show them the circuit: `chartered_by_NCUA == true` evaluated inside a Groth16 proof over 8 attribute slots. The examiner's next question: "Who attested that attribute? What's your chain of custody from the NCUA charter database to that bit?" The construction's predicate is an in-circuit boolean evaluated over whatever the issuer put in the credential. There is no normative binding between the Circom attribute slot and an authoritative NCUA data source. The FFIEC CAT and GLBA Safeguards Rule §314.4(c) require that member authentication and third-party verification rely on documented, auditable processes. A ZK predicate over an issuer-asserted attribute is not a documented process — it's a cryptographic assertion with no regulatory chain of custody.

- **Why it works / why it fails:** The construction's formalism proves that *if* the credential attributes are correct, the predicate evaluates correctly, and the issuer key is in the Merkle tree. It does not prove that the issuer populated `chartered_by_NCUA` from an authoritative source, nor does it provide an auditable link to NCUA's own chartering records. An examiner treating this as a third-party data source will ask for the data lineage documentation that doesn't exist in the construction.

- **In-threat-model?** No — construction must address. Needs a normative specification binding credential attribute slots to authoritative regulatory sources (e.g., NCUA chartering database, NMLS for FINRA scenario) with a documented issuance policy that can be reviewed by an examiner — separate from the cryptographic proof.


## Persona: rfc7662_advocate

### Attack 1: AS-Filtered Introspection + OIDC PPID Achieves the Same End-User Property

- **Attack:** A well-configured AS using RFC 7662 with per-RS introspection policy strips all issuer-identifying fields from the introspection response before returning it to PenFed. The AS responds only with `{"active": true, "chartered_by_NCUA": true}` — no `iss`, no `sub`, no `aud`. Pair this with OIDC pairwise pseudonymous identifiers (PPIDs): PenFed sees a pairwise `sub` scoped to itself, so it cannot link the member to SECU or any other CU. The predicate `chartered_by_NCUA == true` is satisfied. The verifier learns nothing about the issuer. Where is the gap?

- **Why it works / why it fails:** It works up to the AS trust boundary. The AS sees the token, knows the home CU, and applies the filter. The AS is a single correlation point with a complete membership graph. C4's IND-ISS game (§ "Formal IND-ISS game") is defined over the *verifier's* view, but the AS is not the verifier — the AS is the adversary in the construction's strongest threat model. RFC 7662 with per-RS policy gives PenFed issuer-blindness; it does not give issuer-blindness to the AS itself. C4 gives issuer-blindness to *everyone*, including the AS, because the issuer key only appears in the private witness.

- **In-threat-model?** Yes — construction survives, but the construction's write-up must explicitly name the AS as an adversary in the IND-ISS game definition. If the threat model only covers the verifier (PenFed), the RFC 7662 approach is a valid, simpler alternative and the ZK overhead is unjustified. The construction must state: *"The AS is a semi-honest or malicious participant; AS-side issuer-blindness is a first-class requirement."*

---

### Attack 2: Signed JWT Introspection Response Removes the AS from the Hot Path Entirely

- **Attack:** `draft-ietf-oauth-jwt-introspection-response` (now heading toward RFC) lets the AS pre-sign a compact JWT containing only the filtered claim set. PenFed receives a signed, self-contained `{"chartered_by_NCUA": true, "exp": ..., "aud": "penfed.org"}` JWT it can verify offline using the AS's public key. The AS is not contacted at verification time. The introspection JWT is constant-size. It is audience-bound via `aud` (RFC 8707 semantics applied to the response). PenFed cannot link it to a home CU. Walk me through how C4's constant-size proof is differentiated.

- **Why it works / why it fails:** The signed JWT introspection response is still *issued by the AS*, which means: (a) the AS performed the issuer-lookup and signed the predicate result — issuer identity transited the AS, (b) the JWT is bound to a specific token, so if the token is reused across RSes, correlation is possible via the token handle even if the JWT contents are stripped, and (c) the AS must be online at issuance time even if not at verification time. C4 never has the AS touch the issuer key at verification time because the member's wallet holds the credential and generates the proof locally. The issuer key is never sent anywhere — not even to an AS.

- **In-threat-model?** Yes — construction survives. However, the construction (§ "Deployment scenario") should explicitly benchmark the latency model: signed JWT introspection imposes one AS round-trip at token issuance; C4 imposes local proof generation (~3s PLONK). For batch or pre-computed proof scenarios, C4 wins on latency. The construction must quantify this rather than leaving it implicit.

---

### Attack 3: Audience-Bound Tokens + DPoP Already Break Cross-RS Linkability Without ZK

- **Attack:** RFC 8707 Resource Indicators force each token to name its intended RS in the `resource` parameter. RFC 9449 DPoP binds the token to the client's ephemeral key pair, making the token non-transferable between RSes. OIDC PPID ensures PenFed sees a pairwise `sub` it cannot correlate with SECU's pairwise `sub` for the same member. In combination: cross-RS linkability is already broken at every RS, the token is sender-constrained, and the predicate can be baked into the token claims by the AS. Name a property C4 provides that this stack cannot provide.

- **Why it works / why it fails:** The DPoP + Resource Indicator + PPID stack breaks *RS-to-RS* linkability but preserves *AS-to-all-RSes* linkability. The AS holds the mapping `(real_sub → {penfed_ppid, secu_ppid, ...})` and issued every token. A subpoena, breach, or malicious AS operator recovers the full graph. C4's issuer-hiding property means the AS never had to know which specific CU credential the member is asserting — the member generates a proof from a locally-held credential signed by SECU, and the AS is not in the loop at all. DPoP cannot provide *AS-side issuer-blindness* because DPoP's sender-constraint is enforced by the AS issuing the token.

- **In-threat-model?** Yes — construction survives. The construction must name this explicitly as *"regulatory compelled disclosure resistance"*: even a lawfully subpoenaed AS cannot produce the issuer-to-member mapping because it was never collected. This is the load-bearing differentiation. Without this framing, reviewers will dismiss C4 as overengineered OAuth.

---

### Attack 4: The Public Merkle Root Is an Issuer-Set Fingerprint That RFC 7662 Deployments Do Not Expose

- **Attack (reversed direction — this one cuts against C4):** The construction uses a depth-16 Merkle tree over ~4,700 NCUA CU public keys, with the Merkle root as a public signal in every proof. The root commits to the *exact membership set*. If CUNA updates the registry (a CU merges, fails, or is added), the root changes. A verifier who sees proofs across root versions can bin proofs by issuer-set epoch. Worse, if a small sub-federation (say, 12 state-chartered CUs) runs their own registry with a distinct root, a verifier trivially learns the prover is from that sub-federation without seeing any issuer key. RFC 7662 deployments have no analogous global commitment — they leak nothing about the issuer-set structure.

- **Why it works / why it fails:** This is a genuine gap the construction does not address. The IND-ISS reduction (§ "Formal IND-ISS game") assumes a fixed, shared issuer-set known to both challenger and adversary, so the Merkle root is a public parameter that does not vary between proofs in the security game. But in deployment, root versioning and sub-federation roots are a real side-channel. An adversary who can observe multiple proofs and query the registry can do set-membership inference even without breaking ZK.

- **In-threat-model?** **No — construction must address this.** The construction should either: (a) mandate a single global root updated on a fixed schedule with proofs always committed to the current root (reducing epoch-based correlation to a coarse time window), (b) use a blinded root technique where the prover commits to the root in a way that hides which epoch's root was used, or (c) explicitly scope the threat model to exclude registry-metadata side-channels and document the residual risk.


## Persona: spiffe_engineer

---

### Attack 1: Federation Already Solves Your Stated Scenarios

- **Attack:** The cross-CU NCUA membership proof is the headline scenario, but SPIFFE trust-domain federation already achieves issuer-hiding at the federation layer. A SPIRE bundle endpoint at CUNA can publish a federated trust domain bundle for `spiffe://ncua.gov/cu/*/member`. PenFed configures a single trust bundle from NCUA — it never sees individual CU keys. The SPIFFE ID encodes membership in the NCUA federation, not the specific home CU. No ZK required. The cross-firm FINRA and cross-country KYB scenarios map identically: each regulatory body operates as a trust domain root; federation hides the leaf issuer.

- **Why it works / why it fails:** The construction never articulates the *attribute-level* gap. Federation hides the issuer identity, but it does not let the holder prove `chartered_by_NCUA == true` without revealing other credential fields. If the use-case is specifically *selective disclosure of a predicate over attributes* — not just membership — then the attack misses the mark. But the construction conflates the two: its scenarios only require "prove membership in the NCUA-supervised set," which federation handles. The construction must identify a scenario where predicate-level hiding — not just issuer-level hiding — is the requirement.

- **In-threat-model?** **No** — the construction must add a scenario where attribute-predicate privacy and issuer-privacy are simultaneously required in a way SPIFFE federation cannot express. "Cross-CU NCUA membership proof" alone does not qualify.

---

### Attack 2: The Merkle Root Is an Epoch Pin — You Have No Rotation Story

- **Attack:** The verifier circuit takes the Merkle root as a public input (it must, otherwise the verifier cannot check the membership proof). That root is a commitment to a specific snapshot of the 4,700-CU registry. Any issuer key addition, removal, or rotation changes the root. PenFed must accept proofs against exactly the root it has stored. If SECU rotates its signing key after a breach, the old root is stale and PenFed either (a) keeps accepting stale-root proofs, breaking forward security, or (b) invalidates all outstanding member proofs until holders re-prove against the new root.

  SPIRE solves this with bundle endpoint federation: CAs rotate continuously, SPIRE agents fetch updated bundles on a configurable TTL, and SVIDs have short validity windows. The construction has no equivalent. The section on "CUNA-managed issuer registry" does not mention root versioning, epoch management, or what happens to in-flight proofs during a rotation event.

- **Why it works / why it fails:** This is a pure liveness/freshness gap. The ZK construction is mathematically sound but operationally frozen — it describes a static registry. If the construction adds a versioned root with a migration path (e.g., a root-of-roots commitment or an on-chain registry with proof-of-inclusion against a rolling commitment), the attack fails. As written, it does not.

- **In-threat-model?** **No** — the construction must specify root rotation mechanics and proof validity windows, or defer to a concrete registry management protocol.

---

### Attack 3: "Arbitrary Schema" vs. Hardcoded 8-Slot Encoding

- **Attack:** The construction claims "arbitrary-schema support" in the top-level claim, then immediately contradicts itself: the circuit has "8 credential attribute slots using a fixed-size predicate encoding." These are not the same thing. JWT SVIDs carry arbitrary JSON claim maps. WIMSE SD-JWT (building on RFC 7519 + draft-ietf-oauth-selective-disclosure-jwt) supports selective disclosure over schemas of arbitrary depth and width without a slot limit. A FINRA-licensed agent credential easily carries 15+ claim fields (CRD number, license type, state registrations, exam dates, firm affiliations). The construction requires the holder to map those fields into 8 pre-allocated slots at issuance time — which means the issuer controls the slot mapping, and any schema change requires a new circuit or a new credential issuance. That is not "arbitrary schema support," it is "schema that fits in 8 slots."

- **Why it works / why it fails:** The attack lands squarely. The BBS+ comparison in the construction is a strawman: BBS+ also supports arbitrary attribute counts (the construction's claim that it "cannot match" is about issuer-key exposure, not schema flexibility). The 8-slot constraint is a real engineering tradeoff — constant-size proofs require a fixed witness layout — but calling it arbitrary is a false claim. The construction should either (a) rename the property to "fixed-arity predicate support" and document the schema mapping protocol, or (b) replace the fixed-slot design with a Merkle-committed attribute tree that admits variable-length schemas at the cost of a slightly larger witness.

- **In-threat-model?** **No** — the "arbitrary-schema support" claim must be retracted or the circuit must be redesigned. This is a specification integrity issue, not just a gap.

---

### Attack 4: IND-ISS Reduction Assumes Non-Adaptive Adversary; Rogue-Issuer Attack Breaks It

- **Attack:** The reduction sketch states that "ZK property of Groth16/PLONK directly implies issuer indistinguishability." This is only correct for a non-adaptive adversary who cannot influence the issuer set. In the NCUA deployment, any NCUA-chartered credit union is a valid issuer in the registry. A rogue CU (or a compromised CU) is a valid tree member. The IND-ISS game must account for an adversary who controls issuer key $k_i$ and queries the credential-issuance oracle to obtain credentials from both $k_i$ and the challenge issuer $k_j$. The adversary then checks whether the circuit's *Merkle sibling path structure* — though entirely private — is consistent with their known position in the tree.

  More concretely: the rogue CU knows it occupies leaf index $l_i$ in the depth-16 tree. It obtains a proof from the challenge credential. The proof is zero-knowledge over the witness, but the *proof size and constraint count are identical* regardless of the path — so path structure leaks nothing. However, the adversary can submit credentials to the verifier and observe accept/reject signals across many epochs as the tree mutates. Differential analysis of which root changes cause a holder's proofs to break can narrow the issuer to a subtree. This is an adaptive chosen-epoch attack, not a chosen-witness attack.

- **Why it works / why it fails:** The reduction to ZK closes the chosen-witness game but leaves the chosen-epoch game open. The formal IND-ISS definition in the construction must include an epoch-oracle and forbid the adversary from observing proof validity across root transitions. If the construction adds this to the game definition and shows the reduction holds under adaptive epoch queries (which requires either a hash-of-hashes commitment or a simulator that can reprogram roots), the attack fails. As written, the "reduction sketch" does not address epoch adaptivity at all.

- **In-threat-model?** **No** — the IND-ISS game definition must be strengthened to include adaptive epoch queries, and the reduction must close under that game before the construction can claim strength 10.
