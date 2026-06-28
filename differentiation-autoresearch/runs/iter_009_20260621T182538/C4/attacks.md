# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: The Onboarding Cliff

**Attack:** The construction assumes a functioning issuer Merkle tree with "4,500+ NCUA-chartered credit unions" enrolled (§7, Scenario 1). Who bootstraps that tree? The PM asks NavyFed's IT team what they need to do to verify a PenFed agent: stand up a Circom prover environment, integrate snarkjs/rapidsnark, ingest and Merkle-hash 4,500 CU public keys, track on-chain `issuerRegistryRoot` updates, and register examiner keys in `examinerKeyRegistry`. Compare to Auth0 MCP auth: copy a client ID and secret, point at the JWKS endpoint, done in 15 minutes. WorkOS handles SAML federation — no new enrollment ceremony, no key ceremony, no tree. The construction's Section 5 ("Bolyra primitive mapping") lists ten distinct primitives that all require operational deployment. Each one is a blocker.

**Why it works / fails:** The construction has no answer. It describes the cryptography with precision but hand-waves "pre-enrolled in the on-chain `examinerKeyRegistry` by NCUA" as if NCUA's IT team will just do this. The IND-ISS security proof is watertight; the go-to-market is not.

**In-threat-model?** No — the construction must address: who runs the issuer registry, what the enrollment SLA is, and how integration compares to a paste-API-key baseline. Without this, the construction is a proof of concept, not a product.

---

### Attack 2: The Latency Tax Compounds in Agentic Workflows

**Attack:** Section 6 claims IssuerBlindPredicate proves in <4.5s (WASM) or <0.8s (rapidsnark native). WorkOS and Auth0 issue OAuth tokens in <100ms on their CDN edges. The PM points out that agentic workflows don't make one tool call — they make 20–60 per task. If every tool invocation requires a fresh handshake proof (because `sessionNonce` must be fresh per §2's nullifier design to prevent replay), the latency tax is 0.8s × 40 calls = 32 seconds of pure proof generation overhead per task. The construction binds the nullifier to `sessionNonce` specifically to prevent replay, which means the prover cannot amortize proof cost across calls within a session without weakening the anti-replay guarantee.

**Why it works / fails:** The construction partially acknowledges this ("< 5s PLONK agent budget") but only for the single-call case. It does not address whether `sessionNonce` can safely be scoped to a session (rather than a call) without leaking the issuer across calls. If `sessionNonce` is reused within a session, the nullifier is the same across calls — a verifier aggregating logs could attempt cross-call correlation. The construction is silent on session-level nonce scoping.

**In-threat-model?** No — the construction must specify whether per-session or per-call nonce semantics are required and, if per-session is safe, demonstrate that the amortized latency is acceptable. If per-call is required, it must benchmark against Auth0's <100ms baseline and explain why the operator accepts a 10× latency penalty even with rapidsnark.

---

### Attack 3: Regulatory Opinion Risk — The Compliance Claim Is Unverified

**Attack:** Section 7 asserts that IssuerReveal "satisfies 12 CFR §748.1(b)," "satisfies FINRA Rule 4511," and "satisfies FATF Recommendation 10." These are the author's legal interpretations, not agency guidance. The PM pulls up the actual 12 CFR §748.1(b) text: it requires records to be "readily available" and "accurately retrievable." A ZK proof generated on demand by the prover is not a record held by the institution in the agency's sense — it is a computation the prover could theoretically refuse to generate (credential material deleted, key lost). PenFed's general counsel will ask: "Has NCUA issued a no-action letter or examination guidance accepting ZK proofs as §748 records?" The answer is no. Auth0 issues SAML assertions. SAML assertions are already in NCUA's examination toolbook.

**Why it works / fails:** The construction correctly describes what the protocol *can* compute but conflates cryptographic capability with regulatory acceptance. The regulatory compliance section (§3) is the weakest part of the document — every compliance claim is hedged with "satisfies because" followed by the author's own interpretation. This is the exact question PenFed's procurement committee will escalate to outside counsel, who will recommend the established vendor.

**In-threat-model?** No — the construction must either (a) cite actual agency guidance or (b) explicitly scope the compliance claim to "technically sufficient to satisfy the record-availability requirement if the agency accepts ZK proofs" and flag that regulatory acceptance is a go-to-market dependency, not a solved problem.

---

### Attack 4: The BBS+ Comparison Is a Strawman — Client Attestation Already Exists

**Attack:** Section 8 ("Why the baseline cannot match") exclusively benchmarks against BBS+ and W3C VC-DI. The PM pulls up `draft-ietf-oauth-attestation-based-client-auth` (Client Attestation, now in IETF Last Call as of Q1 2026) and Cloudflare's enterprise MCP deployment. Client Attestation lets a client prove "I was minted by attester X" without the verifier directly verifying against a specific issuer key — the attestation JWT is signed by the attester, but the verifier only needs to trust the attester registry, not the individual client. The issuer-hiding property is not identical to IND-ISS, but for the stated scenarios (cross-CU NCUA membership, FINRA licensing), the verifier *already knows* the attester set is "all NCUA-chartered CUs" and doesn't need strict issuer unlinkability — it needs to know the predicate holds and the credential is legitimate. Client Attestation + Dynamic Client Registration (RFC 7591) gives NavyFed exactly that, in <100ms, with standards-body backing and Auth0/WorkOS implementation today. The construction never addresses this alternative.

**Why it works / fails:** The IND-ISS game provides a formal privacy guarantee that Client Attestation does not — if NavyFed is colluding with another CU to identify which CU PenFed is, Client Attestation leaks that information because the attester's public key is visible. But the construction never argues *why* verifier-side issuer unlinkability is a real operational requirement for NCUA members interacting with each other. The business case for strict IND-ISS among mutually regulated entities under the same charter authority is not made. The PM asks: "Show me a credit union that told you they need to hide their identity from another NCUA-chartered credit union." Without that, Client Attestation is the simpler answer.

**In-threat-model?** No — the construction must (a) address Client Attestation directly, not just BBS+, and (b) articulate a concrete buyer scenario where verifier-side issuer unlinkability is a hard requirement, not just a nice-to-have privacy property that the construction's cryptography supports.


## Persona: cryptographer

Applied cryptographer, IACR publications, skeptical of constructions where the security argument is looser than the claims. I read the reduction sketches in §4 first, then work backwards to find where the proof breaks.

---

### Attack 1: Nullifier Conflation Breaks Multi-Principal Replay Protection

**Attack:** Two agents — call them P₀ and P₁ — hold credentials from *different* issuers (Issuer₀ ≠ Issuer₁) but with identical attribute vectors `attrValues` and identical `expiryTimestamp`. For any given `sessionNonce`, they produce the *same* `credNullifier`:

```
credCommitmentBlind₀ = Poseidon2(PoseidonN(A), E)   # no issuer term
credCommitmentBlind₁ = Poseidon2(PoseidonN(A), E)   # identical
credNullifier₀ = credNullifier₁
```

This is load-bearing by design (§2: "The nullifier cannot be correlated across presentations to de-anonymize the issuer"). But it also means that any on-chain nullifier registry — which is the only replay-prevention mechanism for PLONK-style proofs — cannot distinguish a genuine replay from a second legitimate holder with matching attributes.

**Concrete exploitation:** In the cross-CU NCUA scenario (§7, Scenario 1), a malicious agent P₀ can monitor the mempool for P₁'s IssuerBlindPredicate proof, extract the `sessionNonce` from the public inputs, generate their own proof with the same `sessionNonce` and matching attributes, and submit first. P₁'s proof is rejected as a replay. The construction calls this a feature (issuer-hiding); from a soundness perspective it is a griefing vector with zero cryptographic cost.

**Why the reduction doesn't capture it:** The IND-ISS game in §3 is a *single-prover* game. There is no adversary that controls P₀ and observes P₁. Multi-principal interactions are entirely outside the security model. The game definition as written cannot distinguish "two agents with the same attributes" from a single agent replaying, because the game doesn't include a principal-identity binding.

**Fix required:** The nullifier must incorporate a per-agent blinding factor (e.g., an identity commitment or secret salt) that survives issuer-blinding. Without this, the construction provides issuer-anonymity at the cost of agent non-collision.

**In-threat-model?** No — the construction must address this.

---

### Attack 2: IssuerReveal Circuit Has an Unverifiable Nullifier Binding (sessionNonce Missing from Witness)

**Attack:** Read the IssuerReveal private-input list (§2) carefully:

> `issuerPubkeyAx`, `issuerPubkeyAy`, `attrValues[MAX_ATTRS]`, `expiryTimestamp`, `examinerPubkeyAx`, `examinerPubkeyAy`, `examinerEncNonce`

`sessionNonce` is **not listed**. Yet Constraint 1 of IssuerReveal states:

> "Recompute `credCommitmentBlind = Poseidon2(PoseidonN(attrValues), expiryTimestamp)`, then verify `credNullifierCheck = Poseidon2(credCommitmentBlind, sessionNonce)` equals the provided `credNullifier`."

A Circom circuit cannot constrain a signal it has no access to. One of three things is true in any implementation that follows this spec: (a) the circuit fails to compile (dangling signal reference), (b) `sessionNonce` is hardcoded to zero or some constant, breaking the binding for any real session, or (c) this is a specification omission and `sessionNonce` must be added as a private or public input.

**Why (b) is the exploitable case:** If an implementation defaults `sessionNonce = 0`, then IssuerReveal only proves consistency with credentials that were originally generated under `sessionNonce = 0`. Any credential issued under a real session nonce ≠ 0 would fail the IssuerReveal binding — but an adversary can generate a fresh IssuerBlindPredicate proof with `sessionNonce = 0`, get `null_0`, then produce an IssuerReveal linking to `null_0` that encrypts an *arbitrary* issuer key `pk_adv` (not the one that signed the credential). DV-SOUND's reduction (§4) invokes knowledge soundness to extract the witness, but the extractor finds only `(attrValues, expiryTimestamp, issuerPubkey, examinerEncNonce)` — the binding to the *original* session is absent from the extracted witness, so the reduction cannot verify the link to the prior blind proof.

**Why this matters for the regulatory model:** The entire 12 CFR §748 / FINRA Rule 4511 argument (§3, §7) rests on IssuerReveal proving "the disclosed issuer is the TRUE signer of the credential behind `credNullifier`." If the binding is broken, the regulatory escape hatch reduces to a self-attestation with a ZK wrapper — exactly what the construction claims to improve on.

**In-threat-model?** No — this is a concrete soundness gap in the circuit specification that must be repaired before the DV-SOUND claim is meaningful.

---

### Attack 3: IND-ISS Reduction is Vacuous — It Proves ZK, Not Issuer Hiding

**Attack:** The reduction sketch in §4 reads:

> "Construct simulator S that invokes the ZK simulator to produce a simulated proof π* (which is independent of the witness, hence independent of which issuer signed). If A distinguishes π* from a real proof, A breaks ZK."

This proves that **simulated proofs** don't leak the issuer. But IND-ISS gives the adversary a **real proof**, not a simulated one. The argument needs two steps:

1. Real proof ≈ₛ simulated proof (ZK property)
2. Simulated proof leaks nothing about which issuer signed (follows from the simulator being witness-independent)

Step 1 is the ZK property. But the ZK property of PLONK under Fiat-Shamir (ROM) is **honest-verifier ZK**: it holds when the verifier's random coins (the hash challenges) are generated honestly. In IND-ISS, the adversary A *controls* the session context — it chose `(iss_0, iss_1, attrs)` and presumably interacts with the challenger. If A can influence the `sessionNonce` (which appears as a public input and in practice comes from a challenge the verifier generates), A plays the role of a possibly-adversarial verifier.

Under malicious-verifier, PLONK does not guarantee ZK without an additional simulation-soundness argument. The construction claims AGM+ROM provides simulation extractability (§4, Assumptions), which is a strictly stronger property than HVZK, but: (a) simulation-sound ZK under AGM+ROM applies to the *extraction* direction (knowledge soundness), not to the *hiding* direction. The ZK property under AGM is not the same as SE-ZK. The Fiat-Shamir transform for PLONK achieves NIZK in the ROM, which is sufficient for ZK under adaptive adversaries in the ROM — but the construction needs to state this explicitly rather than conflating AGM (used for knowledge soundness) with the ZK argument.

**Concretely:** The reduction as written does not establish a hybrid argument. It jumps directly from "ZK simulator exists" to "A can't distinguish" without explicitly constructing the hybrid. A proper proof needs:

- Hybrid₀: Real proof for `iss_b`
- Hybrid₁: Simulated proof (by ZK) — indistinguishable from Hybrid₀ under ZK
- Hybrid₁ is manifestly independent of `b` (simulator has no witness)
- Therefore A's advantage in Hybrid₀ ≤ Adv_ZK

The reduction sketch skips the hybrid and jumps straight to "hence A breaks ZK." This is the right intuition but not a proof. Under malicious `sessionNonce`, the ZK property must be invoked carefully — specifically whether the ROM simulation in Fiat-Shamir handles adversarially chosen public inputs before the hash query. In standard Fiat-Shamir PLONK, public inputs are committed before the verifier's challenges, so they can be adversarial — but the reduction must account for the RO programming.

**In-threat-model?** Partially. The construction survives if the ZK argument is tightened to a proper hybrid with explicit ROM programming. As written, the reduction is a proof sketch with a logical gap, not a proof.

---

### Attack 4: Predicate Compiler Trust is an Unmodeled Assumption

**Attack:** The verifier checks `predicateHash` against an expected value H_expected representing "chartered_by_NCUA == true." The construction's security relies on Poseidon collision resistance ensuring no two semantically distinct instruction vectors share the same hash. This is correct. But there is a prior unmodeled trust assumption: **who compiled H_expected, and how does the verifier know it encodes the intended predicate?**

The `predicateInstructions` are `(opcode, src1, src2, dst)` tuples. The spec defines opcodes EQ, NEQ, AND, OR, NOT, LT, IN_SET, but does not define whether `src1`/`src2` are **attribute slot indices** or **intermediate register indices**. This distinction matters:

- `EQ(attr_slot_k, 1)` — attribute slot k equals `true` (non-trivial)
- `EQ(reg_0, reg_0)` — register 0 equals itself (always true, regardless of attributes)

Both are valid `EQ` instructions under the spec as written. An adversary who controls predicate compilation (e.g., a compliant-appearing agent that submits predicate hash H to a naïve verifier) can construct an instruction vector that evaluates to `1` via a tautological register comparison, producing a valid `predicateHash` H_tautology ≠ H_expected. The verifier rejects H_tautology — so this fails against an honest verifier who checks H_expected.

But: in a multi-party deployment where **verifiers accept any valid `predicateHash` paired with `predicateResult = 1`** (e.g., a permissionless smart contract that checks "prove ANY predicate evaluates true"), the prover can submit tautological instruction vectors. The construction does not formally define what it means for the verifier to "know which predicate was evaluated." The `predicateHash` is a binding commitment, but the semantic interpretation of what that hash *means* — the mapping from predicate text to canonical instruction vector — is outside the security model entirely.

**Formal statement of the gap:** The IND-ISS game says nothing about predicate soundness — only about issuer indistinguishability given that *some* predicate was satisfied. There is no game definition for "the predicate that evaluates to 1 is actually the one the verifier intended." Without a canonical compiler and a registry of (predicate_text → predicateHash) mappings, the `predicateHash` provides binding but not semantic security. A verifier who doesn't independently verify the hash-to-predicate mapping is relying on prover honesty, not on cryptographic guarantees.

**In-threat-model?** No — the construction must define a canonical predicate language and compiler, specify how verifiers obtain trusted H_expected values (on-chain predicate registry?), and add a predicate-soundness game to the formal model. Without this, the "arbitrary-schema support" claim is operationally undefined.


## Persona: cu_ciso

---

### Attack 1: Examiner Key Registry Has No Governance Owner

**Attack:** I ask your compliance team: who enrolled the NCUA examiner's public key into `examinerKeyRegistry`, and how do I know that entry is authentic? The construction (§3 Regulatory compliance model, §7 Scenario 1 Step 6) simply states the examiner's key is "pre-enrolled in the on-chain `examinerKeyRegistry` by NCUA." But NCUA does not operate blockchain infrastructure, does not publish Baby Jubjub public keys, and has no published key-enrollment process. If my examiner's key is rotated mid-examination (happens regularly — examiners change laptops, agencies rotate credentials), the `IssuerReveal` proof I generated is encrypted to a stale key. The decryption fails. My audit trail is now an unusable ciphertext. Under **12 CFR §748.1(b)**, I must maintain records in a form that permits reasonable access. A ciphertext the examiner can no longer decrypt is not a record — it is a liability. Further: if the `examinerKeyRegistry` admin key is compromised, a hostile party could substitute a fake examiner key. My IssuerReveal proof would then encrypt my issuer identity to an attacker, not to NCUA — and I'd have no way to detect this before generating the proof.

**Why it works against the construction:** §7 Scenario 1 delegates governance to "NCUA" without providing a governance model, a root of trust, or a key rotation procedure. The on-chain registry protects confidentiality only if the enrollment process is trustworthy, and that trust chain is entirely unspecified. The IND-ISS and DV-PRIV games in §3 assume `examinerPubkey` is authentic — the construction does not prove authenticity of the registry itself.

**In-threat-model?** No — construction must address. Needs: a defined key-enrollment authority (e.g., NCUA signs examiner keys with an offline root), a key rotation protocol that links old and new keys via `credNullifier`, and a recovery path when decryption fails.

---

### Attack 2: The Audit Trail Is Cryptographically Opaque to the Examiner

**Attack:** During my NCUA examination under **12 CFR §741**, the examiner asks me to demonstrate that my agent's cross-CU proof is attributable to PenFed. I hand them a `disclosureTag = Poseidon3(credNullifier, examinerPubkeyHash, encIssuerC1x)` and an ElGamal ciphertext on Baby Jubjub. The examiner — working from a standard NCUA examination laptop with SAR software, Excel, and a PDF reader — has no idea what to do with this. They need to: (1) run a Baby Jubjub ElGamal decryption, (2) verify a PLONK proof on-chain, (3) resolve the recovered EC point to an issuer identity in a Merkle registry. The construction (§7 Scenario 1 Step 8) states the examiner "verifies the ZK proof on-chain" and the `disclosureTag` is "an immutable audit record satisfying 12 CFR §748.1(b)." Satisfying §748.1(b) requires that the record be "reasonably accessible" — not that it be cryptographically sound. There is no examiner-facing workflow described, no reference implementation, no tooling contract with NCUA. Under the **FFIEC CAT Cybersecurity Assessment Tool Domain 2** (Threat Intelligence) and **Domain 3** (Cybersecurity Controls), I am expected to demonstrate that my controls are testable and verifiable by examiners. A control that requires the examiner to run custom cryptographic software is not testable in an ordinary examination.

**Why it works against the construction:** The regulatory compliance claims in §3 (12 CFR Part 748, FINRA Rule 4511, FATF R.10) are made at the legal-citation level but not at the operational level. The construction proves the *existence* of a disclosure mechanism but does not show that mechanism produces output a regulator can consume with existing tooling.

**In-threat-model?** No — construction must address. Needs: a defined examiner-facing workflow (web portal? signed PDF export? API call to NCUA's existing examination system?), a reference to NCUA's actual records format requirements, and ideally a pilot or MOU that NCUA has acknowledged.

---

### Attack 3: No Credential-Level Revocation — Stolen Credential Runs Forever

**Attack:** My Tier 1 ops team calls at 2am: an agent credential was exfiltrated — `attrValues`, `expiryTimestamp`, and the issuer signature (`issuerSigR8x/y/S`) are all in a threat actor's hands. I open an incident under **12 CFR §748.1(b)** and the GLBA Safeguards Rule **16 CFR §314.4(h)** (incident response). I need to revoke this credential immediately. The construction defines `credNullifier = Poseidon2(credCommitmentBlind, sessionNonce)` where `sessionNonce` is fresh per session. This means the nullifier is **session-scoped, not credential-scoped**. There is no unique credential identifier that would let me blacklist the stolen credential at the registry level. The attacker generates new proofs with fresh session nonces indefinitely — each one produces a fresh nullifier that does not collide with any prior seen nullifier. The only revocation mechanism I can infer from the construction is waiting for `expiryTimestamp` — but if I issued a credential valid for 90 days, I have a 90-day exposure window with no kill switch. Under NCUA's third-party risk guidance (**Supervisory Letter 07-01**) and the **FFIEC Information Technology Examination Handbook**, I must demonstrate the ability to respond to and contain unauthorized access. "Wait for expiry" is not a containment strategy.

**Why it works against the construction:** Section 5 (Bolyra primitive mapping) maps the nullifier to "standard Bolyra agent nullifier pattern" but does not define a credential commitment revocation registry. The threat model (§3) focuses on issuer-hiding and designated-verifier soundness but never models an adversary who *steals the credential material itself* — only one who forges proofs. Stolen-but-valid credentials are out-of-scope for the IND-ISS game, and the DV-SOUND game assumes the adversary cannot produce a valid disclosure proof for a credential they don't hold. But if they *do* hold it because they stole it, both games are moot.

**In-threat-model?** No — construction must address. Needs: a credential-level nullifier or commitment that can be added to an on-chain revocation set, a defined revocation latency SLA, and a 2am ops runbook that does not require cryptographic expertise.

---

### Attack 4: Third-Party Vendor Risk With No SOC 2, No SLA, Testnet Chain

**Attack:** My board's Vendor Management Policy, required under **NCUA Part 748 Appendix A** and **FFIEC Third-Party Relationships guidance**, requires that any critical technology provider demonstrate: financial stability, a SOC 2 Type II audit, a defined SLA with remedies, business continuity and disaster recovery documentation, and a data processing agreement covering member data. Bolyra's deployment scenario (§7) targets Base Sepolia — a testnet chain. Even if production moved to Base mainnet, the on-chain registry has no published uptime SLA. The PLONK SRS (`pot16.ptau`) is a trusted setup artifact from an external ceremony — if the ceremony was compromised, every proof generated against it is unsound, and I have no contractual recourse. The construction benchmarks proving time at `< 0.8s (rapidsnark native)` but says nothing about what happens when the native prover binary is unavailable or when the chain is congested and registry reads fail. My core processor (Symitar, Corelation) publishes a 99.95% uptime SLA. The CISO attack prompt is direct: "If your on-chain registry has a 1% outage budget, that's more than my core processor." Mapping under **FFIEC CAT Domain 4** (External Dependency Management): I cannot clear the third-party risk checkbox for a vendor with no SOC 2, no SLA, and infrastructure on a chain that does not publish uptime guarantees.

**Why it works against the construction:** The entire §7 deployment scenario reads as a technical integration guide, not an operational readiness document. The "why the baseline cannot match" section (§8) compares against BBS+/W3C VC on cryptographic dimensions only. My examiner does not score me on cryptographic novelty — they score me on whether I can demonstrate vendor oversight. Nothing in the construction addresses the regulatory procurement and vendor management layer that any CU must clear before deploying a new authentication mechanism.

**In-threat-model?** No — construction must address. Needs: a defined operational layer (who operates the registry, under what SLA), a path to SOC 2 Type II audit coverage, a fallback mode for registry unavailability (offline credential cache? local Merkle snapshot?), and a clear statement of what "member data" — if any — transits through Bolyra infrastructure and how that is governed under the GLBA Safeguards Rule.


## Persona: rfc7662\_advocate

---

### Attack 1: Filtered Introspection Response — "The AS Already Hides the Issuer for the RS"

**Attack:**
RFC 7662 §2.2 permits the AS to return any subset of claims. A well-configured AS returns exactly `{"active": true, "chartered_by_NCUA": true, "exp": ..., "sub": <PPID>}` — full stop. NavyFed (the RS) never sees the issuer field. The AS policy layer is the privacy mediator. This is not hypothetical: FAPI 2.0 profiles mandate per-RS claim filtering today.

The construction's §8 ("Why the baseline cannot match") attacks BBS+ exclusively. It never addresses this attack surface. The claim in §1 is "verifier learning which issuer signed" — RFC 7662 with AS-side policy eliminates exactly that disclosure for the RS.

**Why it works / why it fails against the construction:**
The construction *does* achieve more — the AS itself cannot correlate issuer→verifier tuples because it is not in the loop. But §3 (threat model) never defines a threat actor that *is* the AS. Games IND-ISS, DV-SOUND, and DV-PRIV all treat the AS as implicitly trusted or absent. If the AS is honest (the RFC 7662 deployment assumption), the RS-level privacy property is identical.

The construction must either (a) add an explicit AS-compromise threat actor to the game definitions, or (b) formally argue why the AS's *knowledge* of the issuer-verifier mapping is independently harmful even when the AS behaves correctly.

**In-threat-model?** No — construction must address.

---

### Attack 2: JWT Introspection Response Removes the AS from the Hot Path — "Offline Verifiable Predicates Without ZK"

**Attack:**
`draft-ietf-oauth-jwt-introspection-response` (now RFC 9701) allows the AS to issue a *signed JWT* containing introspection results. This JWT is presented directly to the RS — no real-time AS call. The RS verifies the AS signature offline.

The AS issues this JWT at credential-issuance time or on first use: `{"chartered_by_NCUA": true, "iss": "https://bolyra-as.example", "aud": "navyfed.example", "sub": <PPID>}`. The issuer is abstracted; the RS verifies a predicate offline with constant-size output (a signed JWT). The construction's benchmark in §6 shows IssuerBlindPredicate at < 4.5s (snarkjs WASM) or < 0.8s (rapidsnark). A JWT signature verification runs in microseconds.

**Why it works / why it fails against the construction:**
The ZK construction's root of trust is the *issuer's EdDSA key in the witness*. The JWT's root of trust is the AS signing key. If the AS is compromised or coerced, it asserts false predicates for any issuer — the RS has no cryptographic recourse. Knowledge soundness (PLONK, §4) means a forged ZK proof requires breaking the underlying assumption, not merely coercing an operational party.

However: the construction never quantifies this gap. §8 does not include a "trusted-AS failure mode" scenario. The benchmark comparison in §6 lists only BBS+ proving times, not JWT verification times. The adversary's argument — "AS coercion is an operational risk handled by SOC2/examination authority, not a cryptographic gap requiring ZK" — is unanswered in the construction.

**In-threat-model?** No — construction must benchmark against JWT introspection latency and explicitly argue why AS-key compromise is in-scope when BBS+ issuer-key exposure is in-scope.

---

### Attack 3: RFC 8693 Token Exchange Achieves the Regulatory Escape Hatch Without ZK

**Attack:**
The IssuerReveal circuit (§2, "Designated-Verifier Disclosure Circuit") is the construction's regulatory compliance mechanism. RFC 8693 §2.1 defines an `actor` claim and a full token exchange flow:

1. Agent holds original token (`chartered_by_NCUA: true`, issuer abstracted).
2. During NCUA examination, agent calls the AS's token-exchange endpoint with `requested_token_use: actor` and examiner audience `aud: ncua-examiner.example`.
3. AS issues a new token to the examiner with full issuer attribution and signs it with the examiner's audience binding (RFC 8707).
4. Examiner verifies issuer identity via standard JWT validation — no ZK circuit required.

This matches the IssuerReveal operational model in §7 (Scenario 1, steps 5-9) almost exactly. The `disclosureTag` in the ZK construction is a Poseidon hash providing audit-trail linkage; the RFC 8693 exchange produces a standard `jti`-linked audit record. Both satisfy 12 CFR §748.1(b) records requirements.

**Why it works / why it fails against the construction:**
The construction's DV-SOUND game (§3) requires that the examiner receives a *cryptographic proof* that the disclosed issuer actually signed the credential — not an AS assertion. RFC 8693 exchanges delegate to the AS's assertion: the examiner trusts the AS said "PenFed." The ZK IssuerReveal proof lets the examiner verify without trusting the AS.

But this advantage is only load-bearing if the AS is an adversary in the regulatory model — specifically, if the AS might collude with the credential holder to misrepresent the issuer. In practice, NCUA examination authority includes subpoena power over the AS. The construction's DV-PRIV and DV-SOUND games do not include a colluding AS. The argument that the examiner gains *cryptographically verifiable* attribution (not AS-mediated) is correct but unquantified against the regulatory framework actually cited (12 CFR §748).

**In-threat-model?** Partially — the ZK proof provides a strictly stronger guarantee (AS-coercion resistance), but the construction does not demonstrate that the cited regulations *require* this strength rather than merely permitting it. Must address.

---

### Attack 4: Audience-Bound PPIDs Already Break the Cross-RS Linkability the Anonymity Set Defends Against

**Attack:**
The construction's primary scenario (§7, Scenario 1) claims that NavyFed "cannot distinguish PenFed from any of the 4,500 other NCUA-chartered CUs." The IND-ISS game formalizes this.

OIDC pairwise pseudonymous identifiers (OIDC Core §8.1) + RFC 8707 resource indicators already achieve the operationally relevant property: NavyFed sees a PPID for the agent that is mathematically independent of what other RSes see. Cross-RS linkability — the scenario where NavyFed and a third RS correlate the same agent — is broken at the RS layer without any knowledge of the issuer.

The adversary's question: the anonymity set of 4,500 issuers protects against what exact attack? If NavyFed cannot link the agent across RSes (PPIDs), and cannot see the issuer (AS-filtered introspection), the remaining threat is: NavyFed *infers* the issuer from the agent's behavioral fingerprint or from out-of-band information. That inference attack is orthogonal to the cryptographic construction — it is not defeated by IND-ISS because it doesn't operate on the proof.

The construction in §3 defines IND-ISS as adversary A receiving the proof and public signals. But A in the PPID + RFC 8707 stack also receives only a PPID-bound token with filtered claims — the same information reduction, achieved without a ZK circuit.

**Why it works / why it fails against the construction:**
The ZK construction provides a stronger property: even the *AS* cannot link issuer to verifier after proof generation, because the proof is generated client-side with no AS interaction. PPIDs protect RS-to-RS correlation but the AS retains full knowledge. Whether AS-knowledge is a threat depends on the threat model — which §3 never enumerates as a named adversary class.

Additionally: the PPID approach has a concrete limitation the construction doesn't exploit — PPIDs require pre-registration between agent and RS, making cold-start cross-CU interactions (e.g., a PenFed agent connecting to a NavyFed API for the first time) require AS-mediated discovery. The Bolyra proof is AS-independent and works for any RS that has the registry root. This is a real operational advantage but is not stated as such in the construction's §8 comparison.

**In-threat-model?** No — the construction must add a "AS-knowledge of issuer-verifier correlation" adversary to the threat model, or explicitly scope the claim to the AS-is-adversary case and justify why that scope is the relevant one for the cited regulatory scenarios.


## Persona: spiffe_engineer

---

### Attack 1: NCUA-Operated Trust Domain Makes §2's 53K-Constraint Circuit Unnecessary

- **Attack:** The construction's primary deployment scenario (§7, Scenario 1) is a cross-CU NCUA membership proof. In standard SPIFFE/SPIRE, NCUA operates a trust domain `spiffe://ncua.gov`. Every NCUA-chartered CU registers its workloads with the NCUA-operated SPIRE server, receiving JWT SVIDs bearing claim `chartered: true` and a privacy-preserving path component — e.g., `spiffe://ncua.gov/chartered/<anon-id>` where `<anon-id>` is an opaque rotation token, not the CU name. NavyFed configures trust for `spiffe://ncua.gov/*`. It learns the predicate holds (`chartered_by_NCUA == true`) but learns nothing about which CU holds the SVID. The IND-ISS game (§3, Game 1) is irrelevant because issuer-blindness falls out of the trust-domain structure at zero marginal cost — no 53K-constraint circuit, no `issuerMerkleProofSiblings`, no `credCommitmentBlind` nullifier engineering.

- **Why it works / why it fails:** The construction silently assumes a decentralized trust model where CUs self-issue credentials and no party like NCUA will operate a SPIRE server. That is an organizational assumption, not a cryptographic one, and the construction never states it. If NCUA is willing to run a SPIRE cluster (which is precisely what a federal regulator with 4,500+ chartered entities and a compliance mandate should do), the IssuerBlindPredicate circuit solves a non-problem at high complexity cost.

- **In-threat-model?** No. The construction must acknowledge the delegated-issuance SPIFFE architecture and justify why CUs will not federate under NCUA's trust domain. The only valid answer is "CUs refuse to let NCUA issue their agent SVIDs" — which is a real constraint, but it needs to be stated as a design axiom, not left implicit. Otherwise, the entire §2 circuit is unjustified overhead against a simpler baseline.

---

### Attack 2: WIMSE Token Exchange Already Standardizes the Predicate Case

- **Attack:** The predicate evaluation gadget in §2 — 32 compiled instruction slots, `(opcode, src1, src2, dst)` tuples, `predicateHash` binding — is functionally a **policy engine** that transforms a credential into a scoped access token attesting predicate satisfaction. This is exactly what the WIMSE architecture (draft-ietf-wimse-arch §6, "workload-to-workload token exchange") defines: a workload presents its SVID to an exchange endpoint, the endpoint evaluates a policy (arbitrary Boolean expressions over claims), and issues a short-lived scoped token. The scoped token is constant-size. The `predicateHash` public input in §2 is operationally identical to a WIMSE `policy_id` claim in the exchanged token. The construction (§1) claims "constant-size proof and arbitrary-schema support" as distinguishing properties — both hold for a signed JWT SVID from a WIMSE exchange endpoint. The construction does not cite WIMSE at all, which is notable given that co-authors of the WIMSE draft are actively scoping selective disclosure and credential transformation.

- **Why it works / why it fails:** The construction's counter-argument would be that WIMSE requires a trusted exchange endpoint (the policy-evaluation service), introducing a liveness and trust dependency. In the ZKP construction, the prover generates the predicate proof locally without any online exchange service. That is a legitimate advantage — the construction is *endpoint-free* for the verifier. However, the construction never makes this argument. §8 compares against BBS+ exhaustively but does not mention WIMSE, which is the actual near-term IETF competition. A standards body reviewing this construction will immediately ask why the authors are not contributing predicate-compilation semantics upstream to WIMSE rather than defining a parallel protocol.

- **In-threat-model?** No. The construction must add a §8 comparison row for WIMSE specifically addressing: (i) the trusted exchange endpoint dependency, (ii) the liveness requirement, (iii) the fact that WIMSE token exchange leaks the exchange endpoint URL to verifiers (which may correlate to issuer domain). Without this, the "why not contribute to WIMSE" objection is unanswered.

---

### Attack 3: IssuerReveal's Prover-Initiated Model Collapses Under Adversarial Examination

- **Attack:** The regulatory escape hatch (§3, "regulatory compliance model"; §7, Scenarios 1–3) rests on a critical unstated assumption: the prover cooperates. The construction states "the IssuerReveal proof is generated **only** when the prover elects to cooperate" (§2, Operational model). In SPIFFE, the SPIRE server's issuance log is **not** under the prover's control — the examiner queries the SPIRE audit database directly, and the entity under examination cannot prevent this. In the Bolyra construction, the prover must: (i) retain the private inputs (`attrValues[MAX_ATTRS]`, `issuerSigR8x/y/S`, `expiryTimestamp`) after the fact, (ii) correctly identify which `credNullifier` corresponds to the transaction under examination, and (iii) generate a valid IssuerReveal proof on demand. If the prover is the subject of a fraud examination under 12 CFR §741.12, they can claim technical inability, assert that private inputs were rotated, or generate a valid IssuerReveal proof that links to a `credNullifier` from a *different* transaction. The construction's §3 claim that this "satisfies 12 CFR §748.1(b)" is asserted, not argued. §748.1(b) requires records to be "maintained and preserved" — a prover-side cryptographic operation is not a maintained record, it's a computation that can fail or be withheld.

- **Why it works / why it fails:** The construction has a partial answer: the `disclosureTag` is logged on-chain as an immutable audit record (§3, FINRA Rule 4511). But this only records that a disclosure happened — it doesn't help when no disclosure has been made yet and the examiner is trying to compel one. The construction needs a stronger claim here: either (a) prover-side key management requirements that make private input loss a regulatory violation in itself, or (b) an escrow mechanism where a trusted third party holds the witness. Neither is described.

- **In-threat-model?** No. The construction claims regulatory compliance but only models the cooperative prover case. An adversarial-prover model is missing. A SPIFFE comparison here is not just stylistic — SPIFFE's server-side issuance log is architecturally non-repudiable, and the construction must explain how it achieves equivalent non-repudiation without a server.

---

### Attack 4: The Issuer Registry Merkle Tree Has No Issuer-Key Revocation Mechanism

- **Attack:** The `issuerRegistryRoot` (§2, public input to IssuerBlindPredicate) is the root of a depth-10 Merkle tree of issuer public keys. The construction describes adding issuers but never describes removing or rotating them. In SPIFFE, X.509 SVID TTLs (typically 1 hour) are the primary revocation mechanism — compromised workload keys are simply not re-issued. The SPIRE server's WorkloadAPI pushes fresh SVIDs continuously. In the Bolyra construction, if a CU operator's EdDSA key (`issuerPubkeyAx`, `issuerPubkeyAy`) is compromised, the attacker can generate IssuerBlindPredicate proofs indefinitely until an on-chain transaction updates the `issuerRegistryRoot`. Any proof generated against the old root with the compromised key verifies correctly — the `credNullifier` binds to the credential commitment, not to the issuer key (§2, "issuer-free"), so there is no issuer-key-based revocation lever. The construction's `nullifier` prevents replay of a specific credential but does not prevent a compromised issuer from minting new credentials continuously with fresh `sessionNonce` values, all producing distinct valid nullifiers.

- **Why it works / why it fails:** The construction might argue that the on-chain registry update invalidates the old `issuerRegistryRoot`, and verifiers must reject proofs against stale roots. This is true but introduces a root-freshness synchronization requirement that is not specified — what is the maximum acceptable root staleness? How do mobile provers learn about root updates? In the cross-CU scenario (§7, Scenario 1), NavyFed's verifier must track root updates in real time. This is the same solved problem as SPIFFE bundle endpoint synchronization, but the construction provides no equivalent mechanism. The §2 mapping table (§5) maps the issuer registry to "Lean Incremental Merkle Tree" with no associated refresh protocol.

- **In-threat-model?** No. The construction is missing an issuer key lifecycle protocol: rotation, revocation, root update propagation, and maximum acceptable proof age relative to root age. Without this, the security argument in §4 is incomplete — the reduction proves IND-ISS relative to a fixed registry root, but does not bound the window during which a compromised issuer key remains exploitable.
