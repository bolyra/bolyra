# Tier 3 Adversarial — C4 Issuer-blind attribute predicates

## Persona: auth0_pm

---

### Attack 1: The Proving Latency Kills Agentic MCP Workflows

- **Attack:** The construction's §6 targets "< 5 seconds" PLONK proving on snarkjs and ~1.2s on rapidsnark. In a typical MCP agentic workflow, a tool call chain has 5–15 hops per user request. If each hop requires a fresh IssuerBlindPredicate proof (fresh `proofSalt`, fresh `sessionNonce`), the prover latency compounds: 6 × 1.2s = **7.2 seconds of ZK proving per request**, before any business logic runs. Auth0 MCP auth issues a cached, verified JWT in < 100ms, reusable for the session lifetime via `access_token` caching. WorkOS issues a signed assertion in comparable time. The construction offers no credential caching mechanism — every proof has a fresh `proofSalt` (§2, Gadget 6) to ensure unlinkability, but this unlinkability is what kills reuse. You cannot cache a proof without destroying its unlinkability guarantee.

- **Why it works / why it fails against the construction:** The construction does not address credential or proof caching anywhere. It defends unlinkability (§3, Property 2) but does not acknowledge the latency–unlinkability tradeoff in multi-hop chains. The IND-ISS game (§3) is per-proof; it has no notion of session-scoped credential reuse. An operator who wants < 1s total auth overhead across a 10-tool chain has no upgrade path in this construction.

- **In-threat-model?** No. The construction must address this: either define a session-scoped "proof ticket" mechanism where one IssuerBlindPredicate proof authorizes an entire MCP session (binding to a session-level `sessionNonce`), or explicitly bound the deployment to low-frequency auth contexts (e.g., batch KYB checks, not real-time tool calls). As written, the latency profile is incompatible with interactive MCP latency budgets.

---

### Attack 2: The Registry Operator Is the New AS — You Just Hid It

- **Attack:** Section 8 (Gap 6) argues the construction is superior to RFC 7662 because "no party in the protocol — not the verifier, not the relay, not the registry operator — ever possesses the issuer identity in cleartext." But the construction requires an operator to maintain the NCUA issuer Merkle tree (§7: "updated quarterly"), insert and remove issuer keys, and publish `issuerRegistryRoot` on-chain. This operator holds the write keys to the registry — they decide which issuers appear in the anonymity set. An issuer removed from the tree cannot prove membership; an issuer inserted with a typo in their key produces invalid proofs silently. The construction outsources AS functions to a "registry operator" without ever naming who that operator is, how they're governed, or what their key management looks like. Auth0 and WorkOS *are* the registry operators for their customers today — with SOC 2 Type II, 99.99% SLA, incident response teams, and audit logs. Bolyra's registry operator is a solo founder with a GitHub repo.

- **Why it works / why it fails against the construction:** The construction's §7 scenario says the NCUA "publishes" the registry root, implying the NCUA is the operator. But the NCUA does not run ZK registry infrastructure. Someone must bridge the NCUA's existing charter database (a PDF list, in practice) to an on-chain Merkle tree. That bridge is a trusted party. The construction's AS-blind hiding claim (§3, Property 2) is valid for the verifier and relay, but it doesn't eliminate the registry bridge operator's power — it just doesn't model that operator as an adversary class. `A_REV` (§3, Class 3) covers revocation-tree observation but not registry-write authority. A malicious or subpoenaed registry operator can silently add a tracking key to the issuer registry and request proofs against it — the construction has no mechanism to detect or prevent this.

- **In-threat-model?** No. The construction must either (a) define the registry governance model and key management procedure for whoever operates the NCUA bridge, or (b) acknowledge that the registry operator is a new trust anchor not present in the IND-ISS game and bound the security claims accordingly.

---

### Attack 3: AS-Blind Hiding Is a Compliance Liability, Not a Feature, for Regulated CUs

- **Attack:** Section 8 (Gap 6) presents AS-blind issuer hiding as the killer differentiator: "even the registry operator never learns which leaf was used." The NCUA membership scenario (§7) specifically highlights that the IssuerBlindPredicate construction prevents the NCUA from learning "real-time transaction patterns of individual credit unions." But credit unions operate under **12 CFR Part 748** (NCUA cybersecurity), **Bank Secrecy Act / AML obligations**, and **NCUA examination authority**. The NCUA *has the legal right* to see exactly which credit unions are transacting and when. A product that cryptographically prevents the regulator from observing member institution activity is not a privacy feature for this buyer — it is a regulatory red flag. Auth0 and WorkOS generate full audit logs that credit unions can present to examiners. The construction's §7 scenario presents issuer anonymity to the NCUA as a benefit; a credit union's BSA officer will read the same paragraph and kill the procurement.

- **Why it works / why it fails against the construction:** The construction's cryptographic argument is sound — PLONK ZK + Poseidon PRF does prevent the registry operator from learning which issuer proved membership. The problem is that this property is undesirable for the stated buyer in the stated scenario. The cross-CU NCUA scenario (§7) is the construction's primary concrete deployment, and it targets exactly the regulated financial institution buyer for whom AS-blind hiding is a compliance problem, not a selling point. Auth0 MCP auth's RFC 7662 filtered introspection — which the construction frames as inferior (§8, Gap 6) — is actually the *right* design for regulated CUs: the AS (NCUA or CUSO) retains full audit visibility while the RS (partner CU) sees only the predicate result.

- **In-threat-model?** No. The construction must segment its buyer matrix: AS-blind hiding is valuable for cross-jurisdictional KYB (§7, Extension) and privacy-sensitive B2B contexts, but it is the wrong property for regulated US financial institutions under NCUA examination authority. The current draft presents a single construction for all scenarios without acknowledging that some buyers cannot legally use it.

---

### Attack 4: Onboarding Cliff — The Predicate Compiler Has No Reference Implementation

- **Attack:** Section 2 (Predicate Compilation) defines a predicate compiler that translates Boolean expressions into a 25-element clause vector and `predicateHash`. The construction specifies the canonical encoding in detail (§2, Gadget 4a), including the don't-care encoding `(0, GTE, 0)`, the ordering rules, and the Poseidon25 input layout. But there is no reference implementation, no SDK function, and no test vector suite for the compiler itself. A verifier who wants to publish `predicateHash` for `chartered_by_NCUA == 1` must independently implement the compiler, match the Poseidon25 field encoding (big-endian, BN254 scalar field), and produce the identical hash. A mismatch between the verifier's `predicateHash` and the prover's circuit re-derivation means every proof silently rejects — with no diagnostic information beyond "constraint unsatisfied." Auth0's MCP auth onboarding is: generate client ID, paste into SDK, call `authorize()`. WorkOS MCP auth is: copy `client_id` from dashboard, configure redirect. The IssuerBlindPredicate onboarding for a new predicate is: understand Poseidon sponge mode arity, implement compiler, match circuit encoding, generate test vectors, deploy on-chain. This is not a paste-an-API-key experience for the credit union compliance officer who is the actual buyer.

- **Why it works / why it fails against the construction:** The construction acknowledges the compiler–circuit agreement invariant (§2): "A mismatch is a compiler bug, not a circuit vulnerability." This is technically correct but operationally useless — a credit union with a compiler bug gets silent proof failures, not an error message explaining the encoding mismatch. The construction has no prescribed error reporting format, no reference compiler, and no canonical test vector (the `chartered_by_NCUA` example in §7 gives the expected hash symbolically but not as a concrete field element). Auth0/WorkOS ship compilers, SDKs, and dashboards. Bolyra ships a circuit specification. For enterprise procurement, this is a 12–18 month integration project versus a one-afternoon API integration.

- **In-threat-model?** No (GTM, not cryptographic). The construction must ship a reference predicate compiler with concrete test vectors (field elements, not symbolic expressions) and an SDK-level `compilePredicate(expression, schema) → { clauseVector, predicateHash }` function before the construction is deployable by anyone other than its author.


## Persona: cryptographer

I'm reading a construction that has clearly been through several revision cycles — the dual-commitment split and the `predicateHash` re-derivation are both non-trivial improvements over a naive design. But several gaps remain where the security claims outrun the formal argument.

---

### Attack 1: Nonce-pinning by a malicious verifier destroys cross-session unlinkability

**Attack:** The `sessionNonce` is a *public input chosen by the verifier* (§2, Gadget 7; §3 Adversary Class 1). A malicious verifier or two colluding verifiers simply fix `sessionNonce = 0` across every interaction they control. Because `blindNullifier = Poseidon2(credentialId, 0)` is a deterministic function of `credentialId` alone when the nonce is fixed, the nullifier becomes a **stable, per-credential identifier** for all interactions at those verifiers. Two colluding Resource Servers who both use `nonce = 0` can pool their `blindNullifier` observations and identify when the same credential is presented to both — exactly the cross-session linkage the construction claims to prevent.

**Why it isn't resolved by the PRF argument:** The construction's PRF argument (§3, Note on AS adversary's extra view) says "outputs at distinct inputs are jointly indistinguishable from independent random values." This is correct when nonces are distinct. But the verifier *controls* the nonce. The PRF assumption is `Poseidon2(credentialId, ·)` is pseudorandom for *uniform* key `credentialId`; it says nothing when the *evaluator* forces the same input point. The hybrid argument in §4 relies on "different `sessionNonce` values" but nowhere does the protocol enforce that nonces are *fresh or unique across verifiers*. There is no commitment scheme, no freshness proof, and no on-chain nonce registry.

**In-threat-model?** **No — construction must address.** The threat model explicitly models `A_AS` aggregating observations across sessions (§3), and the claim is cross-session unlinkability. A nonce enforcement mechanism (e.g., the verifier commits to a fresh random nonce on-chain before the prover generates the proof, or the nonce is derived from a shared block hash) is needed to make the PRF argument hold.

---

### Attack 2: Low-entropy `credentialId` enables PRF-key enumeration via `blindNullifier` — the same attack the construction already acknowledges for the revocation tree, applied to a different surface

**Attack:** The IND-ISS reduction (§4, Hybrid 1–2) treats `credentialId` as a high-entropy, unknown PRF key when arguing that `blindNullifier = Poseidon2(credentialId, sessionNonce)` is indistinguishable from random. But:

1. The issuer registry is *public* — every `(Ax_j, Ay_j)` is known (it has to be for Gadget 3 membership verification).
2. `credentialId = Poseidon3(credentialDigest, Ax_j, Ay_j)`, so the only unknown factor is `credentialDigest = PoseidonN(attrValues)`.
3. For low-entropy credentials (e.g., a Boolean NCUA membership credential where `attrValues` is dominated by a handful of flag bits), `credentialDigest` takes only `|attr_domain|` values.

A malicious verifier who knows the issuer registry, the predicate domain, and the attribute schema can enumerate all candidate `credentialId` values, compute `Poseidon2(candidate, sessionNonce)` for each, and check against the observed `blindNullifier`. This recovers `credentialId` — breaking both unlinkability *and* the revocation-tree issuer-hiding property simultaneously.

**Scope of the gap:** Section 3 (Class 3 adversary) explicitly warns about this attack for the revocation tree and recommends a per-credential random nonce in `attrValues[15]`. But the *same* attack applies to `blindNullifier`, and §3 does not mention it there. The hybrid argument in §4 silently assumes `credentialId` is indistinguishable from uniform at the point where it is used as a PRF key — this assumption collapses when the effective key space is `O(|attr_domain| × |issuers|)`. The low-entropy mitigation must be stated as a requirement for the `blindNullifier` security claim, not just for the revocation-tree hiding claim.

**In-threat-model?** **No — construction must address.** The IND-ISS reduction is stated for a PPT adversary; a poly-time dictionary attack on a polynomial-size key space is PPT. The construction should either (a) lower-bound `credentialId` entropy explicitly as a security parameter, or (b) redesign `blindNullifier` so that the prover contributes entropy (e.g., `Poseidon3(credentialId, proofSalt, sessionNonce)`) such that even a low-entropy `credentialId` yields an unlinkable nullifier. Option (b) introduces a fresh tradeoff: the nullifier would no longer be deterministic per credential per session, but that property is only needed for replay prevention, which can be achieved by binding the proof to an on-chain commitment.

---

### Attack 3: The hybrid argument silently requires simulation-extractable ZK, not HVZK

**Attack:** The hybrid argument (§4, Hybrid 3) switches issuer witnesses from `j_0` to `j_1` and asserts this is undetectable "by the zero-knowledge property of PLONK." But in the IND-ISS game, the adversary receives **polynomially many real proofs** in Phase 1 and Phase 2 before and after the challenge. Standard PLONK zero-knowledge (the property proved in the KZG + ROM literature) is **honest-verifier zero-knowledge (HVZK)** — it guarantees that a single proof to an *honest verifier* who does not deviate from the protocol is simulatable. It does *not*, without further argument, guarantee security when:

- The adversary sees many real proofs (multi-proof setting).
- The adversary chooses the verification key and nonces adversarially.
- The adversary correlates the challenge proof against Phase 1 proofs that use the same circuit but different witnesses.

What the reduction actually needs is **simulation extractability** (SE-ZK): even after seeing polynomially many proofs, a simulator can produce indistinguishable proofs without the witness, and extracted witnesses from forged proofs remain valid. SE-PLONK has been proved (Ganesh et al., CRYPTO 2022) but requires an additional argument in the AGM + ROM and is not the same as the standard "PLONK is ZK" claim. The construction's security argument cites "zero-knowledge property of PLONK" without specifying HVZK vs. SE-ZK.

**Why this matters concretely:** In Hybrid 3, after replacing `blindedCredCommitment` and `blindNullifier` with random values, the construction argues the adversary cannot distinguish issuer `j_0` from `j_1` because the proof `π` reveals nothing. But the adversary in Phase 1 has seen real proofs for issuer `j_0` — proofs whose KZG commitments are computed over the real witness. If PLONK is only HVZK, the phase 1 proofs might correlate algebraically with the challenge proof in a way the simulation cannot match. The reduction needs to invoke SE-ZK to handle this multi-proof adaptive setting.

**In-threat-model?** **No — construction must address.** The claimed bound `Adv^{IND-ISS}(A) ≤ Adv^{ZK}_{PLONK}(A) + 4 · Adv^{PRF}_{Poseidon}(A)` is only valid if the ZK property used is SE-ZK. The construction should cite Ganesh et al. or an equivalent, state the model explicitly (AGM + ROM), and confirm that the `pot16.ptau` ceremony satisfies the required structural properties for SE-PLONK.

---

### Attack 4: Subverted universal SRS collapses both soundness and zero-knowledge — with no mitigation, no ceremony transcript

**Attack:** PLONK's "universal" setup means a single SRS (here, `pot16.ptau`) covers all circuits up to 2^16 constraints. But "universal" does not mean "trustless." The toxic waste `τ` (the secret trapdoor in KZG's structured reference string) must be destroyed. If any party who participated in generating `pot16.ptau` retained `τ`, they can:

1. **Forge proofs:** Construct a PLONK proof asserting `predicateResult = 1` for a credential that does not satisfy the predicate — or assert a valid signature from an issuer key not in the registry. This breaks soundness completely and is undetectable by any verifier.
2. **Extract witnesses from honest provers:** Recover private inputs (`issuerPubkeyAx, issuerPubkeyAy`, `attrValues`, `credentialId`) from any honestly generated proof, since the KZG extractor can use `τ` to invert commitments.

The construction (§2, Proving System row of §5) simply states "PLONK with universal setup via `pot16.ptau`" as a fait accompli. Section 4's named assumptions include "Knowledge soundness of PLONK (in the AGM + ROM)" but the reduction sketch gives no attention to the case where the SRS is adversarially generated. The IND-ISS game (§3, Setup) says "Challenger generates PLONK CRS" — this implicitly assumes honest CRS generation as a game axiom, sweeping the subverted-setup threat under the rug.

**Threat model gap:** Real deployment does not use a game-axiom CRS. The `pot16.ptau` used for Bolyra is either (a) the snarkjs "Powers of Tau" ceremony output, (b) the Semaphore ceremony (cited for HumanUniqueness), or (c) an independently generated file. None of these is publicly referenced with a verifiable multi-party computation transcript in this construction. There is no "subverted setup" section, no mention of `SUBZERO`-style ceremony auditing, and no discussion of what the security model degrades to if `τ` is known (spoiler: to zero — all IND-ISS claims, all ZK claims, and all knowledge soundness claims become vacuous simultaneously).

**In-threat-model?** **No — construction must address.** At a minimum, the construction should: (a) cite the specific `pot16.ptau` file with its provenance and ceremony transcript URL; (b) state explicitly that security assumes the SRS was generated honestly (i.e., at least one party in the MPC destroyed their `τ` share); (c) discuss whether a subverted SRS is in or out of the adversary model and what the degraded security claim is if it is excluded. Omitting this entirely in a construction that claims formal IND-ISS security is a significant specification gap that any IACR reviewer would flag as a major revision requirement.


## Persona: cu_ciso

---

### Attack 1: Issuer Registry Operator Is an Unreviewed Critical Vendor

- **Attack:** I ask you to name the legal entity that operates the NCUA issuer registry Merkle tree, produce their SOC 2 Type II report, and show me their SLA for root updates. Section 7 says the root is "updated quarterly." NCUA Part 748.0(b) and the FFIEC Vendor Management guidance require me to assess any third party whose failure would impair my security program. The registry operator controls `issuerRegistryRoot` — a stale or compromised root means every proof my system accepts is either invalid or forged against a revoked key. A 90-day update cadence means a CU whose key was compromised in month 1 is still in a valid registry state for month 3 if the quarterly publish hasn't landed. The construction gives me a cryptographic guarantee conditioned on a registry root I didn't audit.

- **Why it works / fails:** The construction's security argument is algebraically tight: given a correct `issuerRegistryRoot`, the Merkle membership proof is binding under Poseidon collision resistance. But it says nothing about the trust chain *above* the root — who signs the root, how it's published on-chain, how key removals are batched, or what the revocation lag is. This is entirely outside the threat model. The construction outsources that trust to "the NCUA publishes this on-chain," which is an operational assumption, not a cryptographic one.

- **In-threat-model?** No. The construction must address: (a) the legal and operational identity of the registry operator, (b) the key-removal SLA (quarterly is operationally indefensible), (c) what my verifier does when `issuerRegistryRoot` is stale because the on-chain update is delayed by gas costs or chain congestion.

---

### Attack 2: Issuer-Blindness Breaks GLBA Incident Response and Breach Notification

- **Attack:** I cite 16 CFR Part 314.5(a) (GLBA Safeguards Rule, 2023 amendments) — I must notify the FTC within 30 days of a security event involving unauthorized access to customer financial information. I also cite NCUA Part 748 Appendix B, which requires my incident response plan to identify the source of unauthorized access. Now I run the scenario: an AI agent using a stolen PenFed credential accesses my core processor integration via a valid IssuerBlindPredicate proof. My SIEM fires. My Tier 1 SOC opens an incident ticket. The proof is valid, `predicateResult == 1`, `revocationRoot` is current. I can tell the examiner "a valid NCUA-chartered CU's agent accessed the system." I cannot tell them which CU, which agent, which credential, or which human authorized it. The issuer-blindness that is the construction's primary selling point is my breach notification blocker.

- **Why it works / fails:** The construction correctly notes that `blindedCredCommitment` and `blindNullifier` are per-session unlinkable. It does not address the regulatory requirement to identify a party in the event of a breach. The construction treats issuer anonymity as uniformly desirable. For a verifier operating under GLBA and NCUA Part 748, anonymity from the verifier is sometimes a liability, not an asset. The construction provides no escrow, no out-of-band disclosure mechanism, no "break-glass" path by which a regulator or the verifier could learn the issuer's identity under subpoena or supervisory order.

- **In-threat-model?** No. The construction must address the dual-use problem: the property that prevents a malicious verifier from profiling issuers also prevents a legitimate verifier from complying with breach notification obligations. One mitigation would be a selective-disclosure escrow (e.g., the issuer encrypts their identity to a regulator key and includes the ciphertext as an additional public output), but the current construction has no such mechanism.

---

### Attack 3: Signing Key Custody Is Unspecified, Undermining the Entire Anonymity Set

- **Attack:** Section 7 says "PenFed's compliance officer signs an attribute credential" using `(Ax_penfed, Ay_penfed)`. I ask: where does the private key corresponding to `(Ax_penfed, Ay_penfed)` live? The construction is silent. Under FFIEC CAT Domain 1 (Cyber Risk Management and Oversight) and NCUA Part 748, I must have a documented key management policy covering generation, storage, rotation, and revocation of cryptographic keys used to issue credentials. If that compliance officer's Baby Jubjub private key lives in a browser extension, a laptop keychain, or any non-HSM environment, a single successful phishing or malware attack against one of 4,600+ CU compliance officers yields a signing key that can produce credentials claiming `chartered_by_NCUA == 1`. Gadget 2 verifies a valid EdDSA signature under a key in the issuer registry — it cannot distinguish a legitimately held key from a stolen one. The attacker can produce proofs for any attribute vector they want, all passing `predicateResult == 1`. The anonymity set of 4,600 CUs becomes an attack surface amplifier: now 4,600 potential weak links, any one of which compromises the entire predicate.

- **Why it works / fails:** The construction's soundness argument (§4, Soundness argument) correctly states that forging a proof requires breaking EdDSA unforgeability under DL on Baby Jubjub. That holds if the private key is securely held. The construction never specifies key custody requirements, HSM mandates, or key ceremony procedures for issuer enrollment. This is not a circuit vulnerability — it is an operational gap that the construction's deployment scenario (§7) must address but does not.

- **In-threat-model?** No. The construction must specify minimum key custody requirements for issuer enrollment, including HSM storage (FIPS 140-2 Level 2 minimum for a regulated CU), key ceremony procedures, and the process for revoking an issuer key from the registry when a compliance officer's credentials are compromised — with an SLA measured in hours, not quarters.

---

### Attack 4: Replay Detection Is Operationally Unverifiable at 2am

- **Attack:** The `blindNullifier = Poseidon2(credentialId, sessionNonce)` is the replay prevention mechanism. My on-chain registry rejects duplicate nullifiers within a session. At 2am, my on-call engineer sees: registry contract emitting a nullifier-collision event. They need to answer three questions before escalating: (1) Is this a replay attack or a client bug? (2) Which system is being targeted? (3) Do I revoke something, and if so what? The answers: (1) indeterminate from the on-chain event alone — the `blindNullifier` is a Poseidon hash of a private `credentialId` the engineer doesn't know; (2) the session is identified by `sessionNonce` but the credential behind it is opaque; (3) the engineer cannot compute `credentialId` from `blindNullifier` without the issuer's private credential data, so they cannot submit a revocation. The construction's Gadget 7 explicitly says nullifiers are unlinkable across sessions under the Poseidon PRF assumption — which means my SOC team also cannot correlate the attack across sessions to determine if it's a sustained campaign. My FFIEC CAT (Domain 3: Cybersecurity Controls) requires me to have an incident response procedure that can detect, respond to, and recover from an attack. This construction gives me a cryptographically correct audit trail and an operationally unworkable one.

- **Why it works / fails:** The construction gives cryptographic guarantees about unlinkability that are precisely what defeat operational forensics. The only actionable signal in a nullifier collision is the `sessionNonce` and the `issuerRegistryRoot` — neither of which identifies the attacking party. An operator could log `(sessionNonce, blindNullifier, blindedCredCommitment, timestamp)` for forensics, but none of these values can be decoded into a human-actionable identity. The construction does not address the monitoring and alerting layer at all.

- **In-threat-model?** No. The construction must provide an operational appendix covering: (a) what events the on-chain registry contract should emit and what they mean to a Tier 1 operator, (b) the escalation path when a nullifier collision is detected, (c) how a CU's security team requests emergency revocation from the registry operator when they cannot compute `credentialId` themselves (because the compromised agent's credential data may not be accessible), and (d) the minimum logging requirements for SOC 2 Type II audit evidence — since all verifier-side logs contain only opaque field elements.


## Persona: rfc7662\_advocate

---

### Attack 1: Privacy-Preserving AS Architecture Eliminates the Load-Bearing "AS-blind" Differentiator

**Attack:**

The construction's entire Case for Superiority over RFC 7662 rests on Property 2 (§3): *AS-blind issuer hiding* — the claim that a traditional AS "inherently knows the issuer." The comparison is not against RFC 7662; it is against a strawman monolithic AS. A threshold-MPC AS — where issuance authority is split across *n* nodes, *t*-of-*n* required for token validation, with each node holding only a shard of the issuer-to-token mapping — does not have a single party that knows the issuer. Combined with draft-ietf-oauth-jwt-introspection-response, the AS cluster returns a signed JWT asserting `predicate_result: true` with all issuer-identifying fields omitted. No single introspection node can correlate issuer to session.

Concretely: use an oblivious PRF (e.g., 2HashDH) inside the AS to produce the token handle. The AS evaluates `F_k(credential_id)` via threshold OPRF — each AS node computes a partial evaluation, the client combines them. No node sees `credential_id` in cleartext. The AS issues a token bound to `F_k(credential_id)` without any node individually knowing the issuer. This is a deployed pattern in Privacy Pass (RFC 9578).

**Why it (partially) fails against the construction:** The token-holder still presents a stable token handle to the AS for introspection; the OPRF output is stable across sessions and linkable across RSs. The IssuerBlindPredicate construction's `blindedCredCommitment = Poseidon2(credentialId, proofSalt)` is *per-proof* randomized and carries no token handle. A threshold AS using Privacy Pass achieves AS-blind issuance but still produces a stable, RS-linkable token unless token rotation is deployed per session — adding significant infrastructure complexity.

**In-threat-model?** Partially. The construction survives the basic MPC-AS attack because stable token handles remain linkable without per-session rotation. However, **the construction must address this directly in §8 Gap 6** rather than comparing against a naive single-party AS. The current text treats "AS inherently knows the issuer" as axiomatic. A deployed Privacy Pass-based AS with per-session token rotation (RFC 9578 §8) narrows the gap to a complexity argument, not a fundamental one. The construction should either formalize why stable token handles with rotation remain linkable, or concede the AS-blind property is architectural-dependent for *both* approaches.

---

### Attack 2: `predicateHash` Binding Is Equivalent to a Signed JWT Claim — the In-Circuit Gadget Adds Nothing Over a Trusted AS

**Attack:**

The construction's Gadget 4a (in-circuit `predicateHash` re-derivation via Poseidon25) is the mechanism preventing predicate substitution by a malicious prover. The construction presents this as a unique ZK property. But consider the RFC 7662 analogue: the AS evaluates the predicate server-side using the token's claims, then returns a signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response §4) with a claim `"ncua_chartered": true`. The RS checks the AS's signature. There is *no predicate substitution attack* because **the AS is the prover** — the holder never generates a proof. The construction's predicate integrity guarantee is solving a problem that exists *only* in the trustless self-proving model it creates.

The rfc7662_advocate's explicit question (attack_prompt 1): *"Why is the AS-side advantage load-bearing?"* — applied here: why is in-circuit predicate binding load-bearing when the AS can simply evaluate the predicate and sign the result? The construction's §8 Gap 7 acknowledges "BBS+ has no predicate integrity guarantee against a malicious prover" — but in the RFC 7662 model, there is no malicious prover because the prover is the trusted AS.

**Why it fails against the construction:** The RFC 7662 model requires the credential to be presented to the AS for evaluation, which requires the holder to reveal attributes to the AS (or requires the AS to hold attributes in its token store). The IssuerBlindPredicate circuit evaluates the predicate over *locally held* private attributes — the holder never surrenders attributes to any party. The predicate integrity guarantee is the price of eliminating AS-side attribute access.

**In-threat-model?** Yes — construction survives. But **the construction must be explicit that Gadget 4a is necessary precisely because the holder is the prover, not the AS.** As written, §8 Gap 7 presents predicate integrity as a general advantage over BBS+ without contextualizing that this whole problem class disappears if an AS evaluates predicates server-side. An honest reader can ask whether eliminating the trusted AS is worth the circuit complexity. The construction should address this trade-off explicitly.

---

### Attack 3: Unified Revocation Tree Operator Is a New, Unmodeled Trust Assumption

**Attack:**

The construction introduces a *unified sparse Merkle revocation tree* (all issuers share one tree, keyed by `credentialId`). The IND-ISS game models a verifier who checks `revocationRoot` against the current tree root. But who operates this tree? The construction never names the operator or bounds their behavior. The verifier sees only the Merkle root — they cannot verify:

1. The tree contains *all* revoked `credentialId` values (the operator could omit a revocation to keep a compromised credential valid).
2. The `revocationRoot` published on-chain corresponds to the tree the prover actually proved against (if the operator timestamps roots with delay, stale revocations pass verification).
3. The operator is not selectively inserting `credentialId` values to deanonymize specific credential holders (an adversary who operates the revocation tree and also knows issuer keys can enumerate `Poseidon3(credentialDigest_candidate, Ax_j, Ay_j)` for candidate attributes and match against tree entries).

RFC 7662 token revocation (RFC 7009) is managed by the AS, which is a *named, legally accountable entity* under OAuth server metadata (RFC 8414). The revocation endpoint is in the AS's published metadata. If the AS fails to honor revocation, it violates its OAuth server obligations with auditable evidence. The unified ZK revocation tree operator has no equivalent accountability structure in the construction.

**Why it partially fails against the construction:** RFC 7662 revocation requires contacting the AS, which leaks the issuer identity (Gap 4 in §8). The unified tree *prevents* issuer-specific revocation endpoint queries. However, the construction has substituted one trust assumption (trust the AS) for another (trust the tree operator) without formally bounding the tree operator's capabilities in the IND-ISS game.

**In-threat-model?** No — **this is an unaddressed gap**. The IND-ISS game (§3) models Class 1 (malicious verifier), Class 2 (honest-but-curious intermediary), Class 3 (revocation-tree observer), and Class 4 (predicate substitution adversary). It does not model a **malicious revocation tree operator** who selectively omits revocations or manipulates tree contents. The construction should either (a) add a Class 5 adversary bounding the tree operator (reducing tree completeness to a transparency log assumption, e.g., RFC 9162 Certificate Transparency), or (b) acknowledge that the tree operator is a trusted party with the same accountability requirement as an AS, eliminating the trust advantage over RFC 7662 for revocation integrity.

---

### Attack 4: DPoP Key Rotation Per Session Matches `blindedCredCommitment` Unlinkability Without ZK

**Attack:**

The construction's cross-session unlinkability relies on `blindedCredCommitment = Poseidon2(credentialId, proofSalt)` with fresh per-proof `proofSalt`. Two proofs from the same credential are unlinkable because `proofSalt` randomizes the commitment. The RFC 7662 toolbox includes RFC 9449 DPoP (Demonstrating Proof-of-Possession). The construction's attack_prompt explicitly asks: *"DPoP provides sender-constraint without any ZK. Name the property DPoP cannot provide."*

The rfc7662_advocate's answer: DPoP binds tokens to a *stable* client key pair, making cross-RS and cross-session correlation trivial via the DPoP public key. This is the obvious DPoP limitation. The construction seems to win here.

But the rfc7662_advocate pushes further: **DPoP does not require a stable key.** RFC 9449 §4.1 says the DPoP proof MUST use a fresh key per token request — the client generates a new key pair, proves possession in the token request, and the token is bound to that ephemeral key. RFC 9449 §9.3 explicitly warns against key reuse across RSs. If the client generates a new DPoP key per session, presents it at the token endpoint, and never reuses it, the RS sees a different DPoP public key each session. Combined with PPID sub values (OIDC §8.1) providing per-RS stable pseudonyms *only within* an RS (not across RSs), and RFC 8707 resource indicators binding tokens to a single RS, the combined stack achieves:

- Per-session unlinkable public keys (rotating DPoP)
- Per-RS pseudonymous subjects (PPID)
- Sender-constrained tokens (DPoP)
- RS-blind issuer hiding (filtered introspection response)

This matches or exceeds `blindedCredCommitment`'s unlinkability guarantee without any ZK circuit.

**Why it fails against the construction:** Per-session ephemeral DPoP keys require the client to perform a new OAuth token request each session, interacting with the AS. The AS logs these requests with timestamps, client IP, and associated token metadata — creating a session-level audit trail even if the DPoP key is ephemeral. The construction's prover generates the IssuerBlindPredicate proof *locally*, with zero AS interaction per session. There is no AS-side session log. Additionally, the DPoP key-generation/token-request flow requires AS availability, whereas the ZK proof is generated offline.

More critically, **the DPoP public key in the token request is observable by the AS, which can correlate ephemeral keys to client sessions via timing, IP, and client authentication metadata** even if the DPoP key itself is per-session. The construction's `proofSalt` is generated locally with no AS interaction, and there is no session-level transcript at the AS. This is a fundamental architectural difference DPoP cannot close.

**In-threat-model?** Yes — construction survives. But **§8 must address per-session ephemeral DPoP key rotation explicitly**, as the current Gap 4 analysis of DPoP limitations is too brief. The gap is not "DPoP binds to a stable key" (which is easily addressed by per-session rotation per RFC 9449 §4.1) but rather "DPoP requires AS-interaction per session, which creates a session log at the AS that serves as a side-channel even when the DPoP key is ephemeral." This is the specific sub-claim that needs a citation and elaboration to be convincing to an OAuth Working Group reviewer.


## Persona: spiffe_engineer

---

### Attack 1: Schema-Index Agreement is Unverified — "Which CU Put `chartered_by_NCUA` at Index 2?"

- **Attack:** The predicate compiler (§2, Predicate Compilation) maps a claim name like `chartered_by_NCUA` to an attribute slot index — e.g., `clauseAttrIndex[0] = 1`. The `predicateHash` commits to the index, not the claim name or its semantic meaning. The claim of "arbitrary-schema support" (C4 candidate spec) therefore requires that all 4,600+ NCUA issuers in the registry agree that `attrValues[1]` means `chartered_by_NCUA`. The circuit has no mechanism to enforce this: there is no `schemaHash` public input, no constraint linking `issuerRegistryRoot` leaves to a particular schema commitment, and no gadget preventing an issuer from signing a credential where `attrValues[1]` holds a charter number (12345) rather than a Boolean.

  A misconfigured or malicious issuer enrolled in the registry signs a credential where `attrValues[1] = charter_number`. The predicate `clauseAttrIndex = [1, ...]`, `clauseComparator = [EQ, ...]`, `clauseThreshold = [1, ...]` then evaluates `charter_number == 1` rather than `chartered_by_NCUA == 1`. If any CU holds charter number 1, the circuit produces `predicateResult == 1` with a fully valid PLONK proof — signature valid, issuer in the registry, no revocation, `predicateHash` matches. The semantic claim is false; the cryptographic claim is true.

  SPIFFE avoids this by making the SPIFFE ID URI itself carry semantic identity within the trust domain (`spiffe://ncua.gov/cu/penfed`). Meaning is governed by the trust domain operator at enrollment time, not by index convention. Bolyra needs either a `schemaHash` public input that issuer key registration commits to on-chain, or a schema registry whose root is linked to `issuerRegistryRoot` via an additional Merkle layer.

- **Why it works / why it fails:** The circuit is formally correct under its own constraints. The attack exploits the gap between circuit correctness (index `i` evaluates to threshold `t`) and semantic correctness (index `i` means `chartered_by_NCUA` for all issuers). Nothing in the construction enforces the latter.

- **In-threat-model?** No — the construction must address this. "Arbitrary-schema support" is a false claim without schema-agreement enforcement. A single issuer with a non-conforming schema can produce proofs that pass all circuit and IND-ISS checks while asserting a false semantic predicate, defeating the entire cross-CU scenario in §7.

---

### Attack 2: `issuerRegistryRoot` Has No Freshness Guarantee — "Stale Root, Valid Proof"

- **Attack:** §7 states the NCUA issuer registry root is "published on-chain and updated quarterly." The `issuerRegistryRoot` is a public input; the verifier checks it against "the on-chain NCUA registry root." The circuit imposes no constraint on when that root was published or whether it reflects current NCUA membership. A verifier accepting a 90-day-old `issuerRegistryRoot` would accept proofs from an issuer whose NCUA charter was revoked or whose EdDSA key was compromised after the last registry update.

  The credential-level `revocationRoot` (§2, Gadget 5) is separate and presumably updated more frequently — but it covers individual credential revocation, not issuer removal. If the NCUA de-charters a credit union, the appropriate revocation mechanism is removing the issuer from `issuerRegistryRoot`, not inserting 10,000 individual `credentialId` values into the revocation tree. The protocol provides no mechanism for the former.

  In SPIFFE/SPIRE, trust bundles carry a `refresh_hint` TTL and SPIRE agents rotate them automatically. SVIDs have short `exp` claims (typically 1 hour) that force re-validation. A workload whose SPIFFE registration is deleted cannot renew its SVID after expiry. Bolyra has no equivalent for issuer-level liveness: no `registryTimestamp`, no TTL, no `exp` on the `issuerRegistryRoot` commitment. The verifier policy described in §7 — "issuerRegistryRoot matches the on-chain NCUA registry root" — is an application-layer assertion with no protocol enforcement.

- **Why it works / why it fails:** The IND-ISS game (§3) assumes honest issuer enrollment and does not model registry root staleness. The game's challenger controls the registry and enrolls correctly; the reduction gives no bound against proofs generated using a stale root containing de-registered issuers. The construction's soundness argument (§4) proves that a valid proof implies the issuer's key is a current leaf in the root provided as public input — but says nothing about whether that root is the correct current root.

- **In-threat-model?** Partial. The construction acknowledges freshness as a verifier responsibility but provides no protocol mechanism to enforce it. A `registryTimestamp` field committed inside the proof (e.g., as an additional public input checked against a verifier-configured staleness bound) would close this gap. Without it, the construction silently degrades in the face of delayed registry updates — exactly the kind of failure that SPIFFE's automatic TTL-based rotation is designed to prevent.

---

### Attack 3: `issuerRegistryRoot` Governance is Undefined — "The Registry Controller Has God Mode"

- **Attack:** The construction places `issuerRegistryRoot` as the global trust anchor for all IssuerBlindPredicate proofs. §7 says it is "published on-chain," but the protocol defines no governance model for who can write to this registry: no multisig threshold, no DAO, no timelocked dispute process, no key ceremony for the registry controller's signing key. An adversary who compromises or coerces the party controlling the on-chain registry contract can insert `(Ax_rogue, Ay_rogue)` as a leaf. The adversary then signs a credential with `attrValues[1] = 1`, generates a valid IssuerBlindPredicate proof, and passes all verifier checks — including the IND-ISS game, which does not model rogue enrollments.

  This is the trust anchor capture attack. The construction's IND-ISS game (§3, Setup step) has the challenger enroll `n ≥ 2` issuers with honest keys. A registry controller who enrolls rogue keys is outside the game by construction. The reduction in §4 proves security under the assumption that `issuerRegistryRoot` contains only legitimate issuer keys; it provides no security when that assumption fails.

  In SPIFFE, the trust bundle is controlled by the SPIRE server — a privileged component whose compromise is explicitly in-threat-model. The SPIRE deployment guide specifies HSM-backed upstream CAs, multi-party signing for trust bundle updates, and audit logging of all enrollment operations. The Bolyra construction names none of these. "Published on-chain" without governance is equivalent to "anyone with the contract owner key is the NCUA" — which is a credential-stuffing attack surface, not a trust model.

- **Why it works / why it fails:** The construction's security argument (§4) explicitly conditions on PLONK soundness, Poseidon collision resistance, and EdDSA unforgeability — none of which help if the registry root is corrupt at the source. The construction fails to distinguish between "the proof is valid given this root" and "this root is trustworthy." The gap is not cryptographic; it is governance.

- **In-threat-model?** No — the construction must address this. The IND-ISS game assumes honest enrollment. A rogue enrollment attack falls outside every theorem in §4. The construction should define a governance model for `issuerRegistryRoot` updates (e.g., on-chain multisig requiring NCUA administrative key + independent auditor, with a timelock for disputed insertions), or explicitly bound the trust model to a named, governed registry operator and move the governance specification to the deployment scenario.

---

### Attack 4: WIMSE Already Scopes This — "Submit a Pull Request, Not a New Protocol"

- **Attack:** WIMSE `draft-ietf-wimse-arch` §5 and the companion `draft-ietf-wimse-workload-identity-bcp` scope cross-boundary workload identity with selective disclosure and token exchange for exactly the agent-to-service authentication scenario Bolyra targets. The IssuerBlindPredicate construction's "cross-CU NCUA membership proof" maps directly onto a WIMSE cross-trust-domain workload identity exchange where the workload's `iss` claim is replaced by a predicate proof. §8 of the construction (Why the baseline cannot match) does not mention WIMSE at all.

  The PLONK proof (768 bytes, §2) could be embedded in a JWT as a `zk_proof` extension field, with `predicateHash` and `issuerRegistryRoot` as registered JWT claims — call it a ZK-WIMSE token. WIMSE's token exchange mechanism (arch §5.3) handles the relay, and the verifier checks the embedded proof against public inputs rather than decoding a cleartext `iss`. The construction's §5 maps every component to existing Bolyra primitives ("no new cryptographic primitives"); by the same logic, the protocol envelope could be WIMSE's JWT-SVID format with a ZK extension rather than a new handshake.

  The one property WIMSE's baseline JWT-SVID cannot provide natively is AS-blind hiding: the JWT `iss` claim is cleartext, so the AS (token exchange service) always knows the issuer. But this is precisely the argument for a WIMSE ZK attestor extension — not a new protocol. A SPIRE ZK attestor plugin that generates IssuerBlindPredicate proofs as the SVID payload would be deployable in any existing SPIFFE infrastructure, interoperate with WIMSE token exchange, and bring the AS-blind hiding property into the IETF standards track without defining a new wire format or proof protocol.

  The construction does not explain why this layering would fail. The answer may be that WIMSE's JWT header still carries `iss` in cleartext even with a ZK-proof body — defeating AS-blind hiding at the transport layer. If so, the construction should say so explicitly, cite the specific WIMSE header field, and frame the contribution as "WIMSE cannot be extended to provide AS-blind hiding without modifying the JWT-SVID header schema" — which is a WIMSE issue, not a Bolyra one.

- **Why it works / why it fails:** This is not a security break but a standards-layer disqualification. Any IETF or financial-industry standardization review will ask "why not WIMSE?" first. Failure to engage with WIMSE leaves the construction open to the strongest non-cryptographic objection: "duplicate work in the wrong venue." The construction survives this attack if it can name the specific WIMSE gap (likely: cleartext `iss` in JWT-SVID headers is not removable without breaking WIMSE's token exchange binding, which requires an `iss`-addressable endpoint).

- **In-threat-model?** Not a security attack. But without an explicit WIMSE engagement section in §8, the construction is incomplete as a protocol specification. It must either (a) justify why a WIMSE ZK attestor extension is insufficient, citing specific WIMSE header semantics that preclude AS-blind hiding, or (b) reframe the contribution as a WIMSE extension profile and target the WIMSE working group as the standards venue. Option (b) is the stronger move — it gains standards traction and avoids the "new protocol" objection entirely.
