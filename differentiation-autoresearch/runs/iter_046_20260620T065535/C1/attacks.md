# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: Latency arbitrage makes the claim irrelevant in practice

- **Attack:** The construction adds a `credentialBlinding` input and a Num2Bits(128) gadget, bringing total constraints to ~11,330. Even with rapidsnark, Groth16 proving at this constraint count runs 2–15s on commodity hardware. I can issue a signed JWT or call WorkOS token introspection in under 100ms from any region. Every MCP use case I have seen — tool dispatch, API proxy calls, agentic loops — executes in a latency-sensitive hot path. The construction's claim is about *what* the proof proves, but it says nothing about *when* the proof is usable.

- **Why it works / fails:** The construction is silent on proof caching and proof reuse. If the operator pre-generates the proof and caches it per-session, latency may be acceptable. But then the proof is no longer "runtime-adaptive" — it was generated ahead of time, which is exactly what an AS-issued JWT with pre-computed minimal scope achieves. The construction cannot simultaneously claim runtime adaptability and be pre-cached.

- **In-threat-model?** No — the construction must address proof generation latency and clarify whether "AS-blind presentation at the moment of use" requires online proving (fatal) or allows cached proofs (collapses the runtime-adaptive claim).

---

### Attack 2: RFC 8707 + pushed authorization requests already give AS-blind scope minimization

- **Attack:** The candidate's gap-to-close states the differentiator is "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)." But RFC 8707 (Resource Indicators) combined with Pushed Authorization Requests (PAR, RFC 9126) already lets an agent specify, at authorization time, exactly which resource server it intends to call and what scope it needs — the AS issues a token scoped to that RS only. The agent never hands over a fat token; it holds multiple narrow tokens. No AS roundtrip at presentation time. The construction's on-chain leaf hides the bitmask from the RS, but the RS in my architecture *never sees the full scope list* either — it only sees the token scopes bound to its `resource` indicator. Same privacy property, zero ZK overhead, compatible with every enterprise IdP today.

- **Why it works / fails:** The construction's genuine gap is the *adversarial AS* sub-case — where the AS itself is semi-trusted and might collude with RS to reconstruct the full bitmask across multiple narrow JWTs. In that model, issuing multiple resource-scoped tokens leaks information to the AS about the agent's full permission surface. The ZK construction's two-layer blinding prevents even the AS from learning the bitmask. But the candidate document does not *assert* this adversarial-AS scenario as the primary use case; it lists it as a candidate. If it's not the headline, the entire RFC 8707 attack stands.

- **In-threat-model?** Partially — the construction survives *if and only if* it explicitly names adversarial-AS as the primary threat. As written, the claim is underspecified. A buyer reading Section 1 will not know this is the scenario being addressed.

---

### Attack 3: Procurement kills it before cryptography enters the room

- **Attack:** A credit union's vendor risk assessment requires SOC 2 Type II (or equivalent), a business associate agreement if PHI is adjacent, a penetration test report, documented incident response SLA, and a named support contact. WorkOS ships all of these today. The construction is technically sound — the blinding is correct, the two-layer rationale is coherent — but it will never reach a CU's security review committee as a primary identity layer because it is a solo-founder open-source library with no compliance posture. The objection is not "your ZK math is wrong"; the objection is "you are not on our approved vendor list and never will be." The attack does not require breaking the cryptography at all.

- **Why it works / fails:** The construction has no answer here because this is outside the threat model. The candidate document treats "buyer-level reasons" as the gap to close, but the construction only addresses the cryptographic gap — not the procurement gap. A differentiation document that cannot answer "how does a CU's CISO approve this?" is incomplete.

- **In-threat-model?** No — this is an explicit requirement from the candidate's attack_prompts ("How do you answer procurement's 'you are a solo founder' question?") that the construction does not address. The construction must either (a) explicitly scope the claim to developer-first or self-sovereign contexts where procurement is not the blocker, or (b) provide a composability story ("ride WorkOS as the token issuer, use Bolyra as the selective-disclosure layer on top") that makes Bolyra additive to an approved vendor rather than a replacement.

---

### Attack 4: The 2^135 security claim is correct but irrelevant to the attack surface that matters

- **Attack:** The construction correctly notes that adding `credentialBlinding` expands the enumeration search space from ~163 bitmask configurations to 2^135. But the construction then says the blinding factor is "sampled by the operator at enrollment time, stored alongside credential secrets." If I compromise the operator's credential store — which is the *actual* attack surface in every real breach I have seen (credential stuffing, secrets manager misconfiguration, supply chain) — I recover `credentialBlinding` directly. The 2^135 expansion only helps against an adversary who *only* observes on-chain leaves and cannot touch the operator's environment. Against a credential-store breach, the hiding property collapses immediately, and the on-chain leaf is now fully reversible from the recovered blinding factor.

- **Why it works / fails:** The construction is correct within its stated threat model (adversary observes on-chain leaves; cannot access operator secrets). The attack works because the construction does not name the credential-store breach as out-of-scope, nor does it describe key management requirements (HSM, KMS, rotation policy) for `credentialBlinding`. A security reviewer reading the spec will ask: "What's the blast radius if the blinding factor leaks?" The answer — "the on-chain leaf is now fully traceable" — should be documented explicitly so the buyer can plan for it.

- **In-threat-model?** Yes (construction survives within stated scope) — but the construction must add a Key Management section that explicitly classifies `credentialBlinding` as a secret requiring HSM-level protection, defines rotation semantics (re-enrollment required on rotation), and states that credential-store breach is outside the ZK threat model. Without this, a security auditor will flag it as an unaddressed attack.


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing.*

---

### Attack 1: Undefined Simulator — the ZK Claim is Hand-Waving

- **Attack:** Demand the simulator. The construction claims "agent proves it satisfies a required permission predicate without revealing the full permission set." That is a ZK claim. For any ZK proof system, you must exhibit a PPT simulator S that, given only the public inputs (predicate, commitment), produces a transcript indistinguishable from a real proof. The construction says Groth16 is HVZK — true. But HVZK requires the verifier to be honest (use the prescribed challenge). The RS in this threat model is *not* necessarily honest. What public inputs does the RS see? If the circuit's public outputs include the committed bitmask root AND the predicate result bit, does the simulator know the bitmask value? If the RS can set a malicious verification key (or is given auxiliary information from a colluding AS), HVZK is insufficient; you need simulation-extractability or at minimum malicious-verifier ZK.
- **Why it works / why it fails:** The construction is silent on what the RS learns beyond "predicate satisfied." The two-layer blinding addresses on-chain hiding, but not proof-level leakage. The public output set of the circuit is never enumerated. If `bitmask` appears as a public signal (even implicitly via a public predicate check), the simulator must know it — collapsing ZK to "the verifier already knows the secret."
- **In-threat-model?** No. The construction must: (a) enumerate all public inputs/outputs of the circuit, (b) state whether ZK is HVZK or SE-ZK, (c) exhibit the simulator or cite a compiled result from the Groth16 ZK reduction for this specific circuit shape.

---

### Attack 2: Subverted Trusted Setup Collapses AS-Independence

- **Attack:** The core differentiator claim is the **adversarial-AS model** — "AS cannot lie about scope membership." The construction uses Groth16 with a project-specific trusted setup (`pot16.ptau` + per-circuit `.zkey`). Groth16's soundness holds only if the toxic waste `(α, β, γ, δ, τ)` was honestly discarded. If the AS (or any party it suborns) participated in the ceremony and retained toxic waste, the AS can compute a valid Groth16 proof `π` for *any* statement, including "this credential has `FINANCIAL_UNLIMITED` bit set" against a commitment that encodes only `READ_DATA`. The RS sees a valid `verifyProof()` result and cannot distinguish forgery from a legitimate proof.
- **Why it works / why it fails:** The blinding construction (Attack 2 from prior round, now addressed) used `Poseidon2` to expand search space to 2^135. That addresses brute-force. It does *nothing* against algebraic forgery via toxic waste, because forged Groth16 proofs satisfy the verification equation by construction — no commitment needs to be reversed. The threat model explicitly targets "adversarial AS." An adversarial AS that controls the ceremony breaks the entire guarantee, not just the blinding layer.
- **In-threat-model?** No. The construction must: (a) either use a public universal SRS (PLONK/Marlin/Nova) that requires no per-circuit ceremony, or (b) specify a transparent MPC ceremony with public audit trail and argue AS exclusion from it as a trust assumption, or (c) scope the threat model to *passive* AS only and drop the adversarial-AS claim. Mixing Groth16 with an adversarial-AS threat model is a fundamental category error.

---

### Attack 3: Nullifier Precomputation Under Predictable `scope_id`

- **Attack:** Let nullifier = `Poseidon(agentSecret, scope_id)`. The `scope_id` identifies the RS resource being accessed. An AS that observes M enrollments on-chain and knows the universe of K deployed RS scope_ids can precompute an M×K table of nullifier candidates offline. When an agent presents a proof to RS_j with nullifier `N`, the AS matches `N` against its table and recovers which agent credential was used — linking the presentation to the on-chain identity. The `blindingNonce` (per-presentation ephemeral) is described as preventing "cross-RS proof linkability," but it lives in the *proof*, not in the nullifier. The nullifier is deterministic in `(secret, scope_id)`.
- **Why it works / why it fails:** The construction's Section on two-layer blinding conflates two different linkability properties: (1) proof-level linkability (two proofs by the same agent look different to an observer) — addressed by `blindingNonce`; (2) nullifier-level linkability (the same credential nullifier appears at RS_j and is matched to the enrollment leaf) — NOT addressed. The credentialBlinding randomizes the *commitment*, not the nullifier.
- **In-threat-model?** Depends on threat model statement. If the AS is semi-trusted and has network-level visibility into RS calls, this is fully in-scope. The construction must either: (a) define a `scope_id` derivation that the AS cannot predict (e.g., RS-side secret + nonce), or (b) prove that the AS has no access to presented nullifiers (requires AS-RS channel assumption not stated), or (c) formally exclude this from the threat model and bound what AS learns.

---

### Attack 4: Cumulative Encoding Invariant Not Enforced In-Circuit for AgentPolicy

- **Attack:** The CLAUDE.md states: "`validateCumulativeBitEncoding()` enforces the implication rules; the **Delegation** circuit enforces them on-chain." The selective scope proof runs through the **AgentPolicy** circuit, not Delegation. A malicious agent operator constructs a credential commitment where the committed bitmask sets `FINANCIAL_MEDIUM` (bit 3) without setting `FINANCIAL_SMALL` (bit 2), violating the cumulative encoding. The AgentPolicy circuit checks "bit 3 is set in bitmask" and outputs `predicate_satisfied = 1`. The RS grants `FINANCIAL_MEDIUM` access. The operator has proved a permission predicate over a structurally invalid bitmask that was never legitimately issued.
- **Why it works / why it fails:** The operator controls bitmask as a *private* witness input. The on-chain commitment `Poseidon2(Poseidon5(..., bitmask, ...), credentialBlinding)` is hiding (by design — that's the whole point of the new blinding). The circuit range-checks `credentialBlinding` via `Num2Bits(128)` but nothing in the described circuit change enforces `bitmask[3] → bitmask[2]`. SDK-level validation (`validateCumulativeBitEncoding`) runs at credential creation, but the adversarial operator bypasses the SDK and constructs the witness directly.
- **In-threat-model?** Yes — but only if the circuit enforces it. The construction as described does **not** include cumulative-encoding constraints in AgentPolicy, only in Delegation. The fix is surgical: add `bitmask[3] * (1 - bitmask[2]) === 0` (and similar) as explicit constraints in AgentPolicy, or add a sub-circuit that verifies the implication chain for all 8 bits. Without this, the blinding construction is sound for hiding but not for soundness of permission semantics.


## Persona: cu_ciso

### Attack 1: Non-FIPS Cryptographic Primitives Violate NCUA Part 748 Appendix B

- **Attack:** The construction's credential commitment uses `Poseidon2(Poseidon5(...), credentialBlinding)` and Groth16 proofs over BN254. I ask my vendor: "Show me where Poseidon appears in FIPS 180-4, FIPS 202, or SP 800-208. Show me where BN254 appears in FIPS 186-5." Neither does. NCUA Part 748 Appendix B §III.C requires "encryption and cryptographic tools" to meet NIST-approved standards. GLBA Safeguards Rule (16 CFR §314.4(e)) mandates "current cryptographic standards." My NCUA examiner runs a checklist. "Is the hash function FIPS-approved?" **No.** Full stop.
- **Why it works:** The construction nowhere claims FIPS compliance or provides a compliance bridge (e.g., a hybrid construction where the ZK commitment is anchored to an SHA-3 outer layer that examiners can see). The differentiation claim ("AS-blind, constant-size") depends entirely on Poseidon's algebraic friendliness — swapping in SHA-256 inside Circom would balloon the constraint count past pot16.ptau. This is not a theoretical gap; it is an actual examination finding category.
- **In-threat-model?** No. Construction must address. Either explicitly scope out regulated financial use cases, or provide a FIPS bridge argument (e.g., outer SHA-3 envelope, HSM-attested proof generation, reference to NIST PQC candidates for future alignment).

---

### Attack 2: Selective Disclosure Destroys the Audit Trail NCUA Examiners Require

- **Attack:** The construction's headline property is that "the RS learns only that the predicate is satisfied, not the full permission bitmask." I am the RS operator (a credit union core system). There is a breach. My NCUA examiner sits across the table and asks: "Which permissions did the agent have when it accessed member records on 14 June?" I go to my logs. I have: a Groth16 proof, a public predicate (`bit 7 is set`), and a nullifier hash. I do **not** have the full bitmask because the construction explicitly hides it from me. NCUA Part 748 and FFIEC CAT Domain 1 (Cyber Risk Management) require that I can reconstruct "what happened, who was involved, and what data was affected." I cannot. The construction's privacy guarantee and my regulatory audit obligation are structurally opposed.
- **Why it works:** Section 1 of the construction is "verbatim" (per the candidate) — the RS-blind property is the core claim. The two-layer blinding rationale in the update only reinforces that the RS sees less, not more. There is no mention of an operator-held audit log, an escrow of the unblinded bitmask, or a regulator-accessible decryption path.
- **In-threat-model?** No. Construction must address. A compliant deployment would need an auditor escrow — a separate, examiner-accessible record of the full credential (bitmask, expiry, operator identity) that is NOT presented to the RS but IS available under subpoena or NCUA examination. The construction is silent on this architecture.

---

### Attack 3: "Stored Alongside Credential Secrets" Is Not a Key Custody Specification

- **Attack:** The update states `credentialBlinding` is "sampled by the operator at enrollment time, stored alongside credential secrets." I invoke my Vendor Management Policy and FFIEC CAT Domain 3 (Cybersecurity Controls — Data Security). I ask: stored **where**, exactly? In a browser? A mobile keychain? An operator database? An HSM? NCUA examiners for third-party risk (Part 748 §III.F) require that I document the key management lifecycle of every cryptographic secret touching member data. "Alongside credential secrets" is one sentence. It tells me nothing about FIPS 140-2 Level 2 hardware requirements, key rotation cadence, split-knowledge controls, or what happens when the operator's storage is compromised. If `credentialBlinding` leaks, the on-chain leaf can be brute-forced back from 2^135 to the known 163 bitmask configurations — the construction's own Section 4 admits this.
- **Why it works:** The construction deliberately defers key storage to the operator ("sampled by the operator"). For a ZK proof system this is standard — but for a regulated financial institution, "operator decides" is not a custody model. My board wants a controls matrix. My examiner wants a FIPS reference. The construction provides neither.
- **In-threat-model?** No. Construction must address. At minimum, the spec needs a normative key custody requirement (e.g., "MUST store `credentialBlinding` in a FIPS 140-2 Level 2 HSM or equivalent") and a key rotation policy. Without this, every credit union deployment has an undocumented key custody gap that an NCUA examiner will flag as a material finding.

---

### Attack 4: AS-Blind Presentation Removes the Authorization Server from the Audit Log — Exactly When Regulators Need It Most

- **Attack:** The candidate's differentiation claim explicitly targets "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)." Under RFC 7662, the AS sees every token introspection call — it is a mandatory choke point that logs "agent X presented token Y to RS Z at time T." Under this construction, the AS is entirely out of the presentation flow. My SOC 2 Type II audit (CC6.1, CC6.2) and FFIEC CAT require that I demonstrate "monitoring of all access to sensitive data." The AS log is the canonical source of that evidence for OAuth deployments. If I switch to Bolyra, that log disappears. I now have RS-local logs only, with no cross-RS correlation capability, because the proof system's linkage-prevention property (the `blindingNonce`) is also designed to prevent me from correlating presentations across resource servers.
- **Why it works:** The construction defends the adversarial-AS model well cryptographically — but from my perspective as CISO, the AS being "untrusted" means I've just eliminated a mandatory control point. The RFC 7662 limitation (AS must cooperate) is, from a regulatory standpoint, a **feature**: it means there is a single authoritative log. The construction's scenario 2 ("AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation") is a threat model that credit unions are not permitted to adopt — their AS is their core processor or identity provider, which they are contractually and regulatorily required to trust and log through.
- **In-threat-model?** No. Construction must address. The use-case framing needs to explicitly exclude regulated financial institution deployments where AS logging is a compliance requirement, OR it must propose a complementary logging layer (e.g., a privacy-preserving audit log where nullifier hashes are aggregated at a regulator-accessible endpoint without revealing linkable presentation content).


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Ten years shipping production introspection. Every ZK claim is suspect until proven not achievable by the existing RFC stack.*

---

### Attack 1: Per-RS Introspection Policy Already Delivers Selective Disclosure

**Attack:**
The construction's core claim (§ "claim") is that the agent proves it *satisfies a required permission predicate without revealing the full permission set to the RS*. RFC 7662 §2.2 allows the AS to return a scope value in the introspection response that is tailored to the calling RS — the AS simply omits permissions irrelevant to that RS. Pair this with `draft-ietf-oauth-jwt-introspection-response` and the RS validates a signed JWT offline; the AS is off the hot path after token issuance. The RS never sees the full bitmask. Where is the gap?

**Why it works / why it fails against the construction:**
This closes the *static* selective-disclosure gap entirely. It fails against the construction only if you accept the **runtime-adaptive** predicate scenario from the `gap_to_close` field: the agent must prove a predicate *chosen at presentation time*, not one fixed at issuance. An AS-minted JWT encodes scope at issuance; it cannot retroactively satisfy a predicate the RS invents post-issuance without a fresh token. However, the construction as written does **not clearly exhibit** a runtime-adaptive predicate: the `bitmask` is fixed at enrollment and the circuit checks `(bitmask & requiredMask) == requiredMask` — a static predicate over a static value. If the required mask is always known at issuance time, the AS could mint a JWT encoding exactly `(bitmask & requiredMask)` per RS, achieving the same result.

**In-threat-model?**
**No — construction must address.** The construction must articulate *why* the required predicate cannot be known at issuance time. Without that, per-RS introspection policy is a credible RFC 7662 baseline for this property.

---

### Attack 2: The 8-Bit Bitmask Enumeration Threat Is Overstated — DPoP Already Provides Sender-Constraint Binding

**Attack:**
The construction defends against on-chain leaf enumeration by adding 128-bit `credentialBlinding`, because "~163 valid bitmask configurations can be enumerated." But 163 configurations is a *preimage* attack on the commitment, not a forgery attack on the proof. An adversary who enumerates all 163 candidates and finds which one matches the on-chain leaf learns the agent's bitmask — but they still cannot produce a valid ZK proof without the agent's private key (`Ax`, `Ay`). EdDSA key secrecy already prevents the adversary from creating a false proof. The blinding adds hiding for the bitmask value itself, but the threat model must specify *who* learns the bitmask and *what harm* that causes.

Meanwhile, RFC 9449 DPoP already provides sender-constraint (the token is bound to a holder key) and the RS can verify holder binding without any bitmask enumeration concern. The construction's credential commitment blinding addresses a confidentiality property (bitmask privacy against a chain observer), not an *unforgeability* property. RFC 7662 + DPoP covers unforgeability without ZK.

**Why it works / why it fails against the construction:**
The construction survives on the *confidentiality* axis: a chain observer who reads on-chain leaves should not learn the bitmask. DPoP provides no help here. But the construction's **Section SP game (Step 1)** ties bitmask hiding to the reduction — if bitmask hiding is not load-bearing for the security proof's unforgeability argument, the 128-constraint addition is defensive-in-depth, not a fundamental gap from RFC 7662.

**In-threat-model?**
**Partially.** The construction must explicitly separate (a) bitmask confidentiality against chain observers (ZK property, survives) from (b) unforgeability of scope claims (also ZK, but DPoP does not compete here for the same reason). Currently the threat model description conflates these two properties into one "Attack 2" narrative. An RS operator reading the paper will ask: "Why can't I just use DPoP + opaque token and keep the bitmask off-chain entirely?"

---

### Attack 3: AS-Blind Presentation Is Already Achievable via `cnf`/PoP JWTs — The Construction's `blindingNonce` Does Not Uniquely Enable It

**Attack:**
RFC 7800 confirmation method (`cnf`) + proof-of-possession JWTs allow the RS to verify a token offline without calling the AS. The agent presents a JWT with a `cnf` claim committing to its key, then produces a PoP assertion at presentation time. The AS is completely off the hot path. `draft-ietf-oauth-jwt-introspection-response` makes this signed and cacheable. The construction's `blindingNonce` (ephemeral, per-presentation) is presented as preventing cross-RS proof linkability — but DPoP already provides per-request proof freshness via the `nonce` claim (RFC 9449 §8), and a new DPoP proof per request is already standard practice.

**Why it works / why it fails against the construction:**
DPoP nonces are AS-issued or RS-issued (RFC 9449 §8), meaning fresh nonces require an AS or RS roundtrip to obtain. The construction's `blindingNonce` is *agent-sampled* — no external party issues it. This is the genuine gap: agent-side, unilateral freshness without AS cooperation. However, the construction does not currently *prove* that AS-issued DPoP nonces require an AS roundtrip for every presentation. An implementation where the RS pre-distributes a nonce pool to the agent would approximate agent-sampled freshness.

**In-threat-model?**
**Yes — construction survives, but incompletely argued.** The construction should explicitly cite that RFC 9449 §8 nonces require RS or AS issuance, creating a coordination dependency the construction eliminates. Without this citation, the `blindingNonce` novelty reads as an implementation convenience, not a cryptographic necessity.

---

### Attack 4: The Adversarial-AS Scenario Is Outside Any Real OAuth Deployment Threat Model

**Attack:**
The `scenarios` field includes "AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation." The entire RFC 7662 ecosystem — token issuance, introspection, JWT signing keys — assumes the AS is a trusted party. If the AS is adversarial, it can mint tokens claiming any scope, forge introspection responses, or revoke valid tokens arbitrarily. The ZK construction does not solve this: the on-chain credential commitment was *written by the operator* (who controls `Ax`, `Ay`), and the circuit verifies against a `humanMerkleRoot` maintained by a smart contract — which itself has admins. An adversarial operator can enroll a fake agent with a fraudulent `bitmask`. The construction simply moves trust from AS to smart contract admin, it does not eliminate trust.

**Why it works / why it fails against the construction:**
The construction partially survives: it ensures that *once a credential is committed on-chain*, the bitmask cannot be silently altered by the AS post-issuance. This is a meaningful immutability property RFC 7662 lacks (an AS can silently narrow or expand returned scope in an introspection response). But the construction must acknowledge that on-chain commitment only locks the bitmask *after enrollment* — the enrollment step itself requires operator trust equivalent to AS trust. The adversarial-AS property is real but narrower than claimed.

**In-threat-model?**
**No — construction must address.** The construction should replace "adversarial-AS model" with the precise property: *post-issuance bitmask immutability* — once committed on-chain, neither the operator nor any AS-equivalent can alter the permission set without creating a new on-chain leaf detectable by any observer. This is a real differentiator from RFC 7662; "adversarial AS" as written overclaims and invites exactly this objection.


## Persona: spiffe_engineer

---

### Attack 1: The Operator Key Is the AS — Adversarial-AS Model Is Circular

- **Attack:** The construction claims ZK proofs survive an adversarial AS (Section: "scenarios — AS is semi-trusted and RS needs cryptographic assurance independent of AS cooperation"). But the construction's trust anchor is the **operator's EdDSA private key** that signs `AgentCredential(modelHash, permissions, expiry)`. The operator IS the credential-issuing authority — structurally identical to an AS. If the AS is adversarial, the operator can issue a credential with any bitmask it chooses. The `credentialBlinding` (128-bit) is sampled by the operator at enrollment and stored alongside credential secrets — meaning an adversarial operator knows the blinding factor and knows what's hidden. The ZK proof proves "this credential commits to *some* bitmask that satisfies predicate P" — but an adversarial operator can choose that bitmask freely. The blinding hides the bitmask from the **RS and on-chain observers**, not from the entity the threat model says is adversarial.
- **Why it works / fails:** The construction conflates two distinct adversaries: (a) the RS learning the full bitmask (→ blinding helps), and (b) the AS/operator issuing false scope (→ blinding is irrelevant). RFC 7662 has the same AS-trust problem, but the construction doesn't eliminate it — it just moves it from the AS to the operator key. The "AS-blind" property in the gap-to-close is only partially satisfied: blind to RS, not blind to issuer.
- **In-threat-model?** **No.** Construction must clarify that "adversarial AS" means "AS that is honest-but-curious about scope revealed to RS," not "AS that lies about issued scope." If the latter is in scope, the construction needs a different trust model (e.g., operator key held in HSM with auditable issuance log, or threshold signing).

---

### Attack 2: Replace the Entire Construction with a SPIRE Custom Attestor

- **Attack:** From the SPIFFE toolbox: SPIRE supports [custom node attestors](https://spiffe.io/docs/latest/spire-about/spire-concepts/#node-attestation) and workload attestors via plugin API. The `modelHash` in `AgentCredential` is structurally identical to a SPIFFE workload selector — e.g., `docker:image_id:sha256:abc123`. A SPIRE attestor plugin that (1) verifies the running workload's image digest matches an enrolled hash, (2) queries an operator-controlled permission registry, and (3) issues a short-lived JWT SVID with only the scopes needed for the target RS, provides the same "selective scope at moment of use" property. The RS validates the JWT SVID offline (no AS roundtrip — SPIRE rotates SVIDs every ~1hr, RS caches the JWKS). The claimed property "agent chooses what to disclose at the moment of use" is covered by issuing per-RS scoped SVIDs at request time via the Workload API. No Groth16 keys, no `pot16.ptau`, no on-chain leaves.
- **Why it works / fails:** The construction's rebuttal must identify what SPIRE cannot express. The 8-bit cumulative bitmask (256 configurations per CLAUDE.md) is well within JWT claim space. The ZK proof's value is **constant-size regardless of bitmask width** — but the construction's actual bitmask is 8 bits, making this a theoretical claim with no production pressure. The on-chain commitment adds a revocation-by-root mechanism, but SPIRE's CRL + short SVID TTL already handles revocation. The construction must defend the on-chain component specifically, not ZK in the abstract.
- **In-threat-model?** **No** (requires response). The claim of superiority over RFC 7662 is established; superiority over SPIFFE+SPIRE is not addressed anywhere in the construction. This is the layer where the comparison belongs.

---

### Attack 3: WIMSE `wth`/`ath` Binding Covers "AS-Blind Presentation"

- **Attack:** [draft-ietf-wimse-arch](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/) defines **workload proof-of-possession**: the calling workload holds a private key bound to its SVID, and presents a `wth` (workload token holder) DPoP-style binding per request. The RS verifies the binding without an AS roundtrip — it holds the JWKS from the SPIRE server trust bundle. The construction's "AS-blind presentation (no AS roundtrip, agent chooses what to disclose at the moment of use)" is precisely what WIMSE `ath` + `wth` provide: the workload selects which bound token to present per RS, the AS is not contacted per-request, and proof-of-possession is cryptographically enforced at the RS. The ZK proving step (~11,330 constraints, ~2 min for full proof per CLAUDE.md `test:circuits:slow`) adds latency that WIMSE's ECDSA PoP verification does not.
- **Why it works / fails:** WIMSE does not yet provide **predicate-based selective disclosure** — it discloses the full bound scope to the RS. The construction's genuine advantage is that the RS learns only "predicate P is satisfied" without learning the bitmask value. This is a real gap in WIMSE. However, the construction must make this the *explicit* claim, not the broader "AS-blind presentation" framing (which WIMSE covers). The construction should drop the AS-blind framing and sharpen to: "RS learns zero bits about permissions beyond threshold satisfaction."
- **In-threat-model?** **Yes** (construction survives if scoped correctly). But the current framing in the gap-to-close overreaches — "AS-blind presentation" is claimed as the unique property, when it's actually predicate-hiding that WIMSE cannot express.

---

### Attack 4: Trust-Domain Federation Gives You "Portable Identity" — Name the Actual Gap

- **Attack:** SPIFFE trust-domain federation (`spiffe://domainA/...` → `spiffe://domainB/...` via federated bundles) provides the "portable identity" property across organizations. An agent enrolled in `spiffe://operator-a.com/agents/gpt4-prod` can present its SVID to an RS in `spiffe://operator-b.com/` if the trust domains are federated. The construction claims "portable identity for AI agents" as a core value proposition (bolyra.ai positioning). Federation bundle endpoints (RFC 8555-style) are already standardized in SPIFFE. The construction's on-chain `humanMerkleRoot` / credential commitment provides cross-operator portability — but federation achieves this without a shared ledger, using bilateral trust agreements. The construction must name what the ledger provides that bilateral federation cannot: specifically, **trustless multi-operator enrollment without pre-negotiated federation agreements**.
- **Why it works / fails:** The construction does have a genuine answer here: the on-chain commitment enables an agent to prove enrollment to *any* RS on the network without the RS having a bilateral trust agreement with the operator. This is qualitatively different from SPIFFE federation (which requires explicit bundle exchange). But the construction never articulates this. The threat model section and the SP game describe security properties of the ZK circuit; they do not explain why a decentralized trust root is necessary versus SPIFFE's bilateral model. An RS operator reading both would not know which to deploy.
- **In-threat-model?** **No** (construction must address). The "portable" claim is load-bearing for the product, but the construction has no section explaining why SPIFFE federation is insufficient. Add a paragraph to the introduction: "Unlike SPIFFE trust-domain federation, Bolyra requires no bilateral bundle agreement — any RS holding the on-chain root can verify any enrolled agent credential without operator coordination."
