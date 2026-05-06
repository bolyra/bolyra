# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: scopeCommitment Is a Public Bitmask Oracle — SSP Is Broken by Construction

**Attack:** Section 2 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output**. Neither `permissionBitmask` nor `credentialCommitment` contain `sessionNonce`. The output is therefore session-invariant and bitmask-deterministic. A colluding RS playing the SSP game (Section 3) doesn't need to invert Poseidon or break the ZK simulator — it compares `scopeCommitment` values across proofs.

Concretely: the SSP challenger holds credentials `(P_0, P_1)` both satisfying mask `M`, flips coin `b`, and proves with `P_b`. The RS adversary observes `scopeCommitment_b`. With overwhelming probability `Poseidon2(P_0, cc_0) ≠ Poseidon2(P_1, cc_1)` when `P_0 ≠ P_1`, so the adversary returns `b' = b` with probability 1 — not `1/2 + negl(λ)`. SSP is trivially broken.

**Why it works:** The SSP security argument in Section 4 claims "distinguishing requires inverting Poseidon (A2) or breaking ZK simulator." This is false: `scopeCommitment` is a deterministic, public encoding of `permissionBitmask` that sidesteps both. The ZK property protects the proof *transcript*, not public outputs the construction itself exposes. Even if the RS cannot recover `permissionBitmask` in cleartext, it can (a) link all proofs from the same credential across sessions and RSes, and (b) trivially distinguish `P_0` from `P_1` in the SSP game.

The SECU deployment scenario (Section 7) describes a structured 64-bit space with cumulative encoding (bits 0–4 hierarchical per constraint 7) and semantic partitioning (bits 5–15 products, 16–31 dollar thresholds, etc.). This dramatically reduces effective entropy. An RS that can enumerate plausible bitmasks can compute `Poseidon2(candidate, agentMerkleRoot…)` offline. Even without that, cross-session linkability via `scopeCommitment` violates the privacy claim regardless of bitmask entropy.

**In-threat-model?** **No — construction must address.** Either (a) include `sessionNonce` in `scopeCommitment` to make it session-unique, accepting that it no longer serves as a delegation chain seed across sessions, or (b) remove it as a public output entirely and replace with a derived session-scoped commitment. The SSP security proof must be rewritten.

---

### Attack 2: "No AS Roundtrip" Trades One Dependency for Two — and the New Ones Have No SLA

**Attack:** Section 2 claims AS-blind presentation ("No AS contact"). But the presentation protocol requires the RS to verify against `operatorRegistryRoot` and `agentMerkleRoot` "from chain" (Section 2, Presentation Protocol step 3). This is not AS-independence — it is AS-replacement with a blockchain RPC dependency plus a Merkle tree indexing dependency. At proof time the RS must either (a) make a live on-chain read, or (b) maintain a cached/synced copy of both Merkle roots.

From a procurement conversation at SECU: Auth0 and WorkOS publish 99.99% uptime SLAs on their token endpoints with documented failover, status pages, and NCUA-auditable availability logs. What is the SLA on the blockchain RPC node? What happens to FCRA-gated agent requests during a Geth/Infura outage? The construction does not specify a fallback. Section 7 frames the AS as a "hot-path bottleneck" — but replacing it with an unspecified chain RPC that RS must poll or cache introduces the same bottleneck class with worse operational tooling and no existing credit union vendor management template.

The "30-entry root history buffer" (Section 5, Extension note) implies roots change. RS must track which root is valid at proof time, adding synchronization complexity that WorkOS solves trivially by returning the current JWKS at token verification.

**Why it works / why it fails:** The cryptographic claim survives — AS cannot forge proofs without the operator's EdDSA key. But the operational claim ("no AS contact") is misleading: it's "no AS contact, plus synchronous or near-synchronous chain state access." The threat model (Section 3) does not model chain RPC availability as an adversary capability. In a credit union's vendor risk framework, an unmodeled dependency is an automatic flag.

**In-threat-model?** **No — construction must address.** Add a chain-access threat model (what if the RPC node is unavailable or returns stale state?), specify cache freshness bounds, and define the operational SLA story. Without this, the deployment scenario in Section 7 is aspirational, not deployable.

---

### Attack 3: Operator Key Compromise Gives the Adversary the Full 30-Root History Window

**Attack:** Section 2 specifies the Operator Registry Merkle Tree, and Section 5 notes a "30-entry root history buffer." The adversarial-AS defense (AFR game, Section 3) assumes the adversary cannot produce a valid EdDSA signature without `sk_i`. But the game does not model operator key compromise — a realistic threat for a credit union with a 64-bit permission space and multi-year credential lifetimes.

If `sk_op` is compromised (insider threat, HSM breach, supply chain), the adversary can generate valid PLONK proofs against *any* of the 30 buffered roots and assign *any* `permissionBitmask` to any agent. The operator registry provides no revocation path that is faster than 30 root updates. The construction does not specify how frequently roots update, so the revocation window is undefined. By contrast, Auth0's JWKS rotation is instantaneous — RS libraries poll the JWKS endpoint, stale keys stop validating within one TTL cycle (typically 24h, configurable to seconds).

Constraint 4 (operator registry Merkle membership) is the adversarial-AS defense. It fails against a compromised operator because the adversary *is* a valid member. The AFR reduction in Section 4 only covers the case where the adversary lacks `sk_i` — it says nothing about the case where `sk_i` is compromised.

**Why it works:** The construction's Section 8 claim 2 ("no adversarial-AS resistance in BBS+") is used to differentiate from the baseline. But the construction's own adversarial-AS defense has a structural gap: it replaces one trust root (AS) with another (operator registry + operator EdDSA key) and provides no emergency revocation. For NCUA-regulated credit unions, "no revocation path faster than 30 Merkle root updates" is not a security improvement over "rotate your AS signing key."

**In-threat-model?** **No — construction must address.** Define a key compromise response protocol: how does SECU revoke a compromised operator key in under 1 hour? Options include an on-chain emergency revocation list (nullifier-style), a time-bound key validity window baked into `credentialCommitment`, or reducing the history buffer with a documented tradeoff. The AFR game must be extended to model `sk_op` compromise as an adversary capability.

---

### Attack 4: The SECU Per-Request Proof Model Requires Pre-Computation Infrastructure That Is Not Specified

**Attack:** Section 7 describes FCRA-gated agents proving `requiredScopeMask` per-request. Section 6 estimates "<5s PLONK (agent)." The presentation protocol (Section 2, step 1) requires the RS to send `(requiredScopeMask, currentTimestamp, sessionNonce)` before the agent can begin proving — meaning the 5s is a blocking, per-request latency on the agent side before any RS response begins processing.

At 260+ SECU branches with concurrent agent activity, a 5s blocking proof per FCRA-gated action is not a performance consideration — it is a product architecture forcing function. Either: (a) agents must pre-generate proofs speculatively for anticipated `requiredScopeMask` values (requiring the RS to telegraph its access policy before the request, which leaks policy to the agent, undermining privacy), or (b) proofs are generated on-demand with 5s latency on every gated transaction, making the system unusable for anything requiring human-scale interaction, or (c) the agent runs a background proving service that amortizes cost — an infrastructure component entirely absent from the construction.

WorkOS issues tokens in <100ms with zero agent-side computation. The construction's Section 8 claim 3 argues RFC 7662 cannot evaluate "runtime-adaptive predicates" — but this is not the objection. The objection is that the construction's proof latency requires an undescribed infrastructure layer before it can match the operational profile of a token endpoint.

**Why it works:** The construction provides circuit constraints and security games but no architectural guidance on proof scheduling, caching, or pre-computation. Section 7 presents a deployment scenario as if 5s latency is a solved problem. For any SECU branch workflow where an agent must respond within a human interaction window (<1s), the construction is not yet deployable without significant additional engineering that is not part of Bolyra. A buyer's "you are a solo founder" question maps directly to this gap: Auth0 has solved proof-of-authorization performance at scale; this construction has an existence proof of a circuit, not a production system.

**In-threat-model?** **Partial — construction should address.** The construction need not become an infrastructure spec, but it must bound the latency claim honestly (is 5s wall-clock or proof generation only?), specify which `requiredScopeMask` values are known in advance (enabling pre-computation), and describe how a proof server or proof cache integrates into the Bolyra protocol without breaking session binding or nullifier uniqueness. Without this, Section 7 reads as aspirational rather than deployable.


## Persona: cryptographer

---

### Attack 1: `scopeCommitment` Is a Stable Fingerprint — SSP Game Is Trivially Broken

**Attack:**
`scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is a **public output** on every proof (Section 2, "Public outputs"). Because `credentialCommitment` is deterministically derived from `(modelHash, opAx, opAy, permissionBitmask, expiry)`, the same credential always produces the **same `scopeCommitment`** regardless of `sessionNonce`. Any adversary — a single RS, or two colluding RSes — observing two proofs from the same agent immediately learns they share the same credential: `scopeCommitment` is a permanent cross-session fingerprint.

**Why it breaks SSP:** The SSP game (Section 3) gives the adversary a challenger who flips a bit and proves with P_b. Augment the game in the standard way with an oracle that answers proof queries before the challenge. The adversary queries the oracle for both P_0 and P_1, records `sc_0` and `sc_1`. The challenge proof leaks `sc_b`. Since `sc_0 ≠ sc_1` whenever `permissionBitmask` differs (Poseidon collision resistance, Assumption A2), the adversary wins with probability 1. The SSP reduction (Section 4) claims "transcript simulatable from public signals" — but `scopeCommitment` **is** a public signal, and it's a deterministic function of the secret. The ZK simulator can produce the same public outputs, but a computationally unbounded adversary with oracle access has already fingerprinted both options.

**Also broken:** The "AS-blind presentation" claim in Section 8 states "AS learns nothing about... that a proof occurred." The AS issued every credential and therefore knows every `(permissionBitmask, credentialCommitment)` pair. It can precompute `scopeCommitment` for all its credentials in O(N) hashes, then scan on-chain proof transcripts to track exactly which agents proved, when, and how frequently — without any RS cooperation.

**In-threat-model?** No. The semi-trusted AS (A_AS) is explicitly modeled, but the game only asks whether the AS can **forge** proofs (AFR), not whether it can **track** them. The SSP game has no oracle phase. Both gaps need addressing. Fix candidates: bind `scopeCommitment` to `sessionNonce` — i.e., `Poseidon2(permissionBitmask, sessionNonce)` — or drop it as a public output entirely if it is only used for delegation.

---

### Attack 2: Nullifier Precomputation — AS-Blindness Collapses Under On-Chain Transparency

**Attack:**
The nullifier `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` (Section 2, constraint 9) is designed to prevent double-spend. However, `sessionNonce` is provided by the RS and appears in the verifier's public input. If proofs are submitted on-chain (or even off-chain to a shared log for NCUA audits as described in Section 7), the `(sessionNonce, nullifierHash)` pair is visible to anyone — including the AS.

The AS knows `credentialCommitment` for every credential it issued. For each observed `(sessionNonce, nullifierHash)` on-chain, the AS can check: does `Poseidon2(credentialCommitment_i, sessionNonce) == nullifierHash`? Over N issued credentials, this is O(N) evaluations per on-chain event — trivial for any realistic N. The AS therefore learns: (i) **which credential** was used, (ii) **when**, and (iii) **how many times** the agent presented.

**Formal framing:** Define a game **AS-Trace**: adversary controls the AS, observes on-chain transcripts, wins if it correctly identifies which credential produced at least one observed nullifier with probability > negl(λ). This game is not defined in Section 3. The reduction in Section 4 only addresses AFR (forgery), not tracing. The claim "AS learns nothing about... that a proof occurred" (Section 8) is therefore unsubstantiated — there is no game, no adversary model, and no reduction for the AS-tracing scenario.

**Aggravating factor:** the deployment scenario (Section 7) explicitly calls for on-chain ZK proofs for NCUA audits. This makes every nullifier and session nonce publicly accessible to the issuing AS by construction.

**In-threat-model?** No. AS-tracing is absent from the threat model and the security game definitions. Fix candidates: nullifier = `Poseidon2(credentialCommitment, sessionNonce, agentBlindingFactor)` where `agentBlindingFactor` is fresh per-session randomness unknown to the AS; or use a PRF-based nullifier keyed on agent-private state.

---

### Attack 3: Universal Setup Subversion — AFR Claim Reduces to Nothing

**Attack:**
The construction uses PLONK with a **universal setup** (Section 2, "Proving system: PLONK universal setup"), and the security argument for both SSU and AFR reduces to PLONK knowledge soundness under the **Algebraic Group Model + Random Oracle Model** (Section 4). Knowledge soundness in these models is an honest-CRS assumption: the extractor works only if the structured reference string (SRS / powers-of-tau) was honestly generated.

The threat model (Section 3) names three adversary classes — semi-trusted AS, colluding RS, network observer — but **does not model a malicious setup participant**. Under a subverted SRS, PLONK is not knowledge-sound: a malicious prover can generate accepting transcripts for false statements without a valid witness. Concretely, an adversary who controls even a single SRS contributor in an underspecified ceremony can:

- Produce a valid `SelectiveScopeProof` for any `(requiredScopeMask, agentMerkleRoot, operatorRegistryRoot)` triple without possessing any enrolled operator key (`sk_i`).
- Bypass constraint 4 (operator registry membership) and constraint 3 (EdDSA signature) entirely, since the SRS subversion is at the arithmetic constraint system level.

This completely voids the AFR claim. The reduction sketch in Section 4 says "Extract witness via A1" — but A1 (PLONK knowledge soundness) does **not hold** under subverted setup. The construction does not specify the ceremony (multi-party computation, KZG tau, number of participants, attestation), nor does it state what trust assumption the RS is making when it pins `operatorRegistryRoot`.

**In-threat-model?** No. PLONK universal setup is cited without a setup ceremony spec or a ceremony trust assumption. The AFR game (Section 3) implicitly assumes an honest CRS — this must be stated explicitly as a setup assumption, and the construction must specify the ceremony or reference one. Without it, the "cryptographic assurance independent of AS integrity" claim (Section 7) is only as strong as the weakest SRS contributor.

---

### Attack 4: Incomplete Cumulative Encoding — Malformed Bitmask Satisfies Predicate

**Attack:**
Section 2, constraint 7 ("Cumulative bit encoding") lists exactly three R1CS constraints:

```
permBits[4] * (1 - permBits[3]) === 0
permBits[4] * (1 - permBits[2]) === 0
permBits[3] * (1 - permBits[2]) === 0
```

The stated intent (Section 7) is that branch-tier bits 0–4 are cumulative: bit `i` set implies bits `0..i-1` are also set. A complete encoding for bits 0–4 requires enforcing `bit[i] → bit[i-1]` for all `i ∈ {1,2,3,4}`, which is **four** constraints. The listed three omit the constraint `permBits[1] * (1 - permBits[0]) === 0`. Bits 5–63 have no cumulative constraints at all despite the circuit claiming a 64-bit cumulative policy space.

**Exploit:** A malicious agent (or a compromised credential issuer) can set `permBits[1] = 1, permBits[0] = 0`. This passes all listed circuit constraints. The agent claims tier-2 access without tier-1. Depending on SECU's tier policy, this grants higher-privilege access (tier-2 branch operations) without the prerequisite lower-tier credential — a horizontal privilege escalation within the bitmask model.

**Against the SSU reduction:** the SSU game asks whether an adversary can prove a `requiredScopeMask` not satisfied by the actual credential. This exploit does not violate SSU as stated — the bitmask *does* satisfy the bitwise AND predicate (`permBits[i] ≥ reqBits[i]`). The violation is in the **semantic integrity** of the cumulative encoding, which is a higher-level application invariant the circuit is supposed to enforce but provably does not. The security argument has no game covering this property.

**In-threat-model?** No. The threat model contains no game for semantic correctness of the cumulative encoding. This is a specification gap between the SECU deployment semantics (Section 7) and the circuit constraints (Section 2). Fix: add `permBits[k] * (1 - permBits[k-1]) === 0` for all intended cumulative ranges and state a separate **Semantic Integrity** game over the encoding.


## Persona: cu_ciso

---

### Attack 1: NCUA Examination Artifact — "What Does My Examiner Actually See?"

- **Attack:** The CISO pulls Section 7's deployment scenario. The construction claims "NCUA examiners verify every FCRA event has a ZK proof." But what the examiner receives is: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`, `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`, and `agentMerkleRoot`. These are opaque field elements over BN254. NCUA Part 748.0(b) requires a "program to respond to incidents of unauthorized access" — which presupposes an audit log that is *human-interpretable and linkable to a member record, transaction, and authorization chain*. The construction proves the agent *had* permission at time T, but produces no artifact linking that proof to: (a) which member's FCRA data was accessed, (b) which branch/agent instance, (c) what action was taken. The FFIEC Cybersecurity Assessment Tool (CAT) Domain 3 "Threat Intelligence and Collaboration" and Domain 4 "Cybersecurity Controls" both require access event logging with sufficient context for forensic reconstruction. A Poseidon hash is not a log entry. The examiner cannot map a `nullifierHash` to a SAR filing obligation under 31 U.S.C. 5318(g).
- **Why it works:** The construction is designed to be *unlinkable* (scope privacy game SSP). That property is exactly what makes it useless as an examination artifact. Privacy and auditability are in direct tension, and the construction resolves that tension entirely in favor of privacy. Section 7 elides the audit integration layer entirely.
- **In-threat-model?** No. The construction must address how ZK proof transcripts bind to interpretable audit events (member ID, action, timestamp, data category) without leaking the hidden `permissionBitmask`. A plausible fix is a separate audit commitment path — but it is not specified, which means the examiner narrative in Section 7 is presently unfounded.

---

### Attack 2: Trusted Setup as Unassessable Third-Party Risk

- **Attack:** Section 2 specifies "PLONK universal setup" and Section 5 maps it to "Spec section 3.3," but neither the construction nor the Bolyra spec describes *who ran the structured reference string (SRS) ceremony, where the toxic waste was destroyed, and how the CU can independently verify the ceremony transcript.* PLONK's soundness reduces to knowledge soundness under the AGM + ROM (Assumption A1 in Section 4), but that reduction is vacuous if the SRS is backdoored — a backdoored SRS lets any party forge valid proofs for any witness, including forged `permissionBitmask` values satisfying any `requiredScopeMask`. Under NCUA's third-party risk guidance (Letter to Credit Unions 07-CU-13) and GLBA Safeguards Rule 16 CFR Part 314.4(f), the CU must assess the security of all service providers with access to or impact on member data systems. The SRS is a cryptographic trust anchor with no analogue in the CU's existing vendor management framework — there is no SOC 2 Type II report that covers "trusted setup ceremony integrity." The CISO cannot sign a vendor risk attestation for Bolyra if Bolyra cannot produce a verifiable MPC ceremony transcript with independent auditor attestation.
- **Why it works:** The construction correctly assumes A1 (PLONK knowledge soundness) but treats it as an axiom rather than a property the CU can operationally verify. This maps to a gap the examiner will surface immediately under FFIEC CAT Domain 5 "Cyber Risk Management and Oversight" — specifically, third-party dependency risk assessment. A construction whose security foundation cannot be independently verified by the relying party fails the vendor management test regardless of mathematical correctness.
- **In-threat-model?** No. The adversary model in Section 3 lists "Semi-trusted AS," "Colluding RS," and "Network observer" — but omits the SRS ceremony operator as an adversary class. This is a fourth adversary the construction must place in threat model and bound.

---

### Attack 3: Credential Revocation Gap During Incident — "My Agent Was Compromised at 2:17am"

- **Attack:** The CISO runs the 2am scenario. An agent credential is compromised — the signed tuple `(credentialCommitment, sigR8x, sigR8y, sigS)` leaks from agent memory or the operator's signing infrastructure. The construction's only expiry mechanism is `currentTimestamp < expiryTimestamp` via `LessThan(64)` (Constraint 8). There is no real-time revocation path. The "30-entry root history buffer" in Section 7 is a backward-compatibility window for the Merkle root, not a revocation mechanism. To revoke a credential, the operator must (a) re-issue a new Merkle tree excluding the compromised leaf, (b) publish a new `agentMerkleRoot` on-chain, and (c) wait for RSes to re-pin the new root. During that window — potentially hours to days depending on the on-chain update cadence and RS configuration lag — the compromised credential remains valid against the old pinned root. NCUA Part 748 Appendix B (Interagency Guidelines Establishing Information Security Standards) §III.C requires institutions to "contain and control" incidents including "preserving evidence" and "restoring operations" — not "wait for the Merkle tree to rotate." The Tier-1 ops team cannot issue a targeted revocation; they can only escalate to whoever controls the operator key and the on-chain registry, which is Bolyra, which is a third party.
- **Why it works:** The construction optimizes for the happy path (no AS roundtrip, fast proof, constant size) at the cost of the incident path (no targeted revocation, no real-time containment). The threat model's AFR game (Section 3) only bounds *forgery without the operator key* — it does not bound the scenario where the operator key or the credential material itself is compromised. That scenario exists and is the dominant real-world incident class for credential systems.
- **In-threat-model?** No. The construction must specify a revocation protocol with an SLA compatible with NCUA incident response obligations — and must clarify the blast radius (how many credentials are invalidated per Merkle root rotation) and the root update latency guarantee.

---

### Attack 4: On-Chain Registry Availability vs. Core Processor SLA

- **Attack:** Section 7 states RSes verify against `operatorRegistryRoot` and `agentMerkleRoot` "from chain." The construction eliminates AS roundtrip dependency (a win) but substitutes a blockchain dependency. The CISO maps this against operational SLA requirements: SECU's core processor (FiServ/Jack Henry tier) commits to 99.99% availability — approximately 52 minutes downtime per year. Public EVM-compatible chains (the implied deployment target, given "~200K gas EVM" in Section 6) have had multi-hour outages (Solana multiple times, Polygon state sync delays, Arbitrum sequencer failures). Even Ethereum mainnet experienced client-diversity incidents. The RS cannot verify a proof if it cannot read the current `operatorRegistryRoot` from chain — or if it must accept a stale root from the history buffer, creating a window where a rotated-out (revoked) operator key still passes verification. The construction does not specify the target chain, its SLA, whether RS pins roots locally (creating staleness risk) or queries chain per-request (creating availability dependency), or what the fallback behavior is when the chain is unreachable. Under FFIEC CAT Domain 4 "Cybersecurity Controls," the CU must maintain resilience for all critical authorization paths. "Authorization gated on blockchain availability" is an exam finding waiting to happen.
- **Why it works:** The construction frames the absence of an AS roundtrip as an unambiguous improvement (Section 8, Gap 5: "AS-blind presentation"). But it replaces one liveness dependency (AS availability) with another (chain availability) without comparing their SLAs or specifying the CU's operational posture when the chain is unreachable. The examiner will ask: "What happens to member transactions when your blockchain is down?" The construction has no answer.
- **In-threat-model?** No. The availability and liveness properties of the on-chain registry are entirely out of scope in the threat model and deployment scenario. The construction must specify target chain SLA, RS root-caching policy with staleness bounds, and a degraded-mode authorization fallback — or concede that it trades one availability dependency for another of equal or greater operational risk.


## Persona: rfc7662_advocate

---

### Attack 1: JWT Introspection Response Already Removes the AS from the Hot Path — Your "AS-Blind" Claim Is Doing No Work

- **Attack:** `draft-ietf-oauth-jwt-introspection-response` (already in Last Call) lets the AS pre-sign a scope response per RS, bound to that RS's audience (`aud` = RS identifier per RFC 8707). The RS pins the AS public key and verifies offline — zero AS contact at request time. The RS evaluates `requiredScopeMask` against the JWT's `scope` claim locally. This is your "no AS roundtrip at proof time" property, already shipped in production. Section 1 of the construction lists AS-blind presentation as a structural gap the baseline cannot match. It can match it, offline, today.

- **Why it works / fails:** The construction survives on one sub-property: the RS receives the **filtered scope set** in the JWT (even if minimal), while the ZK circuit keeps `permissionBitmask` entirely hidden — the RS learns only a single bit (`predicate satisfied / not`). But the construction's Section 8, Gap 5 ("No AS-blind presentation") conflates two distinct claims: (a) AS not in the request path, and (b) RS learns zero information about the permission set. The baseline satisfies (a). The construction must isolate (b) as the load-bearing claim and drop (a) as a differentiator, or the adversary will argue you're counting solved problems.

- **In-threat-model?** Yes — construction survives — but only if Section 8 is rewritten to cleanly assert scope *privacy* (RS learns nothing beyond predicate truth) as the claim, not AS-blindness as a standalone property.

---

### Attack 2: `scopeCommitment` Is a Cross-RS Correlation Handle That the Construction's Own Privacy Games Ignore

- **Attack:** Section 2 lists `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a **public output** revealed to every RS. Because it is derived solely from `permissionBitmask` and `credentialCommitment` — neither of which includes `sessionNonce` — the value is constant across every proof generated from the same credential, regardless of RS or session. Two colluding RSes (A and B, both SECU branches in the deployment scenario of Section 7) that each receive proofs from the same agent can trivially correlate sessions: `scopeCommitment_A == scopeCommitment_B` iff same credential. This is a global pseudonym. RFC 8707 audience-bound tokens + OIDC PPIDs (pairwise subject identifiers) already solve exactly this at the RS layer with no ZK required.

- **Why it works / fails:** Game SSP (Section 3) only models a single RS adversary holding a single transcript. It does not model two colluding RSes. The nullifier (`Poseidon2(credentialCommitment, sessionNonce)`) is session-scoped and does not appear to be the correlation vector — `scopeCommitment` is. The construction explicitly breaks its own unlinkability claim. The fix would be to bind `scopeCommitment` to the session: `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`, but then it no longer serves as a delegation chain seed across sessions (its stated purpose in the Bolyra primitive table).

- **In-threat-model?** **No** — the construction must address this. The multi-RS colluder is an obvious threat in the SECU 260-branch scenario and the current Games do not cover it. Section 8, Gap 5 claims AS-blind presentation while simultaneously emitting a cross-RS tracking token.

---

### Attack 3: Adversarial-AS Separation Is Achievable via RFC 8693 Token Exchange — The On-Chain Registry Adds Operational Cost Without Cryptographic Necessity

- **Attack:** RFC 8693 Token Exchange lets SECU deploy a dedicated *policy AS* (call it PAL) that is organizationally and cryptographically independent of the issuing AS. The resource-requesting agent presents an issuing-AS token; PAL validates it against an authoritative permission store and issues a resource-specific token with filtered scopes, bound to the RS (RFC 8707) and sender-constrained (DPoP, RFC 9449). PAL's public key is pinned by the RS. If the issuing AS is compromised, PAL's independent validation catches forged grants. Section 7 (SECU deployment scenario) uses adversarial-AS resistance — a compromised AS cannot forge FCRA access — as the headline compliance argument. Token Exchange achieves the same trust separation using existing federation standards, no on-chain infrastructure.

- **Why it works / fails:** The construction's genuine advantage is *fully offline, cryptographically verifiable* separation: the RS validates against an on-chain `operatorRegistryRoot` with no live service contact, not even PAL. Token Exchange still requires PAL to be online and trusted at validation time. For NCUA examiner auditability (Section 7: "verify every FCRA event has a ZK proof"), on-chain verifiability is a real differentiator. But the threat model (Section 3) must explicitly state that the adversary includes a **fully offline RS** that trusts no live service, not just a semi-trusted AS. Without that framing, Token Exchange looks like a valid substitute.

- **In-threat-model?** Yes — construction survives — but the adversarial-AS scenario is underspecified. The threat model must add a "no live policy service" constraint to make the separation crisp, otherwise RFC 8693 federation is a valid objection.

---

### Attack 4: Constraint 7 (Cumulative Bit Encoding) Is Provably Incomplete — The Circuit Has a Soundness Gap for the SECU Tier System

- **Attack:** Section 2, Constraint 7 lists exactly three R1CS constraints for the cumulative bit encoding over a 64-bit bitmask:
  ```
  permBits[4] * (1 - permBits[3]) === 0   (if bit4, then bit3)
  permBits[4] * (1 - permBits[2]) === 0   (if bit4, then bit2)
  permBits[3] * (1 - permBits[2]) === 0   (if bit3, then bit2)
  ```
  For a proper 5-bit cumulative tier encoding (bits 0–4 as described in Section 7: "branch tiers (bits 0-4 cumulative)"), a complete encoding requires constraints for **all adjacent pairs**: `(1,0), (2,1), (3,2), (4,3)`. The listed constraints cover pairs `(4,3), (4,2), (3,2)` but omit `(2,1)` and `(1,0)`. A malicious agent holding `permBits = [0, 1, 0, 0, 0]` (bit 1 set, bit 0 unset) satisfies all three listed constraints (`permBits[4]=0` makes the first two vacuously true; `permBits[3]=0` makes the third vacuously true), yet represents an invalid tier assignment. For bits 32–63 (the regulatory and audit fields in Section 7) no cumulative constraints are listed at all. A well-configured AS-side policy validator — a simple bitmask check in the introspection response handler — has no such gap.

- **Why it works / fails:** This is a soundness attack on the circuit independent of the ZK vs. RFC 7662 comparison. If the cumulative encoding is unsound, Constraint 6 (the bitmask predicate) can be satisfied by a credential with an invalid tier assignment that no operator should have issued. The SSU game reduction (Section 4) extracts a witness and argues constraint 3 forces a valid EdDSA — but a malicious *operator* (not the AS) could deliberately issue a credential with `permBits[1]=1, permBits[0]=0` that passes the incomplete cumulative check. The adversarial-AS defense does not cover a malicious operator. The construction's Section 3 threat model only names the AS and the RS as adversaries; operator compromise is not modeled. In the SECU scenario, if SECU is both the AS and the operator, neither adversary exists — but the circuit bug remains.

- **In-threat-model?** **No** — the construction must address this. Either (a) provide the complete set of `n-1` adjacent-pair constraints for each bit range claimed to be cumulative, and (b) add operator compromise to the threat model with a corresponding game, or (c) remove the cumulative encoding claim and treat the bitmask as flat, adjusting the SECU scenario accordingly. The RFC 7662 baseline does not have an analogous implementation gap.


## Persona: spiffe_engineer

---

### Attack 1: The ZK Attestor Plugin — Wrong Layer, Right Property

- **Attack:** SPIRE's node attestation model is a plugin interface (`NodeAttestor`). I can implement a `ZKBitmaskAttestor` plugin that, at SVID issuance time, verifies a ZK proof from the workload that its private permission bitmask satisfies a minimum policy threshold. The resulting X.509 SVID URI SAN (`spiffe://creditunion/agent/branch-2/fcra`) encodes the *attested policy tier* — not the full bitmask — into a stable identity. The RS then does mTLS, checks the SAN, verifies the cert chain back to the SPIRE CA. No AS roundtrip at request time. No bitmask revealed. The ZK proof happened at enrollment, not presentation. Your construction's §2 ("Presentation Protocol: RS sends requiredScopeMask at runtime") is the only thing this doesn't cover — but SPIFFE's "registration entries" with selector matching already handle RS-side policy: the SPIRE server issues *different SVIDs per-registration-entry*, so an FCRA-accessing workload gets an FCRA-scoped SVID. You're not adding ZK to the system; you're moving ZK to a layer SPIFFE already owns.
- **Why it works / why it fails:** It works because SPIFFE's plugin architecture genuinely can absorb a ZK attestor. It *partially* fails because SVIDs are policy-at-issuance: the `requiredScopeMask` in §2 is an RS-runtime parameter unknown when the SVID was issued. The SPIFFE model cannot evaluate a predicate over a hidden bitmask using a mask the RS specifies *after* issuance without re-issuance. But the construction never proves this gap is load-bearing — §8 claims "runtime-adaptive predicates" as a differentiator but §7's SECU scenario only ever uses three fixed masks. If the actual deployment has O(1000) RS-specified masks, the claim holds. If it's a few dozen stable policy tiers, SPIFFE registration entries cover it today.
- **In-threat-model?** Partially. The construction *survives* only if it demonstrates a concrete scenario where `requiredScopeMask` cannot be enumerated at credential issuance time. §7 does not establish this — the listed masks look like a fixed compliance schema. **Must address with a tighter necessity argument.**

---

### Attack 2: Adaptive Scope Probing via `scopeCommitment` Linkability

- **Attack:** Section 2 outputs `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a *public output*. Since `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)`, and `permissionBitmask` and all other inputs are fixed for a given credential, `scopeCommitment` is a *deterministic, session-invariant commitment to the full bitmask*. I operate as a curious RS (A_RS, §3). I issue 64 fresh `sessionNonce` values — each nonce is fresh so §9 nullifiers don't overlap — and request proofs for `requiredScopeMask` equal to each single-bit mask `2^0, 2^1, ..., 2^63`. For each proof the agent generates: success means that bit is set in `permissionBitmask`; failure or refusal exposes the bit via side channel. After 64 probes I have reconstructed the full `permissionBitmask`. The SSP game in §3 is defined as a *single-query* indistinguishability game; it says nothing about adaptive multi-query adversaries. SPIFFE's equivalent — a workload requesting an SVID with a specific selector — fails closed: SPIRE either issues the SVID or it doesn't, and the workload gets no oracle. Your circuit provides an oracle.
- **Why it works / why it fails:** It works because the construction confuses *ZK proof privacy* (no information leaks from a single proof transcript) with *oracle privacy* (no information leaks across adaptive proof queries). ZK proves the first; the circuit provides the second as a service to the RS. An agent that declines to prove single-bit masks closes the oracle, but this is a policy decision outside the circuit — not a cryptographic guarantee. The SSP reduction in §4 only argues about the ZK simulator; it does not bound information leakage across sessions.
- **In-threat-model?** No — the construction *must address* this. Either: (a) redefine SSP as an adaptive multi-query game and prove it, which likely requires binding `requiredScopeMask` into the nullifier so each `(credential, mask)` pair is single-use; or (b) explicitly scope the threat model to non-adaptive RSes and justify why that's acceptable for SECU's compliance scenario.

---

### Attack 3: WIMSE Token Exchange Subsumes the AS-Blind Property

- **Attack:** I co-author WIMSE (draft-ietf-wimse-arch). The architecture explicitly defines *workload-to-workload token exchange* where a service (RS-equivalent) accepts a workload token from a trust domain it federates with, without contacting the issuing AS. The token validation uses a *cached JWKS endpoint* — semantically identical to your on-chain `operatorRegistryRoot`. Your §2 "Operator Registry Merkle Tree" is a blockchain-flavored JWKS with a Poseidon hash. Your §2.3 "Presentation Protocol: no AS contact" is exactly the WIMSE offline-validation flow. WIMSE also has selective disclosure in scope via SD-JWT (draft-ietf-oauth-selective-disclosure-jwt). Your §8 gap claim "No AS-blind presentation: BBS+ requires AS to encode all permissions" conflates BBS+ with WIMSE — the WIMSE architecture is not BBS+. Why are you not contributing the bitmask predicate extension to the WIMSE working group instead of building a new protocol?
- **Why it works / why it fails:** It works as a *process* argument — the WG is the right venue. It partially fails on the *technical* merits: SD-JWT selective disclosure is still claim-granular and cannot evaluate `bitmask & mask == mask` over a hidden integer without an external NIZK, which is exactly your circuit. The construction's genuine gap over WIMSE is Constraint 6 (§2): the bitmask intersection predicate has no representation in SD-JWT claim selection. But the construction never names SD-JWT as the WIMSE baseline — it names BBS+. If the comparison class includes WIMSE+SD-JWT, the "formal separation" in §8 needs to argue against SD-JWT specifically, not BBS+.
- **In-threat-model?** No. **Must address:** (a) update §8 to address WIMSE+SD-JWT explicitly; (b) articulate why contributing the predicate extension to WIMSE is worse than a standalone protocol — the answer probably involves the on-chain operator registry as an AS-independent trust root, which WIMSE explicitly does not provide (WIMSE federation still trusts the remote JWKS endpoint operator).

---

### Attack 4: Cumulative Encoding Underconstraint — Soundness Bug

- **Attack:** Section 2, Constraint 7 ("Cumulative bit encoding") lists exactly three constraints: `permBits[4] * (1-permBits[3]) === 0`, `permBits[4] * (1-permBits[2]) === 0`, `permBits[3] * (1-permBits[2]) === 0`. Section 7 specifies "bits 0-4 cumulative" (branch tiers). For a correct cumulative encoding, `bit[k] = 1` must imply `bit[k-1] = 1` for all `k in [1,4]`. That requires 4 constraints: `(4,3), (3,2), (2,1), (1,0)`. Constraint 7 omits the `(2,1)` and `(1,0)` pairs. An adversary constructs a credential with `permissionBitmask` where `bit[2] = 1`, `bit[1] = 0`, `bit[0] = 0` — the three listed constraints are satisfied, the circuit accepts, but the semantic invariant (tier-2 implies tier-1 implies tier-0) is violated. The operator signs this credential, enrolling an agent that claims tier-2 branch access while lacking tiers 0 and 1. RS that checks `requiredScopeMask = tier2` gets a valid proof from a credential that should never have been issued under SECU's policy. This is a **soundness gap in the circuit**, independent of ZK vs. SPIFFE.
- **Why it works / why it fails:** It works because the constraint list is literally incomplete — this is verifiable by inspection of §2 Constraint 7 against §7's policy spec. It doesn't fail; it's a bug.
- **In-threat-model?** No. **Must fix:** add constraints `permBits[2] * (1-permBits[1]) === 0` and `permBits[1] * (1-permBits[0]) === 0`. Also: the current constraints do not cover bits 5-63 — if any other bit groups carry cumulative semantics (the dollar threshold tiers in bits 16-31 are likely cumulative), the same underconstraint applies. The construction should either enumerate all cumulative ranges explicitly or use a general loop gadget `for k in cumulative_ranges: permBits[k] * (1-permBits[k-1]) === 0`.
