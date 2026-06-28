# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: BSA/AML Compliance Contradiction — The Use Case Is Illegal

- **Attack:** The two stated scenarios (cross-credit-union member agent, healthcare referral network) are precisely the flows where federal law **requires** attribution and correlation. Credit unions operating under BSA/AML/FinCEN guidance must maintain member activity graphs to satisfy SAR filing obligations, OFAC screening, and beneficial ownership rules. A CU that deploys C2 as specified—where even the AS cannot reconstruct the member's merchant graph—is in violation of 12 CFR Part 748 and FinCEN's 2023 AML program rules. The construction's strongest scenario is its own regulatory veto.
- **Why it works:** Section 1 of the construction preserves the threat model verbatim, including "CU-as-AS must not see member merchant graph." A CU compliance officer reading that sentence will stop the procurement conversation. The Poseidon2-tree refinement in Section 2 doesn't touch this; it tightens the cryptographic bound but doesn't introduce a selective-disclosure mode that satisfies regulatory lookback.
- **In-threat-model?** No. The construction must carve out a compliant disclosure path (e.g., auditor-key escrow or selective reveal) or re-scope the credit union scenario to exclude transaction graph unlinkability.

---

### Attack 2: The Adversarial AS Is Not a Real Enterprise Buyer's Threat

- **Attack:** The entire IND-UNL-AS game posits the Authorization Server as adversary. In every Auth0, WorkOS, and Stytch deployment I know of, **the enterprise IS the AS**—they run it, they own the logs, they wrote the SOC 2 policies around it. The threat model is internally incoherent for the enterprise buyer: you're selling them a system that protects their agents from *their own* AS. The correct framing for enterprise is "protect your users from each other's RS" (i.e., the RS is the adversary), which is a different and weaker construction.
- **Why it works:** Section 4's hybrid reduction tightens to `2*ε_PRF` against an adversarial AS, but enterprise procurement asks "who is the threat?" not "what is the bound?" No CISO at a credit union views their own identity stack as the adversary. This means the construction's primary cryptographic novelty (AS-adversarial unlinkability) solves a problem the buyer doesn't have.
- **In-threat-model?** No. The gap-to-close in C2 calls for an "empirical test showing colluding AS+RS cannot de-anonymize"—but no enterprise buyer will sign a PO to prevent their own AS from seeing their own traffic. The construction needs a separate RS-adversarial variant or a clear buyer articulation of who is actually threatening whom.

---

### Attack 3: Proving Latency Makes Cross-Scope Auth a Non-Starter for Synchronous API Flows

- **Attack:** The Section 2 Poseidon2-tree substitution is described as "zero constraint cost change," but constraint count is not the latency bottleneck. The IND-UNL-AS game requires a fresh proof per scope crossing. Even with rapidsnark on modern hardware, a Groth16 prove for the AgentPolicy + Delegation circuit stack runs 8–15 seconds. WorkOS issues a scoped JWT in under 100ms. For any synchronous MCP tool-call chain—where an agent hits three RS endpoints in sequence—Bolyra's cross-scope unlinkability imposes 24–45 seconds of latency per session. No operator building on top of Claude or GPT-4o will accept that, because their users already complain about 3-second tool-call round trips.
- **Why it works:** The gap-to-close acknowledges "timing side channels" but treats them as a side channel privacy concern, not a product-killer latency concern. The construction has no proof-caching architecture specified, and cached proofs reintroduce the linkability that the IND-UNL-AS game is designed to eliminate (a cached nullifier re-use across scopes leaks correlation). The construction is silent on this tradeoff.
- **In-threat-model?** Partially. The timing side-channel mention is in scope, but the construction must specify whether proof reuse is permitted and under what conditions—because any practical deployment will demand it, and permitting it collapses the unlinkability claim.

---

### Attack 4: Zero RS Ecosystem — The Verifier Integration Tax

- **Attack:** Cross-scope unlinkability requires every Resource Server to verify the ZK proof, not just validate a Bearer token against a JWKS endpoint. Auth0 and WorkOS work because every RS already speaks OAuth 2.0 token introspection (RFC 7662) or JWT verification—no RS-side code change required. C2's construction requires each RS to deploy either: (a) a Solidity verifier on Base Sepolia and run a blockchain RPC call per request, or (b) integrate `@bolyra/sdk` and bundle snarkjs. Neither option is zero-integration-cost. A healthcare provider's API gateway doesn't run Node.js. A Stripe-connected merchant RS doesn't want a Solidity dependency. The construction's unlinkability proof is moot if RS operators won't deploy the verifier.
- **Why it works:** Section 3 adds the well-formedness restriction (`credAux_0 = credAux_1`) which is necessary but invisible to RS operators—they still have to implement the verifier to benefit from it. The construction's gap-to-close does not include an RS integration story. In Auth0's world, adding a new auth mechanism to an RS is one line of middleware. In Bolyra's world as specified, it requires circuit artifact distribution, verifier contract deployment, and SDK versioning across every RS in the ecosystem.
- **In-threat-model?** No. The construction is cryptographically sound but economically undeployable without an RS-side integration layer that reduces to something indistinguishable from what WorkOS already ships—at which point the ZK layer is an optional add-on, not a moat.


## Persona: cryptographer

---

### Attack 1: Nullifier Precomputation via AS-Controlled `scopeId`

- **Attack:** The inner node of the Poseidon2 tree is `Poseidon2(scopeId, sbs)` (Section 2). The AS assigns all `scopeId` values for RS instances in its domain. Suppose `sbs` is deterministically derived from the agent's credential (e.g., `H(agentPrivKey, scopeId)` or fixed as part of enrollment). The AS knows the enrolled population — it issued the credentials, so it has the full Merkle leaf set. For each enrolled agent `i` and each scope `j`, it precomputes `nij = Poseidon2(scopeId_j, sbs_i)`. When it observes a nullifier in an authorization proof, it table-lookups `nij`. Cross-scope correlation is then O(1) per proof. This is a **meet-in-the-middle on the nullifier table** with complexity `O(N * S)` precomputation where N = enrolled agents, S = scope count — both small in the healthcare and credit-union scenarios described.

- **Why it works / fails:** It works if `sbs` has low entropy relative to the enrolled population or is deterministic from public credential fields. It fails only if `sbs` is independently sampled with ≥128 bits of entropy *independent of enrollment*, and the construction never states this. Section 3's well-formedness restriction `credAux_0 = credAux_1` suggests `credAux` is derivable from known fields — which implies `sbs` may itself be constrained, potentially reducing its effective entropy.

- **In-threat-model?** **No.** The claim is security against "adversarial AS that tries to correlate per-agent traffic graphs," but the construction gives no entropy lower bound on `sbs`, no argument that the nullifier table is uncomputable, and no game in which this precomputation is excluded.

---

### Attack 2: `credAux_0 = credAux_1` as a Public Linkage Anchor

- **Attack:** Section 3 introduces the well-formedness restriction `credAux_0 = credAux_1` and justifies it because "the Poseidon2-tree makes anchors derivable from pseudonyms + known credential fields." If `credAux` appears as a **public output signal** (or if it is derivable from public signals by a circuit-aware verifier), then two proofs sharing the same `credAux` value are trivially linked as originating from the same credential. An AS that receives authorization tokens from scope RS1 and RS2 computes `credAux = f(pseudonym, knownCredFields)` for each and compares. Equality → same agent.

- **Why it works / fails:** The construction's own justification for this constraint is that anchors are *derivable* from pseudonyms and credential fields — which are by definition known to the verifier. If `credAux` is not private (i.e., hidden from the circuit's public interface), the constraint creates a **stable cross-scope identifier**. The argument only holds if `credAux` is a private witness with no public leakage and no deterministic derivation path available to the AS. The construction does not state this, and the phrase "derivable from pseudonyms + known credential fields" points in the opposite direction.

- **In-threat-model?** **No.** This is precisely the cross-scope correlation the construction claims to prevent. The AS is explicitly in the adversary class, and this attack requires no cryptographic hardness assumption — only the ability to read the public circuit interface.

---

### Attack 3: PRF Security Does Not Imply IND-UNL-AS Security

- **Attack:** The two-step hybrid (Section 4) reduces to `2*ε_PRF` via POS-PRF for Poseidon2. But PRF security is a *computational pseudorandomness* property: `Poseidon2(scopeId, sbs)` is indistinguishable from a random function. This does **not** imply unlinkability. A standard IND-UNL-AS game would proceed as: (1) adversary chooses two agents A0, A1 and two RS instances; (2) challenger samples bit b and generates authorization proofs for Ab accessing RS1 and Ab accessing RS2; (3) adversary must distinguish b. PRF security bounds the advantage only if the *distinguisher's entire view* reduces to distinguishing PRF outputs from random. But the adversary also sees the proof structure — `permBitmask`, `cc`, the Merkle root witness, the Groth16 `(A, B, C)` elements, and the circuit's public inputs. Two proofs from the same agent with the same `permBitmask` and `cc` across different scopes are structurally correlated regardless of PRF security on the nullifier component.

- **Why it works / fails:** The hybrid argument must show that *every* component of the verifier's view is simulatable, not just the nullifier. The reduction to POS-PRF covers one term; it says nothing about the Groth16 proof elements, the Merkle root, or any public signal that is common across both scopes. Without a simulator that produces indistinguishable transcripts for both proofs jointly, the zero-knowledge claim is incomplete and the unlinkability reduction has a gap.

- **In-threat-model?** **No.** The missing IND-UNL-AS game is explicitly called out as a gap in the candidate's own assessment. The reduction to POS-PRF does not close it — it closes a strictly weaker subgoal.

---

### Attack 4: Groth16 Subverted Setup Breaks Unlinkability Under AS Participation

- **Attack:** Groth16 requires a per-circuit trusted setup producing `(pk, vk)`. If the AS participated in the `AgentPolicy` or `Delegation` ceremony (as a contributor or MPC participant), a subverted toxic waste `τ` allows the AS to compute the **simulation trapdoor** `δ^{-1}`. With this trapdoor, for any proof `π = (A, B, C)` in the `AgentPolicy` circuit, the AS can extract the witness — including `sbs`, `permBitmask`, and `cc`. Even without full extraction, a subverted `vk` can be constructed such that the AS can test whether two proofs share the same witness by computing a bilinear pairing check off-label. Concretely: with subverted setup, the AS checks `e(C1 - C2, g2) =? 1` for two proofs `π1, π2` under a crafted `vk` — this is the **setup-dependent linkability** attack known from the "Simulation Extractability" literature (Groth 2016, Lipmaa-Siim 2017).

- **Why it works / fails:** It works unless the setup is performed via a **publicly verifiable MPC ceremony** with at least one honest participant, and the construction explicitly excludes AS from participation. The construction cites `pot16.ptau` for the universal SRS but does not describe the circuit-specific `zkey` generation ceremony or its trust assumptions. The Semaphore v4 ceremony covers `HumanUniqueness` only; `AgentPolicy` and `Delegation` use project-specific keys from `pot16.ptau`, and the construction's threat model must explicitly address whether the AS is a ceremony participant.

- **In-threat-model?** **No** — the construction does not state a trust assumption on ceremony participants, does not bound the adversary's role in setup, and does not cite simulation-extractability results that would survive a subverted-but-detected setup. Without this, the zero-knowledge and unlinkability claims are vacuous under setup compromise, which is the most realistic attack vector for a well-resourced AS (e.g., a large credit union or healthcare network).


## Persona: cu_ciso

---

### Attack 1: Unlinkability Defeats My BSA/AML Obligation

- **Attack:** The construction's core guarantee — same agent, different RS instances, produces "cryptographically unlinkable authorizations" — is a direct conflict with the Bank Secrecy Act and FinCEN guidance on suspicious activity monitoring. BSA requires me to detect patterns *across* systems: an agent touching my loan origination system, my wire transfer system, and my ACH processor in the same session is exactly the signal I need to file a SAR. The IND-UNL-AS game the construction defines is adversarially modeling the AS — which is me, the credit union — as the party that must be blinded. I am legally required to see the cross-system graph. The construction defeats my most important monitoring control and frames that defeat as a feature.

- **Why it works / fails:** The construction does not address layered unlinkability (unlinkable to external RS colluders, linkable to the issuing CU). The adversarial AS model is binary — either the AS sees correlations or it doesn't. There is no mention of a privileged "audit oracle" or a CU-controlled view that preserves regulatory observability while hiding it from colluding RS operators.

- **In-threat-model?** No — construction must address. The CU-as-adversary model needs to be split into (a) CU-as-privileged-auditor (MUST see linkage for BSA) and (b) external-RS-as-adversary (must not see cross-RS graph). These are incompatible under the current single-AS model.

---

### Attack 2: Incident Response — Compromised Agent with No Forensic Blast Radius

- **Attack:** Under NCUA Part 748 Appendix B (Response Program), when a credential is compromised I must determine the scope of exposure: which systems did this agent touch, what data was accessed, when. The construction's Section 3 well-formedness restriction (`credAux_0 = credAux_1`) anchors pseudonyms to credential fields, but the unlinkability guarantee means my SOC cannot reconstruct the cross-scope footprint of a specific compromised agent after the fact. I can revoke the credential going forward, but I cannot answer the NCUA examiner's question: "What did this agent access before you detected the compromise?" I cannot issue a breach notification with an accurate list of affected systems.

- **Why it works / fails:** The construction mentions nullifier separation per scope as the mechanism for unlinkability. Nullifiers are one-way by design. There is no escrow, no audit-path key, no threshold recovery mechanism described. A compromised agent becomes a forensic black hole.

- **In-threat-model?** No — construction must address. Need a recoverable audit path under a CU-held master key that is computationally hidden from RS operators but recoverable by the issuing AS for incident response. This is a well-known tension in anonymous credential systems and is not addressed here.

---

### Attack 3: Timing Side Channel Is Explicitly Unresolved — My Logs Close It Anyway

- **Attack:** The gap-to-close section explicitly states "treatment of side channels (timing, nonce freshness)" as outstanding. This is not a theoretical concern. My AS logs every authorization request with a millisecond timestamp. My RS operators log every resource access. Even with cryptographically unlinkable tokens, I can run a timing-graph correlation: agent hit AS at 10:00:01.042, RS-A at 10:00:01.310, RS-B at 10:00:01.890. Under a colluding AS+RS scenario (which the construction's IND-UNL-AS game explicitly covers), this is trivially de-anonymizing at scale. The Poseidon2-tree commitment change in Section 2 and the hybrid reduction in Section 4 are purely algebraic — they say nothing about the network timing channel. The construction claims "empirical test showing colluding AS+RS cannot de-anonymize" but that test does not exist yet per the gap statement.

- **Why it works / fails:** This is a known open problem in anonymous credential deployments (see Tor's guard-node timing attacks, IETF Token Binding deprecation rationale). The construction's formal security reduction is IND-UNL-AS, which is a cryptographic game — it does not model timing. The reduction to `2*ε_PRF` tightening in Section 4 is meaningless against a side channel outside the algebraic model.

- **In-threat-model?** No — the construction must address or explicitly scope-out with a documented threat boundary. Citing Grassi et al. USENIX 2021 for Poseidon2 PRF security does not close a network timing channel. The gap is acknowledged but unresolved, which means the claim at `current_strength: 9` is overstated.

---

### Attack 4: Vendor Management — Who Certifies the Poseidon2 PRF Assumption?

- **Attack:** My FFIEC CAT and vendor management policy require that cryptographic primitives used in member-facing authentication have gone through a recognized standards process (NIST, IETF) or have an independent third-party assessment I can show an examiner. Section 4 now reduces to POS-PRF for Poseidon2, cited to a single academic paper (Grassi et al. USENIX 2021). Poseidon2 is not NIST-standardized. It is not in FIPS 140-3. My NCUA examiner will ask me: "What standard does this hash function comply with?" My answer is "a 2021 conference paper." The reduction tightening from `2*ε_PRF2 + 2*ε_PRF4` to `2*ε_PRF` is mathematically cleaner, but it doubles down on a non-standard primitive as the single point of cryptographic trust. If Poseidon2 breaks — as ZK-friendly hash functions have historically had near-misses — my entire cross-scope unlinkability guarantee collapses simultaneously across every member's agent credentials.

- **Why it works / fails:** The construction trades assumption complexity for assumption depth on a single non-standard primitive. This is a valid cryptographic engineering tradeoff, but it is not auditable under current FFIEC guidance. There is no fallback, no migration path, and no mention of how a Poseidon2 break gets operationally handled across an already-deployed credential set.

- **In-threat-model?** No — construction must address. Need either (a) a NIST-aligned fallback primitive path documented in the construction, or (b) an explicit regulatory positioning statement that this is a ZK-native primitive accepted by the same examiners who accepted Semaphore v4 ceremony reuse (which itself is not NIST-standardized — the construction is accumulating non-standard assumptions without a migration story).


## Persona: rfc7662_advocate

---

### Attack 1: PPID Partition — The RS-Level Claim Is Already Solved

**Attack:** The construction claims "cryptographically unlinkable authorizations" across RS instances. But OIDC pairwise pseudonymous identifiers (PPIDs) already provide per-RS unlinkability **at the RS level**. Under RFC 9728 (Protected Resource Metadata), an AS can configure per-RS introspection policies that return different `sub` values per audience. From any single RS's vantage point, it sees a different subject identifier per agent × RS pair. The cross-RS correlation problem is solved without ZK.

**Why it works / why it fails:** It works as an RS-level claim. It fails at the AS level: the AS that computes both PPIDs holds the full deanonymization map. If the threat model is a **colluding AS**, PPIDs provide zero protection. The construction's core novelty is precisely this AS-side property — preventing the issuer itself from reconstructing the agent's traffic graph. However, the construction (Section 1, preserved verbatim and therefore unauditable in this review) does **not** appear to define a formal threat model distinguishing AS-side unlinkability from RS-side unlinkability. Until the construction explicitly states "adversarial AS knows `cc`, `scopeId`, and `permBitmask` but cannot invert `sbs`," the PPID baseline is a credible substitute for the weaker RS-side reading of the claim.

**In-threat-model?** Partially. Construction survives the AS-side reading only if the threat model is made explicit. As written, the claim is ambiguous and a reviewer can plausibly argue PPIDs suffice.

---

### Attack 2: Nonce Steganography — AS Controls the Nonce Domain

**Attack:** RFC 9449 DPoP nonces (Section 8, RFC 9449) are AS-issued. An adversarial AS can embed a covert channel in nonce generation — e.g., encoding an agent's internal identifier in the low-order bits of a 256-bit nonce — without violating any observable format constraint. Every `sessionNonce` that enters the Poseidon2 computation carries this tag. The proof commits to the nonce; the AS, knowing the tag, can reidentify any proof output across scopes by filtering on nonce prefix. The construction (Section 4) tightens the reduction to `2*ε_PRF` for Poseidon2 pseudorandomness, but PRF security assumes a **uniform, secret key** — not a nonce the adversary chooses. A chosen-nonce attack is outside the PRF reduction scope entirely.

**Why it works / why it fails:** This is a real gap. The candidate's own gap-to-close explicitly flags "nonce freshness" as unaddressed. The construction's security proof assumes nonces are honestly generated. In the stated threat model — "adversarial AS that tries to correlate per-agent traffic graphs" — the AS controls nonce generation. Nonce steganography is a concrete instantiation of this attack that bypasses all nullifier-separation guarantees.

**In-threat-model?** Yes — construction does **not** survive without addressing it. The fix is a verifiable nonce-generation commitment (e.g., agent-contributed randomness XORed with AS nonce, with the agent's contribution committed on-chain before the AS nonce is revealed). This is non-trivial and not present in the construction.

---

### Attack 3: `credAux_0 = credAux_1` Constraint as a Cross-Proof Fingerprint

**Attack:** Section 3 adds the well-formedness restriction `credAux_0 = credAux_1`. The stated justification is standard k-anonymity. However, this equality constraint is a **structural invariant that holds across every proof produced by the same credential**. A colluding AS+RS pair that accumulates multiple proofs from what they suspect is the same agent can test this invariant: parse the witness auxiliary signals (if exposed via proof metadata or verifier logs), check equality, and narrow the anonymity set to credentials satisfying the constraint. Unlike the Poseidon2 nullifiers (which are pseudorandom per scope), this is a deterministic, non-hiding equality check baked into every proof. RFC 7662 tokens have no analogous structural fingerprint — each token is independently opaque to the RS.

**Why it works / why it fails:** The attack strength depends on whether `credAux` fields appear in the public signal vector or remain private witness inputs. If they are private, the colluding AS+RS cannot observe them directly. But the construction justifies the restriction as "necessary because the Poseidon2-tree makes anchors derivable from pseudonyms + known credential fields" — implying the AS knows enough to compute the constraint value from public data. If so, the AS can test equality across proofs without accessing private witnesses.

**In-threat-model?** Conditionally yes. Construction survives if `credAux` values are strictly private and the AS cannot derive them from public signals + credential fields it already holds. The construction should make this explicit with a signal-visibility table; currently it does not.

---

### Attack 4: IND-UNL-AS Game Absent — RFC 7662 Proof Is Simpler and Exists

**Attack:** The construction claims a strictly stronger privacy property than PPID + per-RS policy: unlinkability even against an adversarial AS. The candidate's own gap-to-close states the IND-UNL-AS game "needs formal security definition." Until that game is defined and the construction is shown to achieve it, the claim is informal. I can construct a distinguisher argument under any reasonable formalization: the AS knows `cc` (credential commitment), `permBitmask`, and `scopeId` for each request. If `sbs` (scope blinding salt) is ever reused — even across sessions for the same scope — the Poseidon2 output is deterministic and the AS trivially links. The construction does not specify `sbs` refresh policy. RFC 7662 + PPIDs, by contrast, has a well-documented privacy analysis (see Fett, Küsters, Schmitz 2017 formal OAuth model), and the AS-side leakage is explicitly bounded. Claiming to beat a formally analyzed baseline with an informally analyzed construction is not a proof — it is an assertion.

**Why it works / why it fails:** This is a burden-of-proof attack, not a cryptographic break. But in standards contexts (where this construction would compete with RFC 7662 extensions), the absence of a formal game definition is disqualifying for the "adversarial AS" claim specifically. The `2*ε_PRF` reduction in Section 4 bounds indistinguishability of the nullifier output given a fixed `sbs` — it does not bound the AS's ability to correlate if `sbs` is predictable or reused.

**In-threat-model?** Yes — construction does **not** survive at current strength=9 → 10 without it. The IND-UNL-AS game definition is the single highest-leverage item in the gap-to-close list, and the construction defers it. A formal definition must specify: (a) what the adversarial AS is given (`cc`, nonces, `scopeId` per request), (b) what it outputs (a linkage graph), (c) the advantage bound. Without this, the "even under adversarial AS" claim is not falsifiable and therefore not credible to an OAuth WG reviewer.


## Persona: spiffe_engineer

---

### Attack 1: AS-controlled `scopeId` Equivocation Breaks Nullifier Separation

- **Attack:** In the Poseidon2-tree commitment `Poseidon2(Poseidon2(scopeId, sbs), Poseidon2(permBitmask, cc))`, the `scopeId` is the domain separator that makes nullifiers scope-specific. But in every real deployment the AS *defines* scopes — it is the party that mints `scopeId` strings. An adversarial AS can simply assign the **same `scopeId` to two colluding resource servers** (RS-A for CU-1, RS-B for CU-2 in the cross-CU scenario of Section 1). Both RSes now receive proofs whose scope-separated nullifier is identical, giving the AS a perfect per-agent linkage signal across "different RS instances." The claim in Section 1 ("cross-credit-union member agent where CU-as-AS must not see member merchant graph") is the exact scenario where the AS has this power.

- **Why it works / why it fails:** The construction never constrains who controls `scopeId` or how it is certified to the agent. If `scopeId` is taken from an AS-supplied token (which is standard OAuth behavior), the adversarial AS can trivially collapse two scopes into one. A ZK proof over a scopeId the adversary chose is not scope-separated at all.

- **In-threat-model?** **No.** The IND-UNL-AS game (listed as a gap to close) must define whether the adversary `A` controls `scopeId` assignment. If yes, Section 3's nullifier separation provides zero cross-scope unlinkability. The construction must add a scope-binding ceremony where the agent independently verifies `scopeId` against a public registry not controlled by the AS.

---

### Attack 2: `credAux_0 = credAux_1` Well-formedness Constraint as Offline Credential Oracle

- **Attack:** Section 3 adds the constraint `credAux_0 = credAux_1` explicitly because "the Poseidon2-tree makes anchors derivable from pseudonyms + known credential fields." This means an observer who knows `(permBitmask, cc)` — either by guessing low-entropy fields or by learning them from one authorized disclosure — can reconstruct the anchor for any pseudonym they observe. In the healthcare scenario (Section 1), `permBitmask` is structural (a small integer from the 8-bit permission model described in `CLAUDE.md`) and `cc` may be the agent's model hash (a public value from `createAgentCredential`). An adversarial AS+RS colluder runs an offline dictionary attack: for each observed pseudonym `P` across two scopes, test all candidate `(permBitmask, cc)` pairs against `P` using the public Poseidon2 circuit. If the candidate space is small (O(256) for permBitmask × a known model hash), the constraint makes unlinkability computationally trivial to break, not information-theoretically protected.

- **Why it works / why it fails:** The Poseidon2 PRF security argument (cited to Grassi et al.) assumes *secret* inputs. If `permBitmask` and `cc` are even partially public — which the agent credential model explicitly allows (`createAgentCredential` takes a `modelHash` as a clear-text parameter per the public API in `CLAUDE.md`) — the reduction to `ε_PRF` does not hold over the observable subspace.

- **In-threat-model?** **No.** The construction must justify entropy bounds on `credAux` fields or use an independently sampled blinding factor inside the Poseidon2-tree that is never exposed. The well-formedness constraint is correctly motivated but its security implication for low-entropy inputs is unaddressed.

---

### Attack 3: Missing PoP Binding to Transport Channel (the "mTLS with SVIDs" Objection)

- **Attack:** In SPIFFE/WIMSE production, a JWT-SVID presented over an unauthenticated channel is pinned to the TLS connection via a Proof-of-Possession (PoP) mechanism — either MTLS with an X.509 SVID, or DPoP-style ephemeral key binding in WIMSE. The Bolyra "mutual ZK handshake" commits to a `sessionNonce` (Section 1, nonce binding described in `CLAUDE.md`), but the `sessionNonce` is an application-layer value. Nothing in Sections 2–4 binds the ZK proof to the TLS session key material (e.g., the TLS exporter or the channel's ephemeral DH share). A network-level adversary that can observe the TLS connection metadata — or that sits as a TLS terminator between agent and RS — can replay captured `(humanProof, agentProof)` pairs across different transport connections while the nonce check passes, because nonce freshness only blocks application-layer replay. More critically for the unlinkability claim: a colluding AS+RS pair can correlate requests by TLS session fingerprint (JA3, TLS 1.3 session ticket, IP/port tuple timing) independent of whether the ZK proof itself is unlinkable.

- **Why it works / why it fails:** The construction reduces unlinkability to the ZK layer but the side channel list in the gap closure ("timing, nonce freshness") does not enumerate transport-layer fingerprinting. The `sessionNonce` binding prevents credential replay but does not achieve channel binding. WIMSE section 5 (draft-ietf-wimse-arch) explicitly requires a workload token to bind to the underlying transport; the construction offers no equivalent.

- **In-threat-model?** **No.** The empirical test proposed ("colluding AS+RS cannot de-anonymize") must be scoped to the ZK layer only, and the threat model must explicitly state that transport-layer correlation is out of scope. If it is out of scope, the cross-CU and healthcare scenarios in Section 1 are not satisfied in practice.

---

### Attack 4: IND-UNL-AS Game Adversary Gets `cc` from One Authorized Session

- **Attack:** The standard k-anonymity framing in Section 3 requires `credAux_0 = credAux_1` and justifies this as preventing anchor derivation. But the IND-UNL-AS game (gap to close) must specify the adversary's oracle access. If the adversary `A` is allowed even one **authorized session** with the agent — a standard left-or-right oracle query — `A` receives `(scopeId_1, pseudonym_1, permBitmask, cc)` directly, since `permBitmask` and `cc` are in the Poseidon2-tree public output path. Armed with these, `A` queries a second scope and tests whether the received pseudonym `pseudonym_2` is consistent with the same `(permBitmask, cc)`. Given the `credAux_0 = credAux_1` constraint, both pseudonyms share an anchor deterministically derivable from the known fields. This collapses IND-UNL-AS to a one-query distinguisher: `A` wins after a single authorized interaction, violating the "cryptographically unlinkable" claim in C2.

- **Why it works / why it fails:** The two-step hybrid proof in Section 4 reduces to `2*ε_PRF` for Poseidon2. But `ε_PRF` is defined over *uniformly random* inputs. After one authorized session, `cc` and `permBitmask` are no longer random to `A` — they are known. The PRF bound applies only to the `sbs` (scope blinding salt), and only if `sbs` is independently sampled per session. If `sbs` is derived deterministically from the agent key and `scopeId` (which would be natural for stateless agents), the PRF input is also predictable.

- **In-threat-model?** **No.** The IND-UNL-AS game definition (still listed as a gap) must specify: (a) whether `A` gets authorized oracle access, (b) whether `sbs` is stateful (fresh per session) or stateless (derived), and (c) whether `cc`/`permBitmask` are treated as public or secret in the security game. Until the game is written down with these parameters explicit, the strength-9 score is not verifiable against the strength-10 target.
