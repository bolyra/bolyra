# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

### Attack 1: The Adversarial-AS Scenario Is Not a Real Enterprise Buying Trigger

- **Attack:** The construction's most defensible property — "AS-blind presentation, no AS roundtrip, agent chooses what to disclose at moment of use" — only matters if you assume the AS (Auth0, WorkOS, Stytch) is semi-trusted or adversarial. But enterprises don't buy identity infrastructure from vendors they consider adversarial. If a credit union trusts their AS enough to run it, they want AS-auditable presentations for compliance, not AS-blind ones. SOC 2, audit logs, and regulator access requirements demand the opposite of what this construction provides. The `adversarial-AS model` scenario in `scenarios[1]` is a cryptography paper threat model, not a procurement conversation.

- **Why it works / why it fails:** The construction's gap analysis (`gap_to_close`) explicitly lists "adversarial-AS model where AS cannot lie about scope membership" as the differentiator. This is technically precise but commercially toxic. A credit union CISO will ask: "So your product's main advantage is that even *I* can't audit what permissions my agent presented?" That's a disqualifier, not a differentiator.

- **In-threat-model?** No — the construction must address why an AS-blind property is *desirable* (not just cryptographically novel) in a regulated enterprise context. Suggest reframing: the value is portability across *multiple* AS providers without re-issuance, not adversarial-AS resistance.

---

### Attack 2: The Rate-Limiting Fix Reintroduces the Privacy Vulnerability It Claims to Solve

- **Attack:** The blinding nonce fix is sound for single-RS use. But the construction explicitly preserves rate-limiting via "optional deterministic derivation `Poseidon2(agentSecret, rsIdentifier)`." If the operator enables rate-limiting (which any production deployment will — you can't ship an agent credential system without replay protection), `agentNullifier` reverts to a deterministic function of `(agentSecret, rsIdentifier)`. An adversary who observes two presentations to the same RS can now link them. The privacy reduction in the fix (the 4-hybrid argument) only holds when `blindingNonce` is truly fresh — it silently breaks when the operator chooses the deterministic path.

- **Why it works / why it fails:** The fix paper-clips two incompatible properties: unlinkable presentation (needs fresh nonce) and rate-limiting (needs deterministic nonce). The "optional" toggle makes both claims true in isolation and false in combination. This is the classic ZK footgun: the security proof is valid for a configuration that no production deployment will use. WorkOS doesn't have this problem — their token is bound to the issuance event, rate-limiting is server-side, and there's no footgun.

- **In-threat-model?** No — the construction must either (a) define a separate `rateLimitingTag = Poseidon2(agentSecret, rsIdentifier)` as a *third* public output, independent of `agentNullifier`, so the privacy reduction holds unconditionally, or (b) explicitly document that enabling rate-limiting degrades the privacy guarantee to linkability within a single RS session.

---

### Attack 3: Constant-Size Proof Is Not a Win When Tokens Are Zero-Size

- **Attack:** The construction claims "constant-size proof regardless of bitmask width" as a property RFC 7662 cannot match. WorkOS's rejoinder: a JWT bearer token is also constant-size regardless of permission space — it's just a signed blob. The bearer token *plus* AS-side policy enforcement is the RFC 7662 answer to `2^64` permission spaces. The construction's advantage only materializes if the RS needs to verify the predicate *without calling the AS*. But RFC 8707 (Resource Indicators) + offline JWT introspection already gives the RS a signed scope claim it can verify without an AS roundtrip. The PLONK proof is larger than a JWT, slower to verify (EVM pairing check or native verifier call vs. RS256 verify), and requires snarkjs or rapidsnark in the RS's stack. The construction section on proving system choice (`AgentPolicy`: Groth16 and PLONK) doesn't address RS-side verification overhead.

- **Why it works / why it fails:** The claim "no configuration of RFC 7662 can match" is only true if the specific threat is a *lying AS* (Attack 1) or *policy-table scaling past practical limits* (scenario 1). For any other RS, the ZK overhead is pure cost with no benefit. The `current_strength: 4` rating is accurate precisely because this attack deflates the most common use case.

- **In-threat-model?** Yes — but the construction must explicitly bound the scope of its claim. As written, "no configuration of RFC 7662 can match" reads as universal. It should read: "in the adversarial-AS or portable-multi-AS subcase, no RFC 7662 configuration can match" — and that subcase must be tied to a real buyer segment, not a cryptographic abstraction.

---

### Attack 4: The Onboarding Delta Is Fatal at the Bottom of the Funnel

- **Attack:** WorkOS MCP auth onboarding is: add an `Authorization` header, paste a client ID, done. Stytch is comparable. The Bolyra onboarding requires: (1) compile Circom circuits, (2) run trusted setup or accept the project's `pot16.ptau`, (3) generate a `credentialCommitment` via `createAgentCredential()`, (4) distribute `AgentPolicy.zkey` to the proving environment, (5) generate a fresh `blindingNonce` per presentation, (6) submit a PLONK proof to the RS's verifier contract or native verifier. The construction's CLAUDE.md documents the test split (`test:circuits:fast` vs `test:circuits:slow`): fast is witness-only, slow is ~2 min for full proof. Even with rapidsnark, the operational complexity is orders of magnitude above a bearer token. The construction doesn't address this at all — the `scenarios` section jumps straight to `regulated agent with 2^64 permission space`, skipping the `developer with a deadline` who is the actual first buyer.

- **Why it works / why it fails:** This isn't a cryptographic attack — it's a distribution attack. The construction is correct. The onboarding is not. Auth0's moat is that a developer can be live in 15 minutes. If Bolyra's answer to procurement is "ZK proofs are more private," but the answer to the developer is "compile Circom first," the enterprise sale dies at the sandbox stage before it reaches procurement.

- **In-threat-model?** No — the construction must specify a hosted proving path (Bolyra-hosted prover API that accepts `credentialCommitment + requiredScopeMask + blindingNonce`, returns a PLONK proof in <500ms) as the default onboarding path, with self-hosted as the privacy-maximizing option. Without this, the `target_strength: 10` is unreachable regardless of cryptographic soundness.


## Persona: cryptographer

---

### Attack 1: PLONK Is HVZK, Not Simulation-Extractable — UC Composition Breaks

**Attack:**
The privacy reduction (section "Privacy reduction repaired") invokes a hybrid that calls a PLONK simulator in hybrid H2→H3. Standard PLONK (Marlin/KZG variant, or even the original PLONK paper) achieves *honest-verifier zero-knowledge* under the random oracle model. It is **not** simulation-extractable (SE-NIZK) without additional machinery (e.g., augmenting the Fiat-Shamir transcript with a proof-of-knowledge tag, as in Atapoor–Baghery–Pagnin–Slamanig 2023, or using the SE-PLONK variant). The hybrid argument as written assumes the PLONK simulator produces indistinguishable transcripts even when the adversary has already seen polynomially many simulated proofs — that is SE-NIZK, not just HVZK.

**Why it matters:**
In any deployment where the agent presents to multiple RSes (or replays across sessions), the adversary accumulates transcripts. Under HVZK alone, the simulator only handles a single challenge; under rewinding it can produce multiple, but the *combined* view is not simulated. The reduction needs `Adv_PLONK_SE` (simulation-extractability advantage), not just `Adv_PLONK_zk`. Without this, the 4-hybrid bound is vacuous — H2→H3 is not tight.

**Formal gap:** The privacy game as written doesn't specify how many proofs the adversary is allowed to collect before issuing its challenge. If `q ≥ 1`, HVZK is insufficient. The construction must either (a) restrict to single-use credentials (not stated), (b) switch to a proven SE-NIZK variant of PLONK, or (c) add a separate commitment to the Fiat-Shamir transcript that enables extraction.

**In-threat-model?** No — construction must address.

---

### Attack 2: Nonce Bifurcation Destroys Either Privacy or Rate-Limiting — No Formal Characterization

**Attack:**
The fix introduces a tension it doesn't resolve. Two modes exist:

- **Mode A (random `blindingNonce`):** `agentNullifier` is fresh each presentation. The RS cannot detect double-presentation. Rate-limiting is impossible.
- **Mode B (deterministic `blindingNonce = Poseidon2(agentSecret, rsIdentifier)`):** `agentNullifier` is deterministic per (agent, RS) pair. Rate-limiting holds, but now: if the AS ever learns `agentSecret` (either at issuance or via a compromised agent device), it can compute the nullifier for every RS, reconstruct the nullifier table, and link all presentations at a given RS back to the agent. This is the classical *nullifier precomputation* attack.

The construction says rate-limiting is "optional" with no game definition for which mode provides which guarantee, no composition theorem stating the two modes are safe to use in the same deployment, and no adversary model for the Mode B linkage risk.

**Concretely:** Suppose AS is semi-trusted (the claimed adversarial-AS scenario). The agent registers at issuance; AS stores `credentialCommitment`. Later, under Mode B, AS sees the public nullifier `Poseidon3(credentialCommitment, mask, Poseidon2(agentSecret, rsId))`. If AS knows `agentSecret` (plausible in credential-issuance flows where the AS generates the keypair), it can precompute the Mode B nonce, reconstruct the nullifier, and link. Even if AS only knows `credentialCommitment`, it can enumerate all known commitments and check — the blinding breaks entirely if the commitment space is small (e.g., AS-assigned IDs).

**In-threat-model?** No — the adversarial-AS scenario specifically requires that Mode B be analyzed under a colluding AS+RS. No such analysis exists.

---

### Attack 3: Groth16 Per-Circuit Trusted Setup Is in Direct Conflict with the Adversarial-AS Claim

**Attack:**
The construction uses Groth16 for `AgentPolicy` and `Delegation` circuits with per-circuit phase-2 keys derived from `pot16.ptau`. The adversarial-AS scenario claims "cryptographic assurance independent of AS cooperation." But: **if the AS participates in (or controls) the per-circuit phase-2 ceremony, it holds toxic waste** — namely the trapdoor `τ` such that it can compute `[τ^i]_1` for any `i`. With this trapdoor, Groth16 knowledge soundness fails completely: the AS can produce a valid proof for *any* statement, including "agent has permission bit `k`" for an agent that was never granted `k`.

The construction points to `pot16.ptau` (the universal Powers of Tau, presumably the Hermez/Zcash ceremony). That covers phase 1. But phase 2 (circuit-specific) is the dangerous step. The CLAUDE.md says "Project-specific keys (Agent/Delegation) use `pot16.ptau`" — which implies a project-run phase 2. If a solo founder runs phase 2 in a dev environment (common in early deployments), the toxic waste exists and the adversarial-AS guarantee is theater.

**Formal statement of the gap:** The security proof must include a setup assumption: either (a) the phase-2 ceremony had at least 1-of-N honest participants and toxic waste was discarded, or (b) the construction switches to PLONK-only (universal SRS, no per-circuit phase 2) for the adversarial-AS scenario. The current construction ships *both* Groth16 and PLONK builds but doesn't state which provides the adversarial-AS guarantee.

**In-threat-model?** No — the adversarial-AS claim requires an explicit ceremony assumption or a PLONK-only proof path.

---

### Attack 4: The Privacy Game Is Undefined for the Predicate — Lower-Bound Leakage Is Unaddressed

**Attack:**
The claim is "agent proves it satisfies a required permission predicate **without revealing the full permission set**." The `requiredScopeMask` is a *public input* to the circuit — the RS supplies it. So the RS learns: "this agent has at least the permissions encoded in `requiredScopeMask`." For the 8-bit cumulative encoding described in CLAUDE.md, revealing that an agent has `FINANCIAL_MEDIUM` (bit 3) also reveals it has `FINANCIAL_SMALL` (bit 2) by the implication rule. More importantly, in many operational contexts, the set of possible permission levels is small (8 bits → 256 profiles). An RS that queries with multiple different `requiredScopeMask` values across interactions can run a binary-search distinguishing game:

1. RS presents mask `m_high` (high bits only). Proof succeeds → agent has high-tier permissions.
2. RS presents mask `m_low`. Proof also succeeds.
3. RS has now bounded the agent's permission set from below across two interactions.

With `k` probing interactions, the RS narrows the permission set to at most `2^(8-k)` candidates. For 8-bit permissions, **8 probing rounds fully determine the permission set** — the ZK claim collapses to statistical zero.

**Formal gap:** The privacy game needs to specify that the RS is *non-adaptive* (fixes its `requiredScopeMask` before the challenge) or must commit to a single query. No such restriction is stated. The simulation in H2→H3 uses a fixed simulated proof for a fixed mask — it doesn't model an RS that queries adaptively. The construction needs either a formal bound on RS query complexity or a proof that adaptive queries don't leak, which requires the full permission bitmask to be hidden even from the RS-chosen predicate — a strictly stronger ZK property than what is claimed.

**In-threat-model?** No — the adversary model for the RS (passive vs. adaptive probing) is unspecified, and the 8-bit permission space makes adaptive attacks practical.


I can't approve file write permissions — you'd need to allow that via your Claude Code permission settings. For the adversarial critique, here it is:

---

## Persona: cu_ciso

### Attack 1: No Audit Trail the Examiner Can Read

- **Attack:** Under GLBA Safeguards Rule §314.4(c)(3) and FFIEC CAT Domain 3 (Cybersecurity Controls), the CU must log and monitor "access to customer information." The selective scope proof is explicitly *AS-blind* — no AS roundtrip, the agent presents at the moment of use. That means there is no central authority that saw the presentation. When the NCUA examiner asks "show me every access event for agent X on March 15," the answer is: the RS received a valid ZK proof, verified it, and logged a boolean. The agent's credential commitment, the scope predicate satisfied, the blindingNonce — all of these are ephemeral to the RS. The examiner cannot reconstruct what scope was claimed.
- **Why it works / fails:** The construction (Section: privacy reduction, G8/G9 outputs) deliberately makes presentations unlinkable across sessions via fresh `blindingNonce`. Unlinkability is the feature — and it directly destroys the audit trail. The RS log says "proof verified" but cannot say "agent claimed FINANCIAL_MEDIUM at 14:32:07." RFC 7662 introspection returns structured JSON (`scope`, `sub`, `exp`, `iat`) that maps directly to a human-readable access log.
- **In-threat-model?** No — construction must address. Proposed fix: a deterministic per-(agent, RS, session) audit token derived outside the blinded path, optionally escrowed to a compliance log service. But that reintroduces a trusted party and partially defeats AS-blindness.

---

### Attack 2: FIPS 140-2 Disqualifier — Poseidon and PLONK Are Not Approved Primitives

- **Attack:** NCUA Part 748 Appendix A requires a "security program" that, in practice, examiners operationalize via NIST SP 800-53 and FIPS 140-2 (soon -3). FIPS 140-2 mandates use of NIST-approved cryptographic algorithms. Poseidon is a ZK-optimized hash function with no NIST standardization. PLONK is a proof system with no FIPS-validated implementation. The CU's Vendor Management Policy will ask: "What cryptographic modules does this vendor use? Are they FIPS 140-2 validated?" The answer for every component of this construction is no.
- **Why it works / fails:** The construction's entire security argument rests on `Adv_PLONK_zk + 4 * Adv_Poseidon_prf`. Neither primitive has a NIST-standardized instantiation, no FIPS-validated module ships it, and no examiner questionnaire has a checkbox for "ZK-friendly hash." The examiner will flag this as a non-standard cryptographic implementation requiring compensating controls or outright remediation.
- **In-threat-model?** No — construction must address. This is an adoption blocker independent of cryptographic correctness. The construction needs either (a) a mapping to a FIPS-validated equivalent path, or (b) explicit language positioning this as an innovation-exception requiring board-level approval and compensating SOC 2 Type II coverage from Bolyra.

---

### Attack 3: Key Custody — Where Does `agentSecret` Live?

- **Attack:** The construction's G1–G4 gates commit to `agentSecret` (the agent's private signing key). Where does this field element live at runtime? If it's in a container's environment variable, it's in the K8s secret store. If it's on the AI agent's inference host, it's accessible to anyone with shell access. NCUA Part 748 Appendix B §II.C requires "dual control and split knowledge" for cryptographic keys protecting member data. There is no HSM story in this construction. The CU's examiner will ask: "Provide your key management procedure for agent credentials. Who has access? How is rotation triggered? What is the RTO after key compromise?"
- **Why it works / fails:** The construction proves cryptographic correctness given `agentSecret` as a private input, but says nothing about the threat model for that secret outside the circuit. The privacy reduction assumes the adversary cannot read `agentSecret` — but in every realistic deployment, the agent runtime is cloud infrastructure with imperfect access control. Key compromise means all issued credentials are retroactively forgeable with no revocation path in the proof (revocation is not addressed in the construction).
- **In-threat-model?** No — construction must address. Need an explicit key custody spec: HSM requirement, rotation policy, and how `credentialCommitment` is invalidated on compromise.

---

### Attack 4: Tier 1 Ops at 2am — Proof Failure Is a Black Box

- **Attack:** Member's AI agent fails to access the resource server. The error: `PROOF_VERIFICATION_FAILED`. The Tier 1 ops team opens a ticket. Is the issue: expired credential (`currentTimestamp` outside validity window, G5)? Wrong scope predicate (agent doesn't hold `FINANCIAL_MEDIUM`, G3)? Corrupt `blindingNonce`? SDK version mismatch between prover and verifier? Stale `humanMerkleRoot` (G6)? Under RFC 7662, introspection returns `active: false` and the RS can log `scope`, `exp`, `sub` — a Tier 1 engineer can read that. ZK proof verification returns a boolean. Debugging requires a cryptographer on-call.
- **Why it works / fails:** The construction optimizes for the RS receiving no unnecessary information. That's correct for privacy. But it transfers all diagnostic burden to the agent-side prover, which is opaque to the CU's support staff. The CU's SLA for member-facing services (typically 99.9%+, per FFIEC Business Continuity guidance) requires root-cause diagnosis within minutes. A proof failure with no structured error signal fails that SLA operationally even if the cryptography is sound.
- **In-threat-model?** No — construction must address. Needs a structured, examiner-legible error taxonomy (not proof internals, but categorized failure codes) and an operator debug mode that the CU can invoke under access-controlled conditions without breaking the privacy model for normal flows.


Here is the adversarial critique. Please approve the write permission if you want it saved to `differentiation-autoresearch/construction.md`.

---

## Persona: rfc7662_advocate

> OAuth Working Group veteran. Ten years shipping production introspection.
> Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.

---

### Attack 1: Filtered JWT Introspection Removes the AS from the Hot Path

- **Attack:** `draft-ietf-oauth-jwt-introspection-response` lets the AS issue a *signed* introspection response the RS verifies offline — no live AS roundtrip. Pair with per-RS scope filtering policy and you get: no hot-path AS, scope-minimized claims, cryptographic binding via AS signature. The construction cites "AS-blind presentation" as a differentiator, but JWT introspection response delivers offline, signature-verified, scope-minimized claims. Where is the residual gap?
- **Why it survives:** The JWT introspection response is *AS-authored*, not agent-authored at presentation time. The RS still learns the filtered scope *set* — it just verifies offline. The construction lets the agent prove "I satisfy READ" without the RS learning the agent also holds WRITE. A filtered JWT introspection response leaks the positive scope list; the construction leaks only a single bit (`satisfies ∈ {0,1}`).
- **In-threat-model?** Yes — construction survives. But **predicate privacy** (RS learns a bit, not the witness) must be named explicitly as the load-bearing property, not offline verification.

---

### Attack 2: PPID + RFC 8707 Audience Binding Covers Cross-RS Linkability

- **Attack:** OIDC PPIDs give the agent a distinct `sub` per RS. RFC 8707 Resource Indicators bind the token to a specific audience. Combined, no RS can correlate the agent's identity across RSes. The construction's `agentNullifier` prevents cross-presentation linkability — but PPIDs already break cross-RS correlation. What residual property remains?
- **Why it survives:** PPIDs give pairwise identifiers *per RS*, but the **same RS** sees the same `pairwise-A` on every visit, enabling within-RS behavioral profiling. The construction's `blindingNonce` fix (G9/G8 updated to `Poseidon3/4`) produces a fresh `agentNullifier` per presentation, making same-RS sessions mutually unlinkable. No RFC 7662 configuration achieves this: the AS must issue a stable pairwise identifier for the RS to enforce rate-limiting.
- **In-threat-model?** Yes — construction survives. The write-up should name **intra-RS per-presentation unlinkability** explicitly as the property PPIDs cannot provide.

---

### Attack 3: Adversarial-AS Model Is Circular — ZK Cannot Bootstrap Trust Not Present at Issuance

- **Attack:** Scenario 2 claims "RS needs cryptographic assurance independent of AS cooperation." But `credentialCommitment` is created by whoever issued the credential. The ZK soundness argument (G1–G7, unchanged by the blindingNonce fix) guarantees the prover knows a valid opening — it cannot guarantee the commitment was *honestly constructed*. An adversarial AS that encodes wrong permissions at issuance produces a commitment the agent correctly proves against, and no RS can detect the lie. Soundness proves the prover knows a witness; it says nothing about whether the AS set the witness correctly.
- **Why this is a gap:** The construction is AS-blind at *presentation time* only. It remains fully AS-dependent at *issuance time*. "Adversarial-AS" must be scoped: the construction defends against an AS that is honest at issuance but attempts to retroactively deny or inflate scope at verification time. It does **not** defend against an AS that maliciously encodes wrong permissions into the commitment. The current write-up conflates these two threat models, and an RFC 7662 advocate can rightly ask: "If the AS lies at issuance, your ZK proof proves a lie — how is that better than a lying AS in an introspection response?"
- **In-threat-model?** **NO** — must be addressed. Scope "adversarial-AS" to verification-time-only. Without this clarification the claimed property is overstated.

---

### Attack 4: RFC 8693 Token Exchange Is Runtime Scope Selection

- **Attack:** RFC 8693 allows the agent to obtain a *fresh, narrowed token* from the AS at runtime — for a specific RS with exactly the scopes needed. Agent sends broad credential → AS issues DPoP-bound (RFC 9449) narrow JWT → RS verifies offline. This is "agent chooses what to disclose at moment of use" without any ZK. The construction's scenario 2 appears directly addressed.
- **Why it survives:** RFC 8693 requires an **AS roundtrip per presentation**. The AS therefore learns: (a) which RS the agent is targeting, (b) which scope subset was requested, (c) the timing of every resource access. The construction lets the agent present to an RS with *zero AS involvement* — the AS never learns which RSes the agent visits or when. In a regulated context where the AS operator and RS operator are adversarial to each other, AS-blind presentation is not optional.
- **In-threat-model?** Yes — construction survives. But **AS-blind, zero-roundtrip, zero-metadata-leakage** should lead the claim, not be buried in the gap analysis. This is the sentence that rules out RFC 8693 as an equivalent.

---

### Summary

| Property | RFC 7662 + Extensions | Construction |
|---|---|---|
| Offline RS verification | Yes (jwt-introspection-response) | Yes (PLONK verify) |
| Predicate privacy (RS sees bit, not scope list) | No | Yes |
| Cross-RS unlinkability | Yes (PPID + RFC 8707) | Yes |
| Intra-RS per-presentation unlinkability | No (stable PPID) | Yes (blindingNonce) |
| Zero AS roundtrip at presentation | No (RFC 8693 requires exchange) | Yes |
| AS metadata blind (AS doesn't learn RS access pattern) | No | Yes |
| Honest issuance-time AS required | Yes | Yes — **same constraint** |

**Only Attack 3 requires action.** Scope "adversarial-AS" to verification-time-only and all four attacks are addressed or survived.


## Persona: spiffe_engineer

### Attack 1: SPIRE ZK-Attestor Plugin Makes This a Feature, Not a Protocol

- **Attack:** SPIRE's attestor interface is a plugin boundary (`NodeAttestor`, `WorkloadAttestor`). Nothing in the SPIFFE spec prevents writing a ZK-attestor plugin that generates a PLONK proof of scope-predicate satisfaction and embeds it as a custom claim in a JWT-SVID. The SPIRE server issues the SVID after attestation; the embedded proof travels with the token to the RS. The RS verifies the PLONK proof offline without an AS roundtrip. This gives you "AS-blind presentation at the moment of use" without a new wire protocol. The construction's claim (C1) is that RFC 7662 *plus* introspection *plus* DPoP cannot match the property — but a SPIFFE JWT-SVID with a bundled PLONK proof is none of those things. The construction never addresses SPIFFE as a carrier.

- **Why it works / why it fails:** The attack is partially right about the carrier question. It fails on the adversarial-AS scenario: the SPIRE server necessarily *sees* the full workload attributes during attestation to decide what to attest. It cannot be blinded to scope membership at issuance time. The construction's `credentialCommitment` is a hash of private inputs the operator holds; the SPIRE server has no equivalent. This is a real gap — but the construction never articulates why the SPIFFE attestation trust model is insufficient. The *paper* defense is implicit; it needs to be made explicit.

- **In-threat-model?** No — the construction must add a section explicitly ruling out "ZK proof bundled inside a SPIFFE SVID" and explaining why the SPIRE server's privileged view of workload identity is incompatible with the adversarial-AS scenario. Without this, a reviewer will ask "why not just a SPIRE plugin?" and have no answer.

---

### Attack 2: WIMSE Token Binding Already Covers AS-Blind Downstream Scope

- **Attack:** WIMSE `draft-ietf-wimse-arch` §4.3 (workload-to-workload token presentation) defines a proof-of-possession binding where a calling workload presents a downstream-scoped token with a DPoP-style proof. The AS issues a narrow-scope token for a specific RS at exchange time; the workload presents it with a PoP proof that binds to the request context. From the RS's perspective, it sees only the scopes the AS chose to include in the downstream token — scope narrowing without revealing the originating workload's full permission set. The construction's `scopePredicateHash` is a commitment to `(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)` — but WIMSE's downstream token achieves the same: RS sees only the required scope, not the full bitmask.

- **Why it works / why it fails:** WIMSE token exchange requires the AS to be online and cooperative at exchange time. The AS learns which RS is being targeted and which scope subset is requested — it mediates every presentation. The construction's ZK proof is generated entirely by the agent from private inputs; the AS is not involved at presentation time and cannot learn (a) which RS the agent is talking to, (b) when the presentation occurs, or (c) which predicate is being evaluated. The `blindingNonce` fix specifically repairs the case where an adversarial AS could correlate presentations. WIMSE has no equivalent protection against a semi-trusted AS.

- **In-threat-model?** Yes — but only if the construction *states* the adversarial-AS threat model explicitly and ties the `blindingNonce` to it. Currently the fix memo describes the privacy hybrid argument without connecting it to the WIMSE comparison. A reader familiar with WIMSE will not see the gap without that bridge.

---

### Attack 3: Nullifier Unlinkability Is Redundant Against Short-Lived SVIDs

- **Attack:** The construction repairs the privacy flaw by adding `blindingNonce` to prevent adversary distinguishing `b=0` from `b=1`. The SPIFFE engineer's objection: SVID rotation in SPIRE defaults to 1-hour TTL. The `currentTimestamp` already in `scopePredicateHash` (G8) limits proof reuse to a time window. If the RS enforces presentation freshness (e.g., `currentTimestamp` within ±5 minutes of wall clock), the adversary's window for the distinguishing game is bounded anyway. The `blindingNonce` adds ~500 constraints (~2.8%) to prevent an attack that short-lived credentials already frustrate. The construction should justify why the offline, long-lived credential scenario (no SPIRE server availability) warrants the constraint overhead rather than simply recommending short TTLs.

- **Why it works / why it fails:** The attack fails for the core offline scenario. The construction's `credentialCommitment` is intended to be long-lived (operator signs it once; agent uses it across sessions). Short TTLs require the issuing AS to be reachable at each rotation — exactly what the adversarial-AS model rules out. The `blindingNonce` is load-bearing for long-lived credentials used offline. However, the construction's current write-up does not distinguish short-lived online credentials (where TTL suffices) from long-lived offline credentials (where blinding is necessary). This conflation weakens the cost justification.

- **In-threat-model?** Yes — construction survives, but it must segment the argument: "for short-lived online credentials TTL is sufficient; for long-lived offline credentials `blindingNonce` is the necessary control."

---

### Attack 4: The 2^64 Claim Is Not Supported by the 8-Bit Construction

- **Attack:** The `scenarios` field of C1 includes "regulated agent with 2^64 permission space where AS-side policy tables do not scale." The `gap_to_close` lists "constant-size proof regardless of bitmask width" as a differentiating property. But the actual `AgentPolicy` circuit uses an 8-bit cumulative encoding (bits 0–7, `CLAUDE.md` §Permissions Model). The constraint count for range checks, implication enforcement, and predicate evaluation over the permission bitmask scales with bitmask width. At 64 bits, the circuit changes materially. The construction has *not* demonstrated a constant-size construction; it has demonstrated an 8-bit one and asserted the 64-bit claim without a proof sketch. SPIFFE with OPA/Rego handles large permission spaces via policy evaluation at request time — the policy engine doesn't embed the permission space in a fixed-size artifact either.

- **Why it works / why it fails:** The 8-bit construction is sound for its stated scope. The failure is in the *claim* made in C1, not the construction. If the differentiating property is "constant-size proof regardless of bitmask width," the construction needs either (a) a recursive SNARK that outsources the bitmask check (e.g., Nova folding), or (b) a Merkle-tree membership proof over a permission set of arbitrary size, or (c) retract the 2^64 scenario as out of scope for Phase 1. Currently, the adversary can point to the 8-bit limit and call the 2^64 claim aspirational marketing, not a demonstrated technical property.

- **In-threat-model?** No — the construction must either deliver the constant-size argument for arbitrary bitmask width (with a circuit sketch), bound the claim to 8 bits explicitly, or remove the 2^64 scenario from C1's scenario list. Leaving it unaddressed invites a reviewer to dismiss the entire differentiation claim as overclaiming.
