# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The Game 3b Self-Collusion Trap

- **Attack:** Section 4 honestly admits Proposition 4.4: under joint AS+RS collusion, `Adv = 1/2` — the adversary wins. The construction offers "anchor visibility gating — anchors sealed until delegation is exercised" as a mitigation. But in the primary use case stated in Section 7 ("cross-credit-union member agent where CU-as-AS must not see member merchant graph"), **the credit union is simultaneously the AS and operates the RS**. There is no colluding *third party* — the CU is colluding with itself by construction. The threat model requires the CU not to learn the member's merchant graph, but the CU controls the enrollment secrets (`cc`, `permBitmask`) that make brute-force anchor matching trivial. The formal game proves the attack works; the mitigation doesn't apply to the primary scenario.
- **Why it works / fails:** It works because the scenario description and the Game 3b admission are in direct tension. A credit union AS *is* the colluding party the game is modeling. The mitigation is architecturally void unless the AS role is delegated to a neutral third party — which the construction does not specify and which no credit union procurement team will accept.
- **In-threat-model?** No — the construction must address this. Either the CU scenario is scoped out of the unlinkability claim, or a trust-split architecture (separate AS operator from RS operator) must be specified and operationalized.

---

### Attack 2: The Latency Cliff Nobody Talks About in §3

- **Attack:** The formal games in §3 and §4 prove cryptographic properties under a model where proof generation is atomic. Real deployments are not. Bolyra's Groth16 proving takes ~15 seconds on reference hardware (`bench_rapidsnark.js` in `circuits/scripts/`). Auth0's MCP auth, WorkOS, and Stytch issue tokens in under 100ms via standard JWKS or token introspection. An operator integrating an AI agent into a credit union transaction workflow — where session latency directly affects conversion — cannot absorb a 15-second auth pause per scope crossing. The construction's formal unlinkability guarantee is irrelevant if the auth path is 150× slower than the incumbent.
- **Why it works / fails:** The construction's security argument is sound, but it doesn't address the operationalized latency budget. Game 1–3 assume proofs exist; they don't model what happens when proof generation blocks the request thread. WorkOS doesn't need to prove anything cryptographically — it just checks a JWT. The buyer's question is "how fast is auth?", not "is unlinkability formally defined?"
- **In-threat-model?** No — the construction is a formal cryptographic document that treats proof generation as instantaneous. It must add a latency section that either (a) specifies a proof pre-computation / caching architecture, or (b) bounds the deployment scenarios to ones where 15s latency is acceptable (batch jobs, not interactive sessions).

---

### Attack 3: "Anchor Visibility Gating" Is Not an Engineering Spec

- **Attack:** Proposition 4.4's mitigation says "anchor visibility gating — anchors sealed until delegation is exercised." This is one sentence with no specification of who manages the seal, what cryptographic mechanism enforces it, where the seal state lives (on-chain? off-chain?), and what happens if a delegating party pre-exercises delegation to force anchor revelation before it's needed. In contrast, WorkOS's MCP auth specifies exactly how dynamic client registration (RFC 7591) works, how client attestation (`draft-ietf-oauth-attestation-based-client-auth`) binds the credential to the client, and what the revocation endpoint looks like. "Gating" is a direction, not a construction. A procurement engineer will ask: "Show me the API call that seals an anchor." There isn't one in this document.
- **Why it works / fails:** The construction proves that *if* anchor visibility gating is implemented correctly, Game 3b can be mitigated. But it defers the entire implementation to future work, which means the stated mitigation doesn't exist yet. Any buyer evaluating the construction today is being asked to trust a proof-of-concept mitigation for the one game where the adversary wins outright.
- **In-threat-model?** No — the construction must specify the anchor gating mechanism concretely: what seals it, what the API surface looks like, and what the adversary model is for the gating layer itself.

---

### Attack 4: The Corollary 4.6 Table Obscures the Deployment Reality

- **Attack:** Corollary 4.6 presents a summary table: "Bolyra beats baseline in Games 1 and 3a, matches in Game 2, ties in Game 3b." This framing implies the only failure mode is a cryptographic tie. But the healthcare scenario in Section 7 ("healthcare agent delegation across providers without issuer learning referral network") is precisely Game 3b territory: the issuer (hospital AS) is exactly the party that must not learn the referral network, and it controls the delegation anchor inputs. The "tie" in 4.6 is actually a **win for the adversary in the stated scenario** — `Adv = 1/2` means the colluding AS+RS can de-anonymize with 50% probability per query, and with enough queries, full de-anonymization follows. A healthcare operator under HIPAA cannot accept a construction where the issuer can learn the referral graph. Auth0 and WorkOS don't claim unlinkability at all — which is honest. Bolyra claims it, then walks it back in the fine print of Proposition 4.4 for the exact scenario it advertises.
- **Why it works / fails:** The table in Corollary 4.6 uses summary language ("ties") that is technically accurate but practically misleading for the healthcare buyer. A `1/2` advantage for a computationally unbounded AS+RS colluder is not a tie — it's a break in the regime where the AS is the threat. The construction must either retract the healthcare scenario from §7 or prove that the anchor gating mechanism reduces `Adv` to `negl(λ)` in that regime before claiming the scenario is covered.
- **In-threat-model?** No — the scenario and the theorem are in direct conflict. The construction must either scope the healthcare claim out of the current version or complete the anchor gating proof before advertising it.


## Persona: cryptographer

*Applied cryptographer. IACR publications; reviewer at CRYPTO/EUROCRYPT/IEEE S&P. Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. The construction has made progress—Proposition 4.4's honest admission of Game 3b failure is refreshing. But three attacks survive, and one is a structural problem the current game definitions cannot see.*

---

### Attack 1: Multi-Session ZK Composition — `Adv^ZK = negl(λ)` Is Under-Specified

**Attack:**
Theorems 4.2 and 4.3 both conclude with the bound `Adv ≤ 2·Adv^PRF + Adv^ZK = negl(λ)`, treating `Adv^ZK` as negligible by citation. But Groth16 is *honest-verifier* zero-knowledge (HVZK), not *malicious-verifier* ZK, and critically, not *simulation-extractable* (SE). In a multi-session setting — which is the *only* setting that matters for cross-scope unlinkability, since the adversary sees many proofs across many RS sessions — HVZK does not compose. The standard HVZK simulator programs randomness it controls; a real adversary controls the verifier's challenges and can adaptively correlate proof transcripts across sessions.

Concretely: in Game 2, the RS-collusion adversary sees pseudonym-proof pairs `(nym_1, π_1)`, `(nym_2, π_2)` from two sessions. If the Groth16 proof leaks any algebraic structure correlated with the witness (e.g., via the same `A`, `B`, `C` curve points in the pairing equation that depend on the fixed SRS and the blinding factors chosen by the prover), a distinguisher can correlate proofs without breaking the PRF. The reduction to `Adv^ZK` requires a *simulation-extractable* or at minimum *composable* ZK argument — Groth16 only achieves this in the Algebraic Group Model (AGM), which the theorems do not cite.

**Why it matters:**
The gap is not in the game definition — it's in the reduction's implicit assumption. The reduction in §4 bundles ZK as a black-box property, but the `Adv^ZK` term silently inherits the HVZK definition, which gives zero guarantees against an adversary who sees multiple adaptively-chosen proofs. To close this, the authors must either (a) instantiate with a simulation-extractable SNARK (e.g., Groth16 + knowledge commitment in the AGM, with an explicit AGM assumption), or (b) prove that the specific proof structure of the AgentPolicy/Delegation circuits produces proofs that are computationally indistinguishable across sessions under the DDH/DLOG hardness assumptions used by BN254.

**In-threat-model?** No — Theorems 4.2 and 4.3 as stated are incomplete. The `Adv^ZK` term needs a precise definition and the composability claim needs a citation or a proof.

---

### Attack 2: Subverted SRS — Groth16 Trusted Setup Not in Any Game

**Attack:**
The AS is modeled in Games 3a and 3b as an adversary who knows `cc` and `permBitmask` but *not* `sbs`. This correctly models a compromised enrollment database. But it does not model the AS as a participant in or corruptor of the Groth16 trusted setup for the AgentPolicy and Delegation circuits.

Per §Architecture in the construction, project-specific Groth16 keys use `pot16.ptau` — a locally-generated Powers of Tau ceremony. If the toxic waste from this ceremony is not destroyed (or the ceremony has only one contributor, which is common in pre-production builds), the entity controlling the ceremony — potentially the AS operator — holds the SRS trapdoor `τ`. With `τ`, the adversary can:

1. **Break soundness**: forge valid proofs for *any* statement, including forged credentials with attacker-controlled `permBitmask`.
2. **Break ZK**: the simulation trapdoor and the extraction trapdoor coincide in Groth16. An adversary with `τ` can extract the witness from any proof, recovering `sbs` — the one secret that Game 3a assumed the AS does not know. This collapses Game 3a's unlinkability reduction entirely.

The construction's §7 deployment implications for credit union and healthcare scenarios do not mention ceremony hygiene, multi-party computation requirements for the trusted setup, or what security properties degrade if the ceremony is conducted by a single party. This is not a theoretical edge case: every single Groth16 deployment has failed silently on this point until forced to address it by a public audit.

**Why it works:**
None of Games 1–3b include a subverted-setup adversary. The threat model excludes the most practically dangerous attacker class for a system where the AS operator is partially trusted. UC composability under a subverted CRS is standard in the literature (Canetti-Fischlin-Goldwasser-Vipul, CRYPTO 2010) and the construction provides no argument here.

**In-threat-model?** No — none of the four games model setup-phase adversaries. The construction must either (a) add a Game 0 for setup integrity and prove security assuming an honest-majority MPC ceremony, or (b) migrate AgentPolicy and Delegation to PLONK with a universal SRS (which the construction already builds — this is the correct path), and prove that the PLONK instantiation used achieves ZK under the universal SRS assumption without circuit-specific toxic waste.

---

### Attack 3: Delegation Anchor Mitigation Is a Deferral, Not a Fix

**Attack:**
Proposition 4.4 honestly proves `Adv = 1/2` in Game 3b: the delegation anchor `Poseidon3(scopeId, permBitmask, cc)` is deterministic and fully computable by a colluding AS+RS from enrollment data. The proposed mitigation is *anchor visibility gating* — anchors are sealed until delegation is exercised.

This mitigation does not achieve unlinkability. It achieves *temporal deferral of linkability*. The moment a delegation is exercised (which is precisely when clinical or financial significance is highest — a referral to a specialist, a sub-delegation to a payment agent), the anchor becomes visible and the AS+RS can immediately correlate the agent to all prior cross-scope sessions by matching the anchor to their precomputed table of `Poseidon3(scopeId, permBitmask, cc)` for all enrolled agents.

In the healthcare scenario from §7: "agent delegation across providers without issuer learning referral network" — anchor visibility gating means the referral network is revealed *at the moment of referral*. This is precisely the moment the privacy guarantee needs to hold.

Furthermore, "sealed until exercised" is not a cryptographic construction — it is an access-control policy. The threat model for Game 3b posits a *colluding* AS+RS. A colluding AS receives the anchor as part of the delegation protocol flow. Policy-level sealing is trivially bypassed by a colluding adversary who controls the AS.

**Formal fix required:** To achieve unlinkability in Game 3b, the delegation anchor must incorporate a per-session blinding factor that the AS does not learn. One approach: `anchor = Poseidon3(scopeId, permBitmask, Commit(cc, r))` where `r ← {0,1}^λ` is freshly sampled by the agent and committed on-chain before delegation. This introduces a new primitive (binding commitment scheme) and requires proving that the circuit enforces the commitment opening, but it is the minimum change that makes Game 3b non-trivially winnable.

**In-threat-model?** Partially — the construction correctly identifies that Adv = 1/2 in Game 3b, so the *failure* is in-model. But the *mitigation* is not formalized and does not achieve the intended property. Corollary 4.6 overstates the result by describing anchor visibility gating as a mitigation without a formal theorem showing it reduces the adversary's advantage in a modified Game 3b'.

---

### Attack 4: Timing Correlation — Outside All Game Definitions

**Attack:**
All four IND-UNL games are defined over pseudonyms and proof transcripts. None of them give the adversary access to a timestamp oracle or model the network-layer metadata the AS observes operationally.

In the credit union scenario from §7: a member agent accesses CU-A's RS at time `t_1` and CU-B's RS at time `t_2`. If `|t_2 - t_1| < δ` for some small `δ` (e.g., 50ms, consistent with a single agent making sequential API calls), a colluding AS+RS can correlate cross-scope sessions with high confidence purely from timing, without ever breaking the PRF or ZK. The adversary's strategy:

1. Observe all authorization requests at CU-A's RS and CU-B's RS with timestamps.
2. Build a bipartite graph: edge weight between pseudonym `nym_A` at CU-A and `nym_B` at CU-B equals the number of temporally co-occurring session pairs within window `δ`.
3. For any agent that makes multiple cross-CU accesses, the bipartite matching density exceeds random by a factor proportional to the agent's activity level. This is a traffic-analysis attack, not a cryptographic attack.

This attack has `Adv → 1` as the number of observed cross-scope sessions grows, regardless of the cryptographic strength of the POS-PRF or the ZK proof. It is entirely outside the threat model of Games 1–3b because no game gives the adversary timing information.

The construction's §1 gap statement acknowledges "treatment of side channels (timing, nonce freshness)" but §4's games do not close this gap. Closing it requires either (a) formally defining a timing-aware game where the adversary gets `(nym_i, π_i, t_i)` tuples and proving the construction achieves indistinguishability under this extended view, or (b) pushing timing obfuscation (mixing, batching, delay randomization) into the protocol spec and proving that the residual distinguishing advantage is bounded.

**In-threat-model?** No — none of the four games model timing. This is not a critique of the cryptographic construction *per se*, but of the completeness of the formal model. A construction that achieves IND-UNL in Games 1–3a while leaking the full agent traffic graph via timing does not achieve the deployment-level guarantee claimed in §7.

---

**Summary Table**

| Attack | Survives construction? | Required fix |
|---|---|---|
| Multi-session ZK composition (Thm 4.2/4.3) | No — `Adv^ZK` term under-specified | Cite AGM or prove SE-SNARKs; add composability argument |
| Subverted SRS (Games 1–3b silent on setup) | No — AS-as-ceremony-participant breaks Game 3a | Add Game 0 for setup integrity; or migrate to PLONK universal SRS and prove security |
| Anchor visibility gating (Game 3b mitigation) | No — mitigation defers, does not prevent linkability | Introduce per-session blinding commitment in anchor; prove modified Game 3b' |
| Timing correlation (all games) | No — outside threat model | Extend games to include timestamp oracle; bound timing advantage or specify obfuscation protocol |


## Persona: cu_ciso

---

### Attack 1: The Regulatory Vocabulary Gap — "Prove the IND-UNL Game to My NCUA Examiner"

- **Attack:** I pull up the NCUA examiner questionnaire for third-party technology risk (Part 748 Appendix A, Section II.C) and ask: which specific NCUA control does IND-UNL-RS satisfy? The construction's formal objects — Game 2, Game 3a, Theorem 4.2, Theorem 4.3 — are written in cryptographic game notation. My examiner's workpapers use URSIT domain ratings and vendor risk tiering, not `Adv ≤ 2·Adv^PRF + Adv^ZK = negl(λ)`. The construction asserts "beats baseline in Games 1 and 3a" with no translation layer into FFIEC CAT Maturity Levels or GLBA Safeguards Rule §314.4(f) (service provider oversight).

- **Why it works / why it fails:** The construction is mathematically complete within its own frame. It fails entirely in my frame. No FFIEC CAT control mapping, no NCUA information security program mapping, no SOC 2 Type II trust service criteria cross-reference. When the exam team asks "what vendor controls protect member data from cross-institution correlation?" I cannot hand them Corollary 4.6. I hand them a SOC 2 report or I hand them nothing.

- **In-threat-model?** No — construction must address. Section 7 extends deployment implications for credit unions but does not produce a regulatory control matrix. A one-page appendix mapping each Game outcome to specific NCUA/GLBA/FFIEC controls is table stakes for a CU deployment conversation.

---

### Attack 2: Unlinkability Is My Audit Trail's Enemy — GLBA §314.4 and SOC 2 CC7.2

- **Attack:** I invoke the GLBA Safeguards Rule §314.4(e): I must implement access controls and monitor for unauthorized access to member financial information. SOC 2 CC7.2 requires logging of system activity sufficient to detect and reconstruct security events. Now I read the construction's core claim: "same agent accessing different RS instances produces cryptographically unlinkable authorizations." That *is* the attack. When my fraud ops team opens a Suspicious Activity Report at 9am Monday, they need to reconstruct what Agent X did across my mortgage RS, my checking RS, and my external payment RS over the prior 72 hours. The construction's unlinkability property — the feature being sold — actively prevents that reconstruction. Cross-scope pseudonymity means the logs at each RS look like three unrelated principals. There is no join key available to my ops team.

- **Why it works / why it fails:** The construction is silent on the lawful access / audit reconstruction problem. Section 7 discusses deployment implications but does not address the forensic conflict. The gap is structural: the property that protects members from AS correlation is the same property that blocks my SOC 2 auditor from correlating legitimate audit events. This is not a fringe edge case — it is the primary operational requirement for any GLBA-covered institution processing multi-service member transactions.

- **In-threat-model?** No — construction must address. The construction needs a designated audit channel that is (a) cryptographically separated from the cross-RS correlation surface and (b) gated by a court-order or SAR-level access policy. Without this, I cannot deploy; my GLBA compliance program requires the audit trail. Unlinkability without a lawful-access carveout is a product I cannot buy.

---

### Attack 3: Proposition 4.4 Admission + "Anchor Visibility Gating" Is an Insider Threat Gift

- **Attack:** I read Proposition 4.4 honestly: in Game 3b (joint AS+RS collusion with active delegation), the adversary advantage is `1/2` — the construction ties, not wins. The mitigation offered is "anchor visibility gating — anchors sealed until delegation is exercised." I now ask two NCUA Part 748 / Vendor Management Policy questions. First: who controls the gate? If the AS in my deployment is my core processor (FIS, Fiserv, Jack Henry — all third parties under my vendor management program), then a single privileged insider at that processor can unseal delegation anchors for all member agents across all RSes, retroactively reconstructing the merchant graph the construction claims to hide. Second: how is the sealing audited? If the gate has no independent audit log that I (the CU) control, I have transferred risk to a third party with no contractual SLA on the confidentiality of that gate state.

- **Why it works / why it fails:** The construction acknowledges the weakness (honest credit for Proposition 4.4) but the mitigation is architectural hand-waving without an operational trust model. "Anchors sealed" requires someone to hold the seal. That someone is either the member (operationally untenable at 2am support calls — see Attack 4) or the AS/processor (who is exactly the adversary in Game 3b). The gap between cryptographic tie and operational risk control is not addressed in Section 7.

- **In-threat-model?** Partially — Game 3b is acknowledged but the insider threat path through the mitigation is not addressed. Construction must add: who holds sealing authority, what separation-of-duties control governs it, and how it is logged under NCUA Part 748 Appendix A §I.C (access controls) and §II.B (audit trails).

---

### Attack 4: Key Custody of `sbs` — Where Does the Member Secret Live at 2am?

- **Attack:** I locate the construction's enrollment secret `sbs` — the value the AS does *not* know (Game 3a assumes AS lacks `sbs`). I ask the operational question my Tier 1 support team will ask at 2am when a member calls saying their mortgage application agent is frozen: "Where is `sbs` stored and how do I restore it?" If `sbs` is browser-local (localStorage, IndexedDB), a device wipe — routine after a lost phone — destroys the member's identity anchor. If `sbs` is server-side at Bolyra or the CU, then the AS *does* hold it, collapsing the Game 3a security claim operationally even if not cryptographically. The construction does not name a key custody model. GLBA §314.4(c) requires I assess and manage risk from service providers holding customer data — `sbs` custody is exactly that assessment.

- **Why it works / why it fails:** The construction's formal model treats `sbs` as a given — it exists, it's secret from AS, Games proceed. The operational model is silent. A cryptographic proof that AS cannot compute `sbs` is irrelevant if in practice I must escrow `sbs` somewhere to support account recovery, and that escrow is either (a) the member's device (operationally fragile) or (b) a third-party KMS (which becomes a regulated custodian under my vendor management program and potentially GLBA). Neither path is addressed in Section 7's CU deployment implications.

- **In-threat-model?** No — construction must address. Section 7 must include a key custody architecture decision tree: device-local with recovery phrase (UX and loss model), CU-operated HSM (regulatory custody implications), or threshold custody (complexity, latency, SLA). Until this is specified, I cannot assess third-party risk under my Vendor Management Policy and I cannot present this to my board as a deployable control.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions. Cites RFCs by number. Demands a counterexample the baseline cannot match.*

---

### Attack 1: The PPID Baseline Already Closes the Game 1 Gap

- **Attack:** The construction's Corollary 4.6 claims Bolyra beats the baseline in Game 1 by a gap of `1/2 - negl(λ)`. The "baseline" appears to be vanilla RFC 7662. But a well-configured AS using OIDC pairwise subject identifiers (PPIDs, OIDC Core §8.1) combined with RFC 8707 Resource Indicators already issues audience-scoped tokens where each RS receives a different `sub` value, derived from `HMAC(sector_identifier_uri ‖ local_account_id, sector_secret)`. Colluding RSes in different sectors see cryptographically distinct subjects — they cannot link sessions even by pooling introspection responses. The AS knows the correlation graph *internally*, but so does a Bolyra AS that issues enrollment anchors. The construction must answer: in Game 1, is the adversary the AS disclosing cross-RS correlation *to RSes*, or the AS simply *possessing* it? If the game only models what RSes can observe, the PPID baseline matches the ZK construction's guarantee and the claimed gap evaporates.
- **Why it works / why it fails:** The construction never specifies the information-theoretic position of the AS in Game 1 relative to a PPID-enabled baseline. If the AS is the adversary and can *see* the enrollment enrollment anchor `cc`, it can correlate via that anchor regardless of ZK. If the game excludes the AS from seeing `cc`, the baseline PPID with sector isolation achieves the same RS-observable unlinkability without any ZK machinery.
- **In-threat-model?** No — the construction must add a direct comparison against PPID+RFC 8707 in the Game 1 definition, or the claimed advantage is undefended.

---

### Attack 2: DPoP Key Rotation Per-RS Closes the Game 3a Gap Without ZK

- **Attack:** Theorem 4.3 (Game 3a) proves Bolyra's advantage over the baseline in the joint AS+RS collusion case (non-delegation) on the grounds that the AS lacks the agent's `sbs` blinding secret, so the pseudonym remains unlinkable. But RFC 9449 DPoP already provides a credential-binding mechanism that the AS does not control: the DPoP proof is tied to an ephemeral asymmetric key pair generated client-side. If the agent generates a *fresh DPoP keypair per RS interaction* (which RFC 9449 §9.1 explicitly permits and recommends for forward secrecy), the access token is sender-constrained to a key the AS has never seen in that RS context. A colluding AS+RS observes: (a) an audience-bound token scoped to RS1 (RFC 8707 `aud`), and (b) a DPoP proof bound to an ephemeral key. Across RS1 and RS2 the agent presents different ephemeral keys. The AS cannot correlate because the keys are client-generated after token issuance. The construction's Theorem 4.3 needs to name a property that DPoP key rotation *cannot* provide — otherwise the baseline closes Game 3a without ZK.
- **Why it works / why it fails:** The construction's proof that `Adv ≤ Adv^PRF + Adv^ZK = negl(λ)` assumes the pseudonym is the *only* binding point between AS and RS. DPoP ephemeral keys introduce a second, ZK-free binding that achieves the same per-RS session independence. The ZK construction adds verifiable scope enforcement, but unlinkability per se is not a ZK-exclusive property here.
- **In-threat-model?** No — the construction must demonstrate a property that per-RS ephemeral DPoP keys cannot achieve. Candidate: verifiable *scope commitment* inside the proof, i.e., the RS can verify the scope is cryptographically bound to the credential without trusting the AS's claim. That is a real distinguisher — but it must be made explicit in §3.

---

### Attack 3: RFC 8693 `act` Claim Gating Outperforms "Anchor Visibility Gating" in Game 3b

- **Attack:** Proposition 4.4 honestly admits `Adv = 1/2` in Game 3b (delegation, AS+RS collusion) because the delegation anchor `Poseidon3(scopeId, permBitmask, cc)` is deterministic from AS-known values. The mitigation proposed is "anchor visibility gating — anchors sealed until delegation is exercised." This is underspecified and weaker than the RFC 8693 baseline. Under RFC 8693 Token Exchange, the AS issues a `may_act` / `act` claim that explicitly models delegation without revealing the delegation graph to downstream RSes: the AS can issue per-RS derived sub-tokens where the `act` chain is truncated at each hop, and the `sub` in each derived token is an audience-specific PPID rather than a persistent delegation anchor. A well-configured AS with RFC 8693 + PPID sectorization can achieve `Adv < 1/2` (i.e., *better* than random guessing) for the RS, because the RS cannot even enumerate the delegation anchor space — it never sees any anchor. The ZK construction's honest tie at `1/2` in Game 3b may actually be *worse* than the RFC 8693 baseline with per-hop claim gating.
- **Why it works / why it fails:** The construction's "anchor visibility gating" mitigation requires the anchor to be conditionally revealed at exercise time, which re-introduces a correlation event. RFC 8693 avoids this by never issuing a stable delegation anchor at all — the AS reconstructs delegation chains server-side from opaque token lineage. The ZK construction's advantage is that it moves the delegation policy enforcement *off* the AS into the circuit, but this comes at the cost of a deterministic anchor that leaks under AS+RS collusion.
- **In-threat-model?** Yes — the construction addresses this in Proposition 4.4, but the comparison is against *vanilla* delegation, not RFC 8693 with `act` claim gating. The claim "ties baseline" may be reversed under the correct baseline. This is the most load-bearing gap in the current document.

---

### Attack 4: Timing Oracle Escapes All Three Cryptographic Games

- **Attack:** The construction's gap statement (C2 candidate) mentions "side channels (timing, nonce freshness)" but the formal treatment in §3–§4 is purely algebraic — the IND-UNL games model polynomial-time distinguishers on cryptographic transcripts, not on protocol *timing*. In the deployed credit union scenario (§7), the AS observes the wall-clock timing of credential requests: Agent X presents a credential to CU-RS1 at `t₀`, then CU-RS2 at `t₀ + Δ`. The AS — even without seeing cryptographic identifiers — can build a timing graph: agents with correlated inter-request intervals across RSes are linkable with high probability via traffic analysis. The nonce freshness property explicitly acknowledged in the gap makes this worse: if the agent must request a fresh nonce from the AS before each proof, nonce issuance timing creates AS-visible per-agent fingerprints that survive nullifier separation. RFC 9449 DPoP proofs carry a `iat` (issued-at) timestamp bound to the proof itself — same attack surface, same limitation — but DPoP does not claim timing resistance. Bolyra does.
- **Why it works / why it fails:** The IND-UNL games assume the adversary receives only the transcript `(pseudonym, anchor, scope)`. A real AS also receives a timing trace. No algebraic proof over `Adv^PRF + Adv^ZK` bounds a timing-trace distinguisher, because timing is not a function of the circuit's input-output relation. The construction must either (a) formally exclude timing adversaries and state this as an explicit out-of-scope assumption in the threat model, or (b) specify a nonce issuance batching/jitter mechanism and prove it reduces timing mutual information below a stated threshold.
- **In-threat-model?** No — the current formal treatment does not address timing adversaries. For the healthcare referral scenario in §7 (where the issuer must not learn the referral network), timing correlation is likely the *primary* practical attack vector once cryptographic linkability is closed. The construction must address this or explicitly bound the threat model to a synchronous, timing-blind adversary.


## Persona: spiffe_engineer

---

### Attack 1: Game 3b is Unfixed — The Top-Level Claim is Self-Falsified

- **Attack:** The candidate's primary claim reads "cryptographically unlinkable authorizations *even under adversarial AS*." The construction's own **Proposition 4.4** sets `Adv = 1/2` in the delegation case (Game 3b). That is not "even under adversarial AS" — that is *broken* under adversarial AS when delegation is active. The proposed mitigation ("anchor visibility gating — anchors sealed until delegation is exercised") defers the attack but does not eliminate it: the colluding AS already holds `cc` and `permBitmask` and can compute `Poseidon3(scopeId, permBitmask, cc)` **offline at any time**, regardless of when the anchor is exposed on-chain. There is no proof that sealing delays the window long enough to prevent correlation; the construction's own §4 makes no formal statement about what "visibility gating" achieves.

- **Why it works / fails:** It works because the formal gap is explicitly acknowledged (`Adv = 1/2`) and the offered mitigation has no accompanying security reduction. Corollary 4.6 honestly presents the tie in Game 3b, but that honesty does not rescue the top-level claim. The credit union scenario in §7 is the precise setting where delegation is the normal path — CU-as-AS issuing delegated agent credentials — meaning Game 3b is the *primary* operating mode for the construction's headline use case.

- **In-threat-model?** **No.** Construction must either (a) restate the claim to exclude delegation settings, (b) replace the deterministic anchor with a blinded anchor (`Poseidon3(scopeId, permBitmask, cc, r)` with a per-delegation random `r` withheld from AS), and prove a new reduction, or (c) provide a formal bound on what visibility gating achieves and under what timing assumptions.

---

### Attack 2: WIMSE Token Exchange + a ZK Attestor Plugin Is a Narrower Delta

- **Attack:** SPIRE ships a plugin interface for node attestation. A ZK attestor — one that generates a nullifier commitment at SVID issuance time and passes it as a JWT-SVID claim — would give you per-scope unlinkability *inside* the existing `spiffe://trust-domain/workload-path` identity envelope, with WIMSE `draft-ietf-wimse-arch` token exchange handling the RS-to-RS binding. The construction instead defines a new wire format, a new DID method (`did:bolyra:`), a new handshake protocol (§2), and a new proving ceremony. None of that delta is justified against the narrower alternative. Specifically: JWT-SVID audience binding already scopes tokens to individual RS instances. Adding a ZK PRF output as a `jti` or `sub` claim per audience achieves Game 1 (IND-UNL-RS) within standards that operators already run.

- **Why it works / fails:** It works at the deployment argument level. The construction offers no comparison against "SPIFFE + ZK attestor plugin" — only against raw mTLS or opaque tokens. Game 2 (IND-UNL-RS) is where the construction claims to win; a ZK attestor in SPIRE would achieve the same reduction (adversary lacks enrollment secrets) without the protocol overhead. Where the construction *would* win is in the human root of trust (Semaphore v4 enrollment) — but that is not what C2 is about. C2's claim is agent-to-RS unlinkability, which WIMSE + ZK attestor covers.

- **In-threat-model?** Partially. The construction is not *wrong* but it is *unreasonably wide*. The threat model for C2 specifically should include a "why not SPIFFE ZK attestor" comparison. Without it, operators running SPIRE have no reason to adopt a new identity layer.

---

### Attack 3: Timing Side Channel Is Listed as a Gap But Not Closed

- **Attack:** The candidate's own `gap_to_close` field lists "treatment of side channels (timing, nonce freshness)." The construction's §7 extension addresses "IND-UNL-RS and IND-UNL-(AS∧RS) deployment implications" but contains no formal or empirical treatment of timing. ZK proof generation time is a function of circuit size, prover hardware, and input entropy. An adversarial AS that observes proof submission timestamps (which it does — it receives the proof for verification) and a colluding RS that observes proof arrival timestamps can run a traffic-correlation attack identical to Tor timing correlation: match inter-arrival time distributions across sessions even when the nullifiers are cryptographically unlinkable. SPIRE avoids this by pre-issuing SVIDs with short TTLs and caching them at the Workload API — proof generation happens out-of-band relative to the request path. Bolyra's construction ties proof generation to the request path.

- **Why it works / fails:** It works because the gap is self-admitted and unaddressed. Theorems 4.2 and 4.3 are information-theoretic over the cryptographic objects; they say nothing about when those objects arrive at the verifier. The credit union scenario involves an AS (CU) that controls the network path between member-agent and merchant-RS — exactly the adversary position needed for timing correlation.

- **In-threat-model?** **No.** The gap was listed but §7 does not close it. The construction needs either (a) a proof-caching layer (pre-generated proofs with randomized submission delay) analogous to SVID pre-issuance, or (b) an explicit out-of-scope declaration with a security caveat, or (c) a formal bound showing timing leakage is bounded by `negl(λ)` under a stated timing model.

---

### Attack 4: "Adversarial AS" Is a Non-Standard Trust Model That Breaks Operator Deployments

- **Attack:** In every production SPIFFE/SPIRE deployment, the SPIRE server *is* the AS and *is* trusted by construction — it is the root of the SVID issuance chain. Designing against an "adversarial AS" is not a workload identity threat model; it is a *different* security boundary. The implication for operators: to deploy Bolyra in a CU setting where CU-as-AS is adversarial, the CU must operate infrastructure that is simultaneously (a) trusted enough to issue delegated credentials, (b) untrusted enough to be modeled as adversarial for correlation purposes. This is not a workload identity deployment pattern — it is closer to a privacy-preserving credential issuance pattern (e.g., Privacy Pass, anonymous credentials). Operators who come from SPIFFE backgrounds will not recognize this trust model, and the construction never explains the translation. §1 (preserved verbatim per the construction note) presumably does not address this.

- **Why it works / fails:** It works as an adoption and framing attack. The construction is technically coherent within its own model, but the model is orthogonal to how workload identity engineers think about trust. This becomes a practical attack on deployment: operators will map CU-as-AS to SPIRE-server-as-root-of-trust and conclude AS is trusted, making Games 3a and 3b irrelevant to their deployment. The genuine novel property (ZK unlinkability across scopes even from the issuer) is a property of **anonymous credential schemes**, not workload identity schemes, and should be framed as such — with a delta over BBS+ / Privacy Pass / ACL-issued tokens, not over SPIFFE.

- **In-threat-model?** Partially. The construction is solving a real problem, but the framing mismatch means the intended adopter (an operator already running SPIFFE) will not recognize the threat model and will not deploy. The construction should either (a) explicitly position C2 as an anonymous credential layer *above* workload identity, not *instead of* it, or (b) provide an integration sketch showing Bolyra nullifiers as a SPIFFE JWT-SVID extension claim, so the trust model delta is legible to the target operator.
