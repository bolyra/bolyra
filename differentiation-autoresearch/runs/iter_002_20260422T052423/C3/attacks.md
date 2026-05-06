# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Latency Kills the AI Pipeline Use Case Before It Starts

- **Attack:** The construction's stated target scenario is "multi-tool AI pipeline where auditor wants proof that no hop exceeded its mandate." But the gap-to-close explicitly frames each hop as a *tool call*. A 5-hop agentic pipeline (e.g., retrieve → summarize → draft → review → send) requires one proof per hop boundary. At the cited ~15s prove time, that's 75s of auth overhead on a workflow that typically completes in under 10s end-to-end. WorkOS issues a delegated M2M token in <100ms. The construction's latency profile isn't a deployment detail — it structurally excludes the primary use case named in the scenarios section.

- **Why it works / why it fails:** The construction addresses the *cryptographic* correctness of hop-by-hop delegation but does not address proof generation latency at all — not in the constraint set, not in the threat model, not in the deployment scenarios. There is no §performance section, no batching argument, no recursive SNARK folding (e.g., Nova/SuperNova) proposed to amortize per-hop cost. The gap-to-close mentions "formal semantics of narrowing proof and in-circuit enforcement" but says nothing about proving time targets.

- **In-threat-model?** No. The construction must address either: (a) a per-hop latency bound with a concrete proving backend that hits it, or (b) a batch/deferred audit model where proofs are generated offline and the runtime path is latency-free. Without this, Scenario A (AI pipeline) is not deployable and the claim is theoretical.

---

### Attack 2: KZG Trusted Setup Is a Solo-Founder Procurement Veto

- **Attack:** Assumption A5 explicitly names the KZG SRS 1-of-N trust model. In any enterprise procurement conversation, the security team will ask: "Who conducted the trusted setup ceremony? Can you provide the transcript? Are the participants auditable?" The correct answer requires either (a) participation in a large ceremony like Ethereum's KZG summoning (public, credible) or (b) running your own ceremony. Option (b) as a solo founder means the enterprise's security posture now depends on trusting that exactly one person did not keep their toxic waste. Auth0, WorkOS, Stytch have SOC 2 Type II, no ceremony required, auditors already accept their trust model. §4.3 offers IPA-PLONK/STARK as alternatives "for the journalist scenario" — but this reads as an afterthought, not a primary deployment path, and does not resolve the KZG question for the enterprise/NCUA scenario (Scenario A).

- **Why it works / why it fails:** The construction names the trust assumption correctly (credit for honesty), but naming it is not resolving it. The construction does not specify which ceremony, does not point to a publicly verifiable SRS, and does not explain why an NCUA examiner should accept a setup that cannot be independently audited through standard compliance tooling. The §8 comparison table does not include "trusted setup requirements" as a row — meaning the construction avoids the comparison where it loses.

- **In-threat-model?** No. The construction must either: (a) commit to a named, public, verifiable SRS (e.g., Ethereum's KZG ceremony), (b) make IPA-PLONK/STARK the primary backend with KZG as optional, or (c) add a §trust-setup section explaining how a credit union procurement team evaluates the ceremony. Otherwise this is a show-stopper at the first security review.

---

### Attack 3: RegulatorReveal Is Inverted From What Compliance Actually Requires

- **Attack:** C14 (ElGamal-over-BabyJubjub escrow) is deployed in Scenario A as the NCUA examiner path. The construction frames this as a feature: the auditor can learn scope narrowing happened without learning intermediate participants. But BSA/AML and NCUA examination authority under 12 CFR Part 748 require *identity disclosure* — the examiner needs to know *who* delegated to *whom*, not merely that a scope monotonically narrowed. The construction's privacy guarantee is the opposite of the compliance requirement. An NCUA examiner presenting a subpoena does not want a ZK proof of monotonic narrowing; they want a ledger entry showing "Member A authorized Agent B to access Account C on date D." The construction has built an excellent tool for minimizing regulator access, then named it the regulator-facing deployment scenario.

- **Why it works / why it fails:** The construction conflates two different auditor models: (1) an auditor who wants *assurance* that delegation was well-formed without learning private details (the whistleblower scenario), and (2) a regulator who has *legal authority* to compel disclosure and wants the actual trail. RegulatorReveal via C14 escrow only helps if the regulator is satisfied with a ZK proof of structural integrity — but no existing regulatory framework treats ZK proofs as equivalent to disclosed records. The gap-to-close does not distinguish these auditor types.

- **In-threat-model?** No. The construction must either: (a) restrict Scenario A to an *internal* audit use case (not NCUA) where the auditor's goal is structural assurance, not identity recovery, or (b) add a compliance layer on top of C14 that produces a human-readable, legally admissible disclosure path separate from the ZK proof. As written, the construction's strongest deployment scenario is the one where the construction's core privacy guarantee is a liability.

---

### Attack 4: The Buyer Problem Is Solved by Append-Only Logs, Not ZK

- **Attack:** The enterprise buyer's actual question is: "Can I prove to an auditor that no agent in my pipeline exceeded its granted permissions?" WorkOS answers this with: OAuth scopes on M2M tokens + an immutable audit log in their dashboard, exportable to Splunk/Datadog, already accepted by SOC 2 auditors. The construction's value claim requires the buyer to also believe that the *intermediate scope values and participant identities must be hidden from the auditor* — but in the overwhelming majority of enterprise deployments, the operator *wants* the auditor to see the full chain. The privacy guarantee that is the construction's core innovation is a feature that most buyers will not pay for and some buyers actively cannot adopt (due to the compliance inversion in Attack 3). The construction has identified a real cryptographic problem (auditable delegation without exposure) but has not identified a buyer segment where that problem is both real and unsolved by existing tooling.

- **Why it works / why it fails:** The scenarios section names two use cases: AI pipeline audit and journalist/source chain. The AI pipeline case does not require hiding intermediate scopes from the operator's own auditor — it requires hiding them from *other pipeline participants* (confidentiality between hops), which is a different property not formalized in the construction. The journalist case is real but is a narrow, non-commercial niche. The construction does not produce a third scenario where (a) the buyer is an enterprise, (b) the auditor must be satisfied, and (c) intermediate scope/participant hiding is a hard requirement. Without that scenario, the GTM story is "we built a cryptographic construction for a problem that matters to cryptographers."

- **In-threat-model?** Partially. The construction does not need to change its cryptography, but it must add a §buyer-problem section that names a specific enterprise segment where the combination of (auditable + private) is a hard procurement requirement — not just a nice-to-have. The journalist scenario is the strongest candidate but needs to be elevated to a first-class deployment scenario with a concrete operator (news org, legal firm, regulated investigative body), not left as a secondary note in §4.3.


## Persona: cryptographer

---

### Attack 1: Semantic Narrowing is Undefined — The Lattice Gap

**Attack:** The adversary submits a proof where each hop's `delegateeScope[i]` is non-zero (satisfying C2) and strictly smaller in *bit-length* than the parent, but the encoding does not correspond to any agreed-upon scope lattice. Concretely: if scopes are capability bitmasks, the adversary sets `delegateeScope[i] = delegateeScope[i-1] XOR k` for some bit `k`, which is "smaller" in one metric but *not* a subset in the capability lattice. The auditor's verifier accepts the proof (C2 is satisfied, the commitment chain hashes correctly), but the semantic narrowing guarantee is void.

**Why it works:** The construction never defines what "narrowing" means as a relation on scope values. C2 enforces `scope ≠ 0`; the circuit presumably enforces some ordering predicate, but no Game definition states: *"the adversary wins if it produces a valid proof π for a chain where ∃i: capabilities(delegateeScope[i]) ⊄ capabilities(delegateeScope[i-1])."* Without a formal scope lattice embedded in the circuit and a soundness game over that lattice, the narrowing claim is not a theorem — it is an assertion.

**In-threat-model?** **No.** The construction must define a scope lattice `(L, ≤)`, commit to it in the circuit as a public parameter, and add a narrowing predicate `C_narrow` that enforces `scope[i] ≤_L scope[i-1]` for every `i`. The soundness game must be stated over this predicate, not just over `≠ 0`.

---

### Attack 2: RegulatorReveal Key Substitution Under an Adversarial AS

**Attack:** §3.1 designates the AS as the primary adversary, yet C14 (ElGamal-over-BabyJubjub escrow) embeds a regulator public key `pk_reg` in the proof. The construction does not specify *who publishes `pk_reg`* or *how its integrity is guaranteed*. A malicious AS generates an ElGamal keypair `(sk_A, pk_A)`, substitutes `pk_A` for `pk_reg` during credential issuance, and stores `sk_A`. Every "RegulatorReveal" ciphertext is now silently readable by the AS. The auditor's proof verifies correctly — the SNARK only checks that the ciphertext is well-formed under *some* public key, not that the key belongs to the regulator.

**Why it works:** ElGamal encryption does not provide key authenticity. The circuit constraint C14 verifies that `Enc(pk_reg, scope_i)` is correctly formed; it cannot verify that `pk_reg` is the regulator's key versus the AS's key. This is a standard key-substitution attack on hybrid encryption in the CCA model, and it is entirely in-threat-model given AS is adversarial.

**In-threat-model?** **No.** The construction requires either: (a) `pk_reg` published in a transparency log with a certificate chain excluding AS, or (b) a proof of knowledge `PoK(sk_reg)` by the regulator committed to the circuit's constraint system. Neither is present. Without this, the RegulatorReveal mode provides confidentiality *against the auditor* but not against the AS — inverted from the claimed threat model.

---

### Attack 3: Cross-Session Scope Correlation — Game 2 Does Not Bound Mutual Information

**Attack:** Game 2 is an adaptive k-proof participant extraction game, reducing to PLONK ZK + Poseidon preimage resistance. Consider the AI-pipeline scenario: the same intermediate agent `A_mid` appears in chains `C₁, C₂, …, Cₘ` issued over time. Each proof commits to `H(delegateeScope[i] || nonce_i)` for hop `i`. If `nonce_i` is deterministic (e.g., derived from a session ID the AS controls), the AS queries the prover for proofs across m sessions, observes the set of scope commitments `{H(s || nonce_j)}`, and runs a preimage correlation: for any two chains where the same scope appears, the commitment is identical. The AS learns the intersection graph of scopes across chains — not full extraction, but enough to de-anonymize the intermediate hop topology.

**Why it works:** PLONK ZK only hides witness values *within a single proof*. It makes no cross-proof mutual information guarantee. Game 2's reduction to Poseidon preimage resistance prevents recovering `scope` from a single commitment, but does not prevent observing that two commitments are *equal* (same preimage). The construction needs session-unlinkability — a property closer to anonymous credential unlinkability (e.g., BBS+ or Groth-Sahai) — which requires random per-invocation blinding factors *outside* the prover's control, or a formal game bounding `I(scope_i; observations across sessions)`.

**In-threat-model?** **No.** The journalist scenario (Scenario B) is precisely the case where this matters: the auditor (or a colluding AS) accumulates proofs over time. The construction must either (a) define a session-unlinkability game and reduce to it, or (b) mandate fresh random nonces per proof with entropy guarantees and prove that equal commitments imply equal nonces (not equal scopes).

---

### Attack 4: Dummy-Hop Indistinguishability Requires Simulation-Extractability, Not Honest-Verifier ZK

**Attack:** Game 4 (LEN-EXTRACT) argues `{π | n=n₀} ≈_c {π | n=n₁}` via PLONK ZK over private `isReal` bits. But *which* ZK property is invoked? Standard PLONK provides *honest-verifier zero-knowledge* (HVZK): the simulator works only for an honest verifier who picks challenges uniformly at random. In the journalist scenario, the verifier (auditor) is *explicitly untrusted* and may be malicious (it is trying to extract intermediate hop identities). For the indistinguishability argument to hold against a malicious auditor, the construction needs *malicious-verifier ZK* (MVZK) or, stronger, *simulation-extractability* (SE-SNARK). PLONK as typically deployed achieves SE under the algebraic group model (AGM) + ROM, but this requires citing the specific SE-PLONK variant (e.g., Maller et al. with the blinding polynomial technique) and including the AGM assumption in the assumption list alongside A5.

**Why it works:** If the auditor is a malicious verifier who replays old challenges (or uses a non-uniform challenge distribution exploiting KZG's algebraic structure), the HVZK simulator's output distribution may not match the real proof distribution. An adversary constructing such a verifier could distinguish `n=1` from `n=3` chains even with dummy hops, because the blinding randomness in the circuit satisfies algebraic relations that a standard HVZK argument does not cover. This is not hypothetical: the PLONK paper's ZK section explicitly notes HVZK and leaves MVZK to the SE-PLONK literature.

**In-threat-model?** **No.** The assumption list must add: A6 — SE-PLONK security under AGM + ROM (citing Kohlweiss-Maller-Nguyen-Sheridan or equivalent). Without it, Game 4's indistinguishability argument has a proof gap precisely in the scenario (journalist/untrusted auditor) where the construction claims the strongest privacy guarantee.


## Persona: cu_ciso

---

### Attack 1: The Escrow Key Is Now My Problem

**Attack:** The CISO reads §C14 (RegulatorReveal — ElGamal-over-BabyJubjub escrow) and immediately asks: *who holds the escrow decryption key, where is it stored, how is it rotated, and what happens when the employee who enrolled it leaves?* The construction hands the NCUA examiner a "reveal" capability but is silent on key lifecycle. Under **NCUA Part 748 Appendix B §II.B** (access controls, separation of duties) and **GLBA Safeguards Rule 16 CFR §314.4(c)(3)** (access controls to customer information systems), the CU's security program must document *who can decrypt, under what authorization, with what logging*. A BabyJubjub private key sitting in a KMS secret or, worse, a config file, is a finding.

**Why it works:** The construction solves the cryptographic problem (prove narrowing without revealing) but creates a new operational-security problem (escrow key management) and doesn't address it. The gap is not theoretical — it's a vendor risk intake form and a Part 748 security program amendment.

**In-threat-model?** No — construction must address escrow key custody, rotation policy, and audit logging of reveal operations as a deployment requirement, or the CISO can't sign the vendor assessment.

---

### Attack 2: My NCUA Examiner Cannot Verify a PLONK Proof

**Attack:** The CISO brings the construction's audit artifact — a PLONK proof π — to the examination table. The examiner asks: *"Show me the audit trail for this delegation chain."* The CU hands over `(π, publicInputs)`. The examiner has a checklist, not a SNARK verifier. Under **FFIEC CAT Domain 3 (Cybersecurity Controls) Baseline** and **SOC 2 Type II CC7.2** (monitoring for anomalies), the *human-readable* audit trail is the control evidence. A proof no one on the exam team can independently inspect is functionally equivalent to "trust us." The construction claims RegulatorReveal produces something "usable beyond narrow regulatory niches" but doesn't specify what artifact the examiner actually receives, in what format, translated by whom.

**Why it works:** ZK proof + public inputs is not an audit log. The construction needs a verified-transcript layer: something that takes π and emits a human-readable, examiner-facing statement ("Hop 3 scope was a strict subset of Hop 2 scope; verified at block height X by contract Y") signed by a third-party attestation service the CU's vendor management policy covers. None of that exists in the construction.

**In-threat-model?** No — the construction must specify the examiner-facing artifact format and the chain of custody from proof to readable finding, or the regulatory usability claim is hollow.

---

### Attack 3: The Trusted Setup Is an Unreviewed Vendor

**Attack:** The CISO's vendor management team processes Assumption A5 (KZG SRS, 1-of-N ceremony). The ceremony happened once, off-site, run by parties the CU did not select and cannot re-audit. Under the CU's **Vendor Management Policy** (required under **NCUA Letter 01-CU-20** and reinforced by **GLBA §314.4(f)** service-provider oversight), every third-party dependency on which member data security rests requires: initial due diligence, annual review, right-to-audit clause, SLA, and incident notification terms. A trusted setup ceremony has none of these. The CISO cannot onboard "the Ethereum KZG ceremony participants" as a vendor. The §4.3 alternative (IPA-PLONK/STARK) removes the ceremony but is offered only for the journalist scenario — Scenario A (NCUA) still uses KZG.

**Why it works:** The construction acknowledges the trust model but treats it as an assumption, not a deployment risk. For a regulated CU, an un-vendored cryptographic dependency on which audit validity rests is a gap that blocks production approval, not a footnote.

**In-threat-model?** No — either Scenario A must also offer a ceremony-free proof system, or the construction must provide a vendor-onboarding template for the KZG SRS dependency including the NCUA-required third-party risk artifacts.

---

### Attack 4: Zero Operational Runbook for a 2am Proof Failure

**Attack:** It's 2am. A delegation proof fails to verify on-chain. The AI pipeline stalls. A Tier 1 ops analyst pages the on-call engineer. The engineer opens the construction — Games 1–4, constraints C1–C14, Poseidon, BabyJubjub, adaptive auditor reductions — and has no idea what broke or how to restore service. **FFIEC CAT Domain 4 (External Dependency Management)** and **NCUA Part 748 §II.C** (business continuity) require that any security control supporting member-facing operations have a documented incident response procedure. "Rerun the circuit" is not a procedure. The construction is entirely about the proof system; it says nothing about: what to do when proof generation times out, how to degrade gracefully, whether a failed proof should block or allow with alerting, or how to triage a constraint violation.

**Why it works:** The construction is a cryptographic specification, not a deployable system. For a CU CISO, a control with no operational runbook is a control that will fail its **SOC 2 Type II CC9.1** (vendor incident management) evidence requirement and will generate a MRA (Matter Requiring Attention) in the next NCUA examination cycle.

**In-threat-model?** No — the construction must specify a degraded-mode policy (what happens when proof generation fails), a minimum operational runbook, and SLA commitments that the CU can hold a vendor to, or it cannot be deployed in a regulated environment.


## Persona: rfc7662_advocate

*OAuth WG veteran, ten years of production introspection. Every ZK claim is a solution looking for a problem RFC 8693 already solved.*

---

### Attack 1: RFC 8693 `act` Chain + Signed JWT Introspection Is Structural Equivalence

- **Attack:** RFC 8693 §4.4 defines the `act` claim, a nested JSON object that records the full delegation chain. Combined with `draft-ietf-oauth-jwt-introspection-response`, the AS returns a *signed, auditor-verifiable* JWT containing the complete `act` chain. Each hop's scope is embedded as a `scope` claim within the nested `act` object. An auditor receives this signed JWT and can verify monotonic narrowing by comparing adjacent `scope` fields — **without contacting each participant** and **without the AS being in the hot path at audit time**. The construction's §3.1 names the AS as primary adversary, but that argument is only load-bearing if the AS produces the delegation record at all. Under RFC 8693, the token *itself* carries the chain. The AS's signature merely bootstraps trust; the chain is self-contained after issuance.

- **Why it works / fails:** It *works* if the AS is honest. The construction claims the AS is adversarial (§3.1), which is the only escape hatch. But the construction must explicitly state: *what property does a colluding AS gain that an RFC 8693-based system cannot mitigate?* Simply asserting "AS is adversarial" without a concrete distinguishing attack is insufficient. If the AS can forge an `act` chain, it can equally forge the public inputs committed to in the ZK circuit — the trust anchor is equivalent unless the construction shows otherwise.

- **In-threat-model?** **No — construction must address.** §3.3 claims AS-attested introspection is insufficient but does not construct an explicit game where a forging AS succeeds against RFC 8693 + signed JWT introspection yet fails against the ZK circuit. Without that game, the adversary model is asserted, not proven.

---

### Attack 2: RegulatorReveal Mode (C14) Reinstates an AS-Equivalent Adversary

- **Attack:** The construction introduces ElGamal-over-BabyJubjub escrow in constraint C14, where the regulator key holder can decrypt the full participant chain. This is structurally isomorphic to the AS holding session logs in a traditional OAuth deployment. The AS in RFC 8693 also knows the full delegation chain — that is exactly §3.1's stated threat. C14 does not eliminate this threat; it *renames* it. The regulator key holder is a new trust anchor with AS-equivalent power. If that key is compromised (court order, insider, key ceremony failure), every chain ever audited is deanonymized retroactively — identical to AS log subpoena. The construction's §4.3 offers IPA-PLONK/STARK alternatives for the journalist scenario *without* RegulatorReveal, but Scenario A (NCUA examiner) deploys C14 wholesale. An NCUA examiner's systems are high-value government targets. A compromise of the regulator escrow key is operationally equivalent to AS log compromise.

- **Why it works / fails:** It *works* against Scenario A's privacy claims. The construction cannot simultaneously claim "AS is the primary adversary" (§3.1) and introduce a single escrow key with equivalent decryption power (C14) without a formal threat distinction. The distinction must be structural — e.g., C14 requires active escrow key use per audit request vs. passive AS log access — not just organizational. Threshold escrow (e.g., k-of-n regulator keys) would weaken this attack but is not described.

- **In-threat-model?** **No — construction must address.** The gap is a formal argument distinguishing regulator escrow from AS log access in the adversary model. Absent that argument, §3.1 is self-undermining when C14 is active.

---

### Attack 3: DPoP Sender-Constraint Covers the Liveness Predicate (C2) Without ZK

- **Attack:** RFC 9449 DPoP binds a token to the holder of a specific ephemeral keypair. Applied to the AI agent pipeline scenario: each hop mints a new DPoP-bound token via RFC 8693 exchange, with scope narrowed by AS policy. The DPoP proof-of-possession (`dpop` header) at each hop *cryptographically enforces* that only the legitimate holder of that hop's keypair can use the token. Constraint C2 (`delegateeScope[i] ≠ 0` for real hops) prevents empty-scope bypass in-circuit. But DPoP already prevents this at the protocol level — a token with empty scope issued at hop *i* cannot be exchanged for a valid token at hop *i+1* if the AS enforces non-empty scope in its exchange policy. The construction must name the specific property C2 enforces that DPoP + AS policy cannot enforce, for a non-adversarial-AS deployment. The only escape is again §3.1, which must carry the entire weight of the argument.

- **Why it works / fails:** It *fails* if the AS is adversarial, because a colluding AS can issue DPoP tokens with forged scope. But the construction must also address the **non-adversarial baseline**: for regulated financial institutions (Scenario A), is the AS (a credit union's authorization server) realistically adversarial? If not, DPoP + RFC 8693 is sufficient and the ZK overhead is unjustified operationally.

- **In-threat-model?** **Partial — construction should address.** The claim is broadened ("usable beyond narrow regulatory niches"), which invites deployment contexts where the AS is a trusted institutional party. The construction needs a formal partition: which deployment contexts justify adversarial-AS assumption, and which do not.

---

### Attack 4: LEN-EXTRACT Game 4 Does Not Close Proof-Metadata Side Channels

- **Attack:** Game 4 establishes computational indistinguishability `{π | n=n₀} ≈_c {π | n=n₁}` over proof transcripts, where `n` is chain length and `isReal` bits are private. PLONK proof size is *circuit-determined*, not input-determined — this is correct for the proof object itself. However, the prover's *witness generation time* is linear in the number of real hops (non-dummy hops require actual scope constraint evaluation; dummy hops evaluate `isReal=0` branches). An auditor with side-channel access to prover infrastructure — e.g., observing CPU time, memory allocation, or proof generation latency — can distinguish `n=2` real hops with 8 dummies from `n=8` real hops with 2 dummies, even if both produce identically-sized PLONK proofs. In the journalist/whistleblower scenario (Scenario B), the prover is likely the journalist's own machine or a trusted compute node — not a hardened ZK coprocessor. Timing oracles are realistic. This is not addressed in Game 4's security argument, which treats `π` as the only adversary-observable value.

- **Why it works / fails:** The attack *works* against a side-channel capable auditor in Scenario B. The construction explicitly uses Scenario B to argue the journalist case (§4.3), where the auditor is explicitly *untrusted*. The fix requires either constant-time witness generation for all dummy/real branches (expensive), or a trusted execution environment for proving (introduces new trust assumptions), or acknowledgment that LEN-EXTRACT only holds in the random-oracle model against transcript-only adversaries.

- **In-threat-model?** **No — construction must address.** The Game 4 security claim (`≈_c` over proofs) is incomplete without specifying the adversary's observable surface. A transcript-only adversary is understated for Scenario B, where the auditor may have persistent access to the proving environment.


## Persona: spiffe_engineer

### Attack 1: Wrong Layer — Extend the SPIFFE Attestor Interface, Don't Rebuild

- **Attack:** SPIFFE's attestor model is a plugin interface: `NodeAttestor` and `WorkloadAttestor` are Go interfaces that can be implemented by third parties. A ZK attestor plugin that takes a scope commitment and produces a narrowing proof as part of SVID issuance would deliver everything the construction claims — without a new protocol. The construction (§3.1, §3.3) argues the AS is adversarial and that AS-attested introspection is insufficient. But SPIFFE's attestation is not AS-rooted: it is hardware-rooted (TPM, AWS Instance Identity Document, GCP GCE attestation). The SPIRE agent independently attests — the Authorization Server never sees the raw attestation material. §3.3's argument for insufficiency must engage with node attestation specifically, not with generic AS introspection.

- **Why it works / why it fails:** Works because the construction does not cite SPIFFE's node attestation architecture at all. It argues against a strawman AS-rooted model. Fails if the construction can show that scope-narrowing semantics (monotonic reduction over ordered lattices of permissions) cannot be expressed as SVID extensions — but that gap is never argued.

- **In-threat-model?** No — the construction must address why a ZK attestor plugin to SPIRE is insufficient before claiming a new protocol is needed.

---

### Attack 2: WIMSE Token Exchange Already Owns the Selective-Disclosure Scope

- **Attack:** `draft-ietf-wimse-arch` (currently in IETF WIMSE WG) defines *context tokens* — tokens exchanged at each workload-to-workload hop that carry selectively disclosed claims from the originating principal. Section 4 of the WIMSE architecture draft explicitly scopes "on-behalf-of" delegation chains with monotonic claim reduction. The construction's core claim — "an auditor verifies that a delegation chain narrowed monotonically without reconstructing intermediate scopes or participants" — is precisely the selective disclosure + audit trail property that WIMSE token exchange is designed to provide. Constraint C2 (`delegateeScope[i] ≠ 0`) is a liveness invariant; WIMSE achieves the same via token exchange profiles that enforce `aud` and `scope` reduction at each hop. The construction's gap-to-close section mentions "cross-org agent handoff" — which is exactly WIMSE federation with SPIFFE trust domain federation.

- **Why it works / why it fails:** The attack is strong because the construction never cites WIMSE at all. The construction's ZK layer would need to demonstrate a property that WIMSE token exchange logs *cannot* provide even with selective disclosure — specifically, that the *count* of hops, the *existence* of participants, and the *values* of intermediate scopes must all be hidden simultaneously from the auditor. WIMSE can hide claim values via SD-JWT, but cannot hide the hop graph structure from a logging infrastructure.

- **In-threat-model?** Partially. If the threat model requires hiding *graph topology* (number of hops, existence of participants) from auditors — which Scenario B (journalist/source) requires — then WIMSE is insufficient and the construction addresses a genuine gap. But the construction must explicitly state this and show that Game 4's LEN-EXTRACT security holds when auditors observe token exchange logs, not just ZK proofs.

---

### Attack 3: Dummy-Hop Indistinguishability Introduces Phantom Workloads

- **Attack:** Game 4 (LEN-EXTRACT) proves `{π | n=n₀} ≈_c {π | n=n₁}` via PLONK ZK over private `isReal` bits. In a SPIFFE deployment, every node in a delegation chain must have a valid SVID issued by SPIRE against a registered workload entry. A dummy hop (`isReal=false`) that is computationally indistinguishable from a real hop is a **phantom workload** — it appears in the proof but has no corresponding entry in the SPIRE workload registry. This creates two concrete problems: (1) An attacker controlling the prover can pad chains with phantom hops to obscure the true delegation depth, defeating the monotonic narrowing guarantee without violating constraint C2 (since `delegateeScope[i] ≠ 0` does not require the workload to *exist*). (2) The auditor has no way to bind a proof position to a live workload identity — the ZK proof proves scope narrowing over *committed* identities, but nothing proves those commitments correspond to real, running workloads at proof time.

- **Why it works / why it fails:** The construction's C2 constraint closes the empty-scope bypass but does not require binding hop commitments to externally verifiable workload identities (SVIDs, JWKs, or DNS-backed endpoints). The attack would fail if the construction required each hop's commitment to include a SVID fingerprint as a public input — but it does not, and adding this requirement would break Scenario B's participant-hiding property.

- **In-threat-model?** Yes — this is a direct construction gap. The phantom-workload attack lets an adversarial prover satisfy all circuit constraints while fabricating intermediate delegation hops. The construction must either (a) bind commitments to verifiable workload identities (breaking Scenario B), or (b) prove that phantom hops cannot expand scope even if injected (which requires an argument not present in the current Game 4 reduction).

---

### Attack 4: RegulatorReveal Escrow Is Incompatible with the Journalist Scenario's Actual Threat Model

- **Attack:** Scenario A deploys constraint C14 (ElGamal-over-BabyJubjub escrow) for NCUA examiner access. Scenario B explicitly omits C14 for the journalist/source chain. But without C14, the auditor in Scenario B has no mechanism to distinguish a legitimate journalist chain from an adversary using dummy hops (Attack 3 above) to inject phantom intermediaries. The construction's §4.3 IPA-PLONK/STARK alternative removes the KZG SRS trusted setup concern (Assumption A5) but does not resolve this fundamental tension. More critically: in SPIFFE's trust domain federation, cross-org identity portability relies on a federated bundle endpoint — a public, auditable list of trust anchors. The journalist scenario requires that intermediate nodes be hidden from auditors, but SPIFFE federation requires that trust anchors be published. The construction's "cross-org agent handoff" scenario (gap-to-close) inherits this tension and does not resolve it — you cannot simultaneously claim SPIFFE-compatible cross-org identity *and* auditor-opaque intermediate participants.

- **Why it works / why it fails:** The attack exposes a structural incompatibility: the construction's two scenarios require contradictory trust anchor properties. Scenario A needs a regulator-visible escrow; Scenario B needs trust-anchor opacity. The construction treats these as mode-selectable, but the underlying proof system (shared PLONK constraint system, shared Poseidon hash) does not have separate security proofs for each mode. Game 2's adaptive auditor reduction is proved over k proofs but does not distinguish between Scenario A and Scenario B proof distributions — an adaptive auditor who submits a mix of both scenario types is not addressed.

- **In-threat-model?** Yes — the construction must provide separate security proofs for each deployment scenario, or prove that the shared circuit satisfies both security properties simultaneously (which would require a new composition theorem not present in the current construction).
