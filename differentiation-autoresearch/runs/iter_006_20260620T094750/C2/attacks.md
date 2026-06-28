# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The blindingSalt lifecycle is a new operational hazard you're calling a security feature

- **Attack:** I read §3.1. You introduced a 3-tier storage hierarchy (HSM > keychain > encrypted file), voluntary rotation, and "no AS recovery, optional Shamir" for `blindingSalt`. My enterprise customer's CISO is going to ask: "Who do we call at 2am when the keychain is wiped during an MDM re-enrollment and every agent authorization in production breaks?" Auth0 and WorkOS handle key material server-side with SLAs, runbooks, and on-call rotation. You handed that operational burden to the operator and called it a privacy guarantee. For a credit union with 3 engineers, this is a support ticket that never closes.
- **Why it works:** The construction's §3.1 MUST NOT rules are security-correct but operationally unforgiving. "No AS recovery" is the right cryptographic choice for unlinkability but means there is no break-glass path. Any outage caused by lost `blindingSalt` is unrecoverable by design. Auth0 absorbs that risk class.
- **In-threat-model?** No — the construction must address the break-glass gap. Suggest at minimum: a "delegated recovery" appendix showing how a Shamir-split `blindingSalt` can be held by the operator's own escrow parties (not the AS), so recovery exists without re-linking to the AS.

---

### Attack 2: The core claim is literally marked unproven in the candidate's own gap field

- **Attack:** Your candidate card says "Needs formal security definition (IND-UNL-AS game)" as the gap to close — and current\_strength is 9, not 10, precisely because of this. But the claim says "cryptographically unlinkable." That's a math word. If the IND-UNL-AS game isn't defined and no reduction exists, the claim is marketing copy, not a theorem. In a competitive evaluation, my legal team can ask Auth0 to produce RFC 6749 and its 14 years of academic citations. What do you produce? A candidate card that self-reports "no formal proof yet"?
- **Why it works:** The construction is internally honest — the gap is called out. But in a vendor bakeoff, that honesty becomes a liability. Procurement scorecards treat "unproven formal claim" the same as "no claim." The blindingSalt change is a meaningful engineering improvement but it is not a security proof.
- **In-threat-model?** No — the construction must close this before claiming strength ≥ 9. The IND-UNL-AS game needs to be written out: define A's view, define the challenge, write the reduction from `blindingSalt` PRF uniformity. Until then the claim is aspirational.

---

### Attack 3: Timing side channels make cryptographic unlinkability irrelevant to a colluding AS+RS

- **Attack:** §7's SECU scenario walks through why `blindingSalt` blocks *cryptographic* correlation. But the candidate's own gap field calls out "treatment of side channels (timing, nonce freshness)" as unaddressed. Here's the practical attack: a colluding AS and RS don't need to link nullifiers. They observe that Agent X always proves to RS-A between 09:00–09:05 UTC and proves to RS-B between 09:05–09:08 UTC. The inter-arrival time distribution is a fingerprint. Cloudflare Access routes all traffic through their global anycast network, which provides timing obfuscation for free as a side effect of their infrastructure. You have no equivalent. For the healthcare referral network scenario specifically — the referral *pattern* (not the identity) is the sensitive signal, and timing analysis recovers it even with perfect nullifier separation.
- **Why it works:** The construction closes the cryptographic correlation gap but leaves the traffic-analysis gap completely open. The two scenarios listed (cross-CU member agent, healthcare referral network) are exactly the use cases where an adversarial AS has out-of-band timing data. The 15,943-constraint proof doesn't help when the proof *submission time* is the leaky signal.
- **In-threat-model?** No — the construction must either scope the threat model to exclude timing adversaries (and justify why that's acceptable) or add a batching/mixing layer to the submission protocol. Ignoring it while listing healthcare referral networks as a target scenario is an unforced error.

---

### Attack 4: Your threat model requires enterprises to assume their AS is hostile — which is the opposite of why they buy from Auth0

- **Attack:** §3 explicitly grants adversary A the `operatorSecret` to model the "operator = AS" case. That's the right cryptographic move. But here's the GTM problem: I sell WorkOS by saying "we are your trusted auth plane." You sell Bolyra by saying "assume your auth plane is adversarial." These are contradictory trust propositions. A credit union's procurement committee is going to read §3 and ask: "Wait — the protocol is designed for when the identity provider is corrupt? Are you telling us the AS might be logging our agents' cross-merchant activity?" That's a headline risk, not a differentiator. No enterprise wants to explain to their board that they adopted a ZK protocol *because* they don't trust their identity provider.
- **Why it works:** The unlinkability claim is only valuable when the AS is actually adversarial. But enterprises self-select for vendors they trust. The construction solves a problem that marketing cannot name without creating a different problem. The §3.1 threat model is technically rigorous and commercially un-sayable.
- **In-threat-model?** Partially. The cryptography survives, but the *positioning* doesn't. The construction needs a reframe: the value isn't "we protect you from your AS" — it's "we give your members cryptographic proof you never built a cross-merchant graph, even though you could have." That's a compliance-and-trust claim, not a threat claim. The credit union CISO can use it in a member disclosure. That's sellable. The current framing is not.


## Persona: cryptographer

---

### Attack 1: `credCommitment` as a Stable Cross-Scope Correlator

- **Attack:** The adversary AS issued the credential and therefore knows `credCommitment` (it is a commitment to data the AS generated or certified). The new derivation `agentSecret = Poseidon2(credCommitment, blindingSalt)` does not help if `credCommitment` ever appears as a **public** circuit output or is inferrable from the proof transcript. The circuit has three public outputs: `humanMerkleRoot`, `nullifierHash`, `nonceBinding` (per §1, preserved verbatim). But the AgentPolicy circuit presumably also exposes a `credCommitmentHash` or binds the credential on-chain so the verifier can check it. If any public wire is deterministically derived from `credCommitment` without per-scope randomness, the AS can index all proof transcripts by that wire and build the exact traffic graph the claim forbids.

- **Why it works:** The construction closes the gap on `agentSecret` derivation (§2) but does not state whether `credCommitment` itself is masked in any public output. §7's SECU scenario says "AS knows `credCommitment`" and then claims `blindingSalt` blocks correlation — but that only holds for `agentSecret`. It says nothing about whether `credCommitment` is a direct public output of AgentPolicy.

- **In-threat-model?** **No — construction must address.** The proof must either: (a) commit to `credCommitment` under a per-scope blinding factor before it reaches a public wire, or (b) explicitly prove that no public output is a deterministic function of `credCommitment` alone. Neither is stated.

---

### Attack 2: The IND-UNL-AS Game Is Undefined — Three Different Games, Three Different Reductions

- **Attack:** The candidate itself lists "formal security definition (IND-UNL-AS game)" as a gap not yet closed. The adversary distinguishes among three game instantiations that require distinct reductions:
  1. **Passive AS** — A sees proof transcripts but cannot inject or choose scopes. Unlinkability reduces to PRF security of Poseidon2 in the ROM.
  2. **Active AS** — A can choose `scope_id` and nonces after seeing some proofs. Now the reduction must handle an adaptive, chosen-message adversary. PRF security of Poseidon2 alone is insufficient; you need simulation-extractability or at minimum non-adaptive ZK.
  3. **Colluding AS+RS** — A pools the AS transcript with the RS audit log. The RS sees `nullifierHash` keyed on `scope_id`; the AS sees the submission metadata. Under this coalition the adversary may be able to enumerate all `(agent, scope)` pairs and reconstruct the graph even without breaking Poseidon2, purely from metadata.

  The construction's §3.1 threat model says "A granted `operatorSecret`" (operator = AS case) and claims §4's Hybrid 0 covers this. But Hybrid 0 only addresses `agentSecret` indistinguishability — it is not a game reduction for **unlinkability across sessions** under an adaptive adversary.

- **Why it works:** Without a game definition with an explicit winning condition ("A wins if it outputs a bit b such that …") and a proof that any PPT A wins with probability ≤ ½ + negl(λ), the unlinkability claim is a heuristic argument. The hybrid sequence in §4 shows credential indistinguishability, not cross-scope session unlinkability. These are different security properties.

- **In-threat-model?** **No — construction must address.** Provide a concrete IND-UNL-AS game. State which of the three AS-power levels is in scope. Sketch the reduction explicitly.

---

### Attack 3: PLONK Universal CRS — Subverted Setup Breaks Zero-Knowledge, Not Just Soundness

- **Attack:** §6 confirms the construction uses PLONK for AgentPolicy and Delegation circuits. PLONK's security rests on a universal structured reference string (SRS) generated in a multi-party ceremony. A subverted SRS (toxic waste retained by any single ceremony participant) does two things: (a) breaks **soundness** — a malicious prover can prove false statements; (b) breaks **zero-knowledge** — the setup authority holding the trapdoor can extract private inputs from any valid proof, including `blindingSalt` and `agentSecret`. The construction's §3.1 lifecycle section discusses `blindingSalt` storage (HSM > keychain > encrypted file) but entirely omits the SRS trust model. If the ceremony has a single honest participant, the ZK guarantee is information-theoretic; if the ceremony is a black-box service, it is not.

- **Why it works:** The construction added ~854 constraints and a `blindingSalt` lifecycle in §3, but the `blindingSalt` is private input to a PLONK circuit. Under a trapdoor-holding extractor, all private inputs to every proof are recoverable. The five MUST NOT rules in §3.1 are operational policy; they cannot compensate for a broken setup.

- **In-threat-model?** **No — construction must address.** Either (a) cite the specific PLONK ceremony used and its transcript/verifiability guarantees, (b) adopt a transparent SRS (STARK-friendly or Halo2-style IPA) that eliminates setup trust, or (c) explicitly scope the threat model to "honest setup" and label the subverted-setup case as out of scope with justification.

---

### Attack 4: `blindingSalt` Lifecycle Policy ≠ Cryptographic Guarantee — Unenforceable MUST NOT Rules

- **Attack:** §3.1 introduces five `MUST NOT` rules to protect `blindingSalt`: it must not be transmitted to AS, stored server-side, recoverable by AS, logged in plaintext, or derived from AS-supplied entropy. These are **policy** constraints with no cryptographic enforcement mechanism. In the cross-credit-union scenario (§ candidate, first scenario), the agent runtime may execute on AS-controlled infrastructure (a credit union's cloud). The AS can instrument the runtime to exfiltrate `blindingSalt` before it is consumed by the Poseidon2 gadget. The circuit proves correct derivation of `agentSecret` from `(credCommitment, blindingSalt)` but cannot attest that `blindingSalt` was generated on AS-excluded hardware. There is no attestation chain from a trusted execution environment to the circuit public output.

- **Why it works:** The construction correctly identifies that `operatorSecret`-based derivation was fatal (§4, Hybrid 1) and replaces it with client-generated randomness. But "client-generated" is an assumption about the deployment environment, not a proven property of the protocol. A MUST NOT rule that can be violated by a sufficiently privileged AS collapses the security argument to "trust the client device," which is exactly the threat model the construction is trying to escape.

- **In-threat-model?** **Partially.** The claim is "adversarial AS that tries to correlate" — if AS controls the agent runtime, exfiltrating `blindingSalt` is trivial. The construction must either: (a) require TEE/SGX attestation and bind the circuit public output to the TEE quote, making exfiltration detectable, or (b) explicitly exclude "AS-controlled runtime" from the threat model and state this limitation. The current §3.1 does neither — it relies on five policy rules that the adversary can simply ignore.


## Persona: cu_ciso

---

### Attack 1: BSA/AML Monitoring Contradiction

- **Attack:** The construction's headline scenario is "CU-as-AS must not see member merchant graph." I hand my BSA officer this sentence and she hands it back unsigned. Under 31 U.S.C. §5318(g) and NCUA's own BSA exam procedures, I am *required* to aggregate member transaction patterns to file SARs. The unlinkability guarantee — specifically the cross-RS nullifier separation in §7's SECU scenario — cryptographically prevents the AS (me, the credit union) from correlating which Resource Servers a member's agent touches. That is precisely the behavioral graph BSA monitoring needs. The construction doesn't mention BSA, FinCEN, or SAR obligations anywhere.

- **Why it works / why it fails:** The construction survives the *cryptographic* claim. It fails the *regulatory product-market fit* claim. A feature marketed as "CU-as-AS cannot de-anonymize member merchant graph" is, from my examiner's desk, a *deliberately engineered BSA evasion mechanism*. Even if I privately believe the cryptography is sound, I cannot deploy a system whose design documents explicitly state the operator cannot see cross-RS activity. My next NCUA examination will surface these documents.

- **In-threat-model?** **No.** The construction must address the BSA/AML carve-out: either scope unlinkability to *third-party* AS actors (not the CU itself), or specify a compliance-mode nullifier registry visible only to the CU's BSA team under dual-control access logging. The current §3 threat model grants A the `operatorSecret` but never distinguishes the regulatory-mandatory visibility case from the adversarial correlation case.

---

### Attack 2: Member Key Custody on Untrusted Devices (GLBA §314.4(c))

- **Attack:** §3.1 lists the `blindingSalt` storage hierarchy: HSM → keychain → encrypted file. For a member-facing agent deployment, HSM means the member's HSM, which means YubiKey at best, browser `localStorage` at worst. The GLBA Safeguards Rule (16 CFR §314.4(c)) requires me to implement access controls "commensurate with the sensitivity of the information." My members' devices are not commensurate. The five MUST NOT rules — notably "MUST NOT transmit blindingSalt to AS" — mean I cannot escrow the key server-side either. So when a member's phone is stolen and wiped, the blinding salt is gone. The construction says "no AS recovery" and marks Shamir as optional. For member-facing systems, recovery is not optional; it is a member service obligation and a CFPB complaint vector.

- **Why it works / why it fails:** The construction correctly identifies that AS-held recovery defeats unlinkability (Hybrid 1 collapse). But it offers no alternative recovery path that satisfies both the unlinkability guarantee and the operational reality that members lose phones. The gap is structural: the construction optimizes for the cryptographic property and treats operational recovery as someone else's problem.

- **In-threat-model?** **No.** The construction must specify at minimum one recovery architecture that does not require AS visibility. Options exist (threshold encryption with a member-controlled recovery shard, hardware attestation-bound keys) but §3.1 leaves this as "optional Shamir" without a concrete deployment recommendation. My vendor management policy requires documented recovery procedures before production approval.

---

### Attack 3: Incident Response Blindspot (NCUA Part 748, Appendix B)

- **Attack:** NCUA Part 748 Appendix B requires a written incident response program that includes "procedures for notifying affected members." If a member's agent credential is compromised — `credCommitment` leaked, or the agent model is trojaned — I need to identify *which Resource Servers that agent contacted*. The construction's unlinkability guarantee means I cannot reconstruct the agent's RS access graph post-incident even with full cooperation of all RS operators, because each RS sees a different nullifier. The examiner will ask: "Show me the audit trail for this incident." The answer under the current construction is: "There is none by design."

- **Why it works / why it fails:** The construction achieves its cryptographic goal. The NCUA incident response requirement is not a cryptographic goal — it is a documentation and traceability goal. These are in direct tension. The construction's §4 Hybrid analysis correctly shows that the AS cannot correlate; it does not address that the *member themselves* or a *court-ordered forensic examiner* might need to reconstruct the access graph.

- **In-threat-model?** **No.** The construction needs a selective disclosure or audit-log design: an optional, member-controlled audit escrow that allows the member (and only the member, via their blinding salt) to reconstruct their own RS contact history and share it with authorized investigators. Without this, the construction is incompatible with my incident response obligations and with discovery obligations in fraud litigation.

---

### Attack 4: Third-Party Risk Examination — On-Chain Registry SLA and Vendor Qualification

- **Attack:** The gap-to-close mentions an "on-chain registry." Under NCUA's third-party risk supervisory guidance (Letter to Credit Unions 07-CU-13, updated 2020) and FFIEC IT Examination Handbook (Outsourcing Technology Services), any critical service provider must furnish a SOC 2 Type II report or equivalent. A smart contract on Base Sepolia (or mainnet) has no SLA document, no incident escalation path, no SOC 2, and no vendor representative who answers my call at 2am when the Hardhat verifier mismatch in `§6` causes a false-reject on a member transaction. The construction notes 15,943 constraints and a PLONK target under 3 seconds — but says nothing about what happens when Base has a sequencer outage. My core processor (Fiserv/FiServ/Jack Henry) publishes 99.95% uptime SLAs with contractual penalties. The on-chain registry does not.

- **Why it works / why it fails:** The construction is technically coherent but institutionally undeployable under my vendor management policy until the on-chain component is either (a) hosted behind a permissioned sidechain with a contractual SLA from an entity I can put in my vendor register, or (b) designed so that the on-chain registry is non-critical-path (i.e., verification degrades gracefully to cached state during outage). Neither option is addressed in the current construction.

- **In-threat-model?** **No.** The construction is scoped to cryptographic security, not operational resilience. The on-chain registry's availability model, its upgrade governance (who can push a new verifier contract, and what is the change control process?), and the absence of any contractual counterparty make this a Category 3 vendor risk under my policy — requiring board-level approval before deployment. The construction should specify a degraded-mode protocol and identify the contractual entity responsible for registry availability.


## Persona: rfc7662\_advocate

---

### Attack 1: Threat Model Inflation — The AS Adversary Is Out-of-Scope for Every OAuth Protocol, So the Comparison Is a Category Error

- **Attack:** RFC 6819 §2.1 and the OAuth Security BCP (RFC 9700 §2.1) explicitly define the AS as a *trusted* entity. The construction's §3 grants the AS adversarial status — it "tries to correlate per-agent traffic graphs." I accept that claim on its face, but then the author cannot benchmark against RFC 7662 and claim superiority, because RFC 7662 was *never designed* to resist an adversarial AS. No OAuth protocol is. Claiming ZK wins over RFC 7662 on AS-opacity is like claiming HTTPS beats UDP on encryption: the comparison is undefined because UDP never entered that contest.

  Sub-attack: the cross-CU scenario ("CU-as-AS must not see member merchant graph") is actually a *federated identity* problem, not a single-AS problem. OpenID Federation (draft-ietf-connect-federation-35) with sector-based pairwise subject identifiers lets a federation hub issue PPID-scoped credentials such that no individual CU-AS ever holds the full traffic graph. No ZK required. Has the construction addressed the federation-layer alternative?

- **Why it works / fails against the construction:** The construction survives if it can formally state its threat model as a strict *superset* of RFC 7662's threat model and prove ZK is necessary (not merely sufficient) for the new threats. It currently asserts the AS is adversarial (§3) but does not prove RFC 7662 + OIDC Federation cannot close the same gap.

- **In-threat-model?** Partially. The construction must either (a) add a "why OIDC Federation + PPIDs fail" subsection to §3 or (b) narrow the claim to "ZK is the *minimal* mechanism for AS-opacity," not merely "ZK achieves what RFC 7662 cannot."

---

### Attack 2: `credCommitment` Is a Persistent Linkability Anchor — The Fix Moved the Problem, Did Not Eliminate It

- **Attack:** The §2 change reads: `agentSecret = Poseidon2(credCommitment, blindingSalt)`. The key question is the *visibility* of `credCommitment` in the circuit's public signal vector. There are only two possibilities:

  **(a) `credCommitment` is a public input** (needed for AS/on-chain policy — "verify this credential is enrolled"): then the AS observes `credCommitment` across every proof interaction at every RS. Each scope yields a different nullifier, yes — but the AS correlates on the credential commitment, not the nullifier. `credCommitment` is a stable, AS-visible identifier functionally equivalent to OAuth's `sub`. The blindingSalt closes the `operatorSecret` vector (correctly identified in §4 Hybrid 1) but leaves a *new* persistent anchor.

  **(b) `credCommitment` is a private input**: the AS cannot verify credential validity without seeing it, which breaks the authorization semantic entirely. The AS cannot distinguish a valid credential from a forged one.

  Neither branch is clean. The old construction had `operatorSecret` as the fatal correlation anchor; the new one potentially substitutes `credCommitment`. If `credCommitment` is computed from public on-chain data (an enrollment Merkle root, say), it is trivially recoverable by the AS even if marked "private" in the circuit.

- **Why it works / fails against the construction:** The construction's §4 argues "A knowing `credCommitment` is irrelevant when `blindingSalt` is the PRF key." True for the *nullifier* derivation. But irrelevant does not mean unobservable — if `credCommitment` appears in the statement (public inputs), the AS correlates on the statement, not the witness. The §4 argument is correct about *nullifier* correlation but silent on *statement* correlation.

- **In-threat-model?** Yes — this is in the construction's own threat model (adversarial AS trying to build a traffic graph). The construction must either (a) prove `credCommitment` is not in the public signal vector and specify what the AS *does* see in its place, or (b) introduce per-scope commitment blinding (a second salting layer at the statement level, not just the witness level).

---

### Attack 3: DPoP + Per-RS Ephemeral Keys Covers RS-Side Unlinkability Completely — Isolate What ZK Actually Adds

- **Attack:** RFC 9449 §4.2 permits per-RS DPoP key registration. Protocol: the agent generates a fresh DPoP keypair `(sk_i, pk_i)` for each RS at first contact and binds all tokens for that RS to `pk_i`. The AS issues RS-specific access tokens bound to `pk_i`. RS_1 sees `pk_1`, RS_2 sees `pk_2` — the two are cryptographically independent. No RS can correlate the agent across RSes. This is production-deployable today with zero proof overhead.

  The only entity that correlates is the AS, because the AS issued both tokens to the same `client_id`. But — see Attack 1 — the AS is the trusted party in every OAuth threat model. If the construction's response is "but we distrust the AS," I accept that. Then please state *explicitly*: "The unique property ZK provides beyond DPoP+PPID is AS-opacity." Section 2 and the current claim statement do not say this. They say "even under adversarial AS" but bury it in a parenthetical.

  Demand: name one concrete property the construction provides that DPoP+per-RS ephemeral keys does not, *without* invoking an adversarial AS.

- **Why it works / fails against the construction:** If the construction's *only* unique claim is AS-opacity, it survives but its scope narrows dramatically. Most enterprise deployments do not operate under an adversarial AS. The construction should stratify: "For RS-side unlinkability, DPoP suffices. For AS-side unlinkability — our novel threat — ZK is necessary." Absent this stratification, a practitioner rightly asks why they'd take on ZK proving overhead when DPoP solves the problem they actually have.

- **In-threat-model?** No — this is a *framing gap*, not a construction break. The construction does not break under this attack; it just fails to clearly delineate the threat DPoP cannot address. The fix is editorial: §1 or §3 must explicitly state the DPoP baseline and the residual gap ZK closes.

---

### Attack 4: AS-Chosen Nonces Create a Timing Correlation Side Channel That blindingSalt Does Not Close

- **Attack:** The construction's §2 includes `nonceBinding` as a public output committing the proof to a fresh session nonce. In any standard OAuth/OIDC flow, the AS *chooses* the nonce (PKCE `code_challenge`, OIDC `nonce`, or DPoP nonce per RFC 9449 §8). If the AS issues nonces, the AS has a nonce-issuance log:

  ```
  14:03:21.004  issued nonce N₁ for RS_1 challenge
  14:03:21.119  issued nonce N₂ for RS_2 challenge
  ```

  Even if the resulting proofs carry different nullifiers and the blindingSalt prevents PRF correlation, the AS correlates proof submissions by nonce-issuance time. Two proof verifications arriving within milliseconds of nonce pairs `(N₁, N₂)` issued to the same authenticated session are trivially attributable to the same agent — no cryptographic analysis needed.

  The gap section explicitly flags "treatment of side channels (timing, nonce freshness)" as unaddressed. The §7 SECU scenario walks through the blindingSalt blocking `operatorSecret` correlation but does not walk through the nonce-timing vector at all.

  RFC 7662 has exactly the same timing exposure — but that is irrelevant here, because the construction claims resistance to "adversarial AS trying to correlate per-agent traffic graphs." Timing correlation *is* graph correlation.

- **Why it works / fails against the construction:** The construction does not survive this attack as stated. The blindingSalt fix correctly closes the PRF correlation vector (§4 Hybrid 0/1), but the nonce-issuance timing vector is an independent channel the fix does not touch. A well-resourced adversarial AS does not need to break the ZK proof — it just reads its own nonce log.

  Mitigations exist (client-generated nonces with AS-side freshness verification only, blind nonce issuance, or rate-limiting nonce requests to break timing resolution) but none are in the current construction.

- **In-threat-model?** Yes. The construction's own gap section acknowledges this is open. The IND-UNL-AS game (also listed as a gap) must formalize the nonce oracle: does A get to see nonce-issuance timestamps? If yes, the game is trivially won by the adversary under the current construction, making the claimed strength of 9/10 overstated until this vector is closed.


## Persona: spiffe_engineer

---

### Attack 1: SVIDs with Short Rotation Already Give You Unlinkability-by-Epoch

**Attack:** SPIRE issues X.509 SVIDs with configurable TTLs down to 5 minutes. Each issuance is a fresh cert with a fresh serial number. A resource server in trust-domain B that federates with trust-domain A sees a valid SVID but has no persistent identifier across rotation windows—linkage across RS instances collapses to "within the same rotation epoch," which is an operational knob, not a cryptographic property. The IND-UNL-AS game the construction promises in its gap description is therefore bounded by the SVID TTL in the SPIFFE model with zero added ZK machinery.

**Why it works / why it fails:** The construction never specifies a session duration model relative to `blindingSalt` validity. If an agent uses the same `credCommitment + blindingSalt` pair across multiple RS calls inside a single long-lived session (hours, not minutes), a colluding AS+RS can correlate the full graph within that window regardless of ZK unlinkability properties. The construction's §3.1 says rotation is "voluntary, no on-chain tx" — that's weaker than SPIRE's forced rotation, not stronger.

**In-threat-model?** No — construction must address maximum `blindingSalt` session lifetime and what unlinkability claim survives within a single epoch.

---

### Attack 2: `credCommitment` Is a Static Correlation Handle the AS Already Holds

**Attack:** The revised derivation is `agentSecret = Poseidon2(credCommitment, blindingSalt)`. The `credCommitment` is issued by the operator — who is explicitly granted the role of adversarial AS in §3's revised threat model. The AS does not need to see `blindingSalt` to correlate: it issued `credCommitment` and knows which agent it belongs to. When the colluding AS+RS pair observe ZK proofs at two different RS endpoints, they cannot invert the Poseidon2 to recover `blindingSalt` — but they don't need to. The AS logs "I issued `credCommitment = 0xABCD...` to agent X." The RS logs "I received a proof that committed to `credCommitment` in the public input." If `credCommitment` appears as a **public circuit output** at both RS endpoints, deanonymization is trivial.

**Why it works / fails:** The construction's §4 ("Hybrid 0") argues A knowing `credCommitment` is irrelevant "when `blindingSalt` is the PRF key." That argument is correct for unlinking `agentSecret` values — but it says nothing about whether `credCommitment` itself is a public output visible to the RS. If the verifier needs `credCommitment` on-chain to check revocation (which a production deployment almost certainly does), it's a public correlation handle. The construction does not state whether `credCommitment` is a public or private circuit input across both proofs.

**In-threat-model?** No — construction must explicitly state `credCommitment` is a **private** input to the RS-facing proof and describe how the RS validates revocation status without exposing it.

---

### Attack 3: WIMSE Token Exchange With a ZK Attestor Plug-in Is Strictly Dominating

**Attack:** `draft-ietf-wimse-arch` §5 defines a workload-to-workload token exchange where a Workload Identity Token (WIT) is exchanged for a scoped, resource-bound token via an AS. Section 6 of the WIMSE architecture draft explicitly leaves the attestation mechanism as a plug-in point. A ZK attestor that binds `(credCommitment, blindingSalt, scopeHash)` into a WIT extension field would give Bolyra's unlinkability property while inheriting WIMSE's federation model, IANA-registered media types, IETF process, and the interop story every enterprise buyer demands. The construction in §1 is instead a parallel wire format that will require every RS to integrate a custom verifier.

**Why it works / fails:** The construction makes no mention of WIMSE interoperability. The SECU scenario in §7 ("operator = AS") is exactly the WIMSE principal hierarchy — `operator → agent → RS`. The construction is shipping a vertically integrated protocol where a horizontal extension to WIMSE would deliver the same cryptographic property with a dramatically lower adoption barrier.

**In-threat-model?** No — this is a protocol-layer positioning gap, not a cryptographic one. The construction should either justify why WIMSE extension is insufficient or explicitly scope itself as a WIMSE-compatible attestation layer.

---

### Attack 4: `blindingSalt` Storage Requirements Reproduce SPIRE Node Attestation With Worse Guarantees

**Attack:** §3.1 specifies a three-tier `blindingSalt` storage hierarchy: HSM > OS keychain > encrypted file, plus five MUST NOT rules (no AS recovery, no transmission, etc.). This is functionally identical to SPIRE's node attestation private key management — the SPIRE agent holds a node-attested private key in the TPM/HSM, never transmits it, and rotates it on a defined schedule. The difference: SPIRE's HSM binding is enforced by the node attestation protocol itself (join token + SVID issuance is cryptographically tied to hardware). The construction's MUST NOT rules are policy statements with no cryptographic enforcement. An operator who stores `blindingSalt` in an "encrypted file" (tier 3) with a passphrase the AS can compel under subpoena has provided no unlinkability guarantee — and the construction acknowledges "no AS recovery" as a MUST NOT, but offers no mechanism to detect or prevent violation.

**Why it works / fails:** The §3.1 lifecycle section describes aspirational key hygiene, not a protocol enforcement mechanism. If `blindingSalt` is recoverable by the operator under any threat model (legal, coercion, supply-chain), the IND-UNL-AS game collapses. SPIRE's node attestation at least binds the secret to hardware attestation evidence that a court-order cannot directly extract. The construction needs either: (a) a hardware-binding requirement with attestation evidence in the proof, or (b) an explicit statement that `blindingSalt` compromise is out of scope and unlinkability degrades gracefully to "unlinkable unless HSM is compromised."

**In-threat-model?** No — §3 grants A the `operatorSecret` but is silent on `blindingSalt` compelled-disclosure scenarios. The threat model boundary is incomplete.
