# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

---

### Attack 1: The latency cliff kills the enterprise demo before it begins

- **Attack:** The construction's §6 targets Groth16/rapidsnark at <0.6s and PLONK/snarkjs at <4s. A Senior PM at WorkOS evaluating this against their own stack: our `/token` endpoint is 80ms p99, globally distributed, with no native binary dependency. Now read the construction's §7, step 2: "Alice's agent computes... and generates a `ScopeBlindAuth` proof **locally**." Locally means the native `rapidsnark_prover` binary must be co-located with the agent runtime. In enterprise deployments — AWS Lambda, Fargate, GKE Autopilot — there is no "local." Spinning up a container that bundles a 40MB native prover binary, warm-starts it, and proves in 0.6s is a fundamentally different operational model than calling `/oauth/token`. The construction's §6 lists a proving time *target* but gives no deployment guidance for cloud-native agent runtimes. The snarkjs WASM path (<4s) is the realistic fallback for most operators — and 4s is not a latency budget any enterprise API consumer will accept for an auth handshake.

- **Why it works / why it fails:** The construction's §8 ("Why the baseline cannot match") addresses the *architectural* difference but not the *operational* one. The claim that unlinkability is worth the latency is a cryptographer's argument, not a buyer's argument. No VP of Engineering at a credit union is approving a vendor whose auth latency is 40× higher than the incumbent with zero deployment complexity advantage.

- **In-threat-model?** No. The construction must address: (a) a concrete deployment path for cloud-native agent runtimes that achieves <1s end-to-end, and (b) a buyer-level latency SLA statement, not just circuit-level targets.

---

### Attack 2: Procurement kills this before the technical review starts

- **Attack:** The construction's §7 names Desert Financial Credit Union and CU\*Answers as the primary deployment scenario. Both are NCUA-regulated entities with third-party vendor risk assessment requirements (NCUA Letter 01-CU-20, FFIEC guidance). The procurement checklist for a fintech vendor at a credit union includes: SOC 2 Type II report, proof of cyber liability insurance (typically $5M minimum), a legal entity with audited financials, a named CISO, a disaster recovery plan, and a minimum two-year operating history for critical infrastructure. A solo founder ZK protocol with no audited implementation, no formal security review of the Circom circuits, and no legal entity behind it fails every single line item. WorkOS has SOC 2 Type II. Auth0 (Okta) has SOC 2 Type II, ISO 27001, FedRAMP. The construction's formal security argument in §4 is rigorous cryptography — and completely irrelevant to a credit union's vendor risk officer, who does not read hybrid arguments.

- **Why it works / why it fails:** The construction does not address GTM risk at all. §8 argues "structural impossibility" for OAuth — a technically valid point — but the credit union's procurement team will not compare constructions. They will compare vendor risk profiles. The solo founder can close a pilot, not a production contract.

- **In-threat-model?** No. The construction must address: (a) the path to independent third-party circuit audit (Zellic, Trail of Bits), (b) the legal/entity structure behind the protocol, and (c) a credible enterprise support commitment.

---

### Attack 3: The batch relayer introduces a new trusted party that is formally unmodeled

- **Attack:** §3 ("Threat model") carefully defines what the adversary controls and does not control. The construction then introduces in §3 ("Anti-timing gadget") a **batch relayer** that "collects `ScopeBlindAuth` proofs from multiple agents and submits them in a single on-chain transaction." The relayer is asserted to be unable to link proofs because "each proof's `scopePseudonym` is scope-specific and the `credentialCommitment` is hidden as a private input." This is correct for *cross-scope* correlation — but misses the point of the timing attack. The relayer sees: (a) the IP address or authenticated connection of each proof submitter, (b) the exact submission timestamp within the epoch, and (c) the proof bytes. The relayer cannot compute who is who from the cryptographic outputs — but it does not need to. It sees Alice's agent connect and submit a proof, then 3 seconds later sees a second proof from the same connection. The batching hides this from the AS (Desert Financial), but the relayer *is* a new entity in the trust model that has precisely the timing information the construction claims to eliminate. §7 names CU\*Answers as the batch relayer operator. CU\*Answers is a CUSO — a cooperative owned by the same credit unions it serves. Desert Financial is a CU\*Answers member. The separation between "adversarial AS" and "relayer" collapses in the deployment scenario the construction itself describes.

- **Why it works / why it fails:** The construction's §3 side-channel sub-game bounds timing advantage to `1/m` per epoch for the *on-chain observer*. It does not bound the relayer's advantage, because the relayer is not in the adversary model. The adversary model grants the adversary "network-level observation of proof submission timing" — but the relayer is not a network observer; it is an active participant that receives authenticated proof submissions.

- **In-threat-model?** No. The construction must either: (a) extend the adversary model to include a potentially colluding relayer, and demonstrate that the construction's unlinkability holds against `AS + relayer` collusion; or (b) replace the batch relayer with an oblivious submission mechanism (e.g., anonymous credentials for relay submission, or a mixnet) and model its security separately.

---

### Attack 4: `scopeBlindingSecret` lifecycle is unaddressed — and loss breaks all guarantees

- **Attack:** The entire unlinkability construction pivots on one value: `scopeBlindingSecret`, a 251-bit random scalar "generated once at agent enrollment and stored alongside the agent's credential material" (§5). The construction specifies what it is, where it appears in the circuit, and why it must never reach the AS. It does not specify: (a) where it is stored in a production agent deployment, (b) how it is backed up without creating a recovery path that re-introduces the AS, (c) what happens when it is lost, and (d) how it is rotated if the agent's credential is compromised. Loss of `scopeBlindingSecret` means the agent loses all delegation chains (the chain-linking constraint requires it as a private witness, per §2 `ScopeBlindDelegation` constraint 2) and all pseudonym continuity (`scopePseudonym` is non-recoverable). Rotation requires re-publishing new anchors at every RS the agent has visited — which itself leaks a correlation event (all anchors rotate simultaneously, on-chain, linkable to the same agent enrollment). The only recovery path that avoids this is re-enrollment — which requires the AS. But the construction's key selling point is "the AS is never on the critical path." In practice, `scopeBlindingSecret` is either: stored in a cloud KMS (introducing a new trusted party), stored in agent memory (lost on restart), or derived from a master secret (which makes it recoverable but requires a derivation hierarchy that is unspecified). Stytch's Connected Apps model doesn't have this problem — there is no agent-held secret whose loss is catastrophic and unrecoverable without re-enrollment.

- **Why it works / why it fails:** This is not a cryptographic break — the circuit is sound. It is an engineering and operational break: the construction assumes `scopeBlindingSecret` is reliably persisted and never needs rotation. In any real enterprise deployment, secrets have a lifecycle. The construction's silence on this lifecycle is a buyer-level gap, not an academic one.

- **In-threat-model?** No. The construction must specify: a concrete secret management model for `scopeBlindingSecret` in cloud-native agent runtimes, a rotation protocol that does not leak cross-RS correlation, and a recovery path that does not re-introduce the AS as a trusted party.


## Persona: cryptographer

*Reviewing "Cross-scope unlinkability" (C2) — construction dated 2026-06-20. I accept the IND-UNL-AS game at face value and go looking for what it does not cover.*

---

### Attack 1: POS-PRF-Joint is a non-standard assumption violated by real Poseidon implementations

- **Attack:** The entire four-step hybrid argument (§4) pivots on a single sentence: *"Poseidon instantiations of different arities are modeled as independent random oracles."* This is the POS-PRF-Joint assumption, which says `(Poseidon2(x, sbs), Poseidon4(x, sbs, a₁, a₂))` are jointly pseudorandom when `(a₁, a₂)` are known to the adversary. The adversary exploits the fact that this assumption is *unproven and likely false for the actual Circom implementation.*

  In the Circom ecosystem, `Poseidon2` and `Poseidon4` are both instantiated from the same underlying Poseidon permutation design (Grassi et al., USENIX 2021). Specifically, they use the same MDS strategy and the same round-constant generation with different state widths (t=3 vs. t=5). The published Poseidon paper proves *collision resistance* and *one-wayness* under the algebraic differential attack model — it does **not** prove that evaluations sharing a key position across different state widths produce jointly independent outputs. No IACR publication I am aware of proves POS-PRF-Joint for `(Poseidon_t=3, Poseidon_t=5)` with a shared key.

  In the ROM, the assumption of "independent random oracles for different arities" is the right model only if the two functions are *unrelated constructions*. Since they share the same permutation design, a cryptanalyst who builds a differential path against the shared permutation could potentially correlate `Poseidon2(x, sbs)` and `Poseidon4(x, sbs, a₁, a₂)` in ways that are invisible in the independent-oracle model. The reduction in §4 would then fail even if each PRF were individually secure.

- **Why it matters vs. fails:** The hybrid argument is structured as `|H₀ − H₁| ≤ ε_PRF2` conditional on `scopeBoundDelegationAnchor_A` remaining a real PRF evaluation. The justification is that "the adversary's view of `O_4(scopeId_A, …)` is unchanged and independent of `O_2(scopeId_A)` by the joint PRF assumption." If the joint independence assumption is wrong, the single-point substitution `H₀ → H₁` may not hold: the adversary could use `scopeBoundDelegationAnchor_A` (which still uses `sbs_b`) to distinguish whether `scopePseudonym_A` was a real PRF evaluation or replaced with `r_1`. The entire hybrid collapses to a weaker, unjustified bound.

- **In-threat-model?** No. The construction introduces POS-PRF-Joint as a named assumption (§4.1) but provides no reduction to a standard assumption (e.g., indistinguishability of the Poseidon permutation from a random permutation). Without a published proof or an explicit reduction from a falsifiable assumption, POS-PRF-Joint is marketing dressed as cryptography. **The construction must either (a) prove POS-PRF-Joint from the algebraic structure of the BN254 Poseidon permutation, (b) use a domain-separated PRF (e.g., keyed BLAKE2 or a distinct commitment scheme) that cleanly separates the two functions, or (c) redesign the circuit to eliminate the shared-key-across-arity pattern entirely.**

---

### Attack 2: Groth16 Phase 2 trusted setup is not in the threat model — extraction attack under subverted setup

- **Attack:** §3 lists what the adversary does *not* control: "The agent's local proving environment (trusted execution); The `scopeBlindingSecret` of any agent." But the threat model says nothing about the Groth16 Phase 2 ceremony for the `ScopeBlindAuth` and `ScopeBlindDelegation` circuits. The per-circuit Phase 2 setup is conducted by Bolyra (ZKProva Inc.) — the same organization that operates the AS (credential enrollment). If the Phase 2 ceremony produces a backdoored proving key (toxic waste retained), an adversary with the trapdoor can:

  1. **Forge proofs without a valid witness:** Present a fake `ScopeBlindAuth` proof at any RS with an arbitrary `scopePseudonym` and `scopeBoundDelegationAnchor` — bypassing permission checks entirely.
  2. **Extract `scopeBlindingSecret` from observed proofs:** In Groth16, the proof `(A, B, C)` is computed as a linear combination of the proving key elements weighted by the witness. A trapdoor holder can solve for the witness from the proof and the proving key — including the private input `scopeBlindingSecret`. Armed with Alice's `sbs_Alice`, the adversary runs `Poseidon2(scopeId_j, sbs_Alice)` for all `j` in a candidate RS dictionary and matches against on-chain `scopePseudonym` values: O(N) lookups reconstruct Alice's full merchant graph in milliseconds.

- **Why it matters vs. fails:** The construction does offer PLONK as an alternative (universal setup — "no per-circuit ceremony," §2). But: (a) the KZG commitment scheme underlying PLONK still requires a universal powers-of-tau ceremony — if the SRS is subverted, analogous extraction attacks apply; (b) the production deployment maps are ambiguous — §5 lists "PLONK (agent circuit — universal setup)" as optional, not mandatory; (c) the batch relayer and on-chain verifier cannot distinguish a Groth16 proof generated from a backdoored key from a legitimate one.

  Even under an honest setup assumption, the ceremony infrastructure (MPC participants, transcript publication, verification tools) is not described. For a system whose entire privacy guarantee rests on the secrecy of `scopeBlindingSecret`, the trusted setup is the single point of catastrophic failure.

- **In-threat-model?** No. **The construction must either mandate PLONK with a publicly verifiable universal SRS (Ethereum KZG, Zcash Sapling ceremony) or commit to a transparent SNARK (STARK, FRI-based) for the agent circuits. If Groth16 is retained, a multi-party Phase 2 ceremony with an independently verified transcript is required, and the threat model must explicitly treat ceremony subversion.**

---

### Attack 3: Delegation blinding secret transfer leaks delegator's sbs out-of-band — compromised delegatee breaks delegator's cross-scope unlinkability

- **Attack:** Section 2 ("Blinding secret transfer mechanism") states: *"the delegator must communicate their `scopeBlindingSecret` to the delegatee through a private channel (e.g., encrypted via the delegatee's public key). The delegatee needs it to verify the chain-linking constraint in future hops where they become the delegator."*

  Wait — the chain-linking constraint in `ScopeBlindDelegation` is:
  ```
  Poseidon4(scopeId, delegatorBlindingSecret, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor
  ```
  The *delegatee* is generating this proof. So the delegatee must supply `delegatorBlindingSecret` as a *private input*. This means the delegator's `sbs` is transmitted out-of-band to the delegatee.

  An adversary controlling the delegatee (a compromised sub-agent, a rogue price-comparison bot, a malicious orchestrator) now possesses the delegator's `sbs`. It can:
  1. Enumerate all candidate RSes: `Poseidon2(scopeId_j, sbs_delegator)` for all `j` in a known RS list — O(N) lookups, feasible for N ≤ 10,000 merchants (the same dictionary attack the construction fixes for the AS, now re-enabled for a compromised delegatee).
  2. Compute all delegation anchors the delegator has ever published: `Poseidon4(scopeId_j, sbs_delegator, permBitmask, cc)` — reconstructing the full delegation graph.
  3. Retroactively deanonymize all past sessions — there is no forward secrecy for `sbs`.

- **Why it matters vs. fails:** The IND-UNL-AS game grants the adversary control over "up to k-1 of k total Resource Servers." It does NOT model a compromised delegatee agent as an adversary. The hybrid argument assumes `sbs_b` is known only to the challenger — but the delegation protocol deliberately transfers `sbs` to delegatees. In a multi-hop chain Alice → Bot₁ → Bot₂, both Bot₁ and Bot₂ receive Alice's `sbs_Alice`. Any compromise in the chain is a full disclosure event.

  The construction's framing in §7 (healthcare scenario) is particularly exposing: "Bob's health agent… carries a delegated credential." If the sub-agent is a third-party application, Bob's `sbs_Bob` is now in a third party's hands.

- **In-threat-model?** No. **The construction must either (a) redesign the chain-linking constraint so it does not require the delegatee to know the delegator's `sbs` (e.g., using a commitment scheme where the delegatee proves they received the anchor from the delegator without learning `sbs`), or (b) formalize a delegatee-compromise game and prove security degrades gracefully — which, given the retroactive exposure, it does not. An alternative is per-scope ephemeral blinding secrets with forward-secure derivation (e.g., HKDF from a root secret + scope + session nonce), so compromise of one scope's key does not expose other scopes.**

---

### Attack 4: Batch relayer is an unmodeled, centralized trust party — timing defense degrades to zero in low-traffic windows

- **Attack:** The anti-timing gadget (§2) claims adversary timing advantage is bounded by `1/m` per epoch, where `m` is the number of proofs submitted in a 30-second batch. The construction treats the batch relayer as a black-box protocol-layer mitigation. In fact, the relayer is:

  1. **A trusted third party not modeled in the game.** The relayer sees all proofs before they are submitted. It has access to `(scopePseudonym, scopeBoundDelegationAnchor, freshNonce, submitter IP)` for every proof in a batch. If the batch relayer is operated by CU*Answers and CU*Answers is compromised (or subpoenaed), the adversary trivially recovers the mapping from submitted proof to agent identity — not through cryptographic attack, but through the relayer's plaintext log. The IND-UNL-AS game does not model relayer compromise.

  2. **Variable batch size destroys the `1/m` guarantee in practice.** The `1/m` bound is an average-case claim based on uniform random shuffling within a batch. But m varies: at 3 AM on a weekday, m might be 1. Alice's proof is the sole proof in its epoch — timing is trivially deanonymizing regardless of cryptographic guarantees. The construction provides no mechanism to enforce a minimum batch size (proof padding with decoys) and no formal analysis of the distribution of m over time.

  3. **Network-level deanonymization is unaddressed.** Alice's agent connects to the batch relayer with her IP address. The adversary who observes the relayer's *inbound* connections (not the relayer-to-chain submission) still recovers Alice's timing with millisecond precision. The relayer only anonymizes Alice from the *chain*; it does nothing against an adversary who can observe the Alice-to-relayer link. The threat model (§3) lists "Network-level observation of proof submission timing and metadata" as an adversary capability without distinguishing Alice-to-relayer from relayer-to-chain timing.

  4. **Bypassing the relayer is undetectable.** Nothing in the circuit or the on-chain verifier enforces that proofs arrive via the batch relayer. An agent that submits directly (for latency reasons) silently loses all timing protection. The timing defense is not a protocol invariant — it is an opt-in infrastructure component with no enforcement mechanism.

- **Why it matters vs. fails:** The formal game (§3, "Side-channel sub-game") states adversary advantage is bounded by `1/m` per epoch. But this bound assumes: (a) the relayer is honest and not modeled as an adversary, (b) m is large, (c) all agents use the relayer. None of these are guaranteed or provable from the circuit constraints alone.

- **In-threat-model?** Partially. The timing sub-game models the batch relayer honestly and derives `1/m`. But it fails to model relayer compromise, network-level timing, variable m, or relayer bypass. **The construction must treat the relayer as an untrusted party. The correct primitive is an *oblivious submission scheme*: either a cryptographic mixing protocol (e.g., Tor-style onion routing into a commit-and-reveal on-chain aggregation), or a ZK-proven batch submission that hides per-proof ordering from the relayer itself. Absent this, "batch relayer" is an engineering approximation, not a formal timing guarantee.**

---

*Summary table:*

| Attack | Assumption violated | In game? | Severity |
|--------|--------------------|----|---------|
| POS-PRF-Joint unproven for shared-permutation Poseidon | Named assumption has no published reduction | No | Critical — proof collapses |
| Groth16 Phase 2 subversion → sbs extraction | Trusted setup excluded from threat model | No | Critical — full deanonymization |
| Delegatee learns delegator's sbs out-of-band | Delegatee compromise not modeled | No | High — retroactive full disclosure |
| Batch relayer: unmodeled trust, variable m, bypass | Relayer treated as honest and mandatory | Partial | Medium — timing defense illusory |


## Persona: cu_ciso

---

### Attack 1: The `scopeBlindingSecret` Has No Recovery Path — This Is a Member Access Continuity Failure Under GLBA

**Attack:**
Section 5 of the construction states: the `scopeBlindingSecret` is "a fresh 251-bit random scalar, never transmitted to the AS or any other party." Section 2 adds that the delegator must "communicate their `scopeBlindingSecret` to the delegatee through a private channel." I want to know: where does this 251-bit scalar live on Alice's device? If Alice's phone is wiped, her laptop is stolen, or her browser local storage is cleared — what is the recovery procedure?

There is none described. The construction is silent on key recovery.

This is not a cryptographic objection. This is a GLBA Safeguards Rule failure (16 CFR § 314.4(c)(2) — safeguarding covered information and maintaining access continuity) and an NCUA Part 748 § III.C issue (protection of member records). Every credit union I've run has a password reset flow, a PIN recovery procedure, and a backup authentication method. If the `scopeBlindingSecret` is lost, Alice's agent loses every delegation chain it ever seeded — permanently, because those anchors (`Poseidon4(scopeId, scopeBlindingSecret, ...)`) cannot be recomputed without the original scalar. Alice calls member support at 2am. What does my Tier 1 rep tell her?

The construction also describes secret *transfer* from delegator to delegatee via "a private channel (e.g., encrypted via the delegatee's public key)." This is an unspecified, unaudited, out-of-band key distribution operation. Under the FFIEC Information Security Booklet (key management controls), this transfer must be logged, authorized, and auditable. There is no mechanism for this.

**Why it works / why it fails:**
The construction's security argument (§4) correctly shows that the `scopeBlindingSecret` being unknown to the AS is what drives PRF unlinkability. But the construction conflates "cryptographically secret from the adversary" with "operationally manageable for the credential holder." These are orthogonal properties. The hybrid argument is sound. The operational model is missing.

**In-threat-model?** No — the construction's threat model explicitly excludes "the agent's local proving environment (trusted execution)" from adversary control. It says nothing about device failure, backup, or recovery. This is outside the stated threat model and must be addressed.

---

### Attack 2: Eliminating the AS From the Request Path Eliminates My Audit Log — FFIEC CAT Monitoring Domain Fails

**Attack:**
Section 8, Structural Impossibility 1, celebrates that "Bolyra eliminates the AS from the per-request path entirely." The construction frames this as a privacy feature. From where I sit, it's an audit catastrophe.

NCUA Part 748 Appendix A (Guidelines for Safeguarding Member Information, § III.B) requires covered financial institutions to "monitor, detect, and respond to attacks, intrusions, or other system failures" and maintain audit logs sufficient to reconstruct events. The FFIEC CAT (Cybersecurity Assessment Tool) Maturity Level 3 requires "logging of all access to sensitive systems including failed attempts."

What is the audit record of an authorization event under this construction? It's an on-chain ZK proof — a field element tuple on a public blockchain. The on-chain record contains `(scopePseudonym, nonceBinding, scopeBoundDelegationAnchor, scopeId, agentMerkleRoot)`. By design, none of these reveal which member's agent performed the authorization. That's the point of unlinkability. But that means: **if there is fraud, my CISO team cannot pull a server log and say "Alice's agent authorized a $95 transaction at Merchant-A at 14:32:07 UTC."** I cannot reconstruct the event from the on-chain record without Alice's `scopeBlindingSecret`. If Alice is the subject of a fraud investigation or an NCUA examiner's inquiry, what document do I hand over?

The construction proposes the batch relayer as a timing defense. This relayer "collects proofs from multiple agents and submits them in a single on-chain transaction." This means even the relayer-level submission log does not map individual proofs to individual members or timestamps within the epoch.

**Why it works / why it fails:**
The construction is internally consistent: unlinkability requires that no party, including the CU-as-AS, can reconstruct the member's authorization graph from public artifacts. This is exactly the privacy guarantee. But this guarantee directly conflicts with the CU's regulatory obligation to maintain auditable access records. The construction cannot simultaneously deliver both. It must explicitly describe what audit artifacts exist, where they live (presumably at the agent's local device, or in an encrypted member-controlled audit log), and how they are produced for law enforcement, fraud investigation, or NCUA examiner request. None of this is addressed.

**In-threat-model?** No. The threat model (§3) is defined against an adversarial AS trying to de-anonymize members. It does not address the dual-use scenario where the CU itself needs to reconstruct events for legitimate regulatory purposes. This gap must be addressed.

---

### Attack 3: The Batch Relayer Is an Unvetted Third-Party Service Processor Under NCUA Part 748 Appendix B

**Attack:**
Section 7 describes the batch relayer as "CU*Answers batch relayer, which aggregates proofs from agents across all 150 member credit unions and submits them in 30-second epochs." CU*Answers is a real CUSO. Let's say they operate this relayer.

Under NCUA Part 748 Appendix B (Guidance on Response Programs for Unauthorized Access to Member Information), and the NCUA's third-party due diligence guidance (Letter to Credit Unions 07-CU-13), any service provider that "touches" member authorization artifacts — even in encrypted or pseudonymized form — must be subject to:

1. A written contract with security and breach notification provisions
2. Due diligence review before engagement and periodically thereafter
3. Evidence of the provider's own information security controls (typically a SOC 2 Type II)

The construction says the relayer "sees proofs but cannot link them." This is a cryptographic claim, not a vendor risk assessment. The relayer still receives and processes ZK proofs that represent member financial authorization events. It has network-level visibility into which agents are active, proof volumes, epoch timing patterns, and potentially correlatable metadata not covered by the unlinkability argument (e.g., IP addresses, TLS fingerprints, proof sizes).

The construction's timing defense argument (§3, side-channel sub-game) bounds the adversary's timing advantage to `1/m` per epoch under random permutation within a batch. This assumes the relayer is honest. If CU*Answers' relayer infrastructure is compromised, a network-level observer can observe pre-shuffle submission patterns. The construction does not model a compromised or malicious relayer.

**Why it works / why it fails:**
The unlinkability argument is sound *against the on-chain adversary model* as stated. The relayer is explicitly placed outside the adversary's capabilities — the construction says "The relayer sees proofs but cannot link them." Whether this is true at the application layer (yes, by PRF unlinkability) is separate from whether the relayer is a safe third-party from a vendor risk perspective. My NCUA examiner does not care about Poseidon PRF security. They care whether CU*Answers has a current SOC 2 Type II report and whether my vendor management policy covers them.

**In-threat-model?** No. The construction's threat model treats the batch relayer as a trusted infrastructure component with no adversarial capabilities. A compromised relayer is not modeled. The construction must either (a) model the relayer as a potential adversary and prove unlinkability holds even against it, or (b) explicitly scope it out and note the vendor risk dependency. Neither is done.

---

### Attack 4: On-Chain Registry Availability Is Not Mapped to Any FFIEC BCP Control — One Blockchain Congestion Event = Member Lockout

**Attack:**
The on-chain Merkle tree is described as protected by "blockchain consensus" (§3, adversary capabilities). The deployment target is Base Sepolia in the CLAUDE.md, with contracts on Base mainnet presumably for production. What is Base's SLA?

Base is an Ethereum L2 (OP Stack). It has experienced sequencer outages. The Base mainnet sequencer went offline for ~1 hour on October 5, 2023 due to a software bug. During that period, no transactions could be submitted. Under this construction, that means no `ScopeBlindAuth` proofs can be verified on-chain — agents cannot be authorized at any RS for the duration of the outage.

My core processor (Symitar, Corelation, or similar) has a contractual 99.9%+ uptime SLA. The FFIEC Business Continuity Planning (BCP) booklet requires financial institutions to define recovery time objectives (RTOs) and recovery point objectives (RPOs) for all critical systems supporting member services. Authorization infrastructure is unambiguously critical.

The construction provides no RTO/RPO analysis, no fallback mechanism for on-chain outages, and no discussion of what happens to in-flight proof submissions during a sequencer downtime event. The batch relayer would simply fail to submit. All 150 credit unions in the CU*Answers network using this infrastructure would simultaneously lose agent authorization capability.

The construction also mentions gas costs (§6): "Groth16 on-chain ~220k gas. PLONK on-chain ~300k gas." During periods of high Base network congestion (e.g., during an NFT mint event or L1 gas spike), transaction fees rise and submission latency increases. The 30-second batch epoch SLA degrades unpredictably. No gas cost ceiling or priority fee strategy is described.

**Why it works / why it fails:**
The construction's security argument is entirely orthogonal to availability. The hybrid argument in §4 proves unlinkability; it says nothing about what happens when proofs cannot be submitted or verified. This is correct scoping for a cryptographic proof — but it leaves a critical operational gap that any NCUA examiner reviewing a third-party technology assessment (NCUA Part 748, § III.D) will surface immediately.

**In-threat-model?** No. The threat model (§3) explicitly states blockchain consensus is outside adversary control — "The on-chain Merkle tree integrity (blockchain consensus)" is listed as something the adversary does not control. This is correct for the IND-UNL-AS game. But availability threats are not adversarial in the cryptographic sense — they are operational failures. The construction must address: what is the fallback when the chain is unavailable, what is the RTO, and how does this map to FFIEC BCP requirements. Without this, no credit union CISO can approve production deployment.


## Persona: rfc7662_advocate

I am a skeptic who has shipped production introspection endpoints for payment networks, healthcare federations, and credit unions for a decade. I read proofs the way I read RFCs: every "impossible" needs a counter-deployment, not a hand-wave.

---

### Attack 1: Per-RS Enrollment JWTs (RFC 9700 + draft-ietf-oauth-jwt-introspection-response) Already Eliminate Per-Request AS Visibility

- **Attack:** The construction's §8 "Structural Impossibility 1" claims the AS "necessarily sees the `(agent, RS, scope, timestamp)` tuple at issuance time" as the fundamental OAuth flaw. But that conflates two distinct AS roles: *enrollment* (one-time) and *authorization* (per-request). A well-deployed AS using signed JWT introspection responses (draft-ietf-oauth-jwt-introspection-response, now RFC 9700) issues a self-contained JWT per `(agent, RS)` pair at enrollment. Thereafter the RS validates locally against the cached JWT — no AS roundtrip, no per-request visibility. The AS sees the enrollment graph once; it does **not** see individual access events or timing. PPID subjects (OIDC §8.1) give each RS a unique opaque `sub`. The construction's primary comparative argument ("AS is on the hot path") is simply false for a hardened JWT deployment.

- **Why it works / why it fails against the construction:** It partially works: §8's prose is overbroad. The real remaining gap in OAuth is that enrollment still reveals which RSes the agent *intends* to use — the AS sees the full RS enrollment set upfront, not the access pattern. Bolyra eliminates even this: an agent can present to any RS with no prior per-RS enrollment action visible to the AS. This is a genuine architectural difference. The construction just states the wrong reason — timing of individual requests is already solvable; the enrollment graph disclosure is the actual gap that OAuth cannot close without agent-local key derivation.

- **In-threat-model?** No — the construction must sharpen §8 Impossibility 1. The current framing ("AS sees the tuple at issuance time") is refuted by RFC 9700 deployments. The correct claim is: "even a one-time per-RS enrollment reveals the full RS graph to the AS, whereas Bolyra requires no enrollment signal per RS whatsoever." This is a true distinction, but it is not what §8 argues.

---

### Attack 2: Batch Relayer Is an Unmodeled Trust Boundary Enabling Arrival-Time Correlation

- **Attack:** Section 3 introduces a batch relayer as the timing defense, claiming "the relayer sees proofs but cannot link them." The formal IND-UNL-AS game grants the adversary "network-level observation of proof submission *timing*" (§3, side-channel sub-game). But the batch relayer is a separate entity entirely outside the formal model — neither adversary-controlled nor formally honest. In the §7 deployment, CU*Answers operates the relayer. It receives proofs before batching and sees: (a) the `scopePseudonym` (public output — §2 table), (b) the `scopeId` (public input — §2 table), and (c) the *wall-clock arrival time* of each proof at the relayer process. If Alice's agent submits proofs for Merchant-A and Merchant-B within milliseconds to the relayer, the relayer can cluster them by arrival time before any batching occurs. The on-chain transaction shuffles submission order; it does nothing for pre-batch arrival correlation at the relayer. The relayer is not the on-chain verifier; the formal bound of "1/m per epoch" applies only to external observers watching chain state, not to the relayer operator itself.

- **Why it works / why it fails against the construction:** It fully works as a gap. The proof's §3 side-channel sub-game correctly models the anonymity set as `m` proofs per epoch — but only from the perspective of a passive chain observer. The relayer, if subpoenaed or compromised, provides sub-epoch arrival-time correlation that the IND-UNL-AS game does not model. The construction provides no formal bound on relayer-side leakage because the relayer is mentioned only in §2 (deployment description) and §7 (scenario), never in §3 (threat model). The claim "the relayer sees proofs but cannot link them" is content-based; timing-based linking at the relayer is entirely unaddressed.

- **In-threat-model?** No — the construction must either: (a) include the relayer as an adversarial party in the IND-UNL-AS game with bounded leakage, or (b) require the relayer to implement an oblivious shuffling protocol (e.g., mix-net with uniform batching delays from first proof receipt, not from epoch start). As written, the timing guarantee is externally valid but internally broken.

---

### Attack 3: `agentMerkleRoot` as AS-Controllable Epoch Discriminator Collapsing the Anonymity Set

- **Attack:** Section 3 classifies `agentMerkleRoot` as a non-signal with "zero distinguishing information" because it is "identical for all agents (shared tree)." This claim is time-invariant only if the Merkle tree never changes. In practice, the tree is a live data structure — its root changes as credentials are enrolled or revoked. The AS (Desert Financial, §7.1) controls enrollment timing. Consider: Desert Financial enrolls agents in deliberate singleton batches — one agent per Merkle tree update. Each root `R_k` is unique to exactly one agent. Two proofs sharing root `R_k` must originate from that sole agent. The AS need not break any PRF; it uses `agentMerkleRoot` as a trivial identity tag it constructed. Even without intentional singletons, small enrollment cohorts (e.g., 3 agents enrolled between tree updates) shrink the anonymity set from `n` to 3, giving the adversary a `1/3` advantage per proof rather than `1/n`. This attack requires zero cryptographic work — it is pure administrative control over enrollment scheduling.

- **Why it works / why it fails against the construction:** It fully works as a gap. The IND-UNL-AS game grants the adversary "full read access to all on-chain state, including every public signal of every proof" (§3). `agentMerkleRoot` IS a public signal (§2 public outputs table). The game's non-signal analysis dismisses it as identical for all agents — but this is only true if the anonymity set is *all* agents, not agents within an enrollment epoch. The hybrid argument makes no reference to Merkle root epochs or cohort size. The §7.1 scenario explicitly has Desert Financial as the AS performing enrollment — it directly controls the epoch cohort.

- **In-threat-model?** No — the construction must either: (a) bound the minimum enrollment cohort size as a deployment parameter and integrate it into the IND-UNL-AS game (the adversary's advantage includes a `1/cohort_size` floor term), or (b) adopt rolling/batched enrollment with a minimum epoch size enforced by the on-chain registry, and prove that the adversary cannot reduce the cohort size below the epoch minimum.

---

### Attack 4: POS-PRF-Joint Is a Non-Standard Assumption That Poseidon's Published Analysis Does Not Cover

- **Attack:** The entire hybrid argument in §4 — specifically the transition from H₀ to H₄ across four signals — rests on "POS-PRF-Joint" (§4, Named Assumptions, item 1): that `(Poseidon2(x, sbs), Poseidon4(x, sbs, a1, a2))` is jointly indistinguishable from `(U_1, U_2)` for adversary-known auxiliary inputs `(a1, a2)`. The justification is "in the random oracle model where Poseidon instantiations of different arities are modeled as independent random oracles." This is a significant non-standard step. Poseidon is a sponge construction parameterized by state width `t`: Poseidon-3 (for 2 inputs) and Poseidon-5 (for 4 inputs) use the SAME underlying permutation family with t-dependent round constants derived from the same parameter generation procedure. They are not independent primitives — they share design lineage and, critically, the same capacity element semantics. The standard Poseidon security analysis (Grassi et al., USENIX 2021) proves PRF security at a fixed width under the CICO assumption. It does not establish independence across widths. Modeling different-arity Poseidon calls as independent random oracles is an unjustified leap that the construction asserts without citation. If there exists any algebraic relation between Poseidon-3 and Poseidon-5 outputs at the same key `sbs` — even a partial one exploitable in the BN254 scalar field — the joint distribution is distinguishable from `(U_1, U_2)`, and the H₁→H₂ and H₃→H₄ transitions are not individually bounded by `ε_{PRF4}`.

- **Why it works / why it fails against the construction:** This is the load-bearing assumption for the four-step hybrid. If POS-PRF-Joint does not hold, the security argument collapses entirely — not to a weaker bound, but to no bound. The construction does not cite any published result establishing cross-arity independence for Poseidon. The correct remedy is domain separation within a single arity: use `Poseidon3(DOMAIN_PSEUDONYM || scopeId, sbs, 0)` vs. `Poseidon3(DOMAIN_ANCHOR || scopeId, sbs, permBitmask)` (or equivalent), where the domain tag makes them independent by design at fixed width, and PRF security follows from the standard single-width analysis. Alternatively, use a keyed BLAKE3 or HKDF-based PRF for `sbs`-keyed derivation and reserve Poseidon only for in-circuit hash gadgets where the permutation-based structure is necessary for constraint efficiency.

- **In-threat-model?** Yes — the construction survives if it either cites peer-reviewed evidence that different-arity Poseidon instantiations are cryptographically independent (no such citation currently exists) or re-derives `scopePseudonym` and `scopeBoundDelegationAnchor` from a single-arity Poseidon with explicit domain separation tags, reducing to the standard POS-PRF assumption at fixed width. This is the most critical gap: it is a foundational assumption error, not a deployment parameter.


## Persona: spiffe_engineer

Staff engineer running SPIFFE/SPIRE across 300+ production clusters for a Fortune 500. Co-author on draft-ietf-wimse-arch. I've shipped the thing you're trying to reinvent at the wrong layer. Let me show you the gaps.

---

### Attack 1: "Write a SPIRE Attestor Plugin" — Wrong Abstraction Layer, And the Construction Knows It But Doesn't Prove It

- **Attack:** SPIRE has a fully pluggable attestor framework — node attestors, workload attestors, SVIDs with custom JWT claims. A ZK workload attestor plugin could generate `scopePseudonym = Poseidon2(scopeId, scopeBlindingSecret)` locally inside the workload and embed it as a custom claim in a JWT SVID. The SPIRE server validates the ZK proof, signs the SVID, and RSes verify against the SPIRE trust bundle. You've described a plugin, not a protocol.

- **Why it fails:** The SPIRE server issues every SVID — it must see `(workload SPIFFE ID, which ZK proof, when)` at issuance time. If the ZK proof includes `scopeId` as a public input (it does — see §2, `ScopeBlindAuth` public inputs), then the SPIRE server observes `(agent, scopeId, timestamp)` at every SVID rotation. SPIFFE's short-TTL model (typically 1-hour rotation via Workload API) means the AS sees a dense per-request event log. This is precisely the AS-per-request visibility that §8 "Structural Impossibility 1" eliminates. A SPIRE plugin cannot avoid this: the Workload API is a pull model where the agent fetches from SPIRE, and SPIRE must know what it's issuing.

  The only escape is to make SPIRE issue a long-lived credential at enrollment and then let the workload derive pseudonyms locally without further SPIRE involvement — but then you've abandoned SPIFFE's rotation model, Workload API, node attestation chain, and short-lived SVID security properties. You've implemented Bolyra with a SPIFFE header on it.

- **In-threat-model?** Yes — the construction survives this. The AS-per-request elimination (§8 Structural Impossibility 1) is a valid categorical distinction. The attack confirms the construction's claim rather than breaking it.

---

### Attack 2: `agentMerkleRoot` Is a Per-Deployment Operator Correlator — The "Shared Tree" Assumption Is Unproven in the Multi-Operator Scenario

- **Attack:** The IND-UNL-AS game (§3) classifies `agentMerkleRoot` as a non-distinguishing signal with the justification "Identical for all agents (shared tree)." This assumes one global Merkle tree containing every enrolled agent from every operator. But §7 describes Desert Financial and CU*Answers as distinct operational entities. In any realistic multi-operator deployment, each operator maintains its own enrollment tree, or the tree is partitioned by operator namespace. If trees are per-operator, then `agentMerkleRoot` is a stable global correlator that identifies the issuing institution. Two proofs at Merchant-A and Merchant-B that share the same `agentMerkleRoot` immediately reveal they originated from agents enrolled by the same operator — organizational-level linkability, visible on-chain, not addressed by the hybrid argument.

  A weaker version of this attack works even with a single global tree: the Merkle root changes on every enrollment. The AS knows exactly when it published each credential commitment to the tree (it's the issuer). An on-chain observer can bracket the enrollment cohort: "this proof uses root R₇, which only existed between block 14,000 and block 14,050, during which Desert Financial enrolled 3 agents." The root value narrows the anonymity set to that cohort.

- **Why it works / why it fails:** The hybrid argument (§4, H₀→H₄) replaces all four distinguishing signals with uniform random values. But it never replaces or analyzes `agentMerkleRoot` — it's excluded from the distinguishing signal list with the shared-tree assumption. If that assumption fails (per-operator trees, or time-windowed roots), the proof's non-signal analysis is incomplete. The threat model says the adversary has "full read access to all on-chain state" — `agentMerkleRoot` is on-chain.

- **In-threat-model?** No — the construction must address this. Either: (a) formally prove that a single global shared tree is maintained across all operators (with governance implications), or (b) extend the hybrid argument to include `agentMerkleRoot` and show it carries zero bits about the challenge agent given a shared tree. The §7 deployment scenario contradicts the shared-tree assumption by describing Desert Financial and CU*Answers as separate infrastructure operators.

---

### Attack 3: `scopeBlindingSecret` Lives Where the AS Can Reach — Trusted Execution Is Assumed, Not Enforced

- **Attack:** The entire unlinkability proof reduces to one assumption: the adversary does not control "the agent's local proving environment (trusted execution)" and cannot observe `scopeBlindingSecret`. This is the threat model's load-bearing wall.

  In production workload environments — the SPIFFE domain — the "trusted execution environment" is managed by the operator, who in the §7 scenario IS Desert Financial. Alice's agent runs in a container scheduled by Desert Financial's Kubernetes control plane. `scopeBlindingSecret` is a 251-bit persistent scalar (§2: "generated once at agent enrollment and stored alongside the agent's credential material"). In Kubernetes this means a `Secret` object. Kubernetes Secrets are:
  - Base64-encoded at rest unless KMS encryption is configured
  - Readable by anyone with `get secret` RBAC permissions — which Desert Financial's infra team holds as cluster operator
  - Backed by etcd, which Desert Financial controls
  - Accessible via AWS KMS admin if EKS + KMS integration is in use

  Desert Financial as AS issues the EdDSA-signed credential. Desert Financial as infrastructure operator can read the Kubernetes Secret containing `scopeBlindingSecret`. With `sbs_b` in hand, the adversary computes `Poseidon4(scopeId_candidate, sbs_b, permBitmask_b, cc_b)` for every candidate merchant in O(1) per candidate — trivially breaking the construction with the same dictionary attack §7 claims to close.

  SPIFFE's Workload API explicitly addresses this: the SPIRE agent delivers SVIDs via a local UNIX socket, and SVIDs are short-lived (no persistent secret storage in the workload). The Bolyra construction has no equivalent: it requires long-lived persistent secret storage with no specification for protection against the operator.

- **Why it works / why it fails:** The threat model exclusion ("agent's local proving environment") is a valid threat model boundary, but §7's deployment scenario violates it by placing the AS and the infrastructure operator in the same institutional entity. The construction provides no mechanism — TEE requirement, HSM storage mandate, threshold secret sharing, or operator/AS separation requirement — to enforce this boundary in practice.

- **In-threat-model?** No — the construction must either: (a) explicitly require TEE/HSM-backed storage for `scopeBlindingSecret` with a specification for the key protection layer, or (b) separate the AS role and infrastructure-operator role into distinct adversary categories and prohibit their conflation. Claiming "trusted execution" without specifying what enforces it is an assumption gap, not a design decision. This is the most actionable gap in the construction.

---

### Attack 4: The Batch Relayer Is an Unmodeled Trusted Third Party With Full Proof Visibility

- **Attack:** The timing sub-game (§3) introduces a batch relayer that "collects ScopeBlindAuth proofs from multiple agents and submits them in a single on-chain transaction at fixed intervals." The adversary's timing advantage is bounded at `1/m` per epoch. This bound requires the relayer to be a trusted black box. It is not modeled that way.

  The relayer receives every proof's full public signal vector before submission — including `scopePseudonym` (deterministic across sessions for the same agent at the same RS), `freshNonce`, and transport metadata (source IP, TLS session, submission timestamp within the epoch). The relayer can:

  1. **Cross-session linkage per RS (by design, but unstated):** `scopePseudonym_A = Poseidon2(scopeId_A, sbs_b)` is deterministic. Alice's agent visiting Merchant-A on Monday and again on Friday produces the same `scopePseudonym_A` both times. The relayer accumulates a pseudonymous activity log per `(scopePseudonym, RS)` pair — this is an intended property for account continuity, but it means the relayer holds a cross-session graph that is not covered by the IND-UNL-AS game.

  2. **Cross-scope linkage via source metadata:** The relayer sees proof with `scopePseudonym_A` arriving from source X, then a proof with `scopePseudonym_B` arriving from source X. Even without knowing `sbs_b`, the relayer can assert both proofs originated from the same source. If the AS subpoenas the relayer (or Desert Financial operates the CU*Answers relay as part of the shared infrastructure), it obtains the correlation the ZK proof was designed to prevent.

  3. **The `1/m` bound assumes adversary exclusion from the relay:** The timing sub-game says "adversary sees epoch boundaries but not per-proof timing within an epoch." This is only true if the adversary does not control the relayer. The threat model says the adversary controls the AS. In §7, Desert Financial is the AS. CU*Answers operates the batch relayer. If Desert Financial and CU*Answers are co-owners of the shared infrastructure (the scenario describes CU*Answers as a CUSO serving Desert Financial), the adversary potentially controls both.

- **Why it works / why it fails:** The IND-UNL-AS game grants the adversary "network-level observation of proof submission timing and metadata." A relayer operator is a network-level observer with *content* access — more powerful than the game's adversary model assumes. The `1/m` timing bound is not a bound on relayer-mediated correlation, only on blind network-layer timing. The construction does not specify relayer trust requirements, operational governance, or decentralization properties.

- **In-threat-model?** No — the construction must either: (a) include the relayer operator in the adversary model and specify a threshold or mixnet relay that remains secure under partial compromise, or (b) explicitly state the relayer trust assumption as a system-level security property (analogous to how Tor specifies honest-majority guard assumptions) and scope the unlinkability claim accordingly. Claiming timing defense via batching while leaving the relayer's content access unaddressed is a gap in the threat model boundary, not a cryptographic failure of the ZK construction itself.
