# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

### Attack 1: The Audit Timing Gap Makes the Privacy Claim Circular

- **Attack**: The PLONK proof in §7 is generated *after* the pipeline runs — the pipeline operator produces the proof and submits it for the NCUA examiner to verify. But if the operator generates the proof *post-hoc* from the actual witness data, the operator already had the scopes in plaintext to construct the witness. The privacy guarantee protects the auditor from learning intermediate scopes, but the operator is not the threat model for an audit. The entire premise of NCUA examination is that the examiner can verify the operator's representations independently — not that the examiner trusts the operator's own proof about their own pipeline. Auth0's audit log export gives the examiner time-stamped, tamper-evident records from a neutral infrastructure provider. This construction gives the examiner a proof the operator generated about themselves.

- **Why it works / fails**: The construction explicitly states the NCUA examiner sees `narrowingHolds = 1` with no extractable intermediate state. But an NCUA Safety & Soundness examiner is asking "show me your authorization controls," not "give me a ZK proof of your authorization controls." The threat model in §3 treats the auditor as a potential privacy adversary (CHAIN-PRIVACY game). But in the regulatory scenario in §7, the auditor is the relying party. Hiding intermediate state from the auditor defeats the purpose of having an auditor. The construction conflates the privacy adversary (a litigation opponent or competitor) with the regulatory examiner — these are opposite roles with opposite access requirements.

- **In-threat-model?** No — the construction must address: (a) how an NCUA examiner gets independent verification that the proof was generated from genuine runtime data (not a constructed witness), and (b) whether NCUA's audit trail requirements (12 CFR Part 748 guidance requires reconstructible records) are satisfied by a proof that deliberately makes intermediate state non-reconstructible.

---

### Attack 2: < 5s Proving Time Breaks the Synchronous Audit Use Case

- **Attack**: The construction targets "multi-tool AI pipelines where auditor wants proof that no hop exceeded its mandate." If audit happens synchronously — before the next hop executes — the 2–5s proving window (§6, PLONK with rapidsnark) blocks the pipeline at every step. A 5-hop Navy Federal loan pipeline with synchronous audit adds 10–25s of latency. If audit happens asynchronously (after the pipeline completes), there is a window where hops have already executed with no verified authorization — exactly what the construction is supposed to prevent. Auth0 MCP auth issues tokens in <100ms with no proving step. The construction either degrades pipeline performance to unacceptable latency, or it is not actually synchronous authorization but a post-hoc attestation system — in which case it competes with standard audit logs, not OAuth.

- **Why it works / fails**: §6 says the proving target is < 5s PLONK, < 2s with rapidsnark. The construction is silent on where in the pipeline lifecycle the proof is generated. If it is generated once at pipeline completion (the most plausible reading), it is a retrospective attestation, not authorization. Auth0 and WorkOS provide authorization (token issuance before action) and separately provide audit logs. The construction is trying to be both simultaneously and the timing doesn't support it for either role.

- **In-threat-model?** No — the construction must specify the exact lifecycle point of proof generation, and whether the system is authorization (before) or attestation (after). If attestation, it must explain how it prevents unauthorized hops from executing before the proof is verified. If authorization, it must explain how 2–5s latency is acceptable for interactive AI pipelines.

---

### Attack 3: Chain Length Hiding Is a Regulatory Liability

- **Attack**: §2, G5 ("Active-hop multiplexing hides chain length") is presented as a privacy feature. The §7 deployment scenario describes an NCUA examiner verifying the pipeline. But NCUA's examination checklist for AI model governance (NCUA Letter 21-CU-09 and subsequent guidance on AI model risk) requires that the institution can demonstrate the scope and number of automated decision-making steps in any member-facing process. A proof that deliberately conceals chain length — and is designed so the auditor "cannot distinguish a 3-hop chain from a 16-hop chain" — could be characterized as obstruction of examination. The construction markets chain length hiding to the compliance audience while regulators view it as opacity.

- **Why it works / fails**: The construction is designed for two audiences simultaneously: (1) operators who want privacy from auditors, and (2) auditors who want to verify narrowing. These audiences have conflicting interests in chain length. WorkOS provides a human-readable authorization event log — the examiner can count hops, name agents, and see timestamps. The Bolyra construction provides stronger cryptographic guarantees while providing weaker evidentiary value for the specific regulatory use case it cites as the anchor scenario.

- **In-threat-model?** No — the construction must either (a) provide a selective disclosure mode where chain length is revealed to a credentialed examiner (contradicting the privacy claim), or (b) demonstrate that NCUA regulatory guidance explicitly permits chain-length-concealed audit proofs (no such guidance exists as of 2026).

---

### Attack 4: The On-Chain Verifier Creates a Trust Dependency the Construction Denies

- **Attack**: §7 states "The PLONK proof is verified on-chain." The auditor must interact with a smart contract on Base Sepolia (testnet per CLAUDE.md) or a production chain. In practice, the NCUA examiner uses a web application provided by NFCU that calls the verifier contract via an RPC endpoint (Infura, Alchemy, or Base's own RPC). This reintroduces exactly the trusted intermediary the construction eliminates at the cryptographic layer: the RPC provider can return falsified contract state, the web app can present a fabricated verification result, and the examiner has no practical way to verify they are reading the correct contract at the correct address. Auth0 provides a HTTPS-accessible audit log the examiner can query with their own credentials against a provider with SOC 2 Type II and FedRAMP. Dynamic Client Registration (RFC 7591) — workable today — handles the agent registration problem without a Merkle tree or ZK circuit. The construction's on-chain verification step moves operational risk from the application layer to the blockchain infrastructure layer without eliminating it.

- **Why it works / fails**: The construction's ZK guarantees are sound. The deployment UX is not. The actual buyer persona — a compliance officer at a credit union — does not run a Base node, does not have a hardware wallet to call contract functions, and does not have an IT team to verify contract addresses against published bytecode. The gap between "cryptographically verified on-chain" and "the examiner pressed a button on a website the operator set up" is the entire trust gap the construction claims to eliminate. This is a distribution problem Auth0 and WorkOS have already solved with their existing customer success, documentation, and integration tooling.

- **In-threat-model?** No — the construction must specify the complete examiner-facing verification UX without assuming the examiner trusts any operator-controlled interface, and must account for the fact that Base Sepolia is a testnet with no production SLA, no regulatory recognition as a valid record system, and no indemnification for data loss.


## Persona: cryptographer

Applied cryptographer. I have read the construction in full — the circuit spec, the security games in §3, the reduction sketches in §4, and the deployment scenario in §7. My objections follow the construction's own notation.

---

### Attack 1: Root-Hop Deanonymization via the Unblinded Handshake Anchor (G3a / §3)

- **Attack:** The public input `handshakeScopeCommitment = Poseidon2(scopes[0], credCommitments[0])` is unblinded. An adversary enumerates all enrolled credential commitments (Merkle leaves are public upon enrollment — the construction states this explicitly in §3) and all 256 valid 8-bit permission bitmasks. For N enrolled agents, this requires 256 × N Poseidon2 evaluations — at N = 500 that is 128,000 evaluations, under one second on commodity hardware. The adversary recovers `(scopes[0], credCommitments[0])` exactly: the root agent identity and its permission bitmask.

- **Why it works / why it fails:** The construction defends its blinded public outputs `rootScopeCommitment` and `finalScopeCommitment` with a 254-bit blinding nonce and Theorem 3. But those are outputs. The attack targets a public *input* — `handshakeScopeCommitment` — which carries no blinding at all. The construction's own §2, G3a says "making it a public input reveals no new information" because it was already on-chain from the handshake. That is a non-answer: it means the handshake already deanonymized the root hop, and the audit proof inherits that leak. The blinded `rootScopeCommitment` output is then theater — it protects information the adversary already has from the unblinded anchor.

- **Consequence for the whistleblower scenario (§7):** The construction explicitly claims "the source agent is identifiable only to themselves." The source's credential commitment is the leaf at hop 0. `handshakeScopeCommitment` is on-chain from the handshake. Any adversary with read access to the registry can invert it by enumeration. The source is not hidden.

- **In-threat-model?** The CHAIN-PRIVACY game (§3) requires both challenge chains to have "identical `handshakeScopeCommitment`" — this constraint is precisely what makes the game trivially avoid the root-hop. The formal game sidesteps root privacy by design. But the informal claim ("without learning any intermediate scope values, any intermediate participant identities") and the whistleblower scenario both presuppose root-hop privacy. **The formal game proves something strictly weaker than the stated claim. The construction must address this or narrow the claim.**

---

### Attack 2: CHAIN-PRIVACY Game Parametrization Makes the Reduction Circular (§3, Theorem 2)

- **Attack:** The CHAIN-PRIVACY game is parameterized so that both challenge chains $C_0, C_1$ must share `(handshakeScopeCommitment, policyFloor, agentRegistryRoot)`. Since `handshakeScopeCommitment = Poseidon2(scopes[0], cc[0])`, this forces both chains to have the *same root agent and same root scope*. The reduction then proves that PLONK ZK + Poseidon preimage resistance hide the *remaining* private inputs — the intermediate hops. But the natural privacy question for a "delegation chain audit" is: can an auditor distinguish which participants were in the chain, including the root? The game, as stated, concedes root-hop distinguishability before the game even starts.

- **Why it matters formally:** The Theorem 2 reduction sketch (§4) invokes PLONK zero-knowledge and Poseidon preimage resistance, both valid. But the security statement reduces to: *given that the adversary already knows the root agent and root scope, they cannot identify intermediate hops*. The scope of "privacy" is the k−2 hops between root and terminal, not the full chain of k hops. A complete privacy theorem would need to cover a game where the challenge chains differ at the root — which requires blinding `handshakeScopeCommitment` itself, or eliminating it as a public input and replacing it with a blinded anchor checked in-circuit.

- **Proposed game that exposes the gap:** Define CHAIN-PRIVACY-FULL identically but allow $C_0$ and $C_1$ to differ in root agent, root scope, *and* `handshakeScopeCommitment`. The current construction fails this game trivially: adversary computes `Poseidon2(s, cc)` for all enrolled (s, cc) pairs, finds the matching root for each audit proof, and distinguishes $b = 0$ from $b = 1$.

- **In-threat-model?** Theorem 2 as stated: **yes, construction survives** (the game is weak enough). For the application's actual need: **no, the construction must either eliminate the unblinded anchor or define a weaker (honest) claim.**

---

### Attack 3: G5 Multiplexer Underconstraint — Chain-Length Leakage via Non-Uniform Padding

- **Attack:** The chain-length-hiding property relies on G5 producing identical blinded scope commitments for all inactive hops:
  ```
  blindedScopeCommitment[i] = Poseidon3(scopes[L-1], credCommitments[L-1], blindingNonces[i])
  ```
  For inactive hops to produce *identical* values, the circuit must enforce `blindingNonces[i] = blindingNonces[L-1]` for all `i ≥ actualLength`. The construction states inactive hops "copy... `blindingNonces[actualLength-1]`... via multiplexer" — but provides no Circom constraint. If the multiplexer is implemented only as a prover-side hint (witness generator) and not as a circuit constraint, a malicious prover can supply distinct `blindingNonces[i]` for each inactive hop.

- **Why it works:** With distinct blinding nonces per inactive hop, `blindedScopeCommitment[i]` for `i ≥ actualLength` are uniformly random independent field elements. The chain digest G6 then encodes a structure like:
  ```
  chainDigest ∝ Poseidon2(...Poseidon2(Poseidon2(salt, bsc[0]), ..., bsc[L-1]), r_{L}, ..., r_{15})
  ```
  where `r_L, ..., r_{15}` are fresh random values chosen by the prover. An adversary who sees two chain digests from the same chain (but generated with different padding strategies) can distinguish them from uniformly random digests. More critically, if an honest prover always uses *uniform* padding (copies the last nonce) but a cheating prover uses *random* padding, the chain digest distributions are distinguishable — leaking whether the prover was honest and indirectly leaking chain length via distribution fingerprinting across multiple proofs.

- **Why it might fail:** A correctly implemented circuit would contain, for each inactive hop i, a constraint `(1 - isActive[i]) * (blindingNonces[i] - blindingNonces[actualLength-1]) === 0`, enforced via the multiplexer output. If present, the attack is closed. The construction provides no Circom code and no explicit mention of this constraint — only that padding "copies" via multiplexer. This is a correctness gap requiring verification.

- **In-threat-model?** If the constraint is missing: **no, construction does not survive** — chain-length hiding fails for provers who deviate from the witness generator. If the constraint is present but undocumented: **construction survives but must document it.** Either way, the construction must show the constraint or the claim is unverified.

---

### Attack 4: Salt-Private `chainDigest` Enables Audit-Record Fragmentation — Regulatory Evasion

- **Attack:** `chainDigest = Poseidon(salt, Poseidon-chain of blinded commitments)` where `salt` is a **private** input. The `auditNullifier = Poseidon2(chainDigest, auditSessionNonce)` prevents exact replay of the same proof, but the operator (prover) can produce arbitrarily many valid audit proofs for the *same underlying chain* with fresh salts and fresh session nonces, each producing a distinct `chainDigest` and a distinct `auditNullifier`. The on-chain verifier cannot determine whether two accepted proofs correspond to the same chain or different chains.

- **Why it works:** The chain digest is a commitment that hides the chain from the verifier, by design. But hiding it also prevents the verifier from *binding* an audit proof to a unique chain. A malicious operator under regulatory audit can:
  1. Produce proof $\pi_1$ for chain $C$ with `auditSessionNonce = nonce_1` → accepted, nullifier $N_1$ stored.
  2. Produce proof $\pi_2$ for a different chain $C'$ (or the same chain $C$ with fresh salt) → accepted, nullifier $N_2 \ne N_1$ stored.
  3. Show both proofs to the auditor as "proof that two different pipelines narrowed correctly" when they may represent the same pipeline run twice, or different pipelines with the same endpoints.
  
  No on-chain linkability check can detect this because `chainDigest` is salt-dependent and reveals nothing about the underlying chain.

- **The game definition omission:** The security game CHAIN-NARROW-SOUNDNESS (§3) asks whether $\mathcal{A}$ can produce an accepting proof for a chain that violates narrowing. It does not ask whether $\mathcal{A}$ can produce two accepting proofs for two chains such that the verifier cannot determine they are the same chain. This is a *chain-identity binding* property that the construction never defines and for which no reduction exists.

- **Concrete regulatory scenario:** NCUA requests audit logs proving each agent pipeline run narrowed correctly. The operator submits 10 distinct audit nullifiers. NCUA cannot determine whether these represent 10 distinct pipeline runs or 1 run audited 10 times. The construction provides no mechanism for the verifier to count distinct chains.

- **In-threat-model?** The formal games as defined: **yes, construction survives** (the games don't ask for chain-identity binding). For the stated regulatory use case in §7 ("compliance officer receives proof"): **no, construction must address this** — either by making the salt public (linking digest to chain) or by introducing a chain-identity commitment that is verifier-visible without exposing the chain contents.

---

### Summary

| Attack | Formal Game | Informal Claim / Use Case |
|---|---|---|
| A1: Root-hop deanonymization | Survives (game excludes it) | **Fails** (whistleblower scenario broken) |
| A2: CHAIN-PRIVACY game too weak | Survives (by game design) | **Fails** (proves less than claimed) |
| A3: G5 multiplexer underconstraint | Unknown (no Circom shown) | **Unverified** (chain length leak if missing) |
| A4: Audit-record fragmentation | Survives (game excludes it) | **Fails** (regulatory use case broken) |

The construction's ZK machinery is sound for what the formal games specify. The problem is the gap between the formal games and the informal claims in §1, §3 (threat model prose), and §7. A construction at strength 10 would need: (1) a blinded root anchor or explicit acknowledgment that root-hop privacy is excluded from the claim, (2) a CHAIN-PRIVACY-FULL game covering root-hop distinguishability, (3) circuit-level constraints for the multiplexer (not just prose), and (4) a chain-identity binding mechanism for regulatory completeness.


## Persona: cu_ciso

### Attack 1: Forensic Dead-End Under NCUA Part 748.0(b) — Privacy Properties Obstruct Your Own Incident Response

- **Attack:** At 3am, a member dispute triggers a forensic pull: which specific agent in the pipeline accessed PII and what permissions did it exercise at runtime? The construction's answer is `narrowingHolds = 1` and six opaque field elements. The blinding nonces (`blindingNonces[MAX_HOPS]`) are chosen ephemerally by the pipeline operator at proof generation time — if the operator is a third-party vendor (the cross-org handoff variant in §7), those nonces live in their memory or an ephemeral buffer, not in your systems. Section §7 explicitly says the auditor does not learn "what permissions each hop had" or "which agents participated." That is the feature. It is also the reason your forensics team cannot determine which tool called by the chatbot accessed `ACCESS_PII` in the ten minutes before the dispute was filed. NCUA Part 748.0(b) and the GLBA Safeguards Rule (16 CFR §314.4(f)) require that you "monitor, detect, and respond" to security events affecting member information — and the FTC's 2023 amended Safeguards Rule adds a 30-day notification clock from *discovery*. Discovery requires attribution. This construction cryptographically eliminates attribution for anyone who doesn't hold the blinding nonces, including you.

- **Why it works / why it fails:** The ZK proof that narrowing held at proof-generation time is not a runtime access log. It proves the *delegation was valid when the chain was issued*, not what was accessed or when. The construction has no mechanism for selective unblinding under court order or examiner subpoena — the blinding nonces are private inputs held by the prover, not by the CU. There is no key escrow, no trusted third party holding nonces, and no mention of a disclosure protocol for incident response.

- **In-threat-model?** No. The construction's threat model (§3) defines the adversary as an outside attacker or a corrupted auditor trying to extract scope information. It explicitly does not model the scenario where the CU itself needs to unbind the proof for its own forensic investigation. The construction must address: (a) a nonce custody and escrow mechanism for the CU's own incident response team; (b) how selective disclosure of a single hop's scope and participant identity is performed under legal compulsion without invalidating the privacy properties for remaining hops.

---

### Attack 2: Tier 1 Ops Cannot Revoke — The 30-Root History Buffer Is a Revocation Time Bomb

- **Attack:** The on-chain verifier accepts `agentRegistryRoot` from a 30-entry circular root history buffer (§2, G9, and §7 step 3). An active delegation chain proof is valid only if the Merkle root used at proof time is still in that buffer. My ops team identifies a compromised agent at 2am — say, the credit scoring tool in the NFCU scenario (hop 2) has been exfiltrating data. Standard response: revoke the credential, update the Merkle tree, publish a new root. The new root pushes the old root through the 30-entry buffer. Once it rotates out, any in-flight audit proof anchored to the old root is now unverifiable on-chain — even for legitimate, non-compromised chains that were issued before the incident. Meanwhile, the compromised agent's *already-issued delegation tokens* remain valid until their `expiries` lapse: the on-chain verifier checks `agentRegistryRoot` against the history buffer, but an attacker holding a valid delegation token can still call into your pipeline using a root that was valid when the token was issued. The construction does not distinguish between "root is in buffer because the chain is recent and valid" and "root is in buffer because the attacker moved fast before revocation propagated."

- **Why it works / why it fails:** The construction treats the root history buffer as a liveness convenience, not a security boundary. Revocation invalidates future proofs but not the already-issued delegation tokens, because those tokens were signed by enrolled-at-the-time keys (G4: EdDSA signature verification uses the key valid at signing). There is no in-circuit check against a revocation list or a CRL-equivalent. The section §3 adversary model explicitly says $\mathcal{A}$ *cannot* "enroll arbitrary credential commitments" — but it doesn't address what happens when a legitimately enrolled credential is compromised and needs revocation with immediate effect.

- **In-threat-model?** No. The construction's soundness argument (Theorem 1) proves that a proof cannot be forged for *unenrolled* credentials. It says nothing about the window between credential compromise and effective revocation. The construction must address: (a) how revocation invalidates outstanding delegation tokens before their encoded expiry lapses; (b) whether the 30-root buffer window is sized to the CU's incident response SLA (FFIEC CAT Maturity Level 3 requires documented and tested response times, typically under 4 hours for Tier 1 systems); (c) what the ops procedure is when a revocation and a legitimate audit proof race the buffer rotation.

---

### Attack 3: SLA Inversion — Your Member-Facing AI Pipeline Is Now Gated on L2 Liveness

- **Attack:** The `agentRegistryRoot` and the `handshakeScopeCommitment` are checked on-chain by the verifier contract before PLONK proof verification (§7, step 3). The deployment target is Base Sepolia per `CLAUDE.md` — a testnet. Even in a production deployment on Base mainnet, the SLA of your AI pipeline is now the intersection of: (1) Base L2 liveness, (2) the sequencer's block inclusion latency, (3) the gas market at the time of the on-chain `verifyProof` call, and (4) your own RPC provider's uptime. None of these are under your control. The FFIEC CAT (Domain 5: Cyber Incident Management and Resilience) requires that third-party dependencies have contractual SLAs, tested BCPs, and recovery time objectives documented in your vendor management program. Can you produce a contract with Coinbase (Base operator) or with whoever operates the registry contract that commits to 99.9% uptime? No — smart contracts have no SLA, no support escalation path, and no indemnification. When your core processor (Symitar, Corelation) has a 2-hour outage, you have a contract, a dedicated support line, and a regulatory notification framework. When Base has a sequencer outage, you have a GitHub issue.

- **Why it works / why it fails:** Section §7 describes proving time targets (< 5s PLONK, < 2s with rapidsnark) and gas cost (~300K gas per on-chain verification) but zero mention of: what the pipeline does when the verifier call reverts due to gas spike or chain congestion; whether there is an off-chain fallback mode; what the BCP is for a chain reorganization that removes a previously verified `auditNullifier` from on-chain state. The construction optimizes for cryptographic properties and ignores operational continuity.

- **In-threat-model?** No. The threat model (§3) is purely cryptographic — it models a PPT adversary against soundness and privacy games. It does not model infrastructure failure. The construction must address: (a) an off-chain fallback verification mode with equivalent audit defensibility that does not require live blockchain access; (b) a vendor management framework for the L2 dependency that satisfies NCUA's third-party due diligence requirements (Letter to Credit Unions 07-CU-13); (c) explicit SLA commitments or a design that degrades gracefully when the chain is unavailable.

---

### Attack 4: The NCUA Examiner Cannot Read Your Audit Artifact — And That Is Your Problem, Not Theirs

- **Attack:** "Name the NCUA Part, GLBA section, or FFIEC control this maps to." The construction's audit artifact delivered to the NCUA examiner is: `narrowingHolds = 1`, `policyMet = 1`, six BN128 field elements, and one PLONK proof blob. The examiner's questionnaire asks: *Which employees or systems had access to member information? What access controls were in place? How do you demonstrate that access was limited to what was necessary?* NCUA Part 748, Appendix A, §III.C.1(a) requires documentation of access controls. GLBA Safeguards Rule §314.4(c)(3) requires you to "control access to customer information" and demonstrate it. Neither the NCUA nor GLBA defines a ZK proof as a valid access control attestation — because no NCUA examiner has been trained to verify one, no examination questionnaire has a line for "PLONK proof hash," and no supervisory guidance from the NCUA accepts cryptographic proofs in lieu of human-readable access logs or SOC 2 Type II control reports. The whistleblower variant and journalist scenario in §1 are not credit union use cases — a credit union cannot tell its examiner "we hid which agents accessed member PII to protect journalistic sources."

- **Why it works / why it fails:** The construction is technically sound but regulatory-context-deaf. It names "NCUA examiner" as an explicit stakeholder in §7 ("compliance officer (auditor) receives `auditSessionNonce`") but provides no mapping between the proof outputs and any named NCUA, GLBA, or FFIEC control. The comparison table in §8 benchmarks against RFC 8693 + BBS+ + WIMSE on cryptographic properties — none of which are NCUA-relevant criteria. A `chainDigest` field element is not a substitute for the access log entry format described in NIST SP 800-92. The construction must address: (a) a human-readable audit summary layer — produced by a trusted component holding the nonces — that translates proof outputs into NCUA-legible access records; (b) explicit mapping of `narrowingHolds` and `policyMet` to named GLBA §314 controls and FFIEC CAT maturity indicators; (c) guidance on how this fits into an existing SOC 2 Type II audit scope, since your SOC 2 auditor (likely A-LIGN or Coalfire) has no procedure for evaluating PLONK proofs.


## Persona: rfc7662_advocate

*OAuth Working Group veteran, 10 years shipping production introspection. Every ZK claim is suspect until proven not achievable by RFC 7662 + its extensions.*

---

### Attack 1: Root Hop Deanonymization via Unblinded `handshakeScopeCommitment` (G3a Bypass)

- **Attack:** The construction makes `handshakeScopeCommitment = Poseidon2(scopes[0], credCommitments[0])` a **public input** (G3a, §2). The enrolled Merkle leaves — all `credCommitments[i]` — are publicly enumerable from the on-chain agent registry (explicitly acknowledged in §3: "Enumerate all enrolled credential commitments from the on-chain agent Merkle tree"). There are at most 256 valid scope bitmasks. An adversary enumerates all `256 × N` pairs and computes `Poseidon2(s, cc_i)` for each, matching against `handshakeScopeCommitment` in O(256·N) time — the same brute-force attack the blinding nonces were introduced to defeat (§2, G3). For N = 10,000 enrolled agents, this is `2.56 × 10^6` Poseidon evaluations, taking under one second on commodity hardware, directly revealing the root hop's agent identity and initial permission bitmask. The blinded public **output** `rootScopeCommitment = Poseidon3(scopes[0], credCommitments[0], blindingNonce[0])` is then entirely beside the point for the chain origin: the adversary already has both `scopes[0]` and `credCommitments[0]`. The construction's own §2 (G3) quantifies this as the "brute-force threat (now blocked)" in §7, but G3a immediately reintroduces it via the public input channel.

- **Why it works / why it fails:** The construction's defense (G3a) states: "making it a public input reveals no new information" because the value is already on-chain from the handshake. This confuses *on-chain storage* with *on-chain invertibility*. The value being on-chain does not mean it was previously invertible to `(scopes[0], credCommitments[0])` by a third-party auditor — prior to the audit proof being generated, `handshakeScopeCommitment` sat on-chain as an opaque field element. Once the audit circuit designates it a public input and anchors the proof to it, the auditor is directed to look at this value and check it against the `lastScopeCommitment` mapping. This constitutes disclosure. Theorem 3 (SCOPE-COMMITMENT-HIDING) applies only to `Poseidon3` outputs; it says nothing about `Poseidon2` public inputs. The CHAIN-PRIVACY game (§3) assumes identical `handshakeScopeCommitment` for both challenge chains — meaning the privacy proof conditions away the most informative field in the public transcript.

- **In-threat-model?** **Yes — construction must address.** The root hop's identity and scope are fully recoverable from the public transcript by the auditor, defeating the construction's core privacy claim for the chain origin. The fix is non-trivial: removing `handshakeScopeCommitment` from public inputs severs the handshake-anchoring guarantee (G3a); keeping it breaks root privacy. A blinded version `Poseidon3(scopes[0], credCommitments[0], salt)` as the on-chain anchor — committed at handshake time, not revealed during the handshake — would close this gap, but requires a protocol change upstream of the audit circuit.

---

### Attack 2: Commitment-Only AS Achieves Equivalent Auditor-Facing Semantics (RFC 8693 + Signed JWT Introspection)

- **Attack:** Section 8 claims "RFC 8693 structurally requires the AS at every hop" and that "a compromised/subpoenaed AS reconstructs the full chain." This argument assumes the AS stores delegation tokens in plaintext. It does not hold against a commitment-only AS design. Consider: the AS at each hop stores only `Poseidon2(scope_i, credCommitment_i)` — never the plaintext scope or credential identity. Delegation tokens themselves are issued as opaque handles indexed by commitment. An audit endpoint built on `draft-ietf-oauth-jwt-introspection-response` (signed JWT introspection response) then returns a non-repudiable signed JWT attesting `{ narrowing_holds: true, policy_met: true, chain_id: <opaque_handle> }`. Per-RS introspection policy (RFC 9728 PRM) controls what each auditor class may query. The AS is no longer on the hot path for verification — the signed JWT can be cached and verified offline. A subpoena of the AS yields only commitments, not plaintext scopes. The gap the construction claims to close — "a compromised/subpoenaed AS reconstructs the full chain" (§8) — is nullified if the AS was never architected to store plaintext in the first place.

- **Why it works / why it fails:** The construction's baseline analysis (§8) targets RFC 8693 as specified, not RFC 8693 as optimally deployed with commitment-based storage and signed JWT audit responses. This is a strawman: the IETF OAuth toolbox is not static. The genuine residual advantage of the ZK construction over a commitment-only AS is: (1) **no AS involvement at proof time** — the pipeline operator generates the proof unilaterally, without contacting any AS; (2) **prover-controlled privacy** — the operator's blinding nonces are never transmitted to any server; (3) **AS cannot be compelled to produce an audit attestation** because the ZK proof is self-sovereign. Points (2) and (3) are real but narrow: they require an AS-adversarial threat model that the construction never formally states. The claim "baseline cannot match" is too broad; it should be scoped to "AS-adversarial deployments where the operator distrusts the AS."

- **In-threat-model?** **No — construction must address.** The claim that the baseline "cannot" produce equivalent auditor-facing semantics is falsified by a commitment-only AS with signed JWT introspection. The construction should bound its advantage to a formally stated threat model where the AS is adversarial (coerced, compromised, or absent). The current §3 threat model does not name the AS as an adversary — it only lists the auditor as a potential adversary. Without an AS-adversarial model in §3, the construction's §8 comparison is arguing against a weaker baseline than the strongest deployment of RFC 8693.

---

### Attack 3: `policyFloor` Public Input Collapses Final Scope Anonymity Set

- **Attack:** The `policyFloor` is a 64-bit **public input** visible to any on-chain observer. The constraint `finalScope & policyFloor == policyFloor` (G7) is enforced in-circuit, and `policyMet = 1` signals the final scope satisfies it. In the NFCU scenario (§7), `policyFloor = 0b00000001` (READ_DATA). But operational audit policies are rarely this permissive: an NCUA examiner auditing a loan-signing pipeline specifies `policyFloor = SIGN_ON_BEHALF (bit 5)`. The valid final scopes satisfying this are all bitmasks with bit 5 set — exactly 128 of 256 values. More operationally specific policies (e.g., `policyFloor = FINANCIAL_UNLIMITED | SIGN_ON_BEHALF = bits 4,5`) reduce the anonymity set to ≤32 values. Combined with Attack 1 (root hop deanonymized via `handshakeScopeCommitment`), the adversary now knows: root scope and identity (from Attack 1), and that the final scope is one of ≤32 values. If the final `credCommitment` can be guessed (e.g., the pipeline has a known terminal tool class), the blinded `finalScopeCommitment` is invertible in O(32 × N) evaluations of Poseidon3 over known (scope candidate, known credCommitment, trial nonce) — though the nonce search remains infeasible. Separately: DPoP (RFC 9449) provides sender-constraint without publishing any policy floor as a verifiable public input. An AS audit endpoint can verify `policyMet` internally and return only the boolean, without exposing the policy floor to on-chain observers. The ZK construction trades this privacy for verifier-side auditability.

- **Why it works / why it fails:** The `policyFloor` leak is real but bounded: it reduces the final scope's anonymity set without breaking it entirely, because the blinding nonce still protects `finalScopeCommitment` from enumeration (blinding nonce search space is 2^254, unchanged). However, the construction's privacy argument treats `finalScopeCommitment` as hiding the final scope entirely — which it does under the SCOPE-COMMITMENT-HIDING game. That game fixes `cc*` (known credential commitment) and unknown nonce. In practice, if `policyFloor` constrains `finalScope` to a small set and the terminal agent is guessable from operational context, the blinded commitment is a weaker privacy guarantee than claimed. The construction does not analyze `policyFloor` as an information leak anywhere in §3 or §4.

- **In-threat-model?** **Yes — construction should address.** The construction should add a `policyFloor` leakage analysis to the CHAIN-PRIVACY game and clarify the final scope anonymity set as a function of `policyFloor` specificity. Optionally: make `policyFloor` a private input with a public commitment `Poseidon2(policyFloor, policyNonce)`, verified in-circuit, to prevent on-chain observers from using it to narrow the final scope search.

---

### Attack 4: Merkle Leaf Enumeration Correlates `chainDigest` Across Audit Sessions

- **Attack:** The `chainDigest = Poseidon(salt, chain-of-blinded-commitments)` uses a **private** salt (G6), claimed to make the digest computationally indistinguishable across chains of different lengths. However, the `agentRegistryRoot` is a **public input** and the Merkle leaves are publicly enumerable. Consider a scenario where the same delegation chain is audited twice — same actual hops, same scopes, but fresh `blindingNonces`, fresh `salt`, fresh `auditSessionNonce`. The two proofs produce distinct `chainDigests` (due to fresh nonces) and distinct `auditNullifiers`. An on-chain observer linking proofs by `handshakeScopeCommitment` (the same anchor — already on-chain, same handshake) can: (1) confirm both proofs reference the same handshake session via matching `handshakeScopeCommitment`; (2) observe both `narrowingHolds = 1` and `policyMet = 1`; (3) count the number of distinct audit proofs anchored to a single handshake, inferring operational tempo and audit frequency. More critically: a distinguishing audit — where an adversary requests audits with different `policyFloor` values for the same chain and observes which values yield `policyMet = 1` vs `policyMet = 0` — performs a binary search over the final scope's bit positions. With 8 bits and 8 queries, the final scope bitmask is fully recovered. RFC 9449 DPoP tokens are nonce-bound and not susceptible to this oracle attack because the AS, not the auditor, controls the verification predicate.

- **Why it works / why it fails:** The binary-search oracle attack is real. The on-chain verifier contract accepts any `(policyFloor, proof)` pair from any caller — there is no rate-limiting or caller-binding in the described deployment. An adversary who can submit arbitrary audit requests against the same `handshakeScopeCommitment` can recover the final scope in O(log 64) = 6 on-chain calls by bisecting on individual bit positions. The construction's `auditNullifier = Poseidon2(chainDigest, auditSessionNonce)` prevents *replay* of a specific proof, but does not prevent an adversary from generating fresh proofs (as the pipeline operator) or requesting new audits. Crucially, the construction does not specify access control on who may request an audit or how many times.

- **In-threat-model?** **Yes — construction must address.** The on-chain verifier should enforce that `policyFloor` is committed at handshake time (or at chain-creation time) and cannot be varied per audit call against the same `handshakeScopeCommitment`. Alternatively, `policyMet` should be replaced by a range-commitment scheme where the auditor proves `policyFloor ∈ [finalScope]` without varying `policyFloor` as a free parameter. Without this, the oracle attack recovers the final scope in a small number of on-chain interactions, defeating Theorem 2 (CHAIN-PRIVACY) in any deployment where the adversary has audit-request capability.


## Persona: spiffe_engineer

### Attack 1: Cross-Org Enrollment Assumes What It Must Prove

**Attack:** §7's "cross-org handoff variant" claims the auditor verifies a chain spanning NFCU and a third-party appraisal vendor "without learning which appraisal vendor was used." But `agentRegistryRoot` (public input, §2) is a *single* Merkle tree root administered by one registry. G9 forces every active hop to prove inclusion against *that one root*. For a genuine cross-org handoff, the vendor's agents must first be enrolled in NFCU's registry. Who controls enrollment? The adversary model (§3) states enrollment "requires operator-signed credentials verified by the `AgentPolicy` circuit" — but it does not say who holds the operator key for cross-domain agents.

In SPIFFE, cross-domain identity has an explicit answer: federated trust bundles exchanged via authenticated SPIFFE bundle endpoints, rooted in each domain's SPIRE server. Federation is bidirectional, auditable, and the Workload API surfaces it transparently to workloads. The construction gives no equivalent mechanism. Either: (a) the vendor enrolls in NFCU's registry (but then NFCU controls the vendor's identity — not cross-org at all), or (b) there are two registry roots and the circuit must verify two Merkle trees (not in the construction). The §7 cross-org claim is unsubstantiated by the circuit design.

**Why it works against the construction:** The construction's circuit signature is `DelegationChainAudit(MAX_HOPS)` with a single `agentRegistryRoot`. Multi-domain chains require either a merged registry (centralizing trust) or a circuit extension for cross-root proofs. Neither appears in §2–§6.

**In-threat-model?** No — construction must address. The cross-org scenario in §7 is presented as a working deployment variant but is unsupported by the circuit.

---

### Attack 2: WIMSE Audit-Time Characterization Is Incorrect

**Attack:** §8 claims WIMSE "structurally requires the AS at every hop" and that "a compromised/subpoenaed AS reconstructs the full chain." This mischaracterizes `draft-ietf-wimse-arch`. WIMSE's workload-to-workload token exchange (WIMSE §5) uses JWT-SVIDs issued by SPIRE's intermediate CA per workload, not by a per-hop authorization server. At audit time, the verifier holds a sequence of JWT-SVIDs — each is a self-contained, CA-signed artifact. Auditing the chain requires only the SPIRE root CA certificate, which is public. No AS involvement is needed at audit time.

The genuine gap the construction would need to claim against WIMSE is narrower: (1) WIMSE exposes hop count (the sequence of SVID issuance timestamps and JWT `iss` claims); (2) WIMSE exposes participant workload IDs (the `sub` claim in each JWT-SVID); (3) WIMSE cannot produce a single aggregated proof. The "AS-blind auditing" framing in §8 is a strawman — retire it, or cite the specific WIMSE mechanism being defeated.

**Why it works:** §8 is the primary comparative argument for why the baseline fails. If the AS-blind claim is incorrect for WIMSE's actual architecture, the construction has misidentified the gap it closes. The correct gap is *chain aggregation* and *participant anonymity*, not AS independence.

**In-threat-model?** Partially — the aggregation and anonymity gaps are real and in-scope; the AS-blind framing is wrong and the construction must correct it. If a reviewer reads the WIMSE draft and finds the claim false, the entire §8 table is undermined.

---

### Attack 3: Operator-Controlled Enrollment Defeats G9

**Attack:** The adversary model (§3) explicitly excludes the ability to "enroll arbitrary credential commitments in the agent Merkle tree." But the same section states enrollment "requires operator-signed credentials." In the NFCU scenario (§7), the entity generating the `DelegationChainAudit` proof is "the pipeline operator." If the pipeline operator also controls enrollment (which is the typical case — operators provision their own agents), they can:

1. Generate a fresh EdDSA keypair for a phantom agent that will never execute any workload.
2. Submit a valid `AgentPolicy` circuit proof (the operator has the operator key) to enroll `credCommitment_phantom` in the on-chain registry.
3. Construct a delegation chain that routes through the phantom agent at any desired hop — G9's Merkle inclusion check passes because *the operator enrolled it*.
4. The narrowing proof holds, `narrowingHolds = 1`, `policyMet = 1`. The phantom agent's scope is set to satisfy policy floor.

This is not the "phantom root attack" described in §2 (which involves *unenrolled* credential commitments). This is a *legitimately enrolled phantom*: a credential commitment that passed all on-chain enrollment checks but corresponds to no real workload.

In SPIFFE, SPIRE node attestation (TPM-based, cloud instance identity documents, Kubernetes pod attestation) cryptographically ties workload identity to actual executing compute. An operator cannot enroll a SPIFFE ID for a process that isn't running on real hardware without defeating the attestation plugin — a much higher bar. The Bolyra enrollment model has no equivalent hardware root.

**Why it works:** §2 (G9) explicitly defends against phantom chains by requiring Merkle inclusion, but defines phantoms as unenrolled. A legitimately-enrolled-but-fake agent passes G9 by construction. The threat model boundary ("cannot enroll arbitrary credential commitments") holds only if operator enrollment is honest — an assumption not cryptographically enforced.

**In-threat-model?** No — construction must address. The threat model should either (a) acknowledge honest-operator assumption for enrollment, or (b) describe the registry's enrollment mechanism's resistance to phantom enrollment by the operator being audited.

---

### Attack 4: ZK Proves Logical Chain Integrity, Not Causal Execution

**Attack:** The construction's strongest real-world claim is that an NCUA examiner can verify "the AI system actually operated within these bounds." But the `DelegationChainAudit` circuit proves only: *a valid delegation token chain exists* with consistent scopes, signatures, and enrollments. It cannot prove the chain *actually governed execution*.

A malicious NFCU operator runs the real pipeline with the loan underwriting tool holding `FINANCIAL_UNLIMITED` permissions, then post-hoc constructs a `DelegationChainAudit` proof over a fake chain with properly narrowed scopes — all agents enrolled, all scopes consistent, all signatures valid. The proof is accepted on-chain. The auditor sees `narrowingHolds = 1`, `policyMet = 1`. The actual execution was unconstrained.

The construction has no *causal binding* between the proof and runtime behavior. In SPIFFE, SVIDs are issued to workloads *at runtime* by the Workload API via the local SPIRE agent; each SVID has a short TTL (default 1h). The token's existence is a side effect of the workload executing — there is no path to fabricate a post-hoc SVID for a workload that didn't run, because SVID issuance requires a live node attestation. The causal link is enforced by the platform.

The deployment scenario in §7 steps 2–4 describes the *pipeline operator* generating the proof. The gap is real: who enforces that the proof's private witness (`scopes[MAX_HOPS]`, `delegationSigs`) matches what actually executed, rather than what the operator *wishes* had executed?

**Why it works:** This is a category-level mismatch between what ZK proves (logical predicate satisfaction over supplied witness data) and what the auditor needs (causal link to actual runtime execution). The construction should bound its claim precisely: it proves *a valid credential chain was constructable*, not that *the chain governed execution*. The §7 deployment scenario and §1 claim imply the stronger guarantee without warranting it.

**In-threat-model?** No — and this is the deepest structural gap. The construction must either (a) explicitly scope the claim to "credential chain integrity" and disclaim runtime enforcement, or (b) describe a complementary enforcement mechanism (e.g., agent runtime signing a nonce at each tool call, binding the session to the delegation token) that provides the causal link. Without this, the NCUA deployment scenario is oversold.
