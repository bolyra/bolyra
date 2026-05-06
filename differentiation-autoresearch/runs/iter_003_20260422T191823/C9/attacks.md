# Tier 3 Adversarial — C9 Forward-secure agent delegation

## Persona: auth0_pm

---

### Attack 1: The Proving Time Is the Product

- **Attack:** Section 6 admits ForwardSecureAgentSession takes ~5s and ForwardSecureDelegation ~5s. A lending agent making 50 tool calls per loan decision generates 250 seconds of proof latency per workflow. WorkOS MCP auth issues a signed token in <100ms — that's a **50x latency gap on the critical path**. The construction's §2.5 says epoch rotation is per-epoch (e.g., daily), but each *session* still runs the ForwardSecureAgentSession circuit. The credit union's loan officer sees a 5-second hang every time the agent calls a new tool. That's the demo that kills the deal.
- **Why it works / why it fails:** The construction does not address latency in a production MCP call stack. It cites <5s as acceptable but that is measured in isolation. Compounded over an agentic workflow with N tool calls, the cost is O(N × 5s). The construction has no mechanism to amortize this (e.g., session-long batch proofs or pre-computed proof caches). Section 7's "SECU 30-day lending agent" scenario would be unusable in practice if each tool call requires a fresh circuit proof.
- **In-threat-model?** No — the construction must address: (a) whether the ~5s figure applies per-session or per-epoch, (b) whether proof generation is on the hot path of every tool call, and (c) a concrete performance comparison against RFC 9449 DPoP at real-world call volumes.

---

### Attack 2: Unlinkability Is a Compliance Liability, Not a Feature

- **Attack:** NCUA Examination Procedures require credit unions to maintain complete audit trails for automated systems acting on member accounts. The entire value proposition of §8 — "epoch nullifiers have no `sub`/`client_id`/`jkt`" — is indistinguishable from "your regulators cannot audit this agent's behavior." The construction proves that a regulator with full on-chain access *cannot link prior sessions to the agent*. That is exactly the property that NCUA would flag in a BSA/AML examination. Auth0 and WorkOS sell credit unions the opposite: a tamper-evident, legally attributable audit log that satisfies examiners. The whistleblower scenario (§7) actively demonstrates the product's regulatory liability.
- **Why it works / why it fails:** The construction conflates "private" with "secure" in the regulatory context. §8.3 argues "operational deletion ≠ cryptographic guarantee" against competitors, but the same frame applies here: "cryptographically unlinkable ≠ regulatorily auditable." The IND-FS-AGENT game proves the construction is secure against a key-compromise adversary; it says nothing about whether a court order, NCUA examiner, or BSA audit can reconstruct the agent's activity. The construction does not define a dual-mode operation where unlinkability can be selectively disclosed to authorized auditors.
- **In-threat-model?** No — the construction must address how the credit union satisfies NCUA/BSA audit obligations when prior-epoch sessions are, by design, unlinkable even to the deploying institution.

---

### Attack 3: Secure Deletion Is Load-Bearing and Unverifiable

- **Attack:** The entire forward-secrecy claim in §4 rests on "secure deletion assumption" for `(s_e, r_e)`. Section 3 states "Does NOT have deleted epoch secrets or blinding factors (secure deletion assumption)" as a given. But in the actual SECU deployment scenario (§7), the Claude agent runs in a cloud environment — AWS Lambda, ECS, or a managed container. AWS does not guarantee memory erasure between invocations. Container snapshots, EBS volume snapshots, CloudWatch log streams, and core dumps can capture the process state including `r_e` before the application-layer deletion fires. The construction's cryptographic guarantees reduce to a runtime hygiene assumption it explicitly disclaims responsibility for (§8.3 says "no proof of deletion exists in any RFC" — but Bolyra has no proof of deletion either). Auth0's token-based model doesn't ask the application to securely delete anything; the forward secrecy lives in TLS, not in user-space code.
- **Why it works / why it fails:** §8.3 is a double-edged argument. The construction uses it to attack RFC baselines, but the same critique applies: the application must reliably zero `s_e` and `r_e` before epoch transition. If the agent crashes mid-rotation, both `s_e` and `r_e` survive in the crash dump. The construction has no epoch-transition commit protocol that proves deletion occurred before `newEpochCommitment` is published. An adversary who obtains a crash dump from epoch `e-1` recovers `r_{e-1}` and can link the hiding commitment, breaking Case 2 of the IND-FS-AGENT reduction.
- **In-threat-model?** No — the construction must define a verifiable deletion protocol (or hardware enclave requirement) and acknowledge that the forward-secrecy guarantee is conditional on the deployment environment, not unconditional.

---

### Attack 4: The Incumbent Already Covers the Actual Buyer Objection

- **Attack:** The construction's differentiated claim is: "If an agent's signing key is compromised at time T, sessions before T remain unlinkable and non-replayable." The procurement question is: *how often does a credit union's MCP agent signing key get exfiltrated by an adversary who also has full transcript access but lacks the PLONK SRS trapdoor?* The answer in the actual threat landscape of credit union IT is: essentially never. Their real incidents are phishing, misconfigured IAM policies, and supply chain compromises of npm packages — none of which are addressed by ZK forward secrecy. Auth0 handles these with MFA, SCIM provisioning, and anomaly detection. The construction's §2 scenarios (whistleblower relay agents, key-in-public-repo) are real attack scenarios, but they are not the scenarios a credit union CISO puts in their risk register. The construction is solving a problem from the Signal threat model and selling it to SECU.
- **Why it works / why it fails:** The construction does not include a threat frequency analysis. §7 asserts scenarios as if they are representative credit union incidents. But Auth0/WorkOS close deals by mapping to the CISO's existing risk register. The construction's IND-FS-AGENT game is cryptographically sound but buyer-irrelevant if the threat it protects against has a near-zero prior probability in the target market. The "solo founder" procurement objection compounds this: the buyer needs to justify the switching cost from a SOC 2 Type II vendor to an unaudited ZK protocol by citing a specific, named risk that the incumbent doesn't cover.
- **In-threat-model?** No — the construction must (a) identify a credit-union-specific incident class that forward secrecy resolves and incumbents do not, or (b) reposition away from credit unions toward a buyer segment (e.g., investigative journalism platforms, regulated whistleblower systems) where the IND-FS-AGENT threat model actually matches the buyer's risk register.


## Persona: cryptographer

*Adversarial review of C9 — "Forward-secure agent delegation." I will cite the construction by section and gadget name.*

---

### Attack 1: `epochTransitionNullifier` Breaks the Unlinkability Claim Entirely

**Attack:** The IND-FS-AGENT adversary receives `s_T`. Section 2.4 defines `epochTransitionNullifier = Poseidon2(s_e, epochIndex)` as a **public output** of EpochRotation. The adversary computes `Poseidon2(s_T, T)` — this is a direct computation requiring only `s_T` and the public epoch index. They look up this value on-chain, locating the epoch-T rotation proof. That proof exposes `previousEpochCommitment_{T-1}` as a **public input** (§2.4). The adversary then traverses backward: find the rotation proof where `newEpochCommitment` equals `previousEpochCommitment_{T-1}`, extract its public input `previousEpochCommitment_{T-2}`, repeat. After O(T) lookups they have `epochCommitment_e` for every e ∈ [0, T). They then query all session proofs with matching `epochCommitment` and reconstruct the full session timeline.

**Why it works:** The construction's §4 Case 2 reduction argues the adversary "cannot identify which on-chain commitments belong to the compromised chain" because `r_e` is destroyed and `s_e` requires inverting Poseidon1. That argument addresses **direct computation** of a commitment. It does not address **graph traversal**: the transition nullifier is computable from `s_T` alone, functioning as a deterministic chain anchor. The EpochRotation proofs form a public linked list — each proof's input/output commitment pair is visible — and `epochTransitionNullifier` is the key that finds the head of that list. Destroying `r_e` protects individual commitment preimages but leaves the chain structure fully traversable. The §3 threat model's claim that "adversary cannot even identify which on-chain commitments belong to the compromised agent" is false.

**In-threat-model?** No. The construction must address this. Either remove `epochTransitionNullifier` from public outputs entirely (derive double-blinded chain anchors off-chain), or prove that chain traversal does not leak the session graph. As written, §7's SECU 30-day scenario — "attacker cannot identify which commitments belong to the compromised agent" — is incorrect.

---

### Attack 2: EpochRotation Proof Graph is a Public Linked List (Structural Linkability Independent of Commitments)

**Attack:** Separate from Attack 1, the EpochRotation circuit structure in §2.4 creates an observable chain graph without any knowledge of `s_T`. Every rotation proof links `previousEpochCommitment` (public input) to `newEpochCommitment` (public output). Any on-chain observer can reconstruct the complete directed graph of all agents' commitment chains from public transaction data. Commitments themselves are pseudorandom under A5, but the graph structure is a persistent, stable identifier for each agent: an agent's "identity" on-chain is precisely this commitment chain, not any individual commitment.

**Why it works / fails:** The hiding commitment construction (§2.2) correctly prevents a standalone commitment `Poseidon2(s_e, r_e)` from leaking `s_e`. But the ZK unlinkability claim (§3, IND-FS-AGENT game step 3) asks whether an adversary can link "two transcripts from e*." The game challenger picks `e*` and gives a transcript `τ_b`. If the adversary can determine which chain that commitment belongs to — which they can by the proof graph — they win not by computing `s_e` but by structural pattern matching. The §4 reductions analyze only cryptographic preimage hardness; they do not model graph-structural linkability.

**In-threat-model?** Partially. Against a passive on-chain observer (no key compromise), commitments are pseudorandom so the graph structure alone doesn't help link sessions. But once `s_T` is known (Attack 1), the graph enables full reconstruction. The construction should treat the EpochRotation proof graph as a separate privacy surface and provide an explicit argument that the linked-list structure doesn't violate IND-FS-AGENT. Currently there is none.

---

### Attack 3: Subverted PLONK SRS — Platform-Level Backdoor

**Attack:** §3 asserts "Does NOT have the PLONK SRS trapdoor" as an adversary exclusion. But Bolyra — the platform deploying this construction — plausibly generated or controls the universal SRS. The PLONK ZK property holds only if the SRS trapdoor `τ` (powers-of-tau secret) is destroyed post-ceremony and is not known to any party. If Bolyra retains `τ`, they can extract the private inputs `(s_e, r_e)` from any proof via the algebraic extraction procedure. This is not a future attack; it is a retroactive one: every proof ever generated is deanonymizable from archived on-chain data.

**Why it works:** PLONK's ZK proof is: pick random `r` (distinct from blinding `r_e`), include hiding polynomial commitments, challenge via RO. If `τ` is known, the hiding polynomial commitments are computable from their evaluations — the standard extraction applies in the AGM. The construction's §4.3 reduction assumes PLONK ZK holds and cites "ZK simulator exists in ROM," but the simulator requires that the SRS is honestly generated. The §4 threat model excludes the trapdoor holder by assumption, but the scenarios in §7 (CFPB whistleblower, SECU agent) implicitly require protection against the platform operator. A credit union deploying this for whistleblower protection must trust Bolyra's ceremony provenance absolutely.

**In-threat-model?** Construction survives if the SRS is from a publicly verifiable multi-party ceremony (e.g., Zcash powers-of-tau or Hermez). But the construction doesn't specify this. The gap: (a) no ceremony specification, (b) no UC model of the setup functionality `F_CRS`, (c) no argument about what happens under subverted setup. For the adversary model to be complete, the platform operator must be explicitly modeled as either trusted or untrusted, and the ceremony provenance stated. "Does not have the PLONK SRS trapdoor" is an assumption, not a guarantee.

---

### Attack 4: Deletion Atomicity Failure During Epoch Rotation

**Attack:** The EpochRotation circuit (§2.4) takes `s_{e-1}` and `r_{e-1}` as private inputs. This means the agent must retain `(s_{e-1}, r_{e-1})` in memory until the rotation proof is successfully generated, verified, and posted on-chain. Section 2.2 says "the blinding factor `r_e` is destroyed alongside `s_e` at epoch transition," but this deletion is not atomic with respect to the proof submission. If the agent process crashes, is OOM-killed, or is suspended mid-proof (common in long-running 30-day autonomous agents per §7), `(s_{e-1}, r_{e-1})` persists — on the heap, in a core dump, in swap, or in a checkpoint file.

**Why it works:** The forward secrecy security argument in §4 reduces to "A1 prevents inverting Poseidon1" and "A5 ensures hiding commitments are pseudorandom." Both of these are computational assumptions about what the adversary can compute given only on-chain data. Neither covers the case where the adversary extracts `s_{e-1}` from a crashed agent's memory image. The §3 threat model requires "secure deletion assumption" but does not specify: a TEE requirement, an OS-level memory zeroing guarantee, a proof of deletion primitive, or any bound on the deletion window. The §8.3 claim "Operational deletion ≠ cryptographic guarantee (re: baseline)" applies with equal force to this construction: "Bolyra's security is a property of Poseidon preimage resistance + hiding commitments, not runtime hygiene" — but runtime hygiene IS load-bearing here because deletion happens at user-space.

**In-threat-model?** No, and this is the sharpest operational gap. A crashed 30-day lending agent (§7 scenario) mid-rotation leaves `(s_{day-14}, r_{day-14})` in a core dump. The construction must either: (a) bound the epoch rotation window and prove deletion within that window using hardware attestation (TPM/TEE), (b) use a key derivation construction that requires zero persistent state at rotation time, or (c) explicitly acknowledge this as an out-of-scope OS-level assumption and remove the §8.3 comparison claim.


## Persona: cu_ciso

---

### Attack 1: Secure Deletion is an Unauditable Operational Assumption

- **Attack:** The construction's entire forward-secrecy claim rests on the **"secure deletion assumption"** stated in §3: the adversary "does NOT have deleted epoch secrets or blinding factors." §2.1 says the agent "irreversibly deletes" `s_e` and `r_e` at epoch boundary. §8.3 even acknowledges that memory forensics can recover "deleted" keys — but then waves it away as a baseline problem. It is equally this construction's problem. I will ask my examiner: *Show me the cryptographic proof of deletion for `s_{29}` on day 30 of the SECU lending agent scenario.* There is none. The construction provides no HSM requirement, no TPM-backed key zeroing, no hardware enclave spec, no deletion audit log, and no attestation mechanism. "Destroyed" appears five times in the document. It is never operationalized.

- **Why it works:** Under GLBA Safeguards Rule §314.4(f)(2), I must document and test disposal procedures for customer information. Under NCUA Part 748 Appendix B, "destruction" of sensitive data must be documented and verifiable. The construction's security property — `Adv[A] ≤ negl(λ)` — is contingent on a runtime hygiene guarantee that no cryptographic primitive enforces. A compromised VM memory dump at epoch boundary recovers `(s_e, r_e)` before deletion. The reduction in §4 implicitly assumes deletion happened; no circuit constraint enforces it.

- **In-threat-model?** **No.** The construction must specify: (a) a hardware root of trust (HSM, TPM, or secure enclave) for epoch secret storage, (b) an attestation mechanism proving deletion occurred before the next epoch commitment is published on-chain, or (c) explicitly scope the claim to hardware-backed deployments only. Without this, the IND-FS-AGENT game is defined against a stronger adversary than the deployment reality supports.

---

### Attack 2: The Privacy-Audit Paradox (Examiner's Nightmare)

- **Attack:** §3 proves that an adversary who obtains `s_T` "cannot even identify which on-chain commitments belong to the compromised agent." §7 (SECU 30-day lending scenario) states that the "30 on-chain commitments `Poseidon2(s_e, r_e)` are opaque." This is the construction's headline claim. It is also my incident response disaster. When NCUA examiners arrive after a member-facing breach involving the lending agent, they will ask: *Produce the agent's activity log for the 30-day period.* The construction's unlinkability guarantee applies equally to me and my internal audit team as it does to the adversary — unless I retained `(s_e, r_e)` pairs in a separate audit store, which directly undermines the deletion assumption in Attack 1. There is no key escrow, audit-mode, or regulatory access path described anywhere in the construction.

- **Why it works:** NCUA examination guidance requires financial institutions to maintain audit trails sufficient for incident reconstruction. FFIEC CAT Domain 3 (Cybersecurity Controls) requires logging and monitoring that supports forensic analysis. The construction achieves cryptographic privacy at the cost of operational auditability. The two goals are in direct tension and the construction makes no architectural choice between them. The whistleblower scenario in §7 is presented as a feature; to a regulated credit union it is a compliance liability.

- **In-threat-model?** **No.** The construction must define a dual-mode architecture: a regulatory audit path (e.g., a separately-keyed audit log encrypted to a custody key held in escrow with the credit union's board-designated officer) that does not compromise the forward-secrecy guarantees for external adversaries. This is architecturally non-trivial and not addressed.

---

### Attack 3: Key Custody Specification Gap — "Agent Holds `s_0`"

- **Attack:** §2.1 states the agent holds an initial epoch secret `s_0`. §7 says the agent "samples `r_e`" and performs deletion. The construction is completely silent on *where* `s_0` lives and *what process* performs key operations. The SECU lending agent is described as a "Claude agent" — does `s_0` live in the LLM's context window? In a Python `bytes` variable in a cloud VM? In a browser? The attack prompt is blunt: *Key custody: where does the member secret live? If it's a browser, you've lost me.* Nothing in §2–§8 answers this. The Bolyra primitive mapping table (§5) maps everything to circuit constraints and on-chain operations, but `s_0` generation and storage has no mapping to any hardware or key management primitive.

- **Why it works:** Under NCUA Part 748 and the GLBA Safeguards Rule §314.4(c), I must maintain a written information security program that includes access controls and encryption key management for systems handling member data. My Vendor Management Policy requires third-party vendors to demonstrate key management practices. A construction that says "agent holds `s_0`" without specifying an HSM, a KMS (AWS KMS, HashiCorp Vault), or a TEE cannot pass third-party risk due diligence. The constraint count table (§6) and the Bolyra primitive table (§5) give me circuit economics; they give me nothing for my vendor questionnaire.

- **In-threat-model?** **No.** The construction must specify a key custody model as a first-class deployment requirement — not an implementation detail left to the integrator. At minimum: (a) `s_0` must be generated inside a hardware boundary (HSM or TEE), (b) epoch rotation operations must occur inside that boundary, (c) the boundary must produce an attestation that deletion occurred. Without this, the "secure deletion assumption" in §3 is decorative.

---

### Attack 4: Regulatory Framework Vacuum — The Examiner Won't Care

- **Attack:** The construction contains zero references to NCUA Part 748, GLBA, FFIEC CAT, or SOC 2. The security argument (§4) is organized around cryptographic assumptions A1–A5 and game-theoretic reductions. §8 argues against DPoP and WIMSE on cryptographic grounds. My NCUA examiner does not use the AGM+ROM model. They use the FFIEC Cybersecurity Assessment Tool and NCUA's third-party due diligence questionnaire. When I present this construction to my board as justification for deploying autonomous agents handling member loan data, the board will ask: *What NCUA control does this satisfy? Do we have a SOC 2 report for the Bolyra infrastructure?* The answers are: none specified, and none exists. The construction is a cryptographic paper that lands in a regulatory vacuum.

- **Why it works:** NCUA examiners assess risk, not cryptographic novelty. My ability to deploy this technology depends on mapping it to existing control frameworks. The DPoP comparison in §8.1 is technically correct — but DPoP exists within an RFC, has OIDC ecosystem support, and my examiner can find it in FFIEC guidance. "IND-FS-AGENT game under A1–A5" has no NCUA citation. The construction's differentiation claim (§8) is framed entirely as a technical superiority argument; a regulatory defensibility argument is absent.

- **In-threat-model?** **No — and this is the construction's largest deployment blocker.** The construction needs a regulatory mapping appendix that cross-walks each security property to a named control: NCUA Part 748 §748.0(b) (security program), GLBA Safeguards §314.4 (access controls, encryption, disposal), FFIEC CAT (cybersecurity controls domain), and a SOC 2 Type II scope definition for the Bolyra registry infrastructure. Without this, the construction solves a cryptographic problem that my institution cannot purchase.


## Persona: rfc7662_advocate

---

### Attack 1: Ephemeral DPoP keys collapse the replay argument

- **Attack:** Section 8.1 argues that DPoP key compromise "reveals every DPoP proof the agent ever generated." This is only true if the agent reuses a single long-lived DPoP key. RFC 9449 §4.1 allows DPoP proofs to be generated from *any* asymmetric key — nothing binds the agent to a stable DPoP thumbprint. A well-configured agent generates a fresh ephemeral DPoP key pair per session, binds the access token to the ephemeral `jkt`, then destroys the key after use. At time T, compromise of the long-term credential key yields exactly: the current epoch's DPoP key. Prior ephemeral keys are gone — prior DPoP proofs are unreplayable.

  The construction's FS-REPLAY argument (§4) rests on "recovering `s_{e*}` from `s_T` breaks A1." But the DPoP analog is identical: recovering a prior ephemeral DPoP private key from a deleted key pair breaks EC DL. The deletion claim is structurally the same.

- **Why it works / fails:** The construction does not address the ephemeral-DPoP deployment. Its §8.1 rebuttal targets static-DPoP configurations. Against ephemeral DPoP + destroyed-after-use keys, the replay non-achievability argument fails as stated. The construction would need to show either (a) that ephemeral-DPoP-with-deletion is operationally infeasible at scale, or (b) that there is a correlation mechanism DPoP cannot suppress even with ephemeral keys (see Attack 2).

- **In-threat-model?** No — construction must address this. The gap is specifically in §8.1 and the FS-REPLAY proof sketch.

---

### Attack 2: RFC 8693 token exchange with PPID `act` claims breaks delegation graph linkability

- **Attack:** Section 8.2 attacks WIMSE/SPIFFE for stable SPIFFE IDs in plaintext SVIDs. Fair. But the construction never engages with RFC 8693 token exchange used *without* SPIFFE. RFC 8693 §4.1 produces a composite token with an `act` claim representing the acting party. If the AS assigns pairwise pseudonymous identifiers (OIDC PPID, RFC 8693 §2.1 subject) per `{delegator, resource_server}` tuple, the `act` chain observed by any RS is a per-RS pseudonym — structurally different at each RP, not linkable across RSes. Delegation depth is visible as `act` nesting depth, but the identities at each layer are pseudonymous per-audience.

  The specific claim under attack is that "delegation graph is structural and key-independent" (§8.2). RFC 8693 + PPID at each hop makes the graph non-structural from any single RS's vantage point. The AS sees the real chain — but the IND-FS-AGENT game (§3) has the adversary compromise the *agent key*, not the AS. An AS with no long-term logs and PPID delegation chains provides linkability resistance matching the construction's claim under the same threat model.

- **Why it works / fails:** The construction's §8.2 rebuttal is scoped to WIMSE/SPIFFE only and does not engage RFC 8693 PPID delegation. This is a genuine gap. The defense would need to argue either that PPID-based RFC 8693 still leaks at the AS (true, but outside the threat model as defined) or that per-RS pseudonymization is insufficient for cross-session unlinkability within a single RS — which requires a different argument than §8.2 currently provides.

- **In-threat-model?** No — construction must address this directly.

---

### Attack 3: Secure deletion is an operational assumption in both constructions — the "cryptographic guarantee" label is unearned

- **Attack:** Section 8.3 attacks the OAuth baseline: "No proof of deletion exists in any RFC. Memory forensics can recover 'deleted' keys." Correct. But the IND-FS-AGENT game (§3) explicitly states "does NOT have deleted epoch secrets or blinding factors (secure deletion assumption)." The construction's forward secrecy property is *entirely load-bearing* on `s_e` and `r_e` being irreversibly gone after epoch transition.

  The security argument (§4) says "Bolyra's security is a property of Poseidon preimage resistance + hiding commitments, not runtime hygiene." But Poseidon preimage resistance is only relevant *after* `s_e` is deleted. If `s_e` is recoverable via OS swap, cloud snapshot, cold boot, or kernel memory forensics — the same attacks that compromise "operationally deleted" OAuth keys — the construction provides no forward secrecy. The distinction between "runtime hygiene" (baseline) and "Poseidon preimage resistance" (Bolyra) is a category distinction that evaporates unless the deletion guarantee is cryptographically enforced (e.g., via TEE with remote attestation). The construction provides no such mechanism.

  This is not merely philosophical: the CFPB whistleblower scenario (§7) and the 30-day SECU agent (§7) both involve adversaries who "seize" hardware or cause "key leaks" — exactly the scenarios where OS-level deletion is unreliable.

- **Why it works / fails:** The construction does not provide a cryptographic deletion primitive. Its claimed advantage over the baseline — cryptographic guarantee vs. operational hygiene — rests on a deletion assumption that is operationally enforced in both cases. Without a TEE attestation story or a cryptographic commitment-to-deletion scheme, §8.3 attacks the baseline for a flaw the construction shares.

- **In-threat-model?** Yes, but the construction survives *only if* it acknowledges the secure deletion assumption is operational and adds a note that TEE/HSM deployment is required to make the guarantee meaningful. As written, the §8.3 attack on the baseline is self-undermining.

---

### Attack 4: Threat model conflation — the IND-FS-AGENT game does not isolate the property the baseline actually lacks

- **Attack:** The IND-FS-AGENT game (§3) has the adversary receive `s_T` and credential key material at time T. Section 8.1 then argues the baseline fails because "AS logs `sub + jkt` per session." But this means the baseline fails under a *different* compromise — AS log access, not agent key compromise. The construction is comparing:
  - **Its own game:** adversary has agent key, no AS access
  - **Baseline failure mode:** adversary has AS logs, may or may not have agent key

  These are incomparable threat models. Under the *same* threat model as IND-FS-AGENT (adversary has agent key, no AS access, no RS logs), a baseline using: ephemeral DPoP keys (destroyed per session) + PPID subjects (RFC 7519 `sub` pairwise per RS) + a stateless AS (no session logs, token validity via JWT claims only, RFC 9728 PRM for RS autodiscovery) provides:
  - **Unlinkability across RSes:** PPID `sub` per RS
  - **Replay resistance:** ephemeral DPoP key destroyed; `jti` claim in JWT with short TTL
  - **No persistent correlator in the agent key:** the long-term key signs credential assertions, not session tokens; prior ephemeral keys are gone

  The construction must demonstrate that this specific configuration — stateless AS + ephemeral DPoP + PPID — fails the IND-FS-AGENT game. It does not. The §8.1 rebuttal assumes a logging AS, which is an implementation choice, not an RFC requirement.

- **Why it works / fails:** Section 8.4 claims "The baseline fails (c) via `sub`/SPIFFE ID." This is true for naive deployments but not for the hardened configuration above. The construction's differentiating property — epoch commitments unlinkable to known key material — is genuinely novel, but the claim that *no* RFC-based construction achieves this remains unproven. The game definition and the §8 baseline comparison use different adversary configurations, creating an unfalsifiable comparison.

- **In-threat-model?** No — construction must define a single coherent adversary model and demonstrate the hardened-baseline configuration fails *that specific game*, not just a logging AS deployment. This is the load-bearing gap in the "no bearer-token construction achieves this" claim.


## Persona: spiffe_engineer

---

### Attack 1: On-Chain Transaction Metadata Destroys Unlinkability

**Attack:**
Section 7 claims "attacker cannot even identify which commitments belong to the compromised agent." But `EpochRotation` proofs are submitted as on-chain transactions. Every submission carries transaction-layer metadata: sender address (or relayer address), gas price pattern, block timestamp, and nonce sequence. Even if `Poseidon2(s_e, r_e)` is cryptographically opaque per A5, the transaction submitting it is not. An adversary who observes the on-chain registry can cluster commitments by sender EOA, submission cadence (daily rotation in the SECU scenario), or gas price fingerprint — reconstructing the epoch chain without ever breaking Poseidon.

**Why it works / why it fails:**
The construction's security argument (§4, Cases 1-4) is purely over the *values* of circuit outputs. It says nothing about the *metadata envelope* of on-chain publication. In the SECU scenario, daily EpochRotation transactions from the same relayer wallet trivially identify 30 prior commitments. A5 (hiding under blinding) is not violated — the values are opaque — but the adversary doesn't need to break A5. They just read `tx.from` or correlate block timestamps to the known deployment date of the agent.

**In-threat-model?** No. The construction must address either (a) private relayer rotation per epoch, (b) mix-net submission, or (c) a batched commitment scheme that obscures per-agent transaction patterns. Section 3's adversary model says "full on-chain registry read access" but does not restrict access to transaction metadata. The claim in §7 is not supported.

---

### Attack 2: WIMSE Ephemeral WProT Keys Approximate IND-FS-AGENT Without ZK

**Attack:**
Section 8.1 attacks DPoP's `sub + jkt` logging, and §8.2 dismisses WIMSE delegation chains as metadata-leaking. But the WIMSE architecture (draft-ietf-wimse-arch §5) separates the *context token* (bound to the workload SPIFFE ID, issued once per session establishment) from the *workload proof-of-possession token* (WProT, per-request ephemeral key). If each epoch is a fresh WIMSE session with a freshly generated WProT key pair, and the AS issues context tokens using PPID-style pairwise sub per RP, then: (a) the AS never observes a stable correlator across epochs, (b) WProT keys are ephemeral and not retained, and (c) SD-JWT selective disclosure hides policy attributes. Now define the IND-FS-AGENT game over this construction — where does it fail?

**Why it works / why it fails:**
The construction's §8.4 claims IND-FS-AGENT requires "(d) on-chain commitments unlinkable to known key material," but this is a *design choice* of Bolyra's on-chain registry, not a logical necessity of the security game. WIMSE with ephemeral per-epoch WProT keys and PPID subs has no on-chain footprint at all — there is nothing to link. The construction needs to demonstrate that WIMSE's AS-side session logs (which do exist even with PPID) constitute a linkable correlator equivalent to the stable `sub` it attacks in §8.1. Simply asserting "SPIFFE IDs are stable" misses the WIMSE token exchange layer, which is specifically designed to break that stability.

**In-threat-model?** No. The construction must either (a) show that WIMSE ephemeral WProT key rotation fails the IND-FS-AGENT game with a concrete distinguisher, or (b) scope the claim narrowly to "SPIFFE SVID-based constructions without token exchange," not "no baseline achieves this."

---

### Attack 3: Secure Deletion Is an OS Assumption Dressed as a Crypto Assumption

**Attack:**
The entire forward-secrecy argument reduces to: "adversary does NOT have deleted epoch secrets (secure deletion assumption)" (§3). But this is listed as an *operational* precondition, not a named crypto assumption. Assumptions A1-A5 are all Poseidon-layer — none of them say anything about whether `s_{e-1}` is actually gone from memory. In any realistic deployment: swap partitions, Linux `/proc/[pid]/mem` forensics, hibernation images, core dumps on crash, and HSM-less container environments can all retain `s_e` values that the application believes it deleted. SPIRE with TPM-backed node attestation stores SVID private keys in hardware — the key *cannot* be extracted even under OS compromise. Bolyra's software-level `s_e` deletion has no such guarantee.

**Why it works / why it fails:**
Section 8.3 dismisses "operational deletion" as insufficient for the *baseline*, calling it "not a crypto guarantee." But Bolyra's own forward secrecy rests on exactly that — software deletion of `s_e`. The asymmetry is not justified. A1 (Poseidon preimage resistance) only matters if `s_e` is gone; if the OS retains it in swap, A1 is never even invoked. The SECU deployment scenario (§7) says "agent samples `r_e`, publishes commitment, deletes `(s_{e-1}, r_{e-1})`" — but deletion in a containerized Claude agent is not verifiable, auditable, or hardware-enforced.

**In-threat-model?** Partial. The construction correctly identifies this as a prerequisite but does not model the adversary's ability to recover `s_e` from OS artifacts. It should either (a) add a hardware enclave requirement (SGX/TDX/ARM CCA) as a named deployment constraint, or (b) add a "soft deletion failure" sub-game and show the security degradation. The whistleblower scenario (§7) is especially exposed — a seized agent device under forensic analysis has no cryptographic protection against memory recovery.

---

### Attack 4: SPIRE ZK Attestor Plugin Is the Right Abstraction Layer

**Attack:**
SPIRE's plugin architecture supports custom `NodeAttestor` and `WorkloadAttestor` implementations. A ZK epoch attestor could be written as a SPIRE plugin: the workload proves epoch membership via a PLONK circuit, SPIRE issues a short-lived X.509 SVID tied to that epoch's commitment, and the SVID TTL enforces epoch rotation. You get: Workload API integration (gRPC socket, no bearer token), X.509 mTLS (PFS via ECDHE, so past TLS sessions are protected by session key forward secrecy independent of SVID compromise), SPIFFE federation across trust domains (SECU → another CU without bespoke delegation circuits), and existing SPIRE operational tooling. The EpochRotation and ForwardSecureAgentSession circuits (§2.4-2.5) become a single SPIRE attestor plugin. Why is a new protocol registry preferable to an attestor plugin that plugs into existing SPIFFE infrastructure?

**Why it works / why it fails:**
The construction never engages with this objection. Section 8.2 says "SPIFFE IDs are stable" — true for static workloads, but a ZK attestor can issue *epoch-scoped* SPIFFE IDs (`spiffe://bolyra.io/agent/{epochCommitment}`) where the path component changes each epoch. The SVID is then epoch-bound by construction, issued by SPIRE after ZK attestation, and the short TTL means SPIRE never reissues the same SVID twice. The on-chain registry becomes optional — SPIRE's internal store serves as the commitment registry, and SPIRE's federation protocol handles cross-institution delegation. The construction's novel contribution shrinks to "a PLONK circuit for epoch attestation" — valuable, but not a new protocol.

**In-threat-model?** No — this is an architectural objection, not a cryptographic break. But it challenges the *necessity* of the construction as a standalone protocol. The construction should either (a) demonstrate a capability that SPIRE's plugin architecture cannot support (e.g., the on-chain nullifier's public verifiability without trusting a SPIRE server), or (b) explicitly position itself as a SPIRE attestor plugin rather than a competing identity protocol. The current §8 comparison set (DPoP, WIMSE, SPIFFE) treats SPIFFE as a fixed target rather than an extensible platform.
