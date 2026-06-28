# Tier 3 Adversarial — C2 Cross-scope unlinkability

## Persona: auth0_pm

### Attack 1: scopeId Is a Public Input — AS Reconstructs the Merchant Graph Anyway

- **Attack:** `scopeId` is listed as a **public input** to `ScopeBlindAuth` (§2, Public Inputs table). When a proof is submitted on-chain for verification, `scopeId` appears in plaintext in the transaction calldata. The construction defines `scopeId = Poseidon(domain)` (e.g., `Poseidon("merchant-a.example.com")`). Merchant domains are publicly enumerable — I can precompute `Poseidon` of every merchant in the US in under an hour. Desert Financial (the adversarial AS) watches the on-chain verifier contract, computes the inverse lookup table, and reconstructs exactly which RSes Alice's agent visited, even though `scopePseudonym` is unlinkable. The batch relayer obscures *when* within a 30-second window, but not *where*. §7's claim that "Desert Financial has zero visibility into which merchants the agent contacted" is false as written.

  The construction partially acknowledges this in §7: "mitigatable by salting the domain hash with a shared RS-agent secret." But this mitigation is parenthetical, not designed into the core circuit. The public input table has no salt. The IND-UNL-AS game in §3 does not model this attack surface (the adversary in the game controls the AS and sees on-chain state, but the game doesn't include the adversary querying public contract events).

- **Why it works:** The unlinkability proof in §4 reduces to POS-PRF on `scopeBlindingSecret` and `credentialCommitment` — but the reduction never addresses the plaintext `scopeId` leaking in the proof's public inputs. `scopePseudonym` is unlinkable; `scopeId` is not, and it directly identifies the RS.

- **In-threat-model?** **No.** The IND-UNL-AS game in §3 grants the adversary "all AS-side logs" and "network-level observation of proof submission timing and metadata" — but does not explicitly model the adversary querying on-chain public inputs of submitted proofs. The construction must either (a) make `scopeId` a private input and verify via ZK (adding ~800 constraints + a new commitment scheme), or (b) mandate an opaque `scopeId` salt at the protocol level and add it to the formal game.

---

### Attack 2: The Batch Relayer Is an Unnamed Trusted Third Party

- **Attack:** Section 3 states the adversary controls "the Authorization Server (full control)" and "up to k-1 of k total Resource Servers." The batch relayer is not in the threat model at all. In §7, "CU*Answers" is designated as the relayer operator. CU*Answers sees every proof *before* batching: raw proof bytes, submission timestamp (sub-second resolution), source IP, and the public inputs including `scopeId` (see Attack 1). The construction claims the relayer "cannot link" proofs because `credentialCommitment` is private — but the relayer doesn't need to break the ZK circuit to correlate. It just logs submission metadata. The adversary advantage bound of `1/m` in §3 (timing sub-game) assumes submissions within an epoch are indistinguishable to the relayer, which is false: the relayer is the *submission endpoint*, not a passive observer of the shuffled output.

  Furthermore, "Who operates the batch relayer in production?" has no answer for enterprises that aren't CU*Answers members. A hospital network using the healthcare scenario (§7) would need to spin up their own relayer or trust a Bolyra-operated one. Neither path is specified.

- **Why it works / why it fails:** The construction's timing defense is sound *against a network observer who sees only the on-chain batch submission*. It fails against an adversary who IS the relayer — or who compromises the relayer. Every enterprise procurement team will ask "who runs this?" and the honest answer today is "an unspecified operator you also have to trust."

- **In-threat-model?** **No.** The relayer is explicitly called out as a mitigation component but is not modeled as a potential adversary. The threat model should either (a) include an honest-but-curious relayer variant of the game and show that proof metadata is insufficient to de-anonymize, or (b) replace the relayer with an oblivious submission mechanism (e.g., private mempools, threshold relay networks). As written, the construction trades "trust Auth0's AS" for "trust the batch relayer operator" — a lateral move, not an improvement, for most enterprise buyers.

---

### Attack 3: scopeBlindingSecret Is a New Key Management Obligation with No Recovery Path

- **Attack (buyer-level):** WorkOS, Auth0, and Stytch manage all cryptographic state server-side. An enterprise operator pastes an API key and gets MCP auth. This construction requires every agent to locally generate and durably store a 251-bit random scalar (`scopeBlindingSecret`) per credential. The construction says it is "stored alongside the agent's credential material" (§5) but provides no specification of what that means — HSM? OS keychain? Encrypted file? If the `scopeBlindingSecret` is lost, the agent loses `scopePseudonym` continuity at every RS it has ever visited: it cannot prove it is the same agent that previously authenticated at Merchant-A, because `Poseidon2(scopeId_A, new_secret) ≠ Poseidon2(scopeId_A, old_secret)`. If it is *compromised*, an attacker who obtains `scopeBlindingSecret` can de-anonymize the agent across all scopes by computing `Poseidon2(scopeId_X, scopeBlindingSecret)` for every known `scopeId_X` and matching against on-chain records (compounding Attack 1).

  The construction explicitly distinguishes `scopeBlindingSecret` from `credentialCommitment` to prevent brute-force correlation (§5: "NOT derived from the credential commitment") — but this correct design decision creates an additional secret that enterprises must protect, rotate (rotation is undefined), and recover (recovery is undefined).

- **Why it works:** OAuth delegates all state management to the AS. This construction shifts secret management to the agent operator — for a credential that was specifically invented to remove AS involvement. Enterprise buyers evaluate operational complexity, not just cryptographic elegance. "You now have two secrets to manage instead of one, and losing the second one silently breaks account continuity at every RS you've ever used" is a procurement blocker.

- **In-threat-model?** **Partially.** The construction is aware the secret is sensitive and specifies its domain. But loss/rotation/recovery are completely unaddressed. This is not a cryptographic weakness — the threat model correctly models compromise — but the construction provides no mitigations and no operational guidance. A one-paragraph §9 on key lifecycle would close this, but it doesn't exist.

---

### Attack 4: The Formal Security Argument Is a Sketch, Not a Proof — Enterprises Cannot Buy a Sketch

- **Attack:** §4 explicitly states: "QED (sketch). Full formal proof would proceed via hybrid argument over the number of colluding RSes and delegation hops." The POS-PRF assumption applied to Poseidon2 and Poseidon3 is non-standard — Poseidon was designed for ZK circuit efficiency, not as a PRF. The IACR literature on Poseidon security (Grassi et al. 2019, USENIX Security 2021) provides collision resistance and preimage resistance arguments, but PRF security of Poseidon keyed on one coordinate of a two-input hash is a distinct claim that requires its own reduction. The construction asserts it ("Poseidon2(scopeId, ·) keyed on scopeBlindingSecret is a PRF") without citing a theorem.

  Auth0 has SOC 2 Type II, ISO 27001, and FIPS 140-2 validated cryptographic modules. When a Fortune 500 CISO asks "what is your cryptographic assurance level?", the answer cannot be "we have a reduction sketch to a non-standard PRF assumption on a hash function designed for a different purpose." WorkOS recently completed a third-party cryptographic review of their MCP auth implementation. The construction has had zero external review.

  More concretely: the hybrid argument in §4, step 3 ("joint leakage") claims that `scopePseudonym_A` and `scopeBoundDelegationAnchor_A` are "derived from independent secrets." But they are NOT fully independent: both are derived from circuit inputs that share the same `credentialCommitment` as a component. The hybrid argument needs to establish that the joint distribution of `(Poseidon2(scopeId, sbs), Poseidon3(scopeId, perm, cc))` is computationally indistinguishable from two independent random values — which requires a joint PRF security statement that is not cited or proven.

- **Why it works:** For CTF/academic contexts, a reduction sketch is fine. For enterprise procurement, a sketch is a liability. "We will have a formal proof later" maps to "we don't have one now." Combined with solo-founder status, no third-party audit, and a non-standard cryptographic assumption, this gives any procurement security team four independent reasons to reject the construction without engaging its technical merits.

- **In-threat-model?** **Yes (cryptographic claim is coherent) but unsubstantiated.** The IND-UNL-AS game is correctly scoped. The attack is that the security proof supporting the game is incomplete (step 3 joint leakage) and rests on a non-standard assumption. This is addressable: commission a formal proof or cite a theorem from the Poseidon literature that covers the PRF-on-one-coordinate case. Until then, the claimed strength-9 rating is unsupported by a verifiable argument.


## Persona: cryptographer

> Applied cryptographer, IACR publications, reviews for CRYPTO/EUROCRYPT/S&P. Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. You gave me a game definition and a reduction sketch. Now let me break them.

---

### Attack 1: AS-as-Issuer Knows the Poseidon3 Key — PRF Assumption Collapses for `scopeBoundDelegationAnchor`

- **Attack:** The adversary is the AS. The AS signs the credential commitment at enrollment time, meaning the AS has computed and stored `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` and knows `permBitmask`. Both are required to compute `scopeBoundDelegationAnchor = Poseidon3(scopeId, permBitmask, credCommitment)`. The `scopeId` for any RS is `Poseidon(domain_string)`, where domain strings are publicly enumerable. So the AS can compute the full preimage of `scopeBoundDelegationAnchor` for every candidate RS without any oracle access.

  Concretely: the AS enrolls Alice's agent, records `(modelHash, opPubAx, opPubAy, permBitmask=0b00000101, expiry)`, derives `cc`, and precomputes a table `{ scopeId_RS : Poseidon3(scopeId_RS, 0b00000101, cc) }` for all known merchant domains. Then it polls the on-chain `lastScopeBoundAnchor` mapping and matches. This is a table lookup, not a PRF break.

- **Why it breaks the construction:** Section 4 ("Reduction sketch: IND-UNL-AS → POS-PRF") states:

  > "Cross-scope linking requires inverting Poseidon3 to extract the shared (permBitmask_b, cc_b) suffix, which reduces to breaking POS-PRF."

  This statement is flatly false under the adversary model the construction itself specifies ("The adversary controls the Authorization Server — **full control, issues credentials, logs all interactions**"). A PRF `F_k(x)` is secure when the key `k` is *secret*. The AS is the keyholder — it computes `k = (permBitmask, cc)` at issuance. No inversion is required. The adversary evaluates `F_k` directly.

  The `scopePseudonym = Poseidon2(scopeId, scopeBlindingSecret)` is correctly protected because `scopeBlindingSecret` is agent-local and the AS never sees it. But `scopeBoundDelegationAnchor` is always a public output (Section 2, circuit public outputs, non-delegation flows included), and its PRF key is fully known to the exact adversary the game models.

- **In-threat-model?** **No.** This is within the stated threat model (adversarial AS). The construction must either (a) remove `scopeBoundDelegationAnchor` from public outputs for non-delegation flows, (b) add a fresh per-proof secret into the anchor derivation (analogous to `scopeBlindingSecret`), or (c) restrict the unlinkability claim to `scopePseudonym` only and restate the game accordingly. As written, §7's claim that "Desert Financial has zero visibility into which merchants the agent contacted" is false.

---

### Attack 2: Batch Relayer Is an Unnamed Trusted Third Party — Game Assumption Is Violated Operationally

- **Attack:** The IND-UNL-AS game (§3) states: "In the ZK system, `A` receives nothing — the agent proves locally." Section 2 introduces a "batch relayer" that receives fully formed `ScopeBlindAuth` proofs from agents, shuffles them, and submits them on-chain. The relayer receives every proof's public inputs and outputs: `(scopeId, scopePseudonym, nonceBinding, agentMerkleRoot, scopeBoundDelegationAnchor)`. The relayer observes which `scopeId` accompanies which `scopePseudonym`.

  In §7, the batch relayer is operated by CU*Answers, the CUSO that also serves 150+ credit unions — including Desert Financial (the adversarial AS). CU*Answers is a legal affiliate of Desert Financial's ecosystem. If CU*Answers shares logs with Desert Financial (or is compelled to under a BSA information-sharing agreement), the AS sees `(scopeId_B, scopePseudonym_B)` for every proof — linking which RS was contacted.

- **Why it works:** The game treats the batch relayer as outside the adversary's control (it is listed neither as a compromised party nor as a trusted party). This is an unmodeled entity. The security argument says "the relayer sees proofs but cannot link them," but the relayer sees `scopeId` in the clear as a public input. At a minimum, the relayer learns the traffic graph `(scopeId_A → scopePseudonym_A, scopeId_B → scopePseudonym_B)` within each epoch. If those `scopeId` values map to known merchant domains, the graph is the exact information the construction claims to protect.

  The timing defense argument reduces adversary advantage to `1/m` per epoch, but this only bounds timing-based correlation *within* a batch. It does not bound leakage to the relayer itself.

- **In-threat-model?** **No.** The formal game does not model the relayer's trust boundary. The construction needs a formal definition of what the relayer is permitted to see and under what cryptographic assumption (oblivious relay, secure enclave, trusted third party, etc.). Without it, the batch relayer is a gap between the formal model and the deployment scenario.

---

### Attack 3: Groth16/PLONK Trusted Setup — Subverted SRS Enables Witness Extraction, Breaking ZK

- **Attack:** The `ScopeBlindAuth` and `ScopeBlindDelegation` circuits use PLONK (universal SRS). Section 5 notes the agent circuits use "PLONK (agent circuit — universal setup)." The universal SRS for PLONK has a trapdoor (the toxic waste from the Powers of Tau ceremony). If the party who ran the SRS ceremony retained the trapdoor `τ`, they can extract the full witness from any valid PLONK proof — including `scopeBlindingSecret`.

  Once `scopeBlindingSecret` is extracted, cross-scope pseudonym linkability is trivial: `scopePseudonym_B = Poseidon2(scopeId_B, scopeBlindingSecret)` is computable for any `scopeId_B`. The entire unlinkability claim depends on `scopeBlindingSecret` remaining private; the PLONK setup is the only cryptographic barrier.

  The construction says the Groth16 `HumanUniqueness` circuit reuses the public Semaphore v4 ceremony (multi-party, widely audited). But for the agent circuits, the SRS provenance is unspecified. Section 2 says `pot16.ptau` is used for Groth16 project-specific keys with no mention of how it was generated or who verified it.

- **Why it matters formally:** The IND-UNL-AS game in §3 lists "the agent's local proving environment (trusted execution)" as outside adversary control. But the proving environment's security depends on the SRS used to compile the proving key. A subverted SRS doesn't compromise the proving *environment* — it compromises the *proof system*. This is a gap in the threat model.

  The security argument (§4, Assumption 4) states knowledge soundness holds "in the generic group model + random oracle model." Neither the GGM nor the ROM accounts for a subverted SRS. Simulation extractability of Groth16/PLONK is proven under *honestly generated* CRS. Under a subverted CRS, the zero-knowledge property fails; there is no known reduction that preserves ZK under CRS subversion.

- **In-threat-model?** **No.** The game explicitly excludes the prover environment from adversary control but does not specify the trust model for the SRS generation. The construction must either (a) cite a specific multi-party computation (MPC) ceremony for `pot16.ptau` and the PLONK SRS, or (b) state that SRS subversion is out of scope and remove "full control" from the AS's adversary capabilities, or (c) use a transparent proof system (STARKs, FRI) where no toxic waste exists.

---

### Attack 4: IND-UNL-AS Uses Static Corruption — Delegation Chain + Adaptive Adversary Is Unhandled

- **Attack:** The IND-UNL-AS game (§3) fixes the adversary's coalition at challenge time: "adversary controls up to `k-1` of `k` total Resource Servers." This is a *static corruption model*. In UC and standard composition frameworks, the natural model for multi-RS settings is *adaptive corruption*: the adversary can choose which RSes to corrupt after observing on-chain state.

  With delegation: the delegation chain at RS-A produces `newScopeBoundAnchor` values on-chain after each hop. These are visible to the adversary at any point. Suppose the adversary initially corrupts only RS-A. After the challenge phase, they corrupt RS-B as well. They now see `scopeBoundDelegationAnchor_B` retroactively from the RS-B log. Under static corruption, the game says the adversary never sees RS-B's public signals. Under adaptive corruption, they do.

  The reduction sketch (§4, item 4) argues that each hop is a "fresh PRF evaluation at the same `scopeId_A` under different keys (different delegatees)." But this argument is per-scope: it says nothing about the adversary adaptively learning `(scopeId_B, scopeBoundDelegationAnchor_B)` after the challenge and using it to mount a correlation attack against the proof already submitted at RS-B during the challenge phase.

- **Why the static model is insufficient here:** The IND-UNL-AS game's challenge phase requires proof `π_B` to be generated for `agent_b` at `scopeId_B`. That proof is submitted to the on-chain verifier and its public outputs are permanently on-chain. If the adversary adaptively corrupts RS-B post-challenge, they retrieve `scopeBoundDelegationAnchor_B = Poseidon3(scopeId_B, permBitmask_b, cc_b)`. Combined with Attack 1 (AS knows `permBitmask_b` and `cc_b`), they compute `Poseidon3(scopeId_B, permBitmask_b, cc_b)` directly and match.

  Even setting Attack 1 aside: the static model means the reduction sketch is incomplete. A proper UC treatment would require the simulator to handle adaptive corruptions without rewinding, which is a strictly harder requirement. The paper offers no argument that the construction is UC-secure or that the static game is adequate for the multi-RS deployment scenarios described.

- **In-threat-model?** **No.** The deployment scenarios (§7) describe long-lived agents interacting with many RSes over time — exactly the setting where adaptive corruption is realistic. The security definition should be restated against an adaptive adversary, or the scenarios should explicitly bound what the construction protects and what it does not (e.g., "this construction is secure against a static coalition fixed before the first proof is generated").

---

**Summary table:**

| Attack | Breaks what | Severity |
|--------|-------------|----------|
| 1 — AS knows Poseidon3 key | `scopeBoundDelegationAnchor` unlinkability | Critical — trivial table lookup, no cryptographic hardness required |
| 2 — Batch relayer unmodeled | AS-off-critical-path assumption | High — operationally likely in the described deployment |
| 3 — SRS subversion | ZK of `scopeBlindingSecret` | High — defeats the only secret the `scopePseudonym` relies on |
| 4 — Static corruption model | Delegation chain security under adaptive adversary | Medium — theoretical gap, exploitable in practice with Attack 1 |


## Persona: cu_ciso

### Attack 1: The AS Sees Nothing — So Does My NCUA Examiner

**Attack:** The construction's central architectural claim (§8, "Structural impossibility 1") is that Desert Financial's AS is "reduced to one-time credential enrollment" and "has zero visibility into which merchants the agent contacted, when, or how often." From a privacy standpoint that's the point. From a regulatory standpoint, it destroys my audit posture.

NCUA Part 748 Appendix A (Guidelines for Safeguarding Member Information) requires a written information security program with "access controls on customer information systems" and "monitoring systems and procedures to detect actual and attempted attacks." FFIEC CAT Category "Cyber Incident Management" requires that I demonstrate *after the fact* who accessed what and when. If a member's agent transacts fraudulently at Merchant-A, my examiner will ask me to produce the authorization log. My answer is: "The agent proved a ZK circuit locally; nothing was logged." The examiner's next question is: "Where is your audit trail?" The construction has no answer.

The batch relayer's on-chain transaction hash is not an audit trail a Tier 1 examiner can read. An epoch-batched Poseidon hash is not a GLBA-compliant access log.

**Why it works / why it fails:** The construction never addresses NCUA Part 748 §III.C ("Access Control and Authorization Records") or FFIEC CAT Maturity Level 2 ("Logs of access to sensitive systems are retained"). The security argument is cryptographically tight but institutionally illiterate — the threat model (§3) only considers cryptographic adversaries, not regulatory auditors. The construction does not propose an off-path audit substrate (e.g., a privacy-preserving disclosure protocol the CU controls that can produce court-admissible access records without revealing the merchant graph to the AS).

**In-threat-model?** No — the construction must address this. A log-nothing architecture is not deployable at a federally-regulated institution regardless of cryptographic elegance.

---

### Attack 2: Key Custody — "Generated Locally" Is Where My Risk Lives

**Attack:** Section 5 (Bolyra primitive mapping) states: "The `scopeBlindingSecret` is a new per-agent secret, generated once at agent enrollment and stored alongside the agent's credential material." Section 7 states: "Alice's agent generates a random `scopeBlindingSecret` locally." Neither section specifies *where* "locally" is.

I will now apply GLBA Safeguards Rule (16 CFR Part 314, revised 2023) §314.4(c)(3): the CU must "assess the sufficiency of any safeguards in place to control [customer information]." The `scopeBlindingSecret` is customer information — it is the key that determines Alice's pseudonym at every merchant she ever visits. If it lives in browser localStorage: device wipe = permanent account lockout at every scope. If it's backed up to Desert Financial's server: that server is now the exact AS-level correlating entity the construction claims to eliminate. If it's in a hardware token: the construction has just mandated HSM deployment for every member, which no $2B credit union can operationalize.

The construction's Section 7 scenario hand-waves this entirely. Alice's "agent" is never specified — is it a browser extension, a mobile app, a cloud service? The `scopeBlindingSecret` recovery path (what happens when the member gets a new phone?) is nowhere discussed.

**Why it works / why it fails:** The unlinkability proof in §4 assumes `scopeBlindingSecret` is secret. If the secret is stored in a recoverable, centralized location (which member-facing usability requires), the entity holding the recovery copy can correlate pseudonyms across scopes — exactly the attack the circuit is designed to prevent. The construction argues against the AS as correlator but silently introduces a key-custody provider as a correlator. This is not a theoretical attack; it is the default implementation path for any credit union trying to deploy this.

**In-threat-model?** No — the construction must specify the key custody model and prove that the custody mechanism does not reintroduce a correlating entity. Ideally map it to a GLBA §314.4(c) compliant control.

---

### Attack 3: The Batch Relayer Is an Unmanaged Critical Vendor

**Attack:** Section 7 introduces "CU*Answers batch relayer" as the timing-correlation mitigation, submitting epoch-batched proofs for "agents across all 150 member credit unions." The entire timing defense (§3, side-channel sub-game) depends on this relayer. Without it, the adversary's timing advantage is unbounded (one proof per agent per event = perfect correlation). The construction gives it a single sentence and moves on.

Under NCUA Letter 07-CU-13 (Third-Party Relationships) and the interagency guidance on Third-Party Risk Management (2023), I must perform due diligence on any vendor "on the critical path of member-facing services." The batch relayer is now on the critical path for *every member agent authorization*. My vendor management questions:

- What is the relayer's SLA? (The construction targets 30-second epochs — is that a contractual guarantee?)
- What is the relayer's disaster recovery RTO/RPO?
- Does the relayer pass SOC 2 Type II? (It processes aggregated proof metadata for 150 credit unions — it IS a covered entity under GLBA.)
- What happens if the relayer is unavailable? Does agent auth fail closed (no transactions) or fail open (proofs submitted individually, destroying timing privacy)?
- The relayer sees all `scopePseudonym` values across epochs. Over time, it can build a per-pseudonym frequency graph across scopes — which is exactly the merchant graph the construction is designed to prevent the AS from seeing. The construction says "cannot link" because each pseudonym is scope-specific, but a relayer that aggregates proofs from the same agent across multiple scopes *over time* can identify a persistent submitter by behavioral fingerprint even without cryptographic linking.

**Why it works / why it fails:** The batch relayer is trusted but unspecified. The construction never defines its trust model (§3 only defines AS and RS adversaries), never addresses its availability contract, and never addresses the behavioral fingerprinting attack a long-running relayer can mount. The timing defense is also trivially defeated if the CU deploys the construction without the relayer — and nothing in the construction makes the relayer mandatory or enforceable.

**In-threat-model?** No — the relayer is outside the formal threat model (§3) but is a load-bearing security component. The construction must either bring it inside the threat model or eliminate the dependency.

---

### Attack 4: Scope-Persistent Pseudonym = Surveillance Within Scope

**Attack:** Section 7 states: "Within a single scope (e.g., Merchant-A), Alice's agent always produces the same `scopePseudonym_A` (deterministic in `scopeId` and `scopeBlindingSecret`). Merchant-A can detect if Alice tries to register two accounts." The construction presents this as a *feature* (sybil resistance). My examiner sees it differently.

`scopePseudonym_A` is a persistent, unlinkable-across-scopes but *fully linkable within scope* identifier. Alice's agent uses it every time it visits Merchant-A. Merchant-A now has a permanent, stable pseudonymous identifier for Alice across all her sessions — indefinitely, across account resets, across device changes, across time. Under NCUA Regulation V (implementing FCRA affiliate sharing) and emerging state privacy laws (California CCPA, New York SHIELD Act), a stable identifier that enables longitudinal behavioral profiling at a merchant is functionally equivalent to a PII linkage.

The construction argues this is acceptable because Merchant-A cannot correlate with Merchant-B. But I'm the CU issuing the credential — Desert Financial. My member Alice has given me authority to issue her agent credentials. If Alice's agent builds a three-year behavioral history at Merchant-A under `scopePseudonym_A`, and Merchant-A is subpoenaed or breached, that behavioral profile is linked to Alice's credential commitment `cc` (which Desert Financial holds). Under GLBA §314, Desert Financial has an obligation to protect member information. A durable pseudonym that enables merchant-side profiling is member information that I issued and cannot retract.

The construction provides no pseudonym rotation mechanism, no expiry for `scopePseudonym`, and no member-controlled unlinkability within scope.

**Why it works / why it fails:** The construction solves AS-level cross-scope correlation but introduces RS-level within-scope dossier accumulation as a design choice. For a credit union operating under NCUA Regulation V and GLBA, the persistence of `scopePseudonym_A` is a regulatory liability — it is a stable identifier I issued that enables third-party behavioral surveillance of my member. The construction does not address pseudonym rotation, selective disclosure of session-level vs. account-level pseudonyms, or member rights to pseudonym reset.

**In-threat-model?** No — the construction explicitly accepts within-scope linkability as a design feature. It must address whether persistent pseudonyms violate the CU's GLBA obligations toward member data minimization, and provide a rotation or expiry mechanism that preserves sybil resistance while limiting longitudinal profiling risk.


## Persona: rfc7662_advocate

*OAuth Working Group veteran, a decade of production introspection. Every ZK claim is suspect until proven unreachable by RFC 7662 + extensions.*

---

### Attack 1: `scopeBoundDelegationAnchor` PRF key is held by the adversary — the POS-PRF reduction collapses

**Attack:**

The AS enrolled the agent's credential and therefore holds the exact values of `modelHash`, `operatorPubkeyAx`, `operatorPubkeyAy`, `permBitmask`, and `expiryTimestamp`. It computed `credCommitment = Poseidon5(…)` at enrollment time. It issued `permBitmask`. These are inputs to the PRF that the construction treats as a *secret key*.

`scopeBoundDelegationAnchor = Poseidon3(scopeId, permBitmask, credCommitment)`

The §4 security argument characterizes this as PRF-keyed-on-`(permBitmask, credCommitment)`, and argues security reduces to POS-PRF. A standard PRF assumption requires the key to be secret from the distinguisher. Here the distinguisher *is* the AS, and the AS *holds the key*.

The adversary's attack is a rainbow table: for each enrolled agent, precompute `Poseidon3(Poseidon(domain), permBitmask_i, cc_i)` over the finite set of plausible RS domains (publicly enumerable: merchant websites, healthcare provider URLs, credit union domains). Match against on-chain published anchors. This is a dictionary attack, not a cryptographic break.

The construction's §7 acknowledges this in passing: *"Kaiser sees only the on-chain delegation event, not which RS the scope ID refers to (the Poseidon hash of the domain is opaque to Kaiser unless Kaiser can brute-force the domain string, which is mitigatable by salting the domain hash with a shared RS-agent secret)."* But this mitigation is buried in a deployment note, does not appear in the formal circuit definition (§2), is absent from the IND-UNL-AS game (§3), and is not part of the §4 security reduction. The circuit emits `scopeBoundDelegationAnchor` as a public output with no salting.

**Why it works:** The POS-PRF reduction fails for any adversary that holds the PRF key. In the standard model, PRF security is stated for a *uniform random* key hidden from the distinguisher. The AS is not a random oracle receiving queries; it is a party with full knowledge of the key material. The §4 proof sketch does not account for this — it treats `(permBitmask, cc)` as opaque to the adversary, which is false in the credential-issuer threat model.

**In-threat-model?** Yes — the adversary is explicitly the AS, which is the issuer. The construction must either (a) include a per-agent, AS-unknown `scopeBlindingSecret` inside the delegation anchor (analagous to the `scopePseudonym` derivation), so the anchor becomes `Poseidon4(scopeId, scopeBlindingSecret, permBitmask, credCommitment)`, making the key partially secret from the AS; or (b) formally bound the adversary's domain enumeration advantage and show it is negligible when the domain space is large or salted. As written, the construction does not survive this attack.

---

### Attack 2: The batch relayer is an unmodeled adversary that sees `scopeId` in plaintext

**Attack:**

Section 2 introduces a batch relayer as the anti-timing gadget: *"a batch relayer collects `ScopeBlindAuth` proofs from multiple agents and submits them in a single on-chain transaction."* The relayer is credited with reducing timing correlation advantage to `1/m` per epoch.

But `scopeId` is a **public input** to `ScopeBlindAuth` — it must be, because the verifier checks that the proof was generated for a specific RS scope. The relayer receives each proof together with its full public signal vector, including `scopeId`, `scopePseudonym`, `nonceBinding`, and `scopeBoundDelegationAnchor`. The relayer therefore observes tuples of the form:

```
(scopePseudonym_i, scopeId_j, scopeBoundDelegationAnchor_k, timestamp)
```

for every proof it batches. A relayer that logs these tuples can reconstruct the exact cross-RS access graph that the IND-UNL-AS game is designed to hide. The §3 game defines the adversary as controlling *up to `k-1` RSes* and the AS. The batch relayer is not enumerated as an adversary class. CU*Answers, which §7 names as the relayer for 150 credit unions, would have visibility into every member agent's per-scope pseudonym across all RSes it serves.

The timing defense is real but orthogonal: the epoch hides *when within 30 seconds* a proof was submitted. It does not hide *which RS* from the relayer.

**Why it works:** The threat model gap is structural. Introducing the batch relayer as a mitigation creates a new trusted third party whose adversarial capabilities are unanalyzed. RFC 7662 introspection, by contrast, has well-understood trust boundaries: the AS is the single point of correlation. Bolyra replaces AS-as-correlator with relayer-as-correlator without formally bounding the relayer's advantage.

**In-threat-model?** No — the relayer is not in the adversary model defined in §3. This is a construction gap. Options: (a) route proofs through an anonymizing relay (e.g., mixnet submission, Tor hidden service), so the relayer receives blinded submissions; (b) model the relayer as semi-honest and prove that `scopePseudonym` alone is insufficient for the relayer to link across scopes without `scopeBlindingSecret`; or (c) extend the IND-UNL-AS game to include a colluding relayer and show the construction still holds. None of these is currently in the spec.

---

### Attack 3: `draft-ietf-oauth-jwt-introspection-response` (RFC 9701) removes the AS from the per-request path — "Structural Impossibility 1" is overstated

**Attack (from toolbox):**

Section §8 opens with: *"In OAuth/OIDC, every token is issued by the AS. The AS necessarily sees the `(agent, RS, scope, timestamp)` tuple at issuance time."* This is used to establish structural impossibility. The §8 framing conflates issuance-time visibility with per-request visibility, and the claim as written is refuted by RFC 9701.

RFC 9701 (`draft-ietf-oauth-jwt-introspection-response`) allows the AS to issue a **signed JWT introspection response** that the RS caches and validates locally — no introspection round-trip per request. Combined with OIDC pairwise subject identifiers (`sub` is sector-scoped, different per RS sector), RFC 8707 resource indicators (token is audience-bound to a specific RS), and RFC 9449 DPoP (token is sender-constrained to the client's DPoP key), the per-request AS visibility is eliminated. The AS sees the access event exactly **once per token issuance**, not per request.

For access tokens with a 1-hour lifetime serving agents that make dozens of calls per session, the AS's visibility is reduced by orders of magnitude. The baseline §8 criticizes is not RFC 9701 + PPID + DPoP — it is naive bearer token introspection from 2013. The actual comparison class available to an OAuth Working Group veteran is far stronger.

**Why it partially fails:** The attack is correct that §8 overstates the per-request claim — RFC 9701 eliminates per-request AS involvement. But the attack does not eliminate issuance-time correlation. When Alice's agent requests a token for Merchant-A with `resource=https://merchant-a.example.com` (RFC 8707), the AS records `(agent-credential, merchant-a, scope, timestamp)`. For Merchant-B, same. The AS's traffic graph is at **token-issuance granularity**, not per-request granularity — but it remains a complete graph. Bolyra eliminates issuance-time correlation entirely. This is the genuine structural difference.

**In-threat-model?** The attack is a valid challenge to the *framing* of §8, not to the underlying claim. The construction should be corrected to: *"The AS sees the complete RS access graph at token-issuance granularity, not per-request. RFC 9701 reduces per-request exposure but does not eliminate issuance-time correlation."* As written, §8's "structural impossibility" argument is vulnerable to this rebuttal from any RFC 9701 practitioner.

---

### Attack 4: `scopeId` is a public input — on-chain observers reconstruct RS access patterns; formal game and deployment privacy goal diverge

**Attack:**

`scopeId` is a public input to `ScopeBlindAuth` (§2 public inputs table). On-chain proof submissions include the full public signal vector. Any observer of the blockchain — including the AS, if it monitors on-chain state — sees `(scopePseudonym, scopeId)` pairs for every submitted proof.

The IND-UNL-AS game (§3) asks whether the adversary can link two proofs at *different scopeIds* to the *same agent*. Public `scopeId` does not break this game — `scopePseudonym_A ≠ scopePseudonym_B` by PRF security even though `scopeId_A` and `scopeId_B` are both visible.

However, §7's stated deployment goal is stronger: *"Desert Financial… has zero visibility into which merchants the agent contacted, when, or how often."* This goal is broken by public `scopeId`. The AS monitoring the chain sees `scopeId = Poseidon("merchant-a.example.com")` submitted by some agent. It cannot link that to *which of its enrolled agents* submitted it — but it knows Merchant-A was accessed, by *someone*, at a given epoch. For small populations (50 enrolled agents at a small CU), this access pattern leaks information about the population even without identity linking.

More precisely: the formal IND-UNL-AS game proves identity unlinkability (Agent-0 vs. Agent-1 cannot be distinguished). It does not prove RS access pattern hiding (which RSes were accessed by any agent). The §7 deployment goal requires the latter; the §3 game delivers the former.

**Why it matters operationally:** In the healthcare scenario (§7), the referral network is the sensitive data. If on-chain observers can see `scopeId = Poseidon("cedars-sinai.org")` being accessed by agents from Kaiser's enrolled population, the referral pattern is exposed at the population level even if no individual agent is identified. HIPAA minimum-necessary analysis would flag this.

**In-threat-model?** The formal game survives this attack — identity unlinkability holds. But the deployment privacy goal (§7) is not captured by the formal game (§3). The construction should either (a) strengthen the game to include RS access pattern hiding (an oblivious RAM-style definition), (b) make `scopeId` a private input with a commitment scheme (adding ~400 constraints for a Pedersen or Poseidon commitment), or (c) explicitly disclaim population-level access pattern privacy. The current spec implicitly claims a stronger privacy property in §7 than the formal game in §3 actually delivers.


## Persona: spiffe_engineer

---

### Attack 1: PRF Key Leakage — AS Knows the Credential Commitment

**Attack:** The security argument in §4 treats `(permBitmask, credCommitment)` as the unknown PRF key for `Poseidon3(scopeId, permBitmask, credCommitment)`. But the AS **enrolled the credential**. The AS computed or received every field in `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiryTimestamp)` and issued the EdDSA signature over it — which means the AS holds the full preimage.

Given that the AS knows `cc_alice` and `permBitmask_alice`, and `scopeId = Poseidon(domain)` is deterministic from public RS domain strings (credit union merchant directories are finite and enumerable), the AS can:

1. Enumerate all known RS domains → compute their `scopeId`s.
2. For each enrolled agent, compute `Poseidon3(scopeId_X, permBitmask_alice, cc_alice)` for every candidate RS.
3. Match against on-chain `lastScopeBoundAnchor` values.
4. Reconstruct Alice's exact merchant graph — with zero cryptographic effort.

The PRF reduction in §4 (Step 2 of the proof sketch) is invalid: it assumes the adversary does not know the PRF key, but the AS is the credential issuer, so it **is** the key holder. `scopePseudonym = Poseidon2(scopeId, scopeBlindingSecret)` survives because `scopeBlindingSecret` is locally generated and never disclosed; `scopeBoundDelegationAnchor` does not survive because its "key" is entirely AS-held.

**Why it fails against the construction:** The construction conflates AS-as-issuer with AS-as-verifier. The unlinkability argument holds for `scopePseudonym` (unknown blinding secret) but breaks for `scopeBoundDelegationAnchor` (AS knows all three inputs once `scopeId` is computable). The §8 "structural impossibility" narrative claims "AS sees nothing" — this is false for any agent that invokes delegation.

**In-threat-model?** **No — construction must address.** The IND-UNL-AS game (§3) explicitly places the AS as the adversary, but the reduction in §4 fails to account for the AS's enrollment-time knowledge of `credCommitment`. The fix requires either: (a) including `scopeBlindingSecret` in the delegation anchor derivation (e.g., `Poseidon4(scopeId, permBitmask, cc, scopeBlindingSecret)`), or (b) replacing the AS-issued `credCommitment` with an agent-generated commitment over a locally held secret that the AS never sees.

---

### Attack 2: scopeId Is a Public Enumeration Surface

**Attack:** `scopeId = Poseidon(domain:"merchant-a.example.com")` is deterministic from a public string. In the deployment scenarios (§7), the RS domain is a merchant website or healthcare provider — domains that appear in public directories (NCUA share insurance lookup, NPI registry, CU*Answers partner list). The SPIFFE trust domain is analogously public: `spiffe://trust-domain/path` — and SPIFFE engineers are used to the fact that identifier *structure* must be assumed public.

For the `scopePseudonym` specifically: knowing `scopeId_X` doesn't help because `scopeBlindingSecret` is private. But it enables a *targeting* attack: the AS can determine that proof `π_B` is for a known RS by checking whether the on-chain `agentMerkleRoot` and epoch align with known enrollment events, then testing candidate `scopeId`s against `scopeBoundDelegationAnchor` (see Attack 1). The batch relayer's epoch defense (§3 side-channel sub-game) bounds timing leakage but does not mitigate this precomputation attack.

§7 mentions salting `scopeId` with "a shared RS-agent secret" as a mitigation, but this secret is not formalized anywhere in the circuit definition, the IND-UNL-AS game, or the constraint set. It is an informal note, not a construction primitive.

**Why it works partially:** Domain enumeration narrows the adversary's search space from exponential to polynomial in the number of known RSes. Combined with Attack 1 (AS knows `cc`), this reduces to a lookup table attack with zero cryptographic hardness.

**In-threat-model?** **No — construction must address.** The RS-agent shared salt needs to be formalized as a circuit input (private to agent and RS, never seen by AS), incorporated into `scopeId` derivation, and added to the IND-UNL-AS game as an adversary capability constraint.

---

### Attack 3: Batch Relayer Is an Unanalyzed Trusted Third Party

**Attack:** The timing defense in §3 and §7 depends entirely on a "batch relayer" operated by CU*Answers. In SPIFFE, the workload API is a local Unix socket — there is no intermediary. In the Bolyra construction, the relayer:

- Sees every proof before submission (it must read them to batch them).
- Is operated by a CUSO that has contractual relationships with the AS (Desert Financial) and the merchant RSes.
- Is explicitly named as the aggregator for "proofs from agents across all 150 member credit unions."

This creates an undisclosed collusion surface: relayer + AS can correlate proof submission with enrollment epoch. The batch relayer knows *which* agents submitted proofs in a given epoch (it received them). If the relayer shares epoch membership lists with the AS — even without sharing the proofs themselves — the AS narrows the anonymity set from `m` (all proofs in epoch) to a much smaller set of agents the relayer observed.

The §3 side-channel sub-game states adversary advantage is `1/m`, but this bound assumes the relayer is honest and non-colluding. The threat model (§3) only excludes adversary control of "the agent's local proving environment" and "on-chain Merkle tree integrity" — the relayer is not mentioned as a trust boundary.

**Why it works:** The timing sub-game's `1/m` bound is correct only under an honest-relayer assumption that is never stated. In the CU*Answers scenario, the relayer is a natural AS ally (CUSO partner), making collusion a realistic business-layer attack with no cryptographic mitigation.

**In-threat-model?** **No — construction must address.** The threat model must either: (a) formally include the relayer in the adversary's capability set and show the batch mechanism survives (likely requiring an oblivious submission design, e.g., PIR or onion routing to the relayer), or (b) move proof submission to a decentralized mempool where no single relayer sees the agent-to-proof mapping.

---

### Attack 4: SPIFFE Extension Avoidance — The Wrong-Layer Argument

**Attack:** The §8 "structural impossibility" section lists five reasons OAuth cannot match the construction but never engages with SPIFFE's extensibility model. SPIRE supports pluggable node attestors via its plugin API. A ZK attestor plugin could:

1. Accept a `ScopeBlindAuth` proof as the attestation material.
2. Issue a JWT-SVID with a scope-specific `sub` field derived from `scopePseudonym`.
3. Bind the SVID to a DPoP-style proof-of-possession key held by the agent.

The WIMSE architecture draft (draft-ietf-wimse-arch) is explicitly scoping workload-to-workload identity for AI agent contexts and includes token binding and selective disclosure in its charter. The SPIFFE federation model (`spiffe://trust-domain-a/` federating with `spiffe://trust-domain-b/`) provides the "portable identity across credit unions" property that §7 describes as a novel Bolyra capability.

The construction's claim of "categorical architectural difference" (§8.1) rests on the premise that the AS is necessarily on the per-request path in OAuth. But SPIRE's SVID rotation model issues credentials at enrollment time and validates them locally — the SPIRE server is not on the per-request path after issuance. The gap between SPIRE SVIDs and Bolyra credentials is a ZK attestor plugin and a scope-pseudonym derivation convention, not a protocol-layer impossibility.

**Why it partially fails against the construction:** The SPIFFE engineer's attack is weakest on the formal security definitions gap. SPIRE SVIDs have no IND-UNL-AS game, no PRF reduction, and no timing mitigation. X.509 SVIDs are globally unique per workload — literal cross-RS correlators. JWT-SVIDs use `sub` values that are either SPIRE-assigned (AS-visible mapping) or per-SVID (no continuity). The `scopePseudonym`'s determinism-plus-unlinkability property (same pseudonym across sessions at the same RS, different pseudonym at different RSes) has no SPIFFE equivalent without exactly the ZK primitive Bolyra is proposing.

**In-threat-model?** **Yes — construction survives on cryptographic merits** but must address the WIMSE engagement gap. The §8 argument would be stronger if it cited WIMSE's current charter scope and identified the specific capability (`scopePseudonym` with IND-UNL-AS security) that is not covered by existing WIMSE work items. Contributing the ZK pseudonym primitive as a WIMSE extension mechanism — rather than a parallel protocol — would also accelerate adoption without requiring ecosystem abandonment.
