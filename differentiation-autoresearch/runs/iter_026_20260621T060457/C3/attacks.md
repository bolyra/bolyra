# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Proof generation timing is undefined — the "in-circuit enforcement at verification time" claim is marketing

- **Attack:** §8 lists "In-circuit enforcement at verification time" as a differentiator, contrasting it with "AS enforces narrowing at issuance time only." But the construction never specifies *when the DelegationAuditChain proof is generated*. If it is generated **post-hoc** (after the AI pipeline completes — which is the only viable deployment given §6's 2–3s proving time), then the enforcement happened at issuance time too: the pipeline already ran, the scopes were already committed on-chain, and the proof is just a compact certificate of what happened. The auditor is verifying a log, not catching live violations. WorkOS does this today with token introspection endpoints and encrypted audit trails — no Circom required. If the proof is generated **inline** (synchronously, in the hot path of a multi-tool pipeline), the 2–3s stall kills the product: modern tool calls complete in 50–500ms, and Navy Federal's loan pipeline (§7) would stall for seconds at each hop. The construction says nothing about this choice. The differentiation in §8 collapses to "we produce a more compact audit artifact" — which is a feature, not a product.

- **Why it works / why it fails:** The construction cannot have it both ways. "In-circuit enforcement" either means synchronous (untenable latency) or post-hoc (same enforcement model as OAuth token logs). Neither reading makes the comparison to WorkOS/Auth0 as strong as §8 implies.

- **In-threat-model?** No — the construction must specify the proof generation timing model and revise the §8 differentiation claim accordingly.

---

### Attack 2: Single `agentTreeRoot` makes "cross-org agent handoff" impossible without Bolyra as centralized trust anchor

- **Attack:** §2 defines a single `agentTreeRoot` public input, used in Constraint 9 to verify enrollment for every hop across the chain. §7's Navy Federal scenario involves agents from at least three organizations: Navy Federal (loan officer delegate), Equifax (credit pull), a risk vendor (scoring model), and an internal logging system. In practice, each of these organizations maintains its own agent registry for legal, security, and data sovereignty reasons. They will not enroll their agents into a shared on-chain Bolyra tree. The circuit has two choices: (a) **all orgs write to Bolyra's single on-chain tree** → Bolyra becomes the federation anchor, directly contradicting the "No trusted third party" claim in §8; (b) **multi-tree support** → the current circuit design breaks (Constraint 9 binds all hops to one root). §8 positions cross-org chain-in-single-artifact as a structural advantage over WIMSE federation, but the single-root assumption makes it a centralization risk equal to or worse than a shared AS.

- **Why it works / why it fails:** The construction's cross-org claim requires a shared enrollment namespace. Any enterprise deploying this must accept Bolyra as the enrollment authority — which is a harder procurement conversation than "use WorkOS, which already has your org in its directory."

- **In-threat-model?** No — the construction must either (a) extend the circuit to support per-hop root commitments (`agentTreeRoots[MAX_CHAIN_LEN]`) with a forest-of-roots design, or (b) explicitly scope the cross-org claim to deployments with a shared Bolyra registry and drop the "no trusted third party" differentiation.

---

### Attack 3: The history buffer creates a stale-root enrollment bypass that the DAF game does not close

- **Attack:** §2 specifies `agentTreeRoot` as "current agent Merkle root **or any root in the history buffer**." The DAF game (§3) defines enrollment bypass as: adversary produces a valid proof where "some intermediate delegatee's `credCommitment` is not a leaf in the agent Merkle tree." The game does not specify which root must be used — it only says the proof must reference "the agent Merkle tree." Scenario: Agent X is enrolled at root R₀, participates in a delegation chain at T=1, is **revoked** (tree updated to R₁ removing X) at T=2. An audit proof generated at T=3 uses R₀ as `agentTreeRoot` (valid history root). Constraint 9 verifies X against R₀ and succeeds. The auditor sees a valid proof confirming X was enrolled — but X's credential was revoked before the audit was requested. The construction calls this "enrollment proof" but it is actually "was-once-enrolled proof." The history buffer is referenced but never formally bounded: no maximum lookback window, no on-chain revocation epoch, no circuit constraint tying `agentTreeRoot` to `auditTimestamp`. An adversary who retains a stale root can prove enrollment for a revoked agent.

- **Why it works / why it fails:** The security game definition in §3 is too loose — "not a leaf in the agent Merkle tree" is meaningful only if the valid root is pinned to the audit timestamp. Without that constraint, the DAF game as written does not prevent stale-root bypass.

- **In-threat-model?** No — the construction must add a constraint linking `agentTreeRoot` to `auditTimestamp` (e.g., the root must have been current within a bounded window before `auditTimestamp`), and the DAF game must explicitly include stale-root forgery as a winning condition.

---

### Attack 4: The "solo founder" procurement veto — cryptographic correctness does not substitute for operational guarantees

- **Attack:** §7 names Navy Federal Credit Union as the deployment target. Credit unions of this size run multi-year procurement cycles with mandatory requirements for SOC 2 Type II, vendor financial stability assessments, indemnification clauses, 99.9% SLA with penalties, and named incident response contacts. The construction is entirely about cryptographic correctness — and it achieves that. But it provides zero answers to: Who do you call when `BinaryMerkleRoot` returns an incorrect result due to a circuit bug? What is the remediation SLA when the on-chain PLONK verifier contract needs an emergency upgrade? What is the liability if an audit proof is accepted by the NCUA and later found to have a soundness hole? Auth0 and WorkOS already have answers to all of these — signed vendor agreements, bug bounty programs, dedicated enterprise support, and legal entities with balance sheets. The construction's §8 comparison table has eight rows, none of which mention operational availability, support, or legal accountability. An Auth0 PM presenting to Navy Federal's procurement committee wins this meeting without discussing cryptography at all.

- **Why it works / why it fails:** Cryptographic novelty is not a procurement criterion. The construction needs a deployment model — managed service, open-source self-host, or third-party operator network — and an answer to the "what happens when it breaks" question before §7's concrete scenario is credible.

- **In-threat-model?** No (it is a go-to-market gap, not a cryptographic one) — but it is the veto that kills adoption before the circuit's security properties are ever evaluated. The construction should address the operational trust model explicitly, even if only to scope the claim to "self-hosted deployments where the credit union runs the prover infrastructure."


## Persona: cryptographer

---

### Attack 1: Execution Binding Gap — The Circuit Proves Existence, Not Actuality

**Attack:**
The adversary (a coalition of colluding agents in the chain) submits an audit proof for a *fabricated* intermediate chain that is entirely different from the delegation chain that actually executed on-chain. Concretely:

The on-chain state publishes only two anchors: `rootScopeCommitment = Poseidon2(scope₀, cred₀)` and `terminalScopeCommitment = Poseidon2(scopeN, credN)`. The actual execution had intermediate hops with scopes `scope₁, …, scope_{N-1}` (some of which may have had broad permissions). The colluding prover constructs a *sanitized* chain `scope₁', …, scope_{N-1}'` (aggressively narrow, e.g. all equal to `scope_N`) with `cred₁', …, cred_{N-1}'` drawn from legitimately enrolled agents, such that:
- The chain is monotonically narrowing,
- All `cred_i'` pass the `BinaryMerkleRoot` check (they are enrolled),
- Poseidon commitment chaining (Constraint 6) is internally consistent.

No Poseidon collision is required. The prover simply presents a different *valid witness* for the same pair of public endpoints.

**Why it works:**
Constraints 2 and 3 bind only the chain *endpoints* to on-chain data. The intermediate commitment chain (Constraint 6) is entirely private — intermediate `Poseidon2(scopes[i], credCommitments[i])` values are never published on-chain at execution time and are never cross-referenced against any on-chain event log. The circuit is satisfiable by *any* monotonically narrowing sequence of enrolled agents that begins at `rootScopeCommitment` and ends at `terminalScopeCommitment`. This is a proof of *existence* of a valid chain, not a proof of *identity* of the chain that executed.

**Why the security argument fails:**
Section 4 claims "chain injection → Poseidon collision resistance." The reduction is only valid for attacks that try to *move the endpoints* (forge a different `rootScopeCommitment` or `terminalScopeCommitment`). It does not cover the construction of an alternative *interior* witness — which requires no collision whatsoever. The DAF game definition (§3) correctly names this win condition but the reduction does not close it.

**In-threat-model?** **No — the construction must address this.** The gap is fundamental: without on-chain commitment to intermediate scope hashes at execution time (e.g. a Merkle accumulator over `(scopeCommitment_i)_{i=0}^{N}` published when the chain executes), no circuit-only proof can distinguish "the chain that actually ran" from "any chain consistent with the endpoints." Either (a) the on-chain registry must anchor intermediate commitments at delegation time, or (b) the security claim must be weakened to "auditor is convinced a valid narrowing chain *could* exist," which is not the same as auditing actual execution.

---

### Attack 2: Chain Compression — Prover Suppresses Intermediate Hops

**Attack:**
`chainLengthOut` is a public output derived from the private input `chainLength`. Nothing binds `chainLength` to the number of hops recorded in the on-chain registry. A prover who executed an 8-hop pipeline can submit a proof claiming `chainLengthOut = 2` by presenting a direct two-hop witness (root delegator → terminal delegatee) that satisfies all circuit constraints, provided the two-hop scopes are consistent with the public endpoints.

Operationally: in the Navy Federal scenario (§7), if the credit-pull agent actually had `ACCESS_PII` for 4 intermediate hops before reaching the risk-scoring agent, a complicit operator presents a 1-hop proof claiming the root directly delegated `READ_DATA` to the risk-scoring agent. All public signals remain valid; the examiner sees `chainLengthOut = 1` and concludes the pipeline was a single hop.

**Why it works:**
Constraint 12 (inactive-hop gating) multiplexes all constraints for indices `i ≥ chainLength` to trivially satisfied. The `isActive` selector is computed from the private `chainLength` — there is no circuit constraint that `chainLength ≥ actualHopsOnChain`. The on-chain registry publishes only `rootScopeCommitment` and `terminalScopeCommitment`; it does not publish the hop count at delegation time.

**Why it fails (partially):**
If the on-chain delegation transactions are sequentially ordered and publicly visible (i.e. the prover cannot suppress on-chain events), an examiner can independently count hops from the event log. The ZK proof would then be redundant for chain length. But in the journalist/source scenario (§7), chain length is supposed to be *private* — the construction explicitly contemplates hiding it via MAX_CHAIN_LEN padding. If the auditor is meant to rely solely on `chainLengthOut` for hop-count information, suppression is undetected.

**In-threat-model?** **Partially.** If on-chain hop-count is always independently observable, this is low-severity. But the construction's claim that "even the chain length could be hidden" (§8, journalist row) and its use of `chainLengthOut` as a public output creates an inconsistency: either the auditor trusts `chainLengthOut` (in which case compression is an attack), or hop count is always externally verifiable (in which case the privacy claim in §8 is false). The construction must clarify which regime it is in and, if hiding chain length, must prove the prover cannot lie about it.

---

### Attack 3: Scope Commitment Preimage Ambiguity — Bitmask Aliasing Under BN254 Field Arithmetic

**Attack:**
The scope is a 64-bit value embedded as a BN254 scalar field element (254 bits). Constraint 4 decomposes each scope via `Num2Bits(64)` and checks subset relations bit-by-bit. However, the *input* to Poseidon2 in Constraints 2, 3, and 6 is the field element `scopes[i]`, not the bit decomposition. The circuit does not enforce that `scopes[i]` is in the range `[0, 2^64)` before feeding it into Poseidon — `Num2Bits(64)` is invoked for the narrowing check (Constraint 4) but the Poseidon invocations in Constraints 2/3/6 consume `scopes[i]` directly.

A malicious prover supplies `scopes[i] = v + k·2^64` for some `k ≥ 1` such that `v` is the legitimate 64-bit scope. The Poseidon commitment `Poseidon2(v + k·2^64, credComm)` differs from `Poseidon2(v, credComm)` and would not match the on-chain scope commitment — so this is not directly exploitable for endpoint forgery. But it creates a *second preimage* for the scope commitment that bypasses the range check: the Num2Bits(64) decomposition of `v + k·2^64` extracts only the low 64 bits (`v`), so the narrowing check passes for `v`, while the Poseidon commitment is computed over the *full field element*. If the on-chain scope commitment was computed with `v`, a proof using `v + k·2^64` will fail Constraint 2. However, if scope commitments are computed off-circuit (e.g. by the SDK) without strict range enforcement, an operator could store `Poseidon2(v + k·2^64, credComm)` on-chain, and a circuit using `v` in the bit-decomposition but `v + k·2^64` in Poseidon would be inconsistent.

More practically: the circuit must enforce `Num2Bits(64)(scopes[i])` as a *range gate* (the output bits reconstituted to the original signal must equal the input) — standard circomlib does this — but the construction does not state whether the `Num2Bits` invocations in Constraint 4 are also wired back to the signal used in Poseidon (Constraints 2/3/6). If the circuit uses two separate signal paths for the same scope value (one bit-decomposed, one raw), a malicious prover can supply mismatched field elements.

**In-threat-model?** **Conditionally.** If the Circom implementation correctly wires the same signal into both `Num2Bits` and `Poseidon2`, the attack is closed by construction. The security argument in §4 does not mention this wiring requirement, and the construction text does not make it explicit. This is a correctness obligation that must be stated as a proof obligation for the implementation, not just assumed.

---

### Attack 4: Audit Nullifier Does Not Prevent Alternative-Witness Proofs for the Same Session

**Attack:**
The `auditNullifier = Poseidon2(rootScopeCommitment, sessionNonce)` is intended to "prevent duplicate audits per session." However, it is deterministic over *public values*: `rootScopeCommitment` is on-chain; `sessionNonce` is a public input. Two proofs with identical `(rootScopeCommitment, sessionNonce)` produce the same `auditNullifier` — so the nullifier correctly prevents submitting two proofs for the same (root, nonce) pair.

But consider: the adversary submits proof P₁ for the real chain, then constructs proof P₂ for a fabricated chain (see Attack 1) with a *different* `sessionNonce`. P₂ has a different `auditNullifier` and is accepted as a fresh audit. Nothing in the construction binds `sessionNonce` to a specific delegation execution: the prover chooses it freely as a public input. An adversary can therefore generate arbitrarily many audit proofs for different purported "sessions" — all anchored to the same on-chain `(rootScopeCommitment, terminalScopeCommitment)` pair but presenting different interior chains.

Furthermore, the nullifier is constructed from `rootScopeCommitment` alone, not from the *full chain* (intermediate commitments are private). Two chains with the same root and terminal but different intermediate participants share the same nullifier space modulo nonce. The nullifier prevents replay of the *same proof*, not construction of a *different valid proof for the same chain*.

**In-threat-model?** **Yes for replay; no for alternative-witness binding.** The construction correctly prevents exact proof replay within a session. But as a mechanism for ensuring an auditor sees *at most one valid interpretation* of a delegation chain, the nullifier is insufficient. The construction must clarify whether the audit protocol is intended to be one-proof-per-session (and bind `sessionNonce` to a verifier-issued challenge to prevent prover-chosen nonces), or must accept that multiple valid proofs can coexist for the same execution.


## Persona: cu_ciso

### Attack 1: Scope Narrowing Is Not an Audit Trail

- **Attack:** The construction proves that delegation scopes narrowed monotonically and that terminal scope satisfies `auditPolicyMask`. The NCUA examiner receives `narrowingValid = 1` and `chainLengthOut = 3`. My examiner then asks: "Show me what the credit pull agent actually accessed — which member records, which fields, at what timestamps, from which systems." The ZK proof cannot answer this. I show the NCUA examiner a PLONK proof and they say: "This tells me the agent had permission to read PII. It does not tell me it didn't read 50,000 member records. Where is your access log?"

- **Why it works / why it fails:** The construction is explicit about what it proves (Section 3, DAF game): permission bitmask narrowing and enrollment inclusion. It says nothing about *use* of those permissions. NCUA Part 748, Appendix B, and the FFIEC CAT Domain 3 (Cyber Risk Management) require an audit trail of *actions*, not bounds. The construction conflates "the agent was scoped to READ_DATA" with "the agent's data reads are auditable." GLBA Safeguards Rule (16 CFR §314.4(c)) requires the CU to monitor for unauthorized access — a scope proof is a gate check, not a monitor. A fully compliant PLONK proof with `auditPolicyMask = 0x01` is consistent with a rogue agent that stayed within READ_DATA scope while exfiltrating every member record.

- **In-threat-model?** **No.** The construction never claims to prove behavioral compliance, only scope narrowing. But the deployment scenario (Section 7) explicitly positions this as satisfying NCUA examination needs. That positioning is false. The construction must either scope-down the regulatory claim or layer a complementary access log commitment (e.g., a Merkle root over signed access events per hop) that the examiner can query. The ZK proof proves authorization bounds; the CU still needs an operational audit trail. These are not the same control.

---

### Attack 2: The Witness Storage Honeypot

- **Attack:** Section 7 states: "The credit union's compliance system holds the full private chain data (scopes, credential commitments, Merkle proofs)." I am now the adversary targeting that compliance system. The entire point of the ZK construction is that the *auditor* cannot see intermediate scopes, identities, or Merkle paths. But my own compliance system stores all of it in plaintext to generate the proof. I have built a cryptographic privacy guarantee for the examiner while creating a new high-value target inside my own perimeter. When a threat actor breaches the compliance system, they recover the complete delegation chain the ZK proof was supposed to hide — including which external vendors (credit bureau agents, model vendors) participated.

- **Why it works / why it fails:** This is not a cryptographic attack; it is an operational key custody attack. The construction's zero-knowledge property holds against the *verifier*. It offers no protection against compromise of the *prover's private state*. NCUA Part 748 Appendix A §III requires the CU to protect sensitive data at rest. The compliance system storing `credCommitments[i]` and Merkle witness paths for an 8-hop chain across external vendors is categorically sensitive data — it is the full reconstruction of what the ZK proof hides. The construction does not specify the storage model, access controls, HSM requirements, or encryption-at-rest requirements for this data. For a $2B–$10B CU, the compliance system becomes a Tier 1 critical system with no guidance on protecting it.

- **In-threat-model?** **No.** The threat model (Section 3, DAP game) defines V as the *auditor* and proves the auditor cannot extract private inputs. It does not define an adversary who compromises the prover. This is a gap. The construction must specify: (a) the private witness data lifecycle (generated ephemerally per audit? stored? for how long? under what controls?), and (b) whether the compliance system operator is trusted and what that implies for the threat model. NCUA Part 749 record retention (6+ years) conflicts with ephemeral-witness designs. Either the witness is stored (creating the honeypot) or it is discarded (creating a re-audit impossibility problem).

---

### Attack 3: The Enrollment Authority Is an Unvetted Vendor

- **Attack:** Constraint 9 (Section 2) requires `BinaryMerkleRoot(credCommitments[i+1], delegateeMerkleProofs[i]) === agentTreeRoot`. The `agentTreeRoot` comes from the on-chain agent registry. My NCUA examiner asks: "Who controls the enrollment process that determines what gets into that Merkle tree?" The answer is Bolyra (or whatever party operates the on-chain registry). I now have a critical third-party vendor whose enrollment decisions are the foundation of every delegation audit proof. My PLONK proof is only as trustworthy as the enrollment authority's integrity.

- **Why it works / why it fails:** The cryptographic guarantee is: "the agent was enrolled." The enrollment guarantee is: "someone with write access to the Merkle tree added this credential commitment." The construction offers no in-circuit proof about the *enrollment process* — only membership in the resulting tree. Under GLBA Safeguards Rule §314.4(f) and NCUA's Third-Party Relationships guidance (Letter to Credit Unions 07-CU-13), the CU must perform due diligence on vendors whose services affect member data security. If Bolyra's enrollment process is compromised — a malicious operator inserts a credential commitment for a rogue agent — the DelegationAuditChain circuit will happily prove that rogue agent was "enrolled," because it was. The construction cannot distinguish a legitimately enrolled agent from a fraudulently enrolled one. The examiner cannot either. The CU takes the liability.

- **In-threat-model?** **No.** The DAF game (Section 3) assumes "Challenger runs the Bolyra registry with honest enrollment." This is stated as a setup assumption, not a defended property. In a production CU deployment, the enrollment authority is a real operational system with real attack surface. The construction must either: (a) formally characterize the enrollment trust assumption and surface it as an explicit vendor dependency the CU must manage, or (b) add an in-circuit proof of enrollment authorization (e.g., the enrollment transaction was signed by the CU's own key, not just Bolyra's operator). Until then, the NCUA third-party risk questionnaire has no answer for "who audits the enrollment authority?"

---

### Attack 4: Public Signals Create a Correlation Side-Channel Over Repeated Audits

- **Attack:** The public signals include `rootScopeCommitment`, `terminalScopeCommitment`, `chainLengthOut`, `auditTimestamp`, and `sessionNonce`. `rootScopeCommitment` and `terminalScopeCommitment` are already on-chain. Over 90 days of NCUA examination, I hand the examiner 400 audit proofs. The examiner now has a time series of `(rootScopeCommitment, terminalScopeCommitment, chainLengthOut, auditTimestamp)` tuples. Chains of length 3 that start at the same root commitment and end at the same terminal commitment, clustered at Monday morning timestamps, reveal that loan processing runs a 3-hop pipeline on Monday mornings. Over time, the examiner can infer pipeline topology from frequency, chain length, and commitment recurrence — without breaking a single constraint.

- **Why it works / why it fails:** The DAP game (Section 3) defines V's win condition as learning "intermediate scope values, intermediate credential commitments, or Merkle leaf identity." It does not model a *longitudinal* auditor who aggregates public signals across many proofs. `chainLengthOut` is a direct structural leak. `rootScopeCommitment` is stable across all audits using the same root credential — it is a pseudonym for the root agent that is consistent across sessions. Section 2's ZK argument ("public signals are: rootScopeCommitment, terminalScopeCommitment…already on-chain…no intermediate information appears") is correct for a single proof but inadequate for a repeated-audit deployment. The construction's `auditNullifier` prevents duplicate audits per session but does nothing to prevent cross-session correlation.

- **In-threat-model?** **No.** The DAP game is a one-shot game. The construction has no unlinkability property across proofs. For the journalist/source scenario (Section 2) this is a critical failure: repeated audits of the same journalist's agent chain, even with fresh `sessionNonce`, produce correlated `rootScopeCommitment` values if the journalist's root credential is stable. The examiner cannot reconstruct the chain, but can establish that "this commitment appeared 47 times in Q1, always with chain length 4." The construction must either rotate root commitments per audit (requiring on-chain commitment updates) or explicitly disclaim cross-session unlinkability and exclude the journalist scenario from in-scope privacy guarantees.


## Persona: rfc7662_advocate

---

### Attack 1: The "Offline AS" Equivalence — Signed JWT Introspection Removes the Hot Path

- **Attack:** Section §8 claims the baseline requires the auditor to "query or trust the AS policy log." False. Under `draft-ietf-oauth-jwt-introspection-response`, the AS issues a signed JWT at delegation issuance time — not audit time — asserting: `{ "narrowing_valid": true, "terminal_scope": "<bitmask>", "chain_length": 3, "policy_satisfied": true }`. The auditor verifies an RS256/ES256 signature against the AS's published JWKS. No live AS query. No intermediate scope disclosure. The AS is not in the verification hot path; the auditor is cryptographically verifying the AS's historical attestation, exactly as the auditor verifies the PLONK verifier contract. The construction's "no trusted third party" claim actually means "no trusted runtime query" — which signed JWT introspection also satisfies.

- **Why it works / why it fails:** The attack correctly identifies that the construction conflates *runtime AS availability* with *AS trust*. Both architectures require trusting an issuing authority: Bolyra trusts whoever updates the on-chain Merkle root (see Attack 2); the baseline trusts the AS's signing key. The construction does NOT defeat this attack for the NCUA scenario in §7 — an AS that signs "this chain narrowed, terminal scope satisfies NCUA policy" is operationally equivalent and deployable today.

  Where the construction survives: the journalist/source scenario (§7, whistleblower variant). The signed JWT introspection response requires the AS to have *seen* the intermediate participants at issuance time. That AS becomes a single point of source compromise. The ZK circuit never receives intermediate identities as public data. **This scenario is the sole load-bearing distinction.**

- **In-threat-model?** Partially. The NCUA examiner scenario does NOT require ZK — the "offline AS" baseline is adequate. The construction must narrow its scope claim to adversarial-AS scenarios, not regulatory audit in general. **Construction must address: §8 comparison overstates the gap for any scenario where the AS is a trusted operator.**

---

### Attack 2: The Merkle Root Updater Is the Authorization Server

- **Attack:** Constraint 9 requires `BinaryMerkleRoot(credCommitments[i+1], proof_i) === agentTreeRoot`. The public input `agentTreeRoot` is described as "current agent Merkle root (or any root in the history buffer)" — implying an on-chain Merkle accumulator. RFC 8707 resource indicators + RFC 9728 protected resource metadata provide equivalent enrollment: the AS signs tokens that are only valid for specific resource servers (audience binding), and the RS maintains a local allowlist. The construction's enrollment check is structurally identical to "the AS issued this credential to an enrolled entity" — except the enrollment authority is whoever submits leaves to the Merkle accumulator. The construction never specifies the trust model for that operator. If it is the credit union's compliance system (§7), that is a trusted operator equivalent to an AS. If it is a decentralized contract with permissionless insertion, enrollment bypass becomes a real attack surface.

- **Why it works / why it fails:** Section §4 (Security argument) reduces enrollment bypass to Poseidon collision resistance — but that reduction assumes the Merkle tree is honestly maintained. A malicious leaf insertion (by the tree updater) allows injection of a fake intermediate agent that passes constraint 9 with a valid Merkle proof. The construction has no in-circuit check that the leaf was inserted under any access-controlled policy. The baseline's AS at least has auditable issuance logs. The construction's Merkle accumulator may have no equivalent audit trail for who inserted what leaf.

- **In-threat-model?** Yes — this is NOT addressed by the construction. The threat model (§3) explicitly excludes adversary control of "the Poseidon hash function" and "the PLONK verifier" but says nothing about control of the Merkle tree update role. **Construction must address: what is the trust model for leaf insertion into the agent Merkle tree? An adversarial tree operator trivially wins the enrollment bypass game (DAF win condition 3) without breaking any cryptographic assumption.**

---

### Attack 3: Public `chainLengthOut` Leaks Pipeline Topology — Not Mitigated In-Circuit

- **Attack:** The public output `chainLengthOut` is emitted for every audit proof (§2, Public outputs). In the journalist/source scenario (§7), the adversarial auditor learns the exact number of hops. With knowledge that "source → chain of 4 intermediaries → journalist" is the operational pattern, an auditor observing `chainLengthOut = 4` across multiple audit proofs can correlate sessions with high confidence — narrowing the universe of possible pipelines. The construction acknowledges this in §7: "the chain length could be hidden (by setting MAX_CHAIN_LEN and padding with identity hops)." But this mitigation is **not enforced by the circuit.** The circuit always outputs `chainLengthOut = chainLength` (the actual private input), not `chainLengthOut = MAX_CHAIN_LEN`. Padding requires the prover to enroll dummy agents as valid leaves and insert identity hops — an out-of-band convention with no in-circuit guarantee.

  Contrast: an AS-signed audit JWT omits chain length entirely. The AS controls what fields appear in the response (RFC 7662 §2.2: the AS SHOULD return only the fields necessary for the RS). An RFC 7662 auditor sees a boolean `active: true` and the policy result — zero structural metadata.

- **Why it works / why it fails:** The PLONK zero-knowledge property (§4, DAP theorem) holds over the *private* inputs — intermediate scopes, commitments, Merkle paths. It does NOT hide `chainLengthOut` because that is a public output, not a private witness. The DAP game definition (§3) lists "which Merkle leaf corresponds to any intermediate participant" as protected but does not list chain length as protected. The construction's own DAP game definition excludes chain length from the privacy guarantees, yet §7 describes a scenario (journalist/source) where chain length leaks are operationally harmful.

- **In-threat-model?** Yes — the journalist/source scenario as described in §7 is **not fully addressed**. The construction claims privacy over participant identities but leaks chain length as a public output. If chain length is part of the privacy claim, the circuit must either (a) always output `MAX_CHAIN_LEN` and enforce padding in-circuit, or (b) remove `chainLengthOut` from public outputs entirely and have the auditor infer only whether the chain satisfied the policy. **Construction must fix: either remove `chainLengthOut` from public signals or add an in-circuit padding enforcement gadget that normalizes all proofs to `MAX_CHAIN_LEN` hops.**

---

### Attack 4: The "Irreducible Gap" Against BBS+ Ignores Predicate Credential Schemes Already in Standardization

- **Attack:** Section §8 states: "BBS+ hides individual claims but cannot prove `scope_i+1 ⊆ scope_i` over hidden bitmasks — no arithmetic relation predicates in BBS+ spec. Auditor must see scopes or trust AS assertion." This accurately describes BBS+ as currently specified in `draft-irtf-cfrg-bbs-signatures`. However, the IETF CFRG is actively standardizing BBS+ with **predicate proofs** (informally: BBS+DP, also appearing in the ACDC/KERI ecosystem and Hyperledger AnonCreds 2.0). BBS+ predicate extensions support range proofs and set-membership proofs over hidden attributes. A bit-subset check (`scope[i+1] ⊆ scope[i]`) is expressible as a conjunction of range predicates over each bit position — `bit_j(scope[i+1]) ≤ bit_j(scope[i])` for j in 0..63. Combined with RFC 8693's `act` chain structure, each hop produces a predicate VP proving subset without revealing the value. The "irreducible gap" is a gap against the *current* BBS+ spec, not against the credential ecosystem trajectory.

- **Why it works / why it fails:** The construction's comparison in §8 is technically accurate at time of writing. BBS+ predicate proofs are not yet standardized and no production RFC 8693 implementation ships them. However, the claim "The structural gap is irreducible" is too strong — it will be falsified when BBS+DP or AnonCreds 2.0 reaches RFC status. More importantly, the cross-issuer predicate problem remains: BBS+ predicates operate within a single issuer's credential. A 4-hop chain with 4 different issuers requires 4 separate predicate VPs with no shared commitment binding them into a single monotonic chain proof. The construction's PLONK circuit binds all hops via the `Poseidon2` scope commitment chain (constraint 6), producing a single artifact. This residual advantage — **single-artifact cross-issuer chain proof** — survives even BBS+DP.

- **In-threat-model?** No — the construction survives once scoped correctly. But **the comparison in §8 must be rewritten**: replace "irreducible" with the narrower claim that the gap persists for cross-issuer chains, and acknowledge that single-issuer chains with predicate BBS+ may close the gap in the near future. The current framing will be cited against the construction by reviewers who are aware of BBS+DP work.


## Persona: spiffe_engineer

---

### Attack 1: ZK Attestor Plugin — You're Solving a Plugin Problem, Not a Protocol Problem

**Attack:**
SPIRE's attestation architecture is explicitly plugin-based. Node attestors (AWS IID, TPM, k8s SAT) produce signed SVIDs carrying arbitrary URI SANs and extension fields. A ZK attestor plugin that generates a Poseidon-commitment enrollment proof could embed it as a JWT SVID claim (`zk_enrollment_proof`) or X.509 extension (OID-namespaced). The SPIRE Workload API would then vend these proof-carrying SVIDs to any workload that passes standard node attestation. WIMSE's `wia`/`wat` split means the workload access token — already exchanged hop-to-hop — can carry this extension through the `act` chain. No new protocol needed; one SPIRE plugin + one WIMSE claim extension, deployed inside existing mTLS infrastructure.

The DelegationAuditChain construction (§1, §5) presents itself as the identity layer. But any Fortune 500 already running SPIRE gets this as an extension problem, not a new-protocol problem. The construction implicitly assumes greenfield deployment. It never addresses the migration case: how does an organization running SPIRE/SPIFFE today adopt Bolyra without running two parallel identity stacks?

**Why it works / why it fails:**
The construction's §8 comparison dismisses the baseline as requiring "a shared AS" but doesn't engage with the plugin model at all. The PLONK verifier contract is on-chain; so would be any ZK-attestor-extended SVID verifier. The claim that Bolyra avoids a trusted third party (§8, row 3) is true — but so does a SPIRE node attestor whose trust root is a hardware TPM. The structural gap the construction identifies (BBS+ can't prove relational predicates across chains) is real, but it's an argument for adding ZK predicate proofs to WIMSE token exchange, not for a new credential system.

**In-threat-model?** No — the construction must address why the ZK audit property cannot be achieved via a SPIRE plugin + WIMSE claim extension. Without this, the differentiation claim is "we built a new identity layer" not "we solved what the existing layer cannot."

---

### Attack 2: History Buffer Makes `agentTreeRoot` Prover-Controlled — Revocation Window Is Unbounded

**Attack:**
Section 2 specifies `agentTreeRoot` as a public input that may be "any root in the history buffer." This is necessary because the agent Merkle tree mutates when agents enroll and unenroll; old session proofs would otherwise break. But it means the **prover chooses which historical root to use**. The verifier (on-chain PLONK contract) checks only that the submitted root is a valid historical root — it doesn't enforce recency.

Concrete exploit path:
1. Adversarial operator enrolls `agent_evil` at time T₀.
2. `agent_evil` is discovered and de-enrolled (removed from the tree) at time T₁.
3. The on-chain registry retains history buffer entries including the T₀ root.
4. At time T₂ >> T₁, adversary generates a `DelegationAuditChain` proof using the T₀ `agentTreeRoot`, proving `agent_evil` was enrolled.
5. The expiry check (Constraint 8) passes because `expiries[chainLength]` is set to T₂ + ε and is a *private* input — the prover controls it.
6. The auditor receives `narrowingValid = 1` with all enrollment checks satisfied. They cannot distinguish T₀ from T₂.

The construction's Constraint 9 proves "this credCommitment was a leaf in some historical root," not "this agent is currently valid." The expiry in Constraint 8 only proves the terminal credential hasn't expired per the *prover-supplied* expiry field — it does not bind to on-chain registration timestamps.

**Why it works / why it fails:**
SPIFFE handles this with mandatory short-TTL SVIDs (default 1 hour in SPIRE). Revocation is implicit: an expired SVID cannot authenticate, and no history buffer exists. The construction trades short-TTL simplicity for long-lived Merkle roots, but pays with an unbounded revocation window for the enrollment check. The threat model (§3, DAF game) defines Enrollment Bypass as adversary A winning if "some intermediate delegatee's credCommitment is not a leaf in the agent Merkle tree." This is technically satisfied by the proof's constraint — but the semantics of *which* root to use and *when* it was valid are unspecified.

**In-threat-model?** No — the construction must define: (a) maximum age of an acceptable historical `agentTreeRoot` relative to `auditTimestamp`, enforced as an in-circuit constraint between the two public inputs; and (b) whether de-enrollment removes the leaf (requiring proof-of-non-membership) or just flags it, and how either interacts with historical roots.

---

### Attack 3: `chainLengthOut` Is a Public Output — It Leaks Pipeline Topology to the Auditor

**Attack:**
Section 2 lists `chainLengthOut` as a public output: "number of hops in the chain." The construction's stated privacy goal (§3, DAP game) is that V learns "chain length, the public root/terminal scope commitments (already on-chain), and whether the terminal scope satisfies the audit policy." Chain length is explicitly *intended* to be disclosed.

But in the deployment scenario of §7 (Navy Federal Credit Union, NCUA examiner), the pipeline topology — specifically the number of distinct agents in the loan processing chain — is proprietary operational detail. A chain length of 3 versus 8 reveals whether the organization uses a simple or deeply orchestrated AI pipeline. Correlated with timing data from the on-chain scope commitment events (also public), the auditor can derive: (a) when each hop occurred, (b) how long each agent ran, and (c) whether the pipeline is serial or batched. None of these are in the DAP game's "V wins if..." conditions — the construction's privacy definition simply doesn't protect them.

In the journalist/source scenario (§7), a chain length of 4 combined with network-layer SPIFFE SVID logs (visible to the journalist's Envoy sidecars, which is realistic in any SPIRE deployment) narrows the source to "one of N plausible 4-hop paths through the journalist's infrastructure graph." The construction claims it protects "the source even from the journalist's own infrastructure" — but this claim rests entirely on the auditor seeing only the ZK proof. In a SPIFFE deployment, TLS session logs showing `spiffe://journalist.org/relay-agent-2` appear in every service mesh access log. The ZK proof hides identity in the proof; the infrastructure exposes it at the transport layer.

**Why it works / why it fails:**
Against the construction's formal DAP game (proof-only view), this attack fails — chain length is intentionally public, and infrastructure logs are out of scope. But against the construction's *claim* in §7 that the journalist scenario achieves source protection, the attack succeeds. The claim overreaches the formal guarantee. A SPIFFE engineer deploying this in production would know immediately that Envoy/Linkerd logs defeat the journalist scenario, because every hop produces a TLS handshake with an SVID that is logged by default.

**In-threat-model?** Partial: the formal DAP game survives; the §7 operational claim does not. The construction must either (a) restrict the journalist/source claim to environments where network-layer identity is also suppressed (e.g., onion routing per hop), or (b) extend the threat model to include infrastructure-layer adversaries and prove the construction still holds — which it does not at present.

---

### Attack 4: Scope Commitment Chain Linkage Requires AS-Equivalent On-Chain State — The "No Trusted Third Party" Claim Is Overstated

**Attack:**
Constraints 2 and 3 (§2) bind the private chain to `rootScopeCommitment` and `terminalScopeCommitment` — both described as "on-chain, already public." The security argument for chain injection resistance (§4) depends on these commitments being authentic: a prover who can forge either value can inject an arbitrary chain. The question is: who put `rootScopeCommitment` and `terminalScopeCommitment` on-chain, and under what trust assumption?

In the construction, these values originate from the Bolyra on-chain registry — a smart contract that records scope commitments as agents execute delegation steps. This contract is the trust anchor. It is functionally equivalent to the WIMSE AS: it is the authoritative record of what scope commitments are valid, it is operated by some entity (Bolyra protocol, or a per-org deployment), and its integrity determines whether the DelegationAuditChain proof is meaningful.

The §8 comparison claims the baseline "requires querying or trusting the AS policy log" while Bolyra requires "only the PLONK verifier contract and the chain's public scope commitments (already on-chain)." But the on-chain registry *is* the AS policy log, just in Solidity form. An auditor who cannot trust the Bolyra registry's record of `rootScopeCommitment` gets exactly the same assurance as one who cannot trust the WIMSE AS's token log: zero.

For cross-org deployments (§8, row 4: "chains spanning arbitrary organizations"), the registry must be shared or federated. SPIFFE federation already handles this via trust bundle distribution — organizations exchange bundles, not credentials. Bolyra's cross-org story implicitly requires all organizations to share one `agentTreeRoot` or to maintain mutually trusted registries. The construction does not specify the federation model, which is exactly what WIMSE's architecture draft (draft-ietf-wimse-arch §5) defines in normative terms.

**Why it works / why it fails:**
The "no trusted third party" property (§8) is semantically true for the ZK proof itself — verification is self-contained given the public inputs. But the public inputs are sourced from an on-chain registry that is a trusted third party in everything but name. The construction survives the formal security game (DAF/DAP) because those games take the public inputs as given. The construction does NOT survive the architectural claim that it eliminates AS dependency — it relocates AS trust to a smart contract and to whoever controls the agent Merkle tree.

**In-threat-model?** No — the §8 comparison row "No trusted third party" must be restated as "trust is relocated to the on-chain Bolyra registry, whose threat model must be specified." The construction should define: who can write scope commitments to the registry, what governance controls the `agentTreeRoot`, and how the cross-org federation model works — answering the same questions WIMSE answers for the AS layer, but for a smart contract.
