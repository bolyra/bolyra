# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Operator-Controlled Audit Is Not an Audit

- **Attack:** Section 7, step 2 reads: *"The pipeline operator generates a `DelegationChainAudit` proof."* The party being audited is also the party generating the proof. The auditor receives a PLONK artifact whose witness was assembled entirely by the prover — who chose which `scopes[]`, `credCommitments[]`, and `delegationSigs[]` to put in. An adversarial operator substitutes a clean 5-hop witness for an actual 12-hop chain that included a non-narrowing hop, generates a valid proof, and submits it. The proof verifies. `narrowingHolds = 1`. NCUA approves.

  The construction never specifies a mechanism for the auditor to *bind the proof to an observed runtime execution*. There is no event log, no runtime attestation, no TEE transcript. The circuit enforces internal consistency of whatever witness the operator provides — it does not enforce that the witness corresponds to what actually ran.

- **Why it works / why it fails:** The construction's threat model (Section 3) explicitly caps the adversary at *n−1 of n* participants. But the operator controls enrollment, proof generation, and witness construction. In practice, the operator *is* a single party controlling all hops. The threat model assumes a multi-party adversary; the deployment scenario (Section 7) assumes a single NFCU operator. These are incompatible.

  Auth0 and WorkOS solve this via AS-mediated issuance: the AS generates tokens, logs them, and is a neutral third party the auditor can subpoena. The construction explicitly eliminates the AS ("AS-blind auditing" in Section 8) — which removes the only entity in the baseline that isn't the operator.

- **In-threat-model?** No. The construction must address how the proof is bound to observed runtime behavior, not just to a witness the prover assembles offline. Without runtime binding (e.g., a trusted execution log, an oracle, a verifiable execution trace), the audit proof is a self-attestation with a fancy math wrapper.

---

### Attack 2: `policyFloor` Is Auditor-Specified — But the Auditor Doesn't Know What to Ask For

- **Attack:** `policyFloor` (Section 2, public inputs) is the auditor's only lever. The construction hides all intermediate scopes, all participants, and the chain length. The auditor can only assert "the final hop must have at least these bits set." But in the NCUA scenario, the regulator doesn't know in advance which permissions a loan processing pipeline's notification tool should hold. If the auditor sets `policyFloor = 0b00000000`, the proof is vacuously satisfied by any chain, including one where the final hop has zero permissions. If the auditor sets `policyFloor` too high, legitimate pipelines fail.

  Regulators examining for data-minimization violations, unauthorized PII access, or scope creep need to ask: *"did any hop access PII that it shouldn't have?"* The construction produces `rootScopeCommitment` and `finalScopeCommitment` — opaque Poseidon hashes. The auditor cannot distinguish a chain that started with `ACCESS_PII` and narrowed correctly from one that started with `ACCESS_PII` and widened illegally (the latter is impossible per G1, but the auditor has no way to verify what root scope was even claimed).

  Auth0's audit logs give regulators the actual token claims, timestamps, and scopes per request. The NCUA examiner can ask "show me every request that touched PII" and get a searchable answer. The construction's auditor gets: two opaque field elements and a bit.

- **Why it works / why it fails:** The construction conflates two different auditor needs: (a) *compliance auditing* — did the pipeline respect scope constraints it set for itself, and (b) *regulatory examination* — did the pipeline comply with external rules the regulator imposed. The circuit enforces (a) given whatever witness the operator provides. It cannot address (b) because the auditor cannot inspect intermediate state to verify it against external policy.

- **In-threat-model?** No. The construction claims the proof is "usable beyond narrow regulatory niches" (candidate gap description) but the single auditor-facing output is a floor check against a bitmask the auditor must specify without seeing any intermediate values. This is unusable for any regulator who does not already know the pipeline's internal permission design.

---

### Attack 3: Proving Latency Eliminates Every Synchronous Use Case

- **Attack:** Section 6 targets < 5s (PLONK) or < 2s (rapidsnark) for a ~209K-constraint circuit at 2^18. That is the proof generation time *for a single audit*. In Section 7, the audit is presented as a batch step — the compliance officer requests it, the operator generates it, it goes on-chain.

  But the candidate's own gap description calls out *"multi-tool AI pipeline where auditor wants proof that no hop exceeded its mandate without learning the mandates."* Real AI pipelines (LangGraph, CrewAI, OpenAI Assistants) make tool call authorization decisions at sub-second latency. If the delegation proof must be generated and verified before each hop is permitted to execute, a 5-hop pipeline incurs 10–25 seconds of ZK overhead before the first useful work completes. The construction offers no synchronous authorization path — it produces a retroactive audit artifact.

  WorkOS MCP auth issues a scoped token in <100ms at the start of the session. Every hop presents the token. Latency is negligible. The operator does not need to generate a ZK proof at all for the happy path.

- **Why it works / why it fails:** The construction's defense is that the proof is generated *after* the pipeline runs, not before each hop. This is true for the audit use case. But this means the construction is *not* a replacement for per-hop authorization — it is only a post-hoc compliance artifact. The differentiation claim depends on "real-time" pipeline use cases; the construction itself concedes those require <5s and does not explain what enforces scopes *during* execution before the audit proof is generated. The gap between "enforcement" and "proof of enforcement" is unaddressed.

- **In-threat-model?** No. The construction must either (a) provide a synchronous per-hop authorization path with <100ms latency (incompatible with ZK proving times today), or (b) explicitly bound its claim to post-hoc auditing and explain what enforces scopes at runtime before the audit proof is produced. Currently the deployment scenario implies enforcement but the latency numbers make real-time enforcement impossible.

---

### Attack 4: On-Chain Registry Enrollment Is a Permanent Deanonymization Vector

- **Attack:** G9 (Section 2) requires every active hop to prove Merkle inclusion of its `credCommitment` against the on-chain `agentRegistryRoot`. Enrollment into that registry is itself a blockchain transaction. The enrollment transaction contains the credential commitment as calldata and is permanently indexed on Base Sepolia (and eventually mainnet).

  The whistleblower scenario (Section 7) requires that "all agents are enrolled in the registry." A journalist's source agent must be enrolled. A law enforcement agency with a subpoena to the chain operator or a block explorer can enumerate all enrollment transactions, identify all credential commitments ever enrolled, and correlate timing: "which credential was enrolled two hours before this delegation proof was submitted?" The ZK proof hides which enrolled credential was used in which hop, but it does not hide that an enrollment happened.

  For the journalist/source protection use case — which the construction explicitly claims — the enrollment creates a permanent, publicly auditable record that a credential was issued at a specific time. Attribution via enrollment timing plus proof submission timing is a practical deanonymization attack that requires no cryptographic breaks, only a blockchain explorer and a timestamp correlation.

  Auth0 and Stytch do not require their users to publish credentials to a public ledger. Enrollment is a private API call to a SOC 2-compliant server. There is no permanent on-chain record of "an agent was created at block 14,392,811."

- **Why it works / why it fails:** The construction's privacy argument relies on PLONK zero-knowledge for proof contents (Section 4, Theorem 2). But Theorem 2 is scoped to the proof artifact itself — it says nothing about the on-chain enrollment trail. The threat model (Section 3) does not include a blockchain analytics adversary who correlates enrollment events with proof submissions. The whistleblower scenario is incompatible with a public permissioned registry.

- **In-threat-model?** No. The construction must either (a) make enrollment private (off-chain registry, TEE-based, or using a separate privacy layer), which eliminates the "anchor to real registrations" guarantees of G9, or (b) remove the whistleblower scenario from its claimed use cases. Currently both claims coexist in Section 7, and they are cryptographically contradictory.


## Persona: cryptographer

Applied cryptographer. I'll hold this construction to the same bar I'd apply at CRYPTO/S&P: every privacy claim needs a simulator, every soundness claim needs a reduction that actually closes.

---

### Attack 1: Brute-force scope extraction — CHAIN-PRIVACY trivially broken for small bitmask spaces

**Attack:**
`rootScopeCommitment = Poseidon2(scopes[0], credCommitments[0])` and `finalScopeCommitment = Poseidon2(scopes[L-1], credCommitments[L-1])` are public outputs. The Merkle tree is an on-chain data structure — an auditor can enumerate its leaves (or observe enrollment transactions) and recover `credCommitments[0]` and `credCommitments[L-1]`. The scope bitmask is declared as `uint64` but constrained by the 8-bit cumulative permission encoding (bits 0–7, with implication rules eliminating many values). In practice, the valid set has ≤ 200 members. The adversary (or curious auditor) computes:

```
for s in valid_scopes:
    if Poseidon2(s, credCommitments[0]) == rootScopeCommitment:
        break  # found scopes[0]
```

This runs in < 200 Poseidon evaluations. Same attack on `finalScopeCommitment`. The root and terminal permissions are fully recovered.

**Why it works:** PLONK's zero-knowledge guarantee hides the *witness* from the verifier given fixed public inputs. It says nothing about inverting a *public output* when the output is a deterministic function of a small-domain input and a guessable co-input. The construction conflates "witness is hidden" with "public output is uninvertible." These are different properties. The privacy reduction in §4 (Theorem 2) does not account for enumeration of `credCommitments` from on-chain state.

**In-threat-model?** No. The threat model (§3, CHAIN-PRIVACY) permits $\mathcal{A}$ to "observe the public outputs `(rootScopeCommitment, finalScopeCommitment, ...)`" and explicitly allows observation of `agentRegistryRoot`. A registry scan is within the adversary's remit. The construction must address this: the fix is either to bind a fresh per-audit blinding scalar into both scope commitments (`Poseidon3(scopes[i], credCommitments[i], auditSessionNonce)`) or to eliminate `credCommitments[i]` from scope commitment and use a Pedersen-like blinded commitment with a private randomness term — at which point the cost of G3 and G9 increases and the reduction must change.

---

### Attack 2: Key-commitment binding gap — phantom delegator attack

**Attack:**
Gadget G4 verifies:
```
EdDSAPoseidonVerifier(delegationToken[i], delegatorPubkeys[i], delegationSigs[i])
```
Gadget G9 verifies:
```
BinaryMerkleRoot(credCommitments[i], ...) == agentRegistryRoot   ∀ active i
```

Observe what is *not* constrained: the circuit never verifies that `delegatorPubkeys[i]` is the public key committed inside `credCommitments[i-1]`. G4 proves "some key signed this token." G9 proves "agent i's credential is enrolled." There is no constraint of the form:

```
ExtractPubkey(credCommitments[i-1]) === delegatorPubkeys[i]
```

**Phantom delegator attack:** Let $\mathcal{A}$ pick an adversary-controlled key pair $(sk^*, pk^*)$. Set `delegatorPubkeys[i] = pk*`. Pick ANY enrolled agent's credential commitment as `credCommitments[i-1]` — say, NFCU's credit-scoring tool (observable from the registry). Use $sk^*$ to sign `delegationToken[i]`. G4 passes (valid signature under $pk^*$), G9 passes (enrolled commitment in tree). But the actual credit-scoring agent never signed anything. $\mathcal{A}$ forges a chain link in which hop $i-1$ "delegated" to hop $i$, while the enrolled agent at $i-1$ had no involvement.

**Why it works / fails:** It works unless `credCommitments[i-1]` is defined as a Poseidon commitment over `(pubkey_{i-1}, ...)` AND the circuit enforces `delegatorPubkeys[i] = pubkey_{i-1}` via an in-circuit extraction constraint. The construction (§2 gadgets, §4.2 delegation circuit reference) never shows this constraint. The mapping from credential commitment to signing key is architecture-critical and must be specified. The spec's `createAgentCredential(modelHash, operatorPrivKey, permissions, expiry)` suggests the *operator* key is distinct from any per-agent EdDSA signing key — which means the binding is even more ambiguous.

**In-threat-model?** No. This is a Case (b) variant of CHAIN-NARROW-SOUNDNESS: `credCommitments[i-1]` belongs to an enrolled agent that never participated in the delegation. The phantom-chain attack is exactly what G9 was designed to close — but G9 only anchors `credCommitments[i]` (the delegatee), not the key used to sign at hop $i$ (the delegator). The reduction sketch in §4 (Theorem 1, Case b) assumes the Merkle inclusion proof alone is sufficient; it is not. The construction must add:

```
isActive[i] * (extractedPubkey[i-1] - delegatorPubkeys[i][0]) === 0
isActive[i] * (extractedPubkeyY[i-1] - delegatorPubkeys[i][1]) === 0
```

with a circuit-native extraction of the Baby Jubjub point from `credCommitments[i-1]`.

---

### Attack 3: Underconstrained `actualLength` — empty-chain vacuous soundness

**Attack:**
`actualLength` is a `uint4` private input with no enforced lower bound. Consider `actualLength = 0`. Then:

- `isActive[i] = LessThan(5)(i, 0) = 0` for all $i \in [0, 16)$.
- All per-hop constraints are gated by `isActive[i] === 0`, so they are vacuously satisfied.
- `narrowingHolds = AND(isActive[i] → narrowing_ok[i])` — with all `isActive[i] = 0`, the AND is over an empty domain. Depending on implementation, this is 1 (vacuous truth) or an undefined intermediate wire.
- The multiplexer copies `scopes[actualLength-1] = scopes[-1]` — an out-of-bounds array access in the conceptual model. In Circom, `scopes[-1]` will compile to `scopes[MAX_HOPS-1]`, an attacker-controlled value.
- `finalScopeCommitment = Poseidon2(scopes[-1], credCommitments[-1])` — entirely attacker-chosen.
- `policyMet = 1` can be satisfied by choosing `scopes[-1]` to have all bits in `policyFloor` set.

The adversary produces a valid proof asserting `narrowingHolds = 1`, `policyMet = 1` over a chain of length zero with an attacker-controlled final scope commitment, and no actual delegation occurred.

**Why it works:** G5 says inactive hops "copy `scopes[actualLength-1]`." When `actualLength = 0`, this dereferences slot `-1`, which in Circom's static array model wraps or is treated as `scopes[MAX_HOPS-1]`. The circuit is not vacuous in output — it is *underconstrained*: it produces meaningful-looking outputs from prover-controlled garbage. The policy floor check (G7) passes because the prover chose the "final scope" freely. No G9 Merkle check fires because all hops are inactive.

**In-threat-model?** No. The game CHAIN-NARROW-SOUNDNESS requires the verifier to accept with `narrowingHolds = 1`, but the winning condition talks about "some hop $i < \text{actualLength}$" having a violation. With `actualLength = 0` there are no hops, yet the proof is accepted. The construction must add:

```
actualLength >= 1   (enforced via range check + nonzero gate)
```

and also verify `actualLength <= MAX_HOPS`. The `uint4` type annotation does not enforce a nonzero constraint in Circom — the author must add it explicitly.

---

### Attack 4: Universal SRS trust model unspecified — subverted setup breaks Theorem 1 completely

**Attack:**
§4 Theorem 1 reduces to A3: "knowledge soundness of PLONK with universal SRS (in the algebraic group model + ROM)." The universal SRS is generated in a setup ceremony with toxic waste $\tau$. If any single participant in the ceremony is dishonest and retains $\tau$, the adversary can:

1. For any false statement $x \notin \mathcal{L}$ (e.g., a delegation chain that violates narrowing at hop 3), compute a valid PLONK proof $\pi$ such that the verifier accepts.
2. Theorem 1 fails with probability 1 under a subverted SRS.

Unlike Groth16 (where the Bolyra spec correctly requires per-circuit trusted setup, reusing the Semaphore v4 ceremony for `HumanUniqueness`), PLONK's universal SRS covers all circuits up to a size bound. This makes the SRS higher-value and a more attractive target. The construction specifies `pot18.ptau` (§6) for the Groth16 path and a "universal PLONK SRS at depth 18" without naming a ceremony, its participants, or its trust assumptions.

**Why it works:** The algebraic group model is a proof technique, not a deployed assumption. In deployment, the actual trust statement is: "at least one of $N$ ceremony participants was honest." The construction inherits this assumption but never states it. For regulatory contexts (NCUA audit, §7 deployment scenario), a subverted SRS is a catastrophic break: a malicious NFCU operator could forge an audit proof asserting `narrowingHolds = 1` for a chain that actually escalated permissions at hop 4.

**Relevant comparison:** §8 criticizes the RFC 8693 baseline for relying on a "trusted AS." The construction then substitutes a trusted SRS ceremony — which is a different trust model but not necessarily stronger, and for some adversaries (nation-state, regulatory) may be weaker (a single server compromise is detectable; a poisoned ceremony participant may not be).

**In-threat-model?** No, and the omission is methodologically significant. The threat model (§3) excludes "breaks knowledge soundness of PLONK" without qualifying this against setup trust. A correct threat model must state: "under an honestly-generated SRS from ceremony X (e.g., Ethereum's KZG ceremony, $N$ participants, at least one honest), the following holds..." The whistleblower scenario (§7) in particular requires that the SRS ceremony not be compromised by state actors, which is a separate, unaddressed trust assumption.

**Minimum required fix:** Name the ceremony (or specify a ceremony requirement: $N \geq 100$ participants, output published, transcripts auditable). Alternatively, use Groth16 for this circuit with a dedicated trusted setup rather than claiming PLONK's universality avoids the problem — PLONK moves the trust to the SRS ceremony, it does not eliminate it.


## Persona: cu_ciso

### Attack 1: The Privacy Guarantee Is an Incident-Response Liability

- **Attack:** Post-breach, my NCUA examiner hands me a questionnaire under Part 748.2: "Reconstruct the sequence of access to member PII." I open my audit log and find `narrowingHolds = 1`, `policyMet = 1`, and two opaque Poseidon field elements. I cannot answer: which tool touched PII, in what order, under what scope, at what timestamp. The construction's Section 5 explicitly maps `credCommitments[MAX_HOPS]`, `scopes[MAX_HOPS]`, and `delegatorPubkeys[MAX_HOPS]` as **private** inputs hidden even from the auditor. The same privacy guarantee that sells the protocol to a privacy engineer kills my 748 examination.

- **Why it works:** NCUA Part 748 Appendix A (Security Program) requires a security audit program that "maintains records sufficient to reconstruct the events leading to a security incident." GLBA Safeguards Rule 16 CFR §314.4(c)(3) requires detecting and responding to "attacks or system failures." Neither regulation accepts a zero-knowledge proof of aggregate behavior as a substitute for reconstructible event logs. The construction Section 7 says the auditor "does NOT learn: how many hops, what permissions each hop had, which agents participated." That sentence is the disclosure I need to hand an examiner, and the protocol has cryptographically destroyed it.

- **In-threat-model?** **No.** The construction treats auditability and privacy as the same axis (auditor sees opaque commitments = good). For an NCUA-regulated CU, auditability and privacy are **opposing** requirements: privacy from the member's perspective vs. mandatory disclosure to the regulator post-incident. The construction has no credentialed-access audit path that reveals the witness to a privileged investigator (e.g., under court order or NCUA subpoena) without re-running a new proof with different public/private partitioning. This gap must be addressed.

---

### Attack 2: policyFloor Is a Floor, Not a Ceiling — FFIEC CAT Requires Least Privilege

- **Attack:** I read Gadget G7 in Section 2:
  ```
  policyFloorBits[j] * (1 - finalScopeBits[j]) === 0
  ```
  This enforces `finalScope ⊇ policyFloor`. So `policyMet = 1` tells me the last tool had **at least** the minimum permitted bits. It says nothing about whether the last tool had **more** than allowed. In the Navy Federal scenario (Section 7), the notification tool's legitimate scope is `WRITE_DATA` only (`0b00000010`). If a misconfigured pipeline delivers it `WRITE_DATA | ACCESS_PII` (`0b10000010`), the proof still verifies: narrowing held (the final scope is a subset of the root scope), and `policyMet = 1` if `policyFloor = WRITE_DATA`. The CU compliance officer has cryptographic confirmation that the pipeline was fine when it was not.

- **Why it works:** FFIEC CAT Domain 2 (Threat Intelligence) and NCUA examiner questionnaires for access control require demonstrating **least privilege**: that each component received only the permissions it needed, not merely some floor. The construction provides a lower-bound assertion. A CISO needs an upper-bound assertion too — a `policyCeiling` input that confirms `finalScope ⊆ ceiling`. Without it, the proof is directionally wrong for my primary control objective: preventing privilege creep in AI pipelines. My board narrative is "tools had exactly the rights they needed." The construction can only say "tools had at least X rights."

- **In-threat-model?** **No.** The construction's claim (Section 1) is that "every hop's permission bitmask is a subset of its predecessor's." That's chain monotonicity, not least-privilege conformance. The gap between "monotonically narrowed from the root" and "conformed to a stated upper bound at the terminus" is exactly where regulatory risk lives.

---

### Attack 3: On-Chain Registry SLA and Third-Party Vendor Risk (NCUA Vendor Management)

- **Attack:** My Vendor Management Policy requires every critical third party to provide a SOC 2 Type II report, an uptime SLA ≥ 99.9%, and a signed Business Continuity Agreement. The construction's Section 2 (G9, G5) and Section 7 make the proof's validity conditional on `agentRegistryRoot` being one of the **last 30 entries** in the root history buffer. If the Base Sepolia L2 (or mainnet, or whatever chain hosts the registry) experiences degraded finality, a chain reorganization, or a sequencer outage: (a) new agent enrollments stall, (b) the root history buffer stops advancing, (c) proofs generated against roots older than the buffer window are rejected, and (d) the entire loan pipeline fails to produce verifiable audit proofs. The construction says nothing about what window the 30-entry buffer covers in wall-clock time, who operates the registry contract, or what the fallback is.

- **Why it works:** NCUA Part 748 requires documented incident response for "systems failures." The FFIEC BCP booklet requires a Recovery Time Objective (RTO) and Recovery Point Objective (RPO) for every critical system. "The on-chain registry had a 2-hour outage" is not a recoverable state in an NCUA examination if your audit proof pipeline was dependent on it. My core processor (FiServ, Jack Henry) maintains 99.95% uptime with contractual SLAs and SSAE 18 / SOC 1 Type II attestation. A smart contract has none of these. Additionally, Section 6 introduces `pot18.ptau` — the Powers of Tau ceremony artifact from "the Hermez/iden3 ceremony repository." My third-party risk team will ask: who controls that repository, what's the software supply chain, and was a SOC 2 done on the ceremony participants? The answer is no.

- **In-threat-model?** **No.** The construction addresses cryptographic soundness exhaustively. It does not address operational resilience, fallback registry states, or third-party governance. For a CU deploying this in production, the operational risk is higher than the cryptographic risk.

---

### Attack 4: BSA/AML Surveillance Conflict — FinCEN Cannot See Through the Proof

- **Attack:** The construction's Section 7 explicitly offers a "Whistleblower variant" where "intermediate nodes must stay hidden from auditor." Now consider the same privacy guarantee applied to my loan pipeline: a chain of AI agents processes a member's loan application, and each hop is hidden from the compliance officer. My BSA officer's automated transaction monitoring system flags a suspicious pattern. FinCEN's 2024 guidance on AI in financial services (FIN-2024-G001) requires that automated decision systems maintain audit trails sufficient for SAR (Suspicious Activity Report) filing, including the identity of automated actors involved in a transaction. The construction's CHAIN-PRIVACY theorem (Section 3) is a proof that intermediate participants are **cryptographically irrecoverable** from the proof. My BSA officer cannot file a complete SAR. I am now in violation of 31 U.S.C. §5318(g).

- **Why it works:** The construction treats "auditor cannot learn intermediate participants" as a security property. Under BSA/AML, "compliance officer cannot learn intermediate automated actors" is a regulatory violation. These are the same person in different hats. The Section 8 comparison table lists "Whistleblower-safe intermediary concealment" as a superiority claim over WIMSE. From a FinCEN examiner's perspective, this is not a feature differentiator — it is an obstacle to lawful surveillance. No CISO at an NCUA-examined institution can deploy a system where the mechanism of privacy is "cryptographically irrecoverable intermediate participants," because that same mechanism blocks mandatory government disclosure.

- **In-threat-model?** **No.** The construction's threat model (Section 3) defines adversaries as cryptographic attackers who try to forge proofs or violate soundness. It does not include the regulator as a party who requires selective, privileged disclosure — a party that is, by statute, owed transparency the construction has cryptographically foreclosed. A compliant deployment would need a separate escrow or re-encryption path that selectively reveals the witness to FinCEN under legal process, which the current construction provides no mechanism for.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. I've shipped introspection for a decade. Every ZK claim is suspect until you show me what a well-configured AS can't do.*

---

### Attack 1: Scope Commitment Is a Low-Entropy Preimage Oracle

**Attack:**
`rootScopeCommitment` and `finalScopeCommitment` are exposed as public outputs, defined as `Poseidon2(scope, credCommitment)` (§2, G3). The `credCommitment` for each hop is a leaf in the on-chain agent Merkle tree — the tree is public by construction (G9 requires the auditor-facing contract to check inclusion proofs against `agentRegistryRoot`, which is itself public). The permission bitmask is 8-bit with cumulative-encoding implication constraints (bits 4→3→2), which further reduces the valid scope space to well under 256 values — likely fewer than 100 semantically legal bitmasks.

An adversary who can read the on-chain Merkle tree (everyone can) enumerates every enrolled `credCommitment` and every valid scope value, then computes `Poseidon2(scope_i, credCommitment_j)` offline for all pairs. Against a tree with *N* enrolled agents and *K* valid bitmasks, this is *N × K* Poseidon evaluations — trivially feasible at any realistic scale. A match against `rootScopeCommitment` or `finalScopeCommitment` recovers the exact root scope and final scope.

**Why it works / why it fails:**
This is a standard low-entropy preimage attack. Poseidon collision resistance (A1) is irrelevant here — the adversary is not finding a collision; they are inverting a commitment whose input space is small and partially public. The construction's security argument (§4, Theorem 2) invokes PLONK zero-knowledge to hide private inputs, but ZK only hides inputs from the *proof transcript*. The adversary never reads the proof; they read the *public output* and the *public Merkle tree*, then invert offline.

The construction treats `credCommitment` as private (it is a private circuit input) but exposes it indirectly: any enrolled agent's `credCommitment` is a Merkle leaf, observable on-chain. The only defense would be a blinding factor inside the scope commitment — e.g., `Poseidon3(scope, credCommitment, blindingNonce)` where `blindingNonce` is a fresh private input per audit session. The current construction has no such blinding.

**In-threat-model?** No — the construction must address this. §4 Theorem 2 and §2 G3 both fail to account for the public leakage of `credCommitment` as a Merkle leaf. The privacy claim for `rootScopeCommitment` and `finalScopeCommitment` is broken under realistic on-chain enumeration.

---

### Attack 2: `policyFloor` Is a Per-Bit Extraction Oracle for `finalScope`

**Attack:**
The auditor controls `policyFloor` (public input) and observes `policyMet` (public output, §2). `policyMet = 1` iff `finalScope AND policyFloor == policyFloor` — i.e., every bit set in `policyFloor` is also set in `finalScope`. This is a 1-bit oracle indexed by `policyFloor`.

In a regulatory setting (the exact scenario in §7 — NCUA examination of NFCU), the auditor has authority to demand a fresh proof for any `policyFloor` value. Submit 8 proofs, one for each `policyFloor ∈ {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}`. Observe `policyMet` for each. In 8 queries, the exact `finalScope` bitmask is recovered bit-by-bit. The construction's claim that "The auditor does NOT learn…what permissions each hop had" (§7, step 5) is broken for the final hop.

**Why it works / why it fails:**
The oracle requires the pipeline operator to cooperate by generating proofs for each query — but in a regulatory examination, the operator has no choice. This is not a cryptographic break; it is a protocol-level information leak the security games in §3 do not model. The CHAIN-PRIVACY game (§3) fixes the public inputs across two challenger chains, including `policyFloor`. It explicitly does not model an adversary who adaptively queries with varying `policyFloor` values on the same underlying chain. The threat model is too narrow.

A defense would be to remove the per-bit query capability — e.g., require `policyFloor` to be pre-committed before the chain is assembled, or restrict the verifier contract to accept only one audit proof per `chainDigest`. Neither constraint exists in the current construction.

**In-threat-model?** No — the construction must address this. The CHAIN-PRIVACY game (§3) must be extended to an adaptive, multi-query version. The current single-proof framing does not capture the 8-query reconstruction attack available to a regulatory auditor in the §7 deployment scenario.

---

### Attack 3: For Regulated Deployments, a Supervised AS Is the Correct Trust Anchor

**Attack (RFC advocate's strongest angle):**
The construction's §7 scenario invokes NCUA examination of Navy Federal Credit Union. This is a regulated financial context. Section 8 claims "AS-blind auditing" is a load-bearing advantage because "a compromised/subpoenaed AS reconstructs the full chain." But in the §7 deployment:

- NFCU's AS is a supervised entity under NCUA examination authority and BSA/AML obligations.
- NCUA already has legal compulsion authority over NFCU's systems. A subpoena on the AS is no different from a subpoena on the loan origination database.
- A signed JWT introspection response (draft-ietf-oauth-jwt-introspection-response) issued by the AS can assert "delegation chain narrowed monotonically, root scope = {bitmask}, final scope = {bitmask}, all hops enrolled as authorized agents, chain length ≤ 16" — cacheable, offline-verifiable, no hot-path AS required.
- The AS's legal accountability under NCUA supervision *is* the trust anchor, exactly as it is for every other data point NCUA examines. Replacing AS accountability with cryptographic enforcement trades a known, legally-grounded assurance model for an exotic one with the attack surface in attacks 1 and 2 above.

The ZK advantage — "auditor cannot learn intermediate scopes" — only matters if the auditor is adversarial to the operator. In an NCUA examination, the auditor is the regulator and *should* have full access. The construction defends against the wrong adversary for its own claimed deployment scenario.

**Why it works / why it fails:**
This attack does not break the circuit math; it attacks the threat model framing. The construction's §7 is self-undermining: it picks a regulatory scenario where the "AS subpoena" threat is not only legal but expected, then claims ZK removes a threat the legal framework mandates. The better deployment claim for ZK is the whistleblower and cross-org variants (§7), where AS trust IS the threat. The headline scenario is the weakest possible choice.

RFC 7662 + draft-ietf-oauth-jwt-introspection-response + RFC 8693 covers the NFCU/NCUA case without new ceremony keys, new circuit audits, or exotic proving infrastructure. The construction should abandon §7's regulatory scenario and lead with the whistleblower case, where the AS-blind property is not moot.

**In-threat-model?** No — the construction must address this. §7 chooses a deployment scenario that actively weakens the ZK advantage and should be replaced or substantially reframed.

---

### Attack 4: G9 Anchors to Enrollment, Not to Authorization — Multi-Org Phantom Chains Survive

**Attack:**
G9 (§2) requires every active hop to prove Merkle inclusion of its `credCommitment` in `agentRegistryRoot`. The threat model explicitly excludes adversaries who can "enroll arbitrary credential commitments" (§3). But the exclusion is too strong for the §7 cross-org handoff scenario.

Consider: NFCU delegates to a third-party appraisal vendor (§7). Both organizations' agents are enrolled in the "same agent Merkle tree." Who controls enrollment? The registry contract requires "operator-signed credentials verified by the `AgentPolicy` circuit before insertion" — but "operator" is per-organization. In the cross-org scenario, NFCU is the operator for its agents, and the appraisal vendor is the operator for its own agents.

The appraisal vendor can enroll a credential commitment for a key they control — call it `credCommitment_phantom`. This credential is legitimately enrolled (it passed `AgentPolicy` verification, the operator signed it, the Merkle leaf is real). The vendor then constructs a delegation chain where one hop uses `credCommitment_phantom`, signs with the corresponding attacker-controlled key, and produces a valid EdDSA delegation token. G9 passes (Merkle inclusion is real), G4 passes (EdDSA signature is valid). The auditor sees `narrowingHolds = 1` and `policyMet = 1`. The "phantom" participant is enrolled but represents a shell agent with no actual operational role — or, in the whistleblower scenario, is a sybil identity used to break anonymity of adjacent hops.

**Why it works / why it fails:**
G9 closes the *unenrolled* phantom attack (§2, "Why G9 is necessary") but does not distinguish enrolled-authorized agents from enrolled-phantom agents. The Merkle tree proves existence in the registry; it does not prove the enrolled agent was authorized by any party outside its own org to participate in this specific delegation chain.

RFC 8693 has the same limitation — the AS can be coerced by a malicious org to issue tokens. But the construction claims to eliminate AS-trust requirements while introducing an equivalent trust requirement on registry operators, without naming it as such. The security game (§3, CHAIN-NARROW-SOUNDNESS condition b) treats "enrolled in the Merkle tree" as equivalent to "legitimate participant," which is only true under single-operator deployments. Multi-org deployments require a cross-org enrollment authorization proof, which the construction does not provide.

**In-threat-model?** No — the construction must address this. A cross-org deployment requires either (a) a single root-of-trust enrollment authority (reintroducing a centralized AS equivalent), or (b) a cross-org credential authorization circuit that verifies not just Merkle inclusion but the delegation lineage of the enrollment credential itself. Neither exists in the current construction, and the cross-org handoff scenario in §7 is not protected.


## Persona: spiffe_engineer

> Staff engineer running SPIFFE/SPIRE in production for a Fortune 500; co-author of WIMSE drafts. Stance: workload identity is a solved problem at the right layer.

---

### Attack 1: Cross-Org Federation Requires a Shared Registry You Never Specified

- **Attack:** §7 describes the "cross-org handoff variant" — NFCU delegates to a third-party appraisal service, and the NCUA auditor verifies the whole chain. But G9 requires every active hop's `credCommitment[i]` to be a leaf in the **same** `agentRegistryRoot`. That root comes from the **same** on-chain Merkle tree. Who controls enrollment into that tree? The construction says enrollment is gated by `AgentPolicy` circuit verification with **operator-signed credentials**. There is exactly one operator key (or operator key hierarchy) authorizing insertions. In a cross-org scenario, either (a) NFCU controls the operator key — the appraisal vendor is at NFCU's mercy for enrollment and can be deregistered at will — or (b) a neutral third party controls enrollment, and you have reintroduced a trusted intermediary, which §8 claims is eliminated.

  SPIFFE solves this with federated bundle endpoints. NFCU's SPIRE server and the appraisal vendor's SPIRE server each maintain their own trust domain (`spiffe://nfcu.com/...` vs `spiffe://appraisal.com/...`). A federation policy maps trust across domains. Neither party controls the other's enrollment; both retain sovereignty. The construction provides no equivalent.

- **Why it works / fails:** The construction fails here. The `agentRegistryRoot` is presented as a single shared root. For single-org pipelines this is fine. For cross-org, the construction punts entirely — it says "both organizations' agents are enrolled in the same agent Merkle tree" as if that were obvious. It isn't. The enrollment governance model for a shared inter-organizational registry is the hard problem, and the construction never specifies it.

- **In-threat-model?** No. The threat model (§3) only defines adversaries operating *within* an established chain with a single `agentRegistryRoot`. Cross-trust-domain enrollment governance is entirely outside scope. The construction must address this to make the cross-org scenario in §7 non-fictional.

---

### Attack 2: Regulatory Audit Blindness Is a Bug, Not a Feature

- **Attack:** The construction repeatedly claims that the auditor learning nothing about intermediate participants is the privacy property that makes this compelling. But look at the concrete regulatory scenario: the NCUA auditor is examining NFCU's loan pipeline for BSA/AML and vendor management compliance. NCUA examination procedures (12 CFR 748, NCUA Letter 01-CU-20) **require** that the credit union demonstrate which third-party service providers processed which member data. `policyMet = 1` and `narrowingHolds = 1` tell the NCUA auditor nothing about whether the appraisal vendor is an approved FFIEC-examined entity, whether they processed PII in a GDPR-compliant jurisdiction, or whether they are even on the credit union's vendor approval list.

  The WIMSE model using X.509 SVIDs gives the auditor exactly what NCUA wants: a signed, attributable delegation record where every workload hop is identified by its SPIFFE ID. The NCUA examiner can trace `spiffe://nfcu.com/loan-pipeline/underwriter` to `spiffe://appraisalco.com/valuation-service`, confirm the vendor is on the approved list, and produce the audit trail. This takes minutes and requires no ZK infrastructure.

- **Why it works / fails:** The construction's privacy properties directly conflict with real regulatory requirements in the stated deployment scenario. The proof is simultaneously too strong (hides things regulators need to see) and too weak (proves only monotonic narrowing, not that the pipeline complied with vendor management policy). The construction is solving for a privacy threat (internal scope leakage to the auditor) that doesn't match the actual threat in the NFCU scenario, where the auditor is an adversarial regulator who is *supposed* to learn who the vendors are.

- **In-threat-model?** No. The threat model only models a "corrupted auditor" who receives public outputs. The scenario where the auditor is a regulatory principal with legal authority to demand participant identity is not modeled. The construction must distinguish "privacy auditor" from "compliance auditor" or the NFCU scenario is misleading.

---

### Attack 3: Operator Key Compromise Collapses G9 Completely

- **Attack:** G9 is the construction's main defense against phantom chains. Its soundness argument (§4, Theorem 1, Case b) reduces to: fabricated credentials cannot produce a valid Merkle inclusion proof against the on-chain root. This holds *if and only if* the Merkle tree itself was not seeded with fabricated credentials during enrollment.

  Enrollment is gated by "operator-signed credentials verified by the `AgentPolicy` circuit before insertion." The operator holds an asymmetric key. This key is a long-lived privileged signing oracle. An insider with access to the operator key (or a compromised CI/CD pipeline, an HSM misconfiguration, or a key ceremony failure) can enroll arbitrary `credCommitments` into the registry — commitments bound to attacker-controlled EdDSA key pairs. Once enrolled, an attacker can construct an entire valid delegation chain with real Merkle proofs, real EdDSA signatures, and real enrollment — and G9 will accept it. The phantom chain attack is fully reinstated via a compromised enrollment ceremony.

  SPIRE addresses this with hardware node attestation. A workload's SVID is only issued after the SPIRE agent validates the workload against a configured attestor plugin: TPM quote, cloud provider instance identity document, Kubernetes service account JWT verified against the API server. The operator key signs *policies*, not individual credentials. An operator key compromise affects policy configuration, not the ability to forge workload identity proofs, because proof of identity is anchored to hardware state, not a signing key.

- **Why it works / fails:** The construction's operator key is a single point of trust whose compromise is unaddressed. The security argument in §4 explicitly excludes "enrollment is permissioned by the registry contract" from the formal game — enrollment integrity is a precondition, not a proven property. The construction must specify the operator key management model (HSM requirements, key rotation, ceremony procedures) or acknowledge that G9's security reduces to operator key security, which is weaker than SPIRE's attestation-rooted model.

- **In-threat-model?** No. §3 states the adversary "cannot enroll arbitrary credential commitments in the agent Merkle tree (enrollment is permissioned by the registry contract)." This is an assumption, not a proven property. A compromised operator key breaks this assumption, and the threat model simply declares it out of scope. This is the construction's most significant underspecification.

---

### Attack 4: The On-Chain Verification Model Adds Failure Modes Without Adding Value

- **Attack:** The construction's §6 positions "one PLONK proof, verified in one on-chain call (~300K gas)" as an advantage over O(n) WIMSE artifacts. This inverts the actual operational tradeoff. SPIRE's offline verification model means an auditor verifies the delegation chain against signed bundles with no dependency on network availability, gas markets, sequencer liveness, or blockchain finality. The construction is anchored to Base Sepolia (per the project CLAUDE.md). Any on-chain verification during a Base outage, during a gas spike, or before the `agentRegistryRoot` is confirmed in the root history buffer fails — and the audit cannot proceed.

  More precisely: the root history buffer holds 30 entries (§5). If a chain was generated against root R, and 31 subsequent Merkle tree updates occur before the proof is submitted (plausible in a high-throughput pipeline), the proof is no longer verifiable on-chain — the root R has aged out. The prover must regenerate the entire chain proof against the current root, which requires re-proving with the current Merkle inclusion paths for all hops. This is not a theoretical edge case: any pipeline running at >30 updates/audit cycle hits this. The WIMSE model has no equivalent expiration.

- **Why it works / fails:** This is a partial attack. The construction is correct that a single aggregated proof is more efficient than O(n) artifacts for a *synchronous online audit*. But it does not argue for why the audit must happen on-chain, or why 30-root history is sufficient for the stated use case. The off-chain PLONK verification alternative (the verifier downloads the vkey and checks the proof locally, using a signed checkpoint of `agentRegistryRoot`) is not discussed. Without it, the construction trades WIMSE's operational resilience for on-chain liveness dependency, which is a regression for a Fortune 500 compliance workflow.

- **In-threat-model?** Partial. The construction's proof-of-concept is sound against the stated game. The operational liveness dependency is a deployment concern, not a cryptographic break. However, the root history buffer window is a correctness constraint that interacts with real deployment parameters (how frequently does the agent registry update?), and the construction never bounds or analyzes this. A production deployment at the scale of NFCU's 13M-member pipeline could exhaust the 30-root window in minutes.
