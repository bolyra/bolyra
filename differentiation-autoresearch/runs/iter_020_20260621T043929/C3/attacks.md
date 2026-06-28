# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Proof Latency Makes This Unusable at Hop-Chaining Cadence

- **Attack:** The construction targets < 5s PLONK / ~1.5–3s rapidsnark per proof (§6, Proving time targets). For a 4-hop NFCU pipeline (§7, Scenario), proof generation must complete before the next hop can use the output — because each hop's `chainSeedScopeCommitment` is the prior hop's `finalScopeCommitment`. That's a *minimum* sequential latency of 4 × 1.5s = 6s at best, 4 × 5s = 20s at worst, just to initiate the loan processing pipeline. Stytch MCP auth issues a scoped token in < 100ms. Auth0 does < 80ms at p99. The construction's §7 scenario involves a member waiting at a loan desk — a 6–20 second stall before the first agent does any work is not a product.

- **Why it works / fails:** The construction does not address proof pre-computation or parallelism strategies. It tacitly assumes the chain is built hop-by-hop at runtime. There is no discussion of offline proof batching, optimistic execution with deferred proof submission, or whether the audit proof must be generated at pipeline invocation time versus post-hoc. Until these are addressed, this is an accurate latency attack. A pre-computation approach (proofs generated at delegation-time, not pipeline-invocation time) could neutralize it — but only if delegation topology is known ahead of pipeline execution, which breaks dynamic tool-calling pipelines.

- **In-threat-model?** No. The construction's threat model (§3) is cryptographic only; it does not address operational latency. This must be addressed.

---

### Attack 2: The Global Merkle Tree Requirement is a Network-Effect Moat for Incumbents

- **Attack:** §7 (NFCU scenario, Agent Merkle root pinning paragraph) explicitly states: "the third-party fintech's market-data agent at hop 3 must also be enrolled in the same tree; if it is enrolled in a separate tree, the two organizations must use a shared agent registry (the Bolyra on-chain registry serves this role) or the proof cannot be generated." This is the deployment killer. WorkOS MCP auth works with any OAuth 2.0 client — the counterparty doesn't need to have adopted WorkOS. Auth0 speaks OIDC; everyone already implements OIDC. Bolyra requires both the NFCU and the third-party fintech to have independently enrolled in Bolyra's on-chain registry before a single proof can be generated. The construction's cryptographic strength — a single `agentMerkleRoot` proving all delegatees are real without naming them — is simultaneously its GTM weakness: you cannot prove enrollment without both parties being enrolled. A buyer's procurement team asks WorkOS for a reference customer list; they ask Bolyra how many counterparty fintechs are pre-enrolled. The answer is zero.

- **Why it works / fails:** The attack is structurally valid and unfalsifiable by the construction's current text. The construction offers no path for cross-org enrollment that doesn't require counterparty buy-in to Bolyra specifically. A potential mitigation — cross-registry attestation bridges — is not described and would substantially complicate the security argument (you'd need to argue about trust between root history buffers, not just one). The §8 table claims "Cross-org without shared trust anchor" as a differentiator, but this is misleading: the Bolyra on-chain registry *is* the shared trust anchor — it's just a different one than an OAuth AS.

- **In-threat-model?** No. Cross-org enrollment bootstrapping is not addressed. This is a go-to-market blocker that also has protocol implications.

---

### Attack 3: Regulated Procurement Rejects Solo-Founder Cryptographic Primitives

- **Attack:** NFCU is NCUA-regulated. Their CISO will ask for SOC 2 Type II, ISO 27001, a signed BAA if PII is in scope, indemnification clauses, and an SLA with financial penalties. They will ask: "Who is liable if the NCUA rejects a ZK proof as valid audit evidence?" The construction's §7 frames the NCUA examiner calling `DelegationAuditVerifier.verifyProof()` on-chain as a natural step, but NCUA examiners do not call Solidity verifier contracts. They read PDF reports from certified systems. Auth0 has Okta's legal team, audited infrastructure, and existing NCUA/FFIEC-aware documentation. The construction's "auditor receives `narrowingValid = 1`" output (§1) is not a finding that appears in an NCUA examination report without an interpretive layer that doesn't exist yet.

- **Why it works / fails:** The attack hits a real gap between cryptographic correctness and institutional acceptability. The construction is technically sound — `narrowingValid = 1` is a meaningful output — but the deployment scenario requires NCUA to have a policy position on ZK proofs as audit evidence, which they do not. This is not a cryptographic problem, it's a regulatory recognition problem. Auth0's procurement friction at a credit union is "get on the approved vendor list"; Bolyra's friction is "convince the regulator that a novel cryptographic primitive constitutes audit evidence." The construction does not address this at all.

- **In-threat-model?** No. Regulatory recognition of ZK proofs as audit artifacts is outside the threat model but is the decisive adoption gate for the NFCU scenario specifically.

---

### Attack 4: Registry Operator Breaks Journalist/Source Anonymity at Enrollment Time

- **Attack:** The journalist/source scenario (§7, last subsection) claims "even a compromised auditor learns nothing about hops 1 and 2." But the construction's own threat model (§3, adversary model) states: "A cannot insert leaves without valid operator-signed credential commitments enrolled through the registry." This means *someone* approved the source's agent enrollment. If the Bolyra on-chain registry requires operator-signed enrollment, then the registry operator — whoever runs the enrollment gate — knows the source agent's `delegateeCredCommitment` at the time it was added as a Merkle leaf. The ZK proof hides the source's identity from the *auditor*, but the registry operator can trivially deanonymize the source by correlating enrollment records with the known `agentMerkleRoot` and chain length. The construction's anonymity guarantee is auditor-anonymous, not operator-anonymous. For a whistleblower scenario, the threat is often not the editorial board (the auditor) but the operator of the infrastructure the source must trust to participate. This gap is not acknowledged in §7 or §3.

- **Why it works / fails:** This is a genuine in-scope security gap. The threat model explicitly excludes the operator from the adversary's capabilities without justifying why the journalist/source scenario can tolerate operator trust. The fix would require either (a) a decentralized enrollment mechanism that doesn't require an operator to approve enrollments (removing the operator as a trust point), or (b) explicitly scoping the anonymity claim to exclude operator-level adversaries and removing the journalist/source scenario as a claimed use case. Neither is a trivial change — option (a) raises Sybil resistance questions the construction currently delegates to operator-signed enrollment.

- **In-threat-model?** Partially. Game 2 (Participant Privacy, §3) specifies the adversary as one "playing as auditor" — it does not consider a compromised or malicious registry operator. The journalist scenario is presented in §7 as a first-class use case. The construction must either extend the threat model to cover operator adversaries or retract the journalist/source claim.


## Persona: cryptographer

Applied cryptographer. I've read §§1–8 of the DelegationAuditChain construction carefully. The narrowing-soundness and phantom-enrollment fixes are real improvements. But four problems remain unaddressed.

---

### Attack 1: Dictionary Attack on `finalScopeCommitment` — Theorem 3 Is Vacuous for Small Scope Spaces

**Attack:**
Theorem 3 (Scope Privacy, §4) claims that recovering `delegateeScope[last]` requires inverting `Poseidon2(delegateeScope[last], delegateeCredCommitment[last])`. The argument assumes the scope occupies a 64-bit field with ~2^64 entropy. It does not. The construction's own §1 permission model (bits 0–7, cumulative implication rules on bits 2/3/4) constrains valid bitmasks to a tiny set — the cumulative encoding on bits 2, 3, 4 eliminates all configurations where bit 4 is set without 2 and 3, bit 3 without 2, etc. In practice, the valid mask space is ≤ 20–50 combinations, not 2^64.

Concrete attack: the adversary fixes `delegateeCredCommitment[last]`. If that commitment is inferable — e.g., it appears as a leaf in the public `agentMerkleRoot` tree (which the on-chain registry must populate somehow) or was disclosed in a prior handshake's public output — the adversary enumerates all ≤ 50 valid bitmasks, computes `Poseidon2(mask, credCommitment)` for each, and checks against the public `finalScopeCommitment`. This is not a Poseidon inversion; it is a lookup table of 50 evaluations.

**Why it works:** Theorem 3 conflates field-element entropy with semantic entropy. The circuit uses `Num2Bits(64)` on scope signals, but the cumulative-bit-encoding gate (constraint 4) restricts the valid witness space far below 2^64. The preimage is constrained by an arithmetic system the adversary knows. The reduction to Poseidon preimage resistance is only valid when the preimage has sufficient entropy — here it does not.

**In-threat-model?** No. The threat model (§3, Game 3) states A wins if it can recover any intermediate scope with probability > 1/2^64 + negl(λ). The 1/2^64 bound assumes uniform 64-bit entropy, which the construction itself destroys via the cumulative-bit-encoding constraint. The construction must either (a) explicitly prove that the effective preimage space has high min-entropy even after constraint reduction, or (b) commit the scope as a full-field-element random nonce with the bitmask derived from it, rather than using the bitmask directly as the Poseidon input.

---

### Attack 2: HVZK ≠ Malicious-Verifier ZK — Theorem 2 Fails for an Adversarial Auditor

**Attack:**
Theorem 2 (Participant Privacy, §4) reduces to "zero-knowledge of the proving system." §7 goes further, asserting "even a compromised auditor with unbounded compute learns nothing" about intermediate participants. This claim requires **malicious-verifier zero-knowledge (MVZK)**, not honest-verifier zero-knowledge (HVZK).

Standard Groth16 achieves **HVZK**: the simulator requires the CRS trapdoor (toxic waste) to produce indistinguishable transcripts. If the toxic waste is not available (as the adversary model assumes), the simulator in the security argument does not exist in the standard model without additional assumptions. The proof of Theorem 2 says "the simulator produces indistinguishable transcripts" but never exhibits the simulator or states what it needs as input.

For the journalist/source variant specifically: the "adversarial auditor" in §7 is explicitly described as a compromised editorial board. This is exactly a malicious verifier — it deviates from the protocol and may issue non-standard queries or attempt to correlate transcripts. Groth16's HVZK does not protect against this. PLONK (KZG) is also only HVZK in the standard presentation.

The simulator that would be needed for MVZK either requires:
- The CRS trapdoor (which is "not controlled by A" — but this just relocates trust to the ceremony), or
- A transformation to a simulation-extractable NIZK, which Groth16 and standard PLONK are not (without additional wrapping like Fiat-Shamir in the ROM).

**Why it works:** The game definition in §3 Game 2 places A in the role of auditor and gives it the proof transcript. The proof of Theorem 2 offers no simulator construction; it hand-waves to "the ZK property of Groth16/PLONK." That property is HVZK, proven under the trapdoor. Without the trapdoor, the reduction is a gap.

**In-threat-model?** No. The construction must either (a) restrict the claim to HVZK with honest auditors and remove the §7 "unbounded compute" claim, or (b) prove MVZK explicitly (e.g., by arguing Fiat-Shamir in the random oracle model gives MVZK for the Groth16 proof of knowledge, and citing a theorem to that effect). The current security argument is incomplete on this point.

---

### Attack 3: Single `agentMerkleRoot` as Global Registry Leaks Cross-Org Business Relationships Before Any Proof Is Generated

**Attack:**
Constraint 7 (§2) pins every active hop's Merkle root to the single public input `agentMerkleRoot`. §7 explicitly acknowledges the consequence: "the two organizations must use a shared agent registry." The on-chain agent Merkle tree is therefore a **global enrollment registry** that all participants in any cross-org delegation chain must join before proving membership.

The adversary does not need to break the circuit. The adversary monitors the on-chain registry's leaf-insertion events. When Navy Federal's front-desk agent, the third-party fintech's market-data agent, and the credit-scoring and rate-lookup agents all enroll in the same tree, the enrollment transactions reveal a business relationship graph — before any delegation proof is ever generated. The adversary constructs a bipartite enrollment graph: organizations on one side, agent credential commitments on the other. Cross-org co-enrollment is a timing side-channel and a business intelligence signal.

For the journalist/source scenario, this is fatal: the editorial publication and its sources must both enroll their agents in the same Merkle tree to use the construction. A state-level adversary who monitors on-chain transactions can identify that a publication's agent and a source's agent enrolled in the same tree within a time window, inferring a relationship before any delegation chain is attempted.

**Why it works:** The ZK circuit hides which leaves are used in a given proof, but leaf insertion is a public, non-ZK operation. The threat model (§3) defines A's view as proof transcripts and public inputs; it does not include enrollment transaction metadata. This is a scope gap in the adversary model, not a circuit bug — but for the stated journalist/source use case, it is mission-critical.

**In-threat-model?** No — the threat model explicitly restricts A's view to proof transcripts. The construction must either (a) extend the threat model to include enrollment metadata and address it (e.g., via anonymous credential issuance for tree leaves, or a shielded enrollment scheme), or (b) retract the journalist/source anonymity claim for any adversary with access to on-chain data.

---

### Attack 4: Groth16 Non-Malleability Is Not Established — `auditDigest` Replay Prevention Is Underspecified and UC Composition Fails

**Attack:**
The construction uses `auditDigest` as a replay-prevention tag checked against an on-chain registry (§2, §5). The security argument implicitly assumes that a valid proof π for a given `(chainSeedScopeCommitment, agentMerkleRoot, sessionNonce, auditDigest)` cannot be re-submitted or mauled without producing a different `auditDigest`.

Standard Groth16 is **not simulation-extractable** in the standard model. It is malleable: given a valid proof π = (A, B, C) for statement x, an adversary can in principle compute related proofs by manipulating group elements. The Groth16 CRS structure (with α, β, δ encodings) is specifically designed so that the only way to produce a valid π is to know a witness, but this is a knowledge-soundness argument in the AGM — it does not imply non-malleability of the transcript itself. Whether a mauled π' satisfies the verification equation is a separate question from whether the public inputs x are preserved.

More concretely, the construction is embedded in a larger protocol ecosystem (handshake, delegation, registry contracts). UC composition requires that the underlying NIZK be simulation-extractable: any sub-protocol that contributes a NIZK proof must produce a transcript that cannot be mauled by a network adversary to appear as a fresh proof in a different protocol context. Without simulation-extractability, an adversary observing a DelegationAuditChain proof in context C1 could potentially replay or maul it as a purported proof in context C2, undermining the cross-protocol security the construction implicitly claims via `sessionNonce` binding.

The construction claims `sessionNonce` prevents cross-context replay (§3, Game 4), but session-nonce binding only prevents literal replay of the same (π, x) pair — it does not prevent a mauled (π', x) where π' ≠ π but both satisfy the verifier, nor a transcript-level attack in the UC model.

**Why it works:** The security argument for Theorem 4 (Chain Integrity) says "The EdDSA signature constraint (6) further requires the delegator's private key to sign the delegation token, so even a Poseidon preimage would not suffice without also forging an EdDSA signature." This reduces chain integrity to EdDSA unforgeability — but this is a knowledge argument, not a non-malleability argument. The reduction in Theorem 4 is to A1 (knowledge soundness) + A2 (Poseidon collision resistance) + A4 (EdDSA unforgeability). None of these imply proof non-malleability or simulation-extractability.

**In-threat-model?** No. The threat model does not define a UC composition game or address what happens when DelegationAuditChain is composed with the handshake protocol or other delegation sessions. The construction must either (a) restrict claims to the standalone non-interactive setting and disclaim UC security, (b) add a Fiat-Shamir-based wrapper that achieves simulation-extractability in the ROM (citing e.g. Bowe–Gabizon or the SE-Groth16 literature), or (c) use a proving system that is already simulation-extractable (e.g. Groth-Maller or a SNARK with a dedicated non-malleability transform). The current security argument has a gap precisely where it matters most for cross-protocol deployment.


## Persona: cu_ciso

---

### Attack 1: Audit Trail Opacity Fails NCUA Part 748 §748.1(b) — "Prove This to My Examiner"

- **Attack:** The NCUA examiner arrives for their annual IT examination and requests the access log for the loan-processing pipeline that touched member account #XXXX on June 15. The construction produces `narrowingValid = 1`, `chainLength = 3`, and an `auditDigest`. The examiner asks: *"What was the credit-scoring agent authorized to do? Did it have ACCESS_PII at that moment? Show me the scope at each hop."* The construction's answer is: *you cannot know — that is the ZK property.* NCUA Part 748 Appendix A (the security guidelines) requires covered institutions to maintain access controls and audit logs sufficient to reconstruct what happened during a security event. The Interagency Guidelines Establishing Information Security Standards (12 CFR Part 748, Appendix B) demand that audit records support *after-the-fact investigation* — not just proof that some narrowing occurred. `narrowingValid = 1` is not an audit record. It is a boolean with no reconstructive value.

- **Why it works / why it fails against the construction:** The construction explicitly treats intermediate scope values as *secret inputs* and advertises this as a feature (§7: "What the examiner does NOT receive: Any intermediate scope bitmask"). But NCUA examiners do not evaluate ZK soundness; they evaluate whether the institution can demonstrate access control governance. The construction provides cryptographic assurance to a peer who trusts ZK proofs. It provides nothing to an NCUA field examiner who needs to write finding narrative. The scenario in §7 describes what the examiner *receives* but never addresses what the examiner *does with it* when there is a dispute — e.g., a member complaint that the AI agent accessed PII it wasn't supposed to. The proof says "all hops narrowed"; it cannot say "hop 2 had ACCESS_PII" because that is a private input. The institution cannot satisfy a member dispute, a BSA/AML SAR narrative, or an NCUA corrective action without a privileged disclosure path.

- **In-threat-model?** No — the construction must address it. The threat model (§3) defines the auditor as an entity who *cannot* learn intermediate scopes. But regulatory audit is adversarial in the opposite direction: the regulator *needs* selective disclosure by the institution to itself for compliance reconstruction, not ZK opacity. The construction needs a dual-mode audit: a ZK proof for the external party proving narrowing occurred, plus an institution-private, institution-readable log that maps `auditDigest` back to plaintext scope transitions, stored under GLBA-compliant encryption and producible on NCUA demand. This is not in the construction.

---

### Attack 2: Incident Response Paralysis at 2am — FFIEC CAT Domain 3 (Cyber Incident Management)

- **Attack:** A member calls at 2:47am reporting an unauthorized $85 transfer attributed to "an AI agent" in the loan pipeline. The Tier 1 ops team pulls up the audit dashboard. They can verify the on-chain `auditDigest` against the replay registry and confirm `narrowingValid = 1`. They cannot answer any of the following: Which agent instance executed the transfer? What scope did it hold at the moment of execution? Was FINANCIAL_SMALL permission active for that hop? Is the agent still running with live credentials? Should they revoke it? The `finalScopeCommitment` is a Poseidon hash over values the ops team cannot see. The `auditDigest` is a hash chain that maps to nothing human-readable without re-running the prover with private inputs the ops team does not possess. The FFIEC CAT Domain 3 (Cyber Incident Management and Resilience) requires documented incident response procedures including containment, eradication, and recovery — all of which require knowing *what was compromised*.

- **Why it works / why it fails against the construction:** The construction's privacy model treats *participant identity* and *intermediate scope* as always-secret. But incident response requires the *operating institution* (NFCU in the scenario) to be able to identify, contain, and remediate. There is no privileged "break-glass" decryption path described anywhere in §2–§8. The institution *cannot* revoke a specific agent mid-chain because it cannot identify which leaf in the Merkle tree corresponds to the active agent from the public outputs alone. The 30-entry root history buffer (§3.1 reference) ensures freshness; it does not provide a revocation mechanism that Tier 1 can invoke in under 15 minutes. The construction conflates *external* privacy (hiding agents from the NCUA auditor or a counterparty) with *internal* operational opacity (hiding agents from the institution's own ops team). These require different keys and different trust models.

- **In-threat-model?** No — the construction must address it. The deployment scenario (§7) is written from the perspective of the NCUA examiner receiving the proof. It is not written from the perspective of the ops team trying to stop a live incident. A construction that cannot support containment is not deployable at a federally-insured credit union regardless of its cryptographic properties.

---

### Attack 3: Third-Party Risk Due Diligence — NCUA Letter 07-CU-13 / 2021 Interagency Guidance on Third-Party Relationships

- **Attack:** At hop 3 in the NFCU scenario (§7), a "third-party fintech" market-data agent is enrolled as a leaf in the agent Merkle tree. The construction proves this agent is enrolled in the tree and that the scope it received is a bitwise subset of the rate-lookup agent's scope — currently just `READ_DATA`. NFCU's vendor management officer asks: *"Who is this vendor? What jurisdiction are they in? Do they have a SOC 2 Type II? What data can they access under their SLA? Are they on OFAC's SDN list?"* The answer from the construction: the agent's `delegateeCredCommitment` is a Poseidon hash of `(modelHash, opPubAx, opPubAy, permBitmask, expiry)`. None of those fields map to a legal entity name, a tax ID, a regulatory registration, or a contractual relationship. Enrollment in the Bolyra agent Merkle registry is not equivalent to completing a vendor risk assessment. Under the 2021 Interagency Guidance on Third-Party Relationships, NFCU must maintain due diligence documentation for *critical activities* — and a third party participating in member loan processing is explicitly a critical activity.

- **Why it works / why it fails against the construction:** The construction proves cryptographic properties of the delegation chain. It proves nothing about the vendor relationship, the vendor's internal controls, the data processing agreement, or the vendor's regulatory status. The `agentMerkleRoot` confirms the third-party agent is enrolled; it says nothing about *who enrolled it* or under what contractual terms. An attacker (or negligent operator) could enroll a shell company's agent with a valid EdDSA key pair and a `READ_DATA` scope, and the proof would be indistinguishable from a legitimate fintech vendor. The construction's baseline comparison (§8) correctly notes that WIMSE SPIFFE IDs are stable identifiers visible to verifiers — but the construction does not acknowledge that *in regulated financial services, visible vendor identity is a compliance requirement, not a privacy liability*.

- **In-threat-model?** No — this is explicitly out of the threat model (§3 does not model vendor management obligations) and the construction must address it. A viable path: the registry enrollment process (outside the circuit) must require operator-signed metadata linking `opPubAx, opPubAy` to a legal entity, with vendor management attestations stored in the registry contract. The circuit remains ZK about delegation specifics; the registry provides the regulatory paper trail. The construction is silent on this.

---

### Attack 4: Key Compromise and Credential Revocation — GLBA Safeguards Rule §314.4(c)(6) and the Expiry Window Attack

- **Attack:** At 11:55pm, NFCU's security team discovers the front-desk agent's EdDSA operator private key has been exfiltrated (e.g., via a compromised HSM or a rogue operator). The key signed the delegation token at hop 1 for a 24-hour expiry window. Under the construction, the only revocation mechanism is: (a) remove the agent's credential commitment from the Merkle tree (triggering a new `agentMerkleRoot`), and (b) wait for that new root to propagate into the 30-entry root history buffer. But existing proofs generated with the *prior* root remain valid until expiry — up to 24 hours. A compromised key holder can continue generating valid hop-1 delegation tokens, each narrowing scope to `READ_DATA | FINANCIAL_SMALL`, for the full 24-hour window. The on-chain replay registry catches reused `auditDigest` values, but each new delegation to a new sessionNonce produces a fresh, valid proof. The GLBA Safeguards Rule §314.4(c)(6) requires procedures to *respond to and recover from* security events, including the ability to revoke access within a defined window. FFIEC expects covered institutions to define RTO for access revocation.

- **Why it works / why it fails against the construction:** The construction's security argument (§4) assumes the adversary cannot insert leaves into the agent Merkle tree "without valid operator-signed credential commitments." But this threat is the opposite: a *legitimate* operator key is compromised and the adversary uses it to generate valid delegation tokens. The circuit correctly enforces narrowing — the adversary cannot *expand* scope. But the adversary can *use* the full remaining scope (including `FINANCIAL_SMALL`) for up to 24 hours. The construction has no emergency revocation path shorter than the expiry-minus-current-time window. The root history buffer's 30-entry tolerance (described as "ample tolerance for concurrent updates" in §2) becomes a liability: an institution cannot force-expire credentials because the circuit respects the `delegateeExpiry` field as set at delegation time, and that timestamp is a private input the verifier cannot override. The verifier checks `currentTimestamp` against `delegateeExpiry` per-hop, but `currentTimestamp` is a public input *supplied by the prover* (§2, public inputs table), not injected by the verifier contract from `block.timestamp`. This is an additional vector: a compromised prover can supply a stale `currentTimestamp` to make an expired credential appear valid at proof-generation time, provided the on-chain verifier does not enforce `currentTimestamp >= block.timestamp - tolerance`.

- **In-threat-model?** Partially. Game 5 (Phantom Enrollment) addresses unauthorized enrollment but not authorized-key-compromise. The construction must address: (1) whether `currentTimestamp` is enforcer-supplied or prover-supplied, and (2) what the operational revocation window is and whether it meets GLBA Safeguards incident response timelines. For a $2B–$10B credit union, an NCUA examiner will ask for the documented RPO/RTO for credential revocation. "Wait for expiry" is not an acceptable answer.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Shipped introspection at scale. Every ZK claim is a performance regression until proven otherwise.*

---

### Attack 1: JWT Introspection Response Already Removes the AS from the Hot Path

**Attack:**
Section 8 anchors its "no trusted third party" row on the premise that an auditor must *query* the AS — making the AS availability load-bearing. This was true of RFC 7662 in 2015. It is not true today.

`draft-ietf-oauth-jwt-introspection-response` (published as RFC-track) allows the AS to return a *signed JWT* as the introspection response. That JWT is offline-verifiable: the auditor caches the AS public key, receives the signed response once at chain-issuance time, and verifies it cold — no AS reachability required. Pair this with RFC 8693 (which already handles scope narrowing at token exchange time) and the AS can embed a `narrowing_valid: true`, `chain_length: 3` claim directly in the signed JWT without exposing intermediate scopes to the auditor.

The *only* information the auditor receives is what the AS chose to include in the response. Per-RS introspection policy (standard AS feature) already lets the AS filter scopes before disclosure. The auditor sees exactly the same surface as your `finalScopeCommitment` + `narrowingValid = 1` + `chainLength`.

**Why it works / why it fails against the construction:**
It fails because the signed JWT is an *assertion*, not a *proof*. The NCUA examiner receives "I, the AS, certify that narrowing occurred" — not a mathematical proof that the circuit constraints were satisfied. A compromised AS issues false attestations with no detectable artifact. The construction's narrowing guarantee is unconditional under A1+A2; the JWT guarantee is conditional on AS integrity, implementation correctness, and key management continuity. For NCUA examiners this matters: a SOC2 AS gets you *regulatory sufficiency*, but not *mathematical soundness*. The construction is strictly stronger here.

**In-threat-model?** Yes — construction survives. But §8's table should be more precise: the baseline's gap is "assertion by a trusted authority" versus "proof of an arithmetic relationship." The current framing ("AS in the hot path") is stale against RFC-track signed JWT introspection.

---

### Attack 2: pot16.ptau Is a Trusted Third Party — The "No Trusted Third Party" Row Is False

**Attack:**
Section 8, table row "No trusted third party": *"Proof is self-verifying against on-chain state. No AS, no federation anchor."*

This is wrong for both proving systems offered.

- **Groth16 path:** The per-circuit `.zkey` is derived from `pot16.ptau`. If the ceremony for `pot16.ptau` was compromised — if any participant retained the toxic waste — an adversary can generate a valid `DelegationAuditVerifier.verifyProof(π, publicSignals) = true` for any false statement, including `narrowingValid = 1` for a chain that widened scope at every hop. The on-chain verifier is mathematically sound but trusts the ceremony.

- **PLONK path:** The "universal setup" reduces but does not eliminate trust. The universal SRS still requires at least one honest participant in its own MPC ceremony. "Universal" means the SRS is reusable across circuits — it does not mean untrusted.

Compare to the baseline: if the AS is compromised, it issues false narrowing attestations. If the ceremony is compromised, the prover issues false narrowing proofs. The *failure mode is structurally identical*. The attack surface differs (AS software vs. MPC ceremony hygiene), but the construction cannot claim categorical trust elimination.

**Why it works / why it fails against the construction:**
The claim in §8 should read: "Trusted setup is a one-time, externally auditable MPC ceremony, not an online service that must be trusted for every verification." That is a real advantage — ceremony compromise is a single historical event, not an ongoing attack surface. But the table's unqualified "no trusted third party" is exploitable in any regulatory dispute: a regulator can reasonably demand "who ran the ceremony, and can I audit it?" The AS is also a deployable entity with auditable code. This is a parity argument, not a ZK defeat.

**In-threat-model?** No — the construction must address this. Replace the "No trusted third party" row with a nuanced claim: "Trust is in a one-time MPC ceremony (auditable, historical, external to NFCU) rather than an online AS (ongoing operational trust requirement)." The current framing overclaims.

---

### Attack 3: `finalScopeCommitment` Is a Stable Cross-Session Identifier for the Terminal Agent

**Attack:**
`finalScopeCommitment = Poseidon2(delegateeScope[last], delegateeCredCommitment[last])` is *deterministic* given the same terminal agent operating at the same permission level.

In any realistic deployment — the NFCU rate-lookup agent at hop 3 runs against the same market-data agent with the same `READ_DATA` scope across thousands of loan-processing sessions — `finalScopeCommitment` is constant across every proof generated. An auditor (or a network observer who correlates public proof transcripts) accumulates a corpus of proofs and observes: *these 4,000 proofs all share `finalScopeCommitment = 0xABCD...`*. The terminal agent is thereby identified as a recurring participant, its scope is narrowed to whatever committed values hash to that value, and longitudinal behavioral analysis becomes possible.

Game 2 as stated is a *within-session* indistinguishability game: "given two candidate chains C₀ and C₁... in a single verification." Game 2 says nothing about cross-session correlation. The construction provides participant privacy within a session but not across sessions for the terminal hop. Pairwise subject identifiers (OIDC PPIDs) — cited in the toolbox — are specifically designed to prevent exactly this: per-RS, per-session identifiers that don't correlate across contexts. The construction has no equivalent mechanism for the terminal commitment.

**Why it works / why it fails against the construction:**
A salt-per-session in the final scope commitment would close this: `finalScopeCommitment = Poseidon3(delegateeScope[last], delegateeCredCommitment[last], sessionNonce)`. The `sessionNonce` is already a public input — including it in the final commitment breaks cross-session correlation at zero circuit cost. The journalist/source scenario (§7) is particularly exposed: even if all intermediate nodes are hidden, a recurring terminal agent (the secure-drop tool always appears last) is linkable across all source interactions by its stable `finalScopeCommitment`.

**In-threat-model?** No — construction must address this. Either include `sessionNonce` in `finalScopeCommitment` or explicitly bound cross-session correlation as out-of-scope (then the journalist/source scenario cannot be cited as a motivation).

---

### Attack 4: Cross-Org `agentMerkleRoot` Requires a Shared Trust Anchor — This Is the AS by Another Name

**Attack:**
Section 7 (concrete deployment, hop 3) states: *"the third-party fintech's market-data agent at hop 3 must also be enrolled in the same tree; if it is enrolled in a separate tree, the two organizations must use a shared agent registry."*

Section 8 then claims the ZK construction achieves *"Cross-org without shared trust anchor"* because *"No per-org AS or federation required."*

These two statements are in direct contradiction. The shared agent Merkle tree **is** a shared trust anchor. To enroll in that tree, an operator must submit a credential commitment accepted by the Bolyra on-chain registry. The registry operator controls enrollment policy. If NFCU and the third-party fintech must both enroll in the same registry, they have adopted the Bolyra protocol as a shared federation anchor — the structural equivalent of a shared AS or a WIMSE SPIFFE trust domain.

RFC 8707 Resource Indicators + a shared WIMSE SPIFFE trust domain between NFCU and the fintech requires the same organizational commitment: both parties must configure trust in the same authority. The ZK construction does not eliminate this requirement; it moves it from "shared AS policy" to "shared on-chain registry with common enrollment."

The privacy properties of the enrollment differ — the ZK proof hides *which* enrolled agent participated — but the trust structure does not. A WIMSE federation with SPIFFE SVID attestation and audience-scoped tokens (RFC 8707) equally requires both orgs to accept the same trust domain, which is standard in B2B API integration and does not require exposing intermediate identities to the auditor (the auditor checks only the final token's audience binding, not intermediate SVIDs).

**Why it works / why it fails against the construction:**
The construction's real advantage is not "no shared trust anchor" but "enrollment proof without identity disclosure." The ZK property means NFCU can prove the fintech's agent is enrolled without revealing the fintech's agent identity to the NCUA examiner. WIMSE cannot provide this: SPIFFE IDs are stable, visible identifiers. But the baseline comparison in §8 must be corrected — WIMSE federation *also* requires a shared trust domain, so the structural equivalence undermines the claimed categorical difference.

**In-threat-model?** No — the "Cross-org without shared trust anchor" claim must be corrected to "Cross-org *audit* without exposing enrollment identities, using a shared on-chain registry as the trust anchor." The trust anchor is required in both cases; the ZK advantage is privacy-of-which-leaf, not absence-of-anchor.


## Persona: spiffe_engineer

---

### Attack 1: Single `agentMerkleRoot` Requires a Centralized Registry — SPIFFE Federation Solves This Without One

**Attack:** The construction's §2 states explicitly: "All delegatees in the chain must be enrolled against the same agent tree snapshot," and §7 adds: "if [hop 3] is enrolled in a separate tree, the two organizations must use a shared agent registry (the Bolyra on-chain registry serves this role)." The SPIFFE engineer presses on what this means in practice. SPIFFE trust domain federation (as specified in draft-ietf-wimse-arch and implemented in SPIRE's bundle endpoint federation) solves exactly the cross-org delegation problem without forcing all participants into a single shared registry. Each organization controls its own SPIFFE trust domain. Federation links trust domains via bundle exchange without either org surrendering control of workload enrollment to a third party.

In the NFCU scenario at §7, the third-party fintech at hop 3 must either (a) enroll its market-data agent in Bolyra's global on-chain registry — ceding enrollment control to Bolyra's registry governance — or (b) the scenario cannot produce a proof. Option (a) creates a single organizational chokepoint: whoever governs the Bolyra registry controls which agents across all organizations may participate in provable delegation chains. That's a governance dependency the construction characterizes as a protocol feature ("the Bolyra on-chain registry serves this role") without specifying who controls the registry, what the enrollment authorization model is, or how registry compromise is handled.

**Why it works / why it fails:** The ZK soundness of constraint 7 is intact — given a single `agentMerkleRoot`, the circuit correctly proves all delegatees are enrolled in that tree. The failure is at the deployment layer: the cross-org scenario requires a shared root, but the construction provides no mechanism for composing multiple per-org roots into a single provable statement. A multi-root variant (e.g., one `agentMerkleRoot` per hop, proven against org-specific root history buffers) would require restructuring the public input and the constraint in §2 — four public roots instead of one, with inter-org federation links proven separately. The current construction assumes global registry as a design choice, not as a proven necessity.

**In-threat-model?** No. The threat model in §3 treats "A cannot insert leaves without valid operator-signed credentials enrolled through the registry" as a given, but doesn't model registry governance, trust domain boundaries, or cross-org enrollment authorization. The construction must either (a) specify the authorization model for cross-org enrollment in the shared registry, or (b) extend to multi-root proofs with per-hop enrollment roots and define how cross-root membership is proven.

---

### Attack 2: Phantom Enrollment Is Closed at the Circuit Layer, Not at the Registry Layer — Operator Key Compromise Reopens It

**Attack:** The construction's §2 treats the phantom enrollment fix (constraint 7: `hopActive[i] * (root_i - agentMerkleRoot) === 0`) as closing Game 5. Theorem 5 in §4 reduces the attack to a Poseidon second-preimage, which is computationally infeasible. But the reduction assumes the on-chain `agentMerkleRoot` corresponds to a tree populated only by legitimately attested agents. What attests an agent at enrollment time?

From §3.2 (credential commitment definition in §5): `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)`. The enrollment of a leaf in the agent Merkle tree requires an operator-signed credential commitment. The operator is any holder of a valid `operatorPrivKey`. There is no hardware attestation step: no TPM measurement, no SGX quote, no k8s pod identity token, no cloud provider IID. An operator can compute `modelHash = keccak256("definitely-a-real-model")`, sign the credential commitment with their key, enroll it in the on-chain registry, and the resulting leaf is cryptographically indistinguishable from a legitimate agent enrollment. The Merkle tree contains the leaf. Constraint 7 passes. Theorem 5 does not fire. The "phantom" agent is now a real enrolled agent — phantom at the platform layer, not the circuit layer.

In SPIRE production, node attestation is mandatory before workload attestation. The SPIRE agent must prove it runs on a legitimate node via AWS Instance Identity Document, TPM-backed key, GCP attestation, or similar. The SVID is bound to that attestation chain. SPIRE's workload API issues SVIDs only to processes that pass both node-level and workload-level selectors (unix UID, k8s namespace, Docker label). Bolyra has no equivalent: the `modelHash` is a self-asserted value. Operator key compromise — a routine concern in any production key management review — allows unlimited phantom enrollment that the ZK construction cannot detect.

**Why it works / why it fails:** The circuit-level argument in §4 Theorem 5 is correct on its own terms: given a legitimate `agentMerkleRoot`, producing a valid proof for a non-enrolled agent requires breaking Poseidon. But the reduction's hypothesis — that `agentMerkleRoot` corresponds to a tree of legitimately attested agents — is unverified by the construction. The circuit and the registry are separate trust surfaces. The construction secures the former; it explicitly relies on the latter by delegating to "valid operator-signed credential commitments" without specifying what makes an operator's assertion valid.

**In-threat-model?** No. The §3 adversary model explicitly states A "cannot insert leaves without valid operator-signed credential commitments." This assumption excludes operator key compromise from the threat model. For a NCUA examination context (§7), auditors would ask precisely about key ceremony, HSM custody, and what "valid operator" means. The construction must either specify the enrollment authorization model and key security requirements, or bound its security claim to the assumption that operator keys are not compromised and acknowledge this is out of scope.

---

### Attack 3: `chainLength` Is a Public Output — Participant Privacy Theorem Is Incomplete

**Attack:** The construction's §4 Theorem 2 (Participant Privacy) argues that all participant identities are private inputs and the ZK property guarantees zero leakage given two candidate chains with identical public outputs. The public outputs listed in §2 are: `finalScopeCommitment`, `chainLength`, `auditDigest`, `narrowingValid`. Theorem 2's game definition stipulates chains C₀ and C₁ with "identical (chainLength, finalScopeCommitment, chainSeedScopeCommitment, agentMerkleRoot)." The theorem is stated and proven only for distinguishers who observe transcripts with the same `chainLength`.

In practice, `chainLength` is disclosed unconditionally. In the NFCU scenario at §7, `chainLength = 3` is disclosed to the NCUA examiner. For the journalist/source variant, the editorial board learns `chainLength`. Consider an adversary who can enumerate the set of deployed pipelines and their known topology (from business context, public filings, or infrastructure reconnaissance): a pipeline with `chainLength = 2` vs `chainLength = 4` substantially narrows the candidate set of pipelines that could have produced a given proof. Combined with `sessionNonce` (which is public and may be linkable to a session timestamp), `chainLength` is a structural fingerprint.

The comparison table in §8 claims "Hide intermediate participants" as a capability, citing ZK property. But the ZK property only hides *who* the participants are — it does not hide *how many* hops exist. SPIFFE SVIDs are structurally isolated: each workload presents its own SVID without revealing anything about the number of delegation hops in the calling chain. The `act` chain in RFC 8693 is admittedly plaintext, but a SPIFFE/WIMSE-based system could strip intermediate chain members entirely before presenting to the auditor, revealing only the leaf SVID. The Bolyra construction reveals `chainLength` necessarily because it is a public output used to anchor `finalScopeCommitment` to the correct hop.

**Why it works / why it fails:** The attack is strictly within the construction's own ZK security claim. Theorem 2's privacy guarantee holds only when the distinguisher's two candidate chains share `chainLength` — the theorem provides no privacy against a distinguisher that uses `chainLength` to narrow the candidate set before applying the ZK argument. The construction partially acknowledges this by hiding intermediate scopes and participants, but the topology fingerprint via `chainLength` is a genuine information leak not addressed in the security argument.

**In-threat-model?** Partially. The §3 Game 2 (Participant Privacy) explicitly fixes `chainLength` as identical across both candidate chains, sidestepping the issue by construction. The construction should either (a) formally acknowledge that `chainLength` is a side-channel on pipeline topology and bound the privacy claim accordingly, or (b) introduce a padded-length variant where all proofs are padded to MAX_HOPS and `chainLength` is hidden (replaced by a range proof: "chainLength ≥ 1"), at the cost of always paying the MAX_HOPS constraint budget regardless of actual chain length.

---

### Attack 4: Wrong Venue — WIMSE Scope Narrowing Is In-Charter; the Construction Should Be an Extension, Not a Fork

**Attack:** The WIMSE working group charter (draft-ietf-wimse-arch, §4 "Workload Identity in Multi-Service Environments") explicitly includes in scope: workload-to-workload delegation, scope narrowing during token exchange, and selective disclosure of claims to verifiers. The construction's §8 comparison table dismisses WIMSE by asserting "WIMSE SPIFFE IDs are stable identifiers visible to verifiers" and "No standard produces a single cross-org narrowing artifact." Both claims require scrutiny.

First, WIMSE's token exchange (draft-ietf-wimse-arch §4.3) explicitly models scope narrowing as a normative requirement during service-to-service delegation. The WG is actively working on mechanisms for a downstream service to receive a narrowed token without the upstream's full scope being disclosed to every downstream. Contributing a ZK-based scope narrowing attestation as an extension to WIMSE's token exchange would place the narrowing proof inside a standardized envelope rather than a new protocol.

Second, the claim that "BBS+ hides individual claims but cannot prove ordering/containment relationships over hidden bitmasks" is technically accurate for BBS+ alone but ignores its composition with commit-and-prove techniques. BBS+ blind signatures with auxiliary proof-of-knowledge allow a prover to commit to claims and then prove predicates over the committed values — including bit-subset relationships — to a verifier without disclosing the values. The construction's 64-bit bitmask fits well within this pattern; the in-circuit bitwise subset constraint in §2 is functionally equivalent to a BBS+ predicate proof. The performance comparison might still favor Bolyra's circuit approach, but the theoretical claim that the baseline "cannot" prove such relationships needs tighter qualification.

More fundamentally: the SPIFFE engineer's objection is architectural. The construction introduces a new DID method (`did:bolyra`), a new credential commitment scheme, a new proving system integration, a new on-chain registry, and a new audit protocol — when the minimal contribution needed to achieve the stated goals might be (a) a WIMSE extension for ZK-based scope narrowing attestation plus (b) a SPIFFE attestor plugin that generates Poseidon-based credential commitments from SVID material. That approach would be deployable today in existing SPIRE infrastructure, interoperable with OIDC/OAuth AS infrastructure, and subject to IETF review — none of which applies to the current construction.

**Why it works / why it fails:** This attack doesn't break the ZK soundness of the construction; it challenges the justification for a new protocol rather than a standards-track extension. The construction's §8 comparison to RFC 8693 + BBS+ + WIMSE is the right frame, but the "why not extend" question is answered only by performance and deployment model arguments, not by a crisp statement of what WIMSE cannot do even in principle. If the gap is "WIMSE cannot produce a single cross-org narrowing artifact today," that's a timing argument, not a capability argument — and it argues for contributing the construction to WIMSE, not forking from it.

**In-threat-model?** No — this is an architectural positioning objection, not a cryptographic attack. But it has a concrete consequence: if WIMSE adopts scope narrowing attestation as a standard, adoption of a parallel Bolyra-specific protocol requires justifying divergence from the standard. The construction should add a section explicitly scoping what WIMSE's current charter normatively excludes (today, not hypothetically) and why that gap requires a new protocol rather than a WG contribution.
