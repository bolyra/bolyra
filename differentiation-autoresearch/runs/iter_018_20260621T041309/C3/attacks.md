# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Auditor Can't Use This

**Attack:** Section 7's deployment scenario hands the NCUA examiner `narrowingValid = 1`, a Poseidon hash (`auditDigest`), and a PLONK proof π, then tells them to call `DelegationAuditVerifier.verifyProof()` on-chain. No NCUA examiner does this. Regulators use GRC tools (Archer, ServiceNow GRC, Vanta), spreadsheet exports, and PDF audit packages — not Solidity verifiers. Auth0's audit log ships as a JSON feed that drops into every major SIEM. WorkOS exports a human-readable token-issuance trail with actor, scope, timestamp, and decision rationale in plain text. `narrowingValid = 1` is a bit. An examiner's finding needs prose, a timestamp chain, a responsible human, and a PDF appendix. The construction produces none of that.

**Why it works / why it fails:** The construction proves the cryptographic property correctly. But the claim in §1 is "in a form usable beyond narrow regulatory niches." The NFCU scenario in §7 is the primary deployment claim, and it fails on the last mile: the regulator-facing artifact is unusable without a custom verifier UI, audit-report generator, and legal attestation wrapper that the construction doesn't specify. The gap-to-close acknowledges the construction is "currently too narrow" — this attack says the deployment scenario in §7 narrows it further, not broader.

**In-threat-model?** No — construction must address. The security games (§3) model a cryptographic auditor. The real auditor is an NCUA examiner with a laptop and a checklist.

---

### Attack 2: Latency Compounds Per Hop, Not Per Session

**Attack:** The construction's §6 proves time targets (1.5s Groth16, ~3s PLONK on commodity hardware) are stated per-circuit, not per-session. In the NFCU scenario (§7), the loan pipeline makes real-time decisions: credit scoring, rate lookup, market data — these are sub-second API calls in production. Every hop that requires a fresh proof because `sessionNonce` binds to a new session means the pipeline stalls for 1.5–5s *per hop* before the next agent can act. Four active hops = 6–20 seconds of cryptographic overhead on top of inference, DB queries, and network round-trips. WorkOS delegated access tokens are stateless JWTs: the front-desk agent issues a narrowed token to the credit-scoring agent in a single HTTP round-trip (<100ms, no proving required). The construction's §6 notes rapidsnark gives "~1.5s Groth16" but doesn't address whether proofs are generated inline (blocking) or pre-generated (which requires knowing the delegation chain in advance, breaking dynamic pipelines).

**Why it works / why it fails:** The construction does not specify the proof generation timing model. If proofs are generated at delegation time (when the front-desk agent decides to delegate to credit-scoring), the latency is inline and sequential. The 15-minute expiry at hop 3 suggests short-lived sessions, meaning proofs cannot be aggressively cached across sessions. The construction's comparison table (§8) correctly notes WorkOS issues tokens in <100ms but doesn't answer whether the ZK overhead is acceptable for the latency budget of the workflow it targets.

**In-threat-model?** No — construction must address. §6 gives a static constraint budget and per-circuit time. It doesn't give a sequence diagram showing when proofs are generated and how latency accumulates across a 4-hop real-time pipeline.

---

### Attack 3: The Trust Assumption Moved, It Didn't Disappear

**Attack:** §8 claims "No trusted third party — Proof is self-verifying against on-chain state. No AS, no federation anchor." This is technically accurate for the cryptographic verifier but ignores the operational trust assumptions the construction actually requires: (1) Someone must maintain the global agent Merkle tree and process enrollment. Who? If it's Bolyra (a solo founder), NFCU's procurement is now trusting a single point of failure for their NCUA-regulated loan pipeline. Auth0 has SOC 2 Type II, 99.99% SLA, indemnification, and a legal team. (2) The `pot16.ptau` universal SRS is a shared trust assumption — the construction says "PLONK avoids per-circuit ceremony" (CLAUDE.md) but pot16.ptau itself requires trusting that the ceremony was not poisoned. The construction doesn't reference the specific MPC ceremony that produced pot16.ptau or whether it meets financial regulator standards. (3) If a vulnerability is found in the circuit (underconstraint, Poseidon parameter mismatch — cf. the `protocol-autoresearch` experiments on underconstrained Merkle depth guards and field overflow), who issues the patch, coordinates the upgrade, and migrates the on-chain registry? There is no circuit upgrade path specified.

**Why it works / why it fails:** The construction's §4 security argument is correct under its named assumptions. But enterprise procurement doesn't buy named assumptions — it buys SLAs, insurance, and vendor viability. The "no trusted third party" claim shifts trust from Auth0's AS to (a) Bolyra's Merkle tree operator, (b) the pot16.ptau ceremony, and (c) an unspecified circuit upgrade governance process. These are all trusted parties; they're just less visible than an OAuth AS.

**In-threat-model?** No — construction must address. §7 targets a $150B+ AUM credit union. The claim requires an operational trust model, not just a cryptographic one.

---

### Attack 4: The Core Use Case is Backwards for Compliance

**Attack:** The construction's §1 claim and §7 scenario rest on a premise: the operator (NFCU) wants to *hide* intermediate permission bitmasks from the NCUA examiner because they "encode internal authorization policy — competitive intelligence." This is backwards for regulated financial institutions. NCUA examiners conducting IT and operational risk examinations under NCUA Letter 01-CU-20 and FFIEC guidance have explicit authority to review authorization policy. NFCU *must* disclose its permission model on request — the examiner doesn't accept a commitment and a ZK proof, they accept a policy document and an audit log showing that policy was enforced. The construction's privacy guarantee (§3, Game 3) is a liability in a regulatory audit context: it prevents NFCU from demonstrating to an examiner exactly what each agent was authorized to do, which is what the examiner needs. Auth0 and WorkOS produce human-readable token claims with explicit scope strings that satisfy FFIEC audit requirements directly. The construction's comparative advantage — hiding intermediate scopes — is the thing regulators require you to show.

**Why it works / why it fails:** The construction is technically sound for the privacy property it claims. But §7's "concrete deployment scenario" uses NCUA compliance as the motivating use case, and NCUA compliance requires disclosure, not concealment, of authorization policy. The journalist/source variant in §7 is a legitimate privacy use case, but the construction names NFCU as its anchor scenario and that scenario's privacy guarantee conflicts with the regulatory obligation that motivates it. The gap-to-close says "broaden beyond narrow regulatory niches" — this attack says the primary scenario *is* a narrow niche where the ZK property is contraindicated.

**In-threat-model?** No — construction must address. The broadening claim requires a buyer-level use case where hiding intermediate scopes from the auditor is a legitimate business requirement, not a regulatory liability. The journalist/source scenario is valid but must be elevated to the primary scenario with a concrete buyer, not treated as a variant.


## Persona: cryptographer

*Applied cryptographer. IACR publications. Reviews for CRYPTO/EUROCRYPT/S&P. I reject claims without game definitions and reduction sketches as marketing. The construction has both, so let's stress-test them.*

---

### Attack 1: Non-Contiguous Hop Splicing — Chain Integrity Break via Inactive Padding

- **Attack:** The adversary produces a proof with `hopActive = [1, 0, 1, 0]` (hops 0 and 2 active, hop 1 inactive). At inactive hop 1, every constraint is gated on `hopActive[1] * ... === 0`, so `delegateeScope[1]` and `delegateeCredCommitment[1]` are **unconstrained free variables** in the witness. The chain-linking constraint at active hop 2 is:

  ```
  hopActive[2] * (Poseidon2(delegatorScope[2], delegatorCredCommitment[2])
                  - Poseidon2(delegateeScope[1], delegateeCredCommitment[1])) === 0
  ```

  The prover controls `delegateeScope[1]` and `delegateeCredCommitment[1]` (inactive, unconstrained), so they simply set them equal to `delegatorScope[2]` and `delegatorCredCommitment[2]`. The constraint collapses to `Poseidon2(X,Y) - Poseidon2(X,Y) === 0`. Hop 2's delegator is now **any** agent the attacker chooses — there is no constraint linking them back to hop 0's delegatee. The attacker can inject an entirely unauthorized participant as the initiator of hop 2, carry a fresh EdDSA keypair for it, and pass the EdDSA check at hop 2. The chain length output reads `2` (two active hops), making the splice invisible.

- **Why it works:** Theorem 4's reduction sketch (§4) explicitly relies on constraint (2) creating a contiguous hash chain: *"At hop 0, previousScopeCommitment = chainSeedScopeCommitment; splicing in an unauthorized hop requires producing a (delegatorScope, delegatorCredCommitment) pair that hashes to the on-chain scope commitment."* That argument is correct for hop 0. It silently assumes the chain is contiguous. For hop i>0, `previousScopeCommitment` comes from `Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])` — but if hop i-1 is **inactive**, those values are unconstrained, so no Poseidon preimage attack is needed. The reduction breaks.

- **In-threat-model?** **No — construction must address.** The fix is to enforce that active hops form a **contiguous prefix**: add a constraint `hopActive[i] * (1 - hopActive[i-1]) === 0` for i > 0, ensuring that once a hop is inactive, all subsequent hops are also inactive. Without this, Game 4 (Chain Integrity) is not achieved.

---

### Attack 2: Delegator Key-Binding Gap — EdDSA Signing Key Not Committed in Credential

- **Attack:** At each active hop i, the circuit verifies an EdDSA signature under `(delegatorPubkeyAx[i], delegatorPubkeyAy[i])` over the delegation token. Separately, `delegatorCredCommitment[i] = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` is used in chain linking. **Nowhere in the listed constraint logic** (§2, constraints 1–8) is there a gate of the form:

  ```
  delegatorCredCommitment[i] ===
      Poseidon5(modelHash[i], delegatorPubkeyAx[i], delegatorPubkeyAy[i],
                delegatorScope[i], delegatorExpiry[i])
  ```

  This binding constraint is absent. Consequently, an insider — say the operator at hop 0 who legitimately knows their own `(delegatorScope[0], delegatorCredCommitment[0])` — can generate a fresh Baby Jubjub keypair `(sk', pk')`, sign the delegation token with `sk'`, and produce a valid proof. The proof is accepted because the EdDSA verifier only checks that `pk'` signed the token, never that `pk'` is the key embedded in `delegatorCredCommitment[0]`. The real operator's private key is never used.

- **Why it works / why it fails:** The security argument in §4 claims EdDSA unforgeability (A4) prevents key forgery. A4 holds — no one can forge a signature under a given public key. But A4 is irrelevant when **the key itself is a free variable**. The circuit enforces "someone signed this token with some key," not "the key in the credential commitment signed this token." This is a missing binding constraint, not a cryptographic hardness failure.

- **In-threat-model?** **No — construction must address.** The delegator's EdDSA public key must be extracted from the credential commitment inside the circuit: add `Poseidon5(delegatorModelHash[i], delegatorPubkeyAx[i], delegatorPubkeyAy[i], delegatorScope[i], delegatorExpiry[i]) === delegatorCredCommitment[i]` as a per-hop constraint. Without it, any insider who knows `(scope, credCommitment)` for a delegator can produce valid delegation proofs without that delegator's private key.

---

### Attack 3: Scope Enumeration via Low-Entropy Bitmask — Theorem 3's Reduction is Not Tight

- **Attack:** Theorem 3 reduces intermediate scope recovery to Poseidon preimage resistance, claiming the preimage space is intractable. The auditor sees `chainSeedScopeCommitment = Poseidon2(S_0, C_0)` and `finalScopeCommitment = Poseidon2(S_n, C_n)`. The argument is that recovering `S_i` requires inverting Poseidon2, a field-element preimage. However, the permission bitmask is declared as a **64-bit value encoding 8 meaningful bits** (§2, Permissions Model). Cumulative bit encoding (bits 2/3/4 with implication constraints) further restricts valid bitmasks: the set of permission-valid 64-bit words is at most ~200 values. Monotonic narrowing over a chain of length `k` means the intermediate scopes form a **decreasing sequence in the bit-subset lattice**, whose size is bounded by the number of antichains in the power set of 8 elements — at most a few hundred sequences. If on-chain enrollment transactions expose credential commitments `C_i` for enrolled agents (enrollment is a public on-chain event), the auditor has a candidate set `{C_j}` for each hop's delegatee. The auditor can enumerate `Poseidon2(S_candidate, C_j)` for all valid `(S_candidate, C_j)` pairs and match against the chain seed and final scope commitment.

- **Why it works:** Poseidon preimage resistance holds when the preimage space is exponential in the security parameter. Here the bitmask entropy is ~8 bits and the set of enrolled agents may be public. The Poseidon "preimage problem" becomes a **small-domain exhaustive search**, not a reduction to a hard problem. Theorem 3's proof sketch treats `delegateeScope[last]` as a field element with full entropy; it is not.

- **In-threat-model?** **No — construction must address it, at minimum with a caveat.** The scope privacy claim requires either (a) high-entropy scope representations (e.g., padding the bitmask with a large blinding salt before hashing, so `Poseidon2(S ∥ r, C)` with `r ← {0,1}^λ`) or (b) explicit acknowledgment that scope privacy is not achieved when the scope space is small and enrollment is public. The journalist/source scenario (§7) depends critically on intermediate scope privacy; this gap undermines it.

---

### Attack 4: HVZK vs. Full ZK Under a Malicious Auditor — Theorem 2's Simulator is Undefined

- **Attack:** Theorem 2 (Participant Privacy) appeals to "the zero-knowledge property of Groth16/PLONK." Groth16 achieves **honest-verifier zero-knowledge (HVZK)** in the algebraic group model: the simulator requires the CRS trapdoor to produce simulated proofs. The security argument for Game 2 posits an adversary *playing as auditor* who receives a real proof `π` and attempts to distinguish between two chains `C_0` and `C_1`. The ZK simulator must produce a transcript indistinguishable from `π` for both chains. For a **malicious** auditor — one who supplies a malformed `sessionNonce` or performs a non-standard verification query — HVZK provides no guarantee. Furthermore, under a subverted CRS (the threat model explicitly assumes honest CRS but does not bound the setup ceremony), the CRS trapdoor holder can extract all private inputs from any valid Groth16 proof via the extraction property (knowledge soundness dual: if A1 holds for the prover, the extractor with trapdoor recovers the full witness). In the journalist/source variant (§7), where "intermediate node anonymity is cryptographically guaranteed by the ZK property — even a compromised auditor learns nothing," the claim is precisely false if the CRS generator is corrupt. Neither the threat model (§3) nor the reduction sketches (§4) scope out subverted setup beyond "A does not control the CRS."

- **Why it works:** The gap is between HVZK (proven for Groth16 in AGM against an honest verifier) and full ZK against a malicious verifier. Real-world auditors are not guaranteed to be honest verifiers — they can supply adversarial public inputs, repeat queries across sessions, and correlate `auditDigest` values. The simulator for Game 2 must produce transcripts for adversarially-chosen public inputs; this requires simulation-extractable NIZK (SE-NIZK), which Groth16 does not natively achieve without additional assumptions (e.g., the Fiat-Shamir heuristic in ROM plus AGM). PLONK with Fiat-Shamir is closer to achieving this, but the construction offers Groth16 as the primary option and does not state which ZK flavor is required.

- **In-threat-model?** **Partially.** The construction survives if restricted to PLONK with Fiat-Shamir in ROM (simulation-extractable). It does **not** survive under Groth16 against a malicious auditor or under subverted setup. The construction must: (a) restrict the participant-privacy claim to PLONK, (b) state that the ZK property required is simulation-extractability (not just HVZK), and (c) explicitly scope the threat model to exclude CRS subversion or propose a distributed setup ceremony with honest-majority assumption for the journalist/source variant — where CRS subversion would be catastrophic.


## Persona: cu_ciso

### Attack 1: Third-Party Vendor Identity Suppression Violates NCUA Part 748

- **Attack:** Section 7 of the construction explicitly states the examiner does NOT receive "the identity of the third-party fintech at hop 3." The CISO points to NCUA Letter to Credit Unions 07-CU-13 and the Vendor Management Policy requirement embedded in Part 748 Appendix B: the CU must maintain a comprehensive inventory of all third-party relationships touching member data, cross-referenced against their information security program. At hop 3, `READ_DATA` is still active — member data could flow to this fintech. The cryptographic hiding of the vendor identity is not a feature; it is a direct conflict with the third-party risk examination checklist. The examiner cannot correlate the `auditDigest` artifact against the CU's vendor register, the SOC 2 Type II report for that vendor, or the contract that establishes permissible use. `narrowingValid = 1` does not substitute for a vendor name.

- **Why it works / why it fails:** The construction's privacy guarantee is unconditional — participant identities are private inputs protected by the ZK property. There is no selective disclosure mechanism that would allow the *CU* (as opposed to the auditor) to confirm internally that hop 3 maps to an approved vendor, without that confirmation being auditable. The construction provides no off-circuit binding between the `delegateeCredCommitment[3]` and a human-readable vendor record. A malicious or negligent integration could enroll an unapproved vendor as an agent and the circuit would still produce `narrowingValid = 1`.

- **In-threat-model?** No — the construction must address how the CU operator maps `delegateeCredCommitment[i]` values to its vendor management register without leaking that mapping to the general auditor. This likely requires a separate, CU-private commitment registry with access controls, outside the circuit.

---

### Attack 2: Incident Response Leaves Tier 1 Ops with an Opaque Hash

- **Attack:** FFIEC CAT Domain 3 (Cybersecurity Controls, Response, and Recovery) and NCUA Part 748 Section 3 require incident response procedures that non-cryptographers can execute at 2am. The `auditDigest` is a Poseidon hash chain over per-hop nullifiers. After a member reports unauthorized loan activity, Tier 1 ops opens a ticket. They need to answer: which agents touched this member's data, in what order, with what permissions, and at what timestamps. The construction's answer is: "run `DelegationAuditVerifier.verifyProof()` on-chain and get back a single bit." That is not a forensic timeline. The per-hop nullifiers are embedded in the proof witness, which is discarded after proving. There is no construction-defined artifact that a Tier 1 analyst can hand to an NCUA examiner that reads: "At 14:32 UTC, agent X delegated READ_DATA to agent Y for 15 minutes."

- **Why it works / why it fails:** The construction optimizes for auditor-facing mathematical proof, not operator-facing forensic reconstruction. The ZK privacy guarantee is exactly what prevents reconstruction — intermediate scopes, identities, and timestamps are private inputs that vanish after proof generation. Section 7 describes what the *examiner* receives; it is silent on what the *CU's own security team* retains for their internal incident log.

- **In-threat-model?** No — the construction must specify a CU-private audit log (not zero-knowledge) retained by the CU's own systems, with the ZK proof serving only as the public-facing regulatory artifact. Without this, the privacy guarantee collapses the forensic capability the CU needs for its own operations.

---

### Attack 3: Trusted Setup Has No Regulatory Certification Path

- **Attack:** Section 4 states the construction relies on "Groth16 in the algebraic group model" and "universal setup for PLONK (pot16.ptau)." The security of every proof produced by this system depends on the integrity of the `pot16.ptau` Powers of Tau ceremony. The CISO pulls out the FFIEC CAT Maturity Level 3 control: "Cryptographic key management policies and procedures are implemented." The examiner asks: Who conducted the pot16.ptau ceremony? Where is the ceremony transcript? How many participants? What is the compensating control if the ceremony was compromised (toxic waste not destroyed)? Is this ceremony FIPS 140-2 certified? The answer is that `pot16.ptau` is a public community artifact from the snarkjs ecosystem — it is not certified by NIST, NCUA, or any body the examiner recognizes. The entire narrowing soundness guarantee (Theorem 1) collapses if the ceremony was compromised, and there is no detection mechanism.

- **Why it works / why it fails:** The construction correctly notes the trusted setup assumption as A1 but treats it as a cryptographic axiom rather than an operational risk. For a regulated institution, an unaudited community MPC ceremony is not a recognized control. PLONK's universal setup is stronger than circuit-specific Groth16, but `pot16.ptau` still requires trusting the snarkjs community's MPC. The construction offers no path to a FIPS-certified or independently audited trusted setup.

- **In-threat-model?** No — the construction must address the trusted setup provenance question with either (a) a reference to an auditable ceremony with published transcripts and participant attestations, or (b) a migration path to a transparent/untrusted-setup proving system (e.g., STARKs or Halo2 IPA) that removes the ceremony dependency entirely.

---

### Attack 4: `narrowingValid = 1` Cannot Prove the Initial Scope Was Appropriate

- **Attack:** The construction's public outputs include `chainSeedScopeCommitment` (the on-chain anchor) and `narrowingValid = 1`. The examiner is told: "Every hop narrowed." But GLBA Safeguards Rule §314.4(e) requires the CU to limit access to customer information "to those employees who need access to provide products or services." The examiner's actual question is not "did narrowing happen?" but "was the *initial* scope at hop 0 appropriate for the member's transaction?" In the Section 7 scenario, hop 0 grants `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bits 0,1,2,7). The proof provides zero evidence that granting `ACCESS_PII` and `WRITE_DATA` to the front-desk agent was a justified authorization decision for *this* member's *this* transaction. An examiner who receives `narrowingValid = 1` and a commitment hash cannot assess whether the initial over-permissioning itself constitutes a GLBA violation. The construction proves the chain was internally consistent; it does not prove the chain was appropriately scoped from the start.

- **Why it works / why it fails:** This is a gap between cryptographic correctness and regulatory adequacy. The circuit enforces monotonic narrowing from the seed, but the seed's appropriateness is entirely outside the circuit. The `chainSeedScopeCommitment` being on-chain only proves the seed existed; it does not bind the seed to a specific transaction type, member consent record, or minimum-necessary determination. An NCUA examiner examining GLBA minimum-necessary compliance needs to see the initial authorization decision and its justification — neither of which survives the ZK proof.

- **In-threat-model?** No — the construction must define how the chain seed itself is constrained to a minimum-necessary scope at origination. One path: bind `chainSeedScopeCommitment` to a transaction classification (e.g., "loan inquiry" maps to a maximum allowed initial scope bitmask), enforced at handshake time and verifiable against a CU-published policy table. Without this, the construction proves consistent narrowing from an arbitrary starting point, which is not the regulatory question.


## Persona: rfc7662_advocate

---

### Attack 1: The Merkle Root Is Never Anchored — Enrollment Proof Is Vacuous

**Attack:**
Section 2 constraint (7) computes `root_i = BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[i], merkleProof[i])` and then states: *"root_i is consumed internally, not output — auditor never sees it."* But the circuit, as written, **never constrains `root_i` to a known public value**. There is no constraint of the form `root_i === agentTreeRoot` where `agentTreeRoot` is a public input anchored on-chain. A malicious prover can supply a fresh Merkle tree containing only their own fabricated credential, generate a valid Merkle path, and the verifier accepts it. The enrollment proof proves membership in *a* tree the prover constructed, not in Bolyra's canonical agent registry.

**Why it works / why it fails against the construction:**
This is a soundness gap in the circuit specification, not a generic ZK limitation. The construction describes Game 4 (Chain Integrity) and claims Theorem 4 holds because "splicing in an unauthorized hop requires producing a Poseidon preimage." But that argument presupposes the delegatee's `credCommitment` is constrained to appear in a canonical tree. Without a public `agentTreeRoot` input constraining `root_i`, a prover can pass Game 4 and Game 1 while enrolling phantom agents — agents that never registered with Bolyra. The construction must add `agentTreeRoot` as a public input per hop (or a shared root across hops) and add the constraint `root_i === agentTreeRoot[i]`.

**In-threat-model?** No — **construction must address.** This is a missing constraint, not a ZK impossibility. Fix: promote `agentTreeRoot` to a public input and add `hopActive[i] * (root_i - agentTreeRoot) === 0`.

---

### Attack 2: Signed JWT Introspection Response Replicates `narrowingValid=1` Without ZK

**Attack (citing RFC 9701, formerly draft-ietf-oauth-jwt-introspection-response):**
The AS maintains the delegation chain internally — it issued each token, it knows every scope at every hop. With RFC 9701 (signed JWT introspection response), the AS produces a cryptographically bound artifact containing a custom claim `narrowing_valid: true` and omits intermediate scope values from the response body via per-RS introspection policy. The NCUA examiner calls the AS's introspection endpoint, receives a JWS-signed response asserting chain integrity, and verifies the AS's public key. No intermediate scopes are disclosed. The artifact is non-repudiable, offline-verifiable, and cacheable.

The construction's Section 7 dismisses this as "assertion by a trusted authority" vs. "mathematical proof." But the threat model (Section 3) grants the adversary only N-1 of N *participants* — it does not consider a colluding AS. In the NFCU deployment (Section 7, concrete scenario), the AS **is NFCU**, which is precisely the entity being audited. The examiner already trusts NFCU to operate a compliant AS as a condition of NCUA examination — the same trust relationship the construction tries to eliminate.

**Why it works / why it fails against the construction:**
The construction's genuine advantage emerges only when the AS and the audited party might collude against the auditor, i.e., when the AS is the adversary. In the journalist/source scenario (Section 7), the editorial board cannot trust the publication's AS to accurately attest chain integrity — the AS operator has an incentive to lie. The ZK construction is the right tool there. But for the NFCU regulatory audit use case — Section 7's primary scenario — the RFC 9701 response achieves equivalent auditability with zero additional infrastructure, zero circuit proving latency, and zero cryptographic ceremony debt. The construction's claim "applies to multi-tool AI pipelines" is correct; the claim that it is necessary for NCUA compliance is overstated.

**In-threat-model?** Partially. The construction survives in adversarial-AS settings (journalist scenario). The NFCU scenario, as framed, does not establish why the AS is untrusted. Construction must sharpen the threat model to specify which party is the adversary and under what collusion assumptions.

---

### Attack 3: Targeted Deanonymization via `auditDigest` Hypothesis Testing

**Attack:**
Section 2 defines `hopNullifier[i] = Poseidon2(token[i], sessionNonce)` and `token[i] = Poseidon4(prevScopeCommitment, delegateeCredCommitment[i], delegateeScope[i], delegateeExpiry[i])`. At hop 0, `prevScopeCommitment = chainSeedScopeCommitment` (public). `sessionNonce` is public. If `chainLength = 1`, then `auditDigest = hopNullifier[0] = Poseidon2(Poseidon4(chainSeedScopeCommitment, credCommitment_X, scope_X, expiry_X), sessionNonce)`.

An auditor who suspects the hop-0 delegatee is one of K candidate agents (say K=5 known credit-scoring agents at NFCU, each with a known `credCommitment`) can enumerate candidate `(scope, expiry)` pairs from the finitely many valid 8-bit bitmasks (256 possible scope values) and O(N) expiry buckets, compute the expected `auditDigest` for each hypothesis, and compare against the public `auditDigest`. For K=5 agents × 256 scopes × a small expiry range, this is an offline brute-force with ~10K hash evaluations — trivially fast.

Game 2 (Participant Privacy, Section 3) guards only against distinguishing between two chains with **identical** `(chainLength, finalScopeCommitment, chainSeedScopeCommitment)`. It says nothing about an adversary who mounts a *hypothesis test* over a candidate list. The security argument in Theorem 2 ("simulator produces indistinguishable transcripts") is correct within the game's restrictive definition — but that definition is too narrow for the stated deployment context, where the auditor knows the universe of deployed agents.

**Why it works / why it fails against the construction:**
The attack works when the delegatee's `credCommitment` is public or semi-public (registered on-chain, as it must be to pass constraint 7). If `credCommitment` is on-chain, the candidate set is the entire Merkle leaf set — enumerable by reading the on-chain tree. The construction hides `credCommitment` as a private input, but its image in the tree is public. The `auditDigest`'s dependence on `token[0]`, which is deterministic given `(chainSeedScopeCommitment, credCommitment, scope, expiry)`, creates a correlation oracle.

**In-threat-model?** No — **construction must address.** Fix: the per-hop nullifier must incorporate a blinding factor known only to the prover, not reconstructable from on-chain public data. E.g., `hopNullifier[i] = Poseidon3(token[i], sessionNonce, blindingRand[i])` where `blindingRand[i]` is a private random input, breaking the hypothesis-test preimage.

---

### Attack 4: The Agent Merkle Tree Is a Federation Trust Anchor by Another Name

**Attack (citing RFC 8693 §4.1 and WIMSE architecture):**
Section 7 claims "cross-org without shared trust anchor" because "each hop's delegatee enrollment is proven against the global agent Merkle tree." The cross-org hop 3 (third-party fintech) is "just another enrolled agent." But this requires the third-party fintech to enroll its agent in Bolyra's canonical Merkle tree. The entity that controls tree membership — who can add and remove leaves — is the effective trust anchor for all cross-org delegations.

In RFC 8693 terms, this entity plays the role of an Authorization Server with global client registration authority. It is structurally identical to the "federation trust anchor" the construction claims to eliminate. The construction replaces "trust the AS to validate tokens" with "trust the Merkle tree operator to validate enrollments" — a distinction without a security difference if both entities are under the same threat model. Under RFC 8707 + a shared AS with per-RS policy, the AS plays exactly the role of the Merkle tree operator: it decides which clients (agents) are legitimate and for which audiences (RS / audit contexts).

Moreover, if the Merkle tree root changes (agents are added/removed), previously valid proofs may fail replay against the current root — or require the circuit to accept stale roots, introducing a replay window where deregistered agents remain provably enrolled. The construction does not address tree root versioning.

**Why it works / why it fails against the construction:**
The construction's genuine advantage is that the Merkle tree operator cannot *retroactively forge* chain proofs — the operator can't claim agent X participated in a chain that already occurred, because the EdDSA signature (constraint 6) requires the delegator's private key. An AS with access to token contents can forge or alter assertions at introspection time. This asymmetry is real and load-bearing, but the construction understates it and overclaims on the "no trust anchor" front.

**In-threat-model?** Partially. The claim "no shared trust anchor" is false as stated — the Merkle tree operator is one. The claim "the trust anchor cannot forge historical chain proofs" is true and is the construction's actual moat. The Section 7 comparison table should be corrected: the accurate row is "trust anchor cannot forge past proofs" not "no trust anchor required."


## Persona: spiffe_engineer

---

### Attack 1: Phantom Enrollment — Merkle Root Is Never Anchored

**Attack:** Section 2, constraint step 7 computes:

```
let root_i = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[i], merkleProof[i])
// root_i is consumed internally, not output
```

`root_i` is computed but **never constrained against any public input or on-chain canonical root.** The circuit verifies internal Merkle consistency — that `delegateeCredCommitment[i]` is a leaf of *some* tree with *some* root — but nothing forces that root to be the global, authoritative agent enrollment registry.

An adversary at hop *i* can:
1. Pick an arbitrary `delegateeCredCommitment[i]` for a phantom agent.
2. Build a toy Merkle tree of depth 20 with that single leaf, padding with zeros.
3. Supply the corresponding sibling path.
4. The circuit accepts — `BinaryMerkleRoot` is satisfied, `root_i` is unconstrained.

**Why it works:** The construction's Theorem 4 (Chain Integrity) argues that splicing requires a Poseidon preimage against the `chainSeedScopeCommitment`. That's true for the *scope commitment chain*. But it says nothing about enrollment integrity. The EdDSA signature at step 6 requires the *delegator's* private key — not the delegatee's. So the delegator can validly sign a delegation token to a phantom, unenrolled delegatee, and the circuit approves it.

**Why it fails to survive:** Section 3's adversary model states "every delegatee is an enrolled agent" as a claim of the construction, and Theorem 1 claims narrowing soundness covers this. It does not — narrowing soundness only covers the scope bitmask subset relation, not enrollment validity.

**In-threat-model?** **No.** This is a gap the construction must address. Fix: promote `agentMerkleRoot` to a **public input** (or constrain `root_i` against a public signal that the on-chain verifier checks against the canonical registry state). In SPIFFE terms: your "enrollment" is equivalent to SPIRE's node attestation — it requires an authoritative anchor, and that anchor must be visible.

---

### Attack 2: The Registry Is a Trusted Third Party — §8's "No Trusted Third Party" Claim Is False

**Attack:** Section 8 claims the construction provides "No trusted third party — Proof is self-verifying against on-chain state. No AS, no federation anchor."

But the global agent Merkle tree — whose root all `BinaryMerkleRoot` calls must (or should, per Attack 1) be bound to — must be maintained by *someone*:
- Who authorizes new agent enrollments?
- Who updates the Merkle root on-chain after a new `credentialCommitment` is inserted?
- Who prevents a malicious registry operator from enrolling phantom agents?

The construction is silent on all of this. In SPIFFE/SPIRE terms, this role is played by the **SPIRE server**, and SPIFFE is explicit that it is a trusted third party within a trust domain. The Bolyra registry is isomorphic to a SPIRE server — it just hides inside the word "on-chain state."

Being on-chain does not eliminate the trust assumption; it displaces it to:
- The smart contract deployer (who set the registry logic),
- The upgrade key holder (if the contract is upgradeable),
- The oracle or bridge that feeds the Merkle root if agents enroll off-chain.

**Why it works:** The §8 comparison to WIMSE and RFC 8693 calls out "auditor must trust or query the AS" as a WIMSE weakness. The Bolyra construction substitutes "auditor must trust the Merkle registry and its update authority" — structurally identical. The §8 table entry is misleading.

**Why it fails against the construction:** The construction has no response because the registry trust assumption is never named. The security argument in §4 names A1–A4 but omits the registry integrity assumption entirely.

**In-threat-model?** **No.** The construction must add a named assumption A5: *The agent Merkle registry is maintained by a correct and censorship-resistant authority.* Then the §8 comparison must be qualified: "no AS for scope enforcement" (true) but "trust anchor still required for enrollment" (true for both WIMSE and Bolyra).

---

### Attack 3: Scope-Space Collapse at Chain Tips — Journalist/Source Privacy Degrades

**Attack:** Theorem 3 (Scope Privacy) reduces to Poseidon preimage resistance: recovering `delegateeScope[last]` requires inverting `Poseidon2(delegateeScope[last], delegateeCredCommitment[last])`.

This reduction is valid when the scope space is large. But the construction's own Scenario 2 (journalist/source) produces a chain that *narrows to a very small scope at the tip*. Section 7's NFCU scenario ends at `READ_DATA` (0b00000001). The journalist variant is similar.

The adversary model allows A to control up to N-1 of N participants. In a 4-hop journalist chain where the editorial tool (hop 1) and secure drop tool (hop 2) are both operated by known, colluding infrastructure:
- A knows `delegateeScope[1]` and `delegateeScope[2]`.
- A knows `narrowingValid = 1`, so `delegateeScope[3] ⊆ delegateeScope[2]`.
- If `delegateeScope[2]` has *k* set bits, the source's scope has at most 2^k possibilities.

When k = 1 (READ_DATA only at hop 2), there are exactly 2 candidate scopes for the source: `{0b00000000, 0b00000001}`. The auditor can evaluate `Poseidon2(0b00000000, x)` and `Poseidon2(0b00000001, x)` and match against `finalScopeCommitment` by iterating over likely `credentialCommitment` values — a 1-bit brute force, not a preimage attack.

**Why it works:** Theorem 3's security argument is parameterized on the scope domain being exponentially large. The monotonic narrowing constraint *by design* collapses the scope space at each hop. The privacy claim and the narrowing guarantee are in structural tension: stronger narrowing → smaller scope space at the tip → weaker hiding.

**Why it partially fails:** For the NFCU scenario, the auditor doesn't know the intermediate scopes, so brute force requires iterating over all possible scope values at hop 2 — which could still be a 64-bit space. The attack sharpens when an adversary controls N-1 hops, which the threat model explicitly allows.

**In-threat-model?** **Yes, partially** — but the construction's journalist scenario claims "even a compromised auditor with unbounded compute learns nothing." That claim is false when the adversary controls intermediate nodes. The construction must bound the journalist privacy guarantee to adversaries controlling at most one intermediate node, not N-1, or it must add a blinding salt to the scope commitment to expand the effective preimage space even for small bitmasks.

---

### Attack 4: WIMSE Layer Argument — You Are Building in the Wrong Place

**Attack:** The §8 table claims WIMSE cannot "prove monotonic narrowing over hidden scopes" and cannot produce cross-org artifacts without a shared trust anchor. As a WIMSE draft co-author: this is a strawman against the 2024 snapshot of the architecture draft.

Specifically:
- `draft-ietf-wimse-arch §6` explicitly scopes "token transformation and scope narrowing" as in-scope work items for the working group. The WG has not closed these issues — it has *deferred* them to companion drafts.
- The §8 comparison assumes WIMSE's token exchange is *only* RFC 8693 + JWT. The WG is actively exploring ZK attestation extensions. The right response is a Bolyra contribution to that WG, not a parallel protocol.
- SPIFFE SVIDs already support **short-lived X.509** certificates (TTL ≤ 5 minutes) as a scope-narrowing mechanism via separate SVID issuance per workload. The "expiry narrowing" in §2 constraint (5) is directly replicable via SVID rotation.

The construction's core ZK contribution — proving a *bitwise subset relationship over hidden values* — is genuinely novel. But the *protocol framing* (chain seed, session nonce, audit digest) reinvents what WIMSE's token exchange profile is trying to standardize. A SPIFFE-ZK attestor plugin + WIMSE token exchange with a ZK narrowing proof extension would deliver the same auditor-facing guarantee while being deployable in existing SPIRE infrastructure.

**Why it works:** The §8 "fundamental gap is structural" argument is correct for the ZK layer. But the rest of the protocol surface — hop linking, chain seed, session binding, replay prevention — is re-implementing WIMSE's token exchange semantics outside the standards process. Any enterprise operator who already runs SPIRE will not adopt a parallel protocol for the ZK narrowing guarantee alone.

**Why it partially fails:** The construction's journalist/source scenario and the MAX_HOPS fixed circuit are genuinely outside WIMSE's current scope. WIMSE targets workload-to-workload within known trust domains; cross-org journalist chains with mandatory intermediate anonymity are not a WIMSE use case today.

**In-threat-model?** **No** — this is a deployment/adoption attack, not a cryptographic one. But the construction must address it in §8 by distinguishing: (a) the ZK narrowing primitive is novel and not replaceable by WIMSE; (b) the surrounding protocol framing could be harmonized with WIMSE token exchange rather than competing with it. The current framing invites exactly this objection from every enterprise security architect running SPIRE in production.
