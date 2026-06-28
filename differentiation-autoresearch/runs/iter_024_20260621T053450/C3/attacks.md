# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

*Senior PM at Auth0/WorkOS/Stytch, owns the MCP auth product line. I ship. You have a whitepaper.*

---

### Attack 1: Regulatory Theater — NCUA Doesn't Run `Verify(vk, π, pubInputs)`

- **Attack:** Section 7 names Navy Federal / NCUA as the primary buyer. The construction's "auditor verification steps" require someone to (a) query on-chain state for nullifier existence, (b) verify a PLONK proof against a verifier contract, and (c) confirm Merkle root membership in an agent root history buffer. NCUA exam teams use examination manuals, Excel, and SQL. They issue findings in prose. They accept SOC 2 Type II reports, vendor due diligence questionnaires, and system audit logs — they do not verify zero-knowledge proofs. The construction conflates "cryptographically auditable" with "regulatorily accepted." These are orthogonal properties. Auth0's audit log export, SCIM provisioning trail, and SOC 2 report are what actually closes NCUA questions.

- **Why it works:** The construction never addresses *who operates the verifier* or *what the regulator's actual acceptance criteria are*. The threat model (Section 3) models a computationally bounded adversary, not an under-resourced federal examiner who wants a PDF. The Section 8 comparison table compares cryptographic properties against BBS+/WIMSE — it never compares against "NCUA Examiner Handbook Chapter 7" or any real-world audit acceptance criterion.

- **In-threat-model?** No. The construction's threat model is purely cryptographic. The GTM claim in Section 7 ("NCUA examiner requests proof") is asserted, not established. Construction must address: what is the examiner's actual verification surface, and what intermediary (audit firm, regulator API, on-chain explorer) translates the PLONK proof into something the examiner accepts? Without this, the deployment scenario is a demo, not a use case.

---

### Attack 2: Smart Contract Trust Substitution — You Didn't Remove the Trusted Party, You Replaced It

- **Attack:** Section 4, Assumption 6 states explicitly: *"REG-INTEGRITY: The on-chain delegation nullifier registry is append-only and accepts writes only from the verified Delegation circuit execution path in the registry contract (smart contract correctness assumption, not a cryptographic assumption)."* GAME-FAITHFUL (Section 3) — the construction's strongest novel claim — rests entirely on REG-INTEGRITY. If the registry contract has a reentrancy bug, an access control flaw, or an upgrade path that a compromised admin can exploit, GAME-FAITHFUL collapses and the shadow-chain prevention guarantee disappears. Auth0 has 15 years of production hardening on its token storage layer, SOC 2 Type II controls on its database, and immutable audit logs backed by AWS CloudTrail. The registry contract has a testnet deploy and no audit history. Section 8 says "No trusted third party — the circuit IS the enforcement." This is false: the enforcement depends on a specific smart contract at a specific address on Base Sepolia, controlled by whoever holds the deployer key.

- **Why it works:** The construction accurately identifies that RFC 8693 requires trusting the Authorization Server. It then replaces that trust with trust in a smart contract — an unaudited, solo-founder-maintained contract on a Layer 2. For procurement, "we trust Auth0's SOC 2-certified infrastructure" is an easier answer than "we trust a Solidity contract on Base Sepolia that hasn't been audited." The cryptographic assumptions (DL-BJJ, CR-Poseidon, KS-Groth16) are sound; the operational assumption (REG-INTEGRITY) is the weak link and it's the one that matters for GAME-FAITHFUL. The construction's honest acknowledgment of this in Section 4 is a weapon, not a virtue.

- **In-threat-model?** Partially. The cryptographic threat model is complete. But REG-INTEGRITY is outside the cryptographic proof system, and the construction provides no mitigations (formal contract verification, audit firm engagement, multi-sig upgrade governance, emergency pause mechanism). A buyer's security team will find Section 4's footnote and stop reading.

---

### Attack 3: The pot18.ptau Problem — "Universal Setup" Still Needs a Ceremony

- **Attack:** Section 6 states: *"The 8-hop standard configuration requires a `pot18.ptau` ceremony or universal PLONK SRS of matching size."* The construction markets PLONK as avoiding per-circuit trusted setup. This is technically true but misleading for enterprise buyers. A 2^18 powers-of-tau ceremony either (a) must be run by Bolyra (solo founder, unaudited ceremony), (b) reused from a third party (Hermez, Semaphore) whose ceremony the enterprise must vet, or (c) run independently by each enterprise (which requires cryptographic expertise and infrastructure they do not have). When a CISO asks "what are your cryptographic assumptions," the answer must include "trust in the participants of this ceremony" — the same class of question that enterprise PKI teams have been managing for CA root certificates for 30 years. Auth0 has no ceremony requirement. Cloudflare Access has no ceremony requirement. WorkOS has no ceremony requirement. Every one of these incumbents uses TLS 1.3 + OAuth 2.1, whose trust anchors are WebPKI — a system with established root programs, audited CAs, and browser/OS vendor vetting. Bolyra's equivalent is: "trust a KZG ceremony."

- **Why it works:** The Section 6 note is correct but buried. Enterprise security teams will surface this during architecture review. The construction does not identify which ceremony to use, who ran it, or how enterprises verify its integrity. The 4-hop compact configuration (`pot16.ptau`, Section 6) avoids this problem but limits chain depth to 4 — which may be insufficient for the real-world AI pipeline in Section 7 (which already uses 4 hops with no headroom).

- **In-threat-model?** No — the threat model assumes an honest CRS generation. The construction should explicitly name the ceremony (e.g., Hermez's perpetual powers of tau), provide a verification transcript, and document which ceremony participant properties enterprise buyers must vet. Without this, every enterprise security review will stall at "who ran the trusted setup."

---

### Attack 4: Nullifier Metadata Leaks Defeat the Whistleblower Scenario

- **Attack:** Section 2 lists `delegationNullifier[0..MAX_HOPS-1]` as *public outputs* of the `ChainAuditProof`, and Section 3 (GAME-FAITHFUL) requires each nullifier to exist in the *public on-chain nullifier registry*. The GAME-HIDE argument claims intermediate participants are hidden. But each `delegationNullifier[h] = Poseidon2(delegationToken, sessionNonce)` is written to a public blockchain when the original delegation occurs (GAME-FAITHFUL requires this for soundness). This means a blockchain observer can see: (a) that a 4-hop chain was executed, (b) the exact block timestamps of each delegation write, (c) that these 4 nullifiers were later consumed in an audit proof with a specific `sessionNonce`, and (d) co-occurrence patterns if multiple audit proofs share a nullifier. For the whistleblower scenario (Section 7: "journalist → source-agent → anonymizing-relay → publication-tool"), the *timing pattern* of four on-chain nullifier registry writes, followed by an audit proof submission, is deanonymizing metadata even if the participants themselves are hidden. OPSEC-aware adversaries — e.g., intelligence agencies — conduct traffic analysis, not just content analysis. Stytch Connected Apps and the Client Attestation draft (draft-ietf-oauth-attestation-based-client-auth) operate over HTTPS where this metadata is far harder to correlate.

- **Why it works:** Section 3's GAME-HIDE note concedes: *"Cross-hop linkage (correlating which nullifiers belong to the same chain) is inherent in the audit proof's public output vector."* This is dismissed as "reveals only that these hops form a chain — the same information conveyed by chainLength." But on a public blockchain, nullifier writes are timestamped, attributed to a transaction sender (gas payer), and permanently linked to a block. The construction's GAME-HIDE proof is information-theoretically tight given its public signal set — but the public signal set is too large for the whistleblower use case. Stytch's Connected Apps use ephemeral session tokens over TLS; the "session" leaves no public on-chain trace. For the journalist use case, Bolyra's public blockchain requirement is strictly worse than any OAuth-based solution's HTTPS-only audit log.

- **In-threat-model?** No — the threat model excludes traffic analysis and on-chain metadata correlation. The construction must either (a) use private on-chain nullifier registries (stealth addresses, Tornado-style accumulators) for the whistleblower case, or (b) drop the whistleblower scenario from Section 7 and scope the claim to regulated financial pipelines where public auditability is a *feature*, not a liability.


## Persona: cryptographer

*Applied cryptographer. IACR publications. Reviews for CRYPTO/EUROCRYPT/S&P. My job is to find the gap between what the construction claims and what it proves. Let's go.*

---

### Attack 1: GAME-HIDE is vacuously true — the challenge distribution is empty, and delegation nullifiers are participant fingerprints

**Attack:**

The author asserts GAME-HIDE holds because "a valid proof is a perfect simulation independent of the witness." That is true of the PLONK verifier's view — but the construction's *public outputs* include `delegationNullifier[h]` for every active hop.

Each nullifier is:

```
delegationNullifier[h] = Poseidon2(
    Poseidon4(runningScopeCommitment, delegateeCredCommitment[h],
              delegateeScope[h], delegateeExpiry[h]),
    sessionNonce
)
```

`delegateeCredCommitment[h]` is a private input that encodes the delegatee's identity. For GAME-HIDE to be meaningful, the author requires challenge pairs (C₀, C₁) that share identical nullifiers but have *different intermediate participants*. But under CR-Poseidon, if `delegateeCredCommitment[h]` differs between C₀ and C₁, then `Poseidon4(...)` differs, and therefore `Poseidon2(...)` differs. No valid challenge pair exists where participants differ and nullifiers agree. The challenge distribution is **empty**.

This is not a win for the construction — it is a vacuous game. The correct conclusion is the opposite: the publicly exposed nullifiers are **deterministic fingerprints of participant identities**. An adversary holding a database of enrolled agent credential commitments can precompute:

```
candidate_nullifier = Poseidon2(
    Poseidon4(knownScopeCommitment, knownCredCommitment,
              knownScope, knownExpiry),
    sessionNonce
)
```

for every enrolled agent and compare against the audit proof's public `delegationNullifier` outputs. Matching reveals which agent was at each hop. In the NCUA scenario (§7), where the on-chain registry necessarily links nullifiers to registration timestamps and operator identities, this is a practical deanonymization, not a theoretical one.

**Why it fails against the construction:** The GAME-HIDE reduction sketch is circular. It asserts ZK-Groth16 gives simulation, then separately asserts the public nullifiers "reveal nothing" under Poseidon preimage resistance. But the adversary does not need a preimage — they need only evaluate Poseidon forward over a finite set of enrolled agents. The preimage resistance argument defends against recovering `delegateeCredCommitment` from the nullifier *in isolation*; it says nothing about an adversary who can enumerate candidates.

**In-threat-model?** No — the construction must address. GAME-HIDE as stated does not provide the claimed privacy guarantee. The fix requires either (a) blinding the nullifier with a secret salt not derivable from public inputs, or (b) restricting the auditor's access to the nullifier set such that the precomputation attack is infeasible. Option (a) breaks GAME-FAITHFUL (the registry check requires the auditor to compute or receive the nullifier); the tension between GAME-HIDE and GAME-FAITHFUL is unresolved.

---

### Attack 2: `allDelegateesMerkleRoot` is a shared trust anchor — Section 8's cross-org claim is false

**Attack:**

Section 8 claims ChainAuditProof achieves "Cross-org without shared trust anchor" while the baseline (RFC 8693 + WIMSE) cannot. Constraint 2h (§2) is:

```
computedRoot = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[h], ..., delegateeMerkleProofSiblings[h]
)
assert computedRoot === allDelegateesMerkleRoot
```

This constraint fires for **every active hop**, and `allDelegateesMerkleRoot` is a **single field element — a single public output** constrained to be identical across all hops. Therefore, all delegatees across all participating organizations must be enrolled in the **same Merkle tree at the same root state**.

The auditor verification procedure (§2, step 2) then checks `allDelegateesMerkleRoot` against "the agent root history buffer" — an on-chain structure. This is a shared trust anchor: it is centralized enrollment infrastructure, just implemented via a smart contract instead of an AS. The construction has not eliminated the shared trust anchor; it has moved it from an AS to a blockchain. For the journalist/source anonymity scenario (§7, whistleblower variant), every intermediate relay must be enrolled in the same on-chain registry visible to the auditor. That registry itself leaks information about the set of possible participants.

A genuine cross-org construction would require per-hop Merkle root verification against distinct, organization-controlled roots, with the circuit proving that each root is a legitimate instance of the Bolyra agent registry (e.g., via a root-of-roots structure or a Merkle tree of valid registry roots). The current circuit has no such gadget.

**Why it fails against the construction:** The constraint is unambiguous — `allDelegateesMerkleRoot` is invariant across all hops. No cross-org interpretation is possible without violating this constraint or extending the circuit.

**In-threat-model?** No — the construction must address. The cross-org claim in §8 is inconsistent with constraint 2h. The construction should either (a) revise the claim to "single-org or pre-federated enrollment," or (b) redesign the circuit to support per-hop root verification, adding a `delegateeMerkleRoot[h]` input and a separate trusted-root registry check per org.

---

### Attack 3: Universal SRS ceremony is unspecified — GAME-NARROW, GAME-FORGE, and GAME-FAITHFUL all collapse under subverted setup

**Attack:**

The construction selects PLONK for the audit proof precisely to avoid per-circuit trusted setup (§6: "PLONK avoids a per-circuit trusted setup ceremony"). But PLONK is not setup-free. It requires a **universal structured reference string** (the "pot18.ptau" referenced in §6). If the trapdoor τ (the "toxic waste") from the SRS generation is retained by any party, that party can:

1. Forge valid PLONK proofs for **any** satisfying or **non-satisfying** witness.
2. Break GAME-NARROW: produce a "proof" that a widening delegation chain narrowed monotonically.
3. Break GAME-FORGE: produce a proof anchored at an `initialScopeCommitment` that was never on-chain.
4. Break GAME-FAITHFUL: produce a proof with fabricated nullifiers that pass the circuit but don't exist in the registry — the GAME-FAITHFUL check (auditor step 3) would catch this at the off-chain verifier, but the KS-PLONK assumption has already failed, so the extractor cannot extract a witness at all.

The security argument (§4) for all four games is conditional on KS-Groth16 or KS-PLONK. Both assumptions are conditioned on **honest SRS generation**. The construction provides:

- No specification of how pot18.ptau was or will be generated.
- No reference to a multi-party computation ceremony.
- No discussion of what happens if Bolyra Inc. retains τ.
- No mention of Ethereum's existing Groth16 ceremony or any reusable universal SRS with a documented trust chain.

For the NCUA examination use case (§7): an NCUA examiner accepting a PLONK proof as regulatory evidence must trust the SRS generation. If Bolyra Inc. ran the ceremony internally, the examiner is trusting Bolyra Inc. not to have retained τ — equivalent to trusting a centralized attestation server, which is exactly the baseline the construction claims to supersede.

The standard mitigation is a publicly verifiable MPC ceremony (e.g., Zcash's Powers of Tau) with diversity of participants such that at least one is honest. The construction must formally state its setup assumption and either (a) reference a ceremony with documented trust, or (b) add setup security to the adversary model with an explicit analysis of what fails under setup compromise.

**Why it works:** KS-PLONK fails under τ-compromise by definition. All reductions in §4 that invoke KS-PLONK as an assumption lose their binding.

**In-threat-model?** No — the construction must address. This is not a theoretical concern for NCUA use — financial regulators will ask "who generated the SRS and how do I know the toxic waste was destroyed?" The construction has no answer.

---

### Attack 4: GAME-FAITHFUL proves each presented hop is real, not that the presented chain is complete — shortcut chain forgery

**Attack:**

GAME-FAITHFUL (§3) is stated as: "adversary produces a valid audit proof where some active hop h has `delegationNullifier[h] ∉ N`." The game prevents **fabricated hops** (hops that never occurred). It does not prevent **hop omission** (real hops that did occur but are not presented).

Consider a 4-hop chain: Root → A → B → C, where:
- Hop 1 (Root→A): executed on-chain, nullifier n₁ ∈ N
- Hop 2 (A→B): executed on-chain, nullifier n₂ ∈ N; **B received a scope expansion** that the `Delegation` circuit rejected and did not record — OR alternatively, the adversary simply pre-registers a second delegation Root→A→C (skipping B) on-chain by executing `Delegation` circuit proofs for that shortcut path, giving nullifier n₁' and n₂' ∈ N.

Now the adversary presents `ChainAuditProof` with `chainLength = 2`, `active = [1, 1, 0, ..., 0]`, nullifiers `[n₁', n₂', 0, ...]`. The auditor's GAME-FAITHFUL check (step 3) passes: n₁' and n₂' are both in N. The narrowing constraint holds. The proof verifies. The auditor concludes "2-hop chain, monotonically narrowing."

But the operational pipeline was 4 hops — and in particular, the B agent with different effective permissions was elided. The NCUA examiner believes the stablecoin transfer went through 2 agents; it actually went through 4. The regulatory guarantee ("no hop exceeded its mandate") does not cover the 4-hop operational reality.

The construction has no mechanism to assert *chain completeness* — that the presented chain is the *only* path the operation traversed, not merely *a* valid path with real nullifiers. An adversary controlling 2 colluding agents can always pre-register shortcut paths that give them flexibility to present a sanitized audit view.

A formal fix requires either (a) a **unique chain identifier** binding the audit proof to exactly one execution path (e.g., a hash-chain over all hop events in order, logged on-chain at execution time), or (b) a revised game definition: `GAME-COMPLETE` where the adversary wins if the presented chain's nullifier set is a proper subset of the nullifiers that occurred during the audited session.

**Why it works:** The on-chain nullifier registry is append-only but does not record *which session* each delegation was associated with, beyond the sessionNonce. Multiple delegation paths (short and long) anchored to the same initialScopeCommitment and sessionNonce can coexist in N. The circuit selects among them by choosing which nullifiers to include in the proof's public output.

**In-threat-model?** No — the construction must address. The gap between "each hop is real" and "this is the complete operational chain" is the difference between proving "no single step was unauthorized" and proving "the audit covers the full execution." For NCUA compliance, the latter is the required guarantee.


## Persona: cu\_ciso

---

### Attack 1: The Proof Is Cryptographically Sound and Legally Inert

- **Attack:** The CISO walks the construction's §7 deployment scenario into an NCUA examination. The examiner asks for the "audit trail" of the stablecoin pipeline. The CU produces a PLONK proof — a `bytes[]` blob — plus 12 field elements that are opaque Poseidon hashes. The examiner's questionnaire (NCUA Part 748 Appendix B, §III.C "Audit") asks for documented evidence that controls operated as designed. Field elements are not documentation. The examiner asks: "Who verified this proof, when, and what did it confirm?" The on-chain transaction hash answers "when." Nothing in the construction answers "who" or "what it confirmed in plain language." The `auditDigest` is a commitment to the audit event, not a human-readable record of the event. Under FFIEC CAT, the "Audit" maturity domain requires that "audit trails are sufficient to reconstruct events." The construction proves the math; it does not produce the record.

- **Why it works / why it fails:** The construction's §7 lists "what the auditor learns" but this is a logical statement about the circuit's ZK properties, not a legal audit artifact. An NCUA examiner cannot certify to the board that the pipeline was compliant by looking at a field element. The construction provides no bridge between `auditDigest` and a timestamped, human-readable compliance record suitable for §748 documentation retention (7-year minimum). The construction is silent on this layer entirely.

- **In-threat-model?** **No.** The construction's threat model covers cryptographic adversaries (PPT, DL-BJJ, CR-Poseidon). It does not address the regulatory artifact layer. The construction must produce — or specify how to produce — a machine-signed, plain-language attestation ("On [date], delegation chain for session [nonce] verified 4-hop monotonic narrowing; terminal scope: FINANCIAL\_SMALL only; each hop confirmed in registry") that a CU examiner can attach to their examination response file. Without this translation layer, the ZK proof is a compliance dead end.

---

### Attack 2: REG-INTEGRITY Is Where the Whole Construction Lives and Dies

- **Attack:** The CISO reads §4 (Security argument, assumption 6): *"REG-INTEGRITY: The on-chain delegation nullifier registry is append-only and accepts writes only from the verified Delegation circuit execution path in the registry contract (smart contract correctness assumption, not a cryptographic assumption)."* The construction explicitly flags this as outside the cryptographic trust boundary. The CISO's Vendor Management Policy requires a SOC 2 Type II or equivalent for any system that generates audit evidence used in examination responses. The registry contract has no SOC 2. It has no named vendor. It has no incident notification SLA. The CISO asks: who audited this contract? What is the upgrade governance? If the contract owner key is compromised, a malicious write to the registry makes fabricated hops pass GAME-FAITHFUL. The construction's entire anti-shadow-chain guarantee (GAME-FAITHFUL) collapses at this single non-cryptographic seam.

- **Why it works / why it fails:** The construction's §4 reduction for GAME-FAITHFUL explicitly states the registry's integrity is assumed, not proven. In a regulatory context, "assumed" means "the examiner will ask for your control evidence." The construction has no answer: no multisig governance spec, no upgrade timelock, no contract audit citation, no key custody policy for the registry admin. An adversary who compromises the registry deployer key or finds a re-entrancy bug in the nullifier write path does not need to break BN128 — they just write phantom nullifiers directly. The ZK math is irreproachable; the smart contract wrapping it is a conventional software target with conventional attack surface.

- **In-threat-model?** **No.** GAME-FAITHFUL's proof sketch stops at "REG-INTEGRITY holds." The construction must specify: (a) immutable or governance-gated registry contract with a named auditor, (b) key custody for the write-path authorizing contract, (c) monitoring/alerting on anomalous nullifier write volume, and (d) how a CU demonstrates REG-INTEGRITY to an NCUA third-party risk examiner. This is the construction's single point of non-cryptographic failure and it is currently unaddressed.

---

### Attack 3: Agent Key Custody Replicates the Browser-Secret Problem at the Operator Layer

- **Attack:** The CISO's attack prompt verbatim: *"Key custody: where does the member secret live? If it's a browser, you've lost me."* The construction's delegation chain requires each delegator to hold an EdDSA private key (constraint 2g: `EdDSAPoseidonVerifier` on `delegationToken`). In the §7 NFCU scenario, the root agent (member-facing chatbot) holds a signing key. In practice, that key lives in the inference infrastructure — a GPU cluster, a Lambda function, an ECS container. None of these are HSMs. GLBA Safeguards Rule §314.4(c)(3) requires "encryption of customer information in transit and at rest" and §314.4(f) requires "oversight of service providers." If the root agent's EdDSA private key leaks — via model inversion, container escape, secrets misconfiguration, or insider threat — an adversary can sign arbitrary delegation tokens. Every subsequent hop's EdDSA check passes. The circuit is satisfied. The GAME-FAITHFUL nullifiers exist on-chain because the attacker ran real delegations. The audit proof is valid. The pipeline was not.

- **Why it works / why it fails:** The construction correctly specifies that scope narrowing is enforced in-circuit and that the delegator must sign. It does not specify where, how, or under what custody model the delegator's EdDSA private key is held. The circuit proves "a valid signature exists" — it cannot prove "the key was held in a FIPS 140-2 Level 3 HSM operated by an authorized party." For a CU operating under GLBA and subject to NCUA IT examination, key custody is a regulatory requirement, not a crypto-optional detail. The construction currently treats operator keys as out-of-scope. They are not out of scope for the regulator.

- **In-threat-model?** **No.** The construction's adversary model grants the adversary control of "up to MAX\_HOPS - 1 colluding agents" but does not model key compromise of honest agents via infrastructure attacks. The construction must specify a key custody requirement (HSM-class or equivalent) and a key rotation protocol for delegation signing keys, or explicitly bound the claim to deployments with adequate key protection. A CU cannot deploy a system where the compliance guarantee is conditioned on "no agent key ever leaks from your AI infrastructure."

---

### Attack 4: On-Chain Liveness Is a Harder SLA Than Any CU Core Processor

- **Attack:** The CISO's attack prompt: *"If your on-chain registry has a 1% outage budget, that's more than my core processor."* The construction's GAME-FAITHFUL auditor verification steps (§2, "Auditor verification procedure") require the auditor to query the on-chain delegation nullifier registry for each hop (step 3). This is a live blockchain read at audit time. Base (the deployment target per `bolyra/CLAUDE.md`) has experienced sequencer outages. During a sequencer outage, the on-chain registry is unreadable. An NCUA examination does not pause for blockchain maintenance windows. If the examiner requests a delegation audit proof at 9am on an exam day and the Base sequencer is down, the CU cannot complete step 3. The audit proof — mathematically valid — cannot be verified to the GAME-FAITHFUL standard. The CU's examination response is incomplete. This is a documented control failure, not a cryptographic failure.

- **Why it works / why it fails:** The construction lists Base Sepolia as the deployment target and specifies on-chain registry reads as mandatory for GAME-FAITHFUL. The construction contains no fallback for registry unavailability: no offline snapshot mechanism, no alternative verification path, no L1 fallback. The PLONK proof itself (step 5) can be verified offline against the verifier contract's bytecode — but step 3 (nullifier registry lookup) requires liveness. The construction creates an availability dependency on a Layer 2 sequencer for a regulatory compliance artifact. CU core processors operate at 99.9%+ availability with contractual SLAs, incident response procedures, and NCUA-recognized vendor risk frameworks. No L2 blockchain provides equivalent regulatory assurance or contractual SLA to a federally insured depository.

- **In-threat-model?** **No.** The construction's threat model covers PPT adversaries, not availability adversaries (including benign infrastructure failure). The construction must either: (a) provide an offline audit path where a snapshot of the nullifier registry (with verifiable Merkle root pinned on L1) enables offline verification, or (b) explicitly bound the deployment context to environments where chain availability is guaranteed through a separate legal/contractual mechanism. Without this, the construction cannot claim suitability for NCUA examination contexts — the very use case named in §7.


## Persona: rfc7662_advocate

*OAuth WG veteran, ten years of production introspection, zero patience for ZK theater.*

---

### Attack 1: Single Merkle Root Defeats the Cross-Org Claim (§2h, §8 "Cross-org")

- **Attack:** Constraint 2h enforces `computedRoot === allDelegateesMerkleRoot` uniformly across **all** active hops. Every delegatee — regardless of organizational origin — must have a Merkle proof against the **same** `allDelegateesMerkleRoot`. In a genuinely cross-org chain (Navy Federal → fintech partner → SWIFT correspondent → settlement agent), agents from four different organizations must be co-enrolled in a single shared Merkle tree before the first delegation fires. That tree is a shared enrollment registry — the construction's own §5 maps it to `allDelegateesMerkleRoot` checked against "the on-chain agent root history buffer." Who administers that buffer? Who approves enrollment? There is a trust anchor; it is just on-chain rather than in an AS.

  Compare with WIMSE (draft-ietf-oauth-workload-identity): each org maintains its own SPIFFE trust domain and SVID-issuing CA. Cross-org trust uses bilateral CA federation, the same model the web PKI has used for twenty years. WIMSE requires no single shared enrollment registry; trust is bilateral and revocable per pair. The construction requires all cross-org agents to be enrolled in one global tree before any delegation can be proven.

- **Why it works / fails:** The construction's §8 table claims "Cross-org without shared trust anchor: Impossible [for baseline]." This is only true if you define "shared trust anchor" as an AS. If you include a shared enrollment registry, the claim collapses. The circuit as written cannot produce a valid proof for a chain whose delegatees are enrolled in different per-org trees — the Merkle root would differ per hop, but the circuit accepts only one. The construction either (a) requires a global unified enrollment tree (a more centralized trust anchor than a federated AS) or (b) must be revised to accept per-hop Merkle roots, which then become additional public outputs that leak organizational structure.

- **In-threat-model?** **No — construction must address.** The §8 cross-org claim is load-bearing for the "beyond narrow regulatory niches" goal in the candidate's `gap_to_close`. As written, the circuit structurally prohibits multi-org chains unless all agents are co-enrolled.

---

### Attack 2: GAME-HIDE Nullifier Leakage Enables Closed-World Deanonymization (§3 GAME-HIDE note, §4 "Privacy note")

- **Attack:** Each `delegationNullifier[h] = Poseidon2(delegationToken, sessionNonce)` where `delegationToken = Poseidon4(prevScopeCommitment, delegateeCredCommitment[h], delegateeScope[h], delegateeExpiry[h])`. These eight values are **public outputs** of the proof. In any realistic deployment, the set of enrolled agents is finite and known (the Navy Federal scenario names four tool agents). The `allDelegateesMerkleRoot` is public, fixing the enrollment universe. An auditor who enumerates all candidate `credentialCommitment` values (computable from `Poseidon5(modelHash, operatorPubkey, permissions, expiry, salt)` for known agents) can compute the expected nullifier for each candidate and match against the observed `delegationNullifier[h]`. This is dictionary attack on the nullifier: Poseidon is a permutation, not a KDF with a fresh secret — the only entropy hiding the delegatee's identity is the `salt` in the credential commitment, whose distribution is unspecified.

  Compare with OIDC Pairwise Pseudonymous Identifiers (PPID, §8.1 of OpenID Connect Core): the OIDC spec explicitly derives PPIDs as `HMAC(sector_id || local_account_id, sector_secret)` where `sector_secret` is AS-held entropy unknown to the RS. The Poseidon-based nullifier has no equivalent secret; the AS (the Bolyra registry contract) holds no per-auditor secret that would prevent nullifier preimage attacks across the full enrollment set.

  The §3 GAME-HIDE note attempts to sidestep this: "two chains can have different intermediate participant identities (different credentialCommitments and public keys) but identical delegation tokens." But `delegationToken` includes `delegateeCredCommitment[h]` as an explicit input. If `delegateeCredCommitment` differs between C0 and C1, `delegationToken` differs (under CR-Poseidon), so `delegationNullifier[h]` differs, so the public outputs differ — and the adversary trivially distinguishes C0 from C1 by reading the nullifiers. The note's claim that "the inputs are held equal" while "the participants differ" requires identical `credentialCommitments` for different participants, which contradicts what a credential commitment is for. The GAME-HIDE proof as written has an internal inconsistency.

- **Why it works / fails:** In an open-world setting with large anonymous agent pools, the attack fails — preimage search is intractable when `salt` has high entropy. In the stated deployment (Navy Federal's named tool agents, enumerable from the agent tree's leaf count visible via `allDelegateesMerkleRoot` public output), it works. The GAME-HIDE indistinguishability game as constructed cannot be satisfied by two chains with genuinely different participants — it can only be satisfied by chains with the same credential commitments but different EdDSA keys, which is an extremely artificial scenario.

- **In-threat-model?** **Partially.** GAME-HIDE holds in the asymptotic sense (computationally bounded adversary, open-world). But the construction must address the closed-world deanonymization gap explicitly and state the minimum entropy requirement on `salt` to prevent it. The GAME-HIDE note's internal contradiction must be corrected — the current statement is unsound.

---

### Attack 3: REG-INTEGRITY Is Not Cryptographic — Smart Contract Trust Replaces AS Trust Without Gaining Formal Guarantees (§4 "Assumptions," §4 GAME-FAITHFUL reduction)

- **Attack:** §4 explicitly concedes: "REG-INTEGRITY: ...smart contract correctness assumption, **not a cryptographic assumption**." The entire GAME-FAITHFUL reduction — the guarantee that every audited hop actually occurred on-chain — reduces to REG-INTEGRITY. Remove it and the shadow-chain attack succeeds: an adversary with a valid `pot18.ptau` SRS can produce a syntactically valid `ChainAuditProof` whose nullifiers are locally computed but never recorded in any registry. The construction closes this gap by trusting a Solidity contract, not by a cryptographic argument.

  Now compare the alternative. An RFC 7662 AS with: (a) HSM-backed signing keys (FIPS 140-2 Level 3), (b) RFC 3161 trusted timestamps on every token issuance, (c) WORM-backed audit log (AWS CloudTrail with Object Lock), and (d) annual SOC 2 Type II certification provides an append-only record with 20 years of regulatory acceptance. NCUA already mandates this for examined institutions. The construction's on-chain registry has: (a) Solidity code that may contain bugs, (b) a Base Sepolia L2 sequencer that is currently centralized (one sequencer, no permissionless fallback in production), (c) governance risk if the registry contract is upgradeable, and (d) zero production deployment history. The trust model is isomorphic — both require a trusted append-only log — but the baseline has hardened instantiations; the construction does not.

  The §8 table claims "No trusted third party." This is false. The claim conflates "no trusted Authorization Server" with "no trusted party." The smart contract + its deployer + the Base Sepolia sequencer + the L2 bridge security all constitute a trusted computing base. Under L2 sequencer failure or a reorg (Base is an OP Stack rollup; reorgs up to the challenge window are possible), `delegationNullifier[h]` could appear absent in the registry even for legitimate hops, breaking the auditor's GAME-FAITHFUL check.

- **Why it works / fails:** The reduction correctly identifies that GAME-FAITHFUL requires REG-INTEGRITY, and the construction is honest about it being non-cryptographic. The attack therefore identifies a gap in the §8 comparative table, not a soundness flaw in the games themselves. But the candidate's target strength of 10 requires the construction to stand on its own against the baseline, and "we trust a smart contract" vs. "you trust an AS" is not a clear win when the smart contract has weaker operational guarantees for the stated regulatory context (NCUA examination).

- **In-threat-model?** **Yes — construction survives — but §8 comparative claim must be qualified.** "No trusted third party" should be replaced with "no trusted Authorization Server" with an explicit acknowledgment that REG-INTEGRITY is a distinct non-cryptographic trust assumption, its instantiation risks (sequencer centralization, upgrade governance), and a comparison with RFC 3161 / WORM-based AS logs.

---

### Attack 4: GAME-FAITHFUL's Auditor Verification Procedure Reinstates an Online Dependency — Signed JWT Introspection Outperforms It (§2 "Auditor verification procedure," §8 "Work without AS")

- **Attack:** The attack prompt asks: "JWT introspection response removes the AS from the hot path — why isn't that equivalent?" The construction's auditor verification procedure (§2, steps 1–5) requires the auditor to, for each active hop `h`, look up `delegationNullifier[h]` in the **on-chain delegation nullifier registry**. This is a live blockchain read — the auditor needs a functioning Base Sepolia node, the nullifier contract must be reachable, and the state must be finalized. For an 8-hop chain, this is 8 separate on-chain lookups, plus `lastScopeCommitment[sessionNonce]` and `allDelegateesMerkleRoot` checks — 10+ RPC calls per audit.

  draft-ietf-oauth-jwt-introspection-response (RFC 8705 supersedes some of this) produces a **signed JWT** — the AS signs a structured introspection result that the auditor verifies entirely offline using only the AS's cached JWK. No RPC call. No live service. The signed JWT can be archived, forwarded, and reverified years later with zero network dependency. Under RFC 8693, a chain of signed exchange tokens provides a tamper-evident delegation record that an auditor can verify offline in O(n) JWS verifications against known AS public keys — one per org.

  The construction's PLONK proof is similarly offline-verifiable as a mathematical artifact, but GAME-FAITHFUL binds the proof's meaning to an online registry check. The PLONK verification step (step 5) is offline; the meaningful anti-shadow-chain step (step 3) is online. Stripping the online check degrades GAME-FAITHFUL to GAME-FORGE, which only prevents anchor forgery, not hop fabrication. The construction therefore does not eliminate the online hot path — it relocates it from the AS introspection endpoint to the blockchain RPC endpoint.

  A combined baseline — RFC 9449 DPoP (sender-constraint), RFC 8693 token exchange (delegation with AS-signed exchange tokens), and draft-ietf-oauth-jwt-introspection-response (offline-verifiable signed introspection) — provides: sender-constraint without ZK (DPoP), delegation audit trail as archived signed JWTs (RFC 8693), and offline verification (signed introspection JWT). The one property it cannot provide is **hiding intermediate scope values from the auditor** — the auditor must see the scopes in the signed JWT to verify narrowing. This is the genuine, irreducible ZK advantage. Everything else in the §8 table is either matched by the baseline or qualitatively equivalent when scrutinized against the actual verification procedure.

- **Why it works / fails:** The attack correctly identifies that the "no AS hot path" advantage is partially illusory — GAME-FAITHFUL requires an online chain query. The attack fails to fully undermine the construction because (a) the blockchain is decentralized and not controlled by any single party (unlike a single AS endpoint), and (b) the scope-hiding property is genuine and not matched by the baseline. But the construction's §8 framing — "JWT introspection response removes the AS from the hot path — why isn't that equivalent?" — must acknowledge that GAME-FAITHFUL's auditor procedure has its own online dependency with distinct failure modes.

- **In-threat-model?** **Yes — construction survives — but §8 must be qualified.** The honest §8 entry for "Work without AS" should read: "Auditor PLONK verification is offline; auditor GAME-FAITHFUL nullifier checks require live blockchain read access. Failure modes differ from AS introspection (decentralized vs. single-AS uptime) but an online dependency exists. The irreducible advantage over the baseline is scope hiding — the auditor never sees permission bitmasks at any hop, a property no RFC 8693 + signed-JWT combination can provide."


## Persona: spiffe_engineer

---

### Attack 1: Single `allDelegateesMerkleRoot` collapses for every stated cross-org scenario

**Attack:** The circuit forces a single public output `allDelegateesMerkleRoot` and asserts at constraint 2h that *every hop's delegatee* resolves against that same root:

```
assert computedRoot === allDelegateesMerkleRoot
```

In a genuine cross-org pipeline — the Navy Federal → external KYC vendor → sanctions-screening provider scenario the construction gestures at — each organization runs its own SPIRE server with its own agent enrollment tree. Org A's `allDelegateesMerkleRoot` is not Org B's root. Either (a) all participating organizations must merge their agent populations into a single shared Merkle tree before the handshake — which is a global organizational registry, not "no shared trust anchor" — or (b) the circuit simply cannot be satisfied when hops straddle organizational boundaries, making the proof-generation step fail silently on the prover side.

SPIFFE federation handles this correctly: each trust domain maintains its own root CA and SPIRE server; cross-domain verification uses X.509 cross-signing without requiring a unified identity store. The construction has no equivalent mechanism. The `BinaryMerkleRoot(MAX_DEPTH)` gadget is hard-coded to a single root; adding per-hop root inputs would require a fundamentally different circuit topology.

**Why it works / why it fails:** The attack succeeds on the construction as written. There is no mechanism in §2 or §5 to assert different roots per organizational boundary. Adding `allDelegateesMerkleRoot[h]` as per-hop public outputs would require per-hop root history checks on-chain and a new public input count of `MAX_HOPS` roots instead of one — an architectural change, not a parameter tweak.

**In-threat-model?** No — the construction must address this. The gap-to-close explicitly lists "cross-org agent handoff" as a target scenario, but the circuit is structurally incompatible with it.

---

### Attack 2: You replaced the Authorization Server with a blockchain — that is still a shared trust anchor, and a worse one

**Attack:** §8 "Why the baseline cannot match" makes the claim: "Cross-org without shared trust anchor: Requires federation (WIMSE) … but no unified narrowing-proof authority … Single proof covers the entire chain regardless of organizational boundaries … No shared AS needed."

The construction's verifier checks depend entirely on three on-chain data structures:

- `lastScopeCommitment[sessionNonce]` — must exist in the on-chain registry
- `allDelegateesMerkleRoot` — must be in the on-chain agent root history buffer
- `delegationNullifier[h]` — must be present in the on-chain delegation nullifier registry

Every participant in a cross-org chain must trust the same smart contract at the same address on the same chain. That is a shared trust anchor. It is not an Authorization Server, but the security-architecture claim — that Bolyra eliminates the need for a common trusted third party — is false. You have not removed the trust anchor; you have relocated it from a federated set of AS deployments to a single append-only contract.

SPIFFE federation actually gives you *per-trust-domain* anchors with no global singleton. Org A trusts its own SPIRE root; Org B trusts its own; they establish federation bilaterally. Neither org needs to trust a global registry. Bolyra's construction requires both orgs to emit on-chain state to the same registry before an audit proof can be generated. If the chain forks, the registry contract is paused by governance, or the chain is congested, all audit capabilities halt — a liveness dependency that an AS cluster behind a load balancer does not have.

**Why it works / why it fails:** The claim "no shared trust anchor" is textually false given REG-INTEGRITY in §3 and the auditor verification procedure in §2. The construction's blockchain registry is a shared trust anchor with different liveness and governance properties than an AS, but it is not absent.

**In-threat-model?** No — §8's comparison table makes an explicit false claim. The table entry for "Cross-org without shared trust anchor" must be corrected to accurately characterize the blockchain registry as a shared trust anchor with specific liveness and governance properties, then argue why those properties are preferable to SPIFFE federation — not that the anchor is absent.

---

### Attack 3: WIMSE `Workload-Trace-Context` already provides tamper-evident delegation audit trails without ZK overhead — construction does not engage

**Attack:** The WIMSE architecture draft (draft-ietf-wimse-arch, §5.x) defines workload-to-workload token exchange with a `Workload-Trace-Context` header that propagates across hops, bound to the originating token's `jti`. An AS-adjacent trust verifier or a SPIRE-integrated log aggregator can reconstruct the full delegation chain from these headers and verify each hop was authorized by the SPIRE-verified issuer at that hop, producing a tamper-evident audit trail without requiring any cryptographic proof beyond standard OIDC/JWT signature verification.

The construction's §8 says the baseline "requires auditor to trust AS execution logs" and that "a rogue agent could claim delegations that never passed through the AS." These are legitimate attacks against a naive AS log. But WIMSE-compliant token exchange requires each hop's token to be a fresh token issued by the workload's own SPIRE-attested SVID, countersigned by the issuing AS. The audit log is not a single AS's log — it is a per-hop SVID-attested issuance record distributed across potentially many SPIRE deployments. Forging a hop requires forging a SVID, which requires compromising the SPIRE server's intermediate CA — a stronger trust model than "the agent constructs a ZK witness."

The construction does not reference WIMSE at all. §8's baseline comparison is against RFC 8693 + BBS+ — a 2020-era RFC that predates WIMSE. Comparing against current WIMSE trajectory is required to justify the design space.

**Why it works / why it fails:** The attack partially succeeds: the construction's baseline comparison is stale. WIMSE's active development scope includes selective disclosure and delegation chain auditability. However, WIMSE cannot hide intermediate scope *values* from the auditor (WIMSE tokens carry scope claims in the clear, or rely on structured encryption that still requires the auditor to have a decryption key). The ZK construction's `GAME-HIDE` property — that the auditor cannot learn intermediate scopes even with full protocol participation — has no WIMSE equivalent. The attack narrows the gap but does not eliminate the construction's core differentiator.

**In-threat-model?** No — the construction must engage with WIMSE draft-ietf-wimse-arch in §8 to credibly claim the baseline gap. Comparing against RFC 8693 + BBS+ is insufficient; it invites this exact dismissal from workload-identity practitioners.

---

### Attack 4: GAME-HIDE's privacy proof is self-contradictory under CR-Poseidon

**Attack:** The GAME-HIDE proof note states:

> "Two chains can have different intermediate participant identities (different credentialCommitments and public keys) but identical delegation tokens, since the delegation token is `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` — if the delegateeCredCommitment differs but the token inputs are held equal, the participants differ while the nullifier is preserved."

This is internally contradictory. `delegateeCredCommitment` *is* one of the four token inputs. If `delegateeCredCommitment` differs between C0 and C1, then the four-tuple `(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` differs between C0 and C1. Under CR-Poseidon (Assumption 2 in §4), `Poseidon4` is collision-resistant, which means:

```
credCommitment_0 ≠ credCommitment_1
  ⟹ Poseidon4(..., credCommitment_0, ...) ≠ Poseidon4(..., credCommitment_1, ...)
  ⟹ delegationToken_0 ≠ delegationToken_1
  ⟹ delegationNullifier_0 ≠ delegationNullifier_1
```

GAME-HIDE requires C0 and C1 to share identical public outputs, including all `delegationNullifier[h]`. If the credential commitments differ, the nullifiers differ, the public outputs differ, and the game challenge becomes trivially distinguishable — the adversary reads off `delegationNullifier[0]` and queries the on-chain registry to find which participant's enrollment produced that nullifier at the time of the original delegation.

The only GAME-HIDE–compatible instantiation is C0 and C1 with *identical* credential commitments (same agents, different EdDSA keys only). But if credential commitments are identical, participant privacy reduces to EdDSA key unlinkability — which is not argued. The privacy claim as stated requires either a Poseidon collision (breaking Assumption 2) or a redefined GAME-HIDE that no longer covers the whistleblower scenario (where different agents are the privacy-sensitive data, not just their signing keys).

**Why it works / why it fails:** The attack exposes a real gap in the formal argument. The GAME-HIDE proof note contradicts CR-Poseidon in the same construction. In practice, the ZK circuit does hide scope values (constraint 2c's private inputs are genuinely hidden by the ZK property), so the *circuit* is sound. But the *proof note* is wrong, and the claimed indistinguishability game does not establish the privacy guarantee the whistleblower scenario requires. A corrected argument must either (a) reformulate GAME-HIDE so C0 and C1 have identical credential commitments and prove only key-unlinkability, or (b) introduce a credential commitment scheme where the participant identifier is separated from the delegation-token commitment — a structural change to the primitive mapping in §5.

**In-threat-model?** No — the construction must fix the GAME-HIDE proof note. The whistleblower scenario's privacy guarantee is currently unproven under the stated assumptions.
