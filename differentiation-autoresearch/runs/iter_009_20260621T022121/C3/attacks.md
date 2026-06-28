# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Trust Laundering — The Prover Is the Accused

**Attack:** Section 7 says "NFCU generates a single PLONK proof" for the NCUA examiner. But NFCU is the entity under examination. The construction replaces "trust NFCU's self-attestation (option b)" with "trust NFCU's self-generated ZK proof." The prover controls all private inputs: the intermediate scopes, the credential commitments, the EdDSA keys. NFCU can simply generate a proof for a *different, compliant chain* and present it to the examiner while running the real, non-compliant chain in production. There is no requirement in the construction that proof generation happens at delegation time, on-chain, or by a neutral party. The examiner's proof only certifies that *some* 4-hop narrowing chain exists rooted at `rootScopeCommitment` — not that it is the chain that actually executed.

**Why it works / why it fails:** The construction has no binding between the delegation proof and the actual API-call log, timestamp evidence, or NFCU's AS token issuance events. The `auditSessionNonce` binds the proof to an audit session, but the session is initiated by the prover. Section 3 (Threat Model) explicitly excludes the case where the *prover itself* is adversarial with respect to the *chain it chooses to prove*. Game 1 only covers forgery of a chain that violates narrowing — it does not cover selective presentation of a valid chain that doesn't reflect actual system behavior. This is not in the threat model. **Construction must address.**

**In-threat-model?** No. The construction must address proof-of-execution binding — either by requiring on-chain proof generation anchored to observable events (block timestamps, tx hashes), or by involving a neutral witness who co-signs the input to the prover. Otherwise the "no self-attestation" claim in §7 is false.

---

### Attack 2: The Compliance Toolchain Integration Gap

**Attack:** The construction's §7 culminates with the examiner "verifying the PLONK proof against the on-chain verifier contract." In practice, an NCUA examiner uses examination workpapers, AIRES (the NCUA's automated examination system), and existing SIEM/GRC integrations (Splunk, ServiceNow, OneTrust). WorkOS delivers audit logs via webhook, exportable to CSV, directly ingestible by every compliance tool on the market. Auth0's Logs API has Datadog and Splunk connectors that ship in the product. The Auth0 MCP auth flow at auth0.com/ai/docs/mcp/intro/overview produces OAuth tokens with RFC 8693 `act` chain claims that any compliance team can read, query, and archive today. A PLONK proof is a 288-byte blob with no schema that existing GRC tooling understands. The construction provides no answer for: (a) how the proof is stored in a compliance-grade system of record, (b) how it surfaces in an audit report next to other controls, or (c) how an examiner with no crypto background independently verifies it. "Check the on-chain verifier" is not a workflow any NCUA examiner has.

**Why it works / why it fails:** The construction's §8 comparison table row "Offline-verifiable without AS" claims an advantage: "proof verifies against on-chain PLONK verifier." But the comparison baseline is Auth0/WorkOS, which delivers audit artifacts into tooling the examiner already has procurement relationships with. The construction substitutes cryptographic verifiability for operational usability without addressing the translation layer. This is a real GTM blocker — procurement won't approve a tool that requires building custom NCUA-to-Ethereum adapters. **Construction must address.**

**In-threat-model?** No. The threat model covers cryptographic adversaries, not procurement committees. The construction should address: a compliance-readable audit report format that wraps the proof, an integration story for existing GRC tooling, and whether on-chain verification is even permissible under NCUA's technology risk guidelines for third-party dependencies.

---

### Attack 3: The Scope Vocabulary Lock-In Attack

**Attack:** The construction's §8 irreducibility argument — "no composition of these standards produces a single offline-verifiable artifact proving monotonic narrowing over hidden intermediate state" — depends critically on scopes being arbitrary 64-bit bitmasks. In practice, OAuth scopes are named strings: `read:transactions`, `write:accounts`, `pii:ssn`. Bolyra's 8-bit cumulative encoding (§CLAUDE.md Permissions Model) is an opinionated, Bolyra-specific ontology. An enterprise adopting this construction must translate its entire existing permission model into Bolyra's 8 named bits. NFCU almost certainly has role/attribute-based access policies with hundreds of distinct permission types — `read:mortgage_applications`, `write:wire_transfers`, `approve:ach_batch` — none of which map onto READ_DATA / WRITE_DATA / FINANCIAL_SMALL. The construction's "in-circuit enforcement" advantage vanishes the moment the customer's real permission model is wider than 8 bits, because either (a) they collapse rich permissions into coarse Bolyra bits, losing precision, or (b) they can't use the circuit at all. WorkOS's MCP auth at workos.com/mcp passes through arbitrary OAuth scopes from the enterprise's existing IdP with zero re-encoding.

**Why it works / why it fails:** The circuit constraint for monotonic narrowing is `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for `i ∈ [0,64)`, which operates on Bolyra's internal 64-bit encoding (only 8 bits currently used). Extending to customer-defined permissions requires either (a) expanding the bitmask and blowing up circuit size, or (b) a custom circuit per customer — which reintroduces per-circuit trusted setup ceremonies that PLONK was chosen to avoid. The construction claims "no new primitives" but every new customer permission model is effectively a new circuit. **Construction must address.**

**In-threat-model?** No. The construction's scope is fixed at Bolyra's own 8-bit encoding. The claim of general applicability to "multi-tool AI pipelines" and "cross-org agent handoffs" requires solving the permission vocabulary mapping problem before the circuit is usable in any real enterprise.

---

### Attack 4: The Merkle Root Bootstrapping Attack

**Attack:** The construction's integrity guarantee bottoms out at `terminalMerkleRoot`, which the examiner checks "against on-chain root history." Section 5 references a "30-entry circular buffer" for root history. Two questions this construction does not answer: (1) Who controls the agent Merkle tree? Who decides whether the USPS API Agent or the Address Validation Microservice is a valid leaf? If Bolyra controls the tree (as a solo founder operating the registry), then every enterprise delegation chain is dependent on Bolyra's key management and operational continuity. That is a worse vendor lock-in than Auth0's tenant model — Auth0 at least has SOC 2, 24/7 ops, and a $6.5B Okta balance sheet behind it. (2) The 30-entry circular buffer means root history is volatile. An examiner auditing a chain from 31 rotation cycles ago cannot verify `terminalMerkleRoot` without Bolyra's off-chain archive. The construction claims "offline-verifiable without AS" but replaces the AS with an on-chain buffer that has a finite retention window and an off-chain append log controlled by the solo founder. Cloudflare Access (blog.cloudflare.com/enterprise-mcp/) runs on infrastructure with 99.99% SLA and global CDN; "check our 30-slot Ethereum buffer" is not a competitive answer.

**Why it works / why it fails:** The construction is silent on (a) who has write authority to the agent Merkle tree, (b) what governance process approves new agent enrollments, (c) what happens to audit proofs when the root history buffer rolls past the audit event, and (d) what the business continuity plan is if Bolyra ceases operations. Section 7 assumes NFCU's agents are already enrolled, but the bootstrapping of that enrollment is the exact trust problem the construction defers. The on-chain verifier removes AS dependency at verification time but creates an enrollment-time dependency on Bolyra's operator. **Construction must address.**

**In-threat-model?** No. The threat model (§3) assumes honest enrollment — agents are already in the tree. It does not model adversarial tree operators, stale root history, or operational failure of the registry. For enterprise procurement, "solo founder controls the root of trust" fails every vendor risk assessment.


## Persona: cryptographer

*Stance: Unless I see a threat model, a game definition, and a reduction sketch, it's marketing. You provided all three — so let's stress-test the reductions.*

---

### Attack 1: Small-Domain Scope Extraction (Game 2 bound is wrong by 2^56)

- **Attack:** The ZK claim in Game 2 bounds `Pr[A wins] ≤ 1/2^64`, treating the scope as a uniform 64-bit secret. But §3.2 defines only 8 meaningful bits (READ_DATA through ACCESS_PII). The actual scope domain is at most 2^8 = 256 values. The agent Merkle tree is public on-chain state — its leaves are `credCommitment = Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)`. An auditor who can read the on-chain tree knows `rootCredCommitment` and `terminalCredCommitment` (both are Merkle leaves). Given `rootScopeCommitment = Poseidon2(rootScope, rootCredCommitment)` as a public signal, the auditor evaluates `Poseidon2(candidate, rootCredCommitment)` for each of the 256 candidate scope values and matches against the public commitment. Total cost: 256 Poseidon evaluations. Same attack applies to `terminalScopeCommitment`. The claim `1/2^64` relies on an implicit assumption that `rootScope` is drawn uniformly from a 64-bit space — an assumption the construction nowhere enforces and that reality refutes.

- **Why it works:** The reduction sketch for Games 2 & 3 (§4) says inverting `Poseidon2` contradicts A2. That's correct for a random input. But the adversary doesn't need to invert — they enumerate. The PRF argument (A5) holds only if the key is unknown; here the Merkle tree is public, so `rootCredCommitment` is the key and is known. The ZK proof hides the witness, but the public signal is a commitment over a tiny plaintext space.

- **In-threat-model?** No — the construction must revise the Game 2 bound to `1/256 + negl(λ)` (or prove that credential commitments are not publicly enumerable), then address whether that residual 1/256 leakage is acceptable. Alternatively, blinding `rootScopeCommitment` with a random salt that is also private (removing scope recoverability) would fix it, at the cost of making `rootScopeCommitment` non-deterministic and less auditable.

---

### Attack 2: Intermediate Enrollment Bypass (Soundness claim is incomplete)

- **Attack:** The construction claims "every participant enrolled in the agent Merkle tree." The circuit enforces, per hop h: `BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[h], proof[h]) = delegateeMerkleRoot[h]`. But `delegateeMerkleRoot[h]` for `h < chainLength − 1` is a **private witness** with no public constraint tying it to the on-chain registry. The on-chain auditor checks only `terminalMerkleRoot` (the single public output, §2 public outputs index 5) against the 30-entry root history buffer. A malicious prover can fabricate a Poseidon-consistent Merkle tree for any `delegateeCredCommitment[h]` at an intermediate hop, assign a fabricated `delegateeMerkleRoot[h]`, and the circuit is satisfied — the intermediate agent is not enrolled anywhere real. The EdDSA signature chain is still valid because the prover controls all intermediate keypairs. Only the terminal agent must be genuinely enrolled.

- **Why it works:** The soundness reduction (§4, Theorem for Game 1) extracts the witness and shows scope expansion would break A1 or A2. But that theorem says nothing about Merkle root consistency across hops. The circuit's Merkle check is self-referential per hop: it proves `credCommitment[h]` is a leaf of **some** tree with root `delegateeMerkleRoot[h]`, not the **on-chain** tree. The on-chain binding exists only for the terminal hop. This is a gap between the informal enrollment claim (§1) and what the circuit actually proves.

- **In-threat-model?** No — the construction must either (a) make all `delegateeMerkleRoot[h]` public outputs and require the auditor to verify each against on-chain root history, or (b) add an in-circuit constraint that all per-hop Merkle roots equal a single committed on-chain root (passed as a public input). Option (b) is cleaner and costs no additional public outputs.

---

### Attack 3: Underconstrained Selector Bits — Non-Binary `active[h]`

- **Attack:** The circuit description labels `active[h]` as type "bit" but the Circom constraint listing shows no `active[h] * (1 − active[h]) === 0` constraint. The contiguity check `active[h] >= active[h+1]` only makes semantic sense for binary values; in the field it is under-specified. The scope expansion check is: `active[h] * delegateeBits[i] * (1 − delegatorBits[i]) === 0`. If `active[h]` is an arbitrary field element (not in {0, 1}), a malicious prover can choose `active[h] = p − (delegateeBits[i] * (1 − delegatorBits[i]))^(−1)` such that the product is zero mod p, satisfying the constraint while the hop is logically "active" (contributing to `chainLength = sum(active[h])`) with an expanded scope. The chain-length accumulator and the terminal mux `newScopeCommitment[chainLength − 1]` depend on `active[h]` being binary; without the binarity constraint, `chainLength` is a malleable public signal.

- **Why it works / fails:** In Circom 2, signal types are informational only — the constraint system does not enforce `bit` type semantics. If the circuit template does include `active[h] * (1 − active[h]) === 0` and the description simply omitted it, the attack is blocked. But the omission from the spec is itself a specification gap: the formal security argument in §4 nowhere mentions or relies on binarity of selector bits. The reduction sketch for Game 1 extracts the witness assuming valid bit decompositions; it does not verify that `active[h]` is binary before applying the scope expansion argument.

- **In-threat-model?** Depends on the actual circuit. If the binary constraint is in the Circom source but not in the spec, the spec is incomplete. If it's absent from the circuit, this is a soundness break of the same class as the underconstrained Merkle depth attacks catalogued in the autoresearch experiments (`tier2_001_formal_verifier_underconstrained_merkle_depth_guard`). The spec must state, for each selector input: "constrained to {0, 1} via `active[h] * (1 − active[h]) === 0`."

---

### Attack 4: Deterministic Chain Fingerprinting Breaks Whistleblower Privacy

- **Attack:** The public signals `(rootScopeCommitment, terminalScopeCommitment, chainLength)` are fully deterministic for a fixed delegation chain — no per-session randomness enters them. The spec acknowledges this ("same chain always produces same digest per nonce") as a feature for integrity, but it is a privacy liability: any observer who sees two audit proofs with identical `(rootScopeCommitment, terminalScopeCommitment, chainLength)` tuple can link them as proofs of the same chain, across sessions, across auditors, across time. In the whistleblower scenario (§7), the journalist verifies a proof on-chain. The on-chain verifier event log is public. Any counterparty monitoring the chain can correlate the journalist's verification event with prior audit events by matching the deterministic triple, potentially identifying which chain (and thus which institution, leaking context) the journalist received, even without breaking ZK.

- **Why it works:** The ZK proof hides witnesses, but the *public signal fingerprint* is a stable identifier. Game 3 (Participant Deanon) asks only whether the adversary can identify "which enrolled agent occupies hop h" — it doesn't model an adversary who tracks which *chains* a verifier checks over time. The simulator for the ZK argument reproduces the public signals exactly, which is precisely why the attack works: the signals are supposed to be stable. The threat model in §3 lists a "curious auditor" but not a network-level observer correlating on-chain verification events across multiple proof submissions.

- **In-threat-model?** Partially. The construction must explicitly add a cross-session unlinkability game: *given two audit proofs π₁, π₂ for chains C₀ and C₁ (randomly assigned), the adversary cannot determine which proof corresponds to which chain with probability better than 1/2.* The current construction fails this game trivially by matching `rootScopeCommitment`. A fix is to include a blinding term in `rootScopeCommitment`: `Poseidon3(rootScope, rootCredCommitment, sessionRandomness)` where `sessionRandomness` is private and fresh per audit, at the cost of making the root anchor non-deterministic — which may conflict with the "same chain always produces same digest" integrity property. This is a fundamental tension the construction has not resolved.


## Persona: cu_ciso

---

### Attack 1: The Examiner Has a Hash. I Have a Questionnaire.

- **Attack:** Section 7 shows my NCUA examiner receiving `rootScopeCommitment = Poseidon2(0x87, credCommRoot)`. The construction claims this proves "chain started from an enrolled agent with some scope." But NCUA examiners don't query Solidity verifier contracts — they hand me a questionnaire that asks "Describe how you ensure third-party AI agents are limited to the minimum necessary access." I need to answer that question with a document, not a Base Sepolia transaction hash. Worse: the public signal `rootScopeCommitment` is an opaque Poseidon hash. The examiner cannot independently verify that `0x87` corresponds to my approved AI agent policy without the prover revealing the preimage — which the construction explicitly withholds. The proof is self-consistent but not *policy-anchored*. I cannot show an examiner "the root scope was READ_DATA + ACCESS_PII (bits 0,1,2,7)" without breaking the ZK. If I *do* reveal the root scope to the examiner for policy binding, I've partly deanonymized the chain, and the differential between what I disclose and what competitors disclose becomes its own regulatory negotiation.
- **Why it works / why it fails:** The construction addresses cryptographic soundness (§4) and provides a comparison table against RFC 8693 (§8). It does not address the semantic gap between "proof verifies" and "examiner can map proof to written policy." NCUA examiners operate on FFIEC CAT maturity domains and written procedures, not algebraic group model reductions. The deployment scenario in §7 describes what the examiner *learns* (`chainLength = 4`) but not how the examiner independently verifies that `rootScopeCommitment` corresponds to a board-approved AI governance policy.
- **In-threat-model?** No. The construction must address: (a) a policy-binding layer where the root scope is committed to a named, examiner-readable policy document in a way the CU can selectively disclose only the root scope claim, not intermediate hops, and (b) a non-cryptographer-facing audit summary artifact (PDF with signatures, not a Solidity call).

---

### Attack 2: Incident Response Deadlock Under NCUA Part 748

- **Attack:** A member complaint comes in at 2am: "I didn't authorize a $47 transfer." My Tier 1 ops team identifies that the USPS API Agent (hop 3 in §7) made an unauthorized financial call. I open an incident under NCUA Part 748 Appendix B. My SOC needs to answer: which hop escalated permissions, and when? The `chainIntegrityDigest` in public signal 4 is `Poseidon(nullifier[0], ..., nullifier[7])` — a single hash of hashes. It uniquely fingerprints the chain but tells me nothing about which hop misbehaved. The intermediate witnesses — `delegatorScope[h]`, `delegateeScope[h]`, `delegatorPubkeyAx[h]` — are all private inputs that exist only in the prover's memory at proof-generation time. If the prover (the AI pipeline orchestrator) is the attacker, or if the orchestrator logs weren't retained, those witnesses are gone. I cannot subpoena a ZK proof. I cannot forensically reconstruct which specific delegation token caused the `FINANCIAL_SMALL` bit to appear downstream without the prover's active cooperation in re-running the witness generation.
- **Why it works / why it fails:** The construction's Game 1 (§3) guarantees I can detect *that* a violation occurred ex-post — if someone generates a new audit proof with manipulated witnesses, soundness prevents a false proof. But it does not help me investigate *past* violations from an already-accepted chain. The `chainIntegrityDigest` is a replay-binding fingerprint, not a forensic log. Section 5 maps the construction to Bolyra primitives but does not map it to Part 748's incident response or record-retention requirements. The 30-entry root history buffer (§5, root history buffer row) helps check Merkle root validity but does not preserve intermediate witnesses.
- **In-threat-model?** No. The construction needs: either (a) a prover-retained witness log with CU-controlled encryption (the CU holds a key that can decrypt witnesses for regulatory subpoena, breaking ZK only to the CU itself, not the auditor), or (b) explicit language that the CU's logging policy must retain witness data outside the circuit, with a threat model acknowledging that forensic reconstruction requires out-of-band trust in the CU's own logs.

---

### Attack 3: Vendor Management Conflict for Cross-Org Hops

- **Attack:** Hop 2 in §7 is a "third-party, cross-org" Address Validation Microservice. The construction guarantees the examiner cannot learn this vendor's identity. But NCUA's Third-Party Vendor Management guidance (Letter to Credit Unions 07-CU-13) and GLBA Safeguards Rule §314.4(f) require me to: (1) inventory all third-party relationships that access member data, (2) conduct due diligence, (3) execute contracts with security provisions, and (4) monitor performance. I cannot execute a vendor contract with a `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)`. I cannot list an opaque Merkle leaf in my vendor inventory. The construction's privacy guarantee for intermediate nodes is structurally incompatible with my vendor management obligations. If I know who hop 2 is (I must, to sign a contract), then *I* know — but I cannot prove to the examiner that I've conducted due diligence on this anonymous-to-examiner node without revealing its identity. The construction treats the examiner's knowledge as the privacy threat, but my regulatory obligation runs *to* the examiner: I must demonstrate vendor oversight.
- **Why it works / why it fails:** The baseline comparison (§8) correctly notes that RFC 8693 exposes SPIFFE IDs to the examiner, which leaks vendor relationships. But the construction overcorrects: it hides intermediate participants from the examiner entirely, creating a regulatory blind spot. The §7 deployment scenario presents this as a feature ("the examiner learns nothing about vendor relationships") without acknowledging the TPRM conflict. FFIEC CAT Domain 3 (Cyber Risk Management) requires documented third-party oversight with evidence — a ZK proof that a third party exists but is anonymous does not satisfy this.
- **In-threat-model?** No. The construction needs a tiered disclosure model: the CU can generate a *CU-audit variant* of the proof that reveals hop identities (with their consent) for NCUA examination, while the *journalist/whistleblower variant* (§7) maintains full anonymity. Currently the construction treats all auditors identically. Regulatory auditors and journalists have opposite disclosure requirements.

---

### Attack 4: Operator Key Compromise Is Unrecoverable

- **Attack:** Each agent credential commitment is `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` signed by `opAx/opAy` (the operator EdDSA keypair). The circuit verifies `EdDSAPoseidonVerifier` at each hop (§2, gadgets table). If NFCU's operator private key is compromised — insider threat, KMS breach, supply chain attack on the key management tooling — an attacker can mint arbitrary agent credentials with any `permBitmask` and enroll them in the Merkle tree. A valid `DelegationAuditRollup` proof will verify cleanly against the on-chain verifier because the circuit checks signature validity, not key provenance. The root history buffer (30 entries, §5) stores past Merkle roots but does not flag which roots were generated with a compromised key. The construction has no operator key revocation mechanism. Post-compromise, NFCU cannot invalidate past proofs — the `chainIntegrityDigest` will still verify. GLBA Safeguards Rule §314.4(c)(3) requires "procedures for change management" and "disposal of customer information" — key compromise affecting all agent credentials is a material change event with no construction-defined remediation path.
- **Why it works / why it fails:** The threat model (§3) defines adversary A as controlling up to N-1 of N agents in the chain, and considers malicious delegators and curious auditors. It does not model a compromised *operator key* that is orthogonal to the delegation chain itself. The named assumptions (§4) include DLP hardness on Baby Jubjub (A3) but assume operator keys are honestly generated and held securely — that assumption is undefended operationally. The PLONK soundness guarantee prevents forging proofs without valid witnesses, but valid witnesses are trivially obtainable once the operator key is leaked.
- **In-threat-model?** No. The construction needs: (a) operator key revocation that propagates to on-chain state (e.g., the agent registry contract should support key rotation with epoch tagging, so proofs generated under a revoked key epoch fail `terminalMerkleRoot` validation), and (b) explicit key custody guidance mapping to GLBA §314.4 — specifically whether operator keys may reside in browser-accessible key stores (the cu_ciso's own attack prompt: "If it's a browser, you've lost me").


## Persona: rfc7662_advocate

### Attack 1: Pre-Signed JWT Audit Artifact — "Offline-Verifiable" Is a Straw Man

- **Attack:** Section 8 of the construction claims "Offline-verifiable without AS" as a ZK-only capability, contrasting against "auditor must query or trust AS." This is a false binary. Under draft-ietf-oauth-jwt-introspection-response, the AS can pre-sign a structured audit assertion at delegation issuance time:

  ```json
  {
    "iss": "https://as.nfcu.org",
    "chain_id": "<sha256-digest>",
    "chain_length": 4,
    "root_scope_tier": "FINANCIAL_PII",
    "terminal_scope_tier": "READ_ONLY",
    "narrowing_valid": true,
    "iat": 1718000000,
    "exp": 1718086400
  }
  ```

  This JWT is offline-verifiable by the NCUA examiner against the AS's WebPKI cert. The examiner needs no live AS query. The comparison table entry "No — auditor must query or trust AS" is factually wrong for the signed JWT introspection variant.

- **Why it works / why it fails against the construction:** It works as a rebuttal to the "offline-verifiable" framing. It fails to fully replicate the ZK construction because **the AS must learn all intermediate scopes at issuance time to produce this assertion** — the AS is still an omniscient trusted party. The ZK construction's real advantage is that *no party ever accumulates all intermediate scope values*, not merely that the AS is off the hot path at audit time. The construction's Section 8 table buries this: the true differentiator is "no trusted party learns intermediate state," not "AS not needed at audit time." The current phrasing conflates the two and a motivated RFC advocate will exploit the gap.

- **In-threat-model?** Yes — construction survives, but Section 8's comparison row must be rewritten. Claim should be "No party learns intermediate scopes to produce the audit artifact" not "AS not needed at audit time."

---

### Attack 2: Prover Capability Is Undefined — Whistleblower Cannot Generate the Proof Alone

- **Attack:** Section 7 Whistleblower Variant states: *"The source generates a DelegationAuditRollup proof showing that an AI agent was granted FINANCIAL_UNLIMITED permissions..."* The circuit requires all of the following **per hop** as private inputs: `delegationToken[h]`, `delegateeCredCommitment[h]`, `sigR8x/y/S[h]`, and `delegateeMerkleProofSiblings[h][MAX_DEPTH]`. In a standard delegation flow, hop h's delegation token is issued by delegator h to delegatee h. The terminal party (the source, at hop N) holds only their own token. They do not hold `sigR8x/y/S[0..N-2]` or the credential commitments of intermediate agents they never interacted with.

  Under RFC 8693, the `act` claim in the access token includes the full delegation chain in plaintext, so the terminal bearer can trivially prove the chain — it leaks participants but the terminal party possesses the proof material. In the ZK construction, the terminal party provably **cannot** generate `DelegationAuditRollup` without obtaining private inputs from every intermediate hop.

  The only party who can generate the proof without coordination is the **root delegator** (who initiated the chain) or the **AS** (in a hybrid deployment). Both contradict the whistleblower scenario where the source is an intermediate or terminal participant acting unilaterally.

- **Why it works / why it fails against the construction:** It works — the construction names the whistleblower as "a source inside a financial institution" without specifying what access they have. An intermediate agent at hop 2 of a 4-hop chain cannot prove the full chain. The construction fails to define the **prover role** and what chain material they must possess.

- **In-threat-model?** No — not addressed. Construction must add a proof-of-chain-possession protocol: either a cooperative multi-party witness generation protocol (each hop contributes their private inputs under MPC), or a restriction that the proof can only be generated by the chain initiator (root delegator), which collapses the whistleblower scenario to a very narrow "insider at the root" case.

---

### Attack 3: 1/2^64 ZK Bound Fails in Practice — Scope Cardinality Is Tiny

- **Attack:** Game 2 (Intermediate Scope Extraction) claims Pr[A wins] ≤ 1/2^64 "under ZK of PLONK and Poseidon PRF." This treats the 64-bit scope bitmask as drawn from a uniform distribution over F_2^64. It is not. The cumulative-bit encoding constraints (bits 4⟹3⟹2 enforced in-circuit, §2 Gadgets) combined with the fact that scopes are monotonically narrowing subsets of the root scope collapse the effective search space dramatically.

  Concretely: if `rootScopeCommitment` commits to bitmask `0x87` (the NFCU example in Section 7), the cumulative-bit-valid subsets of `0x87` obeying the implication constraints total at most **16–20 distinct values**. The auditor who infers the root scope (e.g., by guessing NFCU uses `READ | WRITE | FINANCIAL_SMALL | ACCESS_PII` from regulatory filings, or by brute-forcing against `rootScopeCommitment` with known `rootCredCommitment` candidates) can enumerate the full intermediate scope space in O(20) Poseidon evaluations.

  Compare: RFC 7662 with per-RS introspection policy + OIDC PPIDs. An RFC 7662 AS with per-RS introspection response can already filter the response to reveal only what each RS needs. The scope cardinality problem doesn't arise because the claims are explicitly bounded by the AS's policy at issuance.

- **Why it works / why it fails against the construction:** It works against the stated security bound. The 1/2^64 claim is asymptotically sound under the formal game (which assumes arbitrary 64-bit inputs) but is practically vacuous when the construction constrains the input domain to cumulative-bit-valid subsets of the root scope. An auditor who knows the root scope (which is implied by knowing the root agent's role) faces at most ~20 candidates, not 2^64.

- **In-threat-model?** No — the construction's Game 2 proof sketch does not account for the constraint-induced reduction in scope entropy. Must add: either (a) a revised practical security argument that bounds guessing advantage by the size of the cumulative-bit-valid subset lattice under the root scope, or (b) an additional blinding salt committed into `scopeCommitment = Poseidon3(scope, credCommitment, scopeSalt)` where `scopeSalt` is an independent random field element, which restores the 128-bit preimage resistance even when scope cardinality is small.

---

### Attack 4: Root Authority Is Unbound — The Circuit Proves Chain Consistency, Not Chain Legitimacy

- **Attack:** The circuit proves that the chain is **internally self-consistent**: each hop's scope is a subset of the previous, expiries narrow, every participant is enrolled in the agent Merkle tree, and EdDSA signatures are valid. What it does **not** prove is that the root agent had organizational authority to hold `rootScope` in the first place. `rootScopeCommitment = Poseidon2(rootScope, rootCredCommitment)` is a public signal with no on-chain anchor to a trusted issuer registry.

  An adversary can:
  1. Register 8 fresh agents in the Bolyra agent Merkle tree (permissionless).
  2. Assign `rootScope = 0xFF` (all permissions) to the root agent's self-signed credential.
  3. Generate a valid `DelegationAuditRollup` proof with `rootScopeCommitment = Poseidon2(0xFF, adversarialCredComm)`.
  4. Present this to an auditor claiming it is NFCU's delegation chain. The PLONK verifier accepts the proof.

  The examiner in Section 7 is told to check `terminalMerkleRoot` against on-chain root history. This verifies the **terminal** agent is enrolled. It does not verify that the **root** agent's scope was legitimately issued by NFCU's operator key, or that NFCU's operator key is itself registered with any authority that the examiner can independently verify.

  Compare: RFC 7662. The AS's `iss` claim is a URI with WebPKI backing. The examiner knows that `https://as.nfcu.org` is NFCU's registered AS because it appears in NFCU's `.well-known/openid-configuration` under a domain NFCU controls. The trust chain is externally anchored. In the ZK construction, trust in the root scope is entirely delegated to the Merkle tree deployer — who is the prover's own organization.

- **Why it works / why it fails against the construction:** The attack is valid at the deployment level. The circuit is sound (an adversary cannot forge a valid proof for a chain that violates narrowing), but soundness only covers **relative** claims ("terminal scope is a subset of root scope"). It does not cover **absolute** claims ("root scope was legitimately issued"). The construction must add a root credential binding step: either (a) an on-chain operator registry that maps operator pubkeys (opAx, opAy in the credential commitment) to verified organizational identities, and an in-circuit constraint that the root credential commitment's operator key hashes to a registered entry, or (b) explicit language in Section 3 and Section 7 that the auditor is responsible for verifying root authority out-of-band (and thus the construction does not claim end-to-end legitimacy, only chain-consistency).

- **In-threat-model?** No — the construction's Table (Section 8) implies that the PLONK proof is sufficient for a regulator to "cryptographically guarantee monotonic narrowing at every hop." This is true for narrowing relative to the root, but false for legitimacy of the root. Must add: an operator registry on-chain (extending the existing agent Merkle tree to include operator-to-authority mappings), and a public signal binding `rootCredCommitment` to a registry-verified operator entry.


## Persona: spiffe_engineer

---

### Attack 1: Intermediate Agent Enrollment Is Unconstrained

- **Attack:** The circuit computes `BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[h], proof[h]) = delegateeMerkleRoot[h]` for every hop, but `delegateeMerkleRoot[h]` for hops 0 through N-2 is a **private witness** — it is never constrained against any on-chain commitment. Only `terminalMerkleRoot` (public signal index 5) is checked against the on-chain root history buffer (§2, §5). A malicious prover can fabricate intermediate agents entirely: enroll fake EdDSA keys in a prover-controlled off-chain Merkle tree, satisfy the per-hop BinaryMerkleRoot gadget against that private root, and produce a valid proof where only the root and terminal agents are genuinely enrolled on-chain. The proof is accepted by the on-chain verifier. The "delegatee enrollment" property holds only for the last hop.

- **Why it works:** The construction's threat model (§3) defines the adversary as controlling "up to N-1 of N agents." If N=4 and the adversary controls agents at hops 1 and 2 (the intermediate positions), they can substitute unenrolled credentials at those positions. The chain-linking constraint (`prevCommitment[h] = newScopeCommitment[h-1]`) binds scope commitments across hops but the commitment is `Poseidon2(scope, credCommitment)` — the `credCommitment` inside it is a private field element whose Merkle membership is verified against a private root. Nothing in the public signals exposes the intermediate Merkle roots for auditor cross-checking.

- **In-threat-model?** No. The construction's own adversary model allows N-1 colluding participants but does not account for the prover substituting unenrolled fake credentials at intermediate positions while maintaining valid EdDSA signatures. For the NFCU scenario (§7), a malicious NFCU could claim a 4-hop chain that actually delegates through fabricated intermediaries, bypassing any requirement that those intermediaries be legitimate enrolled workloads. Fix required: all per-hop `delegateeMerkleRoot[h]` values must be public signals checked against the on-chain root history, or a separate accumulator commitment to all intermediate roots must be published.

---

### Attack 2: Cross-Org Trust Requires a Centralized Global Registry

- **Attack:** The NFCU deployment scenario (§7) chains NFCU agents through to a "USPS API Agent" — a cross-org, third-party workload. The circuit verifies each delegatee's `credCommitment` against *some* Merkle tree, but the construction says the auditor checks `terminalMerkleRoot` against "the agent Merkle tree" (§2, §5, §7 setup). Which tree? The USPS API Agent is not enrolled in NFCU's agent Merkle tree. In SPIFFE, cross-org identity is explicit: each trust domain publishes a trust bundle at a well-known endpoint, and federation is configured bidirectionally. SPIRE's Workload API issues SVIDs whose `spiffe://trust-domain/path` makes trust domain membership self-describing. The comparison table (§8) claims "Cross-org chain in single artifact: Yes — all hops (including cross-org) are rolled into one proof with one verification" but the construction never specifies how the cross-org delegatee's enrollment is anchored. If each org has its own on-chain Merkle tree, the intermediate hop from NFCU to USPS crosses trust domains — whose root does the circuit verify against? If there is a single global Bolyra Merkle tree, then all workloads across all organizations must register in a centralized on-chain registry, which is architecturally worse than SPIFFE federation.

- **Why it works:** The construction is silent on the trust domain decomposition. The gadget `BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[h], proof[h])` computes a root but doesn't specify which on-chain registry anchors it. For same-org chains this is implicit. For cross-org, the prover must supply the USPS agent's Merkle proof, but against which tree? If the answer is "a separate USPS on-chain Merkle tree," then the per-hop `delegateeMerkleRoot[h]` must be cross-referenced against USPS's on-chain root — requiring the auditor to know which root belongs to which trust domain, reintroducing the trusted-third-party coordination that the construction claims to eliminate. If the answer is "one global tree," the construction is a centralized identity registry dressed in ZK.

- **In-threat-model?** No. The construction treats cross-org as a capability it inherits for free from the circuit structure. It does not. The trust model for multi-org enrollment requires a specified federation protocol. WIMSE's draft-ietf-wimse-arch §4 handles exactly this by anchoring workload identity to a Workload Platform that issues credentials verifiable by any relying party; the construction would need an equivalent trust anchor per org with a specified root-exchange protocol before the "cross-org in a single proof" claim holds.

---

### Attack 3: `chainLength` as a Metadata Oracle Against the Whistleblower Scenario

- **Attack:** `chainLength` is public signal index 2. In the journalist/whistleblower scenario (§7, §1), the construction asserts: "The journalist can verify this proof on-chain without learning who the source is, which agents were involved, or which institution." But the auditor receives `chainLength` (e.g., 4), `terminalMerkleRoot` (a specific root), and `auditSessionNonce`. In practice, a financial institution running an AI pipeline with a 4-hop delegation chain to a specific terminal agent class produces a small anonymity set. If the adversary (regulator, counterparty, or surveillance actor with on-chain monitoring) can enumerate all (institution, pipeline-topology, chain-length) tuples consistent with a given `terminalMerkleRoot`, the chain length breaks pseudonymity. For the journalist variant: a source inside a 30-person financial institution team who generates a 3-hop chain fingerprints themselves to within a handful of candidates purely from the chain length and the terminal Merkle root appearing on-chain at a specific timestamp.

- **Why it works:** Game 3 (§3) defines the adversary's winning condition as correctly guessing which enrolled agent occupies hop h, with the claim `Pr[A wins] ≤ 1/|enrolled agents|` under PLONK ZK and Poseidon PRF. This bound assumes the adversary has no side-channel information beyond the proof and public signals. In the real protocol, `chainLength`, `terminalMerkleRoot`, on-chain submission timestamp, and the observed set of registered agents in the Merkle tree are all public. The PLONK ZK property guarantees computational indistinguishability of the proof transcript from a simulation — but simulation indistinguishability over the *proof* does not imply indistinguishability of the *public signals themselves* from background knowledge. `chainLength=N` is not zero-knowledge; it is disclosed. The proof system provides ZK only for the private *witness*, not for values explicitly output as public signals.

- **In-threat-model?** No, and it requires a claim revision. The construction must either (a) make `chainLength` private and replace it with a range-proof (`chainLength ∈ [1,8]`), (b) always prove with `MAX_HOPS=8` and use dummy padding for all unused hops so the public verifier never learns the actual length, or (c) explicitly carve the whistleblower scenario out of the anonymity claims and restrict it to adversaries with no background knowledge. SPIFFE does not claim to hide chain length; Bolyra claims this for the whistleblower use case and the public signal falsifies it.

---

### Attack 4: This Is a SPIFFE ZK Node Attestor Layered Wrong

- **Attack:** SPIFFE's trust model separates two concerns: *workload identity* (what is this process?) handled by node attestation + SVID issuance, and *authorization* (what is this process allowed to do?) handled upstream. The construction conflates the two: `credCommitment = Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` bakes permissions into the credential commitment. This means every permission change requires re-enrollment and a new commitment, invalidating prior Merkle paths. SPIFFE decouples these intentionally: SVIDs are short-lived (1h by default), rotated by SPIRE automatically, and authorization policy lives in OPA/Cedar/Envoy policy — separate from identity. The `DelegationAuditRollup` would need to be reproduced from scratch every time an agent's permission set changes. More fundamentally: if you want "prove scope narrowing without revealing scopes," the correct layering is a ZK-based *authorization* attestor that consumes SPIFFE SVIDs as identity anchors. WIMSE's token exchange (draft-ietf-wimse-workload-identity-bcp) handles the identity leg; a ZK proof of scope relationship could be composed on top without replacing the identity layer. The construction replaces the entire stack instead of extending it at the right boundary.

- **Why it works:** The construction's §8 table claims "WIMSE provides workload attestation but not scope arithmetic" — this is true today but WIMSE is a living draft. More importantly, "scope arithmetic" over hidden bitmasks is a one-function ZK gadget (`delegateeBits[i] * (1 - delegatorBits[i]) === 0`) that could be implemented as a WIMSE extension or as a ZK authorization token bound to an SVID via DPoP-style key binding. The construction has not demonstrated that the *identity* layer needs replacement, only that *authorization auditing* layer needs a ZK primitive. Bundling a new identity primitive (EdDSA enrollment, Merkle-based membership, credential commitments) alongside the authorization primitive forces all adopters to replace SPIFFE rather than augment it, dramatically raising the adoption barrier for the cross-org and WIMSE-aligned scenarios the construction targets.

- **In-threat-model?** No — this is an architectural objection, not a cryptographic break. The construction is sound as stated. But the claim in §8 ("The structural gap is irreducible") overstates the case. The irreducibility holds for *today's* BBS+ and RFC 8693. It does not hold for a SPIFFE ZK attestor that issues JWTSVIDs with a ZK-proven scope-subset binding. The honest rebuttal requires the construction to specify why the identity primitive must change, not just the authorization primitive — or to scope the claim to a world where SPIFFE is not the identity substrate.
