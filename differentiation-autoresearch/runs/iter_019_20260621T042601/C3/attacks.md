# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: Real-Time Agent Pipelines Cannot Absorb the Proving Tax

- **Attack:** Section 6 concedes "< 5 seconds PLONK / ~1.5s Groth16 with rapidsnark on commodity hardware" for a 4-hop chain. In the Navy Federal scenario (Section 7), hops 2 and 3 are a rate-lookup agent and a market-data agent — tool calls that modern orchestrators (LangChain, CrewAI, OpenAI function calling) complete in 100–500ms. Bolyra's proving step is 3–10x longer than the tool call itself. Worse, the proof must be generated *before* the next hop can proceed (chain-linking constraint requires the previous hop's delegateeCredCommitment), so these latencies are serial, not parallel. A 4-hop pipeline with PLONK could block the user for 20s — comparable to a full page load in 2012.

- **Why it works / why it fails:** The construction's Section 6 proving time targets are per-proof, not per-pipeline. There is no analysis of how proofs compose temporally in a streaming tool-call architecture. Auth0's token endpoint returns in <100ms; WorkOS session tokens are cached at the edge. The construction provides no latency budget for the typical orchestrator invocation pattern and no design for pre-generation or proof caching that would close the gap.

- **In-threat-model?** No. The construction defines security games but no latency SLO. An enterprise buyer evaluating agentic infra for production will reject a construction that adds multiple seconds to every delegation hop, regardless of cryptographic elegance. The gap to address: specify a proof-pipelining or pre-proving architecture (e.g., prove hop *i* while hop *i-1* executes), or bound the worst-case latency addition per hop to <200ms with a concrete caching design.

---

### Attack 2: The Regulator Won't Call `verifyProof()`

- **Attack:** Section 7 builds its entire enterprise scenario around an NCUA examiner who "calls `DelegationAuditVerifier.verifyProof(π, publicSignals)` on-chain or off-chain." Real NCUA IT examination procedures (FFIEC IT Examination Handbook, 2023 update) ask for audit logs, access-control matrices, and system documentation — not Solidity contract interactions. The examiner at Navy Federal will be using a spreadsheet and asking for a PDF export, not connecting MetaMask to Base Sepolia. The construction's "auditor" is a cryptographer; the buyer's auditor is a GRC analyst with a CISA certification.

- **Why it works / why it fails:** The Section 7 deployment scenario is detailed and technically sound, but it solves the wrong problem layer. Enterprise compliance buyers need artifacts their *existing* GRC tooling can ingest: SOC 2 reports, access logs in Splunk, exportable CSV for examination. The ZK proof is a cryptographic primitive, not a compliance artifact. Auth0's MCP auth ships with audit log integrations (Datadog, Splunk, AWS CloudTrail) out of the box. Bolyra's `auditDigest` is a hash — interpretable only if the examiner also reads the on-chain registry, understands Poseidon, and knows what `chainLength = 3` means relative to the expected policy.

- **In-threat-model?** No. Section 7 does not address how the ZK proof artifact integrates with existing enterprise compliance workflows. The gap to address: specify a proof-to-audit-log bridge that translates `(narrowingValid=1, chainLength=3, auditDigest=0x...)` into a human-readable compliance report with a standard schema (e.g., OSCAL, OpenC2), and describe how an organization attests to a regulator that the on-chain verifier contract is authoritative without requiring the regulator to call it directly.

---

### Attack 3: Who Runs the Prover, and What Happens When It's Down?

- **Attack:** Section 2 specifies that the prover holds all private inputs: `delegatorScope[i]`, `delegatorCredCommitment[i]`, `delegatorPubkeyAx/Ay[i]`, and the Merkle sibling hashes. In Auth0/WorkOS, the authorization server is the prover — it holds keys, issues tokens, and is the reliability surface for the SLA. In DelegationAuditChain, *each agent at each hop* must generate a ZK proof. That means every agent in the pipeline must have access to the `DelegationAuditChain` circuit artifacts (`pot16.ptau`, the proving key), the `rapidsnark_prover` binary, and enough compute to generate a ~55K-constraint proof under latency. The construction requires enterprise operators to ship a native binary prover alongside every agent container — in regulated environments (NFCU's internal infra, a fintech partner at hop 3), this means security review, patching, and dependency management for a C++ binary that is not owned by any vendor with a support contract.

- **Why it works / why it fails:** Section 5 maps to `circuits/build/rapidsnark_prover` but the construction never specifies a proving-as-a-service design or addresses the case where the prover is unavailable. Auth0's reliability is their core product — 99.99% uptime SLA, SOC 2 Type II. If Bolyra's prover infra is "each agent runs rapidsnark," then a prover crash means the delegation chain cannot proceed, silently or with a circuit-level error the orchestrator must handle. Section 7's scenario places hop 3 at a "third-party fintech" — this fintech must also run the prover. The construction provides no protocol for proving delegation failed without revealing why.

- **In-threat-model?** No. The construction's threat model (Section 3) models a cryptographic adversary but not an operational adversary (outage, misconfiguration, version mismatch between proving key and verifier contract). The gap to address: define the trust model for a delegated proving service (where the agent sends private inputs to a service that generates the proof), specify the key management requirements, and provide an availability SLO design that does not require every agent in the pipeline to run native proving infrastructure.

---

### Attack 4: The Privacy Claim Inverts the Enterprise Buyer's Actual Problem

- **Attack:** The core novelty in Section 1 is that "the auditor verifies monotonic narrowing *without learning any intermediate scope values*." Section 8's comparison table calls this the "fundamental gap" versus RFC 8693 + BBS+. But the enterprise buyer at NFCU does *not* want to hide scope bitmasks from NCUA. NFCU's internal policy team, its CISO, and its regulator all have a legitimate need to see what permissions were granted at each hop — that is what an audit is. The ZK construction is optimized for the journalist/source scenario (Section 7's second variant) where intermediate participants *must* stay hidden. But the primary scenario (NFCU loan processing) has no such requirement: NFCU *wants* its examiner to see that hop 1 stripped PII access (bit 7), because that is evidence of good governance, not sensitive competitive intelligence. The construction sells privacy to buyers who need transparency.

- **Why it works / why it fails:** Section 8 frames hiding intermediate scopes as universally desirable, noting "which encode internal authorization policy — competitive intelligence." This is true for some buyers (cross-org handoffs to a competitor's infra) but is the *exception* in regulated financial services. A credit union's examiner expects to reconstruct what happened. Auth0's audit log shows every scope decision in plaintext, and that is a *feature*, not a weakness. The ZK approach cannot produce a human-readable audit trail by design — the privacy guarantee and the transparency requirement are structurally opposed. WorkOS's MCP auth ships an audit log that shows exactly what scopes were granted, to whom, and when. That is what NFCU's BSA officer will ask for in an examination.

- **In-threat-model?** No. The construction's gap statement (in the candidate metadata) acknowledges the need to "broaden" beyond narrow niches, but the NFCU scenario is used to illustrate the broad case while actually exemplifying the narrow one. The gap to address: define a selective disclosure mode where the prover can choose, per verification request, whether to expose intermediate scopes (for internal audit) or hide them (for cross-org or whistleblower scenarios). Without a selective disclosure path, every deployment is forced into the privacy-maximizing mode even when the buyer needs the opposite.


## Persona: cryptographer

*All citations reference the construction's own section headers and constraint numbering.*

---

### Attack 1: Phantom Merkle Enrollment — Agent Registry Root Is Never Bound

**Attack:**
The adversary constructs an arbitrary Merkle tree of their own choosing, places any credential commitment they wish as a leaf, computes a valid inclusion proof, and satisfies constraint 7 with it. They then prove a delegation chain that includes a completely unenrolled (or revoked) agent.

Constraint 7 reads:

```
let root_i = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[i], merkleProof[i])
// root_i is consumed internally, not output — auditor never sees it
```

The constraint verifies internal Merkle consistency — the proof path hashes to `root_i` — but `root_i` is **never constrained to equal any public value**. There is no circuit constraint of the form `root_i === agentRegistryRoot`, and `agentRegistryRoot` does not appear in the public inputs table (§2, Public inputs). The BinaryMerkleRoot gadget is thus a consistency check over a self-chosen tree, not a membership proof against the live agent registry.

**Why it works against the construction:**
By knowledge soundness (A1), a valid proof implies the prover knows a Merkle path for `delegateeCredCommitment[i]` relative to *some* root — but that root is never anchored. Without a public-input root, the enrollment claim is vacuous: any 20-level Merkle tree with `delegateeCredCommitment[i]` as a leaf satisfies the constraint. A malicious prover can enroll phantom agents, revoked agents, or agent identities they fabricated wholesale.

**In-threat-model?** **No.** The construction's §1 claim states "every delegatee is an enrolled agent." That claim requires `root_i === agentRegistryRoot` as a circuit constraint with `agentRegistryRoot` as a public input anchored on-chain. The current construction lacks this constraint entirely. Game 4 (Chain Integrity) is violated: the adversary produces a valid proof with an unauthorized hop that was not enrolled in the live registry, without breaking A2 or A4 — they only need a self-consistent Merkle path.

**Remediation required:** Add `agentMerkleRoot` to the public inputs table and add per-hop constraint `hopActive[i] * (root_i - agentMerkleRoot) === 0`.

---

### Attack 2: Chain Truncation — Prover Suppresses Trailing Hops

**Attack:**
The actual pipeline is A → B → C → D (4 hops). The prover submits a witness with `hopActive = [1, 1, 0, 0]`, declaring only hops 0 and 1 active. The contiguous-prefix constraint (§2, constraint 0) is satisfied. The auditor receives `chainLength = 2` and `finalScopeCommitment` matching hop 1's output. Hops 2 and 3 are invisible to the auditor.

This is not a scope-expansion attack within the presented chain — the 2-hop chain may have narrowed correctly. The attack is **scope-hiding for intermediate-to-final delegation**: agent C (at hop 2) may have been granted permissions the auditor was meant to see narrowed, and agent D (at hop 3) may be operating with a separately-obtained credential that is wider than what C's presented scope suggests. The truncated proof certifies *a* valid 2-hop prefix, not *the* full chain.

**Why it works against the construction:**
The prover alone decides which `hopActive` bits to set. Nothing in the construction binds `chainLength` to an externally observable count of issued delegation tokens. The on-chain registry (§5, "Replay prevention") records the `auditDigest` to prevent replaying the same proof, but there is no mechanism that prevents a different proof over a shorter prefix of the same chain from being submitted. An auditor who requests a "chain audit" cannot distinguish between a genuine 2-hop chain and a 4-hop chain whose prover elected to expose only 2 hops.

**In-threat-model?** **No.** The adversary (per §3) controls N-1 of N participants, which includes the final agent in the chain, who is also the proof generator. The threat model does not specify that chain length is bound to any external commitment. Game 4 is violated for a subtler reason than §4 Theorem 4 addresses: the integrity failure is not "splicing in an unauthorized hop" but "omitting authorized hops that the auditor has a right to see." The NFCU scenario (§7) is particularly vulnerable: the cross-org hop 3 with the third-party fintech could be suppressed, and the examiner would believe the pipeline stopped at hop 2.

**Remediation required:** Bind `chainLength` (or an upper bound on it) to an on-chain commitment emitted at delegation-token issuance time. Alternatively, the chain-seed on-chain record should embed the claimed total hop count, and the circuit should verify `chainLength === expectedLength` against a public input.

---

### Attack 3: `currentTimestamp` Is a Vestigial Public Input — Expired Credentials Verify

**Attack:**
The adversary constructs a delegation chain using credentials whose expiry timestamps are all in the past (e.g., `delegateeExpiry[i]` values from 2 years ago). The circuit outputs `narrowingValid = 1`. The `currentTimestamp` public input is accepted by the verifier contract but never used in any circuit constraint to check that credentials have not expired at proof time.

Scanning all per-hop constraints in §2:
- Constraint 5 enforces `delegateeExpiry[i] ≤ delegatorExpiry[i]` — relative narrowing.
- No constraint in the listed gadgets or constraint logic enforces `currentTimestamp ≤ delegateeExpiry[i]` or `delegatorExpiry[i] ≤ currentTimestamp` in any direction.
- The `currentTimestamp` appears in the public inputs table but in no constraint pseudocode.

**Why it works against the construction:**
Knowledge soundness (A1) extracts a witness satisfying all stated constraints. A witness with expired credentials satisfies all stated constraints because none of them reference `currentTimestamp`. The circuit is therefore a "narrowing proof" over values that may have never been valid at proof time, not at execution time, not at audit time.

**In-threat-model?** **No.** The construction's §1 claim is that the auditor verifies the chain "narrowed permissions monotonically — every hop's scope is a bitwise subset of its predecessor's, every hop's expiry is no later." The reasonable reading is that these credentials were valid during the delegation. An adversary who re-animates a decommissioned, revoked agent pipeline (all credentials expired, agents removed from registry if this attack is combined with Attack 1) can produce a proof that passes verification and satisfies an NCUA examiner. The `currentTimestamp` public input signals that the circuit *intended* to use wall-clock time but never wired it into a constraint.

**Remediation required:** Add per-hop constraints `hopActive[i] * LessEqThan(64)(currentTimestamp, delegateeExpiry[i]) === 1` (i.e., `currentTimestamp ≤ delegateeExpiry[i]`). This requires `currentTimestamp` to be fresh — which in turn requires the proof not to be reused across time windows, already partially addressed by `sessionNonce` binding, but the nonce binding on expiry must be explicit.

---

### Attack 4: Scope Brute-Force via Small Effective Permission Keyspace

**Attack:**
Theorem 3 (§4) reduces Game 3 (scope privacy) to Poseidon preimage resistance with the following argument: recovering `delegateeScope[last]` from `finalScopeCommitment = Poseidon2(delegateeScope[last], delegateeCredCommitment[last])` requires inverting Poseidon2. The reduction assumes that `delegateeScope[last]` is drawn from a large search space. It is not.

The permission bitmask is defined as a 64-bit value, but the cumulative bit encoding (§2, constraint 4 and §, Permissions Model) restricts the valid space:
- Bits 2,3,4 must satisfy: bit4 → bit3 → bit2.
- Valid patterns for (bit2, bit3, bit4): `{(0,0,0),(1,0,0),(1,1,0),(1,1,1)}` = 4 options.
- Bits 0,1,5,6,7 are free: 2⁵ = 32 options.
- **Total valid scope values: 4 × 32 = 128.**

If the adversary can obtain `delegateeCredCommitment[last]` from any other context — the same agent's credential appears in a different proof transcript, the operator publishes their credential commitment for interoperability, or the agent's credential is visible in the AgentPolicy handshake proof from the same session — the adversary performs 128 Poseidon2 evaluations to recover `delegateeScope[last]` with certainty.

The `sessionNonce` binds the proof to a session but does not appear inside `finalScopeCommitment`. Consequently, if the adversary correlates the credential commitment across sessions (which is stable per agent, since it hashes over `(modelHash, opPubAx, opPubAy, permBitmask, expiry)` — static values), they de-anonymize every scope commitment that agent ever appeared in.

**Why it works against the construction:**
Theorem 3's reduction is stated as: "Recovering `delegateeScope[last]` requires inverting Poseidon2, contradicting collision resistance." This is only valid when the second argument to Poseidon2 (`delegateeCredCommitment[last]`) is computationally hidden. The reduction is silent on this precondition. In the ROM, Poseidon2 evaluated on a known 2-tuple with one unknown argument over a 128-element search space is not a preimage problem — it is a 128-query offline search.

More formally: Game 3 should be reduced to the security of a **commitment scheme** where `delegateeCredCommitment[last]` acts as the randomness (hiding parameter). But `delegateeCredCommitment[last]` is deterministic (no randomness injected beyond the inputs), and those inputs include stable values like `opPubAx, opPubAy` that may be published for signature verification elsewhere in the protocol. The hiding property fails against an adversary with cross-context access.

**In-threat-model?** **Partially.** The adversary (§3) observes "all proof transcripts." The AgentPolicy handshake proof and the DelegationAuditChain proof share the same `delegateeCredCommitment` for the agent at the terminal hop. An adversary who captures both transcripts — trivial if both proofs are submitted on-chain — obtains `delegateeCredCommitment[last]` from the AgentPolicy transcript and inverts `finalScopeCommitment` with 128 oracle queries. The construction's Game 3 should be stated as conditional on `delegateeCredCommitment` remaining hidden, or the scope commitment should incorporate fresh randomness independent of the credential commitment.

**Remediation required:** Either (a) add a uniformly random blinding factor `r ←$ F` to `finalScopeCommitment = Poseidon3(delegateeScope[last], delegateeCredCommitment[last], r)` with `r` as a private input, or (b) formally bound the scope search space in the Game 3 statement and require the reduction to account for it, citing concrete security rather than asymptotic negligibility.


## Persona: cu_ciso

### Attack 1: NCUA Examiner Cannot Operate the Audit Artifact

- **Attack:** Section 7 states the examiner "calls `DelegationAuditVerifier.verifyProof(π, publicSignals)` on-chain or off-chain." NCUA examiners do not run Solidity contracts. They arrive with questionnaires, request policies, pull logs from your SIEM, and ask your compliance officer to walk them through controls. The artifact produced — a PLONK proof π, a Poseidon hash digest, and `narrowingValid = 1` — is cryptographically rigorous and operationally meaningless to a regulator. Under FFIEC CAT Domain 3 (Cyber Risk Management), the control must be *understood and evaluated* by the examiner, not merely *trusted* as a black box. The construction maps to no NCUA Part 748 control number and produces no human-readable audit log. The examiner will not accept "the math says it's fine" as a substitute for a documented access control review with named authorizing parties.

- **Why it works / why it fails against the construction:** The construction's Section 7 deployment scenario describes the examiner receiving `chainLength = 3` and `narrowingValid = 1` but deliberately withholds all intermediate scopes and identities. That is the whole security claim. But it is also precisely what an examiner requires: who authorized what, when, with what scope, and who approved it. The construction offers no examiner-facing translation layer — no policy document, no human-readable access log, no named approver per hop. The proof is self-verifying against on-chain state, but the examiner has no framework for evaluating on-chain state as evidence.

- **In-threat-model?** No. The construction's threat model (Section 3) defines adversaries as cryptographic entities: colluding chain participants, auditor query attacks, network observers. The NCUA examiner — a human who needs a paper trail under Part 748 §748.0(c) — is not modeled at all. The construction must address what artifact it produces for a human regulatory reviewer, separate from the cryptographic proof.

---

### Attack 2: Incident Response Destruction — Part 748 Appendix B Conflict

- **Attack:** An NFCU member reports fraudulent loan modifications. The CISO opens an incident under NCUA Part 748 Appendix B, which requires identifying the scope of unauthorized access to member data and notifying affected members. The Tier 1 ops team needs to answer: did the credit-scoring agent (hop 1) access PII? Did the rate-lookup agent (hop 2) write any data it wasn't authorized to write? The construction answers this question with `narrowingValid = 1` and a Poseidon hash. The intermediate scopes — 0b10000111, 0b00000101, 0b00000001 from Section 7 — are private inputs. They are not logged, not recoverable, and explicitly hidden. The construction correctly notes this as a privacy feature. It is simultaneously a Part 748 incident response failure.

- **Why it works / why it fails against the construction:** Section 7 explicitly confirms that what the examiner does *not* receive includes "any intermediate scope bitmask." During breach forensics, the CU must reconstruct which agents had PII access (`ACCESS_PII`, bit 7) to meet the 72-hour notification clock. If the pipeline ran with hidden intermediate scopes and the prover (the agent pipeline) is no longer available or has rotated keys, there is no mechanism to recover the intermediate scope values. The `auditDigest` proves integrity of the chain but reveals nothing about what data was accessible at each hop. The GLBA Safeguards Rule (16 CFR §314.4(h)) requires incident response to include identification of affected information — which this construction structurally cannot provide post-hoc.

- **In-threat-model?** No. The threat model assumes the auditor is an adversary trying to learn private data. It does not model the CU's own incident response team as a legitimate party needing partial disclosure under regulatory compulsion. The construction needs a privileged disclosure path — perhaps a selective-reveal mechanism for the CU's compliance officer that does not expose data to the public auditor — that is currently absent.

---

### Attack 3: Vendor Identity Concealment Violates Part 748 Appendix A Third-Party Oversight

- **Attack:** Section 7, hop 3 crosses to "a third-party fintech" market data provider, and the construction explicitly guarantees: "The identity of the third-party fintech at hop 3 is [not received by the examiner]." Under NCUA Part 748 Appendix A and the NCUA's Third-Party Relationships guidance (Letter 07-CU-13), the CU must maintain a vendor inventory, conduct due diligence (SOC 2, financials, incident history), and have a written contract with every entity that touches member data or financial operations. The construction makes it cryptographically impossible for the CISO's vendor management program to identify and vet the entity at hop 3 — because participant identity is a private input with zero-knowledge guarantees.

- **Why it works / why it fails against the construction:** The journalist/source anonymity use case (Section 7 variant) is a feature. The cross-org fintech case is a regulatory violation. The construction treats these identically at the circuit level, but they have opposite compliance requirements. A CU cannot route loan-processing data through an anonymous agent and call it a controlled third-party relationship. The vendor management policy requires a named entity, a signed BAA (if PHI-adjacent), and a risk tier assessment. None of these are possible if the delegatee's identity is cryptographically hidden from the operator. The security argument in Section 4 reduces participant privacy to zero-knowledge of the proving system — which is exactly the property that breaks vendor oversight.

- **In-threat-model?** No. The threat model defines the adversary as an auditor trying to extract private data. It does not model the CU's own compliance team as a party that legitimately *must* know the third-party's identity. The construction needs a two-track design: operator-visible participant registry (for vendor management) that is provably separate from auditor-visible proof outputs.

---

### Attack 4: Operator Key Custody Silence Under GLBA Safeguards Rule §314.4(c)

- **Attack:** The construction requires each delegating agent to hold an EdDSA private key (`delegatorPubkeyAx[i]`, `delegatorPubkeyAy[i]`, `sigR8x[i]`, `sigR8y[i]`, `sigS[i]` per hop). These keys sign delegation tokens that authorize downstream financial operations. The construction is entirely silent on where these keys live, how they are generated, who has access to them, whether they are rotated, and what happens on compromise. Under GLBA Safeguards Rule 16 CFR §314.4(c), covered financial institutions must implement access controls including encryption key management. Under FFIEC Information Security Booklet (IS), key management requires documented custodianship, split knowledge or dual control for high-value keys, and audit trails for key usage. If operator keys live in a cloud-hosted AI inference environment (the realistic deployment), they are exposed to the operator's cloud provider, the model hosting service, and any compromised CI/CD pipeline that deployed the agent.

- **Why it works / why it fails against the construction:** Section 4 assumes EdDSA unforgeability (A4) and reduces it to discrete log hardness on Baby Jubjub. This is sound cryptography. It says nothing about whether the private key is in an HSM, a .env file, or a Kubernetes secret mounted as an environment variable in a shared tenant cluster. The construction's security proof holds if the key is uncompromised; the CISO's exam risk is entirely about what happens when it is. There is no key revocation mechanism described: if an agent's operator key is compromised at hop 2, every delegation token ever signed by that key remains valid unless the agent's credential commitment is removed from the Merkle tree — and the construction does not describe how the on-chain registry handles emergency revocation with sub-second propagation to prevent in-flight fraudulent proofs.

- **In-threat-model?** No. The threat model explicitly excludes key compromise ("The adversary does NOT control... the CRS/SRS"). Operational key lifecycle — generation, storage, rotation, revocation, compromise response — is unaddressed. For a CISO, a cryptographic construction with no key management story is not a security control; it is an unquantified risk on a balance sheet.


## Persona: rfc7662_advocate

---

### Attack 1: Signed JWT Introspection Response Achieves "Auditor Sees Only a Boolean" Without Any Circuit

- **Attack:** Section 8's comparison table claims the baseline "Requires disclosing scope values to auditor." This is false for a properly configured stack. `draft-ietf-oauth-jwt-introspection-response` allows the AS to issue a *signed, offline-verifiable* JWT introspection response whose content is filtered *per requesting RS*. Configure the AS to return, for the auditor RS: `{ "active": true, "scope_narrowed": true, "chain_length": 3, "final_scope_commitment": "<SHA-256 of terminal scope>" }` — no plaintext scopes, no participant identities. The AS signs this with its JWKS key; the auditor verifies offline without querying the AS again. RFC 9728 PRM lets the auditor RS publish *which claims it accepts*, so the AS knows to strip plaintext scopes before responding. The auditor gets exactly what the ZK circuit outputs: a narrowing boolean, a chain length, and a scope commitment hash.

- **Why it works / why it fails:** The construction's §8 fundamental-gap paragraph claims "No composition of RFC 8693, BBS+, and WIMSE can produce a proof of an arithmetic relationship over values simultaneously hidden from the verifier." Technically true — the AS *doesn't prove* the relationship; it *attests* to it. But the construction never argues why cryptographic proof is necessary rather than trusted attestation. In every regulated deployment scenario in §7 (NCUA, editorial board), the AS is itself subject to regulatory audit and legal obligations. The NCUA examiner scenario specifically relies on confidentiality requirements that apply equally to AS logs. The construction's "mathematical proof vs. trusted assertion" framing is a distinction without a practical difference for these scenarios.

- **In threat model?** **Partially.** The attack fails in the journalist/source scenario where the AS *is* the adversary (the editorial board controls the AS and wants to identify the source). It holds everywhere the AS is not in the adversary model — which is the majority of the §7 NFCU scenario. The construction must sharpen its claim to: "ZK is load-bearing only when the AS itself is untrusted." As written, §8 overstates the baseline gap for the regulatory compliance use case.

---

### Attack 2: `finalScopeCommitment` Is a Stable Session-Correlation Oracle

- **Attack:** `finalScopeCommitment = Poseidon2(delegateeScope[last], delegateeCredCommitment[last])` is a *deterministic function of the terminal agent's static deployment parameters*. Since `delegateeCredCommitment[last] = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` does not include any session-varying entropy, and since a deployed agent (say, the market-data fintech at hop 3) has a fixed `modelHash`, `opPubAx`, `opPubAy`, `permBitmask`, and a slowly-rotating `expiry`, `finalScopeCommitment` is constant across every delegation audit proof where that agent appears as the terminal delegatee with the same authorized scope. An adversary observing on-chain audit digests accumulates a set `{π₁, π₂, …, πₙ}` all sharing identical `finalScopeCommitment`. From this, the adversary learns: (a) a single agent endpoint was used as the terminal delegatee in all N sessions; (b) temporal correlation of those sessions; (c) approximate usage volume. Game 2 in §3 is defined over a *single proof* — the distinguishing experiment asks whether the auditor can tell C₀ from C₁ given one π. Game 2 is silent on multi-proof correlation, which is the operative threat in a live deployment.

- **Why it works / why it fails:** The construction has no session-blinding mechanism at the `finalScopeCommitment` output. Compare: `sessionNonce` is correctly threaded into `auditDigest` via `Poseidon2(token, sessionNonce)`, making `auditDigest` session-unique. But `finalScopeCommitment` omits `sessionNonce`. Fix would be `Poseidon3(delegateeScope[last], delegateeCredCommitment[last], sessionNonce)` — but this changes the public output semantics (the on-chain registry would need to store per-session commitments rather than a stable terminal-agent handle).

- **In threat model?** **Yes — construction must address.** This is a genuine privacy regression relative to RFC 8693 with OIDC PPIDs, where pairwise subject identifiers are *defined* to prevent exactly this cross-session accumulation at the RS level. The construction claims stronger participant privacy than the baseline in §8, but the stable `finalScopeCommitment` creates a persistent pseudonym for the terminal agent that the baseline PPID mechanism was specifically designed to prevent.

---

### Attack 3: `chainSeedScopeCommitment` Is a Backward-Linking Oracle to the Handshake Session

- **Attack:** The construction requires `chainSeedScopeCommitment` as a *public input*, described in §5 as "`lastScopeCommitment[sessionNonce]` from on-chain registry." This value is published on-chain at handshake time. Any observer with read access to the on-chain handshake registry can enumerate all delegation audit proofs containing that `chainSeedScopeCommitment` and immediately map them back to the originating handshake session. If the handshake session is correlated to a member identity through timing, IP metadata, or the human Merkle root (which is also a public output of the handshake), then every audit proof in the chain is backward-linked to that member. The construction's §3 Participant Privacy game (Game 2) asks whether an auditor can distinguish intermediate participants. It does not address whether the *initial delegator* — the human member whose handshake seeded the chain — is identifiable via the chain seed.

- **Why it works / why it fails:** RFC 8693 with OIDC PPIDs issues *pairwise subject identifiers* per (subject, RS) pair. The human member's identity is transformed before it appears in the delegation chain; there is no stable handle linking the delegation chain back to the member across contexts. The construction's chain-integrity requirement — anchoring `chainSeedScopeCommitment` to an on-chain handshake — is structurally at odds with this property. The construction cannot simultaneously provide (a) cryptographic proof that the chain started from a legitimate handshake (requiring on-chain linkage) and (b) unlinkability between the audit proof and the handshake session. The construction acknowledges the `sessionNonce` prevents replay (§5), but does not address that the `chainSeedScopeCommitment` itself is the correlation handle.

- **In threat model?** **Yes — construction must address.** The NFCU scenario requires that the examiner not learn "which member's session spawned this pipeline." But `chainSeedScopeCommitment` is public and on-chain, linking the audit directly to a specific member session. Either the chain seed must be randomized per-audit-proof (breaking the integrity linkage) or the construction must introduce a nullifier-style one-way transform on the chain seed before it appears as a public input.

---

### Attack 4: DPoP Sender-Constraint + Blind Issuance Can Replace `BinaryMerkleRoot` Enrollment Without a Circuit

- **Attack:** The construction's §8 "Replay prevention without identity exposure" column says DPoP's "key thumbprint is visible." But this understates DPoP's composition surface. RFC 9449 DPoP + a blind-issuance step can produce a sender-constrained token where the RS receives only `{ "jkt": H(BLIND_KEY) }` — a *salted pseudonymous thumbprint* issued by the AS after verifying the real key at registration time. The AS binds the real identity to the blind key at issuance; subsequent presentations to auditors use only the blind thumbprint. This produces: sender-constraint without exposing the real key, replay prevention (each DPoP proof binds a fresh `jti` nonce), and an auditor-visible receipt that is pseudonymous. This directly addresses the two properties the construction claims `BinaryMerkleRoot(20)` uniquely provides: (1) proving the delegatee is enrolled without revealing which enrolled agent, and (2) replay detection without identity exposure.

- **Why it works / why it fails:** The attack relies on the AS performing blind issuance correctly and not logging the mapping — reintroducing AS trust. In the journalist/source model of §7, this fails: the AS knows the mapping. More importantly, the construction's in-circuit Merkle proof provides something the DPoP + blind-issuance approach cannot: the Merkle root is *public and verifiable on-chain* without any AS involvement. The DPoP blind thumbprint requires trusting the AS's blind issuance log. However, the construction does not explicitly name this distinction in §8 — it only says "key thumbprint is visible," which is rebutted by blind DPoP. The construction should state clearly: "Merkle enrollment proves delegatee membership in a *publicly auditable, AS-free* set; blind DPoP proves only that *the AS certified* membership at issuance time."

- **In threat model?** **Partially.** The attack succeeds in showing the §8 DPoP comparison is incomplete. The construction must specify that the baseline alternative requires AS certification of enrollment rather than a self-verifying Merkle proof — and that this distinction is only load-bearing when the AS is untrusted or unavailable. For the NFCU regulatory scenario where NFCU operates the AS, blind DPoP achieves the same auditor-facing property. For the journalist scenario, it does not.


## Persona: spiffe_engineer

---

### Attack 1: The "Global Merkle Tree" Is a Shared Trust Anchor in Disguise

**Attack:**
Section 8's comparison table claims the construction provides "cross-org without shared trust anchor." I run SPIFFE federation for six trust domains across three continents — I know what a trust anchor looks like, and the global agent Merkle tree is one. Whoever operates the enrollment authority that issues `credentialCommitment` leaves into that tree *is* the centralized root of trust. The construction doesn't specify who controls tree membership, under what policy, or how revocation works. It just buries the centralization behind a Poseidon hash.

SPIFFE federation is explicit about this: each org runs its own SPIRE server, manages its own SVID issuance, and expresses inter-domain trust via signed trust bundles with a defined lifecycle. The federation graph is auditable and decentralized by design. The construction's tree has one root — compromising the enrollment authority compromises every proof ever generated (retroactively, since old proofs cited the same root). There is no equivalent of SPIFFE's per-domain attestation policy, SVID rotation, or bundle refresh cycle.

The cross-org hop 3 in Section 7 (third-party fintech) is described as "just another enrolled agent." Enrolled *by whom*? Under *what* policy? Against *what* root? The answer is: the same global tree managed by whoever controls Bolyra's on-chain registry. That's a single point of organizational and operational failure the construction does not account for.

**Why it works / why it fails against the construction:**
The construction's ZK properties are sound — a compromised enrollment authority cannot forge a proof that uses a faked Merkle membership without breaking Poseidon collision resistance. But the *organizational* trust model is unaddressed. The soundness argument assumes the Merkle root is correct; it says nothing about *who guarantees that*. For NCUA compliance (the Section 7 deployment scenario), the examiner must also audit the enrollment authority's policies — and those are entirely outside the threat model in Section 3.

**In-threat-model?** No. The threat model in Section 3 assumes the Merkle root is honestly maintained. The construction must address: enrollment authority governance, revocation with historical validity, and how cross-org enrollment works without reintroducing a centralized gatekeeper.

---

### Attack 2: Credential Portability — No Workload Attestation Binding

**Attack:**
SPIFFE's core insight is that identity must be *bound to the workload execution environment*, not just to a key pair. SPIRE agents perform node attestation via TPM measurements, k8s pod identity, AWS instance metadata, or IMDSv2 tokens — the SVID is only issued if the attestor can prove *where* the workload is running. The credential's binding to environment is first-class.

The construction's `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` contains `modelHash` — a hash of the model binary — but nothing that proves the model is running in a specific environment, was loaded by an authorized runtime, or has not been exfiltrated. A credential commitment is a tuple of field elements. If an adversary extracts `opPrivKey` from a compromised agent runtime, they can generate valid EdDSA signatures (constraint 6) and produce valid proofs for any BinaryMerkleRoot membership. The proof is then valid — `narrowingValid = 1`, `auditDigest` checks out — but the actual agent that executed actions was the adversary's process, not the enrolled agent.

WIMSE's draft-ietf-wimse-arch Section 4.2 explicitly calls out workload attestation as a precondition for workload identity claims. The construction's Section 2 says nothing about how the operator private key (`opPrivKey`) is protected or how the credential commitment was issued. Is it stored in a hardware enclave? In a config file? On disk next to the model weights?

**Why it works / why it fails against the construction:**
The construction's narrowing soundness (Theorem 1) is perfectly valid under its assumptions — if the witness is honestly generated, the proof is sound. But soundness is a statement about the *proof system*, not about *key custody*. The construction has no attestation layer below the EdDSA key. A valid credential in the wrong hands generates valid proofs. The ZK construction proves "a valid key signed this" not "an authorized workload signed this."

**In-threat-model?** No. Section 3 ("The adversary does NOT control: the CRS/SRS") addresses setup assumptions but not key custody or workload attestation. The construction must either (a) specify a key management scheme (HSM, TEE) that bounds the private key to an execution environment, or (b) acknowledge that its security guarantee is "the chain narrowed *if* all credential holders are honest about their execution context" — which is a weaker claim than SPIFFE's attestation-backed identity.

---

### Attack 3: The §8 BBS+ Dismissal Is Incomplete — Decomposed Claim Encoding

**Attack:**
Section 8's comparison table states: "BBS+ hides individual claims but cannot prove ordering/containment relationships over hidden bitmasks." This is true if scope is a single opaque claim. But the dismissal is too fast — it forecloses a construction that I, as a WIMSE contributor, would propose: encode each permission bit as a separate BBS+ claim. Eight boolean claims per credential. Then selective disclosure proves "delegatee holds claims ⊆ delegator's claims" by the delegatee presenting only the claims it holds, and the verifier confirming those claims are a subset of the delegator's credential's claim set.

Concretely: delegator holds a BBS+ credential with claims `{READ_DATA: 1, WRITE_DATA: 1, FINANCIAL_SMALL: 1, ACCESS_PII: 1}`. Delegatee receives a derived credential with `{READ_DATA: 1, FINANCIAL_SMALL: 1}`. The auditor sees a BBS+ proof of knowledge that the delegatee's claims are a strict subset of a delegator credential signed by an authorized AS — without seeing the specific bit values, only the structural relationship.

The construction's counter in §8 is: "BBS+ operates within a single credential, not across a multi-issuer chain." This is the actual gap — cross-hop, cross-issuer containment proofs. But the construction doesn't model this precisely. BBS+ with a chained-issuer model (where each hop's AS signs a derived credential) can in principle produce cross-issuer proofs if the AS chain is structured correctly — it just requires the AS to be online and in the loop, which reintroduces the AS trust assumption.

**Why it works / why it fails against the construction:**
The construction's argument is directionally correct but underspecified. The failure mode of BBS+ is *not* "cannot prove containment" in general — it's "cannot prove containment across independently-issued credentials without an AS that sees all scopes." The construction should strengthen §8 to: (a) precisely identify the constraint that BBS+ + selective disclosure cannot satisfy, and (b) show that no AS-mediated composition achieves the cross-issuer, auditor-blind narrowing property in a single artifact. The current dismissal would not survive peer review in a WIMSE working group session.

**In-threat-model?** Partially. The construction addresses the BBS+ comparison (§8) but the argument is insufficiently specific. The construction survives the attack if it can produce a concrete impossibility argument, not just "BBS+ is single-credential." This is a presentation weakness that a standards body would require the authors to close.

---

### Attack 4: `narrowingValid = 1` Is Forensically Useless — The NCUA Attribution Gap

**Attack:**
I'll take the Section 7 NCUA deployment scenario at face value. The NCUA examiner receives `chainLength = 3`, `narrowingValid = 1`, and `finalScopeCommitment`. The construction frames this as a compliance win: "the examiner verifies that no agent exceeded its mandate."

Here is what happens after a breach. A member's loan data is exfiltrated. The examiner opens an investigation. They need to know: *which agent at which hop exfiltrated data, under whose operational control, and what specific permissions that agent held at the time of the incident.* The construction gives them none of this. Every intermediate participant is cryptographically hidden. `chainLength = 3` tells you there were three hops. `narrowingValid = 1` tells you each hop narrowed. The audit digest checks against the on-chain registry to confirm the chain ran and wasn't replayed. But there is no hook from any of these outputs to an attributable legal entity, system, or operator.

NCUA examination — 12 CFR Part 748, Appendix B — requires credit unions to maintain records that can identify the parties involved in automated decision-making affecting member accounts. The SPIFFE approach — even with privacy-degrading WIMSE act-chains — produces SPIFFE IDs (`spiffe://nfcu.org/agent/credit-scoring-v2`) that are revocable, attributable to a specific service account, and logged in an audit trail. The construction's auditor cannot initiate an enforcement action from `auditDigest` alone. They need to trace `auditDigest` back to the on-chain registry entry, which traces back to the proof, which traces back to... nothing attributable, by design.

The journalist/source scenario in Section 7 intentionally trades attribution for anonymity — that is the *point*. But the NCUA scenario in the same section makes the opposite claim: that this construction satisfies regulatory audit requirements. These two scenarios have fundamentally opposed requirements, and the construction cannot simultaneously satisfy both with the same public output set.

**Why it works / why it fails against the construction:**
`narrowingValid = 1` proves a mathematical property of the delegation chain. It does not produce an audit artifact that satisfies regulatory attribution requirements for financial institutions. The Section 7 NCUA scenario overclaims — the examiner gets a proof of *structure* but not a proof of *identity*. For the journalist scenario, this is a feature. For NCUA compliance, this is a defect. The construction must separate these two use cases and either (a) define a mode that exposes selective identity to a designated auditor (breaking participant privacy for compliance deployments), or (b) retract the NCUA compliance claim and scope the construction to contexts where structural proof without attribution is sufficient.

**In-threat-model?** No. Game 2 (Participant Privacy) is listed as a *security property* throughout, and Theorem 2 proves it holds. But the same property that the construction defends as a feature is what makes it inapplicable to the NCUA scenario. The construction's threat model does not include a "regulatory attribution" requirement that conflicts with Game 2 — and it should, because the concrete deployment scenario in Section 7 asserts exactly that conflict without resolving it.
