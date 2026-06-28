# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0\_pm

---

### Attack 1: The Witness Assembly Problem — Who Holds the Private Keys to the Audit?

- **Attack:** §2 Verification Flow Step 2 states: "The chain participant (or any relay) generates the `DelegationAuditRollup` PLONK proof with all intermediate state as private witness." In the NFCU scenario (§7), the pipeline spans four organizations: NFCU, Chainalysis, and Circle. Each hop's `delegateeScope[i]` and `delegateeCredCommitment[i]` are private witness inputs. This means whoever generates the audit proof must have all four hops' private data simultaneously. In practice: Circle will not hand its internal credential commitment to NFCU. Chainalysis will not share its scope commitment with a neutral relay. The proof cannot be generated unless all participants coordinate witness sharing — which requires a new, trust-sensitive coordination protocol that doesn't exist anywhere in the construction.

  Auth0 MCP auth solves this trivially: the Authorization Server is the single source of truth. It issued every token, it logged every delegation event, it produces the audit trail atomically and unilaterally. No cross-org coordination required.

- **Why it works:** The construction names this as a private witness computation but never specifies the coordination protocol by which multi-org witnesses are assembled. The threat model (§3) explicitly says the adversary controls "up to MAX\_HOPS - 1 intermediate agents," but the operational reality is that intermediate agents are *also the witnesses* — and they have legal and competitive reasons to withhold data. The construction is cryptographically sound once you have the witness. It provides no mechanism to actually get the witness.

- **In-threat-model?** No. The construction's threat model scopes adversaries to forgery and deanonymization attacks. Witness-assembly coordination failure is outside the threat model entirely, but it's the first question any enterprise operator will ask.

---

### Attack 2: Proof Latency Is the Wrong Metric — Per-Hop Real-Time Proofs Are the Problem

- **Attack:** The construction focuses on the audit rollup proof (< 5s, §6). But §7 states the pipeline already requires "three delegation hops execute, each producing a per-hop Delegation proof (already in Bolyra spec)" during the actual transaction. The audit rollup is post-hoc — but the per-hop Delegation proofs are synchronous with the AI pipeline execution. The existing Bolyra `Delegation` circuit is Groth16 or PLONK. PLONK on this constraint count runs 2–5s on commodity hardware (§6 explicitly states "< 5 seconds" as the *target*). A member initiating a stablecoin transfer via an AI assistant sits through up to 15–20 seconds of proving across 3 delegation hops before the transaction executes.

  WorkOS MCP auth issues delegation tokens in < 100ms round-trip. Auth0 is < 150ms. Stytch Connected Apps: sub-200ms. The construction's §8 never engages with this gap because it compares the audit artifact size and fidelity — not the latency of the operational pipeline that produces it.

- **Why it works:** The NFCU scenario is a user-facing payment flow. No credit union will deploy a member-facing stablecoin product where the AI pipeline introduces a 10–20 second latency per hop waiting for ZK proofs. The "rapidsnark < 0.7s" number in §6 is the proving time with the native binary, on hardware that must be provisioned per agent. The Chainalysis AML agent and Circle settlement agent (§7) both run on infrastructure controlled by third parties — neither will provision or operate a rapidsnark binary on Bolyra's behalf.

- **In-threat-model?** No. The construction's scope is audit correctness, not pipeline latency. But the buyer's decision is made on pipeline latency, not audit correctness. A construction that is cryptographically superior but operationally 100x slower than the incumbent will lose the account.

---

### Attack 3: The Blockchain Dependency Breaks the Enterprise Procurement Story

- **Attack:** The entire completeness guarantee — the construction's most novel claim (§2 execution log, §4 Theorem Audit Completeness, §7 NFCU audit requirement #3) — depends on `delegationLogDigest` being stored in the Bolyra on-chain registry. This means: (a) NFCU must deploy or trust a Bolyra registry contract on Base Sepolia (or mainnet), (b) every delegation hop requires an on-chain `SSTORE` plus a Poseidon2 computation (~30,000 gas per hop, §6), (c) all four agents in the pipeline must be Ethereum transaction signers capable of calling `verifyDelegation`, and (d) the on-chain state must be available at audit time — which requires a live RPC endpoint to Base.

  Auth0, WorkOS, Cloudflare Access, and Stytch produce audit logs in S3-compatible object storage or write to a SIEM. The NCUA examiner's IT security team will not accept "logs are on Base Sepolia" as an audit trail format. Their SIEM integration is Splunk or Datadog. Their logging compliance is governed by FFIEC IT Examination Handbook guidance. The construction provides no off-chain fallback path for `executionLogDigest` — if the chain reorg'd, if Base is congested, if the contract has a bug, the completeness guarantee evaporates.

- **Why it works:** The construction argues (§8) that an AS-maintained audit log requires "the auditor must *read* those responses to verify completeness — each response contains the scope, participant identity, and timestamp." That's true. But the NCUA examiner reading a Splunk query over Auth0 audit logs is a solved, certified, familiar workflow. Asking the NCUA examiner to verify a PLONK proof against an on-chain Poseidon hash chain is a new, uncertified, unfamiliar workflow — and the construction provides no guidance on how examiners are supposed to actually run PLONK verification. "Verify the single PLONK proof on-chain or off-chain" (§2 verification flow step 3) is not a NCUA exam procedure.

- **In-threat-model?** No. The construction's threat model assumes the on-chain registry's write path is trusted and available. Infrastructure availability and examiner tooling compatibility are outside scope. They are inside scope for every enterprise procurement conversation.

---

### Attack 4: The NCUA Scenario Proves the Wrong Thing — Regulators Already Know Your Vendors

- **Attack:** §7's motivating privacy claim is: "NFCU does not want the examiner to learn that Chainalysis is their AML provider, or that Circle handles settlement." This is the buyer-level justification for the entire journalist/source variant and the intermediate-participant hiding guarantee. It is almost certainly false in practice. NFCU files vendor management disclosures under FFIEC guidance. Third-party vendor relationships with Chainalysis and Circle appear in the vendor risk management program that NCUA examiners review *before* the AI pipeline audit. The construction is solving a privacy problem the examiner doesn't have — or more precisely, one that NFCU is legally required to disclose through other channels.

  The actual problem NCUA cares about: "Did the AI agent have authority to execute this transfer, and can you show me the audit trail?" Auth0 MCP audit logs, RFC 7662 introspection responses, and a signed JWT answer this in a format examiners already accept. The construction's §8 table correctly identifies the cryptographic limitations of the baseline — but misidentifies the buyer's actual purchase criterion. The buyer is not asking "can you prove monotonic narrowing over hidden bitmasks in a single constant-size artifact?" The buyer is asking "can you pass my next NCUA exam and integrate with Splunk?"

- **Why it works:** The gap-to-close in the candidate (C3) says "currently too narrow — must broaden." The construction tries to broaden by adding journalist/source and healthcare scenarios. But all three broadening scenarios (NFCU, journalist, healthcare) depend on the same assumption: that intermediate participants must stay hidden from the auditor. In regulated industries, intermediate participants are disclosed through other required channels. In the journalist/whistleblower scenario, the auditor is chosen by the journalist and is not adversarial — the threat model for that scenario is "hide from a government subpoena," not "pass a regulatory exam." The single construction trying to serve both scenarios creates a proof obligation the construction doesn't meet: it never argues that its hiding guarantees hold against a subpoena that can compel witness disclosure from intermediate agents.

- **In-threat-model?** No — and this is the most damaging attack. The construction's threat model (§3) defines adversary capabilities in terms of forgery and proof manipulation. The actual enterprise adversary is a procurement committee asking "why do I need ZKP to pass my NCUA exam when my Auth0 audit logs already satisfy the examiner?" There is no circuit constraint that answers this question.


## Persona: cryptographer

*Stance: Unless I see a closed threat model that accounts for the actual trust surface, the security claims are aspirational. Let's find the gaps.*

---

### Attack 1: PLONK Universal SRS — Subverted Setup Is Outside the Threat Model

**Attack:**
The adversary retains toxic waste from the `pot16.ptau` Powers of Tau ceremony (or bribes / coerces a ceremony participant). With the trapdoor `τ`, the adversary can compute any polynomial evaluation and fabricate a valid PLONK proof for an unsatisfying witness — e.g., a delegation chain where some hop `i` has `delegateeScope[i] ⊄ delegatorScope[i]`, yet the `DelegationAuditRollup` proof verifies.

**Why it works / why it fails:**
The reduction sketch in §4 cites "KS-PLONK" as an unconditional assumption: "For any valid proof, there exists an extractor…" But knowledge soundness of PLONK is conditional on the SRS being honestly generated. The `pot16.ptau` artifact was produced by a specific ceremony; if a single participant is malicious, the toxic waste is compromised and KS-PLONK fails catastrophically. The construction does not model this at all. The game definition in §3 lists what the adversary "does NOT control" — the PLONK proving system appears implicitly in that list — but the SRS trust surface is never named, parameterized, or bounded.

The universal composability framework provides the right language here: one would need to argue security in the `F_CRS` model (common reference string functionality), where the honest setup is a separate ideal functionality. The construction skips this entirely.

For contrast, Groth16 is equally vulnerable to per-circuit setup subversion — but PLONK's selling point in §2 is "no per-circuit ceremony." This is true, but it does not eliminate the ceremony trust; it just relocates it to `pot16.ptau`. The threat model should either (a) reduce to an assumption about the `pot16.ptau` ceremony, (b) argue security under subverted SRS using the techniques of Abdolmaleki et al. (subversion-zero-knowledge), or (c) commit to a transparency or updatable SRS model.

**In-threat-model?** No. The construction must address this. At minimum: state the SRS trust assumption explicitly, cite the ceremony transcript, and note whether Base Sepolia deployments use a chain-specific ceremony or inherit `pot16.ptau`.

---

### Attack 2: HVZK ≠ SE-ZK — The Adaptive Auditor Multi-Query Attack

**Attack:**
The game in §3 treats deanonymization (win condition 5) as a single-shot event: the adversary gets one proof and tries to extract intermediate data. But a real auditor can issue *multiple* audit requests against the same underlying delegation chain, varying public inputs adaptively. Concretely:

1. Fix a chain with intermediate scope `delegateeScope[1] = 0b00000101` (bits 0 and 2).
2. Auditor queries with `auditPolicyMask = 0b00000001`: proof accepts → terminal scope includes bit 0.
3. Auditor queries with `auditPolicyMask = 0b00000010`: proof rejects → terminal scope excludes bit 1.
4. After 8 rounds (one per bit), the auditor recovers the terminal scope exactly.

That's just the terminal scope — it's a public output, so this is fine. But now extend: the auditor varies `minExpiry` to probe the terminal expiry with binary search. That is also a public output. **But here is the real gap:** the auditor, by observing that a proof with certain `auditPolicyMask` passes or fails, learns that the terminal scope *satisfies or does not satisfy* the mask — and since monotonic narrowing holds, each terminal-scope bit was present at every prior hop. Multi-query probing over the *same* `rootScopeCommitment` with structurally correlated intermediate witnesses can leak intermediate scope structure via the terminal scope oracle.

More formally: the privacy proof in §4 invokes "ZK-PLONK" and asserts "there exists a simulator S that produces proofs indistinguishable from real proofs given only the public signals." Standard PLONK achieves honest-verifier zero-knowledge (HVZK) in the ROM: the simulator works for a fixed, non-adaptive verifier strategy. Multi-use privacy under an adaptive auditor who chooses public inputs as a function of prior proof outputs requires **simulation-extractable ZK (SE-ZK)** — a strictly stronger property. SE-ZK ensures that even an adversary who sees polynomially many simulated proofs cannot distinguish a real proof from a simulated one. The construction cites neither the Groth-Maller-Sahai SE-ZK result for PLONK nor any equivalent.

**Why it matters here specifically:** The execution log digest `executionLogDigest` is deterministic from the on-chain state — it is the *same* across all audit queries for the same session. The intermediate witness is reused. An auditor issuing `n` audit queries for the same session with different `(auditPolicyMask, minExpiry, sessionNonce)` triples is exactly the adaptive multi-query setting that HVZK does not cover.

**In-threat-model?** No. The deanonymization game (win condition 5) must be stated as a multi-query game. The privacy reduction must either establish SE-ZK for the PLONK variant used, or argue why the single-shot privacy game is sufficient given the structure of the public inputs.

---

### Attack 3: L2 Sequencer Transaction Ordering Attack

**Attack:**
On Base (the deployment chain per `CLAUDE.md`), the sequencer (operated by Coinbase) controls the ordering of transactions within a block. The `delegationLogDigest[nonce]` accumulator is updated by sequential `verifyDelegation` calls, one per hop. The update rule is order-dependent:

```
logAcc_{k+1} = Poseidon2(logAcc_k, scopeComm_k)
```

Poseidon2 is not commutative. If hop 1 (`sc_1`) and hop 2 (`sc_2`) arrive in the same block, the sequencer can order them as `sc_2, sc_1` instead of `sc_1, sc_2`. This produces:

```
executionLogDigest_adversarial = Poseidon2(Poseidon2(Poseidon2(0, sc_0), sc_2), sc_1)
  ≠ Poseidon2(Poseidon2(Poseidon2(0, sc_0), sc_1), sc_2)  [= executionLogDigest_honest]
```

The prover now generates a `DelegationAuditRollup` proof with the *reordered* witness (swapping hops 1 and 2 in the private inputs) and constrains `logAcc[chainLength]` against `executionLogDigest_adversarial`. The proof verifies — the circuit enforces narrowing at each hop and log completeness against the on-chain digest, but it cannot enforce that the on-chain log was written in the semantically correct pipeline order.

The auditor sees a valid proof certifying "monotonic narrowing held at every hop and all hops are accounted for," but the hop at index 1 in the proof corresponds to what actually ran at index 2 in the pipeline. If hop 2 was a privileged agent that should have run *after* a compliance check at hop 1, the reordering may violate the policy intent while the proof certifies it as valid.

**Why the construction doesn't close this:** §3 states the adversary does NOT control "the on-chain registry's write path (delegation log updates are executed by the registry contract atomically with each `verifyDelegation` call; the adversary cannot forge, skip, or reorder log entries without controlling the contract itself)." This is true within a single transaction — the contract update is atomic. But it says nothing about *inter-transaction ordering*. On a centralized-sequencer L2, the sequencer can reorder `verifyDelegation` transactions without controlling the contract. The threat model conflates single-transaction atomicity with cross-transaction ordering safety.

**In-threat-model?** No. The construction deploys on Base Sepolia and targets Base mainnet (per `contracts/` Hardhat config). An honest sequencer is an unstated trust assumption. The threat model must either (a) add the sequencer as a potential adversary and argue security with ordering-independent accumulators (e.g., a multiset hash instead of a sequential Poseidon chain), or (b) explicitly list "sequencer is honest" as a trust assumption and note the implications for L2 deployment.

---

### Attack 4: Journalist Variant — On-Chain Initial Log Digest Leaks the Handshake Root

**Attack:**
The journalist/source variant claims the `rootScopeCommitment` is hidden behind a Merkle membership proof over `K` recent handshake roots. The auditor learns only the Merkle root of the handshake set, not which specific handshake initiated the chain. The construction argues: "recovering `rootScopeCommitment` from the digest requires inverting Poseidon."

This argument fails because it reasons about the *final* `executionLogDigest` — but the *initial* value of `delegationLogDigest[nonce]` is written to the blockchain at handshake time:

```
delegationLogDigest[nonce] = Poseidon2(0, rootScopeCommitment)   // hop 0 seed
```

This initial value is a permanent, publicly readable Ethereum/Base state entry, accessible via `eth_getStorageAt` at the block where the handshake was confirmed. It is NOT the same as `executionLogDigest` (which is the final value after all hops); it is the intermediate value before any hops.

An adversary who knows the set of `K` candidate roots (the journalist variant assumes `K` is small — "a small Merkle tree of recent handshake roots") computes `Poseidon2(0, root_j)` for each `j` in `[1, K]` and compares against the on-chain initial `delegationLogDigest[nonce]`. This identifies `rootScopeCommitment` in `O(K)` time, breaking the journalist variant's anonymity claim entirely.

The construction does not describe any mechanism to hide the initial log digest. The Merkle wrapper hides `rootScopeCommitment` from the proof's public inputs, but does nothing about the on-chain storage slot that directly encodes `Poseidon2(0, rootScopeCommitment)`.

**Concretely:** A journalist using this construction with `K = 50` recent handshake roots as the anonymity set has zero anonymity against any adversary who reads the initial `delegationLogDigest` storage slot. The privacy set is not `K`; it is 1.

**Fix required:** The initial log accumulator seed must not be derivable from `rootScopeCommitment` in a way that is readable on-chain. Options: (a) initialize the accumulator with a blinded commitment `Poseidon2(rootScopeCommitment, randomNonce)` where `randomNonce` is off-chain and private; (b) defer writing the `delegationLogDigest` until after the first actual delegation hop (so the initial state is `Poseidon2(someBlinding, sc_0)` rather than `Poseidon2(0, rootScopeCommitment)`); (c) use a zero-knowledge initial-state proof rather than storing `rootScopeCommitment` directly.

**In-threat-model?** No. The journalist/source variant's anonymity claim is stated as a theorem ("the auditor learns 'a valid chain existed' without learning which handshake initiated it") but the on-chain storage layout directly contradicts it for any adversary who reads chain state.


## Persona: cu_ciso

### Attack 1: The Examiner Can't Read a PLONK Proof — This Isn't an Audit Trail

- **Attack:** The construction claims the NCUA examiner "verifies the single PLONK proof" and "learns" that monotonic narrowing held (§7, Verification flow step 4). But a PLONK proof is an opaque byte blob. The public outputs are `chainLength` (an integer), `terminalScopeCommitment` (a BN128 field element), and `auditDigest` (another field element). My examiner from NCUA Region 3 is handing me an examination questionnaire that maps to **NCUA Part 748.A(1)(iv)** ("review and test to monitor and control risks") and **FFIEC CAT Domain 2 (Threat Intelligence)**. None of those map to "run `snarkjs verify` and observe that it returns `true`." The construction never specifies: what human-readable attestation does the verifier produce? Who signs it? What format is it in? How does it appear in my audit binder? "The auditor verifies the proof" is not a control — it's a step that requires tooling, training, and a signing authority that none of my examiners have.

- **Why it works / why it fails:** The construction is technically sound but stops at the cryptographic layer. It assumes the audit outcome (`proof verified = true`) is self-evidently meaningful to a regulatory audience. It isn't. The gap is the mapping from `proofVerified: true + chainLength: 4 + auditDigest: 0x3f7a...` to "NFCU demonstrated that agent delegation controls were in place for transaction session #X on date Y, reviewed by examiner Z." The construction has no attestation layer — no signature, no human-readable report format, no integration with my GRC platform (Archer, ServiceNow GRC, OneTrust). This is not in-threat-model for the cryptographic construction but is the primary reason I, as CISO, cannot use it.

- **In-threat-model?** No — the construction must address the attestation and report layer. A ZK proof is evidence. Evidence without a chain of custody, a signing authority, and a format my examiner recognizes does not survive an NCUA examination. Map `auditDigest` to a signed, timestamped attestation in a format (JSON-LD, PDF-A, XML) that appears in my audit binder. Name the signing authority.

---

### Attack 2: The Witness Custodian Is an Unexamined Third-Party Vendor

- **Attack:** §7 states that "any participant (or a designated auditor relay) generates a `DelegationAuditRollup` PLONK proof with all four hops' scope/credential data as **private witness**." To generate the proof, whoever acts as prover must hold `delegatorScope[i]`, `delegateeScope[i]`, `delegatorCredCommitment[i]`, and `delegateeExpiry[i]` for **all** hops — including the Chainalysis AML scope and the Circle settlement scope (§7, hop table). The construction's privacy guarantee to the auditor is achieved by concentrating all sensitive operational data in a single prover entity. Under **NCUA Part 748.B(2)** and my Vendor Management Policy, any entity that receives, stores, or processes member-adjacent operational data must be in my third-party risk inventory, undergo due diligence, and appear on my Board-reported vendor list. The "designated auditor relay" is a new concentrated risk point that the construction does not name, scope, or bound.

- **Why it works / why it fails:** The construction proves that the auditor doesn't learn intermediate scopes. It does not address who the prover is or what trust we place in them. If the prover is NFCU itself, then NFCU is collecting all intermediate agent credentials from Chainalysis and Circle — which means NFCU has a new data flow from those vendors that must be governed. If the prover is a third-party relay, that relay sees everything before it hashes it into a private witness. The privacy guarantee holds cryptographically, but operationally the relay is a plaintext escrow for the entire delegation chain. A compromise of the relay reveals all intermediate scopes to an adversary before the proof is even generated. This is not addressed anywhere in the threat model (§3), which only considers the adversary *as an auditor*, not as a compromised prover.

- **In-threat-model?** No — the construction must specify: (a) who is authorized to act as prover, (b) what data the prover must hold and for how long, (c) how the prover is governed under the credit union's vendor management framework, and (d) what happens if the prover is compromised. The current threat model explicitly grants the adversary "all public signals" but does not model a compromised prover. For a CU deployment, this is the most likely real-world attack surface.

---

### Attack 3: The Privacy Feature Directly Violates My Third-Party Oversight Obligation

- **Attack:** The NFCU deployment scenario (§7) explicitly states the audit goal is that "NFCU does not want the examiner to learn that **Chainalysis is their AML provider**, or that **Circle handles settlement**." This is framed as a privacy benefit. From my chair, this is a regulatory violation. Under **NCUA Part 748.A(6)** and **GLBA Safeguards Rule 16 CFR §314.4(f)**, I am required to oversee service provider arrangements and ensure they implement appropriate safeguards. My NCUA examiner has explicit authority to review my service provider list and assess third-party risk. Preventing the examiner from learning that Chainalysis and Circle are in the payment pipeline does not protect competitive sensitivity — it obstructs a supervisory examination. The AML screening function (Chainalysis) is directly relevant to **BSA/AML compliance**, which is a separate examination axis. Hiding the AML provider identity from an NCUA examiner is not a feature; it is a finding.

- **Why it works / why it fails:** The construction is solving for the wrong adversary in the regulatory context. The examiner is not an adversary to be blinded — they are a supervisory authority with legal right-to-examine. The ZK proof can legitimately hide *scope values* (the actual permission bitmasks, the credential commitments), but hiding *participant identity* from the examiner conflates data minimization (a privacy principle) with obstruction (a supervisory violation). The §7 scenario treats examiner disclosure of vendor identity as a threat. It is not a threat I can defend against — I am required to disclose it. The construction needs to separate "hide scope values from examiner" (defensible) from "hide participant identities from examiner" (indefensible in a regulatory audit).

- **In-threat-model?** No — the construction must carve the journalist/source privacy model cleanly away from the regulatory audit model. In the regulatory deployment, participant identities (vendor names, agent operator pubkeys) must be disclosable to the examiner as a separate, examiner-only disclosure channel, while scope values remain private. A single construction that hides both conflates two different threat models and makes the product unusable for the regulatory use case as described.

---

### Attack 4: Forensic Dead-End After a Detected Violation

- **Attack:** The construction's soundness guarantee is that a valid proof implies monotonic narrowing held. The contrapositive: if monotonic narrowing was violated at some hop, the proof fails verification. My examiner or internal audit team observes: proof verification fails for session nonce `0xabc...`. Now what? All intermediate `delegatorScope[i]`, `delegateeScope[i]`, and `credentialCommitment[i]` are private witness — by design, they are not available to the auditor. I have a failed proof and I cannot determine **which hop violated narrowing**, **which agent was the violator**, or **what scope they claimed**. Under **NCUA Part 748.A(3)(iii)** ("respond to security events"), my incident response plan requires root cause analysis and evidence preservation. Under **FFIEC CAT Domain 4 (External Dependency Management)**, I need to identify which third-party was responsible for the control failure. A ZK proof that tells me "something went wrong somewhere in a 4-hop chain" with no further information is forensically useless. The construction's privacy guarantees make post-incident investigation impossible for the defender, not just for the adversary.

- **Why it works / why it fails:** The construction assumes the primary use case is confirming compliance, not investigating failures. In practice, audit tooling must serve both paths. The on-chain `executionLogDigest` proves completeness of the log, but the log itself (per the construction) stores only Poseidon hash commitments of scope — not the scopes themselves. Even if I have the raw `delegationLogDigest` values from the chain, I cannot invert Poseidon to recover which agent did what. The construction gives me a tamper-evident audit log that I cannot read in the event I need to read it. This is the privacy/forensics inversion: the system is maximally private to the defender during incident response.

- **In-threat-model?** No — the construction must specify a break-glass forensic path. Options include: (a) an encrypted side-channel where the prover escrows plaintext scope data under a court-order key held by a regulated custodian, (b) a designated examiner key that can request a selective-disclosure proof revealing only the violating hop's scope (not all hops), or (c) an explicit acknowledgment that the product is compliance-attestation only, not forensic infrastructure, with a companion forensic logging product in scope. Without this, I cannot sign a contract with a vendor whose incident response story is "the proof failed, good luck."


## Persona: rfc7662_advocate

---

### Attack 1: AS-Signed Hash-Chain Commitment Achieves the Same Completeness Guarantee

**Attack:** The construction's §8 completeness argument rests on this claim: *"The baseline cannot prove 'the audit covers all logged events' without disclosing the events themselves."* This is false. A well-configured AS operating under draft-ietf-oauth-jwt-introspection-response can maintain its own append-only SHA-256 (or Poseidon) hash-chain over `H(scope_i || credId_i)` for each delegation hop — structurally identical to the construction's `executionLogDigest`. The AS then issues a *single signed JWT introspection response* whose body contains exactly:

```json
{
  "active": true,
  "chain_length": 4,
  "log_digest": "<hex>",
  "policy_satisfied": true,
  "terminal_scope_commitment": "<hex>"
}
```

No intermediate scopes are disclosed. The auditor verifies the AS's signature (already a legal requirement for NCUA-regulated institutions — see 12 CFR Part 748). The *log_digest* field plays the same role as the construction's `executionLogDigest` public input: a commitment to all hops without revealing their contents. The auditor's completeness check is "does `log_digest` in the signed JWT match the AS's published commitment ledger?" — one signature verification, not a PLONK proof.

**Why it works / why it fails against the construction:** The construction responds (§8, final "audit completeness" row) that the AS "must read the events to verify completeness." This is wrong — a standards-conformant AS applies per-RS scope filtering (draft-ietf-oauth-jwt-introspection-response §5.2) *before* generating the response and can commit to a log hash without exposing values. The construction does not rebut this. **The gap that remains:** the AS computes `H(scope_i)` from plaintext scope values it holds. If the AS is honest, it behaves identically to the Bolyra registry's `delegationLogDigest` update rule. If the AS is compromised, neither construction gives the auditor independent recourse — the construction swaps trust-in-AS for trust-in-registry-operator, which is the same class of assumption under a different name.

**In-threat-model?** No. The construction must address this directly. The §8 table entry for "Audit completeness without revealing chain contents" is the construction's central novelty claim and it overstates the baseline's weakness. The response must articulate *why* the registry-operator trust assumption is strictly weaker than AS trust — or concede that the audience is specifically the subset of deployments where the AS IS a colluding chain participant, which is a narrower claim than §1 states.

---

### Attack 2: Root Scope Legitimacy Is Not Proven — The Chain Is Unanchored

**Attack:** Constraint 2 in §2 proves `Poseidon2(delegatorScope[0], delegatorCredCommitment[0]) === rootScopeCommitment`. This proves the chain *starts at* the registered root. It does not prove the registered root represents *legitimately granted authority*. The `rootScopeCommitment` is a public input that the auditor reads from the on-chain registry. The registry stores whatever value was written during handshake. Nothing in the construction prevents the following sequence:

1. A colluding operator registers a session with `rootScopeCommitment = Poseidon2(FINANCIAL_UNLIMITED_BITMASK, fabricatedCredCommitment)`.
2. The delegation chain narrows monotonically from this inflated root.
3. The `DelegationAuditRollup` proof verifies cleanly. The auditor sees "monotonic narrowing held; terminal scope satisfies `FINANCIAL_SMALL`."
4. The audit passes — but the root credential was never legitimately issued to anyone.

In RFC 7662, this attack fails by construction: the AS issued the root token based on documented user consent at a specific OAuth authorization flow. The token's `iss`, `sub`, and `scope` are tied to that consent event. An auditor can call the AS's introspection endpoint and trace the token back to the authorization grant. The Bolyra construction has no equivalent: there is no circuit that binds `rootScopeCommitment` to a human enrollment event or to a human-signed authorization of `FINANCIAL_UNLIMITED` for the root agent. The `AgentPolicy` circuit presumably gates agent credential issuance, but the `DelegationAuditRollup` doesn't verify that the root credential commitment was produced by the `AgentPolicy` circuit — it takes `rootScopeCommitment` as an opaque public input.

**Why it works / why it fails against the construction:** The security argument in §4 (Audit Forgery Game) explicitly excludes this. The game setup says "Challenger *enrolls* `n` agents with *known* credential commitments and scopes" — meaning legitimacy of the root is assumed, not proven. This is a game design choice that lets the proof go through, but it sidesteps the deployment reality. In the NFCU scenario (§7), the auditor's question is precisely "was the member's AI assistant legitimately authorized to hold `FINANCIAL_SMALL`?" The proof answers "the chain narrowed from whatever the root was" — which is not the same question.

**In-threat-model?** No. The construction must either (a) add a constraint that `delegatorCredCommitment[0]` is a valid leaf in the agent Merkle tree under a known enrollment root, binding the chain to a verifiable credential issuance event, or (b) explicitly scope the claim to "assumes legitimate root" and acknowledge this trust assumption is equivalent to trusting the AS's issuance records.

---

### Attack 3: `chainLength` Is a Public Output — the Journalist/Source Variant Leaks Pipeline Topology

**Attack:** The journalist/source variant (§2, §7) is presented as the strongest privacy case. The construction correctly notes that `rootScopeCommitment` can be hidden behind a Merkle membership proof over recent handshake roots. However, `chainLength` remains a public output (listed explicitly in §2, "Public outputs"). In a whistleblower scenario, the auditor learns exactly how many hops separated the journalist from the source. This is load-bearing metadata.

Concretely: if the auditor knows the journalist's agent is always at hop 0 and the source's anonymizing relay infrastructure typically uses 2-hop, 3-hop, or 4-hop chains (standard Tor-style anonymization depths), learning `chainLength = 3` immediately narrows the anonymization set. If the auditor also controls timing data from the on-chain `delegationLogDigest` updates (each hop emits a Poseidon2 update, visible on-chain with block timestamps), the auditor can correlate chain length against known relay configurations.

RFC 9449 DPoP with OIDC PPIDs does not disclose chain length to the RS. The RS sees a sender-constrained token and a DPoP proof — no information about how many intermediate systems handled the credential. The AS's introspection response under per-RS filtering policy (RFC 7662 §5) can return `{"active": true, "scope": "READ_DATA"}` with no structural information about the delegation path.

**Why it works / why it fails against the construction:** The construction has no mitigation. The Merkle membership proof for the journalist variant hides `rootScopeCommitment` but does not hide `chainLength`. Making `chainLength` private would require the auditor to accept a proof over all possible chain lengths simultaneously (a range proof: `chainLength ∈ [1, MAX_HOPS]`), which would require reformulating the `auditDigest` computation and the `executionLogDigest` binding — the latter depends on selecting `logAcc[chainLength]` via a `QuinSelector`, which in its current form requires `chainLength` to be a known selector value visible to the verifier.

**In-threat-model?** Yes, partially — the §3 deanonymization win condition covers intermediate credentials, but `chainLength` is a public output by design, so the game explicitly does not protect it. The construction must either acknowledge `chainLength` as a controlled disclosure (and remove the journalist/source claim for adversaries who can exploit topology), or add a range-proof wrapper that hides exact chain length while proving `chainLength ≥ 1`.

---

### Attack 4: The Registry Is the AS — Trust Is Relocated, Not Eliminated

**Attack:** The construction's §8 repeatedly asserts "no AS is in the trust path." The PLONK proof is self-contained; verification requires only the PLONK verification key and the two on-chain values (`rootScopeCommitment`, `executionLogDigest`). But both of these values are written by the Bolyra registry contract. The registry contract is deployed and controlled by the Bolyra protocol operator. In the cross-org NFCU scenario (§7), the registry is a single contract that all four parties (NFCU routing agent, Chainalysis AML agent, Circle settlement agent, member AI assistant) interact with.

This is structurally identical to a federated AS in a WIMSE deployment, except the AS is a Solidity contract on Base Sepolia rather than an OIDC-compliant HTTP server. The attack: the registry operator (Bolyra / ZKProva Inc.) controls what gets written to `delegationLogDigest`. The adversary model in §3 explicitly states the adversary "does NOT control the on-chain registry's write path" — this is *assumed*, not derived from the construction. A Bolyra-controlled registry that writes favorable `delegationLogDigest` values before the audit is indistinguishable from a compromised AS that logs favorable scope hashes.

RFC 7662 in a regulated financial context (NFCU, NCUA exam) uses an AS operated by the financial institution itself, subject to examination, regulatory audit, and legal liability. The Bolyra registry operator is not subject to these controls. The NCUA examiner can subpoena NFCU's AS logs. They cannot subpoena a Bolyra smart contract's write history (Base Sepolia is a public chain, but the write authorization model is not regulated). The claim "eliminates AS trust" is more precisely "substitutes unregulated registry-operator trust for regulated AS trust" — which is a regression for the NFCU/NCUA deployment scenario in §7.

**Why it works / why it fails against the construction:** The construction partially addresses this with the observation that the registry's write path is "executed by the registry contract atomically with each `verifyDelegation` call" — implying the contract logic itself is the trust anchor, not the operator. But smart contract upgradeability is not addressed. If the registry is upgradeable (a standard pattern for production contracts), the operator can modify the `verifyDelegation` write path before an audit. The construction must either commit to an immutable registry deployment or add a version-hash public input that pins the contract bytecode at the time of each delegation hop.

**In-threat-model?** No. The §4 threat model excludes registry operator compromise by assumption. For the construction to displace the AS in regulated deployments, it must make the registry-operator trust surface explicit and demonstrate it is strictly smaller than the AS trust surface — not simply rename it.


## Persona: spiffe_engineer

---

### Attack 1: The Off-Chain Hop Blindspot — Completeness Only for On-Chain Hops

- **Attack:** The construction's completeness guarantee rests on the `executionLogDigest` being updated atomically inside `verifyDelegation` (§2, "On-chain execution log"). But in a real multi-tool AI pipeline, tool calls are HTTP/gRPC round-trips — not every hop is required to call `verifyDelegation`. A colluding agent at hop `i` can: (a) accept a delegated credential off-chain without registering the hop, (b) exercise elevated permissions against a permissive resource server that does no on-chain check, and (c) then call `verifyDelegation` at hop `i+1` with a narrowed scope. The `delegationLogDigest` records a clean `k-1` hop chain. The auditor in §7 is told to "compare `chainLength` in the proof against the expected pipeline depth" — but "expected depth" is an assertion by the party generating the proof, not a cryptographic invariant. There is no mechanism in the construction that requires every tool call in a pipeline to register a hop on-chain.

  In SPIFFE terms: SPIRE's node attestation happens at workload startup at the infrastructure layer. Every workload that presents an SVID creates an audit trail at the SPIRE server *regardless of application-layer choices*. There is no "opt-in" attestation step a rogue workload can skip. The Bolyra construction's completeness is application-layer opt-in, not infrastructure-layer mandatory.

- **Why it works / why it fails against the construction:** The construction's §3 threat model explicitly states the adversary does NOT control "the on-chain registry's write path." This is accurate for *registered* hops but says nothing about *unregistered* hops. The completeness proof in §4 reduces to: "the in-circuit hash chain must equal the on-chain `executionLogDigest`." If a hop never touches the registry, it never enters `executionLogDigest`, and the circuit constraint is vacuously satisfied for the registered subset. The incompleteness win condition (§3, condition 4) requires `chainLength` to be less than "the number of hops recorded in the on-chain execution log" — not less than the number of hops *executed*. The construction conflates "executed" with "registered."

- **In-threat-model?** No — the construction must address this. The fix requires making on-chain registration mandatory for any hop that exercises delegated permissions — either via a resource server that calls `verifyDelegation` before granting access, or by having the PLONK proof bind to an external completeness oracle. Without this, the execution log is a voluntary audit trail, not a mandatory one.

---

### Attack 2: WIMSE Token Exchange + SPIFFE Federation Already Covers Cross-Org Delegation Without On-Chain Infrastructure

- **Attack:** The construction's §8 dismisses WIMSE federation as requiring "bilateral AS coordination" per call. This misrepresents how SPIFFE federation actually works. SPIFFE trust bundle federation is one-time per org-pair: each trust domain publishes a bundle endpoint (JWKS or X.509 CA bundle); federating NFCU ↔ Chainalysis ↔ Circle requires exchanging three bundle endpoints at org-onboarding time, not per-delegation-event. After that, WIMSE token exchange (building on RFC 8693 with audience-bound DPoP-style proofs) handles the NFCU → Chainalysis → Circle chain as ordinary workload-to-workload calls. The WIMSE WI-UCr document (draft use-case registry) explicitly covers AI agent pipeline delegation as a target use case. The construction's claim that "no org sees another org's internal scopes" is also not unique: in WIMSE, the `act` chain encodes delegation depth but each hop's resource server only sees its own token — it does not see upstream hops' scope values unless the token explicitly carries them.

  Concretely: the §7 scenario (NFCU → routing agent → Chainalysis → Circle) maps directly to a four-workload SPIFFE deployment. NFCU runs a SPIRE server for its workloads; Chainalysis and Circle each run their own. A federation bundle exchange at contract-signing time (not per-transaction) enables cross-org SVID validation. The NCUA examiner gets mTLS session logs from each SPIRE server — all hops are mandatory (SPIRE does node attestation at workload start), all scopes are defined in SPIFFE ID path hierarchy, and no custom ZK stack is required.

- **Why it works / why it fails against the construction:** The construction's uniqueness claim ("Single artifact for cross-org chains" in §8) is real for *cryptographic privacy* — WIMSE does not hide intermediate scope values from the NCUA examiner the way the PLONK proof does. SPIRE audit logs are readable. If the NCUA examiner's regulatory requirement actually mandates that intermediate scopes be hidden from the examiner (not just from other orgs), SPIFFE/WIMSE cannot satisfy it without an additional privacy layer. However, the §7 scenario states NFCU "does not want the examiner to learn that Chainalysis is their AML provider" — this is a business confidentiality concern, not a regulatory requirement. Most NCUA examination frameworks do not grant examiners the right to audit internal vendor relationships beyond what is reported in BSA/AML filings. The construction is solving a privacy problem that may not exist in the regulatory context it cites.

- **In-threat-model?** Partially. The privacy claim survives: WIMSE cannot prove monotonic narrowing over hidden bitmasks. But the construction must justify why the regulatory context *requires* hiding intermediate participants from the auditor rather than assuming it does. If the answer is "the privacy is a feature for non-regulatory use cases," the §7 deployment scenario should not be the lead example, because it weakens the claim's credibility with the infrastructure-layer audience.

---

### Attack 3: Terminal Participant Deanonymization via Credential Dictionary

- **Attack:** The construction publishes `terminalScopeCommitment = Poseidon2(delegateeScope[chainLength-1], delegateeCredCommitment[chainLength-1])` as a public output. `delegateeCredCommitment` = `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)`. In the §7 scenario, the terminal agent is Circle's settlement agent. Circle's settlement workload has a known `modelHash` (the deployed model version is public), a known `opPubAx`/`opPubAy` (Circle's operator public key is registered on-chain in the agent Merkle tree — enrollment is public), and a known `permBitmask` (`FINANCIAL_SMALL`, bit 2). The `expiry` is bounded (say, 90-day credential windows). An auditor with the `terminalScopeCommitment` and access to the agent Merkle tree can enumerate `(modelHash, opPubAx, opPubAy, bit2, expiry)` tuples for all known Circle settlement agents, compute `Poseidon5` for each candidate `expiry` value in the bounded window, compute `Poseidon2(0b00000100, candidate)`, and test equality with the public `terminalScopeCommitment`. The anonymity set for the terminal participant is not the global agent set — it is the set of agents with `FINANCIAL_SMALL` permission, a small subset of a commercially deployed registry.

  The journalist/source variant (§2) adds a Merkle membership proof over a set of `K` handshake roots to hide the `rootScopeCommitment`. But it does not hide `terminalScopeCommitment`. For the journalist use case, the terminal node is the journalist's agent — potentially a well-known deployed model with a small anonymity set. The construction's privacy theorem (§4) states the proof "reveals nothing about the witness beyond the public signals" — this is correct. But it does not claim that the public signals are themselves unlinkable to participants. The privacy argument stops at the proof boundary; it does not account for out-of-band linkage through a credential dictionary over the public outputs.

- **Why it works / why it fails against the construction:** The ZK-PLONK privacy argument is sound: the proof leaks nothing beyond public signals. But `terminalScopeCommitment` is a deterministic function of `(terminalScope, terminalCredCommitment)`, and `terminalCredCommitment` is a deterministic function of `(modelHash, opPubAx, opPubAy, permBitmask, expiry)`. If any of these inputs are predictable (which they are for commercially deployed models with registered operator keys), the terminal participant is recoverable. SPIFFE SVIDs rotate by default every hour (configurable down to minutes), collapsing the enumeration window. Bolyra credentials use a 64-bit `expiry` with no mandatory rotation schedule — a 90-day credential gives the attacker a 7,776,000-second search space, trivially enumerable.

- **In-threat-model?** No. The threat model in §3 lists "deanonymization of intermediate participants" as a win condition but focuses on in-circuit privacy. It does not address out-of-band credential dictionary attacks on public outputs. The construction must either (a) require credential blinding (randomize `credentialCommitment` with a fresh nonce per session so the same credential produces different commitments in different proofs — the `sessionNonce` is already a public input and could serve this role) or (b) explicitly scope the privacy claim to intermediate hops only and acknowledge terminal participant linkability as a known limitation.

---

### Attack 4: No Revocation Mid-Chain — The Completeness Guarantee Survives a Compromised Hop

- **Attack:** The construction's execution log binding proves that a proof covers all hops *as recorded at the time of proof generation*. It does not address what happens if a credential used at hop `i` is revoked after the delegation chain executes but before the audit proof is generated. More precisely: suppose hop 2 (the Chainalysis agent in §7) is later discovered to have been operating under a stolen credential. The delegation chain executed cleanly — `executionLogDigest` reflects four valid scope commitments. The `DelegationAuditRollup` proof is generated after the fact. The proof verifies successfully: the circuit proves the chain narrowed monotonically, the terminal scope is correct, and the digest matches. The audit is clean. But hop 2's credential was fraudulent. There is no on-chain revocation registry for `credentialCommitment` values, and the circuit has no constraint checking whether any `credentialCommitment[i]` appears on a revocation list. The proof proves the *structural* properties of the chain; it cannot prove the *validity* of individual credentials at execution time.

  In SPIFFE, SVID rotation is the revocation mechanism. SVIDs have short TTLs (1 hour default). A compromised SVID is automatically invalid after its TTL expires. An audit log produced after SVID expiry shows a gap in the attestation chain — the SPIRE server's audit log records when each SVID was issued and by what node attestation plugin. There is no equivalent in Bolyra: a 90-day agent credential that is revoked at day 45 still produces a valid `credentialCommitment` that satisfies the circuit at day 46 (the circuit cannot check revocation at proving time, only at issuance time).

- **Why it works / why it fails against the construction:** The construction does not claim to address revocation. The `delegateeExpiry[i]` constraint enforces temporal narrowing forward (delegatee expires no later than delegator) but does not distinguish between "credential validly expired" and "credential revoked early." The NCUA audit scenario (§7) requires the examiner to confirm the chain was valid *at execution time*. A post-hoc audit proof generated after a credential revocation cannot make this distinction. The construction implicitly assumes credentials are either valid or expired — not revoked. For the regulatory context cited, this is a material gap: NCUA examinations frequently occur months after the audited transactions.

- **In-threat-model?** No. The threat model in §3 restricts the adversary to "up to `MAX_HOPS - 1` intermediate agents" and assumes they cannot forge proofs. But a *post-compromise* adversary (one whose credential was valid at execution time) can generate a `DelegationAuditRollup` proof that is cryptographically valid even after the credential is revoked, because the circuit has no revocation check. The construction must specify either (a) a revocation registry that the circuit reads at proving time (e.g., a Merkle non-membership proof against a revocation accumulator), or (b) an explicit statement that the audit proof attests to structural chain properties only, not to the validity of individual credentials at execution time, and that revocation is enforced by a separate mechanism outside the ZK system.
