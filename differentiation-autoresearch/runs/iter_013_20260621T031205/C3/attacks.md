# Tier 3 Adversarial — C3 Delegation audit without exposure

## Persona: auth0_pm

---

### Attack 1: The Latency Cliff Makes This a Non-Product

- **Attack:** Section 6 estimates ~5s proving time per `DelegationHopAccumulator` hop. The Navy Federal scenario has 4 hops → 20s of proving overhead before the pipeline produces a single loan decision. That 20s is wall-clock time the agent pipeline is blocked, not a background task — `submitDelegationHop()` must succeed and update `chainAccumulators[sessionNonce]` on-chain before the next hop can begin (Section 2, on-chain components: "verifies DelegationHopAccumulator PLONK proof, updates `chainAccumulators[sessionNonce]`"). Add L2 block confirmation latency on Base Sepolia and you're at 30–40s per pipeline invocation. WorkOS and Auth0 MCP auth issue scoped tokens in <100ms. Cloudflare Access adds ~10ms at the edge. The operator faces a 300x latency multiplier for a cryptographic audit guarantee they can get with signed structured logs stored in S3.

- **Why it works / why it fails:** The construction does not address the sequential on-chain dependency between hops. Even if off-chain proving is parallelizable, the `lastScopeCommitment[sessionNonce]` chain-link (Section 2) is a serial dependency — hop k+1 cannot start until hop k's proof lands on-chain and the state is readable. The 5s estimate is also PLONK prover-local; it excludes gas submission, block inclusion, and RPC latency. There is no discussion of batching, optimistic execution with deferred proof submission, or off-chain accumulator state with on-chain settlement. The construction's own circuit cost analysis (Section 6) makes no mention of this operational bottleneck.

- **In-threat-model?** No — this is a deployment/product gap the construction must address. The threat model (Section 3) only considers adversarial proof forgery; it does not bound end-to-end latency or consider whether the proof submission cadence makes the protocol viable in a real-time tool-call pipeline. A construction targeting "multi-tool AI agent pipeline" scenarios that adds 30s per invocation will not be adopted regardless of its cryptographic soundness.

---

### Attack 2: The "Distrusting Auditor" Is a Regulatory Fiction

- **Attack:** Section 7 and Section 8 are built around one key claim: "the examiner's verification requires zero callbacks to NFCU, Experian, or SendGrid infrastructure. The proof is self-contained. The examiner trusts math, not the auditee's servers." This is a cryptographic property, not a regulatory one. NCUA examiners under 12 CFR Part 748 have subpoena power. They compel production of audit logs, system access credentials, and vendor contracts. The actual NCUA examination workflow is: request access to the core system, pull transaction records, interview compliance officers, and request documentation from third-party vendors directly — not by verifying a PLONK proof. The "distrusting auditor" who cannot contact the auditee's infrastructure is a fiction that describes a whistleblower situation, not a regulatory examination. Auth0's audit log export + a signed attestation from a SOC 2 Type II auditor satisfies NCUA today, at zero marginal ZK cost, with tooling the compliance team already knows how to use.

- **Why it works / why it fails:** The construction conflates "cryptographically self-contained" with "regulatory sufficient." The NCUA does not require zero-callback proofs — it requires reliable, tamper-evident, auditable records. Signed structured audit logs with a trusted timestamping authority (RFC 3161) satisfy this requirement and are already accepted by NCUA. The construction's Section 8 baseline comparison ("BBS+ commit-and-prove") never benchmarks against the actual baseline an enterprise would consider: structured audit logs + OAuth 2.0 token introspection logs + vendor-signed attestations. The ZK property solves a problem (distrusting cross-org auditor with no subpoena power) that is not the procurement-relevant problem for the stated buyer.

- **In-threat-model?** No — the threat model (Section 3) defines the adversary as one who controls n-1 of n participants and wants to forge a narrowing proof. It does not model the adversary that matters for procurement: a buyer who compares total cost of ownership against an OAuth+audit-log baseline that already satisfies their regulator. The construction must produce a buyer-level reason, not a cryptographic one, for why the NCUA examination scenario requires ZK proofs rather than subpoenaed logs.

---

### Attack 3: Enrollment Authority Circularity Undercuts the "No Trusted Third Party" Claim

- **Attack:** Section 8 claims: "The auditor trusts only: (1) the PLONK verification key (a public parameter generated during universal setup), and (2) the on-chain Merkle roots (publicly auditable state). Neither is controlled by any participant in the chain." This is incorrect. The `delegateeMerkleRoot` used in `DelegationHopAccumulator` (Section 2, public outputs) is populated by whoever can call the agent enrollment function on `BolyraAuditRegistry.sol`. The construction does not specify enrollment access control. If NFCU controls enrollment of its agent tree, NFCU controls what appears as a valid `delegateeMerkleRoot`. An adversarial NFCU could enroll a fake agent, delegate to it with fabricated scopes, and produce a valid `ChainAuditProof` — the proof would be sound against the circuit constraints, but the enrolled agent is NFCU's own creation. The distrusting NCUA examiner still trusts NFCU's key management, just transposed from a BBS+ issuer key to an on-chain enrollment authority. The attack the construction claims to defeat in the `CrossOrgDistrust` game (Section 3) can be replayed at the enrollment layer.

- **Why it works / why it fails:** The Section 4 soundness reduction (step 5) says "each `scopeCommitmentTrace[i]` was a public output of a previously verified `DelegationHopAccumulator` proof" and "by A2, extract the per-hop witness" — but this only proves the witness satisfies the circuit constraints given a valid `delegateeMerkleRoot`. It does not prove the `delegateeMerkleRoot` was populated by a trustworthy enrollment process. The security argument is silent on the enrollment trust assumption. The privacy reduction (Section 4) notes that "`delegateeMerkleRoot` is shared across all agents enrolled in the tree" — but if the enrollment authority is the auditee, the tree is under auditee control, and the k-anonymity claim is only as strong as the enrollment process's integrity.

- **In-threat-model?** No — the construction defines adversary capabilities (Section 3) as controlling "up to n-1 of n delegation participants" and "all k organizations" in the `CrossOrgDistrust` game. It does not model an adversary who also controls the enrollment authority for the agent tree. For a self-contained audit claim to hold against a fully distrusting auditor, enrollment must either be permissionless (with its own spoofing risks) or governed by a trusted authority — which reintroduces the trusted third party the construction claims to eliminate.

---

### Attack 4: There Is No Onboarding Story and the Complexity Kills Enterprise Sales

- **Attack:** The construction describes two new circuits (`DelegationHopAccumulator`, `ChainAuditProof`), a new Solidity contract (`BolyraAuditRegistry.sol`), on-chain state management per `sessionNonce`, a PLONK prover binary (`pot16.ptau`), and coordination between cross-org participants who must each call `submitDelegationHop()` sequentially. Auth0's MCP auth documentation shows integration in 3 code blocks. WorkOS MCP auth ships with an SDK where the token issuance call is one function. Stytch Connected Apps requires adding a middleware line. The Bolyra construction has no equivalent "getting started in 10 minutes" path. An enterprise procurement team evaluating MCP auth vendors will ask: "Who deploys the contract? Who manages the ptau ceremony file? What happens when a hop prover is down and the pipeline hangs waiting for on-chain confirmation?" The answers require a ZK engineer on staff, which no credit union has.

- **Why it works / why it fails:** The construction is a cryptographic research artifact presented as a deployable product claim. The gap between Section 2's circuit specification and a shippable SDK with error handling, retry logic, gas estimation, and operator documentation is not acknowledged anywhere. Section 7's "concrete deployment scenario" describes NFCU generating a `ChainAuditProof` as if it is a one-line SDK call, but the actual integration surface includes circuit proving key distribution, on-chain contract deployment, cross-org coordination for sequential hop submission, and handling proof generation failures mid-pipeline. Against WorkOS — which has SOC 2 Type II, enterprise SLAs, dedicated support, and a documented MCP auth flow — "solo founder with a research-grade ZK circuit" does not clear procurement's vendor risk threshold regardless of the cryptographic novelty.

- **In-threat-model?** No — the construction defines no deployment model, no operator abstraction, and no failure modes. The claim in Section 1 that the proof "works across organizational boundaries without a shared authorization server" is a cryptographic property, not a product property. A buyer asking "what do I do when the prover crashes at hop 2 of a live loan application?" has no answer in this construction. The gap to close must include either a hosted proving service (which reintroduces a trusted third party) or a hardened embedded prover with documented fallback behavior — neither of which is addressed.


## Persona: cryptographer

*Stance: I will accept zero hand-waving. Show me the game, show me the reduction, or the claim is marketing.*

---

### Attack 1: `finalAccumulator` Is an Unconstrained Private Input — Soundness Break

**Attack:**
In `ChainAuditProof`, `finalAccumulator` is a **private input** (§2, Circuit 2 private input table). Constraint 5 binds `accumulatorTrace[hopCount-1] === finalAccumulator`. The public output is `chainDigest = Poseidon2(finalAccumulator, sessionNonce)`. The only public input that anchors the proof to on-chain state is `onChainChainSeed` — the *start* of the chain. There is no public input representing the on-chain terminal accumulator `chainAccumulators[sessionNonce]`.

The adversary's strategy: construct any self-consistent tuple `(rootScope, accumulatorTrace[], scopeCommitmentTrace[], finalAccumulator, hopCount)` where every intermediate scope monotonically narrows (trivially satisfiable by construction) and `Poseidon2(rootScope, rootCredCommitment) = onChainChainSeed`. This produces a valid PLONK proof with `auditResult = 1` and a `chainDigest` that **does not correspond to the actual on-chain execution history**.

The `verifyChainAudit` function is specified as "verifies `ChainAuditProof` PLONK proof, emits `ChainAudited(...)`" (§2, on-chain components). It is never specified to check `chainDigest == Poseidon2(chainAccumulators[sessionNonce], sessionNonce)`. Without this contract-level check, the proof is decoupled from reality. Even if the contract does perform this check, it is nowhere stated in the circuit or the security argument — the reduction sketch in §4 cites constraint 4 for chain consistency but never addresses whether the `finalAccumulator` is externally anchored.

**Why it works / why it fails:**
It works unconditionally as specified. The Poseidon collision resistance argument in §4 (step 4) only establishes that the extracted `scopeCommitmentTrace` is *internally* unique — it says nothing about whether `finalAccumulator` matches what actually happened on-chain. The argument is circular: the reduction assumes the extracted witness is valid, but validity is defined relative to the private `finalAccumulator` the adversary chose.

**In-threat-model?** The adversary wins `DelegationAuditSoundness` game (§3) with advantage 1 — condition (b) is satisfied because no hop on-chain need violate narrowing; instead, a fictitious chain replaces the real one entirely. **Construction must address this.**

---

### Attack 2: Low-Entropy Scope Breaks `IntermediateAnonymity` Game

**Attack:**
`newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment)` is a **public output** of every `DelegationHopAccumulator` submission (§2, Circuit 1 public outputs). It appears on-chain at each hop, permanently.

The privacy argument in §4 states: "recovering the scope or credential from the commitment requires inverting Poseidon (breaks A1)." This is only true when the preimage space is large. It is not true here:

- `delegateeScope` is a 64-bit cumulative bitmask, but the **cumulative bit encoding constraints** (§4.2 constraint 4 of the existing circuit) reduce the valid value space dramatically. Bits 4→3→2 form an implication chain; with 8 permission bits under these constraints, the set of valid bitmasks is at most ~30 values in practice — call it S_scope with |S_scope| ≈ 30.
- `delegateeCredCommitment` values are binding to enrolled agents. Agent enrollment is a public on-chain action; an adversary maintaining a watch table of enrollment events accumulates a set S_cred of known commitments.

The adversary precomputes `T = { Poseidon2(s, c) : s ∈ S_scope, c ∈ S_cred }`. Table size: 30 × |enrolled agents| entries — for a credit union with 100 enrolled agents, |T| = 3,000 entries. A single lookup inverts any observed `newScopeCommitment`.

This breaks the `IntermediateAnonymity` game (§3) perfectly: upon seeing the public output at hop k, the adversary looks up `newScopeCommitment_k` in T, recovers `(delegateeScope_k, delegateeCredCommitment_k)`, and outputs the correct guess b' with advantage 1.

**Why it works / why it fails:**
The `delegateeMerkleRoot` argument ("reveals only tree membership") is orthogonal — the adversary doesn't need the Merkle proof. The scope commitment alone identifies the agent and their scope. The anonymity set is not "thousands of agents" as claimed in §7 (whistleblower variant); it is however many agents are in S_cred.

**In-threat-model?** The `IntermediateAnonymity` game is won by the adversary. The privacy reduction in §4 ("inverting Poseidon breaks A1") is formally false under the game as defined — it conflates a one-way function with a hiding commitment over a small domain. **Construction must address this** by hiding `newScopeCommitment` (e.g., blinding with a random salt as a private input) or removing it from the per-hop public outputs entirely.

---

### Attack 3: `previousAccumulator` Is Private — Chain-of-Custody Breaks Even with Attack 1 Fixed

**Attack:**
In `DelegationHopAccumulator`, `previousAccumulator` is a **private input** (§2, Circuit 1 private input table). The circuit constrains `newAccumulator = Poseidon3(previousAccumulator, newScopeCommitment, hopIndex)`, but the contract's `submitDelegationHop` function stores only the output `newAccumulator` into `chainAccumulators[sessionNonce]`. It cannot verify that the prover used `previousAccumulator = chainAccumulators[sessionNonce]` prior to this call, because that value is private.

**Concrete exploitation (assuming Attack 1 is fixed — `onChainFinalAccumulator` is now a public input to `ChainAuditProof`):**

Adversary submits K hop proofs, each with a strategically chosen `previousAccumulator` value that is *not* the accumulated value from the prior hop. Specifically, the adversary designing a 2-hop claim from 3 actual hops:

- Submit hop A with `previousAccumulator = 0`, `hopIndex = 0`. On-chain: `chainAccumulators[nonce] = Poseidon3(0, SC_A, 0) = A0`.
- Submit hop B with `previousAccumulator = A0`, `hopIndex = 1`. On-chain: `chainAccumulators[nonce] = Poseidon3(A0, SC_B, 1) = A1`.
- Submit hop C with `previousAccumulator = A1`, `hopIndex = 2`. On-chain: `chainAccumulators[nonce] = Poseidon3(A1, SC_C, 2) = A2`.

Now claim `hopCount = 2` in `ChainAuditProof`. The circuit checks `accumulatorTrace[1] = finalAccumulator = A2`. Constraint 4 requires `accumulatorTrace[1] = Poseidon3(accumulatorTrace[0], scopeCommitmentTrace[1], 1)`, which means `accumulatorTrace[0] = Poseidon3^{-1}(A2 / SC_B / 1)`. The only way to satisfy this with honest inputs is `hopCount = 3`. The adversary *cannot* forge a 2-hop proof here under collision resistance — the internal audit circuit enforces the count correctly relative to `A2`.

**But the reverse is also possible:** submit 2 hops with the *same scope commitment* (by replaying a valid but already-used delegation token at a different `hopIndex`) to pad chain length, then claim `chainLength = 4` in the audit. `hopIndex` is private and range-checked only to `< 256` — nothing prevents two hop submissions with `hopIndex = 0` and `hopIndex = 0` again, as long as the on-chain accumulator accepts the `newAccumulator` output. The `delegationNullifier = Poseidon2(delegationTokenHash, sessionNonce)` might prevent this if the contract checks nullifier uniqueness — **but this uniqueness check is never specified** in `BolyraAuditRegistry.sol` (§2, on-chain components).

**Why it works / why it fails:**
Without nullifier uniqueness enforcement on-chain, the same hop can be replayed with different `hopIndex` values to inflate `chainLength`. The security argument (§4) does not include a nullifier replay game and does not specify the contract performs this check.

**In-threat-model?** The `DelegationAuditSoundness` game condition (b)(i) is satisfied if the inflated chain includes a hop where `scope_k` exceeds `scope_{k-1}` in the fictitious ordering. Without nullifier uniqueness enforcement, this is feasible. **Construction must address this.**

---

### Attack 4: `pot16.ptau` Subversion — Universal Setup Trust Is Unspecified

**Attack:**
Both circuits use PLONK with `pot16.ptau` (§5 primitive mapping). The security assumption A2 ("Knowledge soundness of PLONK in AGM+ROM") holds only under an *honest* SRS — one generated correctly with the trapdoor destroyed. The construction does not:
- Identify which ceremony produced `pot16.ptau`.
- Specify how many independent participants contributed.
- Provide a commitment (e.g., hash) to the specific artifact in use.
- Discuss what the adversary gains from a subverted SRS.

Under a subverted SRS (one where the trapdoor τ is known to the adversary), PLONK proof forgery is straightforward: given τ, the adversary constructs a convincing proof for any false statement including `(auditResult = 1, chainLength = k)` for a chain that never occurred. Every game in §3 — `DelegationAuditSoundness`, `CrossOrgDistrust`, `IntermediateAnonymity` — collapses immediately.

The construction's core value proposition against BBS+ (§8) is: "The auditor trusts cryptography, not the organizations being audited." This is self-undermined if the `pot16.ptau` was generated by one of the organizations being audited, or by Bolyra itself. In this case, the auditor is trusting the auditee's ceremony output — precisely the circular dependency the construction claims to eliminate. A distrusting NCUA examiner who demands BBS+ issuer independence should equally demand SRS independence.

The Groth16 alternative for `HumanUniqueness` (§2, table) reuses the Semaphore v4 ceremony, which has a documented, multi-party ceremony with publicly verifiable transcript. No equivalent is claimed for `pot16.ptau`.

**Why it works / why it fails:**
The reduction in §4 correctly reduces to A2, but A2 assumes honest setup. The reduction sketch says nothing about the case A2 fails. The PLONK knowledge soundness theorem (Gabizon-Williamson-Ciobotaru 2019) is proven in AGM+ROM assuming the SRS is honestly generated. If it isn't, the algebraic group model adversary can compute forgeable proofs directly from the trapdoor.

**In-threat-model?** The §3 adversary model explicitly controls up to n-1 participants but does not scope the SRS ceremony. The `CrossOrgDistrust` game (§3) says "A controls all k organizations" — if one of those organizations participated in the `pot16.ptau` ceremony and the ceremony was not n-of-n honest (PLONK MPC requires only one honest participant if using a Powers-of-Tau MPC with proper domain separation), the trapdoor may be recoverable. The construction must cite the specific `pot16.ptau` artifact, its ceremony participants, and address setup independence as a trust assumption. **Not in-threat-model as specified, but a critical omission that a distrusting auditor will immediately raise.**


## Persona: cu_ciso

---

### Attack 1: The Privacy Feature Is a GLBA Violation

- **Attack:** I pull up GLBA Safeguards Rule §314.4(f) — written vendor/service provider oversight. My examiner will ask: "Provide your inventory of all third parties processing member data." Section 7 of the construction explicitly says the NCUA examiner does **not** learn "which vendors NFCU uses (Experian, SendGrid), what the intermediate scope values were, or which agent models were involved." That is not a privacy win for me. That is a compliance gap. My GLBA program requires documented evidence that I *know* every third party touching member PII, that I performed due diligence on them, and that I can revoke their access. Proving to me that "some enrolled agent had READ_DATA" is not a substitute for "Experian processed member credit file #4471 at 14:32 UTC, under contract #XYZ." The construction's privacy guarantee is precisely what my regulator prohibits me from having.

- **Why it works / why it fails:** The construction has no defense here because the feature and the requirement are structurally opposed. `ChainAuditProof` hiding participant identity is not a configurable option — it is the core claim. The construction does not offer a mode where the credit union can produce a plain-language vendor access log for its GLBA inventory while still using the ZKP for the auditor's monotonicity check. Section 7 frames privacy as benefit; it is actually a GLBA finding for any examiner who reads the safeguards rule.

- **In-threat-model?** No — the construction must address this. Proposed mitigation path: a dual-rail architecture where the CU operator maintains a permissioned plaintext audit log (GLBA-facing) while the ZKP audit artifact serves the cross-org monotonicity claim. The construction currently treats these as the same problem.

---

### Attack 2: Incident Response Leaves the Examiner with a Hash

- **Attack:** I invoke the 2am scenario. A member calls disputing a loan denial. My compliance team opens an investigation. The on-chain state gives them `chainDigest = Poseidon2(finalAccumulator, sessionNonce)` and `chainLength = 4`. That is a 256-bit Poseidon output and a number. NCUA Part 748 Appendix A requires my security program to include an "incident response program" with the ability to reconstruct the sequence of events involving member data. The construction produces a proof that the chain was *valid* — it says nothing about what actually happened to member data at each hop, in what order, with what inputs or outputs. When my examiner asks "show me the audit trail for loan application #8847," I cannot answer with `0x4af3...` and `chainLength = 4`. There is no mapping from the on-chain accumulator to a human-readable incident timeline. The construction conflates *authorization proof* with *audit trail*.

- **Why it works / why it fails:** Section 7's deployment scenario explicitly positions `ChainAuditProof` as the examiner artifact. But the examiner's actual workflow is: (1) identify the event, (2) trace actors, (3) determine what data was accessed, (4) assess harm. Steps 2–4 are completely unaddressed. The `chainDigest` is a fingerprint for correlation, not reconstruction. The construction would need to explain how `chainDigest` maps to any incident ticket, log entry, or member record ID in systems the examiner actually uses — none of which are on-chain.

- **In-threat-model?** No — the construction must address this. A construction that helps an examiner confirm monotonic narrowing but cannot answer "what happened to member #4471's data on Tuesday" fails the primary NCUA examination use case it claims to serve.

---

### Attack 3: Key Custody Is Missing an Architecture

- **Attack:** I point at Section 2's private inputs table: `delegatorPubkeyAx`, `delegatorPubkeyAy`, `sigR8x`, `sigR8y`, `sigS` — EdDSA signing keys on Baby Jubjub. I ask the construction author: where does the operator private key live between proof generations? The construction does not answer this. FFIEC IT Examination Handbook (Management booklet, §II.B) requires a documented cryptographic key management program: generation in an approved environment, storage in HSM or equivalent, rotation schedule, and revocation procedure. The construction has no key rotation protocol, no revocation mechanism (a nullifier prevents replay but does not revoke a compromised signing key), and no specification of the key storage boundary. If the operator private key lives in a Lambda environment variable or a browser Web Crypto store, my FFIEC examiner will write a finding the moment I describe the architecture. The construction spends 8 sections on circuit constraints and zero words on key management.

- **Why it works / why it fails:** The PLONK soundness argument in Section 4 assumes the operator's EdDSA private key is uncompromised (A3: discrete log hardness on Baby Jubjub). The moment that assumption is operationalized — i.e., the key has to live *somewhere* — the construction inherits all the operational key management requirements it has not specified. The security argument is technically correct but operationally incomplete. Proving `Adv[A] ≤ negl(λ)` does not tell my security team whether to deploy this key in AWS KMS, a Thales HSM, or the agent container's environment.

- **In-threat-model?** No — the construction must address this. Minimum requirement: specify an approved key storage boundary (HSM or cloud KMS with FIPS 140-2 Level 2+), a rotation period that triggers re-enrollment, and a revocation path that does not require re-running the Merkle tree ceremony for all enrolled agents.

---

### Attack 4: The On-Chain Registry Is Not a Core Processor

- **Attack:** I pull out my Vendor Management Policy and the SLA section. The construction deploys `BolyraAuditRegistry.sol` on Base Sepolia (per `bolyra/CLAUDE.md`: "Deploy target chain: Base Sepolia"). Base Sepolia is a testnet. Production would presumably be Base mainnet or equivalent. I ask: what is the SLA? L2 liveness depends on the sequencer (currently operated by Coinbase with no published enterprise SLA), the Ethereum L1 for data availability, and the RPC provider my infrastructure uses to submit and read transactions. My core processor (e.g., Fiserv, Jack Henry) publishes a 99.9% uptime SLA with a regulated incident response procedure. `submitDelegationHop(...)` in Section 2 is a blocking call — if the on-chain registry is unavailable, the pipeline cannot submit hop proofs, which means no `ChainAuditProof` can be generated, which means I cannot demonstrate compliance during an examination. The construction's circuit cost table (Section 6) gives me proving times of < 5s per hop, but says nothing about L2 transaction finality time, gas cost under congestion, or the fallback behavior when the sequencer is down. My board risk appetite does not include "loan pipeline stalls when Coinbase's sequencer has an incident."

- **Why it works / why it fails:** Section 7 presents the deployment scenario as production-ready for Navy Federal with 13M members. The on-chain dependency is treated as a solved infrastructure problem. It is not. For a regulated financial institution, every third-party system dependency requires a Business Impact Analysis, a Recovery Time Objective, and a documented fallback. The construction offers none of these. The FFIEC CAT (Cybersecurity Assessment Tool) Domain 2 requires "resilience planning" for all critical systems. If `BolyraAuditRegistry.sol` is a critical system for loan pipeline compliance, it needs an SLA, a failover architecture, and an answer to "what do ops do when `eth_sendRawTransaction` returns a 503."

- **In-threat-model?** No — the construction must address this. The architecture needs either (a) an off-chain fallback accumulator with deferred on-chain settlement and a defined grace window, or (b) an explicit non-reliance model where on-chain submission is asynchronous and loan pipeline execution is not blocked by registry availability. Neither is present.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Decade of production introspection. ZK is a solution looking for a problem until proven otherwise. Every claim below is sourced to a section of the construction.*

---

### Attack 1: Signed JWT Introspection Response Eliminates the "Offline Artifact" Gap

**Attack:**
Construction §8 ("Why the baseline cannot match") rests on the claim that BBS+ and RFC 7662 cannot produce "a self-contained artifact that the examiner can verify offline, without callbacks to infrastructure controlled by the organizations being audited." This is factually wrong against a modern AS deployment.

Concrete counter-deployment: each RFC 8693 token-exchange hop instructs the AS to issue a `token_type=urn:ietf:params:oauth:token-type:jwt` introspection response per `draft-ietf-oauth-jwt-introspection-response`. The AS signs this JWT with its private key. The AS's JWKS endpoint (`/.well-known/jwks.json`) is fetched once by the auditor at examination time and cached. The auditor then verifies the entire chain of signed JWTs — one per hop — offline using cached keys. No runtime AS callback is required after the initial JWKS fetch, which is O(1) per organization regardless of chain length. For the NFCU four-hop chain (§7), the auditor caches four JWKS endpoints at session start, then verifies offline.

**Why it fails against the construction:**
The construction's threat model (§3, `CrossOrgDistrust` game, condition (c)) excludes "interactive queries to any organization's infrastructure." The JWKS fetch is such a query — it is issued against Experian's and SendGrid's key endpoints. Worse, for a distrusting NCUA examiner (§7), trusting NFCU's AS signing key is circular: NFCU controls the key that signs the attestation that NFCU's delegation was valid. A rotated or backdated NFCU AS key would forge a valid audit trail. The construction's verification path (PLONK vkey + on-chain accumulator) is not controlled by any participant in the chain. This distinction is real and the construction correctly articulates it in §8.

**In-threat-model?** Yes — construction survives. But the construction should cite `draft-ietf-oauth-jwt-introspection-response` by name in §8 and explicitly close this door, since it is the strongest RFC 7662-family counter-argument and the current §8 table does not name it.

---

### Attack 2: Scope Brute-Force via Credential Commitment Leakage from Enrollment Transactions

**Attack:**
Circuit 1 (`DelegationHopAccumulator`, §2) outputs `newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment)` as a **public on-chain value**. The construction claims the scope is hidden, and so it is — if `delegateeCredCommitment` is also unknown to the adversary.

But `delegateeCredCommitment` may not stay hidden. The Bolyra enrollment flow requires each agent to insert its credential commitment as a Merkle leaf in the global agent tree (§2, constraint 8: `BinaryMerkleRoot(20)` against the agent tree). If enrollment transactions are posted on-chain — which they must be to update the Merkle root — the leaf values (credential commitments) are observable in transaction calldata. Once an adversary has `delegateeCredCommitment` from the enrollment transaction, breaking scope privacy is trivial: the 8-bit cumulative permission bitmask (CLAUDE.md, "Permissions Model") has only 256 possible values. Enumerate all 256 candidates, compute `Poseidon2(candidate, knownCredCommitment)`, compare against the on-chain `newScopeCommitment`. One Poseidon evaluation per candidate, 256 evaluations total. Runtime: milliseconds.

Even with a 64-bit bitmask (as used in the circuit signals), the cumulative bit encoding (§2, constraint 8 in `ChainAuditProof`: "cumulative bit encoding on finalScope") dramatically constrains the valid space. Bits 2/3/4 must satisfy implication rules; bits 5/6/7 are independent; effective entropy is well under 2^8. This is not a security parameter.

**Why it fails / why it lands:**
The construction's §4 (Privacy reduction) states: "recovering the scope or credential from the commitment requires inverting Poseidon (breaks A1)." This argument is **only valid when both preimage components are unknown**. If `delegateeCredCommitment` leaks from enrollment, the privacy argument collapses to a 256-element (or smaller) exhaustive search, not a preimage inversion.

The construction does not model enrollment transaction visibility in the threat model (§3) or the security argument (§4). The `IntermediateAnonymity` game (§3) gives the adversary "all public signals, on-chain state, and per-hop `DelegationHopAccumulator` public outputs" — but does not explicitly include enrollment calldata. It should.

**In-threat-model?** No — the construction must address this. Either: (a) prove that enrollment does not expose `credCommitment` on-chain (e.g., enrollment uses a hiding commitment scheme), (b) add a blinding factor to `newScopeCommitment = Poseidon3(delegateeScope, delegateeCredCommitment, scopeBlindingNonce)` with a fresh per-hop nonce, or (c) acknowledge this as a known limitation and bound the privacy guarantee to the case where `credCommitment` is secret.

---

### Attack 3: Chain Length Disclosure Breaks Whistleblower Scenario Anonymity

**Attack:**
`ChainAuditProof` reveals `chainLength` as a public output (§2, Circuit 2, "Public outputs"). Construction §7 ("Whistleblower variant") claims that the journalist's auditor "verifies the chain narrowed correctly" without "learning any intermediary's identity." But `chainLength` is leaked — and in a whistleblower scenario, it is highly deanonymizing.

Concrete attack using RFC 7662 toolbox framing: an auditor playing the role of the adversary (the `DelegationAuditPrivacy` game, §3) receives the proof and observes `chainLength = 3`. In the whistleblower scenario (§7), the adversary knows: (a) the journalist's agent is the terminal hop (public), (b) the document source is constrained to agents enrolled in the tree who have the `READ_DATA` permission on the relevant resource, (c) there are exactly 3 hops. The intersection of "agents with READ_DATA on this resource" × "agents who would plausibly route through exactly 2 intermediaries to reach this journalist" may be very small — potentially a singleton.

Audience-bound tokens (RFC 8707) plus PPIDs already break RS-level linkability for normal OAuth flows — this is the RFC 7662 advocate's point that RFC 7662 + extensions handles the normal case. But in the whistleblower case, the comparison is: RFC 7662 audit logs reveal per-hop scope and identity (bad); Bolyra reveals chain length (better, but not good enough). The construction's §1 claim — "the proof is a single constant-size artifact... without learning any intermediate scope values, participant identities, or the structure of the chain **beyond its length**" — admits this leak but does not quantify its deanonymization risk in the whistleblower context.

**Why it fails / why it lands:**
The construction explicitly acknowledges the leak ("beyond its length") but provides no analysis of whether chain length disclosure is safe in the whistleblower scenario. The `DelegationAuditPrivacy` game (§3) is defined for chains "of equal length" — making the game trivially avoid this issue by construction. This is a game definition artifact, not a security guarantee.

A stronger construction would pad `chainLength` to a fixed public value (e.g., `MAX_HOPS = 16`) or prove `chainLength ∈ {low, medium, high}` via range proof, hiding the exact length. The current `ChainAuditProof` circuit (§2, constraint 9: `chainLength === hopCount`) makes exact length mandatory as a public output.

**In-threat-model?** No — the construction must either (a) add length padding/bucketing, (b) justify why exact length revelation is safe in the whistleblower scenario with a concrete anonymity bound (k-anonymity argument over the agent tree), or (c) remove the whistleblower scenario from the claim scope. The current §7 whistleblower claim is unsupported by the privacy analysis.

---

### Attack 4: The Blockchain Sequencer Is a Trusted Third Party

**Attack:**
Construction §8 claims Bolyra enables the auditor to "trust cryptography, not organizations" and contrasts with BBS+ where "the auditor must trust each issuer's key infrastructure." The verification path is: PLONK vkey (public parameter) + on-chain state (`onChainChainSeed`, `chainAccumulators[sessionNonce]`) on Base Sepolia.

But the on-chain state is controlled by the Base Sepolia L2. Base Sepolia's sequencer is operated by Coinbase. The sequencer can:
- Reorder transactions (affecting which hop proof lands first)
- Censor `submitDelegationHop` calls, forcing a chain to appear shorter than it is
- Apply future upgrades to `BolyraAuditRegistry.sol` if it uses a proxy pattern

More fundamentally, `BolyraAuditRegistry.sol` (§2, "On-chain components") has no stated immutability guarantee. If it uses an upgradeable proxy (standard Hardhat deploy practice), the contract admin key can rewrite `chainAccumulators` mappings retroactively. This is exactly the "auditee controls the infrastructure" problem the construction attributes to BBS+: NFCU deploys `BolyraAuditRegistry.sol` on Base Sepolia — if NFCU holds the proxy admin key, NFCU can modify the on-chain state.

Contrast: an NIST-certified AS operated by a CU trade association (e.g., CUNA Mutual) under NCUA supervision, issuing signed JWT introspection responses, has **more** regulatory accountability and **clearer** key governance than a Coinbase-sequenced L2 contract with an unspecified upgrade policy. The RFC 7662 advocate's position: "you've replaced my AS trust assumption with a blockchain sequencer trust assumption and haven't improved the trust model for a regulated institution."

**Why it fails / why it lands:**
The construction partially survives: even an upgradeable contract's *historical* on-chain state is cryptographically committed in the L2 block hash, and the PLONK proof binds to the state at a specific block. A retroactive rewrite by NFCU would require rewriting L2 history, which requires compromising Base Sepolia's consensus — a much higher bar than rotating an AS signing key.

However, the construction does not make this argument. It states only that on-chain state is "publicly readable" (§4), not that it is immutable or that the contract lacks upgrade keys. The threat model (§3, `CrossOrgDistrust`) requires "no single trusted third party was consulted during verification" — the Coinbase sequencer is a single party that must be trusted to not have rewritten the state. 

**In-threat-model?** Partially — the construction must address (a) the contract upgrade key governance (commit to a `renounceOwnership()` or timelocked multisig after deployment), (b) explicitly acknowledge the L2 sequencer trust assumption and argue it is weaker than per-organization key trust (the argument exists but is not made), and (c) clarify that the Base Sepolia state referenced in the audit proof is block-hash-anchored so retroactive rewrites are detectable. Without this, a regulator's counsel will ask "who controls that contract?" and the answer is currently silence.


## Persona: spiffe_engineer

*Staff engineer, SPIFFE/SPIRE production operator, WIMSE draft co-author. Stance: you are reinventing workload identity at the wrong layer.*

---

### Attack 1: WIMSE Already Has This — You Are a ZK Attestor Plugin, Not a Protocol

**Attack:**
The WIMSE architecture (`draft-ietf-wimse-arch`) already specifies workload-to-workload token binding with a delegation chain model. Section 4 of the WIMSE draft defines a Workload Identity Token (WIT) exchange where a caller workload presents its SVID + a token, the callee returns a bound token for the next hop, and the chain is auditable end-to-end. The proposed `DelegationHopAccumulator` is functionally a ZK attestor plugin for SPIRE (which already has a plugin API for custom attestors) wired to a WIMSE token exchange endpoint. The `ChainAuditProof` is WIMSE's audit log requirement, just with a ZK twist instead of signed audit tokens.

The construction (§2) never addresses WIMSE. The baseline comparison (§8) attacks BBS+ commit-and-prove — a credential-layer primitive — but WIMSE is an infrastructure-layer protocol, which is the right comparison. A ZK attestor that emits a scope commitment instead of a JWT SVID could slot into SPIRE's attestor interface today. Why is this a new protocol and not `spiffe://bolyra.ai/zkp-attestor`?

**Why it works / fails:**
The construction partially survives on the cross-org distrusting-auditor argument: WIMSE still requires the auditor to trust each organization's SPIFFE trust domain and its SVID issuer keys, which is the same circular-trust problem as BBS+. WIMSE federation (`spiffe://org-a/...` → `spiffe://org-b/...`) requires explicit trust bundle exchange between domains — the auditor must trust each domain's bundle. The `ChainAuditProof` does eliminate this by reducing to a single universal verification key.

However, the construction must explicitly show that its primitives cannot be expressed as an extension to WIMSE without a new protocol. As written, this gap is addressed only against BBS+, not against WIMSE + ZK attestor extensions currently in scope for the WIMSE working group.

**In-threat-model?** Partially. The distrusting-auditor property survives; the protocol-layer justification does not. **Construction must address this.**

---

### Attack 2: Enrollment Governance Hole — The Merkle Tree Has No Attestation Root

**Attack:**
The `delegateeMerkleRoot` is the anonymity set underpinning the entire privacy claim. The whistleblower scenario (§7) asserts k-anonymity: "the tree contains thousands of agents, providing k-anonymity." The `IntermediateAnonymity` game (§3) is defined against an adversary who can't identify which leaf corresponds to which agent.

But the construction never specifies **who inserts leaves into the enrollment tree**, **what attestation is required at enrollment time**, or **who controls the tree's write authority**. In SPIRE, a SPIRE server attests a workload before issuing its SVID — using TPM-bound keys, AWS EC2 instance identity documents, or GCP service account tokens. The attestation chain runs from hardware to identity. In Bolyra, enrollment is "operator inserts `credentialCommitment` into the Merkle tree." An operator IS a participant in the delegation chain. If NFCU controls enrollment for its agents, NFCU can insert a fake leaf for an agent it never actually deployed, pre-build a valid `DelegationHopAccumulator` proof for that leaf (all constraints satisfied — it's a real enrolled agent), and anchor a synthetic hop in the chain.

More specifically: the `DelegateeMerkleRoot` revealed per-hop is the global agent enrollment root. If NFCU controls enrollment for the Experian and SendGrid agents (because it delegated to them using keys it manages), then the examiner's k-anonymity set is "all agents NFCU chose to enroll." That's not thousands of independent agents — it's agents under NFCU's key management. The anonymity set collapses to whatever the operator controls.

**Why it works / fails:**
The privacy reduction in §4 correctly argues that Poseidon is one-way over committed values. But one-wayness of the commitment doesn't help if the operator who controls enrollment also controls the committed values. The cryptographic argument is sound; the trust assumption is not stated. The `IntermediateAnonymity` game assumes the adversary cannot identify which leaf is which, but the adversary in the NCUA scenario IS the operator (NFCU controls enrollment). The game definition excludes this case by saying "A controls up to n-1 of n participants" — but enrollment governance is not a participant in the protocol; it is a precondition that the construction leaves to "the operator."

**In-threat-model?** No. **Construction must state enrollment attestation requirements** (who can insert leaves, what attestation is required, what prevents an operator from pre-enrolling synthetic agents) or explicitly bound the anonymity claim to "anonymity within the set of independently-attested agents."

---

### Attack 3: `ChainAuditProof` Is Not Anchored to On-Chain State Without an Unspecified Contract Check

**Attack:**
The `ChainAuditProof` circuit (§2, Circuit 2) takes `finalAccumulator` as a **private input**. The public output `chainDigest = Poseidon2(finalAccumulator, sessionNonce)` is published. On-chain, `chainAccumulators[sessionNonce]` holds the accumulated value after all submitted hops.

The circuit has no constraint of the form:
```
finalAccumulator === chainAccumulators[sessionNonce]
```

That binding can only happen in Solidity. The on-chain component description (§2) says `verifyChainAudit(...)` "verifies ChainAuditProof PLONK proof, emits `ChainAudited(...)`" but does not specify that the contract checks:
```solidity
require(Poseidon2(chainAccumulators[sessionNonce], sessionNonce) == proof.publicOutputs.chainDigest);
```

Without this explicit Solidity-side check, a prover who has legitimate access to a real chain's private values (e.g., the root delegator knows everything) can synthesize a `ChainAuditProof` over a **different, fabricated accumulator trace** that is internally consistent (constraints 3–5 pass) but does not correspond to the hops actually submitted on-chain. The `onChainChainSeed` constraint (constraint 1) binds the start of the chain, but does not bind the end. The audit proof passes, emits `ChainAudited`, and the examiner sees a valid proof — over a chain that was never executed.

The `DelegationAuditSoundness` game reduction (§4) identifies the on-chain `chainAccumulators[sessionNonce]` as the anchor, but the circuit-to-contract binding that enforces this anchor is absent from the specification.

**Why it works / fails:**
This does not break PLONK knowledge soundness or Poseidon. It exploits the gap between the circuit's constraint system and the contract's verification logic. In the SPIFFE model, the equivalent would be: the SVID validation happens in the sidecar, and the audit log records SVIDs — but there's no cryptographic binding between "SVID validated by sidecar" and "audit log entry." SPIRE closes this by having the SPIRE agent sign audit events with its node SVID; the construction has no equivalent final-accumulator-to-on-chain binding that is cryptographically enforced in-circuit.

**In-threat-model?** Yes if the Solidity contract implements the Poseidon check (which is implied but not stated). **Construction must explicitly add Constraint 0 to `ChainAuditProof`:**
```
chainDigest === Poseidon2(onChainFinalAccumulator, sessionNonce)
```
with `onChainFinalAccumulator` as an additional public input read from `chainAccumulators[sessionNonce]`.

---

### Attack 4: `hopIndex` Is Private and the Contract Cannot Enforce Sequential Submission

**Attack:**
`hopIndex` is a **private input** to `DelegationHopAccumulator`. The contract `submitDelegationHop(...)` updates `chainAccumulators[sessionNonce]` based on the proof's public output `newAccumulator = Poseidon3(previousAccumulator, newScopeCommitment, hopIndex)` — but `hopIndex` is private. The contract has no way to verify that the prover used `hopIndex = k` for the k-th submitted hop.

A prover controlling two hops can submit them in any order with any `hopIndex` values they choose. For example: submit hop A with `hopIndex = 0` and hop B with `hopIndex = 2` (skipping 1). The on-chain accumulator becomes `Poseidon3(Poseidon3(0, seed, 0), scope_B, 2)`. When `ChainAuditProof` reconstructs with `hopCount = 2`, constraint 4 uses sequential `i`: `accumulatorTrace[1] = Poseidon3(accumulatorTrace[0], scopeCommitmentTrace[1], 1)` — which does NOT match `Poseidon3(acc_0, scope_B, 2)`. So this particular attack fails to produce a valid `ChainAuditProof`.

However, the attack surface is that **the prover must coordinate `hopIndex` values between `DelegationHopAccumulator` submissions and `ChainAuditProof` reconstruction**, and this coordination requirement is **implicit and unenforced**. Nothing in the contract prevents submitting hops with non-sequential `hopIndex` values. If a prover does this (intentionally or by implementation bug), the `chainAccumulators[sessionNonce]` value becomes one that NO valid `ChainAuditProof` can be produced for — the chain is permanently unauditable. In a real pipeline with multiple agents submitting hops (§7: Experian agent submits hop 2, SendGrid submits hop 3), there is no protocol-level enforcement that agents use the correct sequential `hopIndex`. A misbehaving or buggy Experian agent submitting with a wrong `hopIndex` silently corrupts the chain's auditability.

In SPIFFE, the equivalent is sequence number enforcement in SVID rotation — handled by the SPIRE server with server-side state. The construction offloads this to the prover with no server-side guard.

**Why it works / fails:**
The construction survives the soundness game (a fabricated valid audit proof cannot be produced with non-sequential hops). But it introduces a **liveness failure mode**: a single misbehaving hop agent permanently prevents a valid `ChainAuditProof` from being generated for that session. This is not covered by the threat model, which focuses on soundness and privacy but not on audit liveness.

**In-threat-model?** Partially. Soundness is preserved; liveness under misbehaving hop agents is not addressed. **Construction should add**: a public input `expectedHopIndex` to `DelegationHopAccumulator` (enforced by the contract as a monotonic counter per `sessionNonce`), or add `hopIndex` as a public output and have the contract verify it matches the expected sequence number.
