# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Latency Tax Nobody Will Pay at Scale

- **Attack:** Section 6 claims rapidsnark proves in < 0.5 s server-side. That sounds acceptable until you model a real agent workload. A loan-underwriting agent at a credit union makes dozens of API calls per session — member lookup, transaction pull, risk-scoring API, compliance check, wire validation. At 0.5 s per proof, a 20-call session burns 10 seconds of pure proof generation *before any network time*. WorkOS issues a token in < 100 ms and it's reusable across calls within the TTL. The construction's "no AS roundtrip at presentation time" framing obscures that it trades network latency (fast, amortized) for compute latency (slow, per-call). Section 7's deployment scenario mentions CU-A's fraud-detection agent calling `/member/transactions` — but a fraud-detection agent makes *many* calls per detection event, not one.

- **Why it works / why it fails:** The construction does not address per-session call multiplicity anywhere. It presents one proof as the unit of work. For stateless, high-frequency agentic workloads, that's a 5–50× latency regression vs. bearer tokens. The construction could add a session-level token derived from a single proof, but that is not specified and re-introduces the AS-style issuance it claims to eliminate.

- **In-threat-model?** No — the construction must address amortized proof cost across multi-call agent sessions, or explain how a session-proof reduces to O(1) proofs per session rather than O(calls).

---

### Attack 2: On-Chain Root Dependency Is an Operational SLA Nobody Will Sign

- **Attack:** Step 5 of the verification protocol (Section 2, "Verification protocol") requires the RS to check `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`. This mandates that every RS either runs a Base node, pays for an RPC provider, or trusts a Bolyra-operated oracle — introducing a liveness dependency on a blockchain. When I'm selling WorkOS to a CISO at a credit union, I promise 99.99% uptime backed by a SLA and a support contract. The on-chain dependency means: Base Sepolia/mainnet congestion, RPC provider outage, or a gas spike during a market event can silently break agent authorization. The 30-root buffer in Section 5 adds another failure mode: if the CUSO enrolls many agents and root updates are frequent, proofs generated against root N may become invalid by the time they arrive at the RS if 30 newer roots have been published. Section 7 does not address what happens to in-flight agent proofs during root rotation.

- **Why it works / why it fails:** The construction assumes the on-chain root is always reachable and that the 30-root buffer window is never exceeded during normal operation. Neither assumption holds under adversarial or high-load conditions. The construction's adversarial-AS resilience property is compelling on paper, but it is achieved by *replacing* AS trust with *blockchain trust* — and blockchains have different (not lower) operational risk profiles for regulated financial institutions that are not already on-chain.

- **In-threat-model?** No — the construction must specify RS liveness guarantees, fallback behavior when the chain is unreachable, and a bound on root update frequency relative to the 30-root buffer to prevent proof expiry in normal operation.

---

### Attack 3: Enrollment Complexity Kills Developer Adoption Before Procurement Starts

- **Attack:** The construction's enrollment protocol (Section 2, gadget 4 and the "Enrollment protocol change" paragraph) requires the agent to: (1) generate a local `blindingFactor` from a cryptographically secure RNG, (2) compute `credentialCommitment = Poseidon5(...)`, (3) compute `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, (4) submit `leafCommitment` on-chain, (5) obtain an operator EdDSA signature over `credentialCommitment` (via a separate channel, since the operator must not see `blindingFactor`), and (6) store `(blindingFactor, sig, merkleProof, ...)` as durable private credential material. If that credential material is lost, the agent is permanently unable to prove enrollment — Section 7 says revocation is "removing the blinded leaf," but recovery from key loss is not addressed. Auth0's MCP auth onboarding is: register a client, paste a client secret, done. The Stytch flow is comparable. My enterprise buyer's developer experience benchmark is `curl -X POST /oauth/token` — not "implement a Poseidon hash and submit a leaf to a Base Sepolia contract."

- **Why it works / why it fails:** The construction is technically sound but imposes a key management burden with no analog in the OAuth stack. The `blindingFactor` is a new category of secret the agent must generate and store durably — separate from the operator's signing key, separate from the credential itself, and unrecoverable if lost. The construction makes no mention of key storage guidance, HSM integration, or backup schemes. For an enterprise deploying 1,000 agents across 200 CUs, this is a credential management surface larger and more novel than anything the OAuth stack requires.

- **In-threat-model?** No — the construction must address `blindingFactor` loss recovery, secure storage guidance, and the developer onboarding path. A "five-line quickstart" (referenced in the git status as `tier2_004_sdk_designer_five_line_quickstart`) cannot abstract away key management for a secret this critical to the security model.

---

### Attack 4: The Revocation Latency Gap Undermines the Regulated Deployment Scenario

- **Attack:** Section 7 states revocation is "handled by updating the Merkle tree (removing the blinded leaf)." This is a blockchain transaction. In the CUSO scenario with 200 member CUs, if CU-A's fraud-detection agent is compromised at 9:00 AM, the CUSO must: submit a Merkle update transaction on Base, wait for finality (seconds to minutes depending on network), wait for the new root to enter the 30-entry history buffer on-chain, and ensure RSes refresh their root view before accepting proofs. During this window — which could be minutes — the compromised agent continues to prove valid membership because the *old* roots remain in the history buffer. Auth0 revokes a token in the time it takes to write to Redis: < 10 ms, globally propagated. Section 3's adversary model explicitly states the adversary controls "the network between agent and RS" and "up to N-1 of N enrolled agents' credential material" — but the window between compromise detection and effective revocation is not bounded, and the construction provides no emergency revocation mechanism faster than on-chain finality.

- **Why it works / why it fails:** The construction's adversarial-AS resilience is genuine, but it is achieved by anchoring trust in on-chain state, which has inherently slower write latency than an in-memory revocation list. The 30-root history buffer is a deliberate design choice to handle root rotation during proof generation, but it creates a revocation window of at least 30 root-update intervals. The construction does not specify the minimum or maximum root update frequency, so the revocation window is unbounded in the worst case. A CUSO compliance officer asking "how quickly can I revoke a compromised agent?" does not have an answer from this construction — and "as fast as the blockchain" is not acceptable for a regulated entity under NCUA §701.27.

- **In-threat-model?** No — the construction must specify the revocation latency bound (in wall-clock time, not "root updates"), the emergency revocation path for high-severity compromise events, and whether the 30-root buffer can be configured smaller to tighten the revocation window at the cost of proof generation reliability.


## Persona: cryptographer

Reading this construction carefully. The blinding-hardened additions are a genuine improvement over the prior version. The SP game is correctly updated to reflect operator=AS collusion. But several gaps remain unaddressed. Here are four attacks in increasing order of severity.

---

### Attack 1: SP Game Uses Challenger-Chosen Nonce; Deployment Gives Nonce to RS

**Attack:** The SP game (§3) specifies "Challenger flips coin c, generates proof πc for agent c **with a fresh sessionNonce chosen by the challenger**." In the actual deployment protocol (§2, Verification Protocol, step 1), it is the **RS** that generates `sessionNonce`. These are not the same party. A malicious or semi-honest RS chooses correlated nonces across multiple proof requests to the same agent — for example, nonces that are deterministic functions of a suspected agent identity, or nonces with structured algebraic relations to the CRS.

**Why it matters:** Groth16 achieves **honest-verifier zero-knowledge (HVZK)**, not malicious-verifier ZK. HVZK guarantees simulation only when the verifier's challenge (here: `sessionNonce`) is chosen uniformly at random, independently of the witness. The HVZK simulator requires control of the randomness used to generate the proof. When the verifier (RS) chooses `sessionNonce`, the simulator must reprogram this — which is impossible in a setting where the RS is the distinguisher in the SP experiment.

The construction invokes "A6: Zero-knowledge property of Groth16/PLONK" in the SP reduction (§4, step 6: "by A6 (Groth16 zero-knowledge), the proof π itself reveals nothing about the witness beyond the public signals"). This claim is only valid when `sessionNonce` is honestly generated. If the RS chooses `sessionNonce = H(agentSuspect_ID || counter)` for each suspected agent and observes the resulting `nullifierHash`, it runs a transcript distinguishing test that the HVZK simulator cannot simulate because the simulator would need to know the RS's correlated nonce strategy in advance.

**In-threat-model?** No — the construction must either (a) require the RS to prove its nonce is uniformly random (commit-then-reveal with RS's nonce commitment before agent receives it, plus agent's own nonce contribution so the combined nonce is random whenever at least one party is honest), or (b) upgrade A6 to full **malicious-verifier ZK** (simulation-extractable SNARK) and prove the ZK property holds under adversarially chosen public inputs. Neither is present in the current spec.

---

### Attack 2: Groth16 Non-Simulation-Extractability Breaks Delegation Chain Soundness Under Composition

**Attack:** The construction's delegation chain (§2, Gadget 10, "Delegation Chain Impact") chains `scopeCommitment` values across hops: `Poseidon4(delegatorScope, delegatorCredCommitment, delegatorBlindingFactor, previousSessionNonce) == previousScopeCommitment`. An adversary who observes a valid delegator proof π₁ attempts to produce a forged delegatee proof π₂ that references `previousScopeCommitment` from π₁ while embedding a different `delegatorBlindingFactor'` or inflating `delegatorScope`.

**Why it works / fails:** Groth16 is **knowledge-sound** (§4, A1) but **not simulation-extractable**. Knowledge soundness guarantees that a PPT prover who produces an accepting proof must "know" a witness — but only in the **single-proof, non-adaptive** setting. It does not guarantee that an adversary who receives an oracle of valid proofs cannot maul a proof into one that verifies for a different statement. In particular:

- Groth16's proof structure is `π = (A, B, C)` where `C = (αβ/γδ) * (witness_contribution) * (r·δ·A + s·δ·B − rs·δ)`. Given π, an adversary can compute π' = (sA, B/s, C + rs·δ^{-1}) for random s, r that re-randomizes the proof for the **same statement** — this is the well-known Groth16 malleability. More critically, in the delegation context, if the adversary sees π₁ and constructs a "related proof" π₂ via the algebraic structure of the CRS, the multi-proof SSU game does not reduce to single-proof knowledge soundness.

The SSU game (§3) is defined in a single-forgery model: "A outputs (π*, pubSignals*) for a requiredScopeMask*." The reduction sketch (§4) extracts one witness from one proof. In a delegation chain with k hops, the adversary sees k valid proofs in the query phase and targets a forgery that links them. The single-proof extraction argument does not compose to give k-hop soundness without **simulation-extractability**, which requires an extractor that works even when the adversary has seen prior valid proofs for related statements.

**In-threat-model?** No for single-hop SSU (the construction survives here). No for multi-hop delegation chains — the construction must either cite a simulation-extractable SNARK (e.g., Groth16 wrapped with a Fiat-Shamir transformation in ROM to achieve SE, as in Boneh et al.) or restrict the delegation depth to 1 and re-prove soundness under the resulting limited game.

---

### Attack 3: Enrollment Integrity Gap — No ZKPoK Links `leafCommitment` to Operator-Signed `credCommitment`

**Attack:** §2 (Gadget 4, "Blinded Leaf Commitment") specifies the enrollment protocol: "the agent computes credentialCommitment as before, then computes leafCommitment = Poseidon2(credentialCommitment, blindingFactor) locally and submits only leafCommitment to the on-chain registry for Merkle insertion." 

The operator's EdDSA signature covers `credentialCommitment`, **not** `leafCommitment`. The registry receives only `leafCommitment`. **No proof is specified** that `leafCommitment` is well-formed — i.e., that there exists some `credCommitment` with a valid operator signature such that `leafCommitment = Poseidon2(credCommitment, blindingFactor)`.

**Why it works:** Without such a proof, any party can submit an arbitrary field element as a "leaf" to the registry. The Merkle tree grows with adversarial leaves that do not correspond to any operator-signed credential. Now consider the SSU game (§3): the reduction (step 7) argues that if `leafCommitment' = leafCommitment*` (the honest agent's blinded leaf), then Poseidon collision resistance gives `credCommitment' = credCommitment*` and hence `permissionBitmask' = permissionBitmask*`. But this argument assumes `leafCommitment*` was correctly computed as `Poseidon2(credCommitment*, blindingFactor*)`. If the adversary enrolled a maliciously crafted `leafCommitment†` that happens to equal some `Poseidon2(credCommitment†, x)` for a crafted `credCommitment†` with inflated permissions — and if the registry accepted this enrollment without verifying operator signature over `credCommitment†` — then the adversary has a valid Merkle path for a fraudulent credential.

Concretely: the adversary chooses target permissions `permBitmask†` (e.g., all 64 bits set), computes `credCommitment† = Poseidon5(modelHash†, ...)` with desired parameters, then picks random `blind†`, sets `leafCommitment† = Poseidon2(credCommitment†, blind†)`, and submits `leafCommitment†` to the registry. Since no operator signature over `credCommitment†` is verified at enrollment time, the leaf is accepted. The adversary now has Merkle membership for an uncredentialed leaf.

The SSU game's forgery condition (step 4) only requires the proof to verify against "a valid root containing the honest agent's blinded leaf." If the adversary's fraudulent leaf is in the **same tree** as the honest agent, the Merkle root check passes.

**In-threat-model?** No — this is an enrollment integrity attack that the construction must address. The fix is to require a **zero-knowledge proof of knowledge** at enrollment time: the agent submits `(leafCommitment, enrollmentProof)` where `enrollmentProof` proves knowledge of `(credCommitment, blindingFactor)` such that `leafCommitment = Poseidon2(credCommitment, blindingFactor)` and there exists a valid operator EdDSA signature over `credCommitment`. This proof is verifiable by the registry contract without learning `blindingFactor` or the full credential. Without this, the enrollment protocol is fundamentally broken regardless of the circuit's correctness.

---

### Attack 4: RS-Controlled `currentTimestamp` Breaks Expiry Enforcement

**Attack:** `currentTimestamp` is a **public input** provided by the RS at proof request time (§2, Verification Protocol step 2: "Agent receives (requiredScopeMask, currentTimestamp, sessionNonce) as public inputs"). The circuit enforces `LessThan(64)(currentTimestamp, expiryTimestamp)` (Gadget 8). The RS's verification step (§2, step 5d) checks only that "`currentTimestamp` is within acceptable clock skew (e.g., ±30 seconds)."

**Why it works:** The threat model (§3) states the adversary controls the AS but does NOT explicitly enumerate the RS as a trusted party. In the CUSO deployment scenario (§7), 200 member credit unions operate RS endpoints. A compromised RS endpoint that wishes to accept a credential belonging to an agent whose enrollment was revoked (leaf removed from Merkle tree) at time T_revoke has two options:

1. **Old root attack:** Use a `sessionNonce` that points to a pre-revocation Merkle root still in the 30-entry history buffer. The construction handles this: after ~30 root updates, old proofs fail the root membership check. But the construction doesn't bound **how often roots update** — if update frequency is operator-controlled, a colluding operator can slow root updates to extend the revocation window indefinitely.

2. **Past-timestamp attack:** Set `currentTimestamp` to a value before `expiryTimestamp` even though the credential has expired in wall-clock time. The RS's ±30-second clock skew check is self-policed — a malicious RS simply doesn't enforce it. The circuit has no oracle binding `currentTimestamp` to actual blockchain state or a trusted timestamp source. Expiry enforcement is entirely dependent on RS honesty.

Neither the SSU game nor the SP game includes a game-winning condition for accepting expired credentials. The threat model says the adversary controls "the AS" but is silent on RS compromise. In a federated 200-CU deployment, treating all RS endpoints as honest is an architectural assumption that must appear explicitly in the threat model.

**Formal statement:** Define a game `EXP(λ)` analogous to SSU: adversary wins by obtaining RS acceptance of a proof (π*, pubSignals*) where `expiryTimestamp* < T_real` (real wall-clock expiry has passed). Under the current construction, A wins EXP with probability 1 if it controls the RS and sets `currentTimestamp* < expiryTimestamp*`. The construction provides no defense against this because `currentTimestamp` carries no authenticated binding to an external time source inside the circuit.

**In-threat-model?** No — the construction must either (a) bind `currentTimestamp` to an on-chain block timestamp and verify this inside the Solidity verifier (not just in the circuit), or (b) explicitly add RS honesty to the trusted party set in §3 and limit security claims accordingly. The current framing claims "adversarial-AS-resilient" but implicitly assumes RS honesty for liveness and expiry — a gap that must be stated formally or closed with an on-chain timestamp oracle.

---

### Summary

| Attack | Section(s) Cited | In-Threat-Model? | Fix Required |
|--------|-----------------|-----------------|-------------|
| 1: SP game uses challenger nonce; RS controls nonce in deployment | §2 (verification protocol), §3 (SP game), A6 | No | Commit-reveal nonce protocol or upgrade to malicious-verifier ZK |
| 2: Groth16 non-SE breaks multi-hop delegation chain soundness | §2 (gadget 10), §4 (SSU reduction) | No (multi-hop) | Cite SE-SNARK or prove bounded delegation with single-proof soundness |
| 3: No ZKPoK at enrollment — fraudulent leaves accepted by registry | §2 (gadget 4), §4 (SSU reduction step 7) | No | Require enrollment ZKPoK over (credCommitment, blindingFactor) |
| 4: RS-controlled `currentTimestamp` trivially bypasses expiry | §2 (gadget 8, verification protocol), §3 (threat model) | No | Bind timestamp to on-chain block or add RS to trusted party set |


## Persona: cu_ciso

---

### Attack 1: The Blinding Factor Is a New Secret — Who Holds It, Under What Controls?

- **Attack:** Section 2 establishes that `blindingFactor` is "generated locally by the agent and never disclosed to the operator or AS." It is the agent's sole private value independent of the operator. It lives in — what, exactly? The construction says it is part of "the agent's private credential material alongside the EdDSA signature components" but never names a custody mechanism. When I ask my vendor management team to fill out our Third-Party Vendor Management questionnaire (NCUA Letter to FCUs 07-CU-13, Third-Party Relationship Risk Management), the question will be: "Describe the key management controls for all secrets required to operate this system." The construction has no answer. The `blindingFactor` is either stored in the agent runtime (ephemeral — lost on restart, no BCP), in a key management system (a new dependency, a new vendor, a new examination surface), or hardcoded (catastrophic). If it is lost, the on-chain `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` is a permanent orphan — the agent can never again prove Merkle membership. Recovery requires re-enrollment, which requires the operator to re-sign a new `credentialCommitment`. The construction documents this nowhere. NCUA Part 748 Appendix A requires documented security programs with defined access controls, change management, and incident response. The `blindingFactor` is a critical secret material with no control specification. This is a Program gap that fails the administrative safeguards prong of GLBA §501(b) (16 CFR Part 314.4(c) — access controls) before a single examiner looks at the cryptography.

- **Why it works / fails:** The construction's privacy argument *requires* the blindingFactor to be secret, unrecoverable by the operator, and persistent across the agent's lifetime. These three requirements are in tension with standard key management practices (HSM escrow, split knowledge, dual control) that NCUA examiners expect. The construction does not address this tension at all.

- **In-threat-model?** No — the construction treats `blindingFactor` generation as an enrollment-time atomic action with no lifecycle. The loss, rotation, backup, and audit logging of `blindingFactor` are entirely unaddressed. Construction must specify a key management profile that maps to NIST SP 800-57 Part 1 Rev. 5 (or equivalent) and can be validated in a NCUA IT examination.

---

### Attack 2: The Audit Trail You Built to Protect Privacy Fails the Incident Response Examination

- **Attack:** Section 7 asserts regulatory value: "NCUA examiners can audit the on-chain enrollment registry (verifying that CUs are enrolling agents with proper operator signatures) *without being able to correlate enrollment entries with individual API access events.*" The construction then adds — correctly — that "even a subpoena for on-chain data *and* operator records does not reveal which enrolled agent made which API call" without the agent's `blindingFactor`. This is a privacy feature. It is also an examiner nightmare. NCUA Part 748 requires an Information Security Program that includes, per the FFIEC Information Security Booklet (Nov 2006, updated 2016), Section III.C: "logging sufficient to support incident response, including the ability to reconstruct events." When my fraud detection agent accesses the CUSO platform and the CUSO later reports a breach under NCUA Part 748.1(f) notification requirements, my incident response team needs to answer: which of my agents accessed member PII, when, and what did it do? The construction's answer is: correlate `nullifierHash` back to an agent requires that agent's `blindingFactor`. If the agent runtime is the breach source, `blindingFactor` is the attacker's first target. If the agent runtime is destroyed, `blindingFactor` is gone. The audit trail is permanently irreversible. My NCUA examiner reviewing the post-breach examination under NCUA's Cyber Incident Response Assessment (updated 2023) will ask for a full access log. I cannot provide one without a `blindingFactor` recovery mechanism that the construction explicitly prohibits (it would break the SP game). This construction makes privacy and audit defensibility mutually exclusive by design, and Section 7 hand-waves the tension away by citing the wrong NCUA section (§701.27 governs incidental powers of federal credit unions, not third-party due diligence — the correct citation is NCUA §741.11, NCUA Regulation Part 741, and the NCUA Third-Party Relationships Supervisory Guidance 2021-04).

- **Why it works / fails:** The construction correctly identifies that `blindingFactor` disclosure under legal process is per-agent without compromising others. But this requires a custody architecture (the agent must be able to produce its `blindingFactor` on demand under legal process), which contradicts the "generated locally by the agent, never disclosed" design. You cannot have forensic recoverability and cryptographic non-linkability from the same secret simultaneously unless you introduce a third party (e.g., a court-accessible key escrow) — which the threat model treats as an adversary.

- **In-threat-model?** No. The construction's threat model (§3) does not include the CU's own compliance and incident response obligations as constraints. A construction that achieves AS-blindness and operator-privacy at the cost of NCUA-required audit reconstructability is not deployable at a regulated institution. Construction must either (a) specify a `blindingFactor` escrow mechanism compatible with FFIEC audit log requirements, or (b) acknowledge that this property requires a regulatory exception process and document what that looks like.

---

### Attack 3: Base L2 Sequencer Is a Single Point of Failure Against Which I Have No Contractual Recourse

- **Attack:** The RS verification protocol (§2, step 5) requires checking `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`. The on-chain registry is deployed on "Base Sepolia, graduating to Base mainnet" (§7). The Base sequencer is operated by Coinbase. The 30-root history buffer provides a sliding window — if the registry is not updated within that window's time equivalent, an agent with a valid credential whose root has aged out of the buffer cannot present a valid proof until a new root is published. This is availability-coupled authorization: my agent's ability to call the CUSO platform depends on Coinbase's sequencer uptime, Ethereum L1 finality (~12-minute economic finality for Base bridge settlement), and the frequency of Merkle root updates on-chain. FFIEC CAT (Baseline, Access Management Domain, Maturity Level 1) requires that "access to systems and data" have defined availability requirements. NCUA's Supervisory Letter on Cybersecurity (various examiner questionnaires since 2015) specifically asks about concentration risk in critical third parties. Base mainnet is a single sequencer. The Base sequencer has no published SLA, no contractual relationship with my credit union, and no SSAE 18 SOC 1 or SOC 2 Type II report that I can attach to my vendor management file. My core processor (Symitar, Corelation, Fiserv DNA) has a contractual 99.9% SLA and an annual SOC 2 Type II report my examiners accept. "We trust the Ethereum L2 ecosystem" is not a vendor management artifact.

- **Why it works / fails:** The construction does not model sequencer downtime or L2 reorganization in the threat model. The 30-root history buffer is presented as a latency accommodation (§2.1: "last 30 roots"), not as an availability mechanism. There is no discussion of what happens when the root history buffer does not contain any valid root — whether because the sequencer is down, the registry smart contract has a bug, or the L2 is undergoing a fork. In that event, all agent authorizations fail simultaneously across all 200 member CUs in the federated scenario. The construction's "Adversarial-AS-resilient" property — achieved by replacing AS trust with on-chain root trust — trades one single point of failure (AS) for another (L2 sequencer + registry contract), while the former has a contract and a SOC 2 and the latter does not.

- **In-threat-model?** No. The L2 sequencer and on-chain registry are entirely outside the threat model. Construction must address: (a) root history buffer sizing relative to L2 availability targets, (b) fallback behavior when the buffer contains no valid root, (c) the vendor management artifact (or lack thereof) for Base mainnet, and (d) whether a permissioned or consortium chain would be more appropriate for a regulated financial deployment.

---

### Attack 4: The FFIEC CAT Has No Checkbox for This — My Examiner Cannot Give Me Credit

- **Attack:** The construction's entire regulatory value proposition (§7, final paragraph) rests on the assertion that this design satisfies NCUA §701.27 and GLBA §501(b). The §701.27 citation is wrong (§701.27 is NCUA's incidental powers rule governing what activities federal credit unions may engage in — it has nothing to do with third-party due diligence or security programs; the relevant authority for the CUSO scenario is NCUA §712, which governs CUSOs, and NCUA Supervisory Guidance 2021-04 on Third-Party Relationships). The GLBA §501(b) citation is defensible but incomplete — §501(b) requires the FTC/NCUA to establish safeguard standards, and the operative controls are in 16 CFR Part 314 (the Safeguards Rule as amended December 2021), specifically §314.4(c)(3) which requires access controls to "limit access to customer information only to those who need it," and §314.4(f) which requires "monitoring and testing" of the information security program. Neither of these maps to a ZKP-based authorization scheme in any existing examiner questionnaire, FFIEC IT Examination Handbook module, or NCUA examination procedure. When my IT examiner opens the FFIEC IT Examination Handbook — Information Security module and reaches the section on Access Controls, there is no evaluation procedure for "cryptographic proof of permission bitmask predicate satisfaction." The examiner will ask: do you have an access control policy? Does it enumerate who (or what) can access member data? Is it reviewed annually? The Bolyra construction provides a cryptographic mechanism for enforcement, but provides zero mapping to the administrative and documentation controls that make an NCUA examination passable. An examiner who cannot evaluate a control cannot give the credit union credit for it — which means the control effectively does not exist from an examination outcome perspective, regardless of its technical soundness.

- **Why it works / fails:** The construction is technically sophisticated but regulatorily unanchored. Every claim in §7 ("NCUA examiners can audit," "GLBA §501(b) safeguard requirements") would require the credit union's CISO to write a novel control mapping document, get it reviewed by NCUA's Office of Examination and Insurance, and potentially wait for examination guidance to catch up to the technology. This is a 3–5 year regulatory horizon, not a deployment timeline.

- **In-threat-model?** No. The construction's threat model (§3) is a cryptographic game — it models the adversary as a PPT algorithm. The regulatory examination process is not a PPT algorithm. The CISO's actual threat is a failed NCUA IT examination, not a broken ZK proof. Construction must include: (a) corrected NCUA citations (§712, 2021-04 Supervisory Guidance, FFIEC IT Handbook modules), (b) a control-mapping table from the five ZKP properties to specific FFIEC CAT declarative statements or FFIEC IT Handbook examination objectives, and (c) an explicit acknowledgment of which properties require regulatory novelty treatment (i.e., examiner pre-approval or a "pilot program" designation) versus which map to existing examined controls.


## Persona: rfc7662_advocate

*OAuth Working Group veteran. Shipped introspection at scale. Every ZK byte is innocent until proven necessary.*

---

### Attack 1: AS-side per-RS scope filtering + jwt-introspection-response caching collapses Gap 1 and Gap 3 for any realistic deployment

**Attack:**
The construction's entire §8 "Gap 1" argument rests on the claim that "even with jwt-introspection-response caching, the AS was contacted at issuance and at first introspection." I accept this narrowly, then observe that it proves almost nothing.

In a real federated deployment, here is the full baseline:

1. Agent holds a DPoP-bound opaque reference token (RFC 9449). No scopes in the token itself.
2. RS calls introspection endpoint *once*, receiving a signed JWT response (draft-ietf-oauth-jwt-introspection-response) containing only `{"scope": "read_data access_pii"}` — the AS applies per-RS policy, filtering to exactly the scopes relevant to this RS.
3. RS caches the signed JWT response up to its `exp`. No AS contact on subsequent requests within that window.
4. Different RSes get different filtered responses. No RS ever sees the agent's full permission set.

This is not a theoretical configuration. It is production-grade AS behavior today.

The construction's claimed differentiator collapses to: *the AS was contacted exactly once, at first RS introduction, to establish the per-RS scope attestation.* In the CUSO scenario (§7), that single contact happens at *provisioning time*, not at *request time*. The "AS-blind at presentation time" property the construction touts is already achieved.

**Gap 3 (Adversarial-AS model)** is the only load-bearing claim — and it requires the reader to accept that the AS itself is a hostile party who will lie about scope membership. In the CUSO scenario, each CU controls its own AS. If CU-A's AS is willing to grant inflated scopes to CU-A's agents, then CU-A's agents also control the credential enrollment (they're the operator). A malicious CU can enroll a shadow agent with `permissionBitmask = 0xFF` (see Attack 2). The adversarial-AS property doesn't hold against enrollment-time malfeasance; it only holds against presentation-time forgery against a pre-enrolled honest credential. These are different threat surfaces.

**Why it works:** The construction's marketing claim is "six properties simultaneously"; in practice, four of those six (AS-blind, offline verification, scope filtering, sender-binding) are achievable with the baseline stack for any deployment where the AS is at least minimally trustworthy at provisioning time. The genuine residual gap is adversarial-AS + constant-size proof simultaneously — a real but narrow use case.

**In-threat-model?** Partial. The construction survives against the narrow adversarial-AS game (SSU). It does not survive the marketing claim that the baseline "cannot match" Gaps 1–4 under ordinary enterprise deployments. The paper needs to scope its claims to the adversarial-AS model explicitly in the abstract.

---

### Attack 2: Shadow enrollment / agent identity substitution — AS=operator defeats the CUSO trust model without winning the SSU game

**Attack:**
The SSU game (§3) defines forgery narrowly: A must produce a valid proof where `permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*` against the *honest agent's blinded leaf*. The game explicitly allows A to "Corrupt any other enrolled agent" and to "Compromise the AS entirely."

Here is what the game does **not** prevent, and what the construction does **not** address:

In the CUSO federated model (§7), operator=AS per CU. CU-A controls its own EdDSA signing key. CU-A wants its fraud-detection agent (bitmask = `0b10000001`, `READ_DATA | ACCESS_PII`) to also initiate wire transfers (`FINANCIAL_UNLIMITED` = bit 4). CU-A's AS is the adversary.

**Attack procedure:**

1. CU-A (operator=AS) creates a shadow credential: `permissionBitmask_shadow = 0b11111111` (all bits set, including `FINANCIAL_UNLIMITED`).
2. CU-A signs `credentialCommitment_shadow = Poseidon5(modelHash, operatorPubKey, permissionBitmask_shadow, expiry)` using its own EdDSA key.
3. CU-A's shadow agent computes `blindingFactor_shadow`, computes `leafCommitment_shadow = Poseidon2(credentialCommitment_shadow, blindingFactor_shadow)`, and enrolls `leafCommitment_shadow` into the on-chain Merkle tree via a standard on-chain transaction.
4. The updated Merkle root now contains *both* the honest agent's leaf and the shadow leaf. Both are valid enrolled leaves.
5. CU-A's shadow agent generates a Groth16 proof for `requiredScopeMask = 0b00010000` (`FINANCIAL_UNLIMITED`) using `permissionBitmask_shadow`. The proof verifies. `agentMerkleRoot` matches a valid on-chain root (which also happens to contain the honest agent's leaf).
6. The CUSO platform RS performs its verification:
   - `agentMerkleRoot ∈ on-chain root history` ✓ (shadow leaf enrolled legitimately)
   - `nullifierHash` is fresh ✓
   - `requiredScopeMask` matches ✓
   - Groth16 verifies ✓

**The RS accepts. The shadow agent has `FINANCIAL_UNLIMITED`. No forgery in the SSU game occurred — a legitimate shadow credential was enrolled.**

**Why it works:** The RS has no mechanism to verify that the presenting agent is the *specific* agent it expects, rather than a shadow agent enrolled by the malicious operator. The construction's public outputs (`agentMerkleRoot`, `nullifierHash`, `scopeCommitment`) are all session-unique and opaque. The RS cannot cross-reference the proof to any known enrollment record without exposing agent identity (which the construction deliberately prevents). The privacy property and the identity-pinning property are in direct tension here.

The SSU game's forgery definition dodges this attack by construction: it defines forgery as *against the honest agent's leaf*, but the attack doesn't touch the honest agent's leaf at all.

**Baseline comparison:** RFC 7662 introspection returns `client_id` (the specific registered agent identifier) in the response. The RS can verify that the presenting agent matches a known, pre-authorized client. The ZK construction deliberately hides this information to achieve unlinkability, but the cost is that the RS cannot distinguish "honest enrolled agent from CU-A" from "shadow enrolled agent controlled by CU-A's malicious AS."

**In-threat-model?** No — the construction must address this. Either (a) acknowledge that the CUSO platform must maintain an allowlist of `leafCommitment` values per CU and verify that the proof's Merkle path terminates at an authorized leaf, or (b) scope the adversarial-AS claim to exclude operator control of enrollment. Option (a) partially conflicts with the unlinkability property (the RS would know which leaf set is valid per CU); option (b) significantly weakens the adversarial-AS claim.

---

### Attack 3: RFC 8693 Token Exchange achieves runtime-adaptive scope selection without ZK — the "constant-size proof" is the only genuine constant-size advantage

**Attack:**
The construction attacks the baseline on "runtime-adaptive bitmask predicate" (§8, Gap 2), claiming BBS+ cannot support bitwise AND with implication closure and that scope is "fixed at issuance." I challenge this framing.

RFC 8693 (Token Exchange) enables the following flow:

1. Agent holds a master DPoP-bound token with no disclosed scope (opaque reference).
2. At resource access time, agent calls Token Exchange endpoint:
   ```
   POST /token
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   subject_token=<master_token>
   scope=read_data access_pii
   resource=https://cuso.example/member/transactions
   ```
3. AS evaluates its policy: does the agent's enrolled permission set satisfy `{read_data, access_pii}`? If yes, issue a narrowly-scoped access token for this RS.
4. RS receives a token valid only for `{read_data, access_pii}` at this specific resource (RFC 8707 resource indicator). Full permission set is never disclosed.

**Runtime-adaptive:** The RS specifies what scope it needs at request time (step 2). The agent exchanges at runtime. This is exactly the construction's "RS chooses `requiredScopeMask` at the moment of the request" claim — just implemented via Token Exchange instead of a ZK proof.

**What the construction has that the baseline genuinely lacks:**
- The Token Exchange requires an AS roundtrip per {agent, RS, scope-set} combination. The construction generates proofs locally. For a 200-CU CUSO with thousands of daily API calls, this is a latency and availability difference, not a fundamental security difference.
- The AS sees every Token Exchange request — it learns exactly which agent called which RS with which scope request. The ZK construction gives the AS no visibility into presentation events. This is a privacy difference, but it only matters in the adversarial-AS model.
- Constant-size proof (128 bytes) vs. Token Exchange response (a few hundred bytes of JSON + JWT overhead) — comparable in practice, not a fundamental distinction.

**The cumulative-bit implication closure (bits 2/3/4) claim is weakest here.** This is enforced by AS-side policy in Token Exchange. A compromised AS can violate it — but if operator=AS is already corrupt enough to issue a Token Exchange granting `FINANCIAL_MEDIUM` without `FINANCIAL_SMALL`, it can also enroll a shadow agent (Attack 2). The circuit-level enforcement is a defense-in-depth argument, not a fundamental impossibility argument.

**In-threat-model?** Partial. For the AS-online, trusted-AS case, RFC 8693 closes the "runtime-adaptive" gap almost entirely. The construction's genuine advantage is: runtime-adaptive + AS-blind simultaneously, which Token Exchange cannot achieve. The paper should narrow Gap 2 to explicitly require both properties together rather than claiming runtime-adaptivity alone is differentiating.

---

### Attack 4: Revocation latency — the 30-root buffer gives revoked credentials up to 30 root-transition windows of continued validity; RFC 7662 provides real-time revocation

**Attack:**
§2 specifies: "RS checks: `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`." This means a credential remains valid for up to 30 on-chain root transitions after its leaf is removed from the live Merkle tree.

The construction is silent on root transition frequency. In a production CUSO deployment, root updates may be batched (gas optimization). If roots transition once per hour, a revoked credential (for a terminated AI agent, a compromised key, an agent that exceeded risk limits) remains valid for up to 30 hours after revocation.

**Attack scenario:** CU-A terminates a loan-underwriting agent after discovering it was accessed by unauthorized personnel. The operator removes the leaf from the Merkle tree. The next root is committed on-chain. But the agent (or the adversary who compromised it) holds the private credential material including `blindingFactor` and can continue generating valid proofs against the previous 29 roots in the history buffer.

The construction provides no mechanism for:
- Immediate per-credential revocation within the root buffer window
- Proof that a specific `leafCommitment` is NOT in the current root (this would require a non-membership proof, not provided)
- Distinguishing "leaf removed but still in buffer" from "leaf never existed"

**Baseline comparison:** RFC 7662 introspection returns `"active": false` immediately upon token revocation. The RS, if it calls introspection, learns the credential is revoked in real-time. Even with jwt-introspection-response caching, the cache TTL can be set to minutes; the construction's revocation window can be hours.

**The construction's only answer** is that the RS should require proofs against the most recent root only (buffer size = 1), eliminating the latency gap but also eliminating the liveness property: any RS whose root check happens between two on-chain Merkle updates would reject all proofs. The 30-root buffer exists precisely to handle this liveness concern — but it creates a revocation-latency tradeoff that the construction does not acknowledge.

**DPoP cannot do this either** — DPoP tokens bound to compromised keys need token revocation too — so this is not a claim that the baseline beats the construction here. It is a claim that the construction's revocation story is **weaker** than the baseline and that §7 (Regulatory value, NCUA §701.27 third-party due diligence) requires immediate revocation capability for terminated agents. NCUA expects "timely termination" of third-party access — a 30-root-window revocation latency may be unacceptable to an examiner.

**In-threat-model?** No — the construction must specify the root transition frequency, compute the worst-case revocation latency from it, and either (a) provide a nullifier-based immediate revocation mechanism (the RS maintains a revocation nullifier registry separate from the Merkle tree), or (b) acknowledge this as a known limitation relative to RFC 7662 and argue it is acceptable under the target SLA.


## Persona: spiffe_engineer

---

### Attack 1: `modelHash` is self-attested — you replaced SVID attestation with an honor system

**Attack:** In §8, Gap 5, the construction claims "cryptographic binding to runtime model identity" via `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, ...)`. But `modelHash` is a **private witness** — the prover supplies it. The circuit only proves (a) the operator signed a credential *containing* some `modelHash`, and (b) that credential's blinded leaf is in the Merkle tree. The circuit does not and cannot prove that the entity currently generating the proof is *actually running* the model identified by `modelHash`.

In SPIRE production we call this the attestor gap. TPM attestation (`x509pop`), AWS IID attestation, and k8s pod identity attestation all produce cryptographic evidence that the workload is executing in the claimed environment — signed by a hardware root of trust the operator cannot fake at presentation time. A malicious agent with a compromised copy of a valid credential can supply any `modelHash` it wants as a private input and the circuit will accept it, provided the operator's EdDSA signature on `credentialCommitment` checks out. The signature proves "an operator once authorized a credential containing this hash," not "the current prover is that model."

**Why it works:** Gap 5's headline claim — "binding scope satisfaction to a specific runtime identity" — survives proof-of-credential but not proof-of-execution. There is no analog to TPM PCR quote, Nitro Enclave attestation document, or GPU attestation (NVIDIA Hopper) binding the prover's current execution context to the claimed `modelHash`.

**In-threat-model?** **No — construction must address.** The threat model (§3) defines adversary capabilities but says nothing about an agent that presents valid credentials while running a different model than enrolled. The blinding-hardened SP game (§3) protects against operator/AS correlation but assumes the prover IS the enrolled model. A model-substitution attack (one agent uses another's credential) is absent from SSU game definition: SSU only asks whether A can forge a proof for a `requiredScopeMask` the honest agent's *credential* doesn't satisfy — it does not ask whether A can prove a mask using a *different* agent's credential. Since `blindingFactor` is the sole agent-exclusive secret, a credential leak (including `blindingFactor`) is sufficient for full impersonation with no circuit defense.

---

### Attack 2: The "adversarial-AS" property swaps one trusted ceremony for another — and the ceremony is weaker

**Attack:** §8, Gap 3 argues the construction's trust anchor is "the on-chain Merkle root (consensus-secured) and Groth16 knowledge soundness." The adversary in §3 explicitly does NOT control "the Groth16/PLONK trusted setup (honest-majority ceremony assumption)." This is an excluded-from-adversary clause — precisely the kind of assumption that needs scrutiny.

The `pot16.ptau` powers-of-tau ceremony and the project-specific phase-2 `agentPolicy.zkey` setup must both complete without toxic waste exposure. A compromised phase-2 ceremony (one participant who does not destroy their entropy) produces a CRS under which `∀ x, ∃ π : Verify(vk, x, π) = 1` — a universal forgery. This attack requires compromising the ceremony, but the ceremony is a one-time offline event with no ongoing auditability after the fact.

Compare to SPIRE with an HSM-backed intermediate CA: the CA private key never leaves the HSM, is generated inside it with a hardware attestation log, key usage is continuously auditable via CloudTrail or equivalent, and can be rotated with zero downtime via SPIRE's bundle endpoint federation. Post-compromise, the CA can be revoked and the rotation event is observable. A compromised ZK trusted setup is **undetectable** and **irrevocable** — once toxic waste exists, every historical proof and every future proof is suspect and there is no mechanism to rotate the CRS without reproving every enrolled credential.

**Why it works:** §3 frames the AS as the only corruptible authority, making AS-blind seem obviously superior. But the construction does not argue why an honest-majority ceremony is a *better* trust assumption than an HSM-backed SPIRE CA under continuous audit. In adversarial-AS scenarios where the AS is corrupted, you need to ask: what is the analogous corruption event for the ZK stack? It is ceremony compromise, which the construction places entirely outside the adversary's capabilities without justification.

**In-threat-model?** **No — construction must address.** The threat model should include a ceremony-compromised adversary and either argue why the Semaphore v4 ceremony reuse (for `HumanUniqueness`) and the project-specific phase-2 (for `AgentPolicy`) are adequately hardened, or bound the claim to "AS-blind under honest ceremony" — which narrows the differentiation from SPIRE significantly.

---

### Attack 3: WIMSE covers AS-blind workload-to-workload presentation — your Gap 1 is overstated

**Attack:** §8, Gap 1 states: "Even with jwt-introspection-response caching, the AS was contacted at issuance and at first introspection. The agent cannot present a selective scope proof to a *new* RS without the AS having been involved for that audience (RFC 8707 requires audience-specific token issuance)."

This argument conflates **WIMSE workload token exchange** with RFC 8693 generic token exchange. In draft-ietf-wimse-arch Section 6 (workload-to-workload), the calling workload presents its SPIRE-issued JWT-SVID to an intermediate service, which uses it to obtain a *downstream* scoped token via a local WIMSE token service — without contacting the upstream AS at presentation time. The SPIRE agent daemon runs on the workload node and issues SVIDs via the Workload API socket (`unix:///tmp/spire-agent/public/api.sock`) with a default TTL of 1 hour and automated rotation every 30 minutes. At the moment of API call, the workload presents a cached SVID that was issued without any real-time AS roundtrip — the SPIRE server is not contacted per-request, only per-rotation.

The construction's runtime-adaptive predicate (`requiredScopeMask` chosen by the RS at request time) is the genuine differentiator, not AS-blind presentation per se. The WIMSE engineer would grant: "Yes, you can prove a *predicate* over a hidden bitmask, which WIMSE cannot." But the claim in §8, Gap 1 as framed — that SPIFFE+WIMSE *requires* an AS roundtrip at presentation time — is factually incorrect in the WIMSE architecture and weakens the overall case by giving the adversary an easy target to dismiss.

**Why it works partially:** The selective predicate claim (64-bit AND over hidden bits with implication closure) is architecturally inexpressible in SD-JWT or BBS+. That is the real gap. But the AS-blind framing as stated conflates "AS not contacted at runtime" (which SPIFFE achieves via Workload API) with "credential issuer not in trust path at verification time" (which Bolyra achieves). These are different properties.

**In-threat-model?** **Yes — construction survives on the predicate claim, but must sharpen the AS-blind argument.** The construction should reframe Gap 1 as "RS-side predicate evaluation against a hidden bitmask at request time without credential reissuance," not "no AS contact at presentation time." The latter is claimed by WIMSE; the former is not.

---

### Attack 4: The 30-root circular buffer creates an unmodeled revocation race window

**Attack:** §3 states the RS checks `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`. §7 describes revocation as "handled by updating the Merkle tree (removing the blinded leaf)." These two constraints are in direct tension: removing a leaf updates the Merkle root, but the previous 29 roots remain valid for RS verification indefinitely until the buffer rotates.

An attacker who compromises an agent's full credential material (including `blindingFactor`) — by the SSU game's corruption threshold, up to N-1 of N agents can be corrupted — can generate valid proofs referencing any of the last 30 roots, which may predate the revocation. On a Base Sepolia L2 with ~2-second block times, 30 roots = approximately 60 seconds of post-revocation validity. On Base mainnet under congestion where tree updates are delayed, this window extends with every unprocessed update.

SPIFFE handles revocation differently: X.509 SVIDs carry a short `notAfter` (typically 1 hour max, often 30 minutes in hardened deployments), and SPIRE can push a new trust bundle immediately. JWT SVIDs are non-revocable within their TTL but that TTL is bounded. More critically, SPIRE's Workload API does not issue SVIDs to workloads post-revocation — the SPIRE server refuses renewal for revoked entries, so the effective post-revocation window is bounded by the remaining SVID TTL, not by a history buffer of fixed size. For workloads with 30-minute rotation and immediate SPIRE-server-side revocation, the worst-case window is 30 minutes. For Bolyra under the 30-root buffer, the window is block-time × 30, with no cryptographic bound on how long the buffer can accumulate if Merkle tree updates stall.

**Why it works:** The threat model §3 names the adversary's capabilities but does not include a revocation-race attacker — one who compromises a credential and immediately exercises it before the Merkle update propagates through the 30-root buffer. The CUSO scenario in §7 specifically requires that "revocation is handled by updating the Merkle tree (removing the blinded leaf)" but gives no latency bound or guarantee that the buffer will rotate before a revoked credential's proofs are accepted.

**In-threat-model?** **No — construction must address.** The SSU game (§3) does not define an adversary that races credential use against revocation events. The SP game similarly does not model the window between leaf removal and buffer rotation. The construction should either bound `MAX_ROOT_AGE` (e.g., 30 roots × target block time = X seconds, with a stated SLA), require RSes to check against a bounded root age rather than just root membership, or implement a nullifier-registry approach where revocation writes to the used-nonce mapping rather than relying solely on Merkle root expiry.
