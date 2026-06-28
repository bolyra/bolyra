# Tier 3 Adversarial — C1 Selective scope proof

## Persona: auth0_pm

---

### Attack 1: The Procurement Veto — "Solo Founder Risk"

- **Attack:** A credit union's procurement and vendor risk committee runs a standard third-party due diligence checklist (NCUA §748, FFIEC IT Examination Handbook). Line item: "Is the vendor financially stable with a minimum 2-year runway and enterprise SLA?" Bolyra is a solo-founder project with no SOC 2, no BAA, no enterprise support tier, and no indemnification clause. Auth0 (Okta) has a $17B acquirer backstop, a CAIQ-completed Shared Responsibility Model, and a named enterprise CSM. WorkOS has documented enterprise contracts with dedicated SLAs. The procurement officer does not read the Groth16 knowledge soundness argument in §4 — they read the vendor questionnaire. The construction's §7 CUSO deployment scenario specifically targets NCUA §701.27 third-party due diligence. But §701.27 *is* the due diligence framework that would flag this vendor as non-approvable on non-cryptographic grounds.
- **Why it works / why it fails against the construction:** The construction is entirely silent on vendor risk, organizational maturity, or compliance posture. The 8-section document describes cryptographic guarantees but contains no section on support, indemnification, audit rights, or regulatory pre-clearance. No technical argument in the construction rebuts a procurement veto — these are orthogonal domains, and the construction doesn't acknowledge the gap.
- **In-threat-model?** No — construction must address. The CUSO scenario in §7 is the primary deployment argument. It fails at the vendor-selection gate before any technical evaluation occurs.

---

### Attack 2: Latency Ceiling Breaks Synchronous MCP Flows

- **Attack:** The construction's verification protocol (§2, "Verification protocol") requires a synchronous round-trip: (1) RS sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to the agent, then (2) the agent generates a Groth16 proof, then (3) the agent sends `(π, publicSignals)` back. The construction's own §6 claims `< 0.5 s` for rapidsnark native and `< 5 s` for WASM. Auth0 MCP auth and WorkOS MCP auth issue signed JWTs in `< 100 ms` round-trip including network. Cloudflare Access evaluates policy at the edge in single-digit milliseconds. MCP tool calls in an agentic pipeline are sequential — an agent calling 10 tools across 10 RSes on a single task incurs 5–50 seconds of proof generation overhead in the WASM case, or 5 seconds in the native case. The construction's §8 "Gap 4" claims constant-size proofs as a differentiator, but the gap it doesn't address is *proving time*, not proof size. A 128-byte proof that takes 500ms to generate loses to a 512-byte JWT that takes 50ms to issue.
- **Why it works / why it fails against the construction:** The construction presents the `< 0.5 s` rapidsnark figure as a performance target, not a measured benchmark in the Bolyra CI. There is no benchmark in the diff against the specific constraint count (~21,139 constraints, per §6). More critically, the construction assumes server-side agents running rapidsnark natively. Browser-based MCP clients (Claude.ai with tool use, for example) or lightweight agent runtimes without native binary access hit the 5-second WASM path. The construction does not describe how an operator provisions rapidsnark access for every agent runtime environment, nor does it quantify the fallback latency degradation.
- **In-threat-model?** No — construction must address. The deployment scenario targets agentic API calls where sub-second authorization is an operational requirement. The construction must either (a) provide measured benchmarks on representative hardware, (b) describe a proof caching/precomputation strategy that decouples proof generation from the request path, or (c) acknowledge the latency tradeoff explicitly and define the workload profile where it is acceptable.

---

### Attack 3: Revocation Latency Contradicts the Regulatory Claim

- **Attack:** The construction states revocation is "handled by updating the Merkle tree (removing the blinded leaf)" (§7, step 7 implied; §5 root history buffer). The RS verification step in §2 checks `agentMerkleRoot ∈ on-chain root history buffer (last 30 roots)`. On Base Sepolia (and Base mainnet), a block is ~2 seconds. 30 roots × 2 seconds = 60 seconds of continued validity after a leaf is removed. On an L1 (Ethereum mainnet) with ~12-second blocks, the buffer window is 360 seconds — 6 minutes. The CUSO scenario in §7 frames NCUA §701.27 compliance and GLBA §501(b) as design goals. But NCUA guidance on agent/third-party access assumes *immediate* revocation capability when an agent is compromised. RFC 7009 token revocation is synchronous. Cloudflare Access policy evaluation is real-time. The construction trades revocation immediacy for AS-blindness and never names or quantifies the trade.
- **Why it works / why it fails against the construction:** The 30-root buffer is the RS's mechanism for tolerating Merkle root staleness between on-chain updates and RS cache refresh. It is load-bearing for availability — without it, any block delay makes the RS reject valid proofs. But it creates a window where a revoked credential remains provably valid. The construction's §3 threat model lists AS corruption as an adversary capability but does not list "compromised agent key" as a separate revocation urgency scenario. A credit union discovering a rogue agent at 9:00 AM cannot guarantee that agent loses access before 9:06 AM. The §7 NCUA argument is weakened: the construction provides enrollment integrity guarantees but not revocation immediacy guarantees, and it does not compare either against what NCUA examiners actually require.
- **In-threat-model?** No — construction must address. The construction must either (a) reduce the root history buffer and quantify the availability cost, (b) add an on-chain nullifier emergency-revocation mechanism (agent can be forced to prove against a mask that its revoked credential cannot satisfy), or (c) explicitly acknowledge that this is an availability/revocation tradeoff and define the acceptable window for the CUSO scenario.

---

### Attack 4: Developer Onboarding Is Worse Than Paste-an-API-Key

- **Attack:** Auth0 MCP auth onboarding: create application → copy client ID and secret → call `/oauth/token` → done. Stytch Connected Apps: create app in dashboard → receive credentials → done. Cloudflare Access: configure policy in UI → done. Bolyra onboarding for a new agent (per §2 + §7): (1) operator generates a Baby Jubjub EdDSA keypair and registers it with the CUSO's authorized-operator set (an on-chain governance transaction), (2) operator signs `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)`, (3) agent generates a 254-bit random `blindingFactor`, computes `credentialCommitment` and `leafCommitment`, (4) agent generates an `EnrollmentIntegrity` Groth16 proof (~2s WASM / 0.2s native), (5) agent submits an on-chain enrollment transaction with `(leafCommitment, operatorPubKey, π_enroll)` — requiring gas, a funded wallet, and block confirmation (~2s on Base), (6) waits for the Merkle root update to propagate into the RS's root history cache. This is not one step — it is six, with a ZK proof, an on-chain transaction, and a Merkle root propagation delay in the critical path. The construction's `EnrollmentIntegrity` circuit (added in this refinement) extends onboarding with a new proof generation requirement. None of the six incumbent platforms require the operator to hold a funded on-chain wallet or understand ZK circuit artifacts.
- **Why it works / why it fails against the construction:** The construction contains no developer onboarding section, no SDK ergonomics comparison, and no "five-minute quickstart" flow. §2 describes the enrollment protocol in circuit terms (private inputs, public inputs, gadgets) — a format accessible to ZK engineers but not to a CUSO developer integration team. The `EnrollmentIntegrity` hardening, while cryptographically sound, adds a new artifact (`EnrollmentIntegrity.zkey`) and a new on-chain verifier contract that the CUSO must deploy and maintain. The construction's §5 notes the `enroll()` function gains "proof verification parameters" as if this is a minor change — from a developer integration standpoint, it converts a one-field contract call into a ZK proof submission with a separate trusted setup ceremony dependency.
- **In-threat-model?** No — construction must address. The construction's §8 summary table competes on seven cryptographic properties. It does not include "developer integration complexity" or "time-to-first-authorized-agent-call" as rows. For the target buyer (a CUSO integration team, not a ZK research team), these are the deciding rows. The construction needs either a SDK abstraction layer that hides all six steps behind a single `enrollAgent(credential)` call, or an explicit acknowledgment that this protocol targets infrastructure layers (not direct developer consumption) and a description of what sits above it.


## Persona: cryptographer

Applied cryptographer (IACR). Stance: unless I see a game definition, a reduction, and a ceremony specification, the construction is a marketing document. This one is better than most — it has a game and a sketch. Let me find what it missed.

---

### Attack 1: Subverted Phase 2 Trusted Setup — Both Circuits, No Ceremony Specification

**Attack:**
The construction has two Groth16 circuits that require independent Phase 2 (circuit-specific) ceremonies: `AgentPolicy` and `EnrollmentIntegrity`. An adversary who learns the toxic waste τ from either Phase 2 ceremony can generate arbitrary valid Groth16 proofs for that circuit without knowing any witness. For `AgentPolicy`, this breaks SSU directly: the adversary forges a proof with `permissionBitmask' & requiredScopeMask* = requiredScopeMask*` for any requiredScopeMask* against any agentMerkleRoot, regardless of what is actually in the Merkle tree. For `EnrollmentIntegrity`, it breaks enrollment integrity: the adversary inserts arbitrary leaves into the tree, bypassing the operator-key governance check and the structural invariant that Section 3 claims is cryptographically enforced.

**Why it fails / succeeds against the construction:**
The threat model (§3) excludes this attack by fiat: "The Groth16/PLONK trusted setup (honest-majority ceremony assumption)" is listed as outside adversary control. But the construction nowhere specifies *what the Phase 2 ceremony is*: number of participants, transcript format, how participants verify the prior contribution, or how ceremony integrity is publicly auditable. The Phase 1 `pot16.ptau` is an existing public artifact (reused from Semaphore). The Phase 2 is entirely unspecified. The construction notes "The `EnrollmentIntegrity` circuit requires its own Groth16 Phase 2 ceremony (a separate `.zkey` file)" (§6) and stops there. Two trust anchors with no ceremony specification is not "honest-majority assumption" — it is unquantified trust in whoever ran a script.

Additionally: Phase 1 (`pot16.ptau`) is a universal SRS covering 2^16 constraints. Phase 2 is a per-circuit binding that introduces a new toxic-waste surface. Compromise of Phase 2 is *independent* of Phase 1 security. The reduction sketch in §4 (SSU) assumes knowledge soundness of Groth16 as A1, but A1's premise requires an unsubverted CRS. If the CRS is subverted, A1 does not hold — knowledge soundness fails silently, and with it the entire SSU reduction.

**In-threat-model?** No — this attack breaks the construction. The exclusion is stated but unsubstantiated. The construction must specify Phase 2 ceremony parameters (minimum participant count, auditable transcript location, time-of-deployment verification procedure) or migrate to a universal-setup system (PLONK already listed as an option) where Phase 2 is eliminated. As written, the deployment scenario in §7 (CUSO context) relies on cryptographic guarantees that vanish if any single entity controlled the Phase 2 toxic waste — including the construction's own authors.

---

### Attack 2: Adaptive Chosen-`requiredScopeMask` — The RS as a Scope Oracle

**Attack:**
A malicious RS (or an adversarial party who can issue requests to the same agent through a legitimate-appearing RS endpoint) mounts a chosen-mask attack to recover the full 64-bit `permissionBitmask`. The attack proceeds in 64 rounds:

```
for i in [0, 63]:
    RS sends (requiredScopeMask = 2^i, fresh sessionNonce)
    if agent generates and submits a valid proof:
        bit i of permissionBitmask is SET
    else (agent refuses / proof fails):
        bit i of permissionBitmask is UNSET
```

After 64 rounds, the adversarial RS has recovered `permissionBitmask` completely, from proof acceptance/refusal alone — without breaking any cryptographic primitive.

**Why it works against the construction:**
The agent knows its `permissionBitmask` and knows whether it can satisfy a given `requiredScopeMask`. If it cannot (because the required bit is not set), it cannot generate a valid Groth16 proof — the witness doesn't exist. A well-implemented agent would refuse to even attempt proof generation. This refusal is a 1-bit oracle per query.

The SP game (§3) explicitly assumes both challenge agents satisfy `requiredScopeMask`: "Challenger enrolls two agents with bitmasks b₀, b₁ where `b₀ & requiredScopeMask == requiredScopeMask` AND `b₁ & requiredScopeMask == requiredScopeMask`." The game therefore only protects bits *beyond* what the RS already knows is satisfied. It does not model an adversarial RS that *chooses* different masks across sessions. The SP game fixes `requiredScopeMask` across the challenge; the real deployment fixes nothing — the RS has full control over mask choice per request.

The construction's property claim (§1) "no bits of `permissionBitmask` beyond the predicate outcome" is accurate *given a fixed requiredScopeMask*. But it conflates this with full scope privacy across adaptive queries, which the SP game does not prove and which the construction does not protect.

Concretely: the CUSO scenario (§7) requires that CU-A's agent can prove `READ_DATA | ACCESS_PII` without revealing `FINANCIAL_UNLIMITED`. The CUSO platform itself — as the RS — can determine whether the agent has `FINANCIAL_UNLIMITED` by querying `requiredScopeMask = FINANCIAL_UNLIMITED` and observing whether a proof is produced. No cryptography is broken. The seven-paragraph proof of SP in §3 is correct within its game definition; the game definition is too narrow.

**In-threat-model?** No — this attack breaks the construction's practical privacy claim. The construction must either (a) formally restrict the privacy claim to passive, single-mask RSes and make this explicit in the threat model, or (b) add a mechanism (agent-side mask-query logging and rate-limiting, zero-knowledge range proofs over bit populations, or a verifiable randomness commitment from the RS that binds mask choice before proof generation) to bound what an adaptive RS can learn.

---

### Attack 3: Groth16 Non-Simulation-Extractability Breaks UC Composition

**Attack:**
The security argument composes two separate Groth16 proofs: the `EnrollmentIntegrity` proof (verified once on-chain) and the `AgentPolicy` proof (verified per-request). The construction argues (§4, SSU reduction step 7, second case) that a forger must produce a valid `AgentPolicy` proof against a leaf `L ≠ leafCommitment*`, and that the `EnrollmentIntegrity` proof verified when `L` was inserted guarantees `L` encodes a legitimately signed credential. This *composes* the two Groth16 proofs' knowledge soundness claims.

The problem: Groth16 is knowledge-sound but **not simulation-extractable** (Groth 2016; Fuchsbauer et al., "Non-interactive zero-knowledge proofs in the random oracle model," CRYPTO 2018). Simulation-extractability (SE) is required for secure sequential composition: it ensures that even after seeing a polynomial number of adversarially generated proofs, extracting from a *new* proof remains possible. Without SE, a malicious party who has seen multiple `EnrollmentIntegrity` proofs (they are all on-chain, public) and multiple `AgentPolicy` proofs (they could request sessions as any RS) may be able to produce a new `AgentPolicy` proof that passes Groth16 verification but for which extraction yields a **different** witness than the one used to produce the proof.

Concretely: Groth16 proofs are malleable. Given valid `(π = (A, B, C), publicSignals)`, the triple `(δA, B/δ², C)` for random scalar δ also verifies (up to Groth16's randomization in the toxic waste; the exact malleability depends on the CRS structure). In the context of this construction, an adversary who has observed a valid `AgentPolicy` proof for `(requiredScopeMask_1, sessionNonce_1)` may derive a proof for `(requiredScopeMask_2, sessionNonce_2)` without knowing the underlying witness — if the malleability permits public-input modification through known relationships.

The SSU reduction (§4) extracts a witness from the forged proof by A1. But if Groth16's knowledge soundness fails in the presence of adversarially chosen, previously seen proofs (because SE is absent), the extractor may fail. The construction needs SE to safely compose two proof systems in a setting where an adversary has oracle access to both. Neither Groth16 nor snarkjs is SE out of the box. Achieving SE requires either (a) using a simulation-extractable variant (e.g., Groth–Maller, or Fuchsbauer–Kiltz–Loss), (b) hashing the proof into the nullifier to prevent replay/malleability at the application level, or (c) proving UC-security in the GGM+ROM where SE follows from the algebraic group model.

The construction does not address malleability. The nullifier `Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` is computed from the *witness*, not from the *proof bytes* — so a malleable proof with the same witness still produces the same nullifier and would be rejected as a replay at the same RS. But at a different RS (different `sessionNonce`), there is no protection.

**In-threat-model?** Partial — the SSU game's forgery condition (step 4) requires the RS's on-chain verifier to accept the forged proof, which malleable variants of *observed* proofs (for different public inputs) would satisfy. Whether a concrete malleability attack exists against this specific Groth16 instantiation (with specific toxic waste) requires circuit-level analysis. The construction should add a clause in §4 stating that A1 is assumed in the *algebraic group model* (AGM), under which SE follows from knowledge soundness (Fuchsbauer et al., 2020), and cite this explicitly. Otherwise the composition argument is incomplete.

---

### Attack 4: Poseidon PRF Assumption (A5) — Algebraic Structure and Underconstrained PRF Domain

**Attack:**
The SP proof (§4) relies on A5: "Poseidon acts as a PRF when keyed by the secret / blindingFactor / credential commitment." The SP argument's final step (§4, step 5) concludes that `Poseidon3(credCommitment_c, blind_c, sessionNonce)` is computationally indistinguishable from random to an adversary who knows `credCommitment_c` but not `blind_c`, by treating Poseidon3 as a PRF keyed by `blind_c` evaluated at `(credCommitment_c, sessionNonce)`.

The issue is threefold:

First, **Poseidon is not designed as a PRF**. It is designed as a ZK-friendly collision-resistant hash. The PRF claim requires that fixing one input (the "key") and varying others produces outputs indistinguishable from a random function. This is a separate, additional conjecture beyond collision and preimage resistance. For SHA-2 and SHA-3, the PRF property follows from standard assumptions (HMAC construction, sponge indifferentiability). For Poseidon, which is an algebraic hash over a prime field designed for short R1CS encoding, the PRF assumption is unproven and not widely analyzed in the cryptographic literature. The SAFE (Sponge API for Field Elements) framework addresses this for Poseidon-based constructions, but the construction does not cite SAFE or any analysis of Poseidon as a PRF.

Second, the key space and input structure matter. In the SP game, the adversary knows `credCommitment₀` and `credCommitment₁` (both public to the operator/AS). The PRF is "keyed" by `blind_c`, unknown. But the adversary ALSO knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)`. So the adversary can query the "PRF" at a related point: it knows `Poseidon2(credCommitment_i, blind_i)` and wants to distinguish `Poseidon3(credCommitment_c, blind_c, sessionNonce)`. If Poseidon has algebraic relationships between `Poseidon2(a, k)` and `Poseidon3(a, k, x)` for the same `(a, k)` pair — which is plausible since both are computed over the same MDS matrix — then A5's standard PRF definition may not capture this joint-evaluation distinguishing attack.

Third, **no PRF assumption (A5) game is stated**. The named assumptions (§4, table) list A5 as "Poseidon acts as a PRF when keyed by the secret / blindingFactor / credential commitment." What is the PRF game here? Is it: given oracle access to `f_{blind}(·) = Poseidon3(credCommitment, blind, ·)` for a fixed `credCommitment` and random `blind`, distinguish from a random function? Or something else? The distinction between these formulations matters because the adversary in SP does *not* have oracle access to `f_{blind}` — it sees a *single* evaluation with `sessionNonce` chosen by the challenger. The "PRF" is being used informally to mean "pseudorandom single-output with unknown key," which is closer to a **one-time PRF** or a **commitment** with hiding. The construction conflates these, and the citation-free A5 is load-bearing in the SP proof.

**Why it matters:** If Poseidon3 is distinguishable from a random function with a known co-input (`credCommitment`) and related output (`Poseidon2(credCommitment, blind)`), the adversary in SP can compute a distinguisher over the two candidates (c=0 vs c=1) without recovering `blind` directly. This would break the SP proof's conclusion (Pr[A wins] ≤ 1/2 + negl) without breaking the preimage resistance claim of A3.

**In-threat-model?** No formal game for A5 is given, so it cannot be ruled in or out. The construction must either (a) define A5 precisely as a PRF game with the joint-input structure `(credCommitment, blind)` appearing in both `Poseidon2` and `Poseidon3`, prove/conjecture that Poseidon satisfies this joint PRF property, and cite supporting evidence, or (b) replace the Poseidon-based PRF with a construction with a proven PRF property (e.g., HKDF over the field element, or a dedicated keyed hash with domain separation) and adjust circuit constraints accordingly. The current A5 is a hand-wave that happens to be the right intuition but isn't a game definition or a reduction.


## Persona: cu_ciso

---

### Attack 1: Privacy-as-Feature Is an Audit Trail Liability Under NCUA Part 748

**Attack:** The SP game (§3) is specifically designed so that "even a subpoena for on-chain data *and* operator records does not reveal which enrolled agent made which API call — that linkage requires the agent's private `blindingFactor`" (§7, regulatory value paragraph). The CISO reads §7 as a feature. The NCUA examiner reads it as a controls failure.

After a member data breach, the examiner asks: "Show me which agent accessed member Johnson's account on April 14." The CUSO platform's RS has a used-nonce mapping full of `nullifierHash` values. The on-chain registry has blinded `leafCommitment` entries. The Merkle root confirms a legitimate enrolled agent was in the tree. None of that answers the examiner's question.

NCUA Part 748 Appendix B, §III.C requires the institution to maintain audit trails that can reconstruct system-user activity. GLBA Safeguards Rule (16 CFR §314.4(e)(3)) requires monitoring for "unauthorized access to, or use of, customer information." The construction's privacy guarantee architecturally prevents this linkage without the agent's `blindingFactor` — which is agent-local and under no documented custodial control. The construction treats "even the operator cannot correlate" as a security win. The NCUA examiner treats "even the operator cannot correlate" as a missing audit log.

**Why it works:** The SP game and the audit requirement are structurally opposed. The construction cannot simultaneously satisfy Scope Privacy (SP, §3) as stated and NCUA Part 748 Appendix B audit reconstruction. The SP game *defines success* as the adversary being unable to link a proof to an enrolled agent — but the examiner is exactly that adversary.

**In-threat-model?** No. The construction claims regulatory value in §7 but does not address the audit trail gap. It must either (a) define a per-agent audit disclosure mechanism gated on the agent's `blindingFactor` with documented custody requirements, or (b) explicitly state that audit linkability is out of scope and requires an additional layer (e.g., encrypted audit log written by the agent at access time).

---

### Attack 2: `blindingFactor` Custody Is Unspecified — GLBA §314.4(c) and NCUA Part 748 §IV Fail

**Attack:** The entire construction's privacy and unforgeability model rests on one secret: `blindingFactor`, "chosen at enrollment by the agent, kept secret from operator and AS" (§2, blinded leaf commitment). The construction says this value is "agent-local" and "never transmitted." It never says: where is it stored, how is it backed up, whether it must be HSM-protected, what happens on agent restart, or what happens if it is lost.

The CISO maps this to GLBA 16 CFR §314.4(c)(6), which requires encryption of customer information at rest and in transit, and to NCUA Part 748 §IV, which requires documented access controls for cryptographic keys. `blindingFactor` controls whether the agent can generate any proof at all. If it lives in a Node.js process environment variable, a supply chain compromise of the agent's runtime extracts it silently. If the agent restarts without persisting `blindingFactor`, it cannot generate proofs — and cannot re-enroll without the operator re-signing a new credential. If it is persisted unencrypted on disk, it fails GLBA at-rest encryption requirements.

The §7 deployment scenario describes the CUSO deploying agents at 200 member credit unions. Each of those 200 CUs now has an agent holding a `blindingFactor` that is (a) the sole secret enabling proof generation, (b) the sole secret enabling audit linkage under attack, and (c) subject to no specified custody controls. The vendor management questionnaire for any one of those 200 CUs will ask: "Where is the credential material stored, who can access it, and what is the key rotation procedure?" The construction has no answer.

**Why it works:** Section 2 defines `blindingFactor` as private input with no operational specification. Section 7 mentions "private credential material" without specifying its storage or lifecycle. The construction is cryptographically rigorous and operationally silent.

**In-threat-model?** No. The threat model (§3) specifies that "the adversary does NOT control the agent's `blindingFactor`" — but this is an assumption, not a guarantee enforced by the construction. The construction must specify: `blindingFactor` storage requirements (HSM, encrypted wallet, etc.), backup and recovery procedures, rotation procedure when an agent is decommissioned, and the remediation path if `blindingFactor` is disclosed.

---

### Attack 3: The 30-Root History Buffer Creates a Revocation Window with No Specified SLA — Fails FFIEC CAT D3.CC.1

**Attack:** Step 5 of the verification protocol (§2) requires the RS to check that `agentMerkleRoot` is "∈ on-chain root history buffer (last 30 roots)." Section 5 confirms the root history is a "30-entry circular buffer on-chain." Revocation is handled by "updating the Merkle tree (removing the blinded leaf)" per §7.

Here is the attack: CU-A's fraud-detection agent is compromised at time T. CU-A removes the agent's blinded leaf from the Merkle tree, generating a new root at T. But the RS's root history buffer still contains up to 29 prior roots — all of which include the compromised agent's leaf. The compromised agent can continue generating valid proofs against any of those 29 prior roots until the buffer fully rotates past T.

How long is that window? The construction does not specify: how frequently the Merkle root is updated, whether roots are committed per-enrollment, per-access, or on a scheduled basis, or what the maximum time between root updates is. On Base (L2), blocks are ~2 seconds. If the root is updated every block, 30 roots ≈ 60 seconds of post-revocation access. If the root is updated every 10 minutes (plausible for cost reasons), 30 roots ≈ 5 hours. For an agent with `ACCESS_PII` (bit 7) accessing 200 CUs' member data, 5 hours of post-revocation access is a material breach window.

FFIEC CAT Domain 3, Control D3.CC.1 (account management) requires timely deactivation. NCUA Part 748 §III.F requires the institution to "respond to and recover from security events." The construction provides no revocation SLA, no specification of root update frequency, and no mechanism for emergency revocation that bypasses the history buffer.

**Why it works:** The 30-root buffer is introduced for liveness (agents can still prove against slightly stale roots while a new enrollment is propagating), but the construction does not pair this with a maximum revocation latency guarantee or an emergency bypass path. The liveness mechanism and the revocation mechanism are in direct tension, and the construction resolves that tension only by silence.

**In-threat-model?** No. The threat model (§3) does not include a compromised-agent-post-revocation scenario. The construction must specify: root update frequency SLA, maximum revocation latency (= root update frequency × history buffer size), and whether an emergency revocation path (e.g., contract-level agent blocklist checked before Merkle root verification) is required for high-privilege agents (`ACCESS_PII`, `FINANCIAL_UNLIMITED`).

---

### Attack 4: The Trusted Setup Ceremony Is an Unauditable Third-Party Dependency — FFIEC CAT Domain 4, SOC 2 CC9.2

**Attack:** The SSU reduction (§4) reduces to "A1: Knowledge soundness of Groth16 in the generic group model + random oracle model for Fiat-Shamir." The construction uses `pot16.ptau` for Phase 1, reused from the Semaphore v4 ceremony. A project-specific Phase 2 ceremony produces the `.zkey` files for `AgentPolicy` and `EnrollmentIntegrity`. Section 4 states the trusted setup assumption without identifying ceremony participants, transcript location, or audit mechanism.

The toxic waste attack: if any single Phase 2 ceremony participant retained their randomness, they can generate a proof π* for any `permissionBitmask*` satisfying any `requiredScopeMask*` — including forging `ACCESS_PII` and `FINANCIAL_UNLIMITED` proofs for agents that do not hold those permissions. The RS verifies these forged proofs successfully. The on-chain `EnrollmentIntegrity` verifier accepts forged enrollment proofs. The entire construction collapses to "whoever compromised the ceremony can impersonate any agent."

FFIEC CAT Domain 4 (External Dependency Management) requires the institution to identify and assess all third-party cryptographic dependencies. SOC 2 CC9.2 requires vendor risk assessment for dependencies affecting security commitments. When the NCUA examiner asks "who are the trusted parties in this system?", the correct answer under §4 is "the Phase 2 ceremony participants." The construction names none of them, links to no ceremony transcript, and provides no mechanism for the credit union to independently verify ceremony integrity.

For the CUSO scenario (§7), the CUSO's third-party risk assessment must document this dependency. "Honest-majority ceremony assumption" is not an acceptable entry in a vendor management policy. The credit union cannot transfer this risk contractually because ceremony participants are not identifiable counterparties.

**Why it works:** The construction's entire security argument (§4) terminates at A1/A2 and the ceremony assumption. In academic cryptography, this is standard. In NCUA examination practice, an unidentifiable set of ceremony participants with no public transcript is an unverifiable control — and an unverifiable control is a finding.

**In-threat-model?** No. The threat model explicitly excludes ceremony compromise: "The Groth16/PLONK trusted setup (honest-majority ceremony assumption)" is listed as what the adversary does NOT control. The construction must address: ceremony transcript availability (public or auditor-accessible), participant count and identity framework, Phase 2 ceremony governance (who conducted it, who verified it), and recovery path if ceremony compromise is discovered post-deployment (answer: re-ceremony + all leaf re-enrollment — a multi-month operational exercise for 200 CUs).


## Persona: rfc7662_advocate

---

### Attack 1: The Trust-Bootstrap Loop — Adversarial-AS Enrolls Inflated Permissions

- **Attack:** The construction's §3 threat model grants the adversary full AS control, explicitly noting "the AS may be the same entity as the operator." The SSU game (step 2) is structured so the *challenger* assigns `permissionBitmask*` to the honest agent. But in the deployment scenario of §7, the operator—not a neutral challenger—decides what `permissionBitmask` gets signed into the credential at enrollment time. There is no circuit constraint preventing the operator from signing a credential where `permissionBitmask = 0xFF` for an agent that should only hold `READ_DATA`. The `EnrollmentIntegrity` circuit (§2, new) enforces structural validity (cumulative-bit closure, correct Poseidon preimage) but says nothing about *whether the permission bits are correct relative to the agent's actual authorization*. A compromised AS-as-operator enrolls the agent with `FINANCIAL_UNLIMITED` set; the ZK circuit then truthfully proves that this enrolled bitmask satisfies any predicate the RS poses.

- **Why it works / why it fails against the construction:** The construction's adversarial-AS claim in §8, Gap 3 is: *"A compromised AS cannot forge scope satisfaction proofs for agents it did not enroll."* True. But the adversary doesn't need to forge proofs—it controls enrollment. The SSU game's reduction (§4, step 7) only handles the case where the adversary proves scope satisfaction for a predicate the *enrolled* bitmask doesn't satisfy. It does not handle the case where the enrolled bitmask was inflated by the adversary at step 3e. This reduces adversarial-AS resilience to the same trust anchor as RFC 7662: both systems ultimately require trusting the issuance authority (operator in Bolyra; AS in RFC 7662) to assign correct permissions. The cryptographic machinery prevents *post-issuance* forgery in both systems identically.

- **In-threat-model?** **No — the construction must address this.** The claim in §8 Summary ("Adversarial-AS resilience: No / No / Yes") is overstated. Bolyra prevents AS *proof* forgery; it does not prevent AS *enrollment* manipulation. The construction should bound the claim precisely: *"adversarial-AS cannot forge proofs for permissions not in the enrolled credential"* — and explicitly note that enrollment integrity (operator assigning correct permissions) is out-of-band, relying on legal/contractual controls (NCUA §701.27) rather than cryptography. This is the same posture as RFC 7662 — not a differentiator.

---

### Attack 2: RFC 9068 + Cached JWKS Already Achieves AS-Blind Presentation

- **Attack:** Section 8, Gap 1 argues that the baseline requires an AS roundtrip at presentation time. This conflates RFC 7662 active introspection (which does require a runtime AS call) with the JWT-based offline-verification path that has been standard practice since RFC 9068 (*JWT Profile for OAuth 2.0 Access Tokens*, 2022). In a standard RFC 9068 deployment: the AS issues a signed JWT access token at issuance time; the RS fetches the AS's JWKS once via RFC 8414 discovery (cached with `Cache-Control: max-age=86400`); every subsequent token presentation is verified offline against the cached public key with zero AS contact. The `draft-ietf-oauth-jwt-introspection-response` adds a signed introspection JWT the agent can cache and re-present, achieving the same structural property as the Bolyra proof: a self-contained, AS-signed artifact the RS verifies without phoning home. The construction's Gap 1 claim that "the AS was contacted at issuance and at first introspection" is accurate for RFC 7662 active introspection but inapplicable to the JWT profile path.

- **Why it works / why it fails against the construction:** The construction's genuine remaining claim after this attack is absorbed is not *AS-blind* but *AS-untrusted*: a compromised AS can issue a fraudulent RFC 9068 JWT with `scope: financial_unlimited` and the RS, verifying offline, accepts it. In contrast, Bolyra's RS trusts the on-chain Merkle root and Groth16 soundness, not the AS's signing key. That is a real cryptographic property difference. However, the AS-blind framing in Gap 1 is the wrong axis. The correct framing is "trust anchor is consensus-secured Merkle root vs. AS public key." When re-read this way, the baseline can partially address it: RFC 7662 federations can use multiple AS instances with per-RS trust anchors, mirroring the CUSO scenario's authorized-operator-key set. Each CU's AS key is trusted by the CUSO platform independently — equivalent to the authorized-operator set in §7, without ZK.

- **In-threat-model?** **Partially.** The construction survives the AS-blind objection on the stronger *adversarial-AS* framing (compromised AS forging JWTs), but §8 Gap 1's current phrasing ("AS in the hot path") will not survive an RFC 9068 expert's review. The text should be corrected to center on *AS-trust-anchor* rather than *AS-roundtrip* — otherwise the baseline reply is two lines citing RFC 9068 and the gap disappears rhetorically.

---

### Attack 3: Per-RS Filtered Introspection + PPID Already Breaks Cross-RS Linkability — The Blinding Innovation Closes Only Intra-Operator Correlation

- **Attack:** Section 8, Gap 6 claims that "the issuer always knows the signed credential content and can correlate any deterministic function of that content with public presentation artifacts." This is the key privacy gap the blinding-hardened construction addresses. The RFC 7662 counter: OIDC Pairwise Pseudonymous Identifiers (PPID, §8 of OIDC Core) assign each RS a distinct opaque `sub` for the same user/agent. The AS issues RS-specific tokens where `sub_for_RS_A ≠ sub_for_RS_B`. Combined with RFC 8707 resource-bound tokens (the token is audience-restricted to RS-A and cannot be replayed to RS-B), cross-RS linkability is broken at the RS layer. The RS sees a pairwise identifier and a resource-scoped token. No RS can correlate with another RS's view. The baseline objection: "Yes, but the AS can still correlate across RSes because it issued both pairwise tokens." True. This is exactly the gap the blinding construction closes: even the operator/AS cannot correlate which enrolled agent made which API call because `nullifierHash = Poseidon3(credCommitment, blindingFactor, sessionNonce)` and `blindingFactor` is unknown to the operator.

- **Why it works / why it fails against the construction:** The blinding innovation genuinely closes this gap — it is the strongest novel property in the construction. However, the threat model assumption that makes this gap load-bearing deserves scrutiny. In the CUSO scenario of §7, the attack is "CU-A (as operator/AS) tracks which of its own agents called the CUSO platform." But: (a) the CUSO platform does not report individual API call events back to CU-A's AS — it simply accepts or rejects requests, (b) CU-A's AS is not consulted per-call under RFC 9068 caching, so it sees no introspection log entries per API call. The AS's correlation opportunity exists only at token *issuance* time, not at presentation time. In the RFC 9068 model, CU-A's AS knows it issued a token to agent X with scopes Y, but does not learn when or how often agent X used the token against the CUSO platform. The Bolyra construction eliminates even issuance-time knowledge of which agent will present which nullifier — but this requires assuming the threat model includes an AS that logs issuance metadata and correlates it with out-of-band side channels (e.g., API gateway timestamps). For most regulated deployments, this is a reasonable privacy goal, but the construction should state explicitly that the threat being addressed is *issuance-time correlation* (the AS knows which credential it signed), not presentation-time active surveillance.

- **In-threat-model?** **Yes — construction survives, but must sharpen the claim.** The blinding innovation closes a real gap that no RFC 7662 configuration can close: the issuer's knowledge of the credential commitment at signing time allows offline correlation with any public signal derived deterministically from that commitment. No PPID scheme removes the AS's knowledge of *which agent it issued to* — it only removes the RS's cross-RS linkability. Bolyra removes both. The construction should clearly separate these two claims: "RS cross-RS unlinkability" (achievable by PPID) vs. "operator correlation resistance" (not achievable by any AS-side mechanism). The current §8, Gap 6 text conflates them.

---

### Attack 4: RFC 8693 Token Exchange Achieves Runtime-Adaptive Scope Restriction Without ZK

- **Attack:** Section 8, Gap 2 claims the baseline cannot evaluate a "runtime-adaptive bitmask predicate" because scope is string-based and not evaluated over a hidden bitmask at proof time. The RFC 8693 counter: the RS communicates its required scopes via `WWW-Authenticate: Bearer scope="read_data access_pii"` (RFC 6750 §3.1) or via RFC 9728 PRM (Protected Resource Metadata). The agent performs an RFC 8693 token exchange, presenting its base token and requesting `requested_scope=read_data access_pii resource=https://platform.cuso.org/transactions`. The AS evaluates whether the agent's base grant covers the requested scopes, then issues a narrow-scoped token. The RS receives and verifies offline (RFC 9068) a token containing only `read_data access_pii` — it never sees `financial_unlimited`. This achieves runtime scope narrowing (scopes are determined at access time based on RS specification) and RS-level selective disclosure (RS sees only what it needs) without ZK. The round-trip cost is one AS call per new RS audience, cacheable per-agent-per-RS.

- **Why it works / why it fails against the construction:** The construction's response is correct on three sub-points: (a) RFC 8693 requires an AS roundtrip — the agent cannot present to a new RS without AS contact, (b) the AS learns which RS the agent is accessing and when — this contradicts AS-blind presentation, (c) a compromised AS can issue a fraudulent narrow-scoped token. However, Gap 2's *specific claim* — that the baseline cannot evaluate a "bitwise AND over a 64-bit field with implication closure" — is accurate. RFC 8693 requires the AS to enumerate which scopes to include; it cannot evaluate an arbitrary boolean predicate over a *hidden* bitmask. The agent must reveal its full scope set to the AS so the AS can determine what to include in the narrow token. BBS+ with an arithmetic circuit predicate would be needed for predicate evaluation over a hidden attribute, and no BBS+ profile in `draft-irtf-cfrg-bbs-signatures` supports bitwise AND. The construction's Gap 2 claim survives on the "hidden bitmask predicate" sub-property, but should be scoped precisely to that: the differentiator is not runtime-adaptive *per se* (RFC 8693 achieves that) but *hidden-bitmask predicate evaluation* at runtime. The current phrasing ("the RS chooses `requiredScopeMask` at the moment of the request; the agent proves satisfaction against whatever mask is demanded without reissuance") does not make clear that the distinguishing feature is *hiding the bitmask from the AS during predicate evaluation*, not merely runtime scope selection.

- **In-threat-model?** **Partially — construction survives on the hidden-bitmask sub-property, fails on the broader framing.** An RFC 8693 deployment in the CUSO scenario (§7) with short-lived narrow-scoped tokens per RS is operationally viable and satisfies NCUA §701.27 audit requirements with *more* AS-visible audit trail than Bolyra provides — which regulators may prefer, not resist. The construction should acknowledge RFC 8693 as a partial baseline that closes the runtime-adaptive gap at the cost of AS visibility, and sharpen Gap 2's uniqueness claim to: "hidden-bitmask predicate with no AS contact and no disclosure of bitmask to the AS at evaluation time."


## Persona: spiffe_engineer

> *"Agent identity is workload identity. You are solving scope-hiding — a boutique requirement — by replacing the entire authorization stack. At every layer, you have chosen complexity over composability."*

---

### Attack 1: Credential Possession ≠ Workload Execution — No Runtime Attestation

**Attack:**

The construction's "model-identity-bound" property claims that `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` binds the scope proof to "a specific runtime identity" (§1). But the word *runtime* is doing fraudulent work here.

The circuit proves that **someone** holds a credential containing `modelHash` and that the credential was signed by the operator. It does not prove that the entity *currently generating the proof* is actually executing the model identified by `modelHash`. The `blindingFactor` is "agent-local" — but local to what? A Python subprocess? A container? A WASM runtime?

In SPIRE, node attestation (via TPM, Nitro Enclaves, or GCP instance identity documents) and workload attestation (via kernel-attested process metadata) together prove that *the running process with this SPIFFE ID is actually the workload described by the selector*. The SPIFFE ID `spiffe://cuso.example/agent/fraud-detection-v2` does not just encode an identifier — it is issued by SPIRE *only after the workload proves it is running in the expected execution environment*.

This construction has no such binding. An operator can sign `credentialCommitment` for `modelHash = Poseidon(GPT-4o-hash)` and distribute the credential material (including `blindingFactor`) to any process capable of running Groth16 witness generation. That process need not be GPT-4o, need not be running in an enclave, and need not be audited by anyone. The credential is fully portable credential material, not a workload-bound assertion.

**Why it works / why it fails against the construction:**

The construction explicitly defines the adversary as not controlling "the agent's `blindingFactor`" (§3). But this assumption is not architecturally enforced — it is a *deployment contract*. There is no circuit constraint, no TEE attestation, and no protocol step that binds `blindingFactor` to a specific hardware root of trust or process lineage. The construction's threat model silently assumes a well-behaved agent runtime as a trusted party it never names.

**In-threat-model?** No. §3 lists adversary capabilities but never lists "agent runtime compromise" because the construction has no answer for it. A compromised or cloned agent runtime that possesses the credential bundle `(sig, blindingFactor, merkleProof)` — all of which must be stored somewhere accessible to the proving process — can generate valid proofs indistinguishable from the legitimate agent. The construction must either (a) bound `blindingFactor` to a hardware secret (TPM, enclave sealing key), explicitly scoping the deployment to TEE environments, or (b) acknowledge that `modelHash` is a label, not an attestation, and drop the "model-identity-bound" security claim.

---

### Attack 2: WIMSE Token Exchange Already Provides AS-Blind Cross-Domain Authorization — With Auditable Trails

**Attack:**

Section §1 lists "AS-blind: generated locally by the agent with no authorization-server roundtrip at presentation time" as a primary differentiator. The WIMSE architecture (`draft-ietf-wimse-arch`, §5) already provides this property at the workload layer using a different mechanism: the WIMSE workload proof-of-possession (WPoP) token binds a short-lived workload assertion to a specific transaction context, verifiable by the RS using cached JWKS without contacting the AS.

More critically: the construction's AS-blind property is **a regulatory liability**, not a feature, in the concrete CUSO scenario (§7).

Section §7 claims the construction satisfies NCUA §701.27 third-party due diligence and GLBA §501(b) because "NCUA examiners can audit the on-chain enrollment registry." But §701.27 requires ongoing vendor oversight, including the ability to reconstruct *which agent performed which action on which member account* for BSA/AML suspicious activity reporting. The blinding-hardened `nullifierHash = Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` is explicitly designed so that "even the enrolling CU itself — acting as operator and AS — cannot perform this correlation without the agent's `blindingFactor`."

This means: if a fraud-detection agent at CU-A executes a suspicious wire and the CUSO platform must produce a SAR within 30 days (31 C.F.R. §1020.320), the CUSO cannot identify which specific agent instance made which call from the on-chain log alone. The agent must cooperate by disclosing `blindingFactor`. Under adversarial conditions (agent compromise, operator dispute, litigation hold), that disclosure may not be forthcoming, or the `blindingFactor` may have been lost.

WIMSE's auditable token exchange, by contrast, preserves a chain of custody: the RS logs the WPoP token (which identifies the workload by SPIFFE ID and binds it to the transaction), and SPIRE maintains workload registration records. The AS is not in the *presentation path* but is in the *audit path* — a distinction the construction collapses entirely.

**Why it works / why it fails against the construction:**

The construction does not fail cryptographically here. The privacy guarantees hold. But the §7 compliance narrative is overclaimed. The construction provides *RS-blind* authorization (RS cannot correlate presentations with agent identity across sessions) and *operator-blind* presentation artifacts, but this is the opposite of what regulated financial workflows need. NCUA examination requires the *operator* (the CU) to be able to reconstruct activity, not to be cryptographically excluded from doing so.

**In-threat-model?** No. The threat model (§3) defines the adversary as the AS/operator acting maliciously against the agent. It does not model the regulatory adversary: a legitimate authority (examiner, court) that needs to compel activity reconstruction. The construction presents AS-blindness as universally desirable, but the CUSO deployment scenario requires selective deanonymization under legal process. The construction must specify how `blindingFactor` custody is managed (escrow? threshold disclosure? logging by agent to a separate audit log?) or drop the NCUA compliance claim.

---

### Attack 3: SPIFFE Federation Closes the "Adversarial-AS Portable Identity" Gap Without Blockchain State

**Attack:**

The construction's core trust anchor is "the on-chain Merkle root (consensus-secured)" (§3). The RS checks `agentMerkleRoot` against an on-chain root history buffer containing the last 30 roots. The adversarial-AS resilience claim (§1, §8, Gap 3) rests on this: "The AS is not in the trust path."

SPIFFE trust-domain federation already provides this property without on-chain state. When CU-A federates its SPIRE server with the CUSO platform:

1. CU-A publishes its SPIFFE trust bundle (a set of root CA public keys) to a well-known HTTPS endpoint.
2. The CUSO SPIRE server fetches and pins this bundle via the federation API.
3. When CU-A's agent presents an X.509 SVID to the CUSO platform, the RS verifies the SVID certificate chain against the pinned CU-A bundle — **no contact with CU-A's SPIRE server at verification time**.
4. A compromised CU-A AS cannot forge valid SVIDs without access to the root CA private key, which SPIRE stores in a hardware-backed HSM.

This is structurally identical to the construction's trust model: the RS trusts a pinned root (the SPIFFE bundle) rather than a live AS endpoint. The security property is identical. The "on-chain" aspect of the Merkle root provides write-once immutability and multi-party observability, but it adds gas costs, L2 finality latency (~2 seconds on Base Sepolia, unbounded during sequencer downtime), and a dependency on the L1 fork-choice rule.

**Why it works / why it fails against the construction:**

The construction's genuine advantage over SPIFFE federation is **scope privacy**: the RS cannot learn which additional bits are set in `permissionBitmask` beyond what it required. SPIFFE SVIDs encode permissions as OID extensions or SVID path segments — the RS sees all of them. This is the real differentiator, and it is valid.

But the construction's framing in §8 conflates "adversarial-AS resilience" (which SPIFFE federation achieves) with "scope privacy" (which it does not). The sentence "The AS is not in the trust path" is true of both constructions. What is unique to Bolyra is the *selective* scope disclosure, not the AS independence. The adversary at the framing level: the construction is overselling its trust model novelty and underselling its privacy novelty.

There is a second, operational attack: **revocation**. The construction states "Revocation is handled by updating the Merkle tree (removing the blinded leaf)" (§7). The 30-entry root history buffer (§5, Bolyra primitive mapping) means a removed leaf remains valid for up to 30 root updates — an undefined wall-clock time that depends on tree activity. SPIRE's default SVID TTL is 1 hour, rotation every 30 minutes; emergency revocation can push a CRL within minutes. The construction has no equivalent: there is no invalidation mechanism that takes effect within a bounded wall-clock window independent of tree churn. For a CUSO scenario where a compromised agent must be revoked immediately (e.g., an agent performing unauthorized wire transfers), 30-root-buffer validity is not a viable SLA.

**In-threat-model?** Partially. The scope-privacy gap versus SPIFFE is in-threat-model and the construction survives. The revocation latency gap is not in-threat-model — the construction lists revocation as handled but gives no SLA, no maximum validity window after leaf removal, and no emergency invalidation path. This must be addressed.

---

### Attack 4: The BlindingFactor Bootstrap Problem — The Construction Needs an Enrollment Channel It Did Not Specify

**Attack:**

The entire Scope Privacy (SP) game (§3) and blinding-hardened design (§2, gadget 4) depend on a single invariant: "Protocol invariant on `blindingFactor` independence: The enrollment protocol MUST ensure that `blindingFactor` is generated locally by the agent and never disclosed to the operator or AS."

This invariant is stated as a protocol requirement but has no enforcement mechanism at the channel level. Consider the enrollment flow as specified in §7:

> *(b) the agent locally generates `blindingFactor` and computes `leafCommitment`*

How? In a CUSO deployment, the "agent" is software running on infrastructure controlled by the operator (the CU). The operator provisions the agent's runtime environment, its secrets store, its network access. The CU that wants to surveil its own agents — which the blinding-hardened construction explicitly tries to prevent — controls the environment where `blindingFactor` is generated. Nothing in the construction prevents the operator from:

1. Pre-generating `blindingFactor` values and injecting them into the agent's secrets store.
2. Logging the agent's memory to extract `blindingFactor` after generation.
3. Running the agent in a VM and snapshotting its state during enrollment.
4. Patching the agent binary to exfiltrate `blindingFactor` before it is sealed.

The WIMSE architecture handles this via SPIRE workload attestation — the SPIRE agent verifies that the process requesting credential issuance matches the registered workload selector, and the credential (SVID) is injected via a Unix socket that only the attested process can access. There is a hardware root of trust (TPM PCR values, Nitro Enclave attestation document) binding the secret to the execution environment.

The Bolyra `EnrollmentIntegrity` circuit (§2) proves that `leafCommitment` is structurally well-formed. It does not prove that `blindingFactor` was generated inside a trusted execution environment inaccessible to the operator. These are different properties. The circuit proves the *form* of the blinding; it cannot prove the *provenance* of the blinding factor.

**Why it works / why it fails against the construction:**

Against the formal SSU and SP games (§3), this is not an attack — the games assume the adversary does not know `blindingFactor`, and the cryptographic argument holds under that assumption. But the games are played against a PPT adversary who cannot access the agent's internal state. In deployment, the "adversary" is the operator, who *does* control the agent's runtime environment.

The construction's Scope Privacy claim — "privacy holds against the operator, the AS (even when operator=AS), the RS, and all on-chain observers simultaneously" (§8, Gap 6) — cannot hold when the operator controls the environment where `blindingFactor` is generated, unless there is a TEE or equivalent hardware isolation boundary. The construction has not specified one.

**In-threat-model?** No. The formal threat model (§3) states the adversary does NOT control "The agent's `blindingFactor` — this is the sole secret the agent holds independent of the operator/AS." This is the exact property the attack breaks in realistic deployments. A SPIFFE engineer would resolve this by binding secret generation to SPIRE's workload attestation and hardware-backed key stores — and would point out that the Bolyra construction must do the same, or scope the "operator-blind" claim to deployments where the agent runs in a hardware-isolated enclave. The construction must either specify the TEE deployment requirement, narrow the scope of the operator=AS privacy claim to enclave deployments, or acknowledge that the SP game models an idealized agent runtime not achievable without additional trusted hardware.
