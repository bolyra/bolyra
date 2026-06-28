# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its permission bitmask satisfies a verifier-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of the permission bitmask beyond predicate satisfaction, in a single constant-size proof, with no authorization server (AS) roundtrip at presentation time, and with security that holds even when the AS is fully adversarial (colluding, compromised, or offline).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, RFC 9449 (DPoP), or W3C VC + BBS+ selective disclosure can simultaneously achieve all five properties: (1) AS-blind presentation, (2) runtime-adaptive bitmask predicate with implication-closure enforcement, (3) adversarial-AS soundness, (4) constant-size proof regardless of bitmask width, and (5) cryptographic binding to the agent's runtime model identity.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: SelectiveScopeProof

A specialization of the existing `AgentPolicy` circuit, restructured for standalone RS-facing presentation (no handshake required). The agent generates this proof at the moment of resource access, with the RS supplying `requiredScopeMask` as the predicate.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Poseidon hash of model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint8 | Actual Merkle proof depth |
| `merkleProofIndex` | uint64 | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Sibling hashes (padded to MAX_DEPTH=20) |
| `blindingNonce` | field | Fresh random field element per presentation |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Current time (RS-supplied) |
| `onChainAgentRoot` | field | Agent Merkle tree root (RS reads from on-chain registry) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopePredicateHash` | field | `Poseidon4(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)` — binds the predicate evaluation to this specific credential and moment, blinded for unlinkability |
| `agentNullifier` | field | `Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)` — blinded per presentation, enables rate-limiting without cross-session linkage |

### Gadgets (constraint groups)

**G1 — Range checks (4 Num2Bits):**
- `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`, `requiredScopeMask`

**G2 — Credential commitment (1 Poseidon5):**
- `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`

**G3 — Operator signature (1 EdDSAPoseidonVerifier):**
- `EdDSA.Verify((operatorPubkeyAx, operatorPubkeyAy), credentialCommitment, (sigR8x, sigR8y, sigS))`

**G4 — Merkle membership (1 BinaryMerkleRoot):**
- `computedRoot = BinaryMerkleRoot(credentialCommitment, merkleProofSiblings, merkleProofIndex, merkleProofLength)`
- `computedRoot === onChainAgentRoot` (equality constraint against public input)

**G5 — Scope satisfaction (64 bit-AND constraints):**
- For each bit `i` in `[0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`
- Proves `permissionBitmask & requiredScopeMask == requiredScopeMask` without revealing any bit of `permissionBitmask` that is not required.

**G6 — Cumulative bit encoding (3 implication constraints):**
- `permBits[4] * (1 - permBits[3]) === 0`
- `permBits[4] * (1 - permBits[2]) === 0`
- `permBits[3] * (1 - permBits[2]) === 0`

**G7 — Expiry enforcement (1 LessThan):**
- `LessThan(64): currentTimestamp < expiryTimestamp`

**G8 — Predicate binding (1 Poseidon4):**
- `scopePredicateHash = Poseidon4(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)`

**G9 — Agent nullifier (1 Poseidon3):**
- `agentNullifier = Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)`

### Verification protocol (RS-side)

1. RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact).
2. RS constructs public inputs: `[requiredScopeMask, currentTimestamp, onChainAgentRoot]`.
3. RS receives proof `pi` and public outputs `[scopePredicateHash, agentNullifier]` from the agent.
4. RS calls the PLONK verifier contract (or verifies locally with the verification key): `Verify(vk, pi, pubSignals)`.
5. RS checks `agentNullifier` against a local rate-limit table (optional).
6. On success: the agent has the required permissions, the credential is unexpired, and the credential is enrolled on-chain — all without learning the agent's full permission set, model hash, operator key, or any other credential field.

### Agent-side response discipline (predicate rejection behavior)

When the agent receives a `requiredScopeMask` that its `permissionBitmask` does NOT satisfy, it MUST NOT reveal this fact through timing or response-format differences. The agent SDK MUST implement the following constant-time rejection protocol:

**Mandatory behavior — `rejectIndistinguishably(requiredScopeMask)`:**

1. **Always generate a proof attempt.** The agent runs the PLONK prover with its real witness. If `G5` constraints are unsatisfied, the prover will fail internally (no valid assignment exists for the R1CS). The agent catches this failure silently.
2. **Constant-time budget.** The agent enforces a fixed wall-clock budget `T_prove` (configured per deployment; default: 3 seconds for snarkjs, 500 ms for rapidsnark). If proving succeeds before `T_prove`, the agent pads with a `sleep(T_prove - elapsed)`. If proving fails (unsatisfied predicate), the agent sleeps for the full `T_prove`.
3. **Uniform rejection response.** After `T_prove` elapses with a failed proof, the agent returns an application-layer error: `{"error": "scope_insufficient", "retry_after": <backoff>}`. This is the SAME error returned for genuinely expired credentials, revoked credentials, or stale Merkle roots — the RS cannot distinguish unsatisfied-predicate from any other proof failure.
4. **No partial disclosure.** The agent MUST NOT return which bits failed, how many bits matched, or any diagnostic beyond the opaque error. The SDK's `proveSelectiveScope()` method returns `Result<Proof, ScopeError>` where `ScopeError` is a unit type carrying no payload visible to the RS.

**Why this is sufficient:** The adversary's bit-extraction attack relies on a distinguisher between "predicate satisfied" (proof returned) and "predicate unsatisfied" (no proof returned). With constant-time budgeting, the adversary observes identical timing for both outcomes. The only signal is binary: proof-accepted vs. error. A 64-query sweep where each query sets a single bit yields at most 64 binary outcomes — but these match exactly the outcomes the adversary would see if the agent had ANY subset of permissions (including a fully privileged or fully unprivileged agent). The formal argument is in Section 4.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:
- The authorization server (AS) — can issue arbitrary tokens, lie in introspection responses, collude with other parties
- Network position — can observe all RS-agent traffic, including timing
- Up to `N-1` of `N` enrolled agents (corrupted agents whose secrets are known)
- The choice of `requiredScopeMask` in each query (chosen-predicate adversary)

The adversary does NOT control:
- The on-chain registry (Ethereum/Base L2 consensus assumptions)
- The RS's local copy of the PLONK verification key
- The honest agent's private inputs (secret, operator key)
- The honest agent's local clock beyond the public `currentTimestamp`

**Critical distinction — circuit-enforced implication closure vs. issuer assertion:** The differentiator between this construction and every baseline variant (including boolean-return RFC 7662, Client Attestation, WIMSE WPoP, hardware-attested SPIRE, SD-JWT, and RFC 8693 token exchange) is *who evaluates the predicate and who enforces structural invariants*. In every baseline, the AS evaluates the predicate (`bitmask & required == required`) and *asserts* the result. The RS trusts this assertion. A lying AS returns the wrong boolean. In `SelectiveScopeProof`, constraints G5 and G6 are R1CS constraints — they are *mathematical facts about the witness* that no prover can circumvent without breaking PLONK knowledge soundness. The implication closure (G6) is particularly significant: no baseline variant even attempts to enforce that `FINANCIAL_UNLIMITED` implies `FINANCIAL_SMALL` at the cryptographic layer. A boolean-return RFC 7662 AS can trivially assert that an agent with `FINANCIAL_UNLIMITED` but without `FINANCIAL_SMALL` satisfies a `FINANCIAL_SMALL` predicate — the RS has no way to detect the structural violation. The circuit rejects such a witness unconditionally.

### Security game: Selective Scope Forgery

```
Game SelectiveScopeForgery(lambda):
  1. Setup: Run trusted setup for SelectiveScopeProof circuit -> (pk, vk)
  2. Enrollment: Challenger enrolls honest agent credential commitment C*
     into the on-chain Merkle tree. A learns C* but not the private inputs.
  3. Oracle: A may query the honest agent for proofs on predicates of A's
     choice (chosen-predicate queries). A receives (pi, scopePredicateHash,
     agentNullifier) for each query.
  4. Challenge: A outputs (pi*, pubSignals*) where requiredScopeMask* is a
     predicate that the honest agent's permissionBitmask does NOT satisfy
     (i.e., exists bit i: requiredBits*[i] = 1 and permBits[i] = 0).
  5. A wins if Verify(vk, pi*, pubSignals*) = ACCEPT and the
     onChainAgentRoot in pubSignals* is a valid root from the registry's
     root history buffer.
```

**Claim:** `Pr[A wins] <= negl(lambda)` under the assumptions in Section 4.

### Sub-game: Implication Closure Forgery

```
Game ImplicationClosureForgery(lambda):
  1. Setup: As above.
  2. Challenge: A produces a valid proof pi with extracted witness w where
     w.permissionBitmask violates implication closure (e.g., bit 4 = 1
     but bit 3 = 0).
  3. A wins if Verify(vk, pi, pubSignals) = ACCEPT.
```

**Claim:** `Pr[A wins] <= Adv_PLONK_ks(lambda)`. Constraint G6 (`permBits[4] * (1 - permBits[3]) === 0`) is an R1CS constraint — no valid witness can satisfy the circuit with an implication-violating bitmask. This is the property no baseline variant even attempts: attestation mechanisms certify *identity and platform state*, not *the algebraic satisfaction of permission-structure invariants*. A hardware-attested client with a structurally invalid permission set (FINANCIAL_UNLIMITED without FINANCIAL_SMALL) passes attestation but fails the R1CS constraint unconditionally.

### Privacy game: Multi-Query Simulation-Extractable Indistinguishability (mqSE-IND)

```
Game mqSE-IND(lambda):
  1. Setup: Run trusted setup -> (pk, vk).
  2. Enrollment: Challenger enrolls two agents with commitments C0*, C1*
     (both in the Merkle tree). A knows both commitments.
  3. Phase 1 (adaptive chosen-predicate queries): A submits predicates
     R_1, R_2, ..., R_q1 of its choice. For each R_i:
       - If the selected agent's bitmask B satisfies R_i (B & R_i == R_i):
         Challenger returns (pi_i, scopePredicateHash_i, agentNullifier_i)
         after exactly T_prove wall-clock time.
       - If B does NOT satisfy R_i:
         Challenger returns {"error": "scope_insufficient"} after exactly
         T_prove wall-clock time.
  4. Challenge: A chooses two bitmasks B0, B1 such that for every predicate
     R queried in Phase 1, B0 satisfies R iff B1 satisfies R.
     Challenger flips coin b <- {0,1}, generates q proof transcripts
     using Bb's witness.
  5. Phase 2 (adaptive post-challenge queries): Same constraints as Phase 1.
  6. A outputs guess b'.
  7. A wins if b' = b.
```

**Claim:** `|Pr[A wins] - 1/2| <= Adv_PLONK_SE_ZK + 4q * Adv_Poseidon_PRF`.

PLONK with Fiat-Shamir in ROM is simulation-extractable (Faust et al. 2022). This ensures that even an adversary collecting polynomially many proofs from the same agent cannot malleate observed proofs or correlate structure across transcripts. The `blindingNonce` (private, fresh per presentation) ensures each proof transcript is independently randomized. The hybrid argument proceeds in 7 steps (q-indexed): for each query, replace the real `blindingNonce` with a PRF output, then invoke PLONK SE-ZK to replace the real proof with a simulated one. BBS+ is HVZK (honest-verifier zero-knowledge), not SE-NIZK — Groth16 proof malleation is a concrete attack that SE-NIZK prevents.

**Comparison to the baseline's privacy failure:** In RFC 7662, a single introspection query returns the full scope string — equivalent to querying all bits simultaneously and receiving all answers. BBS+ selective disclosure reveals claim values, not just boolean satisfaction. SD-JWT discloses claim values in plaintext — disclosed claims are not hidden at all. The `SelectiveScopeProof` returns only a boolean per predicate, and the proof is simulation-extractable zero-knowledge conditioned on that boolean.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Knowledge soundness of PLONK** (with universal SRS, algebraic group model + ROM): Any PPT prover that produces an accepting proof knows a valid witness satisfying all circuit constraints.
2. **Collision resistance of Poseidon** over BN254 scalar field: No PPT adversary can find distinct inputs `(x1,...,xn) != (x1',...,xn')` such that `Poseidon(x1,...,xn) = Poseidon(x1',...,xn')`.
3. **Discrete log hardness on Baby Jubjub**: Given `(Ax, Ay) = s * G`, no PPT adversary can recover `s`.
4. **Unforgeability of EdDSA-Poseidon on Baby Jubjub**: No PPT adversary can forge a valid signature on a new message without the signing key.
5. **Random Oracle Model (ROM)**: Fiat-Shamir transform in PLONK is modeled as a random oracle.
6. **Simulation-extractability of PLONK** (Faust et al. 2022): PLONK with Fiat-Shamir in ROM is simulation-extractable — proofs are both zero-knowledge and extraction-sound even in the presence of simulated transcripts.

### Reduction sketch (soundness)

Suppose adversary `A` wins SelectiveScopeForgery with non-negligible probability `eps`.

By PLONK knowledge soundness (Assumption 1 + 5), extract witness `w = (modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp, sig, merkleProof, blindingNonce)` from `A`'s accepting proof.

**Case 1:** The extracted `permissionBitmask` does NOT satisfy `requiredScopeMask*` (i.e., G5 constraints are violated). This contradicts knowledge soundness — the extractor produced a witness that does not satisfy the circuit relation. Contradiction.

**Case 2:** The extracted `permissionBitmask` DOES satisfy `requiredScopeMask*`. Then the extracted `credentialCommitment` must be a leaf in the Merkle tree at root `onChainAgentRoot` (G4). Sub-cases:

- **2a:** `credentialCommitment = C*` (the honest agent's commitment). But the honest agent's bitmask does not satisfy the predicate by game definition. Since `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` and the extracted bitmask differs from the honest agent's, we have a Poseidon5 collision (Assumption 2 violated). Contradiction.

- **2b:** `credentialCommitment != C*` but is still a valid leaf. Then `A` is using a different enrolled agent's credential — not a forgery against the honest agent, but a legitimate proof for a different agent. If `A` controls the credential, this is not a forgery.

- **2c:** `credentialCommitment` is NOT a leaf but `BinaryMerkleRoot` still outputs `onChainAgentRoot`. This requires a second-preimage attack on the Poseidon-based Merkle tree (Assumption 2 violated). Contradiction.

Therefore `Pr[A wins] <= Adv_PLONK_ks + Adv_Poseidon_cr + negl(lambda)`.

### Reduction sketch (privacy — multi-query SE-IND)

We reduce the mqSE-IND game to PLONK simulation-extractable zero-knowledge.

**Hybrid argument (7 steps, q-indexed):**

- **Hybrid H0:** Real game with agent b.
- **Hybrid H1..Hq (per-query PRF hop):** For query j, replace `blindingNonce_j` (fresh random) with `PRF(k, j)` where k is a secret key. Each hop costs `Adv_Poseidon_PRF`.
- **Hybrid Hq+1..H2q (per-query simulation hop):** For query j, replace the real PLONK proof with a simulated proof (using the PLONK simulator). Each hop costs `Adv_PLONK_SE_ZK / q`.
- **Hybrid H_final:** All proofs are simulated, independent of b. Adversary advantage = 0.

**Bound:** `|Pr[A wins] - 1/2| <= Adv_PLONK_SE_ZK + 4q * Adv_Poseidon_PRF`.

**Timing side-channel closure:** The constant-time budget `T_prove` ensures `SD(D_accept, D_reject) = 0`. Timing is not an additional distinguishing channel.

### Adversarial-AS resilience

The AS never appears in the verification path. The RS verifies the proof against the on-chain Merkle root and the circuit's verification key. Even if the AS is fully compromised:

- It cannot forge a proof for an unenrolled credential (Merkle membership is checked against the on-chain root the RS reads independently).
- It cannot inflate an agent's permissions (the `credentialCommitment` binds the bitmask at enrollment time; changing the bitmask changes the commitment, breaking Merkle membership).
- It cannot suppress an agent's permissions (the agent holds its own secret inputs and generates the proof autonomously).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---|---|---|
| Hash function (all commitments) | Poseidon over BN254 scalar field | `circuits/src/` — all circuits |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` | `AgentPolicy.circom` G2 |
| Operator signature | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | `AgentPolicy.circom` G3 |
| Merkle inclusion | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | Shared across all circuits |
| Scope predicate | Bit-AND: `requiredBits[i] * (1 - permBits[i]) === 0` | `AgentPolicy.circom` G5 |
| Cumulative encoding | 3 implication constraints (bits 4->3->2) | `AgentPolicy.circom` G6 |
| Nullifier | `Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)` | Adapted from agent nullifier pattern, blinded |
| Proving system | PLONK with universal SRS (`pot16.ptau`) | `AgentPolicy` PLONK build in `circuits/build/` |
| On-chain root | Agent Merkle root from `BolyraRegistry` with 30-entry root history buffer | `contracts/` |

No new cryptographic building blocks introduced. Key differences from existing `AgentPolicy`: (a) `onChainAgentRoot` is a public input (RS-verified against chain state, not just a proof output), (b) `scopePredicateHash` binds the evaluation to a timestamp and blinding nonce, (c) nullifier is scoped per predicate and blinded per presentation, (d) `blindingNonce` ensures multi-query unlinkability.

## 6. Circuit cost estimate

| Gadget | Estimated constraints | Notes |
|---|---|---|
| G1: 4x Num2Bits(64) | 256 | 64 constraints each |
| G2: Poseidon5 | ~1,500 | 5-input Poseidon, ~8 full rounds + 57 partial |
| G3: EdDSAPoseidonVerifier | ~8,000 | Dominant cost: Baby Jubjub scalar mul + Poseidon |
| G4: BinaryMerkleRoot(20) | ~6,000 | 20 levels x (Poseidon2 + mux) |
| G5: 64 bit-AND constraints | 64 | One multiplication each |
| G6: 3 implication constraints | 3 | One multiplication each |
| G7: LessThan(64) | ~130 | Num2Bits(65) + comparator |
| G8: Poseidon4 | ~1,200 | 4-input Poseidon (blinded predicate hash) |
| G9: Poseidon3 | ~1,000 | 3-input Poseidon (blinded nullifier) |
| **Total** | **~18,150** | Well within 2^16 = 65,536 (pot16.ptau) |

**Proving time targets:**
- PLONK (snarkjs): **< 3 seconds** on commodity hardware
- PLONK (rapidsnark native): **< 500 ms**
- Verification: **< 2 ms** on-chain, **< 1 ms** off-chain

**Proof size:** 768 bytes (PLONK) — constant regardless of bitmask width or predicate complexity.

**Constant-time budget overhead:** The `T_prove` padding adds at most `T_prove - t_actual` idle time per request. For rapidsnark (`t_actual ~ 500 ms`, `T_prove = 500 ms`), padding is negligible. For snarkjs (`t_actual ~ 2.5 s`, `T_prove = 3 s`), padding is <= 500 ms. Failed proofs (unsatisfied predicate) sleep for the full `T_prove` — this is the cost of constant-time discipline.

## 7. Concrete deployment scenario

### Scenario: Pacific Northwest Credit Union Consortium — AI Agent Loan Processing

**Stakeholder:** Columbia Credit Union (Vancouver, WA) — $3.4B in assets, member of the Northwest Credit Union Association.

**Context:** Columbia CU deploys AI agents to automate member loan pre-qualification across a consortium of 12 credit unions sharing a federated data lake. Each credit union's RS hosts member financial data behind API endpoints. An agent acting on behalf of Columbia CU needs `READ_DATA` (bit 0) and `FINANCIAL_SMALL` (bit 2) to pull credit summaries and run sub-$100 fee calculations — but must NOT reveal that it also holds `FINANCIAL_UNLIMITED` (bit 4) and `ACCESS_PII` (bit 7), reserved for internal Columbia CU operations.

**Problem with baseline:**
1. **Adversarial-AS risk:** Rival credit unions do not trust Columbia CU's AS to be honest about the agent's actual permissions. A compromised AS could claim the agent has `ACCESS_PII` at a partner CU's RS, or deny permissions it actually holds.
2. **AS availability:** During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours. All consortium agents are locked out because partner RSes cannot introspect tokens.
3. **Scope leakage:** Even with BBS+ selective disclosure, the credential issuer knows the full permission set and can correlate which partner CU the agent accessed.

**Chosen-predicate attack in the consortium setting:** A malicious partner CU could probe Columbia CU's agent with 8 sequential single-bit predicates (`requiredScopeMask = 0x01, 0x02, 0x04, ..., 0x80`), observing success/failure for each. Without constant-time discipline, timing differences between "proof generated and returned" (~500 ms) vs. "agent immediately rejects" (~1 ms) would reveal the full bitmask in 8 queries.

**Bolyra deployment with constant-time discipline:**
1. Columbia CU enrolls the agent's credential commitment (`Poseidon5(modelHash, opAx, opAy, 0b10010111, expiry)`) into the on-chain Bolyra agent Merkle tree.
2. When the agent contacts a partner CU's RS, the RS specifies `requiredScopeMask = 0b00000101` (bits 0 and 2: `READ_DATA | FINANCIAL_SMALL`).
3. The agent generates a `SelectiveScopeProof` locally (< 500 ms with rapidsnark). The proof is 768 bytes.
4. If a malicious partner RS probes with `requiredScopeMask = 0b01000000` (bit 6, `SUB_DELEGATE`, which the agent does NOT hold), the prover fails, and the agent waits until `T_prove` elapses before returning `{"error": "scope_insufficient"}`. The response time is indistinguishable from a legitimate proof that happened to take the full budget.
5. The partner RS verifies successful proofs against the on-chain `agentMerkleRoot` — no call to Columbia CU's AS, no trust in Columbia CU's infrastructure, no knowledge of the agent's full permission set.
6. The RS learns exactly one bit of information per query: the agent satisfies (or does not satisfy) the specified predicate. It learns nothing about unqueried bits. For the legitimate query `0b00000101`, it learns only that `READ_DATA` and `FINANCIAL_SMALL` are present — not whether `FINANCIAL_UNLIMITED`, `ACCESS_PII`, or `SUB_DELEGATE` are set.

**Regulatory alignment:** NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised at each access point — satisfying NCUA guidance on third-party AI risk management (Letter to Credit Unions 24-CU-03). The constant-time rejection protocol additionally ensures that probe-based reconnaissance by consortium partners cannot map internal permission structures — a risk highlighted in FFIEC's 2025 guidance on API security in multi-institution arrangements.

### Why boolean-return RFC 7662 does NOT close the gap

An AS could be configured to return only `{"active": true}` or `{"active": false}` for a given `requiredScopeMask` — effectively a boolean predicate endpoint. This appears to match the construction's one-bit-per-query information leakage. However:

1. **The boolean is the AS's assertion, not a mathematical proof.** A compromised AS returns `true` for unauthorized scopes. The RS has no cryptographic recourse — it trusted the AS's signed response, not a proof of predicate satisfaction over committed state.
2. **Implication closure is not enforced.** The boolean-return AS can assert that an agent with `FINANCIAL_UNLIMITED` but without `FINANCIAL_SMALL` satisfies a `FINANCIAL_SMALL` predicate. The RS cannot detect the structural violation. G5 and G6 are R1CS constraints — they reject such witnesses unconditionally.
3. **The AS remains in the hot path.** Even a boolean-return AS is an AS that must be available, trusted, and contacted. The construction eliminates this dependency entirely.

### Why Client Attestation, WIMSE WPoP, and hardware-attested SPIRE do not close the gap

Three emerging mechanisms strengthen the *identity* layer for non-human entities:

1. **Client Attestation (draft-ietf-oauth-attestation-based-client-auth):** Binds the client's identity to a hardware-backed key via an attestation JWT. The AS verifies the attestation at token issuance. **Failure mode:** Attestation certifies *platform identity* (TPM-backed key, device integrity), not *permission-structure invariants*. An attested client with an implication-violating bitmask (bit 4 set, bit 2 unset) passes attestation. The RS receives a token whose scope was determined by the AS post-attestation — the attestation adds trust in the *client's identity*, not in the *predicate evaluation*.

2. **WIMSE Workload Proof of Possession (draft-ietf-wimse-s2s-protocol):** A workload signs a token with its SPIFFE-issued key, proving it is the intended service-to-service caller. **Failure mode:** WPoP proves *which workload holds the token*, not *what the token authorizes*. Scope is still an AS-issued string in the token body. A compromised AS issues tokens with arbitrary scope to a legitimately attested workload.

3. **Hardware-attested SPIRE (SPIFFE Runtime Environment):** SPIRE issues X.509-SVIDs or JWT-SVIDs to workloads after verifying platform attestation (node attestation + workload attestation). **Failure mode:** SPIRE certifies workload identity within a trust domain. Authorization is separate — SPIRE's SVID carries no permission bitmask. Policy engines (e.g., OPA) evaluate authorization using the SVID as identity input, but the evaluation is an *assertion by the policy engine*, not a cryptographic proof.

| Property | Client Attestation | WIMSE WPoP | SPIRE | SelectiveScopeProof |
|---|---|---|---|---|
| What is proven | Platform identity | Token possession | Workload identity | Predicate satisfaction over enrolled bitmask |
| Implication closure | Not addressed | Not addressed | Not addressed | R1CS constraint (G6) |
| Adversarial AS | Attestation is pre-AS; AS still controls scope | WPoP is post-AS; scope is in token | SPIRE is identity-only; authz is separate | AS not in verification path |
| Predicate evaluation location | AS | AS | Policy engine | Circuit (G5) |
| What RS learns | Token scope (from AS) | Token scope (from AS) | Identity (from SPIRE) | Boolean: predicate satisfied or not |

### Why SD-JWT (RFC 9635) does not close the gap

SD-JWT (Selective Disclosure for JWTs, RFC 9635) allows a holder to selectively disclose individual claims from an issuer-signed JWT. This appears to offer holder-controlled selective presentation similar to the construction's scope privacy. Four concrete failure modes show it does not:

**(a) SD-JWT discloses claim *values*, not predicate satisfaction.** When an SD-JWT holder discloses a claim, the RS receives the claim name, salt, and value in plaintext (RFC 9635 Section 5.2). The holder can choose *which* claims to disclose, but disclosed claims are fully revealed. In contrast, `SelectiveScopeProof` reveals only that `permissionBitmask & requiredScopeMask == requiredScopeMask` — the RS learns a boolean, not the value of any individual bit. Furthermore, the *count* of disclosed claims leaks structural information: an SD-JWT with 3 disclosed claims is distinguishable from one with 7 disclosed claims. The ZK proof is constant-size regardless of how many bits satisfy the predicate.

**(b) No predicate evaluation over hidden claims.** RFC 9635 Section 5 is explicit: the verifier can only verify claims that are disclosed. There is no mechanism for the holder to prove `hiddenClaim >= threshold` or `hiddenBitmask & requiredMask == requiredMask` without disclosing the claim value. SD-JWT-based Key Binding (RFC 9635 Section 4.3) binds the presentation to a holder key but does not add predicate evaluation. The RS either sees the claim value or sees nothing — there is no intermediate "I can see that the predicate is satisfied but not the value."

**(c) Selective disclosure and implication closure enforcement are mutually exclusive.** The holder can hide claims (selective disclosure) OR the RS can verify structural invariants (by requiring full disclosure of all permission claims and checking implication closure) — but never both simultaneously. If the holder hides `FINANCIAL_UNLIMITED`, the RS cannot verify that `FINANCIAL_SMALL` is implied. If the RS requires disclosure of all financial-tier claims to check closure, selective disclosure is defeated. `SelectiveScopeProof` achieves both in a single proof because G5 (scope satisfaction) and G6 (implication closure) evaluate over the same hidden `permissionBitmask` witness.

**(d) SD-JWT remains issuer-dependent.** The SD-JWT is signed by the issuer (AS). A compromised issuer can sign an SD-JWT with false claims. The holder's selective disclosure is a privacy feature, not a trust-independence feature — the RS still trusts the issuer's signature. The construction removes the issuer from the trust model entirely.

| Property | SD-JWT (RFC 9635) | SelectiveScopeProof |
|---|---|---|
| What RS receives for hidden claims | Nothing (claim is absent) | Boolean predicate satisfaction |
| Predicate over hidden claims | Impossible (Section 5) | G5 evaluates over private `permissionBitmask` |
| Implication closure + hiding | Mutually exclusive | Simultaneous (G5 + G6 on same witness) |
| Presentation size | Grows with disclosed claims + salts | Constant 768 bytes (PLONK) |
| Issuer dependency | Issuer signs; compromised issuer = false claims | On-chain Merkle root; AS not in trust model |
| ZK property | None — disclosed claims are plaintext | SE-NIZK (PLONK simulation-extractable ZK) |

### Why RFC 8693 Token Exchange does not close the gap

RFC 8693 (OAuth 2.0 Token Exchange) enables an agent to exchange a broader token for a narrower one at the AS, with each exchange producing a new token scoped to the target audience and reduced permission set. This is the baseline's closest analog to runtime-adaptive scope narrowing — the agent can request a new token with only the permissions needed for a specific RS, at the moment of use. Five concrete failure modes show it does not match the construction:

**(a) Token exchange is runtime-adaptive but AS-dependent.** RFC 8693 Section 2.1 requires the agent to contact the AS's token endpoint for every scope-narrowing exchange. The agent sends `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` (the broader credential), `scope` (the narrowed set), and `resource` (the target RS). The AS evaluates the narrowing request and issues a new token. This is runtime-adaptive in the sense that the agent chooses when and how to narrow — but the AS is in the critical path for every narrowing operation. If the AS is offline, compromised, or adversarial, the agent cannot narrow its presentation. `SelectiveScopeProof` achieves runtime-adaptive narrowing with no AS contact: the agent generates a fresh proof with the RS-specified `requiredScopeMask` locally, using only its enrolled credential and the on-chain Merkle root.

**(b) The exchanged token is still an AS assertion.** The narrowed token issued via RFC 8693 is a signed JWT (or opaque token) whose scope field is the AS's assertion of what permissions the exchanged token carries. The RS verifies the AS's signature, not a mathematical proof that the narrowed scope is a valid subset of the original scope. A compromised AS can issue exchanged tokens with inflated scope (granting permissions the original token did not have), deflated scope (denial of service), or structurally invalid scope (FINANCIAL_UNLIMITED without FINANCIAL_SMALL). The RS has no mechanism to detect any of these — it trusts the AS's signature. In `SelectiveScopeProof`, the scope satisfaction (G5) and implication closure (G6) are R1CS constraints evaluated over the committed bitmask. No exchanged token, however signed, provides this guarantee.

**(c) Scope narrowing without implication closure enforcement.** RFC 8693 Section 2.1 specifies the `scope` parameter as a space-delimited string of scope values. The AS MAY apply policy to reject invalid narrowing requests, but this is an application-layer policy decision, not a cryptographic invariant. Nothing in RFC 8693 requires the AS to enforce that `financial_unlimited` implies `financial_small` — the AS can issue an exchanged token with `scope: "financial_unlimited"` but without `financial_small`, and the RS will accept it if the RS's local policy only checks for `financial_unlimited`. The circuit's G6 constraints reject such a witness unconditionally, regardless of what any party asserts.

**(d) Each exchange creates a linkable token.** Every RFC 8693 token exchange produces a new token that the AS can correlate to the original subject token, the requesting agent, the target RS, and the narrowed scope. The AS maintains a complete audit trail of every scope-narrowing operation — which agent narrowed which permissions for which RS at what time. Even if this is desirable for audit purposes, it means the AS has full visibility into the agent's access patterns. In `SelectiveScopeProof`, the `blindingNonce` ensures that the `agentNullifier` and `scopePredicateHash` are unlinkable across presentations. The AS (if it even exists) learns nothing about which RSes the agent contacted or which predicates were evaluated.

**(e) Token exchange does not scale to large permission spaces.** RFC 8693 inherits the scope-string representation: each narrowed permission must be named as a string in the `scope` parameter. For a 64-bit permission space, this requires up to 64 distinct scope strings per exchange request. For the 2^64 possible permission configurations, the AS's policy tables must enumerate valid narrowing combinations — a combinatorial explosion that no practical AS can precompute. The `SelectiveScopeProof` evaluates the predicate over the bitmask arithmetically in 64 multiplication constraints (G5), regardless of the permission space cardinality.

| Property | RFC 8693 Token Exchange | SelectiveScopeProof |
|---|---|---|
| Runtime-adaptive narrowing | Yes, but requires AS roundtrip per exchange | Yes, agent generates proof locally per RS request |
| AS dependency | AS must be online, trusted, and responsive | AS not contacted; trust = on-chain root + proof |
| Narrowing integrity | AS assertion (signed token) | R1CS constraint (G5: bitmask AND predicate) |
| Implication closure | AS policy decision (not cryptographic) | R1CS constraint (G6: unconditional rejection) |
| Cross-RS linkability | AS correlates all exchanges | Blinded nullifier; AS learns nothing |
| Permission space scalability | O(scope strings) per exchange; policy tables explode | O(1) proof; 64 constraints regardless of space |

**The key distinction:** RFC 8693 provides the *mechanism* for runtime scope narrowing but not the *trust model*. The agent can narrow, but the narrowing is attested by the AS — the same party whose trustworthiness is in question. `SelectiveScopeProof` provides both the mechanism (agent generates proof with RS-specified predicate) and the trust model (R1CS constraints over on-chain-committed state, verified by the RS independently).

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP + W3C VC/BBS+ + SD-JWT) fails on six properties the `SelectiveScopeProof` achieves simultaneously:

### Property 1: Adversarial-AS soundness with circuit-enforced implication closure

**Baseline:** RS assurance rests entirely on the AS's signed assertion — whether that assertion comes via RFC 7662 introspection, jwt-introspection-response caching, RFC 8693 token exchange, or BBS+/SD-JWT credential issuance. A malicious AS can lie. A boolean-return AS can assert that an agent with `FINANCIAL_UNLIMITED` but without `FINANCIAL_SMALL` satisfies a `FINANCIAL_SMALL` predicate — the RS cannot detect the structural violation. Client Attestation, WIMSE WPoP, and hardware-attested SPIRE certify *identity and platform state*, not *permission-structure invariants*. SD-JWT's selective disclosure cannot simultaneously hide claims and enforce implication closure. RFC 8693 exchanges are AS-asserted narrowing — a compromised AS can issue structurally invalid narrowed tokens.

**Construction:** G5 (scope satisfaction) and G6 (implication closure) are R1CS constraints. No valid witness can satisfy the circuit with an implication-violating bitmask. The AS is not in the verification path; trust = on-chain root + proof soundness.

**Concrete gap:** Compromise Columbia CU's AS. Issue an RFC 8693 exchanged token asserting `scope: "financial_unlimited"` without `financial_small` for an agent accessing a partner CU. The partner CU's RS verifies the AS signature and grants access — the structural violation is invisible. In `SelectiveScopeProof`, the same witness fails G6 unconditionally. No amount of AS compromise changes this.

### Property 2: Zero-knowledge predicate evaluation (not selective disclosure)

**Baseline:** RFC 7662 introspection reveals the full scope string. BBS+ reveals claim *values* for disclosed claims. SD-JWT reveals claim names, salts, and values in plaintext for disclosed claims (RFC 9635 Section 5.2) — and cannot evaluate predicates over hidden claims (Section 5). RFC 8693 produces a new token with the narrowed scope as a plaintext string. None of these evaluate a predicate over a hidden input and return only a boolean.

**Construction:** The RS learns only `pred(permissionBitmask) = 1` — not any individual bit value, not the Hamming weight, not the claim count, not structural properties beyond predicate satisfaction. This is a ZK property, not a selective disclosure property.

### Property 3: AS-blind presentation

**Baseline:** Every variant requires AS involvement. RFC 7662 requires AS for introspection. RFC 8693 requires AS for each exchange. BBS+ requires AS at issuance. SD-JWT requires AS to sign the original JWT.

**Construction:** The agent generates the proof locally. The RS verifies against on-chain state. The AS is not contacted, not informed, not needed.

### Property 4: Constant-size proof regardless of bitmask width

**Baseline:** JWT scope strings grow linearly. BBS+ derived proofs grow with disclosed message count `O(|disclosed|)`. SD-JWT presentations grow with disclosed claims plus salt/value pairs. RFC 8693 exchanged tokens grow with the narrowed scope string length. For a 64-bit permission space, enumeration is infeasible.

**Construction:** PLONK proof is exactly 768 bytes regardless of bitmask width, predicate size, or permission count.

### Property 5: Cryptographic binding to runtime model identity

**Baseline:** `client_id` is a static registration string. Neither RFC 7662, DPoP, RFC 8693, BBS+, nor SD-JWT bind the token to a specific model hash + operator key + permission bitmask at call time.

**Construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. A different model, operator, or permission set produces a different commitment that is not enrolled.

### Property 6: Multi-query simulation-extractable zero-knowledge

**Baseline:** BBS+ is HVZK (honest-verifier zero-knowledge), not SE-NIZK — Groth16 proof malleation is a concrete attack that SE-NIZK prevents. SD-JWT has no ZK property at all — disclosed claims are plaintext. RFC 8693 exchanged tokens are plaintext JWTs. RFC 7662 introspection responses are plaintext JSON.

**Construction:** PLONK with Fiat-Shamir in ROM provides simulation-extractable zero-knowledge (Faust et al. 2022). The `blindingNonce` randomizes each transcript. Even an adversary collecting polynomially many proofs cannot malleate or correlate them.

### Summary

The baseline's limitations are architectural, not configurational. RFC 7662 defines introspection as "the AS tells you about this token." RFC 8693 defines token exchange as "the AS issues you a narrower token." BBS+ and SD-JWT are "the issuer signed these claims." In every case, the trust root is an assertion by a party whose integrity is assumed. No layering of DPoP, audience binding, token exchange, selective disclosure, client attestation, workload attestation, or hardware roots of trust changes this — because none of these mechanisms evaluate the authorization predicate at the cryptographic layer.

The `SelectiveScopeProof` moves the trust root from "the AS said so" to "the on-chain Merkle tree contains this commitment, the operator's signature is valid, and the bitmask satisfies the predicate with valid implication closure" — verified inside a simulation-extractable zero-knowledge proof that reveals nothing beyond predicate satisfaction. The distinction is not "what the RS sees" (a boolean-return AS or SD-JWT can limit what the RS sees) but "who evaluates the predicate and who enforces structural invariants" — AS assertion vs. R1CS constraint. This is a category difference, not a degree difference.
