# Construction

## 1. Statement of claim

Same agent accessing different Resource Server (RS) instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively attempts to correlate per-agent traffic graphs across scopes. Formally: no PPT adversary controlling the AS and colluding with any strict subset of RSes can distinguish whether two authorization proofs presented to two distinct RSes originate from the same agent or from two independent agents, except with negligible advantage.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopeBlindAuth`

This circuit replaces the AS-mediated token issuance flow. The agent generates a ZK proof locally — the AS is never on the critical path.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Agent model identifier hash |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Agent's full permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `scopeBlindingSecret` | field | Per-agent persistent blinding scalar, range-checked to [0, 2^251) |
| `merkleProofLength` | uint | Depth of Merkle proof |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Sibling hashes |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | field | RS-specific scope identifier (e.g., Poseidon hash of RS domain) |
| `requiredScopeMask` | uint64 | Required permission bits for this RS |
| `currentTimestamp` | uint64 | Verifier-supplied current time |
| `freshNonce` | field | Per-request replay-prevention nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | field | Computed Merkle root for agent tree |
| `scopePseudonym` | field | Poseidon2(scopeId, scopeBlindingSecret) — unlinkable across scopes |
| `nonceBinding` | field | Poseidon2(scopePseudonym, freshNonce) — replay prevention |
| `scopeCommitment` | field | Poseidon2(permissionBitmask, credentialCommitment) — for delegation chain entry |

**Constraints (in order):**

1. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. `Num2Bits(251)` on `scopeBlindingSecret`.

2. **Credential commitment:**
   ```
   credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
   ```

3. **EdDSA signature verification:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credentialCommitment)`.

4. **Merkle membership:** `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf produces `agentMerkleRoot`.

5. **Scope satisfaction:** For each bit `i` in `[0, 64)`:
   ```
   requiredBits[i] * (1 - permBits[i]) === 0
   ```

6. **Cumulative bit encoding:**
   ```
   permBits[4] * (1 - permBits[3]) === 0
   permBits[4] * (1 - permBits[2]) === 0
   permBits[3] * (1 - permBits[2]) === 0
   ```

7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.

8. **Scope pseudonym derivation:**
   ```
   scopePseudonym = Poseidon2(scopeId, scopeBlindingSecret)
   ```

9. **Nonce binding:**
   ```
   nonceBinding = Poseidon2(scopePseudonym, freshNonce)
   ```

10. **Scope commitment (for delegation chain compatibility):**
    ```
    scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
    ```

### Anti-timing gadget: Batch submission envelope

To defeat AS-level timing correlation, a **batch relayer** collects `ScopeBlindAuth` proofs from multiple agents and submits them in a single on-chain transaction at fixed intervals (e.g., every 30 seconds). The relayer sees proofs but cannot link them — each proof's `scopePseudonym` is scope-specific and the `credentialCommitment` is hidden as a private input.

### Delegation extension: `ScopeBlindDelegation`

Extends the existing `Delegation` circuit with a `delegateeScopeBlindingSecret` private input. The delegatee's `scopePseudonym` is derived from *their own* blinding secret, not the delegator's — ensuring delegation chains do not create a correlation handle.

**Additional constraint added to Delegation circuit:**
```
delegateeScopePseudonym = Poseidon2(scopeId, delegateeScopeBlindingSecret)
```

The `delegateeScopePseudonym` replaces the delegatee's nullifier as the public-facing identifier at each RS.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary `A` controls:
- The Authorization Server (full control — issues credentials, logs all interactions)
- Up to `k-1` of `k` total Resource Servers (colluding subset)
- Network-level observation of proof submission timing and metadata

The adversary does NOT control:
- The agent's local proving environment (trusted execution)
- The on-chain Merkle tree integrity (blockchain consensus)
- The honest RS(es) that the agent also contacts

### IND-UNL-AS Game

**Setup:** Challenger enrolls `n ≥ 2` agents in the agent Merkle tree. Each agent `i` has credential commitment `cc_i` and scope blinding secret `sbs_i`, all drawn uniformly from the valid domain.

**Challenge phase:**
1. Adversary `A` selects two distinct agents `(agent_0, agent_1)` and two distinct scope identifiers `(scopeId_A, scopeId_B)` where `A` controls the RS for `scopeId_A` and not for `scopeId_B`.
2. Challenger flips bit `b ←$ {0, 1}`.
3. Challenger generates:
   - Proof `π_A` for `agent_b` at `scopeId_A` (adversary sees this proof and its public signals).
   - Proof `π_B` for `agent_b` at `scopeId_B` (adversary sees only that *some* proof was submitted for `scopeId_B`, but not the public signals, since the honest RS does not collude).
4. Adversary `A` additionally receives all AS-side logs: which agents requested credentials, when, and for which scopes (in a non-ZK system). In the ZK system, `A` receives nothing — the agent proves locally.

**Adversary wins:** `A` outputs `b'` and wins if `b' = b` with advantage `> negl(λ)`.

**Key distinction from baseline:** In the baseline, step 4 gives the AS a complete per-agent authorization log. In Bolyra, the AS receives no per-request signal because proofs are generated locally against on-chain state.

### Side-channel sub-game (timing)

**Setup:** Same as above, but adversary additionally observes submission timestamps.

**Mitigation model:** Proofs are submitted via a batch relayer with epoch `Δ = 30s`. Within an epoch, all proofs are shuffled and submitted atomically. Adversary sees epoch boundaries but not per-proof timing within an epoch.

**Adversary advantage bound:** If `m` proofs are submitted per epoch, adversary's timing-based correlation advantage is at most `1/m` per epoch (random permutation within the batch).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security (POS-PRF):** Poseidon2, keyed on the second input (i.e., `Poseidon2(scopeId, scopeBlindingSecret)` with `scopeBlindingSecret` as the key), is a pseudorandom function family over the BN254 scalar field.

2. **Discrete logarithm hardness on Baby Jubjub (DL-BJJ):** Given `(Ax, Ay) = s · G`, no PPT adversary can recover `s`.

3. **Poseidon collision resistance (POS-CR):** No PPT adversary can find distinct inputs producing the same Poseidon output.

4. **Knowledge soundness of Groth16/PLONK (KS-G16/KS-PLONK):** In the generic group model + random oracle model, the proving systems satisfy knowledge soundness: a valid proof implies the prover knows a satisfying witness.

### Reduction sketch: IND-UNL-AS → POS-PRF

**Theorem:** If Poseidon2 is a secure PRF (POS-PRF), then no PPT adversary wins the IND-UNL-AS game with non-negligible advantage.

**Proof sketch:**

1. The only public signal that could distinguish `agent_0` from `agent_1` at `scopeId_A` is `scopePseudonym_A = Poseidon2(scopeId_A, sbs_b)`.

2. Suppose adversary `A` wins IND-UNL-AS with advantage `ε`. Construct a PRF distinguisher `D` as follows:
   - `D` receives oracle access to either `F_k(·) = Poseidon2(·, k)` for random `k`, or a truly random function `R(·)`.
   - `D` embeds the challenge: set `sbs_0` = the PRF key, draw `sbs_1 ←$ F_p` independently.
   - When `b = 0`, `scopePseudonym_A = F_k(scopeId_A)`. When `b = 1`, `scopePseudonym_A = Poseidon2(scopeId_A, sbs_1)` which is an independent PRF evaluation.
   - `D` runs `A` on the resulting proof. If `A` can distinguish, `D` can distinguish `F_k` from random, contradicting POS-PRF.

3. Cross-scope linking requires correlating `Poseidon2(scopeId_A, sbs_b)` with `Poseidon2(scopeId_B, sbs_b)` — but the adversary never sees the `scopeId_B` pseudonym (honest RS). Even if it did, PRF security means evaluations at different inputs are computationally independent.

4. The `agentMerkleRoot` is shared across all proofs (it is the global tree root). This does NOT help the adversary because all agents share the same root — it reveals the set, not the individual.

5. `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is deterministic per agent, but it is used only for delegation chain linking and can be omitted from the public signals when delegation is not invoked. When present, it is the same across scopes for the same agent — but it is hidden behind Groth16's zero-knowledge property (it is a public *output* verified on-chain, and the adversary would need to break KS-G16 to extract the witness that maps it to a specific credential).

   **Refinement:** When cross-scope unlinkability is required WITHOUT delegation, the circuit omits `scopeCommitment` from public outputs (a compile-time flag). When delegation IS needed, `scopeCommitment` is revealed only to the specific RS that will anchor the delegation chain, and that RS is assumed honest for the delegation sub-protocol. This is the standard trust partition: unlinkability holds against the adversarial AS and colluding RSes; delegation requires at least one honest RS in the chain.

**QED (sketch). Full formal proof would proceed via hybrid argument over the number of colluding RSes.**

### Replay prevention argument

`nonceBinding = Poseidon2(scopePseudonym, freshNonce)` binds each proof to a unique nonce. The on-chain verifier checks nonce freshness. Under POS-CR, an adversary cannot find a different `(scopePseudonym', freshNonce')` pair that produces the same `nonceBinding`, so replayed proofs are rejected.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| `scopePseudonym` derivation | `Poseidon2(scopeId, scopeBlindingSecret)` | Poseidon hash (§2 Cryptographic Primitives) |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | §4.2 Agent Proof Specification |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | §2 Cryptographic Primitives |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §2 Merkle Tree |
| Scope satisfaction | Bitwise AND gate (per-bit constraint) | §4.2 constraint 5 |
| Cumulative bit encoding | Implication constraints on bits 2/3/4 | §4.2 constraint 6 |
| Nonce binding | `Poseidon2(scopePseudonym, freshNonce)` | Analogous to §3.2 human nonceBinding |
| Delegation chain entry | `Poseidon2(permBitmask, credCommitment)` | §5.1 Identity-Bound Scope Commitment |
| Proving system | PLONK (agent circuit — universal setup) | §2.3 Proving Systems (OPTIONAL for AgentPolicy) |
| Nullifier (human side, unchanged) | `Poseidon2(scope, secret)` | §3.2 HumanUniqueness |

The `scopeBlindingSecret` is a new per-agent secret, generated once at agent enrollment and stored alongside the agent's credential material. It is NOT derived from the credential commitment (which is deterministic and could be brute-forced from known fields). It is a fresh 251-bit random scalar.

## 6. Circuit cost estimate

### `ScopeBlindAuth` constraint breakdown

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Num2Bits(64)` × 3 (permBitmask, expiry, currentTimestamp) | 192 |
| `Num2Bits(251)` × 1 (scopeBlindingSecret) | 251 |
| `Poseidon5` (credential commitment) | ~1,500 |
| `EdDSAPoseidonVerifier` | ~5,500 |
| `BinaryMerkleRoot(20)` (20 levels × ~800 per Poseidon2) | ~16,000 |
| Scope satisfaction (64 AND gates) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 3 (scopePseudonym, nonceBinding, scopeCommitment) | ~2,400 |
| **Total** | **~26,040** |

This fits within `pot16.ptau` (2^16 = 65,536 constraints).

### Proving time targets

| System | Target | Rationale |
|--------|--------|-----------|
| PLONK (agent, snarkjs) | < 4s | Universal setup; no per-circuit ceremony. Well within 5s agent budget. |
| PLONK (agent, rapidsnark) | < 0.8s | Native prover ~5× faster than snarkjs WASM. |
| Groth16 (agent, snarkjs) | < 3s | Smaller proof, faster verification, but requires circuit-specific Phase 2. |
| Groth16 (agent, rapidsnark) | < 0.6s | Production target. |

Verification: Groth16 on-chain ~220k gas. PLONK on-chain ~300k gas. Both well within block gas limits.

### Comparison to existing `AgentPolicy`

The existing `AgentPolicy` circuit has approximately the same gadgets minus `Num2Bits(251)` for the blinding secret and the additional `Poseidon2` for `scopePseudonym`. Net addition: ~1,050 constraints (~4% overhead). Negligible impact on proving time.

## 7. Concrete deployment scenario

### Cross-credit-union member agent (primary scenario)

**Stakeholders:**
- **Desert Financial Credit Union** (Phoenix, AZ) — acts as the AS / credential issuer
- **CU*Answers** — CUSO operating shared infrastructure for 150+ credit unions
- **Member "Alice"** — holds accounts at Desert Financial and BECU (Seattle)
- **Alice's AI agent** — authorized to perform balance checks and small payments (< $100) at merchant RSes

**Current problem:** Alice's agent uses Desert Financial's OAuth AS to obtain tokens for Merchant-A (a Phoenix grocery chain) and Merchant-B (a Seattle pharmacy). Desert Financial sees both token requests. Desert Financial's data analytics team can reconstruct Alice's merchant graph — a privacy violation under NCUA Regulation V (affiliate marketing opt-out) and potentially under Arizona's forthcoming financial privacy act.

**Bolyra deployment:**

1. **Enrollment:** Desert Financial enrolls Alice's agent credential in the Bolyra agent Merkle tree. The credential commitment encodes `permissionBitmask = 0b00000101` (READ_DATA + FINANCIAL_SMALL). Desert Financial also issues the EdDSA signature over the credential commitment. Alice's agent generates a random `scopeBlindingSecret` locally.

2. **Authorization at Merchant-A:** Alice's agent computes `scopeId_A = Poseidon(domain:"merchant-a.example.com")` and generates a `ScopeBlindAuth` proof locally. The proof's public output `scopePseudonym_A = Poseidon2(scopeId_A, scopeBlindingSecret)` serves as Alice's pseudonymous identifier at Merchant-A. The proof is submitted to the on-chain registry (or verified off-chain by Merchant-A using the exported verifier).

3. **Authorization at Merchant-B:** Alice's agent computes `scopeId_B = Poseidon(domain:"merchant-b.example.com")` and generates a separate `ScopeBlindAuth` proof. The public output `scopePseudonym_B = Poseidon2(scopeId_B, scopeBlindingSecret)` is a completely different value. Merchant-B cannot correlate it with `scopePseudonym_A`.

4. **Desert Financial (AS) sees nothing:** The agent generated both proofs locally. No token request was sent to Desert Financial's AS. Desert Financial knows Alice's agent *exists* (it enrolled the credential) but has zero visibility into which merchants the agent contacted, when, or how often.

5. **Batch relayer (timing defense):** Both proofs are submitted through the CU*Answers batch relayer, which aggregates proofs from agents across all 150 member credit unions and submits them in 30-second epochs. Even a network observer cannot isolate Alice's proofs by timing.

6. **Sybil prevention:** Within a single scope (e.g., Merchant-A), Alice's agent always produces the same `scopePseudonym_A` (deterministic in `scopeId` and `scopeBlindingSecret`). Merchant-A can detect if Alice tries to register two accounts. Across scopes, pseudonyms are unlinkable.

### Healthcare delegation scenario (secondary)

**Stakeholders:**
- **Kaiser Permanente** — primary care provider, acts as credential issuer
- **Cedars-Sinai** — specialist provider (RS-B)
- **Patient "Bob"** — referred from Kaiser to Cedars-Sinai
- **Bob's health agent** — carries a delegated credential with `ACCESS_PII` narrowed to `READ_DATA`

Bob's agent receives a delegation from Kaiser's agent (which holds `ACCESS_PII | READ_DATA | WRITE_DATA`). The delegation circuit narrows scope to `READ_DATA` only. Bob's agent then generates a `ScopeBlindAuth` proof for Cedars-Sinai using its own `scopeBlindingSecret`. Kaiser sees the delegation event (on-chain) but the `scopePseudonym` at Cedars-Sinai is derived from Bob's agent's blinding secret — Kaiser cannot determine which specialist RS the delegation was used at.

## 8. Why the baseline cannot match

### Structural impossibility 1: AS is the issuer AND the adversary

In OAuth/OIDC, every token is issued by the AS. The AS necessarily sees the `(agent, RS, scope, timestamp)` tuple at issuance time. PPID hides the `sub` from RSes but NOT from the AS itself. BBS+ hides claim subsets from RSes but the original credential issuance is fully visible to the issuer.

**Bolyra eliminates the AS from the per-request path entirely.** The agent proves authorization by generating a ZK proof locally against on-chain state. The AS's role is reduced to one-time credential enrollment. This is a categorical architectural difference, not a parameter tuning.

### Structural impossibility 2: No scope-blind pseudonym primitive exists in OAuth

OAuth identifiers (`sub`, `client_id`, DPoP key thumbprint) are either global (same across RSes) or AS-computed (PPID — AS holds the mapping). There is no mechanism for the agent to locally derive an RS-specific pseudonym that is:
- Deterministic (same pseudonym at the same RS across sessions, enabling account continuity)
- Unlinkable across RSes (different pseudonyms at different RSes)
- Verifiable without AS involvement (RS can check validity via ZK proof)

`scopePseudonym = Poseidon2(scopeId, scopeBlindingSecret)` achieves all three. The PRF property of Poseidon2 ensures computational unlinkability; the ZK proof ensures the pseudonym is bound to a valid enrolled credential.

### Structural impossibility 3: No formal security definition

The baseline provides no IND-UNL-AS game, no reduction to named assumptions, and no bound on adversary advantage. BBS+ multi-show unlinkability is defined only at the holder-to-verifier layer and explicitly assumes an honest issuer. DPoP and RFC 8707 have no privacy security definitions at all.

Bolyra provides a formal game definition (§3), a named assumption (POS-PRF), and a reduction sketch bounding adversary advantage to the PRF distinguishing advantage — which is negligible under standard assumptions on Poseidon over BN254.

### Structural impossibility 4: Timing correlation is unmitigated

Every OAuth token request creates an AS-observable event with a timestamp. No RFC specifies batching, padding, or oblivious issuance. An adversarial AS with millisecond-resolution logs can correlate token requests by timing alone, even if all other identifiers were hidden.

Bolyra's batch relayer submits proofs in fixed-epoch batches of `m` proofs, reducing timing correlation advantage to `1/m` per epoch. This is a protocol-level mitigation, not an application-layer afterthought.

### Structural impossibility 5: Delegation chain topology is AS-visible

RFC 8693 Token Exchange requires an AS roundtrip per delegation hop. The AS sees the full chain: who delegated to whom, with what scope, at what time. In Bolyra, delegation proofs are verified on-chain; the AS sees only that *a* delegation occurred, not the delegatee's identity or the RS where the delegated credential will be used. The delegatee's `scopePseudonym` at the target RS is derived from the delegatee's own blinding secret — architecturally unlinkable from the delegator's pseudonyms.
