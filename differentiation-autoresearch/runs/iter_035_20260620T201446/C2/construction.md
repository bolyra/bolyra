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
| `scopeBoundDelegationAnchor` | field | Poseidon3(scopeId, permissionBitmask, credentialCommitment) — scope-specific delegation chain seed |

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

10. **Scope-bound delegation anchor:**
    ```
    scopeBoundDelegationAnchor = Poseidon3(scopeId, permissionBitmask, credentialCommitment)
    ```

Constraint 10 replaces the prior scope-agnostic `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. The inclusion of `scopeId` ensures the delegation chain seed is scope-specific: an anchor published at RS-A reveals nothing about the anchor at RS-B, even though both derive from the same credential.

### Anti-timing gadget: Batch submission envelope

To defeat AS-level timing correlation, a **batch relayer** collects `ScopeBlindAuth` proofs from multiple agents and submits them in a single on-chain transaction at fixed intervals (e.g., every 30 seconds). The relayer sees proofs but cannot link them — each proof's `scopePseudonym` is scope-specific and the `credentialCommitment` is hidden as a private input.

### Delegation extension: `ScopeBlindDelegation`

Extends the existing `Delegation` circuit with scope-bound chain linking and per-delegatee blinding.

**Private inputs (changes from base Delegation circuit):**

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorCredCommitment` | field | Delegator's credential commitment |
| `delegateeCredCommitment` | field | Delegatee's credential commitment |
| `delegatorScope` | uint64 | Delegator's permission bitmask |
| `delegateeScope` | uint64 | Delegatee's permission bitmask |
| `delegateeExpiry` | uint64 | Delegatee expiry timestamp |
| `delegatorExpiry` | uint64 | Delegator expiry timestamp |
| `delegatorPubkeyAx`, `delegatorPubkeyAy` | field | Delegator EdDSA public key |
| `sigR8x`, `sigR8y`, `sigS` | field | Delegator EdDSA signature over delegation token |
| `delegateeMerkleProofLength`, `delegateeMerkleProofIndex`, `delegateeMerkleProofSiblings[20]` | | Delegatee Merkle proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | field | RS-specific scope identifier — same `scopeId` as the handshake that seeds this chain |
| `previousScopeBoundAnchor` | field | Chain-linking value from prior hop (scope-bound) |
| `sessionNonce` | field | Session binding value |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `newScopeBoundAnchor` | field | Poseidon3(scopeId, delegateeScope, delegateeCredCommitment) |
| `delegationNullifier` | field | Poseidon2(delegationTokenHash, sessionNonce) |
| `delegateeMerkleRoot` | field | Computed Merkle root for delegatee enrollment |

**Modified constraints:**

1. **Scope-bound chain linking (replaces base constraint 2):**
   ```
   Poseidon3(scopeId, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor
   ```

2. **New scope-bound anchor output:**
   ```
   newScopeBoundAnchor = Poseidon3(scopeId, delegateeScope, delegateeCredCommitment)
   ```

3. **Delegation token (unchanged in structure):**
   ```
   delegationToken = Poseidon4(previousScopeBoundAnchor, delegateeCredCommitment, delegateeScope, delegateeExpiry)
   ```

All other constraints (scope subset, cumulative bit encoding, expiry narrowing, EdDSA signature, delegatee enrollment) remain identical to the base Delegation circuit.

**Why `scopeId` is a public input to the delegation circuit:** The delegation chain is intrinsically bound to the RS where it will be exercised. A delegator at RS-A signs a delegation token that commits to `previousScopeBoundAnchor`, which itself includes `scopeId_A`. The delegatee cannot repurpose this delegation proof at RS-B — the `scopeId` mismatch would cause the chain-linking constraint to fail. This scope-binding is not a limitation; it is the mechanism by which delegation and unlinkability coexist: delegation chains are per-RS, and per-RS chains reveal nothing about other RSes.

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

### IND-UNL-AS Game (unified — covers both standalone auth and delegation)

**Setup:** Challenger enrolls `n ≥ 2` agents in the agent Merkle tree. Each agent `i` has credential commitment `cc_i` and scope blinding secret `sbs_i`, all drawn uniformly from the valid domain.

**Challenge phase:**
1. Adversary `A` selects two distinct agents `(agent_0, agent_1)` and two distinct scope identifiers `(scopeId_A, scopeId_B)` where `A` controls the RS for `scopeId_A` and not for `scopeId_B`.
2. Challenger flips bit `b ←$ {0, 1}`.
3. Challenger generates:
   - Proof `π_A` for `agent_b` at `scopeId_A` (adversary sees this proof and its public signals, including `scopeBoundDelegationAnchor_A` if delegation is invoked).
   - Proof `π_B` for `agent_b` at `scopeId_B` (adversary sees only that *some* proof was submitted for `scopeId_B`, but not the public signals, since the honest RS does not collude).
4. **(Delegation extension):** Adversary may additionally request up to `poly(λ)` delegation proofs at `scopeId_A`, receiving full public signals including `newScopeBoundAnchor` values for each hop. Adversary may also request delegation proofs at `scopeId_B` but receives no public signals (honest RS).
5. Adversary `A` additionally receives all AS-side logs. In the ZK system, `A` receives nothing — the agent proves locally.

**Adversary wins:** `A` outputs `b'` and wins if `b' = b` with advantage `> negl(λ)`.

**Why delegation does not weaken the game:** The adversary sees `scopeBoundDelegationAnchor_A = Poseidon3(scopeId_A, permBitmask_b, cc_b)` at the compromised RS. At the honest RS, the anchor would be `Poseidon3(scopeId_B, permBitmask_b, cc_b)` — a different Poseidon3 evaluation on a different first input. Linking the two requires inverting Poseidon3 to extract the shared `(permBitmask_b, cc_b)` suffix, which reduces to breaking POS-PRF (see §4). The prior construction's scope-agnostic `scopeCommitment = Poseidon2(permBitmask, cc)` was identical across scopes — a trivial correlator. The scope-bound anchor eliminates this.

### Side-channel sub-game (timing)

**Setup:** Same as above, but adversary additionally observes submission timestamps.

**Mitigation model:** Proofs are submitted via a batch relayer with epoch `Δ = 30s`. Within an epoch, all proofs are shuffled and submitted atomically. Adversary sees epoch boundaries but not per-proof timing within an epoch.

**Adversary advantage bound:** If `m` proofs are submitted per epoch, adversary's timing-based correlation advantage is at most `1/m` per epoch (random permutation within the batch).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security (POS-PRF):** Poseidon2 and Poseidon3, keyed on the last input(s), are pseudorandom function families over the BN254 scalar field. Specifically:
   - `Poseidon2(scopeId, ·)` keyed on `scopeBlindingSecret` is a PRF (unlinkability of `scopePseudonym`).
   - `Poseidon3(scopeId, ·, ·)` keyed on `(permBitmask, credCommitment)` is a PRF (unlinkability of `scopeBoundDelegationAnchor`).

2. **Discrete logarithm hardness on Baby Jubjub (DL-BJJ):** Given `(Ax, Ay) = s · G`, no PPT adversary can recover `s`.

3. **Poseidon collision resistance (POS-CR):** No PPT adversary can find distinct inputs producing the same Poseidon output.

4. **Knowledge soundness of Groth16/PLONK (KS-G16/KS-PLONK):** In the generic group model + random oracle model, the proving systems satisfy knowledge soundness: a valid proof implies the prover knows a satisfying witness.

### Reduction sketch: IND-UNL-AS → POS-PRF

**Theorem:** If Poseidon2 and Poseidon3 are secure PRFs (POS-PRF), then no PPT adversary wins the IND-UNL-AS game with non-negligible advantage, even when delegation is active.

**Proof sketch:**

1. **Standalone auth (no delegation).** The only public signal that could distinguish `agent_0` from `agent_1` at `scopeId_A` is `scopePseudonym_A = Poseidon2(scopeId_A, sbs_b)`. The reduction to POS-PRF proceeds exactly as before: a PRF distinguisher `D` embeds the challenge agent's blinding secret as the PRF key and runs the adversary. If the adversary distinguishes, `D` breaks POS-PRF.

2. **With delegation (new argument).** The adversary additionally sees `scopeBoundDelegationAnchor_A = Poseidon3(scopeId_A, permBitmask_b, cc_b)` at the compromised RS. We must show this does not help correlate with `scopeId_B`.

   Construct a PRF distinguisher `D'`:
   - `D'` receives oracle access to either `F_{k}(·) = Poseidon3(·, k_1, k_2)` for random key `(k_1, k_2) = (permBitmask, cc)`, or a truly random function `R(·)`.
   - `D'` embeds `agent_0`'s credential fields as the PRF key. For `agent_1`, `D'` draws independent credential fields.
   - When `b = 0`: `scopeBoundDelegationAnchor_A = F_k(scopeId_A)`, a PRF evaluation.
   - When `b = 1`: `scopeBoundDelegationAnchor_A = Poseidon3(scopeId_A, permBitmask_1, cc_1)`, an independent evaluation under a different key.
   - Cross-scope linking requires correlating `F_k(scopeId_A)` with `F_k(scopeId_B)`. But the adversary never sees the `scopeId_B` anchor (honest RS). Even if it did, PRF security means evaluations at distinct inputs under the same key are indistinguishable from random — and the adversary doesn't know *which* key is in play.
   - If `A` wins IND-UNL-AS with advantage `ε`, then `D'` distinguishes `F_k` from random with advantage `ε`, contradicting POS-PRF.

3. **Joint leakage.** The adversary sees both `scopePseudonym_A` and `scopeBoundDelegationAnchor_A` at the compromised RS. These are derived from independent secrets (`scopeBlindingSecret` vs. `credentialCommitment`) under different Poseidon arities. A hybrid argument over the two PRF instances shows the joint advantage is at most `ε_PRF2 + ε_PRF3`, both negligible.

4. **Delegation chain hops.** Each subsequent `newScopeBoundAnchor` in the chain is `Poseidon3(scopeId, delegateeScope, delegateeCC)` — a fresh PRF evaluation under the delegatee's credential as key, at the same `scopeId`. The adversary learns a sequence of PRF evaluations at the same input (`scopeId_A`) under *different* keys (different delegatees). This reveals nothing about evaluations at `scopeId_B` under any of those keys.

5. The `agentMerkleRoot` is shared across all proofs. This does NOT help the adversary because all agents share the same root.

**QED (sketch). Full formal proof would proceed via hybrid argument over the number of colluding RSes and delegation hops.**

### Replay prevention argument

`nonceBinding = Poseidon2(scopePseudonym, freshNonce)` binds each proof to a unique nonce. The on-chain verifier checks nonce freshness. Under POS-CR, an adversary cannot find a different `(scopePseudonym', freshNonce')` pair that produces the same `nonceBinding`, so replayed proofs are rejected.

### Delegation chain integrity under scope binding

The chain-linking constraint `Poseidon3(scopeId, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor` ensures that a delegation proof generated for `scopeId_A` cannot be replayed at `scopeId_B`. The `scopeId` is a public input verified by the on-chain registry — the prover cannot substitute it without breaking the chain-linking equation. Under POS-CR, no `(scopeId', delegatorScope', delegatorCredCommitment')` distinct from the original tuple can produce the same anchor.

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
| Scope-bound delegation anchor | `Poseidon3(scopeId, permBitmask, credCommitment)` | Extends §5.1 Identity-Bound Scope Commitment with scope binding |
| Delegation chain linking | `Poseidon3(scopeId, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor` | Replaces §5.2 constraint 2 |
| Proving system | PLONK (agent circuit — universal setup) | §2.3 Proving Systems (OPTIONAL for AgentPolicy) |
| Nullifier (human side, unchanged) | `Poseidon2(scope, secret)` | §3.2 HumanUniqueness |

The `scopeBlindingSecret` is a new per-agent secret, generated once at agent enrollment and stored alongside the agent's credential material. It is NOT derived from the credential commitment (which is deterministic and could be brute-forced from known fields). It is a fresh 251-bit random scalar.

**Migration from base spec `scopeCommitment`:** The base spec's `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is replaced everywhere by `scopeBoundDelegationAnchor = Poseidon3(scopeId, permissionBitmask, credentialCommitment)`. The on-chain `lastScopeCommitment` mapping is renamed to `lastScopeBoundAnchor` and keyed by `(sessionNonce, scopeId)` to support per-RS delegation chains originating from the same handshake session.

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
| `Poseidon2` × 2 (scopePseudonym, nonceBinding) | ~1,600 |
| `Poseidon3` × 1 (scopeBoundDelegationAnchor) | ~1,200 |
| **Total** | **~26,440** |

This fits within `pot16.ptau` (2^16 = 65,536 constraints). Net change from prior construction: +400 constraints (~1.5% increase) due to Poseidon3 replacing one Poseidon2 for the delegation anchor. The Poseidon3 hash (3-input) uses one additional full round compared to Poseidon2, adding approximately 400 constraints.

### `ScopeBlindDelegation` constraint breakdown

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Base Delegation circuit (unchanged gadgets) | ~25,000 |
| `Poseidon3` × 2 (chain-link check + new anchor output) | ~2,400 |
| Replaces: `Poseidon2` × 2 from base spec | −1,600 |
| **Net change from base Delegation** | **+800** |
| **Total** | **~25,800** |

Fits within `pot16.ptau`.

### Proving time targets

| System | Target | Rationale |
|--------|--------|-----------|
| PLONK (agent, snarkjs) | < 4s | Universal setup; no per-circuit ceremony. Well within 5s agent budget. |
| PLONK (agent, rapidsnark) | < 0.8s | Native prover ~5× faster than snarkjs WASM. |
| Groth16 (agent, snarkjs) | < 3s | Smaller proof, faster verification, but requires circuit-specific Phase 2. |
| Groth16 (agent, rapidsnark) | < 0.6s | Production target. |

Verification: Groth16 on-chain ~220k gas. PLONK on-chain ~300k gas. Both well within block gas limits.

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

2. **Authorization at Merchant-A:** Alice's agent computes `scopeId_A = Poseidon(domain:"merchant-a.example.com")` and generates a `ScopeBlindAuth` proof locally. The proof's public output `scopePseudonym_A = Poseidon2(scopeId_A, scopeBlindingSecret)` serves as Alice's pseudonymous identifier at Merchant-A. The `scopeBoundDelegationAnchor_A = Poseidon3(scopeId_A, permBitmask, cc)` is published for delegation chain seeding — but this anchor is specific to Merchant-A's scope.

3. **Authorization at Merchant-B:** Alice's agent computes `scopeId_B = Poseidon(domain:"merchant-b.example.com")` and generates a separate `ScopeBlindAuth` proof. The public output `scopePseudonym_B` is a completely different value. The `scopeBoundDelegationAnchor_B = Poseidon3(scopeId_B, permBitmask, cc)` is also a completely different value — even though the underlying `permBitmask` and `cc` are identical. Merchant-B cannot correlate either public output with Merchant-A's outputs.

4. **Desert Financial (AS) sees nothing:** The agent generated both proofs locally. No token request was sent to Desert Financial's AS. Desert Financial knows Alice's agent *exists* (it enrolled the credential) but has zero visibility into which merchants the agent contacted, when, or how often.

5. **Delegation with unlinkability preserved:** Alice's agent at Merchant-A delegates `READ_DATA`-only access to a sub-agent (e.g., a price-comparison bot). The sub-agent generates a `ScopeBlindDelegation` proof with `scopeId = scopeId_A`. The delegation chain is anchored to Merchant-A. If Alice's agent also delegates to a sub-agent at Merchant-B, that delegation chain uses `scopeId_B` — the two chains share no public correlator.

6. **Batch relayer (timing defense):** Both proofs are submitted through the CU*Answers batch relayer, which aggregates proofs from agents across all 150 member credit unions and submits them in 30-second epochs. Even a network observer cannot isolate Alice's proofs by timing.

7. **Sybil prevention:** Within a single scope (e.g., Merchant-A), Alice's agent always produces the same `scopePseudonym_A` (deterministic in `scopeId` and `scopeBlindingSecret`). Merchant-A can detect if Alice tries to register two accounts. Across scopes, pseudonyms are unlinkable.

### Healthcare delegation scenario (secondary)

**Stakeholders:**
- **Kaiser Permanente** — primary care provider, acts as credential issuer
- **Cedars-Sinai** — specialist provider (RS-B)
- **Patient "Bob"** — referred from Kaiser to Cedars-Sinai
- **Bob's health agent** — carries a delegated credential with `ACCESS_PII` narrowed to `READ_DATA`

Bob's agent receives a delegation from Kaiser's agent (which holds `ACCESS_PII | READ_DATA | WRITE_DATA`). The delegation circuit uses `scopeId = Poseidon(domain:"cedars-sinai.org")`. The `previousScopeBoundAnchor` is the scope-bound anchor published by Kaiser's agent *specifically for the Cedars-Sinai scope*. Kaiser's agent must generate a fresh `ScopeBlindAuth` proof at `scopeId_cedars` to seed this delegation chain — but Kaiser sees only the on-chain delegation event, not which RS the scope ID refers to (the Poseidon hash of the domain is opaque to Kaiser unless Kaiser can brute-force the domain string, which is mitigatable by salting the domain hash with a shared RS-agent secret).

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

Bolyra provides a formal game definition (§3) that explicitly covers both standalone auth and delegation, a named assumption (POS-PRF for both Poseidon2 and Poseidon3), and a reduction sketch bounding adversary advantage to the sum of PRF distinguishing advantages — which is negligible under standard assumptions on Poseidon over BN254.

### Structural impossibility 4: Timing correlation is unmitigated

Every OAuth token request creates an AS-observable event with a timestamp. No RFC specifies batching, padding, or oblivious issuance. An adversarial AS with millisecond-resolution logs can correlate token requests by timing alone, even if all other identifiers were hidden.

Bolyra's batch relayer submits proofs in fixed-epoch batches of `m` proofs, reducing timing correlation advantage to `1/m` per epoch. This is a protocol-level mitigation, not an application-layer afterthought.

### Structural impossibility 5: Delegation chain topology is AS-visible — and scope-correlated

RFC 8693 Token Exchange requires an AS roundtrip per delegation hop. The AS sees the full chain: who delegated to whom, with what scope, at what time. Worse, the delegation artifacts (token exchange responses) contain the same `sub` or client credential across RSes, making cross-RS delegation correlation trivial.

In Bolyra, delegation chains are scope-bound: `scopeBoundDelegationAnchor = Poseidon3(scopeId, permBitmask, credCommitment)`. A delegation chain at RS-A produces entirely different public anchors than a chain at RS-B, even for the same delegator and delegatee. The AS sees only that delegation events occurred on-chain but cannot correlate chains across scopes without breaking POS-PRF. This is the key improvement over both the baseline and the prior construction — delegation no longer leaks a cross-scope correlator.
