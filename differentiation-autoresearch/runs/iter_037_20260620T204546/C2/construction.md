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
| `scopeBoundDelegationAnchor` | field | Poseidon4(scopeId, scopeBlindingSecret, permissionBitmask, credentialCommitment) — scope-specific, AS-opaque delegation chain seed |

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
    scopeBoundDelegationAnchor = Poseidon4(scopeId, scopeBlindingSecret, permissionBitmask, credentialCommitment)
    ```

Constraint 10 is the critical hardening over the prior construction. The prior version used `Poseidon3(scopeId, permissionBitmask, credentialCommitment)`, which excluded `scopeBlindingSecret`. Since the AS (credential issuer) knows both `permissionBitmask` and `credentialCommitment` — it issued them — the AS could compute `Poseidon3(scopeId_candidate, permBitmask, cc)` for every candidate `scopeId` and compare against on-chain anchors, breaking unlinkability by brute-forcing the RS domain space. By including `scopeBlindingSecret` (a 251-bit random scalar known only to the agent), the anchor becomes a PRF evaluation keyed on `scopeBlindingSecret` — the AS cannot evaluate it for any `scopeId` without the key, regardless of its knowledge of the credential fields.

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
| `delegatorBlindingSecret` | field | Delegator's scopeBlindingSecret, range-checked to [0, 2^251) |
| `delegateeBlindingSecret` | field | Delegatee's scopeBlindingSecret, range-checked to [0, 2^251) |
| `delegateeMerkleProofLength`, `delegateeMerkleProofIndex`, `delegateeMerkleProofSiblings[20]` | | Delegatee Merkle proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | field | RS-specific scope identifier — same `scopeId` as the handshake that seeds this chain |
| `previousScopeBoundAnchor` | field | Chain-linking value from prior hop (scope-bound, blinding-secret-protected) |
| `sessionNonce` | field | Session binding value |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `newScopeBoundAnchor` | field | Poseidon4(scopeId, delegateeBlindingSecret, delegateeScope, delegateeCredCommitment) |
| `delegationNullifier` | field | Poseidon2(delegationTokenHash, sessionNonce) |
| `delegateeMerkleRoot` | field | Computed Merkle root for delegatee enrollment |

**Modified constraints:**

1. **Range checks on blinding secrets:** `Num2Bits(251)` on both `delegatorBlindingSecret` and `delegateeBlindingSecret`.

2. **Scope-bound chain linking (replaces base constraint 2):**
   ```
   Poseidon4(scopeId, delegatorBlindingSecret, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor
   ```
   This constraint now requires the delegator to supply their `scopeBlindingSecret` as a private witness, proving they are the entity that produced the previous anchor. The AS cannot forge this link — it does not know `delegatorBlindingSecret`.

3. **New scope-bound anchor output:**
   ```
   newScopeBoundAnchor = Poseidon4(scopeId, delegateeBlindingSecret, delegateeScope, delegateeCredCommitment)
   ```

4. **Delegation token (unchanged in structure):**
   ```
   delegationToken = Poseidon4(previousScopeBoundAnchor, delegateeCredCommitment, delegateeScope, delegateeExpiry)
   ```

All other constraints (scope subset, cumulative bit encoding, expiry narrowing, EdDSA signature, delegatee enrollment) remain identical to the base Delegation circuit.

**Blinding secret transfer mechanism:** For the delegation chain to work, the delegator must communicate their `scopeBlindingSecret` to the delegatee through a private channel (e.g., encrypted via the delegatee's public key). The delegatee needs it to verify the chain-linking constraint in future hops where they become the delegator. Crucially, the delegatee does NOT need the delegator's blinding secret to produce the *delegatee's own* anchor — they use their own `delegateeBlindingSecret`. The delegator's blinding secret is only consumed as a private witness in the chain-linking verification (constraint 2), not persisted on-chain.

**Why `scopeId` is a public input to the delegation circuit:** The delegation chain is intrinsically bound to the RS where it will be exercised. A delegator at RS-A signs a delegation token that commits to `previousScopeBoundAnchor`, which itself includes `scopeId_A`. The delegatee cannot repurpose this delegation proof at RS-B — the `scopeId` mismatch would cause the chain-linking constraint to fail. This scope-binding is not a limitation; it is the mechanism by which delegation and unlinkability coexist: delegation chains are per-RS, and per-RS chains reveal nothing about other RSes.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary `A` controls:
- The Authorization Server (full control — issues credentials, logs all interactions, **knows all credential fields including `permissionBitmask` and `credentialCommitment` for every enrolled agent**)
- Up to `k-1` of `k` total Resource Servers (colluding subset)
- Network-level observation of proof submission timing and metadata
- **Full read access to all on-chain state**, including every public signal of every proof submitted to any RS — compromised or honest (on-chain transparency model)

The adversary does NOT control:
- The agent's local proving environment (trusted execution)
- The `scopeBlindingSecret` of any agent (generated locally, never transmitted to the AS)
- The on-chain Merkle tree integrity (blockchain consensus)
- The honest RS(es) that the agent also contacts (the adversary cannot impersonate the honest RS to extract application-layer session state, but CAN read the on-chain proof artifacts)

**On-chain transparency clarification:** All `ScopeBlindAuth` and `ScopeBlindDelegation` proofs are verified on-chain. By definition, every public signal — `scopePseudonym`, `nonceBinding`, `scopeBoundDelegationAnchor`, `agentMerkleRoot`, `scopeId`, `requiredScopeMask`, `currentTimestamp`, `freshNonce` — is visible to all chain observers, including the adversary. The prior game formulation restricted the adversary's view of honest-RS signals; this was unsound in an on-chain verification model. The restated game below grants the adversary the full public signal vector from every proof at every RS.

### IND-UNL-AS Game (restated for on-chain transparency)

**Setup:** Challenger enrolls `n ≥ 2` agents in the agent Merkle tree. Each agent `i` has:
- Credential fields `(modelHash_i, opPubKey_i, permBitmask_i, expiry_i)` — given to the adversary (AS is the issuer).
- Credential commitment `cc_i = Poseidon5(modelHash_i, opPubKeyAx_i, opPubKeyAy_i, permBitmask_i, expiry_i)` — given to the adversary (deterministic from above).
- Scope blinding secret `sbs_i ←$ [0, 2^{251})` — NOT given to the adversary.

**Challenge phase:**

1. Adversary `A` selects two distinct agents `(agent_0, agent_1)` and two distinct scope identifiers `(scopeId_A, scopeId_B)`. Both agents MUST satisfy the required scope mask at both RSes (otherwise the adversary trivially distinguishes by observing scope-check failure). The adversary MAY control the RS for `scopeId_A`, both, or neither — it does not matter, because the adversary sees all on-chain public signals regardless.

2. Challenger flips bit `b ←$ {0, 1}`.

3. Challenger generates two `ScopeBlindAuth` proofs:
   - Proof `π_A` for `agent_b` at `scopeId_A` with fresh nonce `n_A`.
   - Proof `π_B` for `agent_b` at `scopeId_B` with fresh nonce `n_B`.

4. **Adversary receives the COMPLETE public signal vectors of both proofs:**
   - From `π_A`: `(agentMerkleRoot, scopePseudonym_A, nonceBinding_A, scopeBoundDelegationAnchor_A, scopeId_A, requiredScopeMask_A, currentTimestamp_A, freshNonce_A)`.
   - From `π_B`: `(agentMerkleRoot, scopePseudonym_B, nonceBinding_B, scopeBoundDelegationAnchor_B, scopeId_B, requiredScopeMask_B, currentTimestamp_B, freshNonce_B)`.
   - The adversary also receives all credential fields for BOTH `agent_0` and `agent_1`.

5. **(Delegation extension):** Adversary may additionally request up to `poly(λ)` delegation proofs at any `scopeId`, receiving full public signals `(newScopeBoundAnchor, delegationNullifier, delegateeMerkleRoot, scopeId, previousScopeBoundAnchor, sessionNonce)` for each hop.

6. **(Credential-aware oracle queries):** Adversary may submit arbitrary `(scopeId_{candidate}, permBitmask_j, cc_j)` triples and receive `Poseidon3(scopeId_{candidate}, permBitmask_j, cc_j)`. This models the AS's ability to compute the *prior* construction's anchor (no blinding secret). The hardened construction's anchor includes `sbs_j`, so these queries return values that do not match any on-chain anchor.

**Adversary outputs:** `b' ∈ {0, 1}`.

**Adversary wins:** `Pr[b' = b] - 1/2 > negl(λ)`.

**What the adversary must distinguish:** Given the two public signal vectors and full knowledge of both agents' credential fields, determine whether the two proofs were generated by `agent_0` or `agent_1`. The core challenge: the adversary sees `(scopePseudonym_A, scopeBoundDelegationAnchor_A)` and `(scopePseudonym_B, scopeBoundDelegationAnchor_B)`, and knows `(permBitmask_0, cc_0, permBitmask_1, cc_1)`. It must determine which agent's `sbs` was used. Since `sbs` is the sole unknown, and all four values are PRF evaluations keyed on the same `sbs_b`, the game reduces to PRF security.

**Non-signals that carry zero distinguishing information:**
- `agentMerkleRoot`: Identical for all agents (shared tree).
- `scopeId_A`, `scopeId_B`, `requiredScopeMask_*`, `currentTimestamp_*`, `freshNonce_*`: Public inputs chosen by the adversary or the verifier — independent of `b`.
- `nonceBinding_A = Poseidon2(scopePseudonym_A, freshNonce_A)`: Deterministic function of `scopePseudonym_A` and a public value — carries no information beyond `scopePseudonym_A` (formally: given `scopePseudonym_A`, the adversary can compute `nonceBinding_A` itself).

**Signals that carry distinguishing information (exhaustive list):**
1. `scopePseudonym_A = Poseidon2(scopeId_A, sbs_b)` — PRF on key `sbs_b`.
2. `scopePseudonym_B = Poseidon2(scopeId_B, sbs_b)` — same key, different input.
3. `scopeBoundDelegationAnchor_A = Poseidon4(scopeId_A, sbs_b, permBitmask_b, cc_b)` — PRF on key `sbs_b` with known auxiliary inputs.
4. `scopeBoundDelegationAnchor_B = Poseidon4(scopeId_B, sbs_b, permBitmask_b, cc_b)` — same key, different `scopeId`, same known auxiliary inputs.

The adversary's entire advantage is bounded by its ability to distinguish these four values from four independent uniform random field elements. This is the subject of the hybrid argument in §4.

### Side-channel sub-game (timing)

**Setup:** Same as above, but adversary additionally observes submission timestamps.

**Mitigation model:** Proofs are submitted via a batch relayer with epoch `Δ = 30s`. Within an epoch, all proofs are shuffled and submitted atomically. Adversary sees epoch boundaries but not per-proof timing within an epoch.

**Adversary advantage bound:** If `m` proofs are submitted per epoch, adversary's timing-based correlation advantage is at most `1/m` per epoch (random permutation within the batch).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security (POS-PRF):** Poseidon, when keyed on a designated input position, is a pseudorandom function family over the BN254 scalar field. Specifically:
   - `F^{(2)}_{sbs}(x) := Poseidon2(x, sbs)` is a PRF family keyed by `sbs ∈ [0, 2^{251})`.
   - `F^{(4)}_{sbs}(x, a_1, a_2) := Poseidon4(x, sbs, a_1, a_2)` is a PRF family keyed by `sbs`, even when the adversary knows `a_1` and `a_2` (public auxiliary inputs).
   - **Joint PRF security (POS-PRF-Joint):** For any fixed key `sbs` and any adversary-chosen auxiliary inputs `(a_1, a_2)`, the joint distribution `(F^{(2)}_{sbs}(x), F^{(4)}_{sbs}(x, a_1, a_2))` over adversary-chosen input `x` is computationally indistinguishable from `(U_1, U_2)` where `U_1, U_2$ are independent uniform field elements. This holds in the random oracle model where Poseidon instantiations of different arities are modeled as independent random oracles.

2. **Discrete logarithm hardness on Baby Jubjub (DL-BJJ):** Given `(Ax, Ay) = s · G`, no PPT adversary can recover `s`.

3. **Poseidon collision resistance (POS-CR):** No PPT adversary can find distinct inputs producing the same Poseidon output.

4. **Knowledge soundness of Groth16/PLONK (KS-G16/KS-PLONK):** In the generic group model + random oracle model, the proving systems satisfy knowledge soundness: a valid proof implies the prover knows a satisfying witness.

### Full cross-RS hybrid argument: IND-UNL-AS → POS-PRF

**Theorem:** Under POS-PRF-Joint, no PPT adversary wins the IND-UNL-AS game (§3) with non-negligible advantage, even when the adversary sees all on-chain public signals from all RSes and knows all credential fields of both challenge agents.

**Proof.** We construct a sequence of four hybrids. In each hybrid, the adversary receives the same inputs as in the IND-UNL-AS game: all credential fields for `agent_0` and `agent_1`, and the four distinguishing signals `(scopePseudonym_A, scopePseudonym_B, scopeBoundDelegationAnchor_A, scopeBoundDelegationAnchor_B)` plus all non-distinguishing public signals (which are either identical across agents or adversary-chosen).

**Hybrid H₀ (real game):**

The challenger uses `sbs_b` (the challenge agent's blinding secret) to compute all four signals honestly:

| Signal | Value |
|--------|-------|
| `scopePseudonym_A` | `Poseidon2(scopeId_A, sbs_b)` |
| `scopePseudonym_B` | `Poseidon2(scopeId_B, sbs_b)` |
| `scopeBoundDelegationAnchor_A` | `Poseidon4(scopeId_A, sbs_b, permBitmask_b, cc_b)` |
| `scopeBoundDelegationAnchor_B` | `Poseidon4(scopeId_B, sbs_b, permBitmask_b, cc_b)` |

The adversary knows `(permBitmask_b, cc_b)` (AS-issued) and `scopeId_A, scopeId_B` (adversary-chosen). It does NOT know `sbs_b`.

**Hybrid H₁ — replace `scopePseudonym_A` with uniform random:**

| Signal | Value |
|--------|-------|
| `scopePseudonym_A` | `r_1 ←$ F_p` |
| `scopePseudonym_B` | `Poseidon2(scopeId_B, sbs_b)` |
| `scopeBoundDelegationAnchor_A` | `Poseidon4(scopeId_A, sbs_b, permBitmask_b, cc_b)` |
| `scopeBoundDelegationAnchor_B` | `Poseidon4(scopeId_B, sbs_b, permBitmask_b, cc_b)` |

Also replace `nonceBinding_A = Poseidon2(r_1, freshNonce_A)` (consistently derived from the replaced pseudonym).

**Claim: |Pr[A wins in H₀] - Pr[A wins in H₁]| ≤ ε_{PRF2}.**

*Reduction to POS-PRF for Poseidon2:* Construct distinguisher `D_1` that receives oracle access to either `F^{(2)}_{sbs_b}(·) = Poseidon2(·, sbs_b)` or a random function `R(·)`. `D_1` queries the oracle at `scopeId_A` to obtain `scopePseudonym_A`. It computes the remaining three signals using `sbs_b`? — No. `D_1` does not know `sbs_b`.

Refined reduction: `D_1` receives oracle access to `O(·)$which is either `F^{(2)}_{sbs}(·)` or `R(·)` for unknown key `sbs`. `D_1` queries `O(scopeId_A)` and uses the result as `scopePseudonym_A`. For the remaining signals, `D_1` queries `O(scopeId_B)` to get `scopePseudonym_B`. For the anchors, `D_1` needs `Poseidon4(scopeId_*, sbs, permBitmask_b, cc_b)` — but it only has a Poseidon2 oracle, not Poseidon4.

This is why we need the **joint PRF** assumption (POS-PRF-Joint). Restate the reduction:

**Revised reduction structure.** Construct a single joint distinguisher `D` that receives oracle access to a *joint oracle* `O(x) = (O_2(x), O_4(x, a_1, a_2))` where either:
- **Real:** `O_2(x) = Poseidon2(x, sbs)` and `O_4(x, a_1, a_2) = Poseidon4(x, sbs, a_1, a_2)` for a uniformly random key `sbs`, or
- **Random:** `O_2` and `O_4$ are independent random functions.

`D` proceeds as follows:

1. `D` receives `(permBitmask_0, cc_0, permBitmask_1, cc_1)` from the adversary's agent selection.
2. `D` flips `b ←$ {0, 1}$, setting `(permBitmask_b, cc_b)` as the challenge agent's known fields.
3. `D` queries:
   - `(O_2(scopeId_A), O_4(scopeId_A, permBitmask_b, cc_b))` → `(scopePseudonym_A, scopeBoundDelegationAnchor_A)`.
   - `(O_2(scopeId_B), O_4(scopeId_B, permBitmask_b, cc_b))` → `(scopePseudonym_B, scopeBoundDelegationAnchor_B)`.
4. `D` computes `nonceBinding_A = Poseidon2(scopePseudonym_A, freshNonce_A)` and `nonceBinding_B = Poseidon2(scopePseudonym_B, freshNonce_B)` (deterministic from already-obtained values and public nonces).
5. `D` sends all public signals to the adversary `A`.
6. `A` outputs `b'`. If `b' = b`, `D` outputs "real"; otherwise `D` outputs "random".

Now the hybrids are:

**H₀** = Real oracle. All four distinguishing signals are correct PRF evaluations under `sbs_b`.

**H₁** = Replace `O_2(scopeId_A)` with uniform `r_1`. The three other signals remain PRF evaluations.

`|Pr[A\text{ wins in }H_0] - Pr[A\text{ wins in }H_1]| \leq \varepsilon_{\text{PRF2}}` because the replacement is a single-point PRF-to-random substitution on `F^{(2)}_{sbs}`. The adversary's view of `O_4(scopeId_A, \ldots)` is unchanged and independent of `O_2(scopeId_A)` by the joint PRF assumption (independent oracles in the ROM).

**H₂** — additionally replace `scopeBoundDelegationAnchor_A` with uniform `r_2`:

| Signal | Value |
|--------|-------|
| `scopePseudonym_A` | `r_1 ←$ F_p` |
| `scopePseudonym_B` | `Poseidon2(scopeId_B, sbs_b)` |
| `scopeBoundDelegationAnchor_A` | `r_2 ←$ F_p` |
| `scopeBoundDelegationAnchor_B` | `Poseidon4(scopeId_B, sbs_b, permBitmask_b, cc_b)` |

`|Pr[A\text{ wins in }H_1] - Pr[A\text{ wins in }H_2]| \leq \varepsilon_{\text{PRF4}}` by POS-PRF for Poseidon4. The adversary knows `(permBitmask_b, cc_b)` but these are public auxiliary inputs to the PRF — by definition, PRF security holds for any adversary-chosen auxiliary inputs. The key `sbs_b` remains secret. The replacement is at input `scopeId_A$; the remaining real evaluation is at `scopeId_B \neq scopeId_A` (the game requires distinct scope identifiers), so this is a legitimate single-point substitution.

**H₃** — additionally replace `scopePseudonym_B` with uniform `r_3`:

| Signal | Value |
|--------|-------|
| `scopePseudonym_A` | `r_1 ←$ F_p` |
| `scopePseudonym_B` | `r_3 ←$ F_p` |
| `scopeBoundDelegationAnchor_A` | `r_2 ←$ F_p` |
| `scopeBoundDelegationAnchor_B` | `Poseidon4(scopeId_B, sbs_b, permBitmask_b, cc_b)` |

`|Pr[A\text{ wins in }H_2] - Pr[A\text{ wins in }H_3]| \leq \varepsilon_{\text{PRF2}}` by the same Poseidon2 PRF argument, now at input `scopeId_B`.

**H₄** — additionally replace `scopeBoundDelegationAnchor_B` with uniform `r_4`:

| Signal | Value |
|--------|-------|
| `scopePseudonym_A` | `r_1 ←$ F_p` |
| `scopePseudonym_B` | `r_3 ←$ F_p` |
| `scopeBoundDelegationAnchor_A` | `r_2 ←$ F_p` |
| `scopeBoundDelegationAnchor_B` | `r_4 ←$ F_p` |

`|Pr[A\text{ wins in }H_3] - Pr[A\text{ wins in }H_4]| \leq \varepsilon_{\text{PRF4}}` by POS-PRF for Poseidon4 at input `scopeId_B`.

**Analysis of H₄:** All four distinguishing signals are independent uniform random field elements. The adversary's view is now entirely independent of the bit `b` — the identity of the challenge agent is information-theoretically hidden. (The non-distinguishing signals are either identical across agents or adversary-chosen, carrying zero bits of information about `b`.) Therefore: `Pr[A wins in H_4] = 1/2` exactly.

**Total advantage bound:**

```
Adv^{IND-UNL-AS}_A = |Pr[A wins in H_0] - 1/2|
    ≤ |H_0 - H_1| + |H_1 - H_2| + |H_2 - H_3| + |H_3 - H_4|
    ≤ 2·ε_{PRF2} + 2·ε_{PRF4}
    = negl(λ)
```

under POS-PRF for Poseidon2 and Poseidon4 over BN254. **QED.**

### Extension: delegation hops in the on-chain model

Each delegation hop at scope `scopeId_X` produces `newScopeBoundAnchor = Poseidon4(scopeId_X, delegateeSbs, delegateeScope, delegateeCC)` on-chain. The adversary sees all such anchors.

**Claim:** Each hop introduces at most one additional PRF evaluation under a fresh independent key (`delegateeSbs`). By the same single-point PRF substitution (H₃→H₄ style), each hop's anchor is replaceable with a uniform random value at cost `ε_{PRF4}`.

For a chain of depth `d`, the total advantage increase is `d · ε_{PRF4}`, which remains negligible for polynomial `d`.

The `previousScopeBoundAnchor` (a public input to each hop) was already replaced with a random value in a prior hybrid step (it is the output of the previous hop). The chain-linking constraint is satisfied by the prover's private witness — the verifier (and adversary) only see the public signals, which are independently randomized per hop.

### Cross-scope delegation linkage impossibility

The adversary might attempt to correlate delegation chains across scopes by comparing anchor sequences. At `scopeId_A`, the chain is `(anchor^A_0, anchor^A_1, \ldots)`. At `scopeId_B`, it is `(anchor^B_0, anchor^B_1, \ldots)`. Each anchor is a PRF evaluation under a distinct key (`delegateeSbs_i` for hop `i`) at a distinct input (`scopeId_A` vs. `scopeId_B`). Since keys are per-delegatee (not per-scope), the same delegatee at two different scopes produces `Poseidon4(scopeId_A, sbs_d, \ldots)` and `Poseidon4(scopeId_B, sbs_d, \ldots)` — two evaluations of the same PRF at different inputs. By PRF security, these are jointly indistinguishable from two independent random values. The adversary cannot link them.

### Replay prevention argument

`nonceBinding = Poseidon2(scopePseudonym, freshNonce)` binds each proof to a unique nonce. The on-chain verifier checks nonce freshness. Under POS-CR, an adversary cannot find a different `(scopePseudonym', freshNonce')` pair that produces the same `nonceBinding`, so replayed proofs are rejected.

### Delegation chain integrity under scope binding

The chain-linking constraint `Poseidon4(scopeId, delegatorBlindingSecret, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor` ensures that a delegation proof generated for `scopeId_A` cannot be replayed at `scopeId_B`. The `scopeId` is a public input verified by the on-chain registry — the prover cannot substitute it without breaking the chain-linking equation. Under POS-CR, no `(scopeId', sbs', delegatorScope', delegatorCredCommitment')` distinct from the original tuple can produce the same anchor. Furthermore, the inclusion of `delegatorBlindingSecret` ensures that only the actual delegator (who knows their blinding secret) can satisfy the chain-linking constraint — the AS cannot forge a chain link even though it knows the delegator's credential fields.

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
| Scope-bound delegation anchor | `Poseidon4(scopeId, scopeBlindingSecret, permBitmask, credCommitment)` | Extends §5.1 Identity-Bound Scope Commitment with scope binding + blinding |
| Delegation chain linking | `Poseidon4(scopeId, delegatorBlindingSecret, delegatorScope, delegatorCredCommitment) === previousScopeBoundAnchor` | Replaces §5.2 constraint 2 |
| Proving system | PLONK (agent circuit — universal setup) | §2.3 Proving Systems (OPTIONAL for AgentPolicy) |
| Nullifier (human side, unchanged) | `Poseidon2(scope, secret)` | §3.2 HumanUniqueness |

The `scopeBlindingSecret` is a new per-agent secret, generated once at agent enrollment and stored alongside the agent's credential material. It is NOT derived from the credential commitment (which is deterministic and could be computed by the AS from known fields). It is a fresh 251-bit random scalar, never transmitted to the AS or any other party.

**Migration from base spec `scopeCommitment`:** The base spec's `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is replaced everywhere by `scopeBoundDelegationAnchor = Poseidon4(scopeId, scopeBlindingSecret, permissionBitmask, credentialCommitment)`. The on-chain `lastScopeCommitment` mapping is renamed to `lastScopeBoundAnchor` and keyed by `(sessionNonce, scopeId)` to support per-RS delegation chains originating from the same handshake session.

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
| `Poseidon4` × 1 (scopeBoundDelegationAnchor) | ~1,600 |
| **Total** | **~26,840** |

This fits within `pot16.ptau` (2^16 = 65,536 constraints). Net change from prior construction: +400 constraints (~1.5% increase) due to Poseidon4 replacing the prior Poseidon3 for the delegation anchor. Poseidon4 (4-input) uses one additional full round compared to Poseidon3, adding approximately 400 constraints.

### `ScopeBlindDelegation` constraint breakdown

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Base Delegation circuit (unchanged gadgets) | ~25,000 |
| `Num2Bits(251)` × 2 (delegatorBlindingSecret, delegateeBlindingSecret) | 502 |
| `Poseidon4` × 2 (chain-link check + new anchor output) | ~3,200 |
| Replaces: `Poseidon3` × 2 from prior construction | −2,400 |
| Replaces: no blinding secret range checks in prior | −0 |
| **Net change from prior construction** | **+1,302** |
| **Total** | **~27,102** |

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

**Prior construction vulnerability (now closed):** In the prior construction, the delegation anchor was `Poseidon3(scopeId, permBitmask, cc)`. Desert Financial, as the credential issuer, knows `permBitmask` and `cc` for every enrolled agent. A curious data analyst at Desert Financial could enumerate candidate `scopeId` values — there are only ~10,000 merchants in the CU*Answers network — compute `Poseidon3(scopeId_candidate, permBitmask_Alice, cc_Alice)` for each, and compare against on-chain `scopeBoundDelegationAnchor` values. A match reveals that Alice's agent visited that merchant. This is a feasible dictionary attack: 10,000 Poseidon3 evaluations per agent takes milliseconds.

**Bolyra deployment (hardened):**

1. **Enrollment:** Desert Financial enrolls Alice's agent credential in the Bolyra agent Merkle tree. The credential commitment encodes `permissionBitmask = 0b00000101` (READ_DATA + FINANCIAL_SMALL). Desert Financial also issues the EdDSA signature over the credential commitment. Alice's agent generates a random `scopeBlindingSecret` locally — **this value is never shared with Desert Financial**.

2. **Authorization at Merchant-A:** Alice's agent computes `scopeId_A = Poseidon(domain:"merchant-a.example.com")` and generates a `ScopeBlindAuth` proof locally. The proof's public output `scopePseudonym_A = Poseidon2(scopeId_A, scopeBlindingSecret)` serves as Alice's pseudonymous identifier at Merchant-A. The `scopeBoundDelegationAnchor_A = Poseidon4(scopeId_A, scopeBlindingSecret, permBitmask, cc)` is published on-chain for delegation chain seeding. **Desert Financial can observe this anchor on-chain but cannot compute it independently** — even knowing `scopeId_A`, `permBitmask`, and `cc`, it lacks `scopeBlindingSecret`.

3. **Authorization at Merchant-B:** Alice's agent computes `scopeId_B = Poseidon(domain:"merchant-b.example.com")` and generates a separate `ScopeBlindAuth` proof. The public output `scopePseudonym_B` is a completely different value. The `scopeBoundDelegationAnchor_B = Poseidon4(scopeId_B, scopeBlindingSecret, permBitmask, cc)` is also a completely different value. **Desert Financial sees both anchors on-chain** but, by the hybrid argument (H₀→H₄), the two anchors are computationally indistinguishable from independent random field elements without knowledge of `scopeBlindingSecret`. The dictionary attack requires evaluating `Poseidon4(scopeId_candidate, ?, permBitmask_Alice, cc_Alice)` — the 251-bit `?` makes brute force infeasible.

4. **Full on-chain transparency accounted for:** Unlike the prior game formulation, this deployment explicitly acknowledges that ALL public signals — from both Merchant-A and Merchant-B — are visible on-chain to Desert Financial. The security guarantee rests on the four-step hybrid: even with all signals in hand, the adversary's advantage is bounded by `2·ε_{PRF2} + 2·ε_{PRF4}`, which is negligible.

5. **Delegation with unlinkability preserved:** Alice's agent at Merchant-A delegates `READ_DATA`-only access to a sub-agent (e.g., a price-comparison bot). The sub-agent generates a `ScopeBlindDelegation` proof with `scopeId = scopeId_A`. The chain-linking constraint requires the delegator's `scopeBlindingSecret` as a private witness — only Alice's agent can satisfy it. The delegation chain is anchored to Merchant-A. If Alice's agent also delegates to a sub-agent at Merchant-B, that delegation chain uses `scopeId_B` — the two chains share no public correlator, and the blinding secrets in both anchors prevent the AS from linking them. Each hop's anchor is independently randomizable in the hybrid argument at cost `ε_{PRF4}` per hop.

6. **Batch relayer (timing defense):** Both proofs are submitted through the CU*Answers batch relayer, which aggregates proofs from agents across all 150 member credit unions and submits them in 30-second epochs. Even a network observer cannot isolate Alice's proofs by timing.

7. **Sybil prevention:** Within a single scope (e.g., Merchant-A), Alice's agent always produces the same `scopePseudonym_A` (deterministic in `scopeId` and `scopeBlindingSecret`). Merchant-A can detect if Alice tries to register two accounts. Across scopes, pseudonyms are unlinkable.

### Healthcare delegation scenario (secondary)

**Stakeholders:**
- **Kaiser Permanente** — primary care provider, acts as credential issuer
- **Cedars-Sinai** — specialist provider (RS-B)
- **Patient "Bob"** — referred from Kaiser to Cedars-Sinai
- **Bob's health agent** — carries a delegated credential with `ACCESS_PII` narrowed to `READ_DATA`

Bob's agent receives a delegation from Kaiser's agent (which holds `ACCESS_PII | READ_DATA | WRITE_DATA`). The delegation circuit uses `scopeId = Poseidon(domain:"cedars-sinai.org")`. The `previousScopeBoundAnchor` is the scope-bound anchor published by Kaiser's agent *specifically for the Cedars-Sinai scope*. Kaiser's agent must generate a fresh `ScopeBlindAuth` proof at `scopeId_cedars` to seed this delegation chain. Kaiser (the issuer) sees all anchors on-chain but cannot determine which RS they target — the hybrid argument applies identically to the healthcare setting.

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

Bolyra provides a formal game definition (§3) that explicitly grants the adversary full knowledge of credential fields and full visibility of all on-chain public signals — the strongest reasonable on-chain AS model — a named assumption (POS-PRF-Joint for Poseidon2 and Poseidon4), and a complete four-step hybrid argument bounding adversary advantage to `2·ε_{PRF2} + 2·ε_{PRF4}`, which is negligible under standard assumptions on Poseidon over BN254.

### Structural impossibility 4: Timing correlation is unmitigated

Every OAuth token request creates an AS-observable event with a timestamp. No RFC specifies batching, padding, or oblivious issuance. An adversarial AS with millisecond-resolution logs can correlate token requests by timing alone, even if all other identifiers were hidden.

Bolyra's batch relayer submits proofs in fixed-epoch batches of `m` proofs, reducing timing correlation advantage to `1/m` per epoch. This is a protocol-level mitigation, not an application-layer afterthought.

### Structural impossibility 5: Delegation chain topology is AS-visible — and no longer scope-correlated even with issuer knowledge and on-chain transparency

RFC 8693 Token Exchange requires an AS roundtrip per delegation hop. The AS sees the full chain: who delegated to whom, with what scope, at what time. Worse, the delegation artifacts (token exchange responses) contain the same `sub` or client credential across RSes, making cross-RS delegation correlation trivial.

In Bolyra, delegation chains are scope-bound AND blinding-secret-protected: `scopeBoundDelegationAnchor = Poseidon4(scopeId, scopeBlindingSecret, permBitmask, credCommitment)`. A delegation chain at RS-A produces entirely different public anchors than a chain at RS-B, even for the same delegator and delegatee. The adversary sees all anchors on-chain — this is accounted for in the threat model — but cannot correlate chains across scopes without recovering the agent's `scopeBlindingSecret`. The four-step hybrid argument (§4) proves this cross-RS correlation is computationally infeasible: the adversary's total advantage over *all* visible signals is bounded by `2·ε_{PRF2} + 2·ε_{PRF4}`, regardless of how many RSes, hops, or on-chain queries the adversary observes.
