# Construction

## 1. Statement of claim

The same AI agent accessing different Resource Server scopes produces cryptographically unlinkable authorization proofs, even when the Authorization Server (AS) is fully adversarial — controlling the Merkle tree, observing all on-chain verification events, and colluding with any subset of RSes. Formally: no PPT adversary controlling the AS wins the IND-UNL-AS game (defined below) with non-negligible advantage.

The current Bolyra `AgentPolicy` circuit computes `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`, which is session-specific but **not scope-specific**. An adversarial AS observing two on-chain verifications for the same agent across different scopes sees the same `credentialCommitment` embedded in the scope commitment `Poseidon2(permissionBitmask, credentialCommitment)`. If the permission bitmask is reused across scopes (common), the `scopeCommitment` is identical — a direct cross-scope linkage vector.

This construction replaces the agent nullifier and scope commitment with scope-separated, blinded variants that are provably unlinkable across scopes under the Poseidon pseudorandomness assumption.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopeSeparatedAgentPolicy`

Replaces the existing `AgentPolicy` circuit. All Bolyra primitives are preserved (Poseidon, BabyJubjub EdDSA, BinaryMerkleRoot, cumulative bit encoding).

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key (Baby Jubjub) |
| `permissionBitmask` | 64-bit | Permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature components |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |
| `scopeBlinder` | F_p | Fresh random blinding factor per proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | Identifies the RS / resource scope being accessed |
| `requiredScopeMask` | 64-bit | Policy requiring specific permission bits |
| `currentTimestamp` | 64-bit | Current time |
| `sessionNonce` | F_p | Session binding value |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root |
| `scopeNullifier` | F_p | Scope-specific nullifier (Sybil detection within scope) |
| `blindedScopeCommitment` | F_p | Blinded, scope-bound commitment (unlinkable across scopes) |
| `sessionBinding` | F_p | Ties proof to session |

**Constraints (in order):**

1. **Range checks**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.

2. **Credential commitment** (unchanged):
   ```
   credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
   ```

3. **EdDSA signature**: `EdDSAPoseidonVerifier` over `credentialCommitment` using operator's public key.

4. **Merkle membership**: `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf → `agentMerkleRoot`.

5. **Scope satisfaction**: For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.

6. **Cumulative bit encoding** (unchanged):
   - `bitmaskBits[4] * (1 - bitmaskBits[3]) === 0`
   - `bitmaskBits[4] * (1 - bitmaskBits[2]) === 0`
   - `bitmaskBits[3] * (1 - bitmaskBits[2]) === 0`

7. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.

8. **Scope-specific nullifier** (NEW — replaces session-based nullifier):
   ```
   scopeNullifier = Poseidon2(credentialCommitment, scopeId)
   ```
   Deterministic per (agent, scope). Enables Sybil detection within a scope while being unlinkable across scopes.

9. **Blinded scope commitment** (NEW — replaces unblinded scope commitment):
   ```
   blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)
   ```
   The random `scopeBlinder` (private) ensures that two proofs for the same agent with the same permissions at different scopes produce distinct, unlinkable commitments. Even if `permissionBitmask` and `credentialCommitment` are identical, different `scopeBlinder` values yield computationally independent outputs.

10. **Session binding** (NEW — decoupled from nullifier):
    ```
    sessionBinding = Poseidon2(scopeNullifier, sessionNonce)
    ```
    Binds the proof to a specific session without leaking the nullifier's relationship to other sessions at different scopes.

### Modified on-chain verification

The registry verifies `ScopeSeparatedAgentPolicy` proofs with the public signal layout:

| Index | Signal |
|-------|--------|
| 0 | `agentMerkleRoot` |
| 1 | `scopeNullifier` |
| 2 | `blindedScopeCommitment` |
| 3 | `sessionBinding` |
| 4 | `scopeId` |
| 5 | `requiredScopeMask` |
| 6 | `currentTimestamp` |
| 7 | `sessionNonce` |

The registry checks:
- `sessionNonce` freshness (as before)
- `sessionBinding == Poseidon2(scopeNullifier, sessionNonce)` — verified implicitly by the circuit's soundness
- `scopeNullifier` is not in the per-scope revocation mapping
- `agentMerkleRoot` is in the agent root history buffer
- Groth16 proof validity

The registry stores `blindedScopeCommitment` as the delegation chain seed (replacing the old `scopeCommitment`). Delegation circuits are updated correspondingly — the delegator proves knowledge of the `scopeBlinder` used to form the previous blinded commitment.

### Modified Delegation circuit linkage

For delegation chain compatibility, the `Delegation` circuit's chain-linking constraint changes from:

```
Poseidon2(delegatorScope, delegatorCredCommitment) == previousScopeCommitment
```

to:

```
Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder) == previousBlindedScopeCommitment
```

The delegator passes `delegatorScopeBlinder` as a private input to the Delegation circuit. The delegatee receives a new blinded commitment with a fresh blinder. This preserves one-way scope narrowing while maintaining unlinkability through the delegation chain.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- **The Authorization Server**: full access to the agent Merkle tree, enrollment records, and all metadata. A knows every `credentialCommitment` in the tree and the mapping from credential to enrolled agent identity.
- **On-chain observation**: A sees every verification transaction, including all public signals (`agentMerkleRoot`, `scopeNullifier`, `blindedScopeCommitment`, `sessionBinding`, `scopeId`, `requiredScopeMask`, `currentTimestamp`, `sessionNonce`).
- **RS collusion**: A can collude with any subset of RSes, receiving the proofs and public signals presented to those RSes.
- **Timing metadata**: A observes transaction timestamps, gas costs, and ordering.

The adversary does NOT control:
- The agent's local proving environment (cannot extract private inputs).
- The randomness source for `scopeBlinder` generation.
- The Groth16 trusted setup (simulation trapdoor).

### IND-UNL-AS game

**Setup**: Challenger C enrolls n agents into the Merkle tree. A receives the full tree and all credential commitments.

**Challenge phase**:
1. A selects two enrolled agents `(agent_0, agent_1)` with identical `permissionBitmask` and `expiryTimestamp` (strongest case for A — removes trivial distinguishers).
2. A selects two distinct scopes `(scope_A, scope_B)`.
3. C flips a random bit `b ∈ {0, 1}`.
4. C generates proof `π_A` for `agent_b` at `scope_A` with fresh `scopeBlinder_A` and `sessionNonce_A`.
5. C generates proof `π_B` for `agent_{1-b}` at `scope_B` with fresh `scopeBlinder_B` and `sessionNonce_B`.
6. A receives `(π_A, pubSignals_A, π_B, pubSignals_B)`.

**A wins** if A outputs `b' = b`.

**Advantage**: `Adv_A = |Pr[b' = b] - 1/2|`.

**Claim**: For all PPT adversaries A, `Adv_A ≤ Adv_Poseidon-PRF + Adv_Groth16-ZKSNARK`, both negligible under the Poseidon pseudorandomness assumption and the knowledge soundness / zero-knowledge property of Groth16.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon pseudorandomness (PRF)**: `Poseidon2(k, x)` is computationally indistinguishable from a random function when `k` is secret. This is the standard assumption under which Poseidon-based nullifiers provide unlinkability — instantiated over the BN254 scalar field with the reference parameterization (t=3, α=5, R_F=8, R_P=57).

2. **Poseidon collision resistance (CR)**: Finding `(x, x')` with `x ≠ x'` and `Poseidon(x) = Poseidon(x')` is computationally infeasible. Required for Merkle tree binding and commitment uniqueness.

3. **Groth16 zero-knowledge**: The proof `π` reveals nothing about the witness beyond what is implied by the public signals. Formally: there exists a simulator S that, given only the public signals and the simulation trapdoor, produces proofs computationally indistinguishable from real proofs.

4. **Discrete logarithm hardness on Baby Jubjub**: Given `(Ax, Ay) = s * G`, recovering `s` is infeasible. Required for EdDSA unforgeability and identity commitment binding.

### Reduction sketch

**Theorem**: If A wins IND-UNL-AS with non-negligible advantage, then either the Poseidon PRF assumption or the Groth16 ZK property is broken.

**Proof sketch**:

*Step 1 — Simulator replaces real proofs with simulated proofs.* By the Groth16 zero-knowledge property, we can replace both real proofs `(π_A, π_B)` with simulated proofs `(π̃_A, π̃_B)` that are computationally indistinguishable. A's advantage changes by at most `2 · Adv_Groth16-ZK`.

*Step 2 — In the simulated world, A's view consists only of the public signals.* The relevant signals per proof are:
- `agentMerkleRoot`: identical for both agents (same tree).
- `scopeNullifier`: `Poseidon2(credentialCommitment_b, scope_A)` and `Poseidon2(credentialCommitment_{1-b}, scope_B)`.
- `blindedScopeCommitment`: `Poseidon3(permissionBitmask, credentialCommitment_b, scopeBlinder_A)` and `Poseidon3(permissionBitmask, credentialCommitment_{1-b}, scopeBlinder_B)`.
- `sessionBinding`: `Poseidon2(scopeNullifier, sessionNonce)` — deterministic given the above.
- Public inputs: `scopeId`, `requiredScopeMask`, `currentTimestamp`, `sessionNonce` — known to A by construction.

*Step 3 — Reduce to Poseidon PRF.* A must distinguish between:
- **World 0**: `(Poseidon2(cc_0, s_A), Poseidon2(cc_1, s_B))` and `(Poseidon3(pm, cc_0, r_A), Poseidon3(pm, cc_1, r_B))`
- **World 1**: `(Poseidon2(cc_1, s_A), Poseidon2(cc_0, s_B))` and `(Poseidon3(pm, cc_1, r_A), Poseidon3(pm, cc_0, r_B))`

where `cc_0, cc_1` are known credential commitments, `s_A, s_B` are known scope IDs, but `r_A, r_B` are uniformly random and secret.

The blinded scope commitments are computationally indistinguishable from random by the Poseidon PRF assumption (keyed on the secret `scopeBlinder`). The scope nullifiers use known inputs (`cc_i` and `scope_j` are both known to A) — however, `credentialCommitment` is a Poseidon5 hash of private fields. While A knows the commitments from the tree, the nullifier `Poseidon2(cc_b, scope)` for a specific `(cc_b, scope)` pair is deterministic and A can compute it directly.

**Critical observation**: A knows both `cc_0` and `cc_1` (they are in the Merkle tree). A can compute `Poseidon2(cc_0, scope_A)` and `Poseidon2(cc_1, scope_A)` and compare against the observed `scopeNullifier` in `π_A`. This would break unlinkability.

**Resolution — Nullifier must use a secret key.** The construction requires modifying the scope nullifier to incorporate a private agent secret:

```
scopeNullifier = Poseidon3(agentSecret, credentialCommitment, scopeId)
```

where `agentSecret` is a private scalar known only to the agent (analogous to the human `secret` in `HumanUniqueness`). The `agentSecret` is committed to via the credential: the credential commitment already binds the operator's public key, and `agentSecret` can be the operator's EdDSA private key scalar. Concretely:

```
scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)
```

This mirrors the human nullifier construction `Poseidon2(scope, secret)` exactly. The operator's private key is never revealed; only the public key appears in the credential commitment. Now A, who knows `cc_0, cc_1` and `scope_A, scope_B`, cannot compute either nullifier without the operator's private key.

**Revised reduction**: Distinguishing World 0 from World 1 requires either:
1. Computing `Poseidon2(scope_A, sk_b)` without knowing `sk_b` → breaks Poseidon PRF (keyed on `sk_b`), or
2. Inverting the blinded scope commitment `Poseidon3(pm, cc_b, r)` with unknown random `r` → breaks Poseidon PRF (keyed on `r`).

Total advantage: `Adv_A ≤ 2 · Adv_Groth16-ZK + 2 · Adv_Poseidon-PRF`, which is negligible. ∎

### Side-channel treatment

**Timing**: Proof generation time depends on circuit size (constant) and witness computation (constant-time Poseidon). The construction mandates constant-time witness generation — no early-exit branches. Proving time variance is dominated by the FFT in Groth16, which is data-independent.

**Nonce freshness**: Each `sessionNonce` is used exactly once (enforced on-chain). An adversarial AS that issues nonces cannot force nonce reuse. Agents SHOULD verify nonce freshness against the on-chain used-nonce set before proving, or generate their own nonces when the protocol permits.

**Request batching**: To resist timing correlation at the network layer, agents SHOULD submit proofs for multiple scopes in a single batched transaction or use a relay/mixer. This is an operational recommendation, not a circuit-level property.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope-specific nullifier | `Poseidon2(scopeId, operatorPrivateKey)` | Mirrors `HumanUniqueness` nullifier: `Poseidon2(scope, secret)` |
| Blinded scope commitment | `Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)` | Extends `AgentPolicy` scope commitment with blinding |
| Session binding | `Poseidon2(scopeNullifier, sessionNonce)` | Mirrors `HumanUniqueness` nonce binding: `Poseidon2(nullifierHash, sessionNonce)` |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` | Unchanged from `AgentPolicy` |
| EdDSA signature | `EdDSAPoseidonVerifier` on Baby Jubjub | Unchanged |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Unchanged |
| Cumulative bits | Bits 2/3/4 implication constraints | Unchanged |
| Delegation chain link | `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder)` | Extended with blinding |
| Proving system | Groth16 (human), PLONK optional (agent) | Per spec; Groth16 REQUIRED, PLONK MAY |

**No new primitives introduced.** The construction uses only Poseidon (with arity 2 and 3), BabyJubjub EdDSA, and BinaryMerkleRoot — all existing Bolyra primitives. The `scopeBlinder` is a standard field element drawn uniformly from F_p.

## 6. Circuit cost estimate

### ScopeSeparatedAgentPolicy constraint count

| Gadget | Constraints | Notes |
|--------|-------------|-------|
| Num2Bits(64) × 3 | 192 | permissionBitmask, expiryTimestamp, currentTimestamp |
| Poseidon5 (credential commitment) | ~1,500 | 5-ary Poseidon, R_F=8, R_P=60 |
| EdDSAPoseidonVerifier | ~5,800 | BabyJubjub scalar mul + Poseidon |
| BinaryMerkleRoot(20) | ~3,200 | 20 levels × ~160 constraints (Poseidon2 + mux) |
| Scope satisfaction (64 bits) | 128 | 64 multiplication constraints |
| Cumulative bit encoding | 3 | 3 multiplication constraints |
| LessThan(64) for expiry | ~130 | Num2Bits + comparison |
| Poseidon2 (scope nullifier) | ~500 | `Poseidon2(scopeId, operatorPrivateKey)` |
| Poseidon3 (blinded scope commitment) | ~800 | `Poseidon3(perm, credComm, blinder)` |
| Poseidon2 (session binding) | ~500 | `Poseidon2(scopeNullifier, sessionNonce)` |
| **Total** | **~12,750** | vs ~11,450 for current AgentPolicy |

**Delta**: +1,300 constraints (~11% increase) from the additional Poseidon2 (nullifier restructuring) and Poseidon3 (blinded commitment).

### Proving time targets

| Proving system | Target | Feasibility |
|---|---|---|
| Groth16 (snarkjs, browser) | < 8s | Well within 15s human budget; agent circuits are smaller |
| Groth16 (rapidsnark, native) | < 1.5s | ~12.7K constraints at ~120K constraints/sec on M1 |
| PLONK (snarkjs) | < 5s | Within spec budget |

The 12,750-constraint circuit fits comfortably under `pot16.ptau` (2^16 = 65,536 constraint capacity).

### Modified Delegation circuit cost

The delegation circuit adds one Poseidon3 evaluation (replacing Poseidon2 for chain linking) and one additional private input (`delegatorScopeBlinder`). Net increase: ~300 constraints. Total delegation circuit: ~13,600 constraints (from ~13,300 baseline).

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent — merchant graph privacy

**Stakeholder**: Pacific Northwest Credit Union Association (5 member CUs, each operating as an AS for its members' AI agents).

**Setup**: A member of Cascade Federal CU authorizes their AI agent to perform transactions at multiple merchant RSes: a pharmacy (RS-Pharmacy), a grocery chain (RS-Grocery), and an auto dealer (RS-Auto). Cascade FCU operates the AS and enrollment infrastructure.

**Threat**: Cascade FCU, acting as a compromised or overly curious AS, attempts to reconstruct the member's merchant graph — which merchants the member's agent visits, in what order, and how frequently. This violates NCUA member privacy expectations and potentially triggers CFPB scrutiny under Reg V (credit reporting) if the merchant graph reveals financial behavior patterns.

**Protocol flow**:

1. **Enrollment**: Member's agent is enrolled in the Bolyra agent Merkle tree with `credentialCommitment = Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask=0b00000101, expiry)`. The `permissionBitmask` grants `READ_DATA` (bit 0) and `FINANCIAL_SMALL` (bit 2, implies bit 0 — cumulative). Cascade FCU stores the commitment in the tree.

2. **Agent accesses RS-Pharmacy** (`scopeId = Poseidon("pharmacy.rx-network.org")`):
   - Agent generates `scopeNullifier_pharmacy = Poseidon2(scopeId_pharmacy, operatorPrivateKey)`.
   - Agent samples fresh `scopeBlinder_pharmacy` and computes `blindedScopeCommitment_pharmacy = Poseidon3(0b00000101, credentialCommitment, scopeBlinder_pharmacy)`.
   - Agent generates Groth16 proof and submits to on-chain registry.
   - RS-Pharmacy verifies: proof valid, `scopeNullifier` not revoked, `agentMerkleRoot` in history buffer. RS-Pharmacy learns the agent is authorized for `FINANCIAL_SMALL` at this scope. RS-Pharmacy does NOT learn the agent's identity, credential commitment, or operator key.

3. **Agent accesses RS-Grocery** (`scopeId = Poseidon("grocery.freshmart.com")`):
   - Agent generates `scopeNullifier_grocery = Poseidon2(scopeId_grocery, operatorPrivateKey)`.
   - Fresh `scopeBlinder_grocery`, fresh `blindedScopeCommitment_grocery`.
   - New Groth16 proof submitted.

4. **Cascade FCU (adversarial AS) observes**:
   - Two on-chain verification transactions.
   - Public signals: `agentMerkleRoot` (same tree — shared across all agents), `scopeNullifier_pharmacy`, `scopeNullifier_grocery` (cryptographically unlinkable without `operatorPrivateKey`), `blindedScopeCommitment_pharmacy`, `blindedScopeCommitment_grocery` (unlinkable due to fresh blinders), `sessionBinding` values (unlinkable).
   - `scopeId` values: Cascade FCU sees `scopeId_pharmacy` and `scopeId_grocery` on-chain but **cannot associate either with the member's agent**. The tree contains N agents; the proof reveals membership but not which leaf.

5. **Cascade FCU's attack surface**:
   - Cannot compute `Poseidon2(scopeId, sk)` without `sk` → cannot match nullifiers to agents.
   - Cannot invert `Poseidon3(pm, cc, blinder)` → cannot match blinded commitments.
   - Sees the same `agentMerkleRoot` for all proofs → no agent-specific root.
   - Timing: if proofs are submitted via a relay or batched, even temporal correlation fails.

**Outcome**: The member's merchant graph is cryptographically hidden from their own credit union. Cascade FCU can verify that *some* enrolled agent accessed the pharmacy and grocery scopes, but cannot determine that it was the same agent, let alone which member it belongs to.

### Healthcare variant

**Stakeholder**: Intermountain Health (regional health system, 33 hospitals).

A patient's AI agent is delegated `READ_DATA` access to request records from a primary care provider (RS-PCP) and a specialist (RS-Specialist). The health system's identity provider (AS) must not learn the referral network — i.e., that the same patient accessed both PCP and specialist, which would reveal a referral relationship.

The construction applies identically: scope-specific nullifiers prevent cross-provider linkage at the AS layer, and blinded scope commitments prevent correlation via permission structure. The delegation circuit's blinded chain linking ensures that even the delegation path (PCP → Specialist) is hidden from the AS.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails against an adversarial AS for structural reasons that no configuration or layering can fix:

**1. The AS is in the issuance hot path — Bolyra removes it entirely.**
In OAuth/OIDC, every scope-specific token requires an AS roundtrip. The AS sees `(agent_id, scope, RS, timestamp)` for every request. In Bolyra's construction, the agent generates proofs locally against a publicly available Merkle root. The AS is contacted only at enrollment time (once), never per-scope. There is no issuance event to correlate.

**2. Nullifier separation is a cryptographic object — PPID is a database lookup.**
OIDC PPIDs assign different `sub` values per RS, but the AS holds the mapping table. The AS can trivially reverse PPIDs to the canonical `sub`. Bolyra's `scopeNullifier = Poseidon2(scopeId, operatorPrivateKey)` is computationally irreversible without the private key. The AS — even with full tree access — cannot link nullifiers across scopes. This is a PRF guarantee, not an access-control policy.

**3. Scope blinding has no OAuth equivalent.**
The baseline has no mechanism to hide the scope being requested from the AS. RFC 8707 audience binding requires the AS to see the `resource` parameter. Bolyra's `blindedScopeCommitment` commits to the permission bitmask without revealing it to the on-chain observer or the AS. The blinding factor is private and fresh per proof.

**4. BBS+ unlinkability stops at the RS layer — Bolyra extends to the AS layer.**
BBS+ derived proofs are unlinkable to each other *at the verifier*. But the issuer (AS) signs the original credential and sees all issuance metadata. Bolyra's zero-knowledge proofs are unlinkable to everyone — including the entity that enrolled the agent — because the proof reveals only Merkle root membership, not which leaf.

**5. Delegation chain privacy is absent in the baseline.**
RFC 8693 Token Exchange exposes the full delegation chain to the AS at every hop. Bolyra's blinded delegation chain linking (`Poseidon3` with per-hop blinders) hides the chain topology. The AS sees a sequence of blinded scope commitments but cannot reconstruct which agent delegated to which.

**6. The baseline has no formal security definition to even attempt matching.**
No OAuth/OIDC specification defines an IND-UNL-AS game or any formal unlinkability notion against an adversarial issuer. The Bolyra construction provides a concrete game, a named assumption (Poseidon PRF + Groth16 ZK), and a reduction. The baseline cannot match what it cannot define.

**Quantitative gap**: The baseline provides 0 bits of security against AS-level cross-scope correlation (the AS has perfect knowledge). Bolyra provides ~128 bits of security under the Poseidon PRF assumption (BN254 scalar field, ~254-bit keys, with standard security margin).
