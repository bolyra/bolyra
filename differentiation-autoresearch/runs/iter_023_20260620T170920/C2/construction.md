# Construction

## 1. Statement of claim

Same agent accessing different Resource Server instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively attempts to correlate per-agent traffic graphs. Formally: no PPT adversary controlling the AS and colluding with any strict subset of RSes can distinguish whether two authorization proofs originate from the same agent or two distinct agents, except with negligible advantage.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopedAgentAuth`

This circuit extends `AgentPolicy` by replacing the single nullifier with a **scope-domain-separated nullifier** and adding an **AS-blinded scope commitment**. The agent proves credential validity and scope satisfaction without revealing any cross-scope linkable identifier to the AS or any RS.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key (Baby Jubjub) |
| `permissionBitmask` | 64-bit | Agent permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration (Unix) |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credentialCommitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |
| `scopeBlindingSecret` | F_p | Per-agent persistent blinding secret (never revealed) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., Poseidon hash of RS domain) |
| `requiredScopeMask` | 64-bit | Minimum permission bits required by this RS |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root for enrollment verification |
| `scopedNullifier` | F_p | `Poseidon2(scopeId, scopeBlindingSecret)` — unlinkable across scopes |
| `sessionBinding` | F_p | `Poseidon2(scopedNullifier, sessionNonce)` — replay prevention |
| `blindedScopeCommitment` | F_p | `Poseidon3(permissionBitmask, credentialCommitment, scopeBlindingSecret)` — hides identity from AS |

**Constraints enforced:**

1. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.
2. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA verification:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credentialCommitment)`.
4. **Merkle membership:** `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf produces `agentMerkleRoot`.
5. **Scope satisfaction:** For each bit `i` in `[0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:** Standard Bolyra implication constraints on bits 2/3/4.
7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scoped nullifier:** `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)`.
9. **Session binding:** `sessionBinding = Poseidon2(scopedNullifier, sessionNonce)`.
10. **Blinded scope commitment:** `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlindingSecret)`.

### New circuit: `ScopedDelegation`

Extends the existing `Delegation` circuit to preserve unlinkability through delegation hops.

**Private inputs:** All existing `Delegation` private inputs plus:

| Signal | Type | Description |
|--------|------|-------------|
| `delegateeScopeBlindingSecret` | F_p | Delegatee's blinding secret |
| `delegatorScopeBlindingSecret` | F_p | Delegator's blinding secret (for chain linking) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `previousBlindedScopeCommitment` | F_p | Prior hop's blinded scope commitment |
| `scopeId` | F_p | Target RS scope |
| `sessionNonce` | F_p | Session binding |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `newBlindedScopeCommitment` | F_p | `Poseidon3(delegateeScope, delegateeCredCommitment, delegateeScopeBlindingSecret)` |
| `delegationNullifier` | F_p | `Poseidon2(delegationTokenHash, sessionNonce)` |
| `delegateeMerkleRoot` | F_p | Delegatee enrollment root |
| `delegateeScopedNullifier` | F_p | `Poseidon2(scopeId, delegateeScopeBlindingSecret)` |

**Additional constraints beyond standard Delegation:**

11. **Chain linking (blinded):** `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlindingSecret) === previousBlindedScopeCommitment`.
12. **Delegatee scoped nullifier:** `delegateeScopedNullifier = Poseidon2(scopeId, delegateeScopeBlindingSecret)`.

### Protocol flow (cross-scope scenario)

1. Agent holds a single credential enrolled in the agent Merkle tree and a persistent `scopeBlindingSecret` known only to the agent.
2. When accessing RS-A (scopeId = `Poseidon("merchant-payments.example.com")`), the agent generates a `ScopedAgentAuth` proof. The public output `scopedNullifier_A = Poseidon2(scopeId_A, scopeBlindingSecret)`.
3. When accessing RS-B (scopeId = `Poseidon("pharmacy-records.example.com")`), the agent generates a separate proof. The output `scopedNullifier_B = Poseidon2(scopeId_B, scopeBlindingSecret)`.
4. The AS (if it relays proofs) sees only `(agentMerkleRoot, scopedNullifier, sessionBinding, blindedScopeCommitment)` — none of these values are linkable across scopes.
5. Each RS verifies the proof on-chain or locally against the PLONK/Groth16 verifier, checking `agentMerkleRoot` against the root history buffer and `sessionBinding` against the nonce registry.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary **A** controls:
- The Authorization Server (full read/write access to all AS state, logs, timing metadata).
- Up to `k-1` of `k` total Resource Servers (colluding subset).
- Network-level observation of all authorization traffic (timing, packet sizes, metadata).

The adversary **cannot**:
- Corrupt the agent's local device (cannot extract `scopeBlindingSecret`).
- Break the Poseidon hash function or the discrete log problem on Baby Jubjub.
- Forge Groth16/PLONK proofs (knowledge soundness holds).

### IND-UNL-AS game

**Setup:** Challenger enrolls `n ≥ 2` agents in the Merkle tree. Each agent `i` has credential `cred_i` and blinding secret `blind_i`.

**Challenge phase:**
1. Adversary A selects two agents `(agent_0, agent_1)` and two scope identifiers `(scopeId_X, scopeId_Y)` where `scopeId_X ≠ scopeId_Y`.
2. Challenger flips a random bit `b ∈ {0, 1}`.
3. If `b = 0`: Challenger generates proof `π_X` using `agent_0` for `scopeId_X` and `π_Y` using `agent_0` for `scopeId_Y` (same agent, two scopes).
4. If `b = 1`: Challenger generates proof `π_X` using `agent_0` for `scopeId_X` and `π_Y` using `agent_1` for `scopeId_Y` (different agents, two scopes).
5. In both cases, proofs use fresh `sessionNonce` values and the same `agentMerkleRoot`.
6. Challenger gives `(π_X, π_Y)` and all public signals to A.

**Adaptive queries:** A may request proofs for any `(agent_i, scopeId_j)` pair except the two challenge pairs.

**Win condition:** A outputs `b'`. A wins if `b' = b`. Advantage = `|Pr[b' = b] - 1/2|`.

**Claim:** For any PPT adversary A, `Adv^{IND-UNL-AS}(A) ≤ negl(λ)` under the assumptions in §4.

### Side-channel extension

The game is augmented with a **timing oracle**: A observes the wall-clock timestamp of each proof submission. The protocol mitigates this via:
- **Batched submission:** Proofs for multiple scopes are submitted in a single transaction batch with randomized internal ordering.
- **Padded proving time:** The agent pads proving time to a fixed quantum (e.g., 5s for PLONK) using a constant-time delay, preventing the AS from fingerprinting agents by proving speed.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF assumption (POS-PRF):** Poseidon2, Poseidon3, Poseidon5 are pseudorandom functions when keyed by a uniformly random field element. Specifically, `Poseidon2(scopeId, ·)` keyed by `scopeBlindingSecret` is indistinguishable from a random function over F_p.

2. **Discrete Log hardness on Baby Jubjub (DL-BJJ):** Given `(Ax, Ay) = s · G` for random `s`, no PPT adversary can recover `s`.

3. **Knowledge soundness of Groth16 (KS-G16) and PLONK (KS-PLONK):** In the random oracle model (ROM) / algebraic group model (AGM), the extractor recovers a valid witness from any convincing prover.

4. **Poseidon collision resistance (POS-CR):** No PPT adversary can find `(x, y) ≠ (x', y')` such that `Poseidon2(x, y) = Poseidon2(x', y')`.

### Reduction sketch

**Theorem:** If there exists a PPT adversary A with `Adv^{IND-UNL-AS}(A) = ε`, then there exists a PPT adversary B that breaks POS-PRF with advantage at least `ε/2`.

**Proof sketch:**

1. B receives a PRF challenge oracle `O` that is either `Poseidon2(scopeId, blind*)` for unknown random `blind*` or a truly random function `R`.

2. B embeds the challenge into the IND-UNL-AS game:
   - B sets `agent_0.scopeBlindingSecret = blind*` (the unknown key).
   - B generates `agent_1` with an independent random blinding secret `blind_1`.

3. When A requests `scopedNullifier` for `agent_0` at any `scopeId`, B queries oracle `O(scopeId)`.

4. For the challenge:
   - `π_X`: B queries `O(scopeId_X)` to get `scopedNullifier_X`.
   - `π_Y` (if `b = 0`): B queries `O(scopeId_Y)` to get `scopedNullifier_Y`.
   - `π_Y` (if `b = 1`): B computes `Poseidon2(scopeId_Y, blind_1)` directly.

5. If `O` is the real PRF: the game is a faithful IND-UNL-AS instantiation; A's advantage is `ε`.
   If `O` is random: `scopedNullifier_X` and `scopedNullifier_Y` are independent random values regardless of `b`, so A's advantage is 0.

6. Therefore B distinguishes PRF from random with advantage `ε/2`.

**Corollary (blinded scope commitment):** `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlindingSecret)` hides `credentialCommitment` under POS-PRF (keyed by `scopeBlindingSecret` in the third position). Two blinded scope commitments from the same agent at different scopes are unlinkable by the same reduction.

**Corollary (session binding):** `sessionBinding = Poseidon2(scopedNullifier, sessionNonce)` binds each proof to a unique session. Under POS-CR, an adversary cannot find a second `(scopedNullifier', sessionNonce')` that produces the same `sessionBinding`, preventing replay.

**Corollary (delegation chain):** The `ScopedDelegation` circuit preserves unlinkability because the chain-linking constraint uses `Poseidon3(scope, credCommitment, blindingSecret)`, which is blinded per-entity. An adversarial AS observing `previousBlindedScopeCommitment` and `newBlindedScopeCommitment` across hops cannot link them to the same delegation chain across scopes without breaking POS-PRF.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Reference |
|---|---|---|
| `scopedNullifier` | `Poseidon2(scopeId, scopeBlindingSecret)` | Mirrors human nullifier pattern `Poseidon2(scope, secret)` from `HumanUniqueness` |
| `sessionBinding` | `Poseidon2(scopedNullifier, sessionNonce)` | Identical to human `nonceBinding` pattern |
| `credentialCommitment` | `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` | Unchanged from `AgentPolicy` spec §4.2 |
| `blindedScopeCommitment` | `Poseidon3(permBitmask, credCommitment, blindingSecret)` | Extension of `scopeCommitment = Poseidon2(permBitmask, credCommitment)` with blinding |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Standard Bolyra Lean IMT at depth 20 |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Unchanged from `AgentPolicy` |
| Permission enforcement | Bitwise scope satisfaction + cumulative bit implication | Unchanged from `AgentPolicy` constraints 5–6 |
| Proving system (`ScopedAgentAuth`) | PLONK with universal setup (primary) / Groth16 (optional) | Agent-class circuit — PLONK preferred per spec §2.3 |
| Proving system (`ScopedDelegation`) | PLONK with universal setup (primary) / Groth16 (optional) | Delegation-class circuit |
| Root history buffer | 30-entry circular buffer on-chain | Unchanged from spec §3.1 |

The `scopeBlindingSecret` is a new per-agent secret, generated once at agent credential creation time (32 bytes, uniform random over F_p). It is stored alongside the agent's EdDSA private key and never transmitted. It plays the same structural role as the human `secret` in `HumanUniqueness` — a persistent identity secret that produces scope-separated, unlinkable nullifiers.

## 6. Circuit cost estimate

### ScopedAgentAuth

| Gadget | Estimated constraints |
|--------|----------------------|
| Poseidon5 (credentialCommitment) | ~1,500 |
| EdDSAPoseidonVerifier | ~6,800 |
| BinaryMerkleRoot(20) — 20 × Poseidon2 | ~14,000 |
| Num2Bits(64) × 3 (range checks) | ~192 |
| Scope satisfaction (64 multiplications) | ~64 |
| Cumulative bit encoding (3 constraints) | ~3 |
| LessThan(64) (expiry) | ~128 |
| Poseidon2 (scopedNullifier) | ~700 |
| Poseidon2 (sessionBinding) | ~700 |
| Poseidon3 (blindedScopeCommitment) | ~1,050 |
| **Total** | **~25,137** |

Fits within 2^16 = 65,536 constraint budget (pot16.ptau). PLONK proving time target: **<3s** on commodity hardware (M1/M2 Mac). Groth16 fallback: **<2s** with rapidsnark.

### ScopedDelegation

| Gadget | Estimated constraints |
|--------|----------------------|
| Poseidon3 × 2 (chain link in + out) | ~2,100 |
| Poseidon4 (delegation token) | ~1,200 |
| Poseidon2 (delegationNullifier) | ~700 |
| Poseidon2 (delegateeScopedNullifier) | ~700 |
| EdDSAPoseidonVerifier | ~6,800 |
| BinaryMerkleRoot(20) | ~14,000 |
| Num2Bits(64) × 4 | ~256 |
| Scope subset (64 multiplications) | ~64 |
| Cumulative bit (3 constraints) | ~3 |
| LessEqThan(64) (expiry narrowing) | ~128 |
| **Total** | **~25,951** |

Within pot16.ptau budget. PLONK target: **<3.5s**. Groth16 with rapidsnark: **<2.5s**.

## 7. Concrete deployment scenario

**Stakeholder:** Pacific Federal Credit Union (PFCU), a mid-sized CU with 45,000 members, acting as the Authorization Server in its open-banking ecosystem.

**Scenario:** A member ("Alice") delegates her AI financial agent to:
1. Access **MerchantPay** (RS-A) for small-value payment initiation (`FINANCIAL_SMALL`, bit 2).
2. Access **HealthInsure** (RS-B) for insurance claim status reads (`READ_DATA`, bit 0).

**Without Bolyra (baseline):** PFCU, as the AS, issues two OAuth tokens — one for MerchantPay (scope: `payment:small`), one for HealthInsure (scope: `claims:read`). PFCU's AS logs reveal that Alice's agent contacted both a merchant payment processor and a health insurance portal within the same 10-minute window. Over time, PFCU reconstructs Alice's merchant-health correlation graph. This is a GLBA §502(a) privacy concern: the CU is aggregating member behavioral data beyond the scope of the financial relationship.

**With Bolyra `ScopedAgentAuth`:**
1. Alice's agent generates `scopedNullifier_A = Poseidon2(scopeId_MerchantPay, blindingSecret)` and `scopedNullifier_B = Poseidon2(scopeId_HealthInsure, blindingSecret)`.
2. Each proof is submitted to the on-chain Bolyra registry (or verified by a Bolyra-aware RS gateway). PFCU never sees a token issuance request — the agent proves authorization directly to each RS.
3. PFCU, even if it monitors the blockchain, sees two proofs with unrelated `scopedNullifier` values, unrelated `blindedScopeCommitment` values, and the same `agentMerkleRoot` (which is shared by all 45,000 members' agents). PFCU cannot determine whether these two proofs came from the same agent.
4. MerchantPay verifies `scopedNullifier_A` is not revoked and the proof is valid. HealthInsure independently verifies `scopedNullifier_B`. Neither RS can correlate with the other.
5. Within each scope, `scopedNullifier` is deterministic — MerchantPay can detect if the same agent re-authenticates (Sybil prevention per scope) without learning anything about the agent's HealthInsure activity.

**Healthcare delegation extension:** Alice's agent delegates to a specialist referral agent (via `ScopedDelegation`) with narrowed `READ_DATA`-only permissions. The delegation proof's `delegateeScopedNullifier` is scope-separated, so the specialist's insurer RS cannot link the delegated agent back to Alice's primary agent at the pharmacy RS.

## 8. Why the baseline cannot match

| Property | Baseline (PPID + RFC 8707 + DPoP + BBS+) | Bolyra `ScopedAgentAuth` |
|---|---|---|
| **AS-level unlinkability** | Impossible. AS issues every token and sees `(agent, RS, scope, timestamp)` for each request. PPID only hides `sub` from RSes, not from the AS. | Achieved. Agent proves authorization directly via ZKP. AS never issues a per-RS token. `scopedNullifier = Poseidon2(scopeId, blindingSecret)` is unlinkable across scopes under POS-PRF. |
| **Scope correlation resistance** | Absent. AS logs the `scope` parameter of every token request. Cross-scope traffic graph is trivially reconstructable. | Achieved. `scopeId` is a public input but `blindedScopeCommitment` hides the credential identity. Two proofs at different scopes share no linkable signal. |
| **Formal security definition** | None. No RFC or W3C spec defines an IND-UNL-AS game or equivalent. | Defined. IND-UNL-AS game in §3 with concrete reduction to POS-PRF in §4. |
| **Delegation chain privacy** | Absent. RFC 8693 Token Exchange exposes every hop to the AS. | Achieved. `ScopedDelegation` uses blinded scope commitments for chain linking. AS cannot correlate hops across scopes. |
| **Timing side-channel mitigation** | None. DPoP `jti` timestamps and token-request timing are visible to AS. | Addressed. Batched submission with padded proving time reduces timing correlation. Not formally modeled but operationally mitigated. |
| **Colluding AS+RS resistance** | Broken. AS holds the PPID mapping table. AS + any RS can fully de-anonymize. | Resistant. AS sees no per-RS identifiers. Colluding RS sees only its scope-specific nullifier. AS + RS learn nothing beyond what one RS alone learns — the scope-specific nullifier for that RS. |
| **Issuer anonymity** | Absent. BBS+ presentations expose the issuer's public key. | Not applicable. No issuer public key is revealed — the operator's EdDSA key is a private input to the circuit. |

The structural impossibility is architectural: OAuth/OIDC places the AS on the critical path of every authorization. The AS is the token factory. Every token request is an observable event that correlates `(agent identity, target RS, requested scope, timestamp)`. No combination of PPIDs, audience binding, DPoP, or BBS+ selective disclosure can remove the AS from this path — they all assume AS trustworthiness as an axiom.

Bolyra's `ScopedAgentAuth` eliminates the AS from the authorization hot path entirely. The agent proves its credential validity and scope satisfaction directly to the RS (or on-chain verifier) via a zero-knowledge proof. The only shared public signal across scopes — `agentMerkleRoot` — is common to all enrolled agents and carries zero bits of per-agent information. The scope-specific signals (`scopedNullifier`, `blindedScopeCommitment`, `sessionBinding`) are all derived from the agent's private `scopeBlindingSecret` via Poseidon PRF, making them computationally indistinguishable from random values to any party that does not hold the secret.
