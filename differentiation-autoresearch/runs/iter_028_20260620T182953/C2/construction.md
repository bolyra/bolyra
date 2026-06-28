# Construction

## 1. Statement of claim

Same agent accessing different Resource Server instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively attempts to correlate per-agent traffic graphs. Unlinkability holds across scopes, across time, and against collusion between AS and any subset of RSes. The construction provides a formal IND-UNL-AS game with a concrete reduction to Poseidon PRF security and Groth16/PLONK knowledge soundness.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Core idea: scope-derived ephemeral identity

The agent never presents its credential commitment or any stable identifier to the AS or any RS. Instead, for each RS scope, the agent derives a **scope-local ephemeral nullifier** that is deterministic (enabling double-spend detection within a scope) but unlinkable across scopes (under the Poseidon PRF assumption). The AS issues no tokens — the agent self-proves authorization via PLONK, and the RS verifies the proof directly against on-chain roots.

### 2.2 Circuit: `ScopedAgentAuth` (RS-facing, no stable fingerprint)

This circuit extends `AgentPolicy` with scope-isolation properties. It replaces the per-session agent nullifier `Poseidon2(credentialCommitment, sessionNonce)` with a **scope-bound nullifier** that is deterministic per (agent, scope) but unlinkable across scopes.

**Critical design decision:** `scopeCommitment` is NOT a public output of this circuit. The `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` is stable across scopes for the same agent — if two colluding RSes both received it, they could trivially link the agent's authorizations by comparing this value. Instead, `scopeCommitment` is computed and exposed only in the separate `DelegationEntry` circuit (§2.6) used exclusively for on-chain delegation chain initialization.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Hash of agent model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Agent's full permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature components |
| `merkleProofLength` | uint8 | Actual Merkle depth |
| `merkleProofIndex` | field | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Merkle siblings (padded) |
| `scopeBlindingSecret` | field | Per-agent persistent blinding secret (≠ operator key) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | field | RS-specific scope identifier (e.g., `Poseidon("CU-A:merchant-read")`) |
| `requiredScopeMask` | uint64 | Policy-required permission bits |
| `currentTimestamp` | uint64 | Verifier-supplied current time |
| `sessionNonce` | field | Per-request freshness nonce |
| `epochId` | uint64 | Timing-bucketed epoch (e.g., 5-minute windows) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | field | Computed Merkle root |
| `scopedNullifier` | field | `Poseidon2(scopeId, scopeBlindingSecret)` — deterministic per (agent, scope) |
| `epochBinding` | field | `Poseidon2(scopedNullifier, epochId)` — timing-bucketed freshness |

Note: exactly **three** public outputs. No `scopeCommitment`. The RS receives only scope-local values — the Merkle root (shared across all agents), the scoped nullifier (unique to this agent × this scope), and the epoch binding (unique to this agent × this scope × this epoch). None of these are stable across scopes.

**Constraints:**

1. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` — intermediate signal, never output
2. **EdDSA signature:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credentialCommitment)` — proves operator authorization
3. **Merkle membership:** `BinaryMerkleRoot(20, credentialCommitment, proof) == agentMerkleRoot`
4. **Scope satisfaction:** `∀i ∈ [0,64): requiredBits[i] * (1 - permBits[i]) === 0`
5. **Cumulative bit encoding:**
   - `permBits[4] * (1 - permBits[3]) === 0`
   - `permBits[4] * (1 - permBits[2]) === 0`
   - `permBits[3] * (1 - permBits[2]) === 0`
6. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`
7. **Scoped nullifier derivation:** `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)` — the critical unlinkability gadget
8. **Epoch binding:** `epochBinding = Poseidon2(scopedNullifier, epochId)` — binds to time bucket
9. **Blinding secret binding to credential:** `blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)` — intermediate constraint (not a public output) ensuring the blinding secret is bound to this specific credential. Prevents an agent from using another agent's blinding secret.

### 2.3 Circuit: `DelegationEntry` (on-chain only, produces scopeCommitment)

When an agent wants to initiate a delegation chain, it must first anchor the chain on-chain by proving its `scopeCommitment`. This is a separate circuit that is submitted **only to the on-chain registry** as part of the handshake transaction — never to an RS.

**Purpose:** Bridge between the RS-facing unlinkable authorization (`ScopedAgentAuth`) and the delegation chain (`ScopedDelegation`) by producing the `scopeCommitment` that the delegation circuit uses as `previousScopeCommitment`.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Same as in `ScopedAgentAuth` |
| `operatorPubkeyAx`, `operatorPubkeyAy` | field | Operator EdDSA public key |
| `permissionBitmask` | uint64 | Agent's full permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature |
| `merkleProofLength` | uint8 | Actual Merkle depth |
| `merkleProofIndex` | field | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Merkle siblings |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `sessionNonce` | field | Binds to the mutual handshake session |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | field | Computed Merkle root (must match the handshake) |
| `scopeCommitment` | field | `Poseidon2(permissionBitmask, credentialCommitment)` — chain seed |
| `entryNullifier` | field | `Poseidon2(credentialCommitment, sessionNonce)` — prevents double-entry |

**Constraints:**

1. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`
2. **EdDSA signature:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credentialCommitment)`
3. **Merkle membership:** `BinaryMerkleRoot(20, credentialCommitment, proof) == agentMerkleRoot`
4. **Scope commitment:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`
5. **Entry nullifier:** `entryNullifier = Poseidon2(credentialCommitment, sessionNonce)` — prevents the same agent from seeding multiple delegation chains per session
6. **Range checks:** `Num2Bits(64)` on `permissionBitmask` and `expiryTimestamp`

**Information flow isolation:** The on-chain registry stores `scopeCommitment` indexed by `sessionNonce` in the `lastScopeCommitment` mapping. This value is visible on-chain but is never sent to any RS. An RS verifying a `ScopedAgentAuth` proof never receives or needs `scopeCommitment`. The on-chain visibility is acceptable because the on-chain registry is a public smart contract — the `scopeCommitment` does not reveal which RSes the agent subsequently contacts (it reveals only that the agent is capable of delegating, not where it authorizes).

### 2.4 Blinding secret lifecycle

The `scopeBlindingSecret` is generated once per agent credential (e.g., `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`). It is stored alongside the agent's credential material. It never leaves the agent's local storage. It is never revealed as a public signal. The circuit proves knowledge of it without revealing it.

### 2.5 Epoch-based timing mitigation

The `epochId` public input quantizes time into fixed windows (recommended: 300 seconds). Within an epoch, the `epochBinding` output is deterministic per (agent, scope), enabling double-authorization detection. Across epochs, different `epochBinding` values are produced, but the underlying `scopedNullifier` remains stable per scope — the RS can detect repeat access within a scope (by checking the nullifier against its local store) but the AS never sees either value.

### 2.6 Verification flow (AS-free)

1. RS publishes its `scopeId` and `requiredScopeMask` on-chain or in a well-known endpoint.
2. Agent generates a PLONK proof of `ScopedAgentAuth` locally.
3. Agent sends `(proof, publicSignals)` directly to the RS. The public signals contain exactly three outputs (`agentMerkleRoot`, `scopedNullifier`, `epochBinding`) and five public inputs (`scopeId`, `requiredScopeMask`, `currentTimestamp`, `sessionNonce`, `epochId`). No `scopeCommitment` is transmitted.
4. RS verifies the PLONK proof against the on-chain `agentMerkleRoot` (via root history buffer lookup) and checks `scopedNullifier` against its local double-spend set.
5. **The AS is never contacted.** There is no token issuance step.

### 2.7 Delegation flow (two-circuit separation)

When delegation is needed:

1. **Chain seeding (on-chain):** The agent submits a `DelegationEntry` proof in the mutual handshake transaction. The registry stores `scopeCommitment` as the chain seed in `lastScopeCommitment[sessionNonce]`. This happens once, on-chain, and is never sent to any RS.

2. **Delegation hops:** Each subsequent `ScopedDelegation` hop reads `previousScopeCommitment` from on-chain state and produces a `newScopeCommitment` for the next hop. Chain linking uses `scopeCommitment` values exclusively within the on-chain delegation verification path.

3. **Delegatee RS-facing authorization:** The delegatee uses its own `ScopedAgentAuth` proof (with its own `scopeBlindingSecret`) to authorize at an RS. The RS never sees any `scopeCommitment` — it sees only the delegatee's scope-local nullifier.

**Separation invariant:** `scopeCommitment` flows only through the on-chain delegation path: `DelegationEntry → ScopedDelegation hop 1 → ... → hop n`. It never appears in the RS-facing `ScopedAgentAuth` proof. The on-chain path and the RS-facing path share only the `agentMerkleRoot` (which is public to all parties) and the credential commitment (which is private in both circuits).

### 2.8 `ScopedDelegation` circuit

For delegation chains, the existing `Delegation` circuit is extended so that the delegatee's `scopedNullifier` is derived from the delegatee's own `scopeBlindingSecret` and the target RS's `scopeId`. The chain-linking constraint uses `scopeCommitment` (which binds to `credentialCommitment`), not the scoped nullifier.

**Additional private input:** `delegateeScopeBlindingSecret`

**Additional public output:** `delegateeScopedNullifier = Poseidon2(targetScopeId, delegateeScopeBlindingSecret)`

**Additional constraint:** `Poseidon2(delegateeScopeBlindingSecret, delegateeCredCommitment)` must be internally consistent (same binding-secret-to-credential check as in `ScopedAgentAuth`).

## 3. Threat model (adversary capabilities, game definition)

### 3.1 Adversary capabilities

The adversary $\mathcal{A}$ controls:

- **The Authorization Server (AS):** Full control over token issuance logic, logging, and timing observation. The AS may be the same entity as the credential issuer (operator).
- **A coalition of up to $k-1$ out of $k$ Resource Servers:** Colluding RSes share all received proofs, nullifiers, and timing data.
- **On-chain observation:** $\mathcal{A}$ reads all on-chain state, including `scopeCommitment` values stored in the `lastScopeCommitment` mapping by `DelegationEntry` proofs.
- **Network observation:** $\mathcal{A}$ sees encrypted channel metadata (source IP, connection timing) but not proof contents in transit (TLS assumption).

The adversary does NOT control:

- The agent's local execution environment (the `scopeBlindingSecret` is not leaked).
- The on-chain Merkle tree integrity (smart contract correctness assumption).
- The Poseidon hash function (collision resistance and PRF assumptions hold).

### 3.2 IND-UNL-AS game

**Game: IND-UNL-AS$(1^\lambda, \mathcal{A})$**

1. **Setup:** Challenger generates agent credential $C$ with `scopeBlindingSecret` $s_b$. Enrolls $C$ in the agent Merkle tree. Generates $n \geq 2$ distinct scope identifiers $\{S_1, \ldots, S_n\}$.

2. **Query phase:** $\mathcal{A}$ adaptively requests proofs for scopes of its choice. For each query $(S_i, \text{nonce}_j, \text{epoch}_k)$, the challenger returns the full `ScopedAgentAuth` public output vector $(\text{agentMerkleRoot}, \text{scopedNullifier}_i, \text{epochBinding}_{i,k})$ — exactly three outputs, no `scopeCommitment`.

3. **Challenge:** $\mathcal{A}$ selects two *unused* scopes $S_a, S_b$ and a nonce. The challenger flips a coin $b \leftarrow \{0, 1\}$. If $b = 0$, the challenger generates a proof for $S_a$; if $b = 1$, for $S_b$. $\mathcal{A}$ receives the proof and all public signals.

4. **Guess:** $\mathcal{A}$ outputs $b'$.

5. **Advantage:** $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} = |Pr[b' = b] - 1/2|$

**Win condition:** $\mathcal{A}$ wins if it can determine which of two scopes the proof was generated for, given that it has never seen a proof for either scope before.

**Claim:** For any PPT adversary $\mathcal{A}$:

$$\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\text{Poseidon}} + \text{Adv}^{\text{KS}}_{\text{PLONK}} + \text{negl}(\lambda)$$

### 3.3 Why removing `scopeCommitment` from `ScopedAgentAuth` is necessary for this game

In the prior construction, `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` was a public output of `ScopedAgentAuth`. This value depends only on the agent's credential and permission bitmask — it is **identical across all scopes** for the same agent. If two colluding RSes (RS-A at scope $S_a$ and RS-B at scope $S_b$) both receive proofs from the same agent, they observe the same `scopeCommitment` and trivially link the authorizations. This breaks the IND-UNL-AS game: the adversary wins with advantage 1 by comparing `scopeCommitment` values across the query phase and challenge.

By removing `scopeCommitment` from `ScopedAgentAuth` and confining it to the `DelegationEntry` circuit (which is submitted only on-chain, not to RSes), colluding RSes no longer receive any cross-scope stable identifier. The on-chain `scopeCommitment` is visible to all parties, but it is stored indexed by `sessionNonce` and is not associated with any particular RS's scope — the adversary learns that an agent initiated a delegation chain, but not which RSes the agent (or its delegatees) subsequently contacted.

### 3.4 Side-channel threat model

| Side channel | Mitigation |
|---|---|
| **Timing of proof submission** | Epoch bucketing: all proofs within a 300s window share the same `epochId`. Agent MAY add random delay within epoch. |
| **Nonce freshness leakage** | `sessionNonce` is per-request but is not visible to the AS (AS is never contacted). RS sees the nonce but learns only scope-local information. |
| **Proof generation timing** | PLONK proving is constant-time for fixed circuit size. Variance is hardware-dependent, not input-dependent. |
| **Merkle root staleness** | 30-entry root history buffer tolerates proof generation latency without requiring tree-update synchronization that could leak timing. |
| **On-chain scopeCommitment observation** | `scopeCommitment` is stored on-chain only during delegation chain initialization. It reveals that an agent can delegate, not where it authorizes. An adversary observing on-chain state learns the set of agents that have initiated delegation chains, but cannot link a `scopeCommitment` to any RS-facing `scopedNullifier` without breaking Poseidon PRF. |
| **IP correlation** | Out of scope for the cryptographic layer; mitigated by transport-layer anonymization (Tor, mixnet). Noted as an explicit non-goal of this construction. |

## 4. Security argument (named assumption + reduction sketch)

### 4.1 Named assumptions

1. **Poseidon PRF security** (A-PRF): Poseidon2, keyed on `scopeBlindingSecret`, is a secure pseudorandom function. That is, $\{(x, \text{Poseidon2}(x, k)) : x \leftarrow \mathcal{X}\}$ is computationally indistinguishable from $\{(x, r) : x \leftarrow \mathcal{X}, r \leftarrow F_p\}$ for any PPT distinguisher, where $k$ is the unknown key.

2. **Poseidon collision resistance** (A-CR): Finding $(x_1, x_2) \neq (x_1', x_2')$ such that $\text{Poseidon2}(x_1, x_2) = \text{Poseidon2}(x_1', x_2')$ requires $\Omega(2^{128})$ work.

3. **PLONK knowledge soundness** (A-KS): The PLONK proving system satisfies knowledge soundness in the algebraic group model + random oracle model. Any PPT prover producing a valid proof for `ScopedAgentAuth` knows a valid witness.

4. **Discrete logarithm hardness on Baby Jubjub** (A-DL): Given $(G, s \cdot G)$ on the Baby Jubjub curve, computing $s$ requires $\Omega(2^{126})$ work.

### 4.2 Reduction sketch: IND-UNL-AS → Poseidon PRF

**Theorem:** If there exists a PPT adversary $\mathcal{A}$ that wins IND-UNL-AS with non-negligible advantage, then there exists a PPT adversary $\mathcal{B}$ that breaks the PRF security of Poseidon2.

**Proof sketch:**

1. $\mathcal{B}$ receives oracle access to either $F_k(\cdot) = \text{Poseidon2}(\cdot, k)$ for unknown $k$, or a truly random function $R(\cdot)$.

2. $\mathcal{B}$ simulates the IND-UNL-AS game for $\mathcal{A}$:
   - Generates a real agent credential $C$ and enrolls it.
   - For query-phase scope $S_i$: queries its oracle on $S_i$ to get $\text{scopedNullifier}_i$. Computes `epochBinding` honestly. Simulates a valid PLONK proof using the PLONK simulator (exists by zero-knowledge property). **No `scopeCommitment` is included in the response** — the public output vector contains only `(agentMerkleRoot, scopedNullifier_i, epochBinding_{i,k})`.
   - For the challenge scopes $(S_a, S_b)$: queries the oracle on $S_b$ (the selected scope) to get the challenge nullifier.

3. If the oracle is $F_k$: the simulation is perfect — $\mathcal{A}$'s view is identical to the real IND-UNL-AS game.

4. If the oracle is $R$: the challenge nullifier is uniformly random and independent of the scope. $\mathcal{A}$'s advantage is exactly 0.

5. Therefore: $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\mathcal{B}} + \text{Adv}^{\text{KS}}_{\text{PLONK}}$.

The knowledge-soundness term accounts for the possibility that $\mathcal{A}$ submits a proof for a scope without knowing a valid witness (bypassing the nullifier derivation). PLONK knowledge soundness bounds this.

**Why the reduction is tight after removing `scopeCommitment`:** In the prior construction, the reduction had a gap: even if the PRF oracle produced random nullifiers, the `scopeCommitment` output was identical across all queries (it depends only on the credential, not the scope). The adversary could ignore the nullifier entirely and link proofs via `scopeCommitment`. With `scopeCommitment` removed from the public output vector, the only scope-dependent public output is `scopedNullifier` (and the derived `epochBinding`). The reduction is now tight: the adversary's entire view of scope-dependent information passes through the PRF oracle.

### 4.3 Collusion resistance argument

When $m$ RSes collude, they share $m$ tuples of `(agentMerkleRoot, scopedNullifier, epochBinding)`. Linking any two tuples to the same agent requires one of:

1. **Inverting the scoped nullifier:** Given `Poseidon2(scopeId_A, scopeBlindingSecret)` and `Poseidon2(scopeId_B, scopeBlindingSecret)`, recovering `scopeBlindingSecret` — equivalent to breaking A-PRF.

2. **Finding a cross-scope stable value in the public outputs:** There is none. `agentMerkleRoot` is shared by all agents in the tree. `scopedNullifier` varies per scope. `epochBinding` varies per scope and epoch. No public output of `ScopedAgentAuth` is stable across scopes for a single agent.

3. **Using on-chain `scopeCommitment`:** The `scopeCommitment` is stored on-chain only when the agent initiates a delegation chain via `DelegationEntry`. Even if the adversary reads this value, it cannot link it to any `scopedNullifier` seen at an RS without recovering `scopeBlindingSecret` or `credentialCommitment` — the `scopeCommitment` is `Poseidon2(permissionBitmask, credentialCommitment)` while the `scopedNullifier` is `Poseidon2(scopeId, scopeBlindingSecret)`. These share no common public field. Linking them requires either breaking A-CR (finding a collision that reveals the relationship) or breaking A-PRF (recovering the blinding secret to recompute nullifiers).

In the non-delegation flow (agent authorizes directly at RSes without delegating), no `DelegationEntry` proof is ever submitted and no `scopeCommitment` appears on-chain. Collusion resistance is unconditional on the RS-facing outputs.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scoped nullifier derivation | `Poseidon2(scopeId, scopeBlindingSecret)` | Nullifier definition (§2 Terminology) |
| Epoch binding | `Poseidon2(scopedNullifier, epochId)` | Analogous to nonceBinding in HumanUniqueness |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | AgentPolicy §4.2 |
| Scope commitment (delegation only) | `Poseidon2(permissionBitmask, credentialCommitment)` | Delegation §5.1 — confined to `DelegationEntry` circuit |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | AgentPolicy §4.2 constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §3.2 Lean Incremental Merkle Tree |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | AgentPolicy §4.2 constraint 6 |
| Proving system (ScopedAgentAuth) | PLONK with universal setup (`pot16.ptau`) | §3.3 — PLONK is OPTIONAL for AgentPolicy |
| Proving system (DelegationEntry) | Groth16 or PLONK | Same as Delegation circuit |
| On-chain root verification | 30-entry root history buffer | §3.1 Registry Contract |
| Scope satisfaction | Per-bit AND constraint: `reqBit[i] * (1 - permBit[i]) === 0` | AgentPolicy §4.2 constraint 5 |

**No new primitives are introduced.** The `scopeBlindingSecret` is a standard field element managed identically to the human `secret` scalar. The `DelegationEntry` circuit reuses all existing gadgets (Poseidon5, EdDSA, BinaryMerkleRoot). The separation is purely architectural — moving an existing public output from one circuit to a dedicated circuit.

## 6. Circuit cost estimate

### `ScopedAgentAuth` constraint breakdown

| Gadget | Constraints (estimated) |
|---|---|
| Poseidon5 (credential commitment) | ~1,500 |
| EdDSAPoseidonVerifier | ~7,500 |
| BinaryMerkleRoot(20) | ~6,000 |
| Num2Bits(64) × 3 (permBitmask, expiry, timestamp) | ~192 |
| Scope satisfaction (64 bit-checks) | ~64 |
| Cumulative bit encoding (3 constraints) | ~3 |
| LessThan(64) (expiry check) | ~65 |
| Poseidon2 (scoped nullifier) | ~600 |
| Poseidon2 (epoch binding) | ~600 |
| Poseidon2 (blinding-secret-to-credential binding) | ~600 |
| **Total** | **~17,124** |

This is ~600 constraints fewer than the prior construction (removed `scopeCommitment` Poseidon2 output computation). Fits within 2^16 constraints (65,536), compatible with `pot16.ptau`.

### `DelegationEntry` constraint breakdown

| Gadget | Constraints (estimated) |
|---|---|
| Poseidon5 (credential commitment) | ~1,500 |
| EdDSAPoseidonVerifier | ~7,500 |
| BinaryMerkleRoot(20) | ~6,000 |
| Num2Bits(64) × 2 (permBitmask, expiry) | ~128 |
| Poseidon2 (scope commitment) | ~600 |
| Poseidon2 (entry nullifier) | ~600 |
| **Total** | **~16,328** |

Fits within `pot16.ptau`. This circuit is used only once per delegation chain initiation, not per RS authorization.

### Proving time targets

| Circuit | Proving system | Target | Rationale |
|---|---|---|---|
| `ScopedAgentAuth` (PLONK) | PLONK | < 3s | Agent-side proving on commodity hardware. Well under 5s budget. |
| `ScopedAgentAuth` (Groth16) | Groth16 | < 2s | ~17.1K constraints with rapidsnark native prover. |
| `DelegationEntry` (PLONK) | PLONK | < 3s | ~16.3K constraints. One-time cost per delegation chain. |

### `ScopedDelegation` additional cost

The delegation extension adds ~1,200 constraints (one Poseidon2 for delegatee scoped nullifier + one Poseidon2 for blinding-secret binding). Total delegation circuit: existing ~18K + 1,200 ≈ 19,200 constraints. Still within `pot16.ptau`.

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent — CU-as-AS must not learn member merchant graph

**Stakeholders:**

- **Navy Federal Credit Union (NFCU)** — issues member credentials and operates an enrollment AS
- **Amazon** (RS-A) — online merchant accepting CU member agent payments
- **Costco** (RS-B) — wholesale merchant accepting CU member agent payments
- **Member agent** — autonomous shopping agent acting on behalf of NFCU member

**Current problem (baseline):** NFCU, acting as AS, issues OAuth tokens to the member's agent for each merchant. NFCU's token issuance logs reveal: "Member #4821's agent requested `financial_small` access to Amazon at 14:02, then Costco at 14:07." NFCU can reconstruct the complete merchant graph. PPIDs hide the member from merchants, but the AS sees everything.

**Bolyra deployment:**

1. **Enrollment:** NFCU enrolls the member's agent credential in the Bolyra agent Merkle tree. The credential commitment encodes `permissionBitmask = 0b00000100` (FINANCIAL_SMALL). The agent generates `scopeBlindingSecret` locally.

2. **Amazon authorization:** The agent computes `scopedNullifier_A = Poseidon2(scopeId_Amazon, scopeBlindingSecret)` and generates a PLONK proof of `ScopedAgentAuth`. Public outputs: `(agentMerkleRoot, scopedNullifier_A, epochBinding_A)`. **No `scopeCommitment` is sent.** It sends the proof directly to Amazon. Amazon verifies against the on-chain root. **NFCU is never contacted.**

3. **Costco authorization:** The agent computes `scopedNullifier_C = Poseidon2(scopeId_Costco, scopeBlindingSecret)`. Different scope → different nullifier. Public outputs: `(agentMerkleRoot, scopedNullifier_C, epochBinding_C)`. Sends proof to Costco. **NFCU is never contacted.**

4. **Collusion resistance:** Even if Amazon and Costco share their received public outputs, they see:
   - `agentMerkleRoot` — identical for all agents, not identifying
   - `scopedNullifier_A` vs `scopedNullifier_C` — unlinkable under Poseidon PRF
   - `epochBinding_A` vs `epochBinding_C` — unlinkable (derived from unlinkable nullifiers)
   - **No `scopeCommitment`** — the cross-scope stable fingerprint that would have trivially linked the two authorizations is absent from the RS-facing circuit.

5. **Double-spend prevention:** Within Amazon's scope, the `scopedNullifier_A` is deterministic. If the agent tries to authorize twice within the same scope, Amazon detects the duplicate nullifier. The `epochBinding` provides time-bucketed freshness without requiring AS-issued nonces.

6. **NFCU's view:** NFCU sees only the initial enrollment event. It has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden.

7. **Delegation (if needed):** If the member wants to delegate to a sub-agent for grocery shopping, the agent submits a `DelegationEntry` proof on-chain (once) to seed the delegation chain. The on-chain `scopeCommitment` reveals that a delegation chain was initiated but not which merchants the delegatee visits. The sub-agent uses its own `ScopedAgentAuth` with its own `scopeBlindingSecret` at each RS.

### Scenario: Healthcare delegation across providers

**Stakeholders:**

- **Kaiser Permanente** — primary care provider and credential issuer
- **Quest Diagnostics** (RS-A) — lab results access
- **Cedars-Sinai** (RS-B) — specialist referral
- **Patient agent** — delegated agent managing cross-provider care

**Flow:** Kaiser enrolls the patient's agent with `permissionBitmask = 0b10000001` (READ_DATA + ACCESS_PII). The agent delegates to a sub-agent for Quest with narrowed scope `READ_DATA` only, using `DelegationEntry` (on-chain, once) followed by `ScopedDelegation`. The sub-agent's `scopedNullifier` at Quest is derived from its own `scopeBlindingSecret` and Quest's `scopeId`. Kaiser cannot determine whether the patient visited Quest, Cedars-Sinai, or both. The referral network topology is hidden from the issuer. Neither Quest nor Cedars-Sinai receives a `scopeCommitment` — they see only scope-local nullifiers that are unlinkable to each other and to the on-chain delegation chain entry.

## 8. Why the baseline cannot match

| Property | Bolyra `ScopedAgentAuth` | Best baseline (PPID + RFC 8707 + DPoP + BBS+) |
|---|---|---|
| **Unlinkability against adversarial AS** | Guaranteed by IND-UNL-AS game. AS never sees per-scope authorizations. RS-facing outputs contain no cross-scope stable identifier. Reduced to Poseidon PRF security. | **Impossible.** AS issues every token and sees every scope request. PPID hides `sub` from RSes, not from AS. No RFC prevents AS from logging scope × agent × time. |
| **Collusion resistance (RS + RS)** | **No cross-scope stable value in public outputs.** `scopeCommitment` is confined to the on-chain `DelegationEntry` circuit and never sent to RSes. Colluding RSes share only scope-local nullifiers that are unlinkable under Poseidon PRF. | **Partially addressed by BBS+** multi-show unlinkability at the RS layer, but the AS's token-issuance log trivially links the same agent across RSes. |
| **Formal security definition** | IND-UNL-AS game with tight reduction — removing `scopeCommitment` from the RS-facing output vector closes the gap that made the prior reduction non-tight. | **None.** No OAuth/OIDC/BBS+ spec defines unlinkability against AS. BBS+ multi-show unlinkability is holder-to-verifier only. |
| **AS removal from hot path** | AS is never contacted after enrollment. Verification is RS-local against on-chain roots. | AS must be contacted for every token issuance. JWT introspection response is optional and still requires initial AS contact. |
| **Timing side-channel resistance** | Epoch bucketing quantizes time into 300s windows. `epochBinding` is deterministic within a window — timing within an epoch leaks nothing. | **None.** DPoP `jti` and timestamps leak per-request timing to AS. No RFC mandates batching or padding. |
| **Collusion resistance (AS + RS)** | Structurally impossible: AS has no per-scope data to share. RS holds only scope-local nullifiers unlinkable across scopes. No `scopeCommitment` bridges the two. | **Trivially broken.** AS shares its token-issuance log with colluding RS. Full traffic graph reconstructed. |
| **Delegation privacy** | Delegation chain links via `scopeCommitment` stored on-chain by `DelegationEntry` — never sent to RSes. Per-RS nullifiers derived from delegatee's own blinding secret. Issuer cannot see chain topology from RS-layer data. | **RFC 8693 delegation is AS-visible at every hop.** AS sees actor token, subject token, requested scope for each delegation step. |
| **Scope blinding** | Scope is a public input to the circuit but the agent's *association* with the scope is hidden behind the ZK proof. The AS never learns which scope the agent proved for. No stable identifier leaks the association to colluding RSes. | **Not expressible.** OAuth scope is a plaintext field in every token request to the AS. |

**The structural impossibility:** The OAuth/OIDC model places the AS on the critical path of every authorization. Every mitigation (PPID, DPoP, BBS+) operates *below* the AS — hiding information from RSes or transport observers, never from the token issuer. Bolyra's construction eliminates the AS from the authorization path entirely: after enrollment, the agent self-proves to each RS using a ZK proof against a public on-chain state root. The RS-facing proof contains exactly three public outputs — the Merkle root (shared by all agents), a scope-local nullifier (unique to this agent × this scope), and an epoch binding (unique to this agent × this scope × this epoch). No cross-scope stable identifier appears in the RS-facing circuit. The `scopeCommitment` needed for delegation chains is confined to a separate `DelegationEntry` circuit visible only on-chain, architecturally isolated from the RS authorization path. This is not an incremental improvement over the baseline — it is a category change in the trust model that no composition of OAuth RFCs can replicate without abandoning the AS-centric architecture that defines OAuth.
