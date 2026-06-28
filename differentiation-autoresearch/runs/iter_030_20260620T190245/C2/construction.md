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
| `scopeBlindingSecret` | field | Agent-local blinding secret (generated independently of operator material — see §2.4) |

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

The `scopeBlindingSecret` MUST be generated by the agent's local execution environment as an independent cryptographic secret, using a CSPRNG with at least 128 bits of entropy. It MUST NOT be derived from operator key material (private key, public key, or any value the operator can reconstruct).

**Rationale:** The IND-UNL-AS threat model (§3.2) explicitly allows the adversary to control the AS, and the AS may be the same entity as the credential operator. If `scopeBlindingSecret` were derived from `operatorPrivKey` — e.g., `Poseidon2(operatorPrivKey, "bolyra-scope-blind")` — then an adversarial operator could recompute the blinding secret, evaluate `Poseidon2(scopeId, scopeBlindingSecret)` for every scope, and reconstruct the full traffic graph. This breaks IND-UNL-AS with advantage 1. The blinding secret must be information-theoretically independent of all operator-held material.

**Generation:** `scopeBlindingSecret ← F_p` sampled uniformly at random (e.g., 32 bytes from `/dev/urandom`, reduced mod $p$).

**Storage:** The `scopeBlindingSecret` is stored alongside the agent's credential material in the agent's local secure storage. It is generated once per agent credential and reused across all scopes (scope isolation is achieved by the Poseidon PRF keyed on this secret, not by per-scope secrets). It never leaves the agent's local environment. It is never transmitted to the operator, the AS, or any RS. The circuit proves knowledge of it without revealing it.

**Rotation:** If the agent's local environment is compromised, the `scopeBlindingSecret` is assumed leaked. The agent MUST generate a new credential (new enrollment in the Merkle tree) with a fresh `scopeBlindingSecret`. There is no in-place rotation mechanism — the old credential's nullifiers become stale as the old Merkle root ages out of the 30-entry history buffer.

**Operator independence invariant:** The operator knows `(operatorPubkeyAx, operatorPubkeyAy, operatorPrivKey)` and the credential fields `(modelHash, permissionBitmask, expiryTimestamp)`. From these, the operator can recompute `credentialCommitment`. The operator CANNOT compute `scopeBlindingSecret` (independent random value) or `blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)` (requires the blinding secret as preimage). Therefore, the operator cannot evaluate `scopedNullifier = Poseidon2(scopeId, scopeBlindingSecret)` for any scope, and cannot link any RS-facing authorization to the agent's credential.

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

- **The Authorization Server (AS) and/or the credential operator:** Full control over token issuance logic, logging, timing observation, AND operator key material (`operatorPrivKey`, `operatorPubkeyAx`, `operatorPubkeyAy`). The AS may be the same entity as the operator — this is the primary threat scenario (e.g., a credit union that both enrolls agents and attempts to surveil their merchant graph). The adversary can recompute `credentialCommitment` from known credential fields.
- **A coalition of up to $k-1$ out of $k$ Resource Servers:** Colluding RSes share all received proofs, nullifiers, and timing data.
- **On-chain observation:** $\mathcal{A}$ reads all on-chain state, including `scopeCommitment` values stored in the `lastScopeCommitment` mapping by `DelegationEntry` proofs.
- **Network observation:** $\mathcal{A}$ sees encrypted channel metadata (source IP, connection timing) but not proof contents in transit (TLS assumption).

The adversary does NOT control:

- **The agent's local execution environment:** The `scopeBlindingSecret` is generated and stored locally by the agent. The operator never receives it. This is the critical trust boundary — the security of IND-UNL-AS rests on the agent's local environment being outside the adversary's control. If the adversary compromises the agent's local storage, all unlinkability guarantees are void (the adversary recovers `scopeBlindingSecret` and can recompute all nullifiers). This is explicitly documented as the trust assumption, not a limitation — it mirrors the standard assumption that a user's secret key is not leaked to the adversary.
- The on-chain Merkle tree integrity (smart contract correctness assumption).
- The Poseidon hash function (collision resistance and PRF assumptions hold).

### 3.2 IND-UNL-AS game

**Prior game definition (flawed) and correction:** The prior iteration defined IND-UNL-AS as a *scope-distinguishability* game: the adversary was challenged to determine which of two scopes a proof was generated for. This game is trivially won because `scopeId` is a public input to `ScopedAgentAuth` — the adversary reads it from the public signal vector and wins with advantage 1. The `scopeId` *must* be public: the RS needs to verify that the proof targets its specific scope. Making `scopeId` private would break the RS's ability to enforce scope-specific authorization policy.

The correct formalization is **agent-unlinkability**: given two proofs at two *known, different* RSes, can the adversary determine whether they originated from the same agent or from two different agents? This matches the actual claim — "same agent accessing different RS instances produces cryptographically unlinkable authorizations." The scopes are public; the agent's identity across scopes is what must be hidden.

**Game: IND-UNL-AS$(1^\lambda, \mathcal{A})$**

1. **Setup:** Challenger enrolls $N \geq 2$ agents in the Merkle tree. For each agent $j$, the challenger generates:
   - An operator keypair $(sk^j_{op}, pk^j_{op})$.
   - A credential $C_j$ with fields $(modelHash_j, pk^j_{op}, permissionBitmask_j, expiryTimestamp_j)$.
   - A blinding secret $s^j_b$ sampled uniformly from $F_p$, independently of $sk^j_{op}$.

   The challenger gives $\mathcal{A}$ **all operator private keys** $\{sk^1_{op}, \ldots, sk^N_{op}\}$ and all credential fields. This models the AS=operator threat: the adversary knows every credential commitment, every operator key, and every enrollment. The only values withheld are the blinding secrets $\{s^1_b, \ldots, s^N_b\}$.

2. **Query phase:** $\mathcal{A}$ adaptively requests proofs. Each query specifies an agent index $j$ and a scope $S_i$. The challenger returns the full `ScopedAgentAuth` public signal vector: `(agentMerkleRoot, scopedNullifier, epochBinding, scopeId, requiredScopeMask, currentTimestamp, sessionNonce, epochId)`. The adversary may query any agent at any scope, any number of times (with fresh session nonces). The adversary accumulates an arbitrary transcript of (agent, scope, proof-outputs) tuples.

   **Restriction:** The adversary may not query the same (agent, scope) pair that will appear in the challenge — i.e., for the challenge agents and challenge scopes defined in step 3, the adversary must not have previously queried agent $j_0$ at scope $S_a$ or agent $j_1$ at scope $S_b$. Queries at other scopes for the challenge agents, and queries at the challenge scopes for other agents, are permitted.

3. **Challenge:** $\mathcal{A}$ selects two distinct agents $j_0, j_1$ and two distinct scopes $S_a, S_b$ subject to the restriction above. The challenger flips a coin $b \leftarrow \{0, 1\}$:
   - If $b = 0$: the challenger generates proof $\pi_a$ for agent $j_0$ at scope $S_a$ and proof $\pi_b$ for agent $j_0$ at scope $S_b$ (same agent, two scopes).
   - If $b = 1$: the challenger generates proof $\pi_a$ for agent $j_0$ at scope $S_a$ and proof $\pi_b$ for agent $j_1$ at scope $S_b$ (different agents, two scopes).

   $\mathcal{A}$ receives both proof public signal vectors $(\vec{v}_a, \vec{v}_b)$.

4. **Guess:** $\mathcal{A}$ outputs $b'$.

5. **Advantage:** $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} = |Pr[b' = b] - 1/2|$

**Win condition:** $\mathcal{A}$ wins if it can distinguish whether two proofs at two different known scopes came from the same agent or from two different agents. The adversary holds all operator private keys and all credential fields — only the blinding secrets are unknown.

**Why this game is well-formed despite `scopeId` being public:** The adversary knows both $S_a$ and $S_b$ — the scopes are not hidden. The challenge is whether the adversary can determine the *agent assignment* behind the proofs. In both worlds ($b = 0$ and $b = 1$), the adversary sees one proof at $S_a$ and one proof at $S_b$. The `scopeId` values are identical in both worlds. The `agentMerkleRoot` is identical (shared by all agents). The distinguishing information, if any, must come from the `scopedNullifier` and `epochBinding` values — and these are derived from the unknown blinding secrets via the Poseidon PRF.

**Why the restriction on queries is necessary:** Without it, the adversary could query agent $j_0$ at scope $S_a$ during the query phase, observe the resulting `scopedNullifier`, then compare it against the challenge proof $\pi_a$. Since `scopedNullifier = Poseidon2(S_a, s^{j_0}_b)` is deterministic, a match would reveal that $\pi_a$ was generated by $j_0$, trivially distinguishing the two worlds. This restriction is standard in unlinkability games (analogous to the CPA restriction in IND-CPA) and does not weaken the security guarantee: it models the realistic scenario where the adversary has not previously observed the specific (agent, scope) pair it is trying to link.

**Claim:** For any PPT adversary $\mathcal{A}$:

$$\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq 2 \cdot \text{Adv}^{\text{PRF}}_{\text{Poseidon}} + \text{Adv}^{\text{KS}}_{\text{PLONK}} + \text{negl}(\lambda)$$

The factor of 2 arises from a standard hybrid argument over replacing the PRF in each of the two challenge proofs.

### 3.3 Why removing `scopeCommitment` from `ScopedAgentAuth` is necessary for this game

In the prior construction, `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` was a public output of `ScopedAgentAuth`. This value depends only on the agent's credential and permission bitmask — it is **identical across all scopes** for the same agent. If two colluding RSes (RS-A at scope $S_a$ and RS-B at scope $S_b$) both receive proofs from the same agent, they observe the same `scopeCommitment` and trivially determine $b = 0$ in the IND-UNL-AS game (same agent) by comparing `scopeCommitment` values. The adversary wins with advantage 1.

By removing `scopeCommitment` from `ScopedAgentAuth` and confining it to the `DelegationEntry` circuit (which is submitted only on-chain, not to RSes), colluding RSes no longer receive any cross-scope stable identifier. The on-chain `scopeCommitment` is visible to all parties, but it is stored indexed by `sessionNonce` and is not associated with any particular RS's scope — the adversary learns that an agent initiated a delegation chain, but not which RSes the agent (or its delegatees) subsequently contacted.

### 3.4 Why `scopeBlindingSecret` must be operator-independent for this game

The IND-UNL-AS game (§3.2 step 1) gives the adversary all operator private keys $\{sk^j_{op}\}$. If `scopeBlindingSecret` for agent $j$ were derived from $sk^j_{op}$ — e.g., `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")` — the adversary could:

1. Recompute `scopeBlindingSecret` for every agent from the known operator keys.
2. Evaluate `Poseidon2(S_a, s^{j_0}_b)` and `Poseidon2(S_a, s^{j_1}_b)`.
3. Compare against the challenge `scopedNullifier` in $\pi_a$ to identify which agent produced it.
4. Win IND-UNL-AS with advantage 1.

This is not a theoretical concern — it is the *primary* deployment scenario. In the credit union case, NFCU is both the operator (signing agent credentials) and the AS (the entity the construction is designed to hide traffic from). Any derivation of `scopeBlindingSecret` from operator-known material collapses the security guarantee to zero in exactly the scenario the construction is built for.

The fix is definitive: `scopeBlindingSecret` is sampled from a CSPRNG at agent-creation time, independent of all operator material. The operator never learns it. The circuit's constraint 9 (`blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)`) binds the secret to the credential without revealing it. The operator can verify that the agent was enrolled (via the Merkle tree) but cannot recover the blinding secret from any public output or on-chain state.

### 3.5 Side-channel threat model

| Side channel | Mitigation |
|---|---|
| **Timing of proof submission** | Epoch bucketing: all proofs within a 300s window share the same `epochId`. Agent MAY add random delay within epoch. |
| **Nonce freshness leakage** | `sessionNonce` is per-request but is not visible to the AS (AS is never contacted). RS sees the nonce but learns only scope-local information. |
| **Proof generation timing** | PLONK proving is constant-time for fixed circuit size. Variance is hardware-dependent, not input-dependent. |
| **Merkle root staleness** | 30-entry root history buffer tolerates proof generation latency without requiring tree-update synchronization that could leak timing. |
| **On-chain scopeCommitment observation** | `scopeCommitment` is stored on-chain only during delegation chain initialization. It reveals that an agent can delegate, not where it authorizes. An adversary observing on-chain state learns the set of agents that have initiated delegation chains, but cannot link a `scopeCommitment` to any RS-facing `scopedNullifier` without breaking Poseidon PRF. |
| **Operator recomputation of blinding secret** | Impossible by construction: `scopeBlindingSecret` is sampled independently of operator key material. The operator holds $sk_{op}$ and all credential fields but has zero bits of information about $s_b$. |
| **IP correlation** | Out of scope for the cryptographic layer; mitigated by transport-layer anonymization (Tor, mixnet). Noted as an explicit non-goal of this construction. |

## 4. Security argument (named assumption + reduction sketch)

### 4.1 Named assumptions

1. **Poseidon PRF security** (A-PRF): Poseidon2, keyed on `scopeBlindingSecret`, is a secure pseudorandom function. That is, $\{(x, \text{Poseidon2}(x, k)) : x \leftarrow \mathcal{X}\}$ is computationally indistinguishable from $\{(x, r) : x \leftarrow \mathcal{X}, r \leftarrow F_p\}$ for any PPT distinguisher, where $k$ is the unknown key. Critically, the key $k = s_b$ is sampled uniformly at random from $F_p$, independent of all other system parameters — this satisfies the standard PRF key-distribution requirement without additional assumptions about key derivation.

2. **Poseidon collision resistance** (A-CR): Finding $(x_1, x_2) \neq (x_1', x_2')$ such that $\text{Poseidon2}(x_1, x_2) = \text{Poseidon2}(x_1', x_2')$ requires $\Omega(2^{128})$ work.

3. **PLONK knowledge soundness** (A-KS): The PLONK proving system satisfies knowledge soundness in the algebraic group model + random oracle model. Any PPT prover producing a valid proof for `ScopedAgentAuth` knows a valid witness.

4. **Discrete logarithm hardness on Baby Jubjub** (A-DL): Given $(G, s \cdot G)$ on the Baby Jubjub curve, computing $s$ requires $\Omega(2^{126})$ work.

### 4.2 Reduction sketch: IND-UNL-AS → Poseidon PRF

**Theorem:** If there exists a PPT adversary $\mathcal{A}$ that wins IND-UNL-AS with non-negligible advantage, then there exists a PPT adversary $\mathcal{B}$ that breaks the PRF security of Poseidon2.

**Proof sketch (hybrid argument):**

Define three hybrid distributions over the adversary's view of the challenge proofs $(\pi_a, \pi_b)$:

- **Hybrid 0 (real, $b=0$):** Both challenge proofs use the same blinding secret $s^{j_0}_b$. The challenge nullifiers are $\text{Poseidon2}(S_a, s^{j_0}_b)$ and $\text{Poseidon2}(S_b, s^{j_0}_b)$.

- **Hybrid 1:** $\pi_a$ uses $s^{j_0}_b$ as before. $\pi_b$'s nullifier is replaced with the output of a truly random function: $\text{scopedNullifier}_b \leftarrow F_p$. The epoch binding is derived from this random nullifier.

- **Hybrid 2 (real, $b=1$):** $\pi_a$ uses $s^{j_0}_b$. $\pi_b$ uses the independent blinding secret $s^{j_1}_b$. The challenge nullifiers are $\text{Poseidon2}(S_a, s^{j_0}_b)$ and $\text{Poseidon2}(S_b, s^{j_1}_b)$.

**Hybrid 0 → Hybrid 1:** $\mathcal{B}_1$ receives a PRF-or-random oracle $\mathcal{O}$ (keyed on $s^{j_0}_b$ or random). $\mathcal{B}_1$ simulates IND-UNL-AS faithfully:

- Generates all $N$ agents honestly. Gives all operator keys to $\mathcal{A}$.
- For query-phase proofs of agent $j_0$ at scope $S_i$: queries $\mathcal{O}(S_i)$ to get the scoped nullifier. For all other agents $j \neq j_0$: $\mathcal{B}_1$ knows $s^j_b$ (it generated them) and evaluates Poseidon2 directly. Simulates valid PLONK proofs via the PLONK zero-knowledge simulator.
- For challenge proof $\pi_a$: queries $\mathcal{O}(S_a)$.
- For challenge proof $\pi_b$: queries $\mathcal{O}(S_b)$.
- If $\mathcal{O}$ is $F_{s^{j_0}_b}$: this is Hybrid 0. If $\mathcal{O}$ is random: this is Hybrid 1.
- $\mathcal{B}_1$'s advantage: $|Pr[\mathcal{A} \text{ distinguishes H0 from H1}]| \leq \text{Adv}^{\text{PRF}}_{\text{Poseidon}}$.

The adversary's possession of all $sk^j_{op}$ does not help because every $s^j_b$ is independent of every $sk^j_{op}$. $\mathcal{B}_1$ can freely hand over all operator keys without compromising the oracle abstraction.

**Hybrid 1 → Hybrid 2:** $\mathcal{B}_2$ receives a PRF-or-random oracle $\mathcal{O}'$ (keyed on $s^{j_1}_b$ or random). $\mathcal{B}_2$ simulates the game with $\pi_b$'s nullifier set to $\mathcal{O}'(S_b)$.

- If $\mathcal{O}'$ is random: this is Hybrid 1. If $\mathcal{O}'$ is $F_{s^{j_1}_b}$: this is Hybrid 2.
- $\mathcal{B}_2$'s advantage: $|Pr[\mathcal{A} \text{ distinguishes H1 from H2}]| \leq \text{Adv}^{\text{PRF}}_{\text{Poseidon}}$.

**Combining:** $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} = |Pr[\mathcal{A}(H_0) = 1] - Pr[\mathcal{A}(H_2) = 1]| \leq 2 \cdot \text{Adv}^{\text{PRF}}_{\text{Poseidon}} + \text{Adv}^{\text{KS}}_{\text{PLONK}} + \text{negl}(\lambda)$.

The knowledge-soundness term accounts for the possibility that $\mathcal{A}$ produces a valid proof without knowing a valid witness (bypassing the nullifier derivation entirely). PLONK knowledge soundness bounds this.

**Why the proof simulation is sound:** The PLONK zero-knowledge property guarantees that simulated proofs are computationally indistinguishable from real proofs. The simulator needs only the public inputs/outputs — not the witness — so $\mathcal{B}$ can simulate proofs without knowing the blinding secret, using the oracle-provided nullifier as the public output.

### 4.3 Collusion resistance argument

When $m$ RSes collude, they share $m$ tuples of `(agentMerkleRoot, scopedNullifier, epochBinding)` along with public inputs `(scopeId, requiredScopeMask, currentTimestamp, sessionNonce, epochId)`. Linking any two tuples to the same agent requires one of:

1. **Inverting the scoped nullifier:** Given `Poseidon2(scopeId_A, scopeBlindingSecret)` and `Poseidon2(scopeId_B, scopeBlindingSecret)`, determining whether the same `scopeBlindingSecret` was used in both — equivalent to breaking A-PRF (the PRF outputs at two different inputs are indistinguishable from independent random values). Note: the adversary may also hold all $sk_{op}$ (AS=operator scenario), but this provides no leverage because every $s_b$ is independent of every $sk_{op}$.

2. **Finding a cross-scope stable value in the public outputs:** There is none. `agentMerkleRoot` is shared by all agents in the tree. `scopedNullifier` varies per (agent, scope). `epochBinding` varies per (agent, scope, epoch). `scopeId` is scope-specific, not agent-specific. No public output of `ScopedAgentAuth` is stable across scopes for a single agent.

3. **Using on-chain `scopeCommitment`:** The `scopeCommitment` is stored on-chain only when the agent initiates a delegation chain via `DelegationEntry`. Even if the adversary reads this value, it cannot link it to any `scopedNullifier` seen at an RS without recovering `scopeBlindingSecret` or `credentialCommitment` — the `scopeCommitment` is `Poseidon2(permissionBitmask, credentialCommitment)` while the `scopedNullifier` is `Poseidon2(scopeId, scopeBlindingSecret)`. These share no common public field. Even an adversarial operator who knows `credentialCommitment` (computable from known credential fields) and therefore knows `scopeCommitment` cannot bridge to `scopedNullifier` without $s_b$, which is independent of all operator material.

In the non-delegation flow (agent authorizes directly at RSes without delegating), no `DelegationEntry` proof is ever submitted and no `scopeCommitment` appears on-chain. Collusion resistance is unconditional on the RS-facing outputs.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scoped nullifier derivation | `Poseidon2(scopeId, scopeBlindingSecret)` | Nullifier definition (§2 Terminology) |
| Epoch binding | `Poseidon2(scopedNullifier, epochId)` | Analogous to nonceBinding in HumanUniqueness |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | AgentPolicy §4.2 |
| Scope commitment (delegation only) | `Poseidon2(permissionBitmask, credentialCommitment)` | Delegation §5.1 — confined to `DelegationEntry` circuit |
| Blinding-secret-to-credential binding | `Poseidon2(scopeBlindingSecret, credentialCommitment)` | Internal constraint; binds agent-local secret to enrolled credential |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | AgentPolicy §4.2 constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §3.2 Lean Incremental Merkle Tree |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | AgentPolicy §4.2 constraint 6 |
| Proving system (ScopedAgentAuth) | PLONK with universal setup (`pot16.ptau`) | §3.3 — PLONK is OPTIONAL for AgentPolicy |
| Proving system (DelegationEntry) | Groth16 or PLONK | Same as Delegation circuit |
| On-chain root verification | 30-entry root history buffer | §3.1 Registry Contract |
| Scope satisfaction | Per-bit AND constraint: `reqBit[i] * (1 - permBit[i]) === 0` | AgentPolicy §4.2 constraint 5 |
| Blinding secret generation | CSPRNG (agent-local, independent of operator material) | §2.4 — operator independence invariant |

**No new primitives are introduced.** The `scopeBlindingSecret` is a standard field element sampled from a CSPRNG, managed identically to the human `secret` scalar (which is also agent-local and independent of any issuer). The `DelegationEntry` circuit reuses all existing gadgets (Poseidon5, EdDSA, BinaryMerkleRoot). The separation is purely architectural — moving an existing public output from one circuit to a dedicated circuit.

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

- **Navy Federal Credit Union (NFCU)** — issues member credentials (acts as operator) and operates an enrollment AS
- **Amazon** (RS-A) — online merchant accepting CU member agent payments
- **Costco** (RS-B) — wholesale merchant accepting CU member agent payments
- **Member agent** — autonomous shopping agent acting on behalf of NFCU member

**Current problem (baseline):** NFCU, acting as both operator and AS, issues OAuth tokens to the member's agent for each merchant. NFCU's token issuance logs reveal: "Member #4821's agent requested `financial_small` access to Amazon at 14:02, then Costco at 14:07." NFCU can reconstruct the complete merchant graph. PPIDs hide the member from merchants, but the AS sees everything.

**Bolyra deployment:**

1. **Enrollment:** NFCU (as operator) signs the agent's credential and enrolls it in the Bolyra agent Merkle tree. The credential commitment encodes `permissionBitmask = 0b00000100` (FINANCIAL_SMALL). **The agent generates `scopeBlindingSecret` locally using its own CSPRNG** — NFCU never receives this value. NFCU knows the operator private key, all credential fields, and can recompute `credentialCommitment`, but has zero information about `scopeBlindingSecret`.

2. **Amazon authorization:** The agent computes `scopedNullifier_A = Poseidon2(scopeId_Amazon, scopeBlindingSecret)` and generates a PLONK proof of `ScopedAgentAuth`. Public outputs: `(agentMerkleRoot, scopedNullifier_A, epochBinding_A)`. **No `scopeCommitment` is sent.** It sends the proof directly to Amazon. Amazon verifies against the on-chain root. **NFCU is never contacted.** Even if NFCU were contacted, it cannot recompute `scopedNullifier_A` because it does not know `scopeBlindingSecret`.

3. **Costco authorization:** The agent computes `scopedNullifier_C = Poseidon2(scopeId_Costco, scopeBlindingSecret)`. Different scope → different nullifier. Public outputs: `(agentMerkleRoot, scopedNullifier_C, epochBinding_C)`. Sends proof to Costco. **NFCU is never contacted.**

4. **Collusion resistance (RS + RS):** Even if Amazon and Costco share their received public outputs, they see:
   - `agentMerkleRoot` — identical for all agents, not identifying
   - `scopedNullifier_A` vs `scopedNullifier_C` — unlinkable under Poseidon PRF (the IND-UNL-AS game directly models this: distinguishing same-agent from different-agent given two proofs at two scopes)
   - `epochBinding_A` vs `epochBinding_C` — unlinkable (derived from unlinkable nullifiers)
   - **No `scopeCommitment`** — the cross-scope stable fingerprint that would have trivially linked the two authorizations is absent from the RS-facing circuit

5. **Collusion resistance (NFCU-as-operator + RS):** NFCU holds `operatorPrivKey` and all credential fields. Amazon shares `scopedNullifier_A` with NFCU. NFCU attempts to verify whether `scopedNullifier_A` belongs to member #4821's agent by computing `Poseidon2(scopeId_Amazon, ?)` — but it cannot fill in `scopeBlindingSecret` because that value was generated by the agent's local CSPRNG, never transmitted to NFCU. NFCU cannot brute-force `scopeBlindingSecret` (it is a uniformly random element of $F_p$, ~254 bits of entropy).

6. **Double-spend prevention:** Within Amazon's scope, the `scopedNullifier_A` is deterministic. If the agent tries to authorize twice within the same scope, Amazon detects the duplicate nullifier. The `epochBinding` provides time-bucketed freshness without requiring AS-issued nonces.

7. **NFCU's view:** NFCU sees only the initial enrollment event. It has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden — not by withholding data from NFCU, but because NFCU cannot compute the mapping between its known credentials and the RS-facing nullifiers.

8. **Delegation (if needed):** If the member wants to delegate to a sub-agent for grocery shopping, the agent submits a `DelegationEntry` proof on-chain (once) to seed the delegation chain. The on-chain `scopeCommitment` reveals that a delegation chain was initiated but not which merchants the delegatee visits. The sub-agent uses its own `ScopedAgentAuth` with its own independently-generated `scopeBlindingSecret` at each RS.

### Scenario: Healthcare delegation across providers

**Stakeholders:**

- **Kaiser Permanente** — primary care provider, credential issuer (operator), and AS
- **Quest Diagnostics** (RS-A) — lab results access
- **Cedars-Sinai** (RS-B) — specialist referral
- **Patient agent** — delegated agent managing cross-provider care

**Flow:** Kaiser enrolls the patient's agent with `permissionBitmask = 0b10000001` (READ_DATA + ACCESS_PII). The agent generates its `scopeBlindingSecret` locally — Kaiser never sees it. The agent delegates to a sub-agent for Quest with narrowed scope `READ_DATA` only, using `DelegationEntry` (on-chain, once) followed by `ScopedDelegation`. The sub-agent generates its own `scopeBlindingSecret` independently. The sub-agent's `scopedNullifier` at Quest is derived from its own `scopeBlindingSecret` and Quest's `scopeId`. Kaiser cannot determine whether the patient visited Quest, Cedars-Sinai, or both — even though Kaiser holds the operator private key and can recompute the credential commitment, it cannot bridge from credential knowledge to RS-facing nullifiers without the agent-local blinding secrets. The referral network topology is hidden from the issuer. Neither Quest nor Cedars-Sinai receives a `scopeCommitment` — they see only scope-local nullifiers that are unlinkable to each other and to the on-chain delegation chain entry.

## 8. Why the baseline cannot match

| Property | Bolyra `ScopedAgentAuth` | Best baseline (PPID + RFC 8707 + DPoP + BBS+) |
|---|---|---|
| **Agent-unlinkability against adversarial AS (= operator)** | Guaranteed by IND-UNL-AS game (agent-unlinkability formulation). AS/operator holds all operator private keys and all credential fields but cannot compute any `scopeBlindingSecret` (independent CSPRNG). RS-facing outputs contain no cross-scope stable identifier. Two proofs at two different scopes are computationally indistinguishable from proofs by two independent agents — reduced to Poseidon PRF security via hybrid argument, with all operator keys explicitly given to the adversary. | **Impossible.** AS issues every token and sees every scope request. PPID hides `sub` from RSes, not from AS. No RFC prevents AS from logging scope × agent × time. |
| **Collusion resistance (RS + RS)** | **No cross-scope stable value in public outputs.** `scopeCommitment` is confined to the on-chain `DelegationEntry` circuit and never sent to RSes. Colluding RSes share only scope-local nullifiers that are unlinkable under Poseidon PRF — formally, the IND-UNL-AS game allows the adversary to control colluding RSes and still bounds the linking advantage. | **Partially addressed by BBS+** multi-show unlinkability at the RS layer, but the AS's token-issuance log trivially links the same agent across RSes. |
| **Collusion resistance (AS/operator + RS)** | Structurally impossible for the adversary: AS/operator knows credential fields but not `scopeBlindingSecret`. RS holds scope-local nullifiers derived from unknown blinding secret. Neither party can bridge the gap. The IND-UNL-AS game explicitly gives the adversary operator keys and RS-received outputs simultaneously. | **Trivially broken.** AS shares its token-issuance log with colluding RS. Full traffic graph reconstructed. |
| **Formal security definition** | IND-UNL-AS game with agent-unlinkability formulation: adversary distinguishes same-agent vs. different-agent given proofs at known, different scopes. Tight reduction via hybrid argument to Poseidon PRF, with factor-2 loss. Adversary receives all operator private keys in game setup. `scopeId` is public (as required for RS policy enforcement) — the game correctly hides the agent assignment, not the scope. | **None.** No OAuth/OIDC/BBS+ spec defines unlinkability against AS. BBS+ multi-show unlinkability is holder-to-verifier only. |
| **AS removal from hot path** | AS is never contacted after enrollment. Verification is RS-local against on-chain roots. | AS must be contacted for every token issuance. JWT introspection response is optional and still requires initial AS contact. |
| **Timing side-channel resistance** | Epoch bucketing quantizes time into 300s windows. `epochBinding` is deterministic within a window — timing within an epoch leaks nothing. | **None.** DPoP `jti` and timestamps leak per-request timing to AS. No RFC mandates batching or padding. |
| **Delegation privacy** | Delegation chain links via `scopeCommitment` stored on-chain by `DelegationEntry` — never sent to RSes. Per-RS nullifiers derived from delegatee's own independently-generated blinding secret. Issuer/operator cannot see chain topology from RS-layer data even with full operator key knowledge. | **RFC 8693 delegation is AS-visible at every hop.** AS sees actor token, subject token, requested scope for each delegation step. |
| **Scope blinding** | Scope is a public input to the circuit but the agent's *association* with the scope is hidden behind the ZK proof. The AS/operator never learns which scope the agent proved for — even with full operator key material, the blinding secret is unknown. | **Not expressible.** OAuth scope is a plaintext field in every token request to the AS. |

**The structural impossibility:** The OAuth/OIDC model places the AS on the critical path of every authorization. Every mitigation (PPID, DPoP, BBS+) operates *below* the AS — hiding information from RSes or transport observers, never from the token issuer. Bolyra's construction eliminates the AS from the authorization path entirely: after enrollment, the agent self-proves to each RS using a ZK proof against a public on-chain state root. The RS-facing proof contains exactly three public outputs — the Merkle root (shared by all agents), a scope-local nullifier (unique to this agent × this scope), and an epoch binding (unique to this agent × this scope × this epoch). No cross-scope stable identifier appears in the RS-facing circuit. The `scopeCommitment` needed for delegation chains is confined to a separate `DelegationEntry` circuit visible only on-chain, architecturally isolated from the RS authorization path. Critically, the `scopeBlindingSecret` that keys the nullifier PRF is generated by the agent's local CSPRNG, independent of all operator material — even an adversary who is simultaneously the operator and the AS cannot recompute nullifiers without compromising the agent's local execution environment. The formal IND-UNL-AS game captures this precisely: with `scopeId` public (as it must be for RS policy enforcement), the adversary's task is to link two proofs at known scopes to the same agent — and the Poseidon PRF reduction shows this is computationally infeasible. This is not an incremental improvement over the baseline — it is a category change in the trust model that no composition of OAuth RFCs can replicate without abandoning the AS-centric architecture that defines OAuth.
