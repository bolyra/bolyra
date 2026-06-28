# Construction

## 1. Statement of claim

Same agent accessing different Resource Server instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively attempts to correlate per-agent traffic graphs. Unlinkability holds across scopes, across time, and against collusion between AS and any subset of RSes. The construction provides a formal IND-UNL-AS game with a concrete reduction to Poseidon PRF security and Groth16/PLONK knowledge soundness.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Core idea: scope-derived ephemeral identity

The agent never presents its credential commitment or any stable identifier to the AS or any RS. Instead, for each RS scope, the agent derives a **scope-local ephemeral nullifier** that is deterministic (enabling double-spend detection within a scope) but unlinkable across scopes (under the Poseidon PRF assumption). The AS issues no tokens — the agent self-proves authorization via PLONK, and the RS verifies the proof directly against on-chain roots.

### 2.2 New circuit: `ScopedAgentAuth`

This circuit extends `AgentPolicy` with scope-isolation properties. It replaces the per-session agent nullifier `Poseidon2(credentialCommitment, sessionNonce)` with a **scope-bound nullifier** that is deterministic per (agent, scope) but unlinkable across scopes.

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
| `scopeCommitment` | field | `Poseidon2(permissionBitmask, credentialCommitment)` — for delegation chain entry |

**Constraints (in addition to standard AgentPolicy constraints 1–7):**

1. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`
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
9. **Scope commitment:** `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` — preserved for delegation chain compatibility
10. **Blinding secret binding to credential:** `blindingCommitment = Poseidon2(scopeBlindingSecret, credentialCommitment)` — constrains that the blinding secret is bound to this specific credential (prevents an agent from using another agent's blinding secret). This value is NOT a public output; it is an intermediate constraint that the prover must satisfy internally, ensuring the blinding secret was derived consistently with the credential.

### 2.3 Blinding secret lifecycle

The `scopeBlindingSecret` is generated once per agent credential (e.g., `scopeBlindingSecret = Poseidon2(operatorPrivKey, "bolyra-scope-blind")`). It is stored alongside the agent's credential material. It never leaves the agent's local storage. It is never revealed as a public signal. The circuit proves knowledge of it without revealing it.

### 2.4 Epoch-based timing mitigation

The `epochId` public input quantizes time into fixed windows (recommended: 300 seconds). Within an epoch, the `epochBinding` output is deterministic per (agent, scope), enabling double-authorization detection. Across epochs, different `epochBinding` values are produced, but the underlying `scopedNullifier` remains stable per scope — the RS can detect repeat access within a scope (by checking the nullifier against its local store) but the AS never sees either value.

### 2.5 Verification flow (AS-free)

1. RS publishes its `scopeId` and `requiredScopeMask` on-chain or in a well-known endpoint.
2. Agent generates a PLONK proof of `ScopedAgentAuth` locally.
3. Agent sends `(proof, publicSignals)` directly to the RS.
4. RS verifies the PLONK proof against the on-chain `agentMerkleRoot` (via root history buffer lookup) and checks `scopedNullifier` against its local double-spend set.
5. **The AS is never contacted.** There is no token issuance step.

### 2.6 Delegation extension: `ScopedDelegation`

For delegation chains, the existing `Delegation` circuit is extended so that the delegatee's `scopedNullifier` is derived from the delegatee's own `scopeBlindingSecret` and the target RS's `scopeId`. The chain-linking constraint uses `scopeCommitment` (which binds to `credentialCommitment`), not the scoped nullifier. This means the delegation chain is verifiable without linking the delegatee's authorizations across scopes.

**Additional private input:** `delegateeScopeBlindingSecret`

**Additional public output:** `delegateeScopedNullifier = Poseidon2(targetScopeId, delegateeScopeBlindingSecret)`

**Additional constraint:** `Poseidon2(delegateeScopeBlindingSecret, delegateeCredCommitment)` must be internally consistent (same binding-secret-to-credential check as in `ScopedAgentAuth`).

## 3. Threat model (adversary capabilities, game definition)

### 3.1 Adversary capabilities

The adversary $\mathcal{A}$ controls:

- **The Authorization Server (AS):** Full control over token issuance logic, logging, and timing observation. The AS may be the same entity as the credential issuer (operator).
- **A coalition of up to $k-1$ out of $k$ Resource Servers:** Colluding RSes share all received proofs, nullifiers, and timing data.
- **Network observation:** $\mathcal{A}$ sees encrypted channel metadata (source IP, connection timing) but not proof contents in transit (TLS assumption).

The adversary does NOT control:

- The agent's local execution environment (the `scopeBlindingSecret` is not leaked).
- The on-chain Merkle tree integrity (smart contract correctness assumption).
- The Poseidon hash function (collision resistance and PRF assumptions hold).

### 3.2 IND-UNL-AS game

**Game: IND-UNL-AS$(1^\lambda, \mathcal{A})$**

1. **Setup:** Challenger generates agent credential $C$ with `scopeBlindingSecret` $s_b$. Enrolls $C$ in the agent Merkle tree. Generates $n \geq 2$ distinct scope identifiers $\{S_1, \ldots, S_n\}$.

2. **Query phase:** $\mathcal{A}$ adaptively requests proofs for scopes of its choice. For each query $(S_i, \text{nonce}_j, \text{epoch}_k)$, the challenger returns the full public output vector $(\text{agentMerkleRoot}, \text{scopedNullifier}_i, \text{epochBinding}_{i,k}, \text{scopeCommitment})$.

3. **Challenge:** $\mathcal{A}$ selects two *unused* scopes $S_a, S_b$ and a nonce. The challenger flips a coin $b \leftarrow \{0, 1\}$. If $b = 0$, the challenger generates a proof for $S_a$; if $b = 1$, for $S_b$. $\mathcal{A}$ receives the proof and all public signals.

4. **Guess:** $\mathcal{A}$ outputs $b'$.

5. **Advantage:** $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} = |Pr[b' = b] - 1/2|$

**Win condition:** $\mathcal{A}$ wins if it can determine which of two scopes the proof was generated for, given that it has never seen a proof for either scope before.

**Claim:** For any PPT adversary $\mathcal{A}$:

$$\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\text{Poseidon}} + \text{Adv}^{\text{KS}}_{\text{PLONK}} + \text{negl}(\lambda)$$

### 3.3 Side-channel threat model

| Side channel | Mitigation |
|---|---|
| **Timing of proof submission** | Epoch bucketing: all proofs within a 300s window share the same `epochId`. Agent MAY add random delay within epoch. |
| **Nonce freshness leakage** | `sessionNonce` is per-request but is not visible to the AS (AS is never contacted). RS sees the nonce but learns only scope-local information. |
| **Proof generation timing** | PLONK proving is constant-time for fixed circuit size. Variance is hardware-dependent, not input-dependent. |
| **Merkle root staleness** | 30-entry root history buffer tolerates proof generation latency without requiring tree-update synchronization that could leak timing. |
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
   - For query-phase scope $S_i$: queries its oracle on $S_i$ to get $\text{scopedNullifier}_i$. Computes `epochBinding` and `scopeCommitment` honestly. Simulates a valid PLONK proof using the PLONK simulator (exists by zero-knowledge property).
   - For the challenge scopes $(S_a, S_b)$: queries the oracle on $S_b$ (the selected scope) to get the challenge nullifier.

3. If the oracle is $F_k$: the simulation is perfect — $\mathcal{A}$'s view is identical to the real IND-UNL-AS game.

4. If the oracle is $R$: the challenge nullifier is uniformly random and independent of the scope. $\mathcal{A}$'s advantage is exactly 0.

5. Therefore: $\text{Adv}^{\text{IND-UNL-AS}}_{\mathcal{A}} \leq \text{Adv}^{\text{PRF}}_{\mathcal{B}} + \text{Adv}^{\text{KS}}_{\text{PLONK}}$.

The knowledge-soundness term accounts for the possibility that $\mathcal{A}$ submits a proof for a scope without knowing a valid witness (bypassing the nullifier derivation). PLONK knowledge soundness bounds this.

### 4.3 Collusion resistance argument

When $m$ RSes collude, they share $m$ distinct `scopedNullifier` values. Linking any two requires inverting Poseidon2 on the `scopeBlindingSecret` — equivalent to breaking A-PRF. The `scopeCommitment` is identical across scopes for the same agent, but `scopeCommitment` is only revealed to the *delegation chain verifier* (on-chain), not to individual RSes in the direct-verification flow. In the standard (non-delegation) flow, the RS sees only `(agentMerkleRoot, scopedNullifier, epochBinding)`, none of which are linkable across scopes.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scoped nullifier derivation | `Poseidon2(scopeId, scopeBlindingSecret)` | Nullifier definition (§2 Terminology) |
| Epoch binding | `Poseidon2(scopedNullifier, epochId)` | Analogous to nonceBinding in HumanUniqueness |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | AgentPolicy §4.2 |
| Scope commitment (delegation) | `Poseidon2(permissionBitmask, credentialCommitment)` | Delegation §5.1 |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | AgentPolicy §4.2 constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §3.2 Lean Incremental Merkle Tree |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | AgentPolicy §4.2 constraint 6 |
| Proving system | PLONK with universal setup (`pot16.ptau`) | §3.3 — PLONK is OPTIONAL for AgentPolicy |
| On-chain root verification | 30-entry root history buffer | §3.1 Registry Contract |
| Scope satisfaction | Per-bit AND constraint: `reqBit[i] * (1 - permBit[i]) === 0` | AgentPolicy §4.2 constraint 5 |

**No new primitives are introduced.** The `scopeBlindingSecret` is a standard field element managed identically to the human `secret` scalar. The `Poseidon2(scopeId, scopeBlindingSecret)` nullifier derivation reuses the exact same pattern as the human nullifier `Poseidon2(scope, secret)`.

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
| Poseidon2 (scope commitment) | ~600 |
| Poseidon2 (blinding-secret-to-credential binding) | ~600 |
| **Total** | **~17,724** |

This fits within 2^16 constraints (65,536), compatible with `pot16.ptau`.

### Proving time targets

| Proving system | Target | Rationale |
|---|---|---|
| PLONK (agent, primary) | < 3s | Agent-side proving on commodity hardware (M1/equivalent). PLONK universal setup avoids per-circuit ceremony. Well under the 5s PLONK budget. |
| Groth16 (agent, optional) | < 2s | ~17.7K constraints with rapidsnark native prover. |

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

2. **Amazon authorization:** The agent computes `scopedNullifier_A = Poseidon2(scopeId_Amazon, scopeBlindingSecret)` and generates a PLONK proof of `ScopedAgentAuth`. It sends the proof directly to Amazon. Amazon verifies against the on-chain root. **NFCU is never contacted.**

3. **Costco authorization:** The agent computes `scopedNullifier_C = Poseidon2(scopeId_Costco, scopeBlindingSecret)`. Different scope → different nullifier. Sends proof to Costco. **NFCU is never contacted.**

4. **Collusion resistance:** Even if Amazon and Costco share `scopedNullifier_A` and `scopedNullifier_C`, they cannot determine these came from the same agent. Linking requires recovering `scopeBlindingSecret` from two Poseidon2 outputs with different first inputs — this is a PRF inversion, not feasible under A-PRF.

5. **Double-spend prevention:** Within Amazon's scope, the `scopedNullifier_A` is deterministic. If the agent tries to authorize twice within the same scope, Amazon detects the duplicate nullifier. The `epochBinding` provides time-bucketed freshness without requiring AS-issued nonces.

6. **NFCU's view:** NFCU sees only the initial enrollment event. It has no visibility into which merchants the agent subsequently contacts, when, or how often. The merchant graph is cryptographically hidden.

### Scenario: Healthcare delegation across providers

**Stakeholders:**

- **Kaiser Permanente** — primary care provider and credential issuer
- **Quest Diagnostics** (RS-A) — lab results access
- **Cedars-Sinai** (RS-B) — specialist referral
- **Patient agent** — delegated agent managing cross-provider care

**Flow:** Kaiser enrolls the patient's agent with `permissionBitmask = 0b10000001` (READ_DATA + ACCESS_PII). The agent delegates to a sub-agent for Quest with narrowed scope `READ_DATA` only, using `ScopedDelegation`. The sub-agent's `scopedNullifier` at Quest is derived from its own `scopeBlindingSecret` and Quest's `scopeId`. Kaiser cannot determine whether the patient visited Quest, Cedars-Sinai, or both. The referral network topology is hidden from the issuer.

## 8. Why the baseline cannot match

| Property | Bolyra `ScopedAgentAuth` | Best baseline (PPID + RFC 8707 + DPoP + BBS+) |
|---|---|---|
| **Unlinkability against adversarial AS** | Guaranteed by IND-UNL-AS game. AS never sees per-scope authorizations. Reduced to Poseidon PRF security. | **Impossible.** AS issues every token and sees every scope request. PPID hides `sub` from RSes, not from AS. No RFC prevents AS from logging scope × agent × time. |
| **Formal security definition** | IND-UNL-AS game with concrete reduction. | **None.** No OAuth/OIDC/BBS+ spec defines unlinkability against AS. BBS+ multi-show unlinkability is holder-to-verifier only. |
| **AS removal from hot path** | AS is never contacted after enrollment. Verification is RS-local against on-chain roots. | AS must be contacted for every token issuance. JWT introspection response is optional and still requires initial AS contact. |
| **Timing side-channel resistance** | Epoch bucketing quantizes time into 300s windows. `epochBinding` is deterministic within a window — timing within an epoch leaks nothing. | **None.** DPoP `jti` and timestamps leak per-request timing to AS. No RFC mandates batching or padding. |
| **Collusion resistance (AS + RS)** | Structurally impossible: AS has no per-scope data to share. RS holds only scope-local nullifiers unlinkable across scopes. | **Trivially broken.** AS shares its token-issuance log with colluding RS. Full traffic graph reconstructed. |
| **Delegation privacy** | Delegation chain links via `scopeCommitment` (on-chain only). Per-RS nullifiers derived from delegatee's own blinding secret. Issuer cannot see chain topology from RS-layer data. | **RFC 8693 delegation is AS-visible at every hop.** AS sees actor token, subject token, requested scope for each delegation step. |
| **Scope blinding** | Scope is a public input to the circuit but the agent's *association* with the scope is hidden behind the ZK proof. The AS never learns which scope the agent proved for. | **Not expressible.** OAuth scope is a plaintext field in every token request to the AS. |

**The structural impossibility:** The OAuth/OIDC model places the AS on the critical path of every authorization. Every mitigation (PPID, DPoP, BBS+) operates *below* the AS — hiding information from RSes or transport observers, never from the token issuer. Bolyra's construction eliminates the AS from the authorization path entirely: after enrollment, the agent self-proves to each RS using a ZK proof against a public on-chain state root. There is no token to issue, no scope to request, no timestamp to log. The AS becomes an enrollment registrar, not an authorization intermediary. This is not an incremental improvement over the baseline — it is a category change in the trust model that no composition of OAuth RFCs can replicate without abandoning the AS-centric architecture that defines OAuth.
