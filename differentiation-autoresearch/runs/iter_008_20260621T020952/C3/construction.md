# Construction

## 1. Statement of claim

An auditor verifies that a multi-hop delegation chain narrowed permissions monotonically at every hop — without learning any intermediate scope values or participant identities — and the resulting proof is anchored to on-chain state so the auditor cannot be fed a fabricated chain. The construction applies to AI agent pipelines (tool-call chains), whistleblower-safe delegation, and cross-org agent handoff — not just narrow regulatory audit.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationChainAudit(MAX_HOPS)`

**Proving system**: PLONK (universal setup, no per-circuit ceremony — auditors can verify without trusting a circuit-specific ceremony)

**MAX_HOPS**: 8 (covers tool-call pipelines, journalist relay chains, cross-org handoffs)

#### Private inputs (per hop `i` in `0..MAX_HOPS-1`):

| Signal | Type | Description |
|--------|------|-------------|
| `scope[i]` | 64-bit | Permission bitmask at hop `i` |
| `credCommitment[i]` | field | Credential commitment of participant at hop `i` |
| `blindingSalt[i]` | field | Random blinding factor for scope commitment hiding (≥ 128 bits of entropy) |
| `delegationNullifier[i]` | field | Nullifier from the delegation proof at hop `i` |
| `chainPredecessor[i]` | field | The `previousScopeCommitment` public input from hop `i`'s on-chain delegation proof |
| `hopActive[i]` | binary | 1 if hop exists, 0 for padding |

#### Public inputs:

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Blinded scope commitment from the initial handshake (on-chain, in `HandshakeVerified` event) |
| `chainLength` | Number of active delegation hops |
| `sessionNonce` | Binds to the originating handshake session |
| `auditPolicyMask` | Bitmask of permissions the auditor wants to confirm the terminal agent satisfies |

#### Public outputs:

| Signal | Description |
|--------|-------------|
| `narrowingValid` | 1 iff monotonic narrowing holds at every active hop |
| `policyOk` | 1 iff the terminal scope satisfies `auditPolicyMask` |
| `chainAnchor` | `PoseidonN(hopDigest[0], ..., hopDigest[MAX_HOPS-1])` where each `hopDigest[i] = Poseidon3(delegationNullifier[i], chainPredecessor[i], scopeCommit[i])` — binds each hop's nullifier, predecessor commitment, and output scope commitment into a single digest, cross-referenced against on-chain `DelegationVerified` events |
| `terminalScopeCommitment` | Scope commitment at the final hop (auditor can verify it matches on-chain `lastScopeCommitment`) |

#### Constraints:

1. **Hop activation monotonicity**: `hopActive[i] * (1 - hopActive[i]) === 0` for all `i` (binary). For `i > 0`: `(hopActive[i-1] - hopActive[i]) * hopActive[i] === 0` (once deactivated, stays deactivated). `hopActive[0] === 1` (at least one hop).

2. **Chain length consistency**: `sum(hopActive[i]) === chainLength`.

3. **Blinded scope commitment reconstruction** (per active hop): `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])`. For `i = 0`: `scopeCommit[0] === rootScopeCommitment`. The blinding salt `blindingSalt[i]` is a per-hop random field element with at least 128 bits of entropy, chosen by the hop's delegator at delegation time. It makes the scope commitment computationally hiding even when `scope[i]` is drawn from a small domain (e.g., 8-bit bitmask → 256 values).

4. **Chain linking** (sequential coherence via predecessor binding):
   Each hop's `chainPredecessor[i]` represents the `previousScopeCommitment` public input that was verified in hop `i`'s on-chain delegation proof. The circuit enforces:
   ```
   // Hop 0's predecessor must be the handshake root
   chainPredecessor[0] === rootScopeCommitment

   // Each subsequent active hop's predecessor must equal
   // the prior hop's (reconstructed) scope commitment
   for i in 1..MAX_HOPS-1:
     hopActive[i] * (chainPredecessor[i] - scopeCommit[i-1]) === 0
   ```
   This ensures the in-circuit scope commitment sequence forms a properly linked chain: hop `i`'s delegation proof took `scopeCommit[i-1]` as its `previousScopeCommitment` input, and hop `i`'s output `scopeCommit[i]` becomes the predecessor for hop `i+1`. The `chainPredecessor[i]` values are then bound to on-chain state via the hop digest (constraint 8), so the auditor can verify that each predecessor matches the `previousScopeCommitment` recorded in the corresponding `DelegationVerified` event.

   For inactive hops (`hopActive[i] = 0`), `chainPredecessor[i]` is constrained to 0 (see constraint 8, inactive-hop zeroing).

5. **Monotonic narrowing** (per active adjacent pair `i > 0`):
   ```
   scope[i] = Num2Bits(64)(scope[i])
   scope[i-1] = Num2Bits(64)(scope[i-1])
   for each bit b in [0, 64):
     hopActive[i] * scopeBits[i][b] * (1 - scopeBits[i-1][b]) === 0
   ```
   Every bit set in the delegatee's scope must also be set in the delegator's scope. Inactive hops are unconstrained.

6. **Cumulative bit encoding** (per active hop):
   ```
   hopActive[i] * scopeBits[i][4] * (1 - scopeBits[i][3]) === 0
   hopActive[i] * scopeBits[i][4] * (1 - scopeBits[i][2]) === 0
   hopActive[i] * scopeBits[i][3] * (1 - scopeBits[i][2]) === 0
   ```

7. **Terminal scope policy check**:
   ```
   auditBits = Num2Bits(64)(auditPolicyMask)
   termIdx = chainLength - 1
   for each bit b in [0, 64):
     auditBits[b] * (1 - terminalScopeBits[b]) === 0
   policyOk = 1 (all constraints satisfied) or 0
   ```
   Uses a multiplexer on `chainLength` to select the terminal hop's scope bits.

8. **Nullifier-predecessor-scope binding** (per hop): Each hop's digest cryptographically binds the delegation nullifier, the predecessor scope commitment, and the output scope commitment:
   ```
   hopDigest[i] = Poseidon3(delegationNullifier[i], chainPredecessor[i], scopeCommit[i])
   ```
   For inactive hops (`hopActive[i] = 0`), all three components are constrained to 0 (deterministic padding):
   ```
   (1 - hopActive[i]) * delegationNullifier[i] === 0
   (1 - hopActive[i]) * chainPredecessor[i] === 0
   (1 - hopActive[i]) * scopeCommit[i] === 0
   ```
   This ensures inactive padding cannot carry non-trivial digest values, and produces deterministic zero digests `hopDigest[i] = Poseidon3(0, 0, 0)` for all inactive hops.

9. **Chain anchor with predecessor binding**: `chainAnchor = PoseidonN(hopDigest[0], ..., hopDigest[MAX_HOPS-1])`. The auditor reconstructs each `hopDigest[i]` by computing `Poseidon3(nullifier_i, previousScopeCommitment_i, newScopeCommitment_i)` from the `(delegationNullifier, previousScopeCommitment, newScopeCommitment)` triple emitted in on-chain `DelegationVerified` events, hashes all 8 digests (active hops from events, inactive hops as `Poseidon3(0, 0, 0)`), and verifies the result equals `chainAnchor`. A mismatch proves the prover used fabricated chain linkage. Critically, this binds not just each hop's output but also its declared predecessor — a prover cannot reorder hops, skip hops, or substitute a different predecessor without producing a non-matching anchor.

10. **Terminal scope commitment output**: `terminalScopeCommitment = scopeCommit[termIdx]` via multiplexer on `chainLength`. Auditor verifies this matches the on-chain `lastScopeCommitment[sessionNonce]`.

### Why constraint 4 is now non-vacuous

The prior version used `select(hopActive[i], scopeCommit[i-1], scopeCommit[i-1]) === select(hopActive[i], previousExpected, previousExpected)` which reduced to `scopeCommit[i-1] === previousExpected` with `previousExpected` undefined — a tautology. The new constraint 4 introduces `chainPredecessor[i]` as an explicit private input representing the `previousScopeCommitment` from hop `i`'s on-chain delegation proof, and enforces two concrete equalities:

- `chainPredecessor[0] === rootScopeCommitment` (anchors the chain start to the handshake)
- `hopActive[i] * (chainPredecessor[i] - scopeCommit[i-1]) === 0` (links each hop to its predecessor)

These are non-trivial constraints: the prover must supply `chainPredecessor[i]` values that simultaneously (a) satisfy the chain-linking equalities inside the circuit and (b) appear in the hop digests (constraint 8) that the auditor cross-references against on-chain events. A prover cannot satisfy both requirements with fabricated values because the hop digest `Poseidon3(nullifier_i, chainPredecessor[i], scopeCommit[i])` must match the on-chain triple — collision resistance of Poseidon3 prevents finding alternative inputs that produce the same digest.

### Required upstream change: blinded scope commitments in `Delegation` and `AgentPolicy` circuits

The blinding salt must originate where scope commitments are first computed — in the `AgentPolicy` circuit (for the handshake root) and the `Delegation` circuit (for each hop). The scope commitment formula changes from:

```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
```

to:

```
scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingSalt)
```

where `blindingSalt` is a new private input (field element, ≥ 128 bits of entropy) in both circuits. The on-chain `lastScopeCommitment` mapping and `DelegationVerified` events store these blinded commitments. The chain-linking constraint in the existing `Delegation` circuit (`Poseidon2(delegatorScope, delegatorCredCommitment) === previousScopeCommitment`) becomes `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorBlindingSalt) === previousScopeCommitment`, requiring the delegator to supply their blinding salt as an additional private input.

This is a minimal, backward-compatible change: `blindingSalt` is a private input (no public signal layout change), and the on-chain scope commitment values remain opaque field elements of the same size. The only coordination requirement is that each delegator retains their `blindingSalt` to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking.

### On-chain event requirement for chain-linking verification

The `DelegationVerified` event MUST emit the `previousScopeCommitment` public input alongside the existing `delegationNullifier` and `newScopeCommitment` outputs. This is already available as a public signal of the `Delegation` circuit (index 3 in the public signal layout) — the registry contract simply needs to include it as an indexed event field. The auditor uses these `(delegationNullifier, previousScopeCommitment, newScopeCommitment)` triples to reconstruct hop digests for chain anchor verification.

### Gadgets used:

- `Num2Bits(64)` — bit decomposition for scope bitmasks (circomlib)
- `Poseidon3` — blinded scope commitment hashing and hop digest computation (circomlib/poseidon)
- `PoseidonN` (N=8) — chain anchor hashing over hop digests
- `Mux1` / `MultiMux` — hop selection for terminal index
- `IsZero`, `IsEqual` — activation flag logic

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:
- Any subset of participants in the delegation chain (collusion)
- The auditor's communication channel (can see auditor queries)
- Up to `MAX_HOPS - 1` of the delegation hops

The adversary sees:
- All public outputs of the audit proof (`narrowingValid`, `policyOk`, `chainAnchor`, `terminalScopeCommitment`)
- The public inputs (`rootScopeCommitment`, `chainLength`, `sessionNonce`, `auditPolicyMask`)
- All on-chain events (`HandshakeVerified`, `DelegationVerified`), including every `(delegationNullifier, previousScopeCommitment, newScopeCommitment)` triple
- The full agent Merkle tree (all `credCommitment` leaf values are public)

The adversary does NOT control:
- The Poseidon hash function (random oracle model for Poseidon)
- The BN128 pairing (trusted setup for PLONK is universal)
- The blinding salts of honest participants

### Security game: NarrowingAuditSoundness

```
Game NarrowingAuditSoundness(λ):
  1. Challenger sets up Bolyra registry with honest enrollment
  2. A adaptively creates delegation chains (may collude with participants)
  3. A produces (proof π, public inputs/outputs)
  4. A wins if:
     (a) Verifier(π) = ACCEPT, AND
     (b) narrowingValid = 1, AND
     (c) chainAnchor cross-references valid on-chain events
         (each hopDigest[i] matches a DelegationVerified event's
          (nullifier, previousScopeCommitment, newScopeCommitment) triple), AND
     (d) the hop digests form a sequentially coherent chain
         (event[i].previousScopeCommitment = event[i-1].newScopeCommitment
          for all active i > 0, and
          event[0].previousScopeCommitment = rootScopeCommitment), AND
     (e) there exists some hop i where the ACTUAL on-chain scope[i] ⊄ scope[i-1]
         (i.e., the real scopes recorded on-chain did NOT narrow monotonically)
```

**Condition (d) is new** relative to the prior construction. It reflects the auditor's strengthened verification: because the hop digest now includes `chainPredecessor[i]`, the auditor can verify not just that each hop corresponds to a real on-chain event, but that the events form a properly linked sequence. This closes the gap where a prover could have selected unrelated on-chain delegation events and composed them into a fictitious chain.

**Claim**: `Pr[A wins] ≤ negl(λ)` under knowledge soundness of PLONK + collision resistance of Poseidon.

### Privacy game: ScopeRecovery

#### Narrowing lattice definition

For a chain of length `n` and a corruption set `S ⊂ {0, ..., n-1}` controlled by the adversary, define the **narrowing lattice** at an honest hop `j ∉ S` as the set of scope values consistent with the adversary's view of the delegation structure:

```
L_j(S) = { s ∈ {0,1}^64 :
             ∀ i ∈ S, i < j : s ⊆ scope[i]       (narrowing from corrupted ancestors)
           ∧ ∀ i ∈ S, i > j : scope[i] ⊆ s        (narrowing to corrupted descendants)
           ∧ cumulative bit encoding holds for s }
```

When the adversary corrupts both immediate neighbors `j-1` and `j+1`, this reduces to:

```
L_j = { s : scope[j+1] ⊆ s ⊆ scope[j-1] ∧ cumulative encoding(s) }
```

The lattice size is `|L_j| = 2^k` where `k = popcount(scope[j-1] ∧ ¬scope[j+1])` minus any bits eliminated by cumulative encoding constraints — i.e., `k` counts the "free" bits that could be either set or cleared at hop `j` without violating narrowing or cumulative implication rules.

**Critical observation**: `|L_j|` is determined entirely by the delegation semantics and the adversary's knowledge of corrupted hops' scopes. It is *not* a failure of the commitment scheme. When `|L_j| = 1`, the adversary learns `scope[j]` with certainty from the narrowing structure alone — no cryptographic attack is needed, and no commitment scheme can prevent it.

#### Formal game

```
Game ScopeRecovery(λ, S):
  1. Challenger enrolls agents in the Merkle tree (credCommitments are public).
  2. Challenger runs an honest delegation chain of length n ≤ MAX_HOPS,
     choosing each blindingSalt[i] ←$ F_p uniformly at random.
  3. A declares a corruption set S ⊂ {0, ..., n-1} with |S| ≤ n-1.
  4. A receives:
     - The full agent Merkle tree (all credCommitment values)
     - All on-chain (delegationNullifier[i], previousScopeCommitment[i],
       newScopeCommitment[i]) triples
     - The audit proof and all public inputs/outputs
     - The scope values, blinding salts, and all private state
       of every corrupted hop i ∈ S
  5. A selects a target hop j ∉ S and outputs a guess scope*[j].
  6. A wins if scope*[j] = scope[j].
```

**Claim (conditional bound)**: For any corruption set `S` and target hop `j ∉ S`:

```
Pr[A wins] ≤ (1 / |L_j(S)|) · (|L_j(S)| / |F_p|) · |L_j(S)| + 1/|L_j(S)|
```

Wait — this requires more care. The adversary's advantage decomposes into two independent sources:

1. **Structural inference** (information-theoretic, inherent to delegation semantics): The adversary can narrow `scope[j]` to the lattice `L_j(S)` from corrupted hops' scopes and the narrowing constraint alone. This leakage is unavoidable by any scheme — it follows from the definition of monotonic narrowing.

2. **Commitment inversion** (computational, defeated by blinding): Given that `scope[j] ∈ L_j(S)`, the adversary attempts to identify which element of `L_j(S)` is correct by attacking the blinded scope commitment `scopeCommit[j] = Poseidon3(scope[j], credCommitment[j], blindingSalt[j])`.

**Theorem (ScopeRecovery bound)**:

```
Pr[A wins] ≤ 1/|L_j(S)| + |L_j(S)| / |F_p| + negl(λ)
```

where:

- `1/|L_j(S)|` is the optimal guessing probability when the adversary cannot distinguish among lattice elements (random guess within the structurally feasible set). This term dominates only when `|L_j(S)|` is small.
- `|L_j(S)| / |F_p|` is the probability that any of the `|L_j(S)|` Poseidon3 preimage queries succeeds under the random oracle model. This is negligible for all practical lattice sizes (`|L_j(S)| ≤ 2^64 ≪ |F_p| ≈ 2^254`).

**Interpretation by lattice size**:

| Lattice size `|L_j(S)|` | Structural leakage `1/|L_j|` | Computational advantage `|L_j|/|F_p|` | Total bound | Interpretation |
|---|---|---|---|---|
| 1 (tight chain) | 1 | `2^{-254}` | **1** | Scope fully determined by narrowing semantics. Blinding irrelevant — adversary wins from structure alone. Inherent and unavoidable. |
| 2 | 1/2 | `2^{-253}` | **≈ 1/2** | One free bit. Adversary guesses with coin-flip odds. Blinding prevents confirmation. |
| 16 (4 free bits) | 1/16 | `2^{-250}` | **≈ 1/16** | Moderate ambiguity. Blinding fully effective. |
| 256 (8 free bits, full bitmask) | 1/256 | `2^{-246}` | **≈ 1/256** | Maximum ambiguity for 8-bit active scope. Blinding fully effective. |
| `2^64` (all bits free) | `2^{-64}` | `2^{-190}` | **≈ 2^{-64}** | Maximum 64-bit scope ambiguity. Negligible advantage either way. |

**Key insight**: The `2^{-246}` bound from the prior construction was the *computational* component alone, valid only when the lattice is maximally ambiguous (`|L_j| = 256` for 8-bit active scope). The prior construction stated this as unconditional while simultaneously acknowledging the `|L_j| = 1` degenerate case in prose — a contradiction. The reformulation above resolves this: the bound is always `1/|L_j| + negl(λ)`, making the dependence on structural leakage explicit. The blinding salt's role is precisely to ensure that the computational component (`|L_j|/|F_p|`) is negligible — it does not and cannot prevent structural inference from the narrowing semantics.

**Without blinding** (comparison): `Pr[A wins] = 1` for any `|L_j| ≤ 2^{64}`. The adversary computes `Poseidon2(s, credCommitment[j])` for each `s ∈ L_j(S)` and matches against the on-chain `scopeCommitment[j]`. Even for `|L_j| = 2^{64}`, this is computationally feasible (2^64 hash evaluations). Blinding raises the cost from `|L_j|` hash evaluations (trivial) to `|L_j|` Poseidon3 preimage inversions (infeasible).

**Collusion geometry**: The adversary optimizes its corruption set `S` to minimize `|L_j(S)|` for the target hop `j`. The worst case is corrupting both immediate neighbors (`j-1, j+1 ∈ S`), which yields the tightest lattice. Corrupting non-adjacent hops provides strictly less information (the narrowing constraint is transitive, so `scope[j+2] ⊆ scope[j]` is weaker than `scope[j+1] ⊆ scope[j]` when `scope[j+1]` is unknown). The adversary's optimal strategy is therefore to corrupt `j-1` and `j+1`, making the lattice analysis above tight.

**Note on `previousScopeCommitment` exposure**: The `DelegationVerified` event now emits `previousScopeCommitment[i]` alongside `newScopeCommitment[i]`. This does not weaken the ScopeRecovery game: `previousScopeCommitment[i] = newScopeCommitment[i-1]`, which was already visible on-chain. No new scope commitment values are exposed — the predecessor is always the prior hop's output, already an on-chain value.

### Relationship between the two games

`NarrowingAuditSoundness` ensures the auditor cannot be deceived about whether narrowing held. `ScopeRecovery` ensures the auditor (or any observer of on-chain state) cannot learn what the actual scope values were, up to the information-theoretic leakage inherent in the narrowing structure itself. Together, they provide the dual guarantee: the auditor is convinced of the structural property (narrowing) without learning the data (scopes and participants), except what monotonic narrowing with known boundary scopes logically implies.

The conditional formulation of `ScopeRecovery` makes this duality precise: the blinding salt is *necessary and sufficient* to close the gap between structural leakage (`1/|L_j|`) and total scope recovery (probability 1 without blinding). It does not claim to hide information that is logically determined by the delegation semantics — that would be impossible for any scheme.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions:

1. **Knowledge soundness of PLONK** (Marlin/PLONK proof): any efficient prover producing an accepting proof can be extracted to a valid witness.
2. **Collision resistance of Poseidon** over BN254 scalar field: no efficient adversary finds `(x₁, x₂, x₃) ≠ (y₁, y₂, y₃)` with `Poseidon3(x₁, x₂, x₃) = Poseidon3(y₁, y₂, y₃)`.
3. **Preimage resistance of Poseidon** over BN254 scalar field: given `y`, no efficient adversary finds `(x₁, x₂, x₃)` with `Poseidon3(x₁, x₂, x₃) = y`.
4. **Discrete logarithm hardness on Baby Jubjub**: credential commitments are binding (operator cannot produce two distinct credentials with the same commitment).

### Reduction sketch (soundness):

Suppose adversary A wins `NarrowingAuditSoundness` with non-negligible probability ε. Then:

1. By PLONK knowledge soundness, extract witness `(scope[0..n], credCommitment[0..n], blindingSalt[0..n], delegationNullifier[0..n], chainPredecessor[0..n], ...)` from A's proof.

2. The extracted witness satisfies constraint 3 (blinded scope commitment reconstruction): `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])` for each active hop.

3. The extracted witness satisfies constraint 4 (chain linking): `chainPredecessor[0] = rootScopeCommitment` and `chainPredecessor[i] = scopeCommit[i-1]` for each active hop `i > 0`.

4. The extracted witness satisfies constraint 8 (nullifier-predecessor-scope binding): `hopDigest[i] = Poseidon3(delegationNullifier[i], chainPredecessor[i], scopeCommit[i])` for each hop.

5. The extracted witness satisfies constraint 9 (chain anchor): `chainAnchor = PoseidonN(hopDigest[0], ..., hopDigest[7])`.

6. By game conditions (c) and (d), the auditor has verified that each `hopDigest[i]` matches the on-chain triple `(nullifier_i^{chain}, prevSC_i^{chain}, newSC_i^{chain})` from `DelegationVerified` events, and these events form a sequentially coherent chain. That is, `hopDigest[i] = Poseidon3(nullifier_i^{chain}, prevSC_i^{chain}, newSC_i^{chain})`.

7. From steps 4 and 6: `Poseidon3(delegationNullifier[i], chainPredecessor[i], scopeCommit[i]) = Poseidon3(nullifier_i^{chain}, prevSC_i^{chain}, newSC_i^{chain})`. By collision resistance of Poseidon3 (Assumption 2): `delegationNullifier[i] = nullifier_i^{chain}` AND `chainPredecessor[i] = prevSC_i^{chain}` AND `scopeCommit[i] = newSC_i^{chain}`.

8. **Chain coherence follows from constraint 4 + step 7**: From step 3, `chainPredecessor[i] = scopeCommit[i-1]` for active `i > 0`. From step 7, `chainPredecessor[i] = prevSC_i^{chain}` and `scopeCommit[i-1] = newSC_{i-1}^{chain}`. Therefore `prevSC_i^{chain} = newSC_{i-1}^{chain}` — the on-chain events are sequentially linked. This is exactly what game condition (d) requires, but now it is *enforced by the circuit* rather than assumed as an external auditor check. If the on-chain events were not sequentially linked, no valid witness could satisfy both constraint 4 and produce a matching chain anchor — the prover would need to find a Poseidon3 collision to make `chainPredecessor[i] = scopeCommit[i-1]` while `hopDigest[i]` matches a non-sequential on-chain event.

9. From step 7, `scopeCommit[i] = newSC_i^{chain}`. By step 2, `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])`, and the on-chain scope commitment was computed as `Poseidon3(scope_i^{actual}, credCommitment_i^{actual}, salt_i^{actual})`. By collision resistance of Poseidon3 (Assumption 2): `scope[i] = scope_i^{actual}`, `credCommitment[i] = credCommitment_i^{actual}`, and `blindingSalt[i] = salt_i^{actual}`.

10. The extracted witness satisfies constraint 5 (monotonic narrowing): for every active hop `i`, `scope[i] & scope[i-1] == scope[i]`. By step 9, these are the actual on-chain scopes.

11. Game condition (e) asserts the actual on-chain scopes did NOT narrow at some hop. But step 10 proves they did. Contradiction.

12. Therefore `ε ≤ negl(λ)`.

**Note on the role of constraint 4 in the reduction**: Step 8 is new and critical. In the prior construction, constraint 4 was vacuous, so the reduction could not establish that the in-circuit scope commitment sequence matched the actual on-chain chain order. An adversary could have supplied scope commitments from unrelated on-chain delegation events (each individually valid) but in a reordered or cherry-picked sequence that happened to satisfy narrowing even though the actual chain did not. Constraint 4 closes this by forcing `chainPredecessor[i] = scopeCommit[i-1]`, which — combined with the hop digest binding to on-chain events — ensures the circuit's scope commitment sequence is exactly the on-chain sequence. The collision resistance of Poseidon3 prevents any alternative input assignment from producing matching digests.

### Reduction sketch (scope hiding):

Suppose adversary A wins `ScopeRecovery` with probability exceeding `1/|L_j(S)| + |L_j(S)|/|F_p| + negl(λ)` for some corruption set `S` and target hop `j`. We construct a reduction B that breaks Poseidon3 preimage resistance:

1. B receives a Poseidon3 preimage challenge: given target `y`, find `(x₁, x₂, x₃)` with `Poseidon3(x₁, x₂, x₃) = y`.

2. B sets up the Bolyra registry honestly, choosing scope values for all hops. At the target hop `j`, B sets `scopeCommitment[j] = y` (the challenge value) instead of computing it honestly. B simulates the rest of the chain honestly, providing corrupted hops' full state to A. B uses the PLONK simulator for the audit proof (honest-verifier ZK).

3. B computes `L_j(S)` — the narrowing lattice at hop `j` given the corrupted scopes — and uniformly samples `scope[j] ←$ L_j(S)` for the honest-looking simulation. (Since the commitment is replaced with the challenge `y`, B does not need the actual blinding salt.)

4. A outputs a guess `scope*[j]`.

5. **Case analysis**:
   - If A's advantage comes only from guessing within `L_j(S)`, then `Pr[A wins] ≤ 1/|L_j(S)|` — no Poseidon preimage is broken.
   - If A's advantage exceeds `1/|L_j(S)|` by a non-negligible margin δ, then A must be distinguishing among lattice elements via the commitment. For each candidate `s ∈ L_j(S)`, A effectively tests whether `∃ r : Poseidon3(s, credCommitment[j], r) = y`. Success on any such test yields a Poseidon3 preimage.

6. B runs A. If A outputs `scope*[j]` with probability > `1/|L_j(S)| + negl(λ)`, B extracts: for the winning guess `s* = scope*[j]`, there exists `r*` such that `Poseidon3(s*, credCommitment[j], r*) = y`. Since `credCommitment[j]` is known, B obtains a Poseidon3 preimage `(s*, credCommitment[j], r*)` of `y`.

7. The total number of preimage queries across all `|L_j(S)|` candidates is at most `|L_j(S)|`, each succeeding with probability `1/|F_p|` under preimage resistance. Therefore the computational component of A's advantage is bounded by `|L_j(S)|/|F_p|`.

8. Combining: `Pr[A wins] ≤ 1/|L_j(S)| + |L_j(S)|/|F_p| + negl(λ)`.

**Note on tightness**: The bound is tight in both extremes. When `|L_j| = 1` (degenerate narrowing), the bound gives `Pr ≤ 1 + negl(λ)` — trivially true, and the adversary does win with certainty from structure alone. When `|L_j| = 256` (full 8-bit ambiguity), the bound gives `Pr ≤ 1/256 + 2^{-246} + negl(λ) ≈ 1/256` — the adversary's best strategy is random guessing within the lattice, and the blinding salt prevents any computational improvement. The prior construction's unconditional `2^{-246}` claim was the computational term alone, which is correct but incomplete — it omitted the `1/|L_j|` structural term that dominates for small lattices.

**Note on Assumption 3 vs. the ROM**: The reduction models Poseidon3 as preimage-resistant rather than requiring the full random oracle model. This is a weaker (more conservative) assumption. The ROM would give a tighter bound but is not needed — preimage resistance suffices because the adversary's task is specifically to invert, not to distinguish.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Blinded scope commitment `Poseidon3(scope, credCommitment, blindingSalt)` | Extension of identity-bound scope commitment with hiding property. Replaces `Poseidon2(scope, credCommitment)` in `AgentPolicy` and `Delegation` circuits. | `draft-bolyra-mutual-zkp-auth-01` §5 (modified) |
| Blinding salt `blindingSalt` | New private input in `AgentPolicy`, `Delegation`, and `DelegationChainAudit` circuits. Field element with ≥ 128 bits of entropy, chosen uniformly at random by the delegator at each hop. | New; required by this construction |
| Chain predecessor `chainPredecessor[i]` | The `previousScopeCommitment` public input from hop `i`'s on-chain `Delegation` proof. Already a public signal (index 3) in the Delegation circuit. | `draft-bolyra-mutual-zkp-auth-01` §5.2, Delegation public signal layout |
| Delegation nullifier `Poseidon2(delegationTokenHash, sessionNonce)` | Delegation nullifier | Delegation circuit public output index 1 |
| Hop digest `Poseidon3(delegationNullifier, chainPredecessor, scopeCommit)` | Binding primitive; composed from three on-chain outputs of each delegation event | Constraint 8 of this construction |
| 64-bit permission bitmask with cumulative encoding | Bolyra permission model (bits 0–7 active, 8–63 reserved) | `CLAUDE.md` Permissions Model |
| `previousScopeCommitment` → `newScopeCommitment` chain | On-chain `lastScopeCommitment` mapping (now stores blinded commitments) | `draft-bolyra-mutual-zkp-auth-01` §5.1 (modified) |
| `rootScopeCommitment` from handshake | `agentPubSignals[2]` stored by registry (now blinded) | Handshake verification step 6b |
| PLONK proving system | Agent/Delegation PLONK option | `CLAUDE.md` Circuits table |
| `sessionNonce` binding | Handshake session nonce | `draft-bolyra-mutual-zkp-auth-01` §4.1 |
| Poseidon hash (BN254 scalar field) | Required hash function | `draft-bolyra-mutual-zkp-auth-01` §3.2 |
| Baby Jubjub EdDSA | Operator signature scheme (used in underlying delegation proofs, not re-verified in audit circuit) | `draft-bolyra-mutual-zkp-auth-01` §3.2 |

The audit circuit does NOT re-verify EdDSA signatures or Merkle membership — those are already enforced by the per-hop `Delegation` circuit proofs verified on-chain. The audit circuit operates one layer above: it proves the *structural property* (monotonic narrowing) over the chain of already-verified hops, and the hop digest (constraint 8) ensures the structural proof is anchored to the actual on-chain delegation state — including the chain ordering via `chainPredecessor` — rather than fabricated or reordered witness data.

### On-chain registry requirement

The `DelegationVerified` event MUST emit `delegationNullifier`, `previousScopeCommitment`, and `newScopeCommitment` as indexed fields. The `previousScopeCommitment` is already a public input of the `Delegation` circuit (signal index 3) and is available to the registry contract at verification time — emitting it requires no additional on-chain computation. The `AgentPolicy` circuit's scope commitment output (public signal index 2) and the `Delegation` circuit's scope commitment output (public signal index 0) both change from `Poseidon2(scope, credCommitment)` to `Poseidon3(scope, credCommitment, blindingSalt)`. This is a change to the commitment formula but not to the public signal layout or the on-chain storage schema — scope commitments remain single field elements.

### Upstream circuit changes required

| Circuit | Change | Impact |
|---------|--------|--------|
| `AgentPolicy` | Add `blindingSalt` private input; change `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` → `Poseidon3(permissionBitmask, credentialCommitment, blindingSalt)` | +1 private input, +~100 constraints (Poseidon3 vs Poseidon2) |
| `Delegation` | Add `delegatorBlindingSalt` and `delegateeBlindingSalt` private inputs; update chain-linking constraint and `newScopeCommitment` output to use `Poseidon3` | +2 private inputs, +~200 constraints |

These are additive changes with no public signal layout modifications. Existing verifier contracts require redeployment (new `.zkey` / `.vkey`), but the on-chain registry ABI is unchanged.

## 6. Circuit cost estimate

### Constraint breakdown (MAX_HOPS = 8):

| Component | Constraints per hop | Total |
|-----------|-------------------|-------|
| `Num2Bits(64)` for scope | 64 | 512 |
| `Poseidon3` for blinded scope commitment | ~400 | 3,200 |
| `Poseidon3` for hop digest (nullifier + predecessor + scope) | ~400 | 3,200 |
| Inactive-hop zero constraints (4 per hop: nullifier, chainPredecessor, scopeCommit, blindingSalt) | 4 | 32 |
| Bitwise subset check (64 bits, 7 active pairs) | 64 per pair | 448 |
| Cumulative bit encoding | 3 | 24 |
| Hop activation logic (binary + monotonicity) | ~5 | 40 |
| Chain linking (predecessor = prior output, 8 constraints) | 1 | 8 |
| Terminal multiplexer (8-way, 64 bits) | ~200 | 200 |
| Policy mask check (64 bits) | 64 | 64 |
| `PoseidonN(8)` for chain anchor (over hopDigests) | ~600 | 600 |
| Chain length consistency | ~16 | 16 |
| **Total** | | **~8,344** |

### Delta from prior construction:

The chain-linking fix and hop digest upgrade add ~816 constraints over the prior ~7,528:
- Hop digest changes from `Poseidon2` (~300/hop) to `Poseidon3` (~400/hop): +800 across 8 hops
- Chain predecessor zero-constraints for inactive hops: +8
- Chain linking equality constraints: +8

This is an 11% increase. The total (~8,344) remains well within the PLONK agent budget.

### Proving time targets:

| System | Constraints | Target | Rationale |
|--------|------------|--------|-----------|
| PLONK (agent-class) | ~8,344 | **< 2 seconds** | Well under the 5s PLONK agent budget; smaller than `AgentPolicy` (~18K) |
| Groth16 (optional) | ~8,344 | **< 1 second** | If circuit-specific ceremony is acceptable |

### Comparison to existing circuits:

- `HumanUniqueness`: ~12,000 constraints → 8,344 is 1.4× smaller
- `AgentPolicy`: ~18,000 constraints → 8,344 is 2.2× smaller
- `Delegation`: ~22,000 constraints → 8,344 is 2.6× smaller

The circuit remains lightweight because it delegates EdDSA verification and Merkle membership to the per-hop `Delegation` proofs already verified on-chain. The Poseidon3 calls for both blinded scope commitments and hop digests are the cost of achieving scope hiding, on-chain anchoring, and sequential chain coherence simultaneously — a necessary trade for closing both the enumeration attack and the chain-linking gap.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), largest US credit union with $176B in assets. Subject to NCUA examination and FFIEC guidance on third-party AI agent use.

**Setup**: NFCU deploys an AI agent pipeline for member loan origination:
1. **Hop 0 (root)**: Member's personal AI assistant (e.g., Claude) — full `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bitmask `0b10000111 = 0x87`)
2. **Hop 1**: NFCU's loan intake agent — narrows to `READ_DATA | WRITE_DATA | FINANCIAL_SMALL` (bitmask `0b00000111 = 0x07`, drops `ACCESS_PII`)
3. **Hop 2**: Third-party credit scoring agent (TransUnion) — narrows to `READ_DATA` only (bitmask `0b00000001 = 0x01`)
4. **Hop 3**: NFCU's underwriting agent — narrows to `READ_DATA | FINANCIAL_SMALL` (bitmask `0b00000101 = 0x05`)

Each delegator chooses a random blinding salt when issuing the delegation. The salt is retained locally by the delegator and passed as a private input to the next hop's delegation proof (for chain-linking) and to the audit proof generator.

**Narrowing lattice analysis for this pipeline** (demonstrating the conditional privacy bound):

| Target hop `j` | Corrupted neighbors | `L_j` (feasible scopes) | `|L_j|` | `Pr[ScopeRecovery]` bound |
|---|---|---|---|---|
| Hop 1 (`0x07`) | Hops 0,2 corrupted: `scope[0]=0x87`, `scope[2]=0x01` | `{s : 0x01 ⊆ s ⊆ 0x87}` = scopes with bit 0 set, bits 1,2,7 free, others clear | 8 | ≤ 1/8 + negl(λ) |
| Hop 2 (`0x01`) | Hops 1,3 corrupted: `scope[1]=0x07`, `scope[3]=0x05` | `{s : 0x05 ⊆ s ⊆ 0x07}` = `{0x05, 0x07}` (bit 1 free) | 2 | ≤ 1/2 + negl(λ) |
| Hop 2 (`0x01`) | Only hop 3 corrupted: `scope[3]=0x05` | `{s : 0x05 ⊆ s}` within 8-bit space — many candidates | 16 | ≤ 1/16 + negl(λ) |

This demonstrates that the privacy guarantee depends on the delegation structure. The auditor (NCUA examiner) cannot learn hop 1's exact permissions even with full collusion from adjacent hops — the best attack is a 1-in-8 guess. For hop 2 in the worst case (both neighbors corrupted), only 2 scope values are feasible, giving a coin-flip bound. The blinding salt ensures even this limited ambiguity cannot be resolved computationally.

**Audit trigger**: NCUA examiner requests proof that the pipeline respected least-privilege at every hop, per FFIEC guidance on AI model risk management (SR 11-7 analogue).

**Without Bolyra** (baseline): NFCU must disclose the full delegation token chain to the examiner, revealing:
- TransUnion's involvement (competitive intelligence)
- The specific permission bitmasks at each hop (proprietary pipeline architecture)
- Each agent's credential commitment (linkable across examinations)

Even with BBS+ selective disclosure, the 8-bit scope bitmask has only 256 possible values. An examiner who sees `scopeCommitment = Poseidon2(scope, credCommitment)` and knows `credCommitment` from the public Merkle tree can brute-force the scope in 256 hash evaluations — rendering selective disclosure moot for the scope dimension.

**With Bolyra `DelegationChainAudit` (blinded, chain-linked)**:

1. NFCU's compliance agent generates a PLONK proof with:
   - Public inputs: `rootScopeCommitment` (from handshake event), `chainLength = 4`, `sessionNonce`, `auditPolicyMask = 0x01` (examiner checks terminal agent had at least `READ_DATA`)
   - Private inputs: all 4 scopes, credential commitments, blinding salts, delegation nullifiers, and chain predecessors

2. Examiner receives: `(proof, narrowingValid=1, policyOk=1, chainAnchor, terminalScopeCommitment)`

3. Examiner verifies:
   - PLONK proof checks out (no trust in NFCU's systems required)
   - Retrieves the 4 `DelegationVerified` events for this `sessionNonce` from on-chain state, each containing `(nullifier_i, prevSC_i, newSC_i)`
   - Verifies the on-chain events form a sequential chain: `prevSC_0 = rootScopeCommitment`, `prevSC_1 = newSC_0`, `prevSC_2 = newSC_1`, `prevSC_3 = newSC_2`
   - Reconstructs each `hopDigest[i] = Poseidon3(nullifier_i, prevSC_i, newSC_i)` from the on-chain events, hashes all 8 digests (4 real + 4 zero-padded as `Poseidon3(0,0,0)`), and confirms the result equals `chainAnchor` — this proves the in-circuit scope commitment sequence is exactly the on-chain sequence, in the correct order, with no hops skipped or reordered
   - `terminalScopeCommitment` matches `lastScopeCommitment[sessionNonce]` on-chain
   - `narrowingValid = 1` — monotonic narrowing held at every hop
   - `policyOk = 1` — terminal agent had at least `READ_DATA`

4. Examiner learns: the chain has 4 hops, narrowing held, the hops are sequentially coherent with on-chain state, and the terminal agent satisfied the policy. Examiner does NOT learn: who the intermediate agents are, what specific permissions each had, or the pipeline architecture. **The examiner's scope inference is bounded by the narrowing lattice: at best a 1-in-2 guess for the tightest hop (hop 2), and no computational attack improves on this.**

**Why chain linking matters in this scenario**: Without constraint 4, a malicious compliance agent could select 4 unrelated `DelegationVerified` events — perhaps from a different pipeline where narrowing happened to hold — and prove narrowing over those events instead of the actual loan origination pipeline. The chain-linking constraint forces the proof's scope commitments to form a sequence where each hop's predecessor equals the prior hop's output, and the hop digests bind this sequence to specific on-chain events. The examiner can verify from on-chain state that `prevSC_1 = newSC_0` etc., confirming the events are actually sequential — not cherry-picked.

### Journalist/source variant:

A journalist's agent delegates to a source's agent through two intermediary relay agents. The journalist generates the audit proof. An editor (auditor) verifies the delegation chain narrowed properly (the source's agent could only `READ_DATA`, not `WRITE_DATA` or `SIGN_ON_BEHALF`) without learning the identities of the relay agents or the source. The blinded scope commitments prevent the editor from inferring scope values even for the small permission space — the relay agents' exact capabilities remain hidden, with privacy bounded by the narrowing lattice (which the journalist controls by choosing how aggressively each hop narrows). The `chainAnchor` lets the editor verify both the chain's existence, its sequential coherence, and its scope integrity against on-chain events, without correlating participants or recovering their mandates.

## 8. Why the baseline cannot match

| Capability | Bolyra `DelegationChainAudit` | Baseline (RFC 8693 + BBS+ + WIMSE) |
|-----------|------------------------------|-------------------------------------|
| **Prove narrowing without disclosing scopes** | Bitwise subset check runs on private inputs inside the circuit. Hop digests (constraint 8) bind each hop's predecessor and output scope commitment to on-chain state via Poseidon3, and chain linking (constraint 4) enforces sequential coherence. Blinding salt (constraint 3) prevents brute-force recovery. Auditor sees only `narrowingValid = 1`. Privacy is bounded by `1/|L_j| + negl(λ)` where `|L_j|` is the narrowing lattice size — an information-theoretic limit that no scheme can beat. | BBS+ can hide individual claims but cannot prove `scope[i] ⊆ scope[i-1]` over hidden bitmasks. Even with selective disclosure, an 8-bit scope has 256 possible values — any observer who knows the credential commitment can brute-force the scope against an unblinded commitment in microseconds. |
| **Enforce sequential chain coherence** | Constraint 4 forces `chainPredecessor[i] = scopeCommit[i-1]` in-circuit. The hop digest binds `chainPredecessor[i]` to the on-chain `previousScopeCommitment` via collision-resistant hashing. A prover cannot select unrelated delegation events or reorder hops — the chain must be the actual on-chain sequence. | RFC 8693 `act` claim nesting implies ordering, but the auditor must trust the AS to have enforced it. There is no cryptographic binding between the ordering and the narrowing proof — the AS log is the only evidence. |
| **Scope hiding under enumeration** | `scopeCommit = Poseidon3(scope, credCommitment, blindingSalt)` with 128+ bits of salt entropy. Recovery requires a Poseidon3 preimage attack. Privacy bound: `Pr[ScopeRecovery] ≤ 1/|L_j| + |L_j|/|F_p| + negl(λ)`, where `|L_j|` is the narrowing lattice size given corrupted neighbors. For 8 free bits: `≈ 1/256`. For fully constrained chains: `= 1` (inherent, unavoidable by any scheme). The bound is honest about what blinding can and cannot achieve. | No mechanism. BBS+ selective disclosure hides claim values from the verifier, but on-chain scope commitments (if ever posted for cross-reference) are brute-forceable for small domains. The baseline has no equivalent of a computationally hiding commitment for small-domain values because it lacks a blinding primitive in the delegation layer. |
| **Anchor proof to actual chain state** | Each `hopDigest[i] = Poseidon3(nullifier_i, chainPredecessor_i, scopeCommit_i)` binds three on-chain values — the delegation nullifier, the predecessor scope commitment, and the output scope commitment — into a single digest. The chain anchor hashes all 8 digests. A prover who substitutes fake scopes, reorders hops, or splices events from different chains produces a non-matching anchor. | RFC 8693 tokens are bearer artifacts. An auditor verifying a token chain trusts that the AS issued them correctly. There is no cryptographic binding between the token's scope and an independently verifiable anchor — the AS is the anchor. |
| **Hide intermediate participants** | All `credCommitment[i]` values are private inputs. Auditor sees only the `chainAnchor` (hash of bound triples). | RFC 8693 `act` claim tree is plaintext. BBS+ selective disclosure operates within a single credential, not across a multi-issuer chain. No standard mechanism hides participants in a multi-hop delegation. |
| **No trusted third party** | PLONK proof is self-verifiable. The hop digest and chain-linking constraints ensure the proof's scopes and ordering match on-chain reality without querying any authority — the BN254 pairing check, Poseidon collision resistance, and in-circuit chain linking are the only trust assumptions. | RFC 8693 narrowing enforcement requires the Authorization Server. Auditor who cannot query or trust the AS has no narrowing guarantee. AS compromise breaks the entire chain. |
| **Cross-org without shared AS** | Each hop's delegation proof is independently verified on-chain. The audit circuit chains blinded scope commitments across organizational boundaries using Poseidon, with sequential coherence enforced by constraint 4 — no shared AS or federation protocol needed. | Cross-org delegation requires either a shared AS or WIMSE federation trust anchor. No standard produces a single artifact proving cross-org monotonic narrowing without a common authority that sees all scopes. |
| **Journalist/source anonymity** | Participant identities never appear in any public output. Nullifiers are pseudonymous (Poseidon2 of delegation token hash + nonce) and unlinkable across sessions. Blinding prevents scope inference even when the permission domain is small, bounded by the narrowing lattice. | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-to-RS correlation but not AS or auditor correlation via the `act` chain. No mechanism proves "a legitimate holder participated at hop k" without identifying them. |
| **In-circuit enforcement at presentation** | Narrowing and chain coherence are proven in-circuit at the moment the audit proof is generated. The proof IS the enforcement — no gap between issuance-time policy and presentation-time reality. | RFC 8693 enforces narrowing at issuance. Post-issuance, tokens can be presented to any accepting RS. No runtime binding between the narrowing proof and the credential's actual use. |
| **Offline verifiability** | PLONK proof + on-chain event cross-reference. No real-time API calls to any authority. | RFC 7662 introspection requires live AS queries. Signed introspection responses (draft-ietf-oauth-jwt-introspection-response) are offline-verifiable but still reveal scope values. |
| **Composability with Bolyra handshake** | `rootScopeCommitment` directly chains from the `HandshakeVerified` event. Constraint 4 anchors hop 0's predecessor to this root. The audit proof extends the existing Bolyra proof pipeline with minimal upstream changes (Poseidon2 → Poseidon3 for scope commitments, `previousScopeCommitment` emitted in events). | Integrating RFC 8693 with a ZKP handshake requires a custom bridge layer. No standard defines how OAuth token exchange interoperates with on-chain ZKP verification. |

**The structural impossibility**: BBS+ provides selective disclosure of *attributes within a single credential*. Monotonic narrowing is a *relational property across a sequence of credentials*. Proving `∀i: scope[i] ⊆ scope[i-1]` over hidden values requires arithmetic over those values — exactly what an R1CS/PLONK circuit provides and what BBS+ signature schemes do not. The chain-linking constraint further widens the gap: even if BBS+ could prove a relational property over hidden scopes, it has no mechanism to enforce *sequential coherence* — that the chain's ordering matches on-chain reality, not a cherry-picked or reordered subset of events. The blinding salt adds a third dimension with a now-precise privacy characterization: it makes small-domain values (8-bit bitmasks) computationally hiding on-chain, with privacy `1/|L_j| + negl(λ)` conditional on the narrowing lattice — an information-theoretically optimal bound that no scheme can improve and no composition of BBS+ derived proofs, RFC 8693 token exchanges, or WIMSE attestations can achieve without either exposing scopes or introducing a trusted aggregator.
