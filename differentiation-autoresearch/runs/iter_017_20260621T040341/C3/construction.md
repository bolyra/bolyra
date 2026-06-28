# Construction

## 1. Statement of claim

An auditor verifies that an N-hop delegation chain narrowed permissions monotonically — each hop's scope is a bitwise subset of its predecessor's, and each hop's expiry is no later than its predecessor's — without learning any intermediate scope values, participant identities, credential commitments, or Merkle tree positions. The proof is a single PLONK proof over a self-contained `DelegationAuditChain` circuit that re-proves the entire chain from scratch (no reliance on a trusted Authorization Server or on-chain intermediate state), anchored only to the root scope commitment emitted by the original handshake.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationAuditChain(MAX_HOPS, MAX_DEPTH)`

Parameters: `MAX_HOPS = 8`, `MAX_DEPTH = 20`.

**Private inputs (per hop `i`, 0 ≤ i < MAX_HOPS):**

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScope[i]` | uint64 | Delegator permission bitmask |
| `delegateeScope[i]` | uint64 | Delegatee permission bitmask |
| `delegatorExpiry[i]` | uint64 | Delegator expiry timestamp |
| `delegateeExpiry[i]` | uint64 | Delegatee expiry timestamp |
| `delegatorCredCommitment[i]` | field | Poseidon5 of delegator credential |
| `delegateeCredCommitment[i]` | field | Poseidon5 of delegatee credential |
| `delegatorPubkeyAx[i]`, `delegatorPubkeyAy[i]` | field | Delegator EdDSA public key |
| `sigR8x[i]`, `sigR8y[i]`, `sigS[i]` | field | Delegator EdDSA signature |
| `delegateeMerkleProofSiblings[i][MAX_DEPTH]` | field[] | Delegatee Merkle proof |
| `delegateeMerkleProofIndex[i]` | field | Delegatee leaf index |
| `delegateeMerkleProofLength[i]` | field | Delegatee proof depth |

Note: `hopActive[i]` is **not** a private input. It is a **derived signal** computed in-circuit from `chainLength` (see constraint 0 below).

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Scope commitment from the handshake (chain anchor) |
| `sessionNonce` | Session binding (ties audit to a specific handshake) |
| `chainLength` | Number of active hops (1..MAX_HOPS) |
| `enrollmentMerkleRoot` | Agent Merkle tree root all delegatees must be enrolled under |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `finalScopeCommitment` | Terminal scope commitment after all hops |
| `auditNullifier` | Poseidon2(rootScopeCommitment, sessionNonce) — replay prevention |

Note: `finalDelegateeMerkleRoot` is no longer a public output — it is replaced by the `enrollmentMerkleRoot` public input constraint (see constraint 8 and the enrollment root binding section below).

### Constraint logic (per hop i):

```
// 0. Derive hopActive from chainLength (NOT a free private input)
//    hopActive[i] = 1 iff i < chainLength
//    Uses LessThan(4) since MAX_HOPS = 8, so indices and chainLength
//    fit in 4 bits (values 0–8).
hopActive[i] <== LessThan(4)(i, chainLength)
//    where i is a compile-time constant wired directly.
//
//    Additionally, enforce chainLength ∈ [1, MAX_HOPS]:
//    (only once, not per hop)
//    Num2Bits(4)(chainLength)
//    LessEqThan(4)(chainLength, MAX_HOPS) === 1
//    LessEqThan(4)(1, chainLength) === 1

// 1. Range checks
Num2Bits(64)(delegatorScope[i])
Num2Bits(64)(delegateeScope[i])
Num2Bits(64)(delegatorExpiry[i])
Num2Bits(64)(delegateeExpiry[i])

// 2. Chain linking — delegator's scope commitment must match prior hop output
// For hop 0: must match rootScopeCommitment (public input)
// For hop i>0: must match newScopeCommitment from hop i-1
let prevSC = (i == 0) ? rootScopeCommitment : newScopeCommitment[i-1]
let computedDelegatorSC = Poseidon2(delegatorScope[i], delegatorCredCommitment[i])
hopActive[i] * (computedDelegatorSC - prevSC) === 0

// 3. Monotonic scope narrowing (bitwise subset)
let delegatorBits = Num2Bits(64)(delegatorScope[i])
let delegateeBits = Num2Bits(64)(delegateeScope[i])
for bit j in [0, 64):
    hopActive[i] * delegateeBits[j] * (1 - delegatorBits[j]) === 0

// 4. Cumulative bit encoding on delegatee scope
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[3]) === 0
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[2]) === 0
hopActive[i] * delegateeBits[3] * (1 - delegateeBits[2]) === 0

// 5. Expiry narrowing
hopActive[i] * LessEqThan(64)(delegateeExpiry[i], delegatorExpiry[i]) === 1

// 6. Delegation token
let delegationToken = Poseidon4(prevSC, delegateeCredCommitment[i],
                                 delegateeScope[i], delegateeExpiry[i])

// 7. EdDSA signature verification
hopActive[i] * EdDSAPoseidonVerifier(
    delegatorPubkeyAx[i], delegatorPubkeyAy[i],
    sigR8x[i], sigR8y[i], sigS[i],
    delegationToken
) === hopActive[i]

// 8. Delegatee enrollment — Merkle membership pinned to enrollmentMerkleRoot
let computedRoot[i] = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[i],
    delegateeMerkleProofLength[i],
    delegateeMerkleProofIndex[i],
    delegateeMerkleProofSiblings[i]
)
hopActive[i] * (computedRoot[i] - enrollmentMerkleRoot) === 0

// 9. New scope commitment for chain propagation
newScopeCommitment[i] = Poseidon2(delegateeScope[i], delegateeCredCommitment[i])

// 10. Inactive hop identity: if !hopActive, propagate prior scope commitment
// finalSC = hopActive[i] ? newScopeCommitment[i] : prevSC
effectiveSC[i] = hopActive[i] * newScopeCommitment[i] + (1 - hopActive[i]) * prevSC
```

**Terminal outputs:**
```
finalScopeCommitment = effectiveSC[MAX_HOPS - 1]
auditNullifier = Poseidon2(rootScopeCommitment, sessionNonce)
```

### Enrollment root binding: why a single public input, not per-hop public outputs

**Prior vulnerability:** In the previous construction, each hop computed a `delegateeMerkleRoot[i]` independently but never constrained it against any public value. Only the terminal hop's root was surfaced as `finalDelegateeMerkleRoot`. This left intermediate hops' enrollment checks unconstrained — a malicious prover could supply a fabricated Merkle proof for any intermediate delegatee, proving "enrollment" against an arbitrary root that no verifier ever checks. Concretely:

- At hop 1, the prover supplies a Merkle proof for a phantom delegatee credential commitment `C*` that was never enrolled in the real agent registry. The proof is valid against a root `R*` that the prover constructs ad hoc (any leaf set containing `C*`). Since no constraint ties `R*` to the on-chain registry, the circuit accepts it. The delegatee at hop 1 passes the enrollment check despite never being a legitimate agent.

- Only the final hop's root was checked. An 8-hop chain had 7 unchecked enrollment proofs.

**Fix:** A single public input `enrollmentMerkleRoot` is added to the circuit. Every active hop's computed Merkle root is constrained to equal this value:

```
hopActive[i] * (computedRoot[i] - enrollmentMerkleRoot) === 0
```

For active hops (`hopActive[i] = 1`), this reduces to `computedRoot[i] === enrollmentMerkleRoot` — the delegatee's Merkle proof must resolve to the exact root the auditor provides. For inactive hops (`hopActive[i] = 0`), the constraint is trivially satisfied regardless of the computed root.

**Why a single root rather than per-hop public outputs:**

1. **Privacy preservation.** Surfacing N intermediate Merkle roots as public outputs would leak timing information: if the agent tree was updated between hop creation times, different roots would reveal *when* each hop was constructed relative to tree updates. A single root reveals nothing about per-hop timing.

2. **Bolyra architecture alignment.** The Bolyra spec defines a single agent Merkle tree (§2.1). All enrolled agents are leaves in this tree. The tree is append-only (agents are added, never removed at the tree level; revocation is handled separately via nullifier mappings). Therefore, a root that is recent enough to contain all delegatees in the chain is guaranteed to exist — it is simply the current root or any root in the 30-entry history buffer that postdates the last enrollment in the chain.

3. **Auditor verification simplicity.** The auditor cross-references the single `enrollmentMerkleRoot` against the on-chain root history buffer (a 30-entry circular buffer per §2.1). One membership check, not N. The auditor confirms: "all delegatees in this chain were enrolled agents at a point in time captured by this root."

4. **No loss of generality.** Because the Merkle tree is append-only, any root R that contains delegatee D_k also contains all delegatees D_j enrolled before D_k. The prover picks the earliest root in the history buffer that contains all N delegatees. If agents were enrolled across multiple tree updates, the prover uses the root after the last enrollment. If no single root in the history buffer contains all delegatees (because some were enrolled more than 30 updates ago), the delegation chain itself is stale and should not be auditable — this is a feature, not a limitation.

**Constraint cost of the fix:** One subtraction and one multiplication per hop, plus the `enrollmentMerkleRoot` public input wire. At 2 constraints per hop × 8 hops = 16 constraints. The removal of the `finalDelegateeMerkleRoot` output saves the selection logic that previously picked the terminal root (approximately 20 constraints for the `chainLength - 1` index mux). Net change: **~0 constraints** (effectively neutral).

### hopActive derivation and the hop-skip attack

**Prior vulnerability:** In an earlier construction, `hopActive[i]` was a free private input (a bit the prover could set arbitrarily). A malicious prover could set `hopActive[2] = 0` while claiming `chainLength = 4`, creating a chain with a gap at hop 2. Because inactive hops propagate the prior scope commitment unchanged and all constraints multiply by `hopActive`, the skipped hop would impose no narrowing, no signature check, and no enrollment check — yet the chain would appear to have 4 verified hops.

**Fix:** `hopActive[i]` is now a **derived signal**, computed in-circuit as `LessThan(4)(i, chainLength)`. The constant index `i` is hard-wired at compile time. The `LessThan(4)` gadget produces a constrained output bit that is 1 iff `i < chainLength`. This makes hop activation a deterministic function of the public `chainLength` — the prover has no freedom to skip or reorder hops.

**`chainLength` range enforcement:** A single global constraint block (evaluated once, not per hop) enforces `1 ≤ chainLength ≤ MAX_HOPS`:

```
// Global: chainLength range
Num2Bits(4)(chainLength)                        // fits in 4 bits
LessEqThan(4)(chainLength, MAX_HOPS) === 1      // ≤ 8
LessEqThan(4)(1, chainLength) === 1             // ≥ 1
```

This prevents `chainLength = 0` (no hops, trivially passes) and `chainLength > MAX_HOPS` (would require unconstrained hops to be active).

**Constraint cost of the hop-skip fix:** `LessThan(4)` uses approximately 12 constraints (two `Num2Bits(4)` decompositions plus a subtraction comparison). Over 8 hops, this adds ~96 constraints. The `chainLength` range check adds ~30 constraints (one `Num2Bits(4)` + two `LessEqThan(4)`). Total overhead: **~126 constraints**, negligible relative to the ~111K circuit.

### Inactive hop handling

For hop `i ≥ chainLength`, `hopActive[i] = 0` (enforced by `LessThan(4)(i, chainLength) = 0`). All constraint multiplications by `hopActive` evaluate to 0, making those hops trivially satisfiable. The scope commitment propagates unchanged through inactive hops via the mux: `effectiveSC[i] = hopActive[i] * newScopeCommitment[i] + (1 - hopActive[i]) * prevSC`.

The prover MUST still supply syntactically valid private inputs for inactive hops (field elements that satisfy range checks independently of `hopActive` — since `Num2Bits(64)` is applied unconditionally). This is standard practice: inactive hops can use zeroed inputs.

Note on inactive hop enrollment: For inactive hops, the enrollment constraint `hopActive[i] * (computedRoot[i] - enrollmentMerkleRoot) === 0` reduces to `0 === 0`, so the Merkle proof for inactive hops is unchecked. This is correct — inactive hops represent padding, not real delegation events. The zeroed inputs will compute some arbitrary root that is ignored.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary **A** controls:
- All intermediate delegation agents (keys, credentials, enrollment)
- The chain construction (can pick any scope values, expiry values, credential commitments)
- The proving environment (can attempt to forge proofs)

The adversary **sees**:
- `rootScopeCommitment`, `finalScopeCommitment`, `chainLength`, `sessionNonce`, `auditNullifier`, `enrollmentMerkleRoot`
- The PLONK proof π

The adversary does **NOT** control:
- The Poseidon hash function (modeled as a random oracle for collision resistance arguments)
- The Baby Jubjub discrete-log problem
- The PLONK/Groth16 CRS (trusted setup or universal SRS)
- The on-chain agent Merkle tree (i.e., cannot insert leaves without going through the enrollment contract)

### Game 1: Narrowing Soundness

```
NarrowingSoundness(A, λ):
  1. A chooses a delegation chain of length N with scope values
     s_0, s_1, ..., s_N where ∃ hop k: s_k ⊄ s_{k-1}
     (i.e., some bit is set in s_k that is not set in s_{k-1})
  2. A produces (π, rootScopeCommitment, finalScopeCommitment,
     chainLength, sessionNonce, enrollmentMerkleRoot)
  3. A wins if Verify(vk, π, public_signals) = 1
```

**Claim:** Pr[A wins] ≤ negl(λ) under knowledge soundness of PLONK over BN128.

**Hop-skip sub-game (closed):** A previously viable strategy was for A to set `hopActive[k] = 0` for some `k < chainLength`, bypassing the narrowing check at hop k while reporting `chainLength > k`. This is now impossible: `hopActive[k]` is derived as `LessThan(4)(k, chainLength)`, which equals 1 for all `k < chainLength`. The prover cannot influence this derivation — it is fully determined by the public `chainLength` and the compile-time constant `k`.

### Game 2: Participant Privacy

```
ParticipantPrivacy(A, λ):
  1. Challenger picks two delegation chains C_0, C_1 of equal length N,
     with identical rootScopeCommitment, finalScopeCommitment, and
     enrollmentMerkleRoot, but different intermediate participants
     and scope values
  2. Challenger picks b ← {0, 1}, generates proof π_b for chain C_b
  3. A sees (π_b, rootScopeCommitment, finalScopeCommitment,
     chainLength, enrollmentMerkleRoot)
  4. A outputs guess b'
  5. A wins if b' = b
```

**Claim:** |Pr[b' = b] - 1/2| ≤ negl(λ) under the zero-knowledge property of PLONK.

Note: the `enrollmentMerkleRoot` is identical for both challenger chains (same public input), so it provides no distinguishing information. The privacy game is well-defined because multiple distinct chains can share the same enrollment root — the root commits to the full set of enrolled agents, not to a specific chain.

### Game 3: Chain Forgery (splice attack)

```
ChainForgery(A, λ):
  1. A produces a valid audit proof for rootScopeCommitment = sc_root
  2. But the chain does NOT start from a delegator whose
     Poseidon2(scope, credCommitment) = sc_root
  3. A wins if Verify(vk, π, public_signals) = 1
```

**Claim:** Pr[A wins] ≤ negl(λ) under Poseidon collision resistance (the adversary would need to find (scope', credComm') ≠ (scope, credComm) with Poseidon2(scope', credComm') = sc_root).

### Game 4: Phantom Delegatee (enrollment forgery)

```
PhantomDelegatee(A, λ):
  1. A produces a valid audit proof with enrollmentMerkleRoot = R
     where R is a root in the on-chain history buffer
  2. But ∃ active hop k (k < chainLength) whose delegatee credential
     commitment C_k is NOT a leaf in the Merkle tree with root R
  3. A wins if Verify(vk, π, public_signals) = 1
```

**Claim:** Pr[A wins] ≤ negl(λ) under Poseidon collision resistance (breaking the Merkle inclusion proof requires a second-preimage attack on Poseidon2).

**Prior vulnerability (now closed):** In the previous construction, intermediate hops' Merkle roots were computed but never constrained against any public value. A prover could supply a fabricated Merkle proof for any intermediate delegatee, constructing an ad-hoc root that no verifier checks. Only the terminal hop's root was surfaced as `finalDelegateeMerkleRoot`. This allowed phantom delegatees at hops 0 through N-2.

**Fix:** Constraint 8 enforces `hopActive[i] * (computedRoot[i] - enrollmentMerkleRoot) === 0` for every hop. For active hops, this pins the computed root to the public `enrollmentMerkleRoot`. The auditor cross-references this root against the on-chain root history buffer. A phantom delegatee at any active hop would require either (a) a Poseidon collision to produce a valid Merkle proof against the real root for a non-enrolled leaf, or (b) a PLONK knowledge-soundness break.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **Knowledge soundness of PLONK** (alternatively Groth16) over the BN128 pairing group in the algebraic group model + random oracle model (AGM+ROM).
2. **Poseidon collision resistance** over BN254 scalar field F_p — no efficient algorithm finds (x, y) ≠ (x', y') with Poseidon2(x, y) = Poseidon2(x', y'). Extends to Poseidon4, Poseidon5.
3. **Discrete logarithm hardness on Baby Jubjub** — given (Ax, Ay) = s·G, no efficient algorithm recovers s.
4. **EdDSA existential unforgeability** under chosen-message attack (EUF-CMA) on Baby Jubjub with Poseidon hash, reducing to DL hardness + Poseidon modeled as a random oracle.

### Reduction sketch: Narrowing Soundness

Suppose adversary A breaks NarrowingSoundness with non-negligible probability ε. By knowledge soundness of PLONK, there exists an extractor E that, given A's proof π, extracts witnesses (delegatorScope[i], delegateeScope[i], ...) for all hops with probability ≥ ε - negl(λ).

The extracted witnesses satisfy all circuit constraints. In particular, for every hop k where `k < chainLength`:

1. **hopActive[k] = 1** (enforced by `LessThan(4)(k, chainLength) = 1`, since k < chainLength). The prover cannot override this — `hopActive` is a derived signal, not a free input.

2. Given `hopActive[k] = 1`, the narrowing constraint is binding:
```
1 * delegateeBits[k][j] * (1 - delegatorBits[k][j]) === 0
    for all j ∈ [0, 64)
```

This means for every active hop, every bit set in `delegateeScope` is also set in `delegatorScope` — i.e., `delegateeScope[k] & ~delegatorScope[k] == 0`, which is the definition of `delegateeScope[k] ⊆ delegatorScope[k]`.

Therefore A's chain must satisfy monotonic narrowing at every hop in [0, chainLength), contradicting the assumption that some hop expands scope. Contradiction. ∎

### Reduction sketch: Chain Integrity

The chain-linking constraint at hop 0 enforces `Poseidon2(delegatorScope[0], delegatorCredCommitment[0]) = rootScopeCommitment`. By Poseidon collision resistance, the extracted (delegatorScope[0], delegatorCredCommitment[0]) is the unique preimage. Each subsequent hop similarly links via the scope commitment. Because `hopActive[k] = 1` for all `k < chainLength` (derived, not chosen), the chain-linking constraint `hopActive[k] * (computedDelegatorSC - prevSC) === 0` reduces to `computedDelegatorSC === prevSC` for every active hop — no gap is possible. Splicing a different chain requires a Poseidon collision. ∎

### Reduction sketch: Enrollment Integrity (Phantom Delegatee)

Suppose adversary A wins PhantomDelegatee with non-negligible probability ε. By knowledge soundness of PLONK, the extractor E recovers witness values including `delegateeCredCommitment[k]` and the Merkle proof `(siblings[k], index[k], length[k])` for the active hop k where C_k is not a leaf in the tree with root R.

The extracted witnesses satisfy constraint 8: `computedRoot[k] = enrollmentMerkleRoot = R` (since `hopActive[k] = 1`). The `BinaryMerkleRoot(MAX_DEPTH)` gadget computes `computedRoot[k]` by hashing `delegateeCredCommitment[k]` up the sibling path. If C_k is not a genuine leaf in the tree with root R, then the prover has found a sibling path that hashes a non-leaf to the correct root — this constitutes a second-preimage attack on the Poseidon2-based Merkle tree, contradicting Poseidon collision resistance. ∎

### Privacy argument

By the honest-verifier zero-knowledge property of PLONK (composable ZK in the AGM+ROM), the proof π reveals no information about private inputs beyond what is deducible from the public signals. Since intermediate scope values, credential commitments, Merkle paths, and EdDSA keys are all private inputs, the auditor learns only `rootScopeCommitment`, `finalScopeCommitment`, `chainLength`, `auditNullifier`, and `enrollmentMerkleRoot`.

The single `enrollmentMerkleRoot` reveals that all delegatees were enrolled under a specific tree state, but this is equivalent to the information already available on-chain (the root history buffer is public). It does not reveal *which* leaves (agents) participated, *when* each was enrolled relative to others, or *where* in the tree each resides — all Merkle proof paths remain private inputs.

The `hopActive` derivation does not leak additional information — `hopActive[i]` is fully determined by the public `chainLength`, which the auditor already sees. ∎

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|------------------|----------------|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Identity-Bound Scope Commitment Chain |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` | §3.2 Agent Proof Specification |
| Delegation token | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | §4.2 Delegation Circuit, constraint 6 |
| EdDSA signature | `EdDSAPoseidonVerifier` on Baby Jubjub | §2.2 Cryptographic Primitives |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 | §2.2 |
| Enrollment root binding | `computedRoot[i] === enrollmentMerkleRoot` for all active hops | §2.1 Root History Buffer (auditor cross-references) |
| Scope subset | Per-bit `delegateeBits[j] * (1 - delegatorBits[j]) === 0` | §4.2 constraint 3 |
| Cumulative encoding | Bits 4→3→2 implication chain | §4.2 constraint 4 |
| Nullifier | `Poseidon2(rootScopeCommitment, sessionNonce)` | Adapted from §3.2 agent nullifier pattern |
| Chain anchor | `rootScopeCommitment` from `HandshakeVerified` event | §3.1 step 6b |
| Hop activation | `LessThan(4)(i, chainLength)` — standard Circom comparator | circomlib `comparators.circom` |
| Proving system | PLONK with universal setup (pot17.ptau) | §2.3 OPTIONAL for Delegation circuits |

All hash functions, curves, signature schemes, and constraint patterns are drawn directly from the Bolyra spec. No new primitives are introduced — only a new composition of existing ones into a single circuit, with `hopActive` derived via a standard circomlib comparator and enrollment pinned to a single public Merkle root rather than left unconstrained.

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints | Count per hop |
|--------|------------|---------------|
| LessThan(4) hop activation | 12 | 1 |
| Num2Bits(64) range checks (×4) | 256 | 4 fields |
| Poseidon2 (delegator scope commitment) | 300 | 1 |
| Poseidon2 (new scope commitment) | 300 | 1 |
| Poseidon4 (delegation token) | 450 | 1 |
| Poseidon2 (audit nullifier, hop 0 only) | 300 | 0-1 |
| EdDSAPoseidonVerifier | 6,000 | 1 |
| BinaryMerkleRoot(20) | 6,200 | 1 |
| Enrollment root equality check | 2 | 1 |
| Scope subset (64 AND gates) | 64 | 1 |
| Cumulative bit encoding | 3 | 1 |
| LessEqThan(64) expiry | 200 | 1 |
| hopActive mux + chain propagation | 80 | 1 |
| **Subtotal per hop** | **~13,867** | |

### Global constraints (once)

| Gadget | Constraints |
|--------|------------|
| Num2Bits(4) on chainLength | 4 |
| LessEqThan(4) chainLength ≤ MAX_HOPS | 12 |
| LessEqThan(4) 1 ≤ chainLength | 12 |
| **Global subtotal** | **~28** |

### Total circuit size

| Chain length | Constraints | SRS required | Proving time (rapidsnark) | Proving time (snarkjs) |
|-------------|-------------|-------------|--------------------------|----------------------|
| 4 hops | ~55,500 | pot16.ptau | ~3s | ~25s |
| 8 hops | ~111,170 | pot17.ptau | ~6s | ~50s |

The enrollment root binding adds 2 constraints per active hop (16 total for 8 hops). The removal of the `finalDelegateeMerkleRoot` output selection mux saves approximately 20 constraints. Net change: **~0 constraints** — the circuit size is effectively unchanged from the prior construction.

PLONK proof size: ~800 bytes (constant regardless of circuit size).
Groth16 proof size: 128 bytes (if Groth16 preferred for on-chain gas efficiency).

The 8-hop configuration at ~111K constraints fits within pot17.ptau (2^17 = 131,072 constraints). For deployments that want to stay within the existing pot16.ptau (2^16 = 65,536), a 4-hop maximum is viable.

## 7. Concrete deployment scenario

### Scenario: Multi-agent loan origination pipeline at Navy Federal Credit Union

**Context:** Navy Federal Credit Union (NFCU, $170B assets, 13M members) deploys an AI-assisted loan origination pipeline. A member initiates a home equity loan application through a conversational AI agent. The pipeline involves:

1. **Agent A** (member-facing chatbot): `READ_DATA | WRITE_DATA | ACCESS_PII` (bits 0,1,7 → bitmask `0b10000011 = 0x83`)
2. **Agent B** (credit decisioning model): `READ_DATA | FINANCIAL_SMALL | FINANCIAL_MEDIUM` (bits 0,2,3 → bitmask `0b00001101 = 0x0D`). Delegated from A with PII stripped — bit 7 removed.
3. **Agent C** (document generation): `READ_DATA | WRITE_DATA` (bits 0,1 → bitmask `0b00000011 = 0x03`). Delegated from B with financial permissions stripped.
4. **Agent D** (e-signature orchestrator): `READ_DATA` (bit 0 → bitmask `0b00000001 = 0x01`). Delegated from C with write stripped.

**Audit trigger:** The NCUA examiner conducting a safety-and-soundness exam requires proof that the AI pipeline's delegation chain was properly scoped — no agent exceeded its mandate. Under current NCUA guidelines, the CU must demonstrate adequate controls over third-party/fintech relationships (NCUA Letter 23-CU-15).

**What the examiner sees** (public signals only):
- `rootScopeCommitment`: opaque hash (verifiable against handshake event)
- `finalScopeCommitment`: opaque hash
- `chainLength = 4`
- `auditNullifier`: replay-prevention token
- `enrollmentMerkleRoot`: verifiable against on-chain agent registry root history buffer — confirms all four agents were legitimately enrolled

**What the examiner does NOT see:**
- Which specific AI models were used (no `modelHash` revealed)
- Which operator signed each credential (no public keys revealed)
- The actual permission bitmasks at any hop (no scope values revealed)
- The Merkle tree positions of any agent (no enrollment indices revealed)

**What the examiner can verify:**
- The chain started from a valid mutual handshake (cross-reference `rootScopeCommitment` with on-chain `HandshakeVerified` event)
- Every hop narrowed permissions monotonically (circuit soundness)
- No intermediate hop was skipped (`hopActive` derived from public `chainLength`, not prover-chosen)
- **Every delegatee in the chain was a legitimately enrolled agent** (all intermediate Merkle roots constrained to equal the public `enrollmentMerkleRoot`, which the examiner cross-references against the on-chain root history buffer)
- The proof has not been replayed (audit nullifier uniqueness)

**Verification cost:** A single PLONK `verify()` call on-chain (~300K gas on Base) or off-chain (< 10ms in snarkjs).

### Scenario 2: Journalist/source whistleblower chain

A source inside a financial institution uses a chain of AI agents to relay redacted evidence to an investigative journalist. Each hop strips identifying metadata:

1. **Source agent**: full access to internal documents
2. **Redaction agent**: strips PII, retains financial data
3. **Relay agent**: strips financial specifics, retains summary
4. **Journalist-facing agent**: read-only summary access

The journalist publishes the audit proof alongside the story. Any reader can verify that the delegation chain narrowed monotonically (the source's agent had broader access than the journalist's agent), that all four hops were enforced (no gap in the chain), and that every agent in the chain was a legitimately enrolled entity in the Bolyra registry, without learning the source's identity, the intermediate agents' identities, or what specific permissions were held at any hop. The `enrollmentMerkleRoot` confirms all agents were real enrolled entities — not phantom identities fabricated by the prover — while revealing nothing about which specific agents participated.

## 8. Why the baseline cannot match

| Capability | DelegationAuditChain | RFC 8693 + BBS+ + WIMSE |
|-----------|---------------------|------------------------|
| **Prove narrowing over hidden scopes** | Circuit enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` per hop, over private inputs. Auditor sees only the proof. | BBS+ can hide individual claims but cannot prove an ordering/subset relationship over hidden bitmasks. The AS can assert narrowing, but the auditor must trust the AS or see the scopes. |
| **No hop-skipping** | `hopActive[i]` is derived in-circuit as `LessThan(4)(i, chainLength)`. The prover cannot deactivate an intermediate hop — every hop below `chainLength` is unconditionally enforced. | RFC 8693 chain integrity depends on the AS refusing to skip steps. A compromised or misconfigured AS can issue tokens that skip intermediate narrowing stages. No cryptographic enforcement that every hop was evaluated. |
| **Enrollment integrity at every hop** | Every active hop's computed Merkle root is constrained to equal the public `enrollmentMerkleRoot`. No intermediate delegatee can be a phantom — all must be leaves in the real agent tree. The auditor verifies this root against the on-chain registry. | WIMSE provides per-hop workload attestation, but attestation is trust-based (SPIFFE trust bundles). A compromised SPIFFE server can issue SVIDs for non-existent workloads. No cryptographic proof that every intermediate participant is a registered entity in a specific registry. |
| **Hide intermediate participants** | All credential commitments, public keys, and Merkle paths are private inputs. Zero-knowledge property guarantees no leakage. The single `enrollmentMerkleRoot` reveals the tree state but not which leaves participated. | RFC 8693 `act` claim tree is plaintext. BBS+ operates within a single credential, not across a multi-issuer chain. No mechanism to hide who delegated to whom. |
| **No trusted third party** | Proof is self-contained. Verification requires only the PLONK verification key (public) and public signals. No AS needed. | RFC 8693 narrowing is enforced by the AS at issuance time. Auditor assurance requires AS trust or AS policy logs. AS compromise breaks the guarantee. |
| **Cross-org chain audit** | The circuit is organization-agnostic. Any enrolled agent (in the shared Merkle tree) can participate. No shared AS or federation anchor needed. | Cross-org delegation requires a shared AS or WIMSE federation trust anchor. No single standard produces a unified narrowing proof across trust domains. |
| **Whistleblower/source anonymity** | Intermediate identities are private inputs. Even the number of distinct organizations is hidden (only `chainLength` is revealed). | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-vs-RS correlation but not auditor correlation via the `act` chain. No mechanism for anonymous participation. |
| **Runtime enforcement** | Narrowing is enforced cryptographically at proof-generation time. A proof for a non-narrowing chain — or one with skipped hops or phantom delegatees — cannot be generated (circuit unsatisfiable). | AS enforces narrowing at issuance. After issuance, the token exists independently — no runtime check that the token is used within its narrowed scope unless the RS independently validates. |
| **Offline verifiability** | PLONK proof is verifiable by anyone with the verification key. No network call, no AS query, no introspection endpoint. | RFC 7662 introspection requires the AS to be online. Signed introspection responses (draft-ietf-oauth-jwt-introspection-response) help but still require AS signing key trust. |

The fundamental gap is structural: the baseline's narrowing assurance flows through a trusted intermediary (the Authorization Server) that sees all scopes in cleartext. Removing the AS removes the assurance. The `DelegationAuditChain` circuit replaces AS trust with mathematical proof — narrowing is verified by constraint satisfaction, not by institutional trust — and does so over encrypted (private) inputs that the auditor never sees. The enrollment root binding ensures this mathematical guarantee extends to participant legitimacy: every agent in the chain is provably enrolled in the on-chain registry, not just the terminal one, closing the phantom delegatee attack that the prior construction left open.
