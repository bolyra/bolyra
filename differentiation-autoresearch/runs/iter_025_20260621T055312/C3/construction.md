# Construction

## 1. Statement of claim

An auditor receives a single zero-knowledge proof certifying that a multi-hop delegation chain narrowed permissions monotonically at every step, without learning any intermediate scope values, participant identities, or chain structure beyond the total hop count. The construction works across organizational boundaries without a shared authorization server and supports whistleblower-safe agent pipelines where intermediate nodes stay hidden from the auditor.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `ChainAuditProof(MAX_HOPS, MAX_DEPTH)`

Parameters: `MAX_HOPS = 8`, `MAX_DEPTH = 20` (matching Bolyra Merkle tree depth).

**Private inputs** (per hop `h` in `[0, MAX_HOPS)`):

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScope[h]` | uint64 | Delegator permission bitmask at hop h |
| `delegateeScope[h]` | uint64 | Delegatee permission bitmask at hop h |
| `delegatorExpiry[h]` | uint64 | Delegator expiry timestamp |
| `delegateeExpiry[h]` | uint64 | Delegatee expiry timestamp |
| `delegatorCredCommitment[h]` | field | Delegator's Poseidon5 credential commitment |
| `delegateeCredCommitment[h]` | field | Delegatee's Poseidon5 credential commitment |
| `delegatorPubkeyAx[h]`, `delegatorPubkeyAy[h]` | field | Delegator EdDSA public key |
| `sigR8x[h]`, `sigR8y[h]`, `sigS[h]` | field | Delegator EdDSA signature on delegation token |
| `delegateeMerkleProofLength[h]` | uint8 | Actual depth of delegatee Merkle proof |
| `delegateeMerkleProofIndex[h]` | uint32 | Leaf index |
| `delegateeMerkleProofSiblings[h][MAX_DEPTH]` | field[] | Sibling hashes |
| `active[h]` | bit | 1 if hop h is real, 0 if padding |

**Global private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rootScope` | uint64 | Original delegator's scope at chain root |
| `rootCredCommitment` | field | Root delegator's credential commitment |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `initialScopeCommitment` | field | Scope commitment from handshake (on-chain, from `lastScopeCommitment[sessionNonce]`) |
| `sessionNonce` | field | Original session nonce from the handshake that seeded this chain |
| `auditNonce` | field | Fresh auditor-chosen nonce binding this audit proof |
| `currentTimestamp` | uint64 | Auditor-supplied current time |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `finalScopeCommitment` | field | Terminal scope commitment of chain |
| `chainLength` | uint8 | Number of active hops |
| `auditDigest` | field | `Poseidon4(initialScopeCommitment, finalScopeCommitment, chainLength, auditNonce)` |
| `allDelegateesMerkleRoot` | field | Agent tree root (uniform across hops) |
| `delegationNullifier[MAX_HOPS]` | field[] | Per-hop delegation nullifiers (0 for inactive hops); checked against on-chain nullifier registry |

### Constraint logic

```
// 1. Root chain anchor
assert Poseidon2(rootScope, rootCredCommitment) === initialScopeCommitment

// 2. Track running scope commitment
var runningScopeCommitment = initialScopeCommitment
var runningChainLength = 0

for h in [0, MAX_HOPS):
    if active[h] === 1:
        // 2a. Range checks
        Num2Bits(64) on delegatorScope[h], delegateeScope[h],
                        delegatorExpiry[h], delegateeExpiry[h]

        // 2b. Chain linking: delegator at this hop matches running state
        assert Poseidon2(delegatorScope[h], delegatorCredCommitment[h])
               === runningScopeCommitment

        // 2c. Monotonic scope narrowing (bitwise subset)
        delegateeBits = Num2Bits(64)(delegateeScope[h])
        delegatorBits = Num2Bits(64)(delegatorScope[h])
        for i in [0, 64):
            assert delegateeBits[i] * (1 - delegatorBits[i]) === 0

        // 2d. Cumulative bit encoding on delegatee
        assert delegateeBits[4] * (1 - delegateeBits[3]) === 0
        assert delegateeBits[4] * (1 - delegateeBits[2]) === 0
        assert delegateeBits[3] * (1 - delegateeBits[2]) === 0

        // 2e. Expiry narrowing
        LessEqThan(64)(delegateeExpiry[h], delegatorExpiry[h])

        // 2f. Expiry liveness (not already expired)
        LessThan(64)(currentTimestamp, delegateeExpiry[h])

        // 2g. Delegation token + EdDSA signature verification
        delegationToken = Poseidon4(runningScopeCommitment,
                                     delegateeCredCommitment[h],
                                     delegateeScope[h],
                                     delegateeExpiry[h])
        EdDSAPoseidonVerifier(
            delegatorPubkeyAx[h], delegatorPubkeyAy[h],
            sigR8x[h], sigR8y[h], sigS[h],
            delegationToken
        )

        // 2h. Delegatee enrollment in agent Merkle tree
        computedRoot = BinaryMerkleRoot(MAX_DEPTH)(
            delegateeCredCommitment[h],
            delegateeMerkleProofLength[h],
            delegateeMerkleProofIndex[h],
            delegateeMerkleProofSiblings[h]
        )
        assert computedRoot === allDelegateesMerkleRoot

        // 2i. Per-hop delegation nullifier (recomputed, bound to sessionNonce)
        delegationNullifier[h] <== Poseidon2(delegationToken, sessionNonce)

        // 2j. Advance running state
        runningScopeCommitment = Poseidon2(delegateeScope[h],
                                            delegateeCredCommitment[h])
        runningChainLength += 1

    else:
        // Inactive hop: nullifier output forced to 0
        delegationNullifier[h] <== 0

// 3. Bind outputs
finalScopeCommitment <== runningScopeCommitment
chainLength <== runningChainLength
auditDigest <== Poseidon4(initialScopeCommitment, finalScopeCommitment,
                           chainLength, auditNonce)
```

### Gadget inventory

| Gadget | Source | Invocations |
|--------|--------|-------------|
| `Poseidon2` | circomlib | 3 × MAX_HOPS + 2 (chain link + new scope + nullifier per hop, plus root anchor + one in auditDigest via Poseidon4) |
| `Poseidon4` | circomlib | MAX_HOPS + 1 |
| `Num2Bits(64)` | circomlib | 4 × MAX_HOPS |
| `EdDSAPoseidonVerifier` | circomlib | MAX_HOPS |
| `BinaryMerkleRoot(20)` | @zk-kit | MAX_HOPS |
| `LessThan(64)` / `LessEqThan(64)` | circomlib | 2 × MAX_HOPS |

### Auditor verification procedure (on-chain / off-chain)

After receiving the PLONK proof and public signals, the auditor (or auditor's verifier contract) MUST perform the following checks beyond PLONK verification:

1. **`initialScopeCommitment`** matches `lastScopeCommitment[sessionNonce]` in the on-chain registry.
2. **`allDelegateesMerkleRoot`** is present in the agent root history buffer.
3. **For each `h` in `[0, chainLength)`**: `delegationNullifier[h]` exists in the on-chain delegation nullifier registry (recorded when each `Delegation` circuit proof was originally verified). Nullifiers for `h ≥ chainLength` MUST equal 0.
4. **No duplicate nullifiers** among the active entries (prevents a single hop from being counted twice).

Step 3 is the GAME-FAITHFUL check: it binds the audit proof to delegation events that actually occurred on-chain, preventing shadow-chain forgery.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` is a computationally bounded (PPT) entity that controls:

- Up to `MAX_HOPS - 1` colluding agents in the delegation chain
- The auditor (the auditor is untrusted for privacy)
- Network traffic between all parties

The adversary does NOT control:

- The BN128 discrete log problem
- The Poseidon hash function (modeled as a random oracle for collision resistance arguments)
- The Groth16/PLONK proving system (knowledge soundness holds)
- The on-chain delegation nullifier registry (append-only, written only by the verified `Delegation` circuit execution path in the registry contract)

### Game 1: Narrowing soundness (`GAME-NARROW`)

```
Setup: Challenger generates Bolyra CRS (pk, vk).

Phase 1: A chooses arbitrary delegation chain data and produces
         a proof π for ChainAuditProof.

Win condition: A wins if:
  (a) Verify(vk, π, pubInputs) = 1, AND
  (b) there exists some hop h where delegateeScope[h] ⊄ delegatorScope[h]
      (i.e., some delegatee bit is set that the delegator's bit is not)

Claim: Pr[A wins] ≤ negl(λ) under knowledge soundness of Groth16.
```

### Game 2: Participant privacy (`GAME-HIDE`)

**Corrected formulation.** The prior version stated an indistinguishability game requiring two chains with different participants but identical nullifier vectors. This is self-contradictory: since `delegationNullifier[h] = Poseidon2(Poseidon4(prevScopeCommitment, delegateeCredCommitment[h], delegateeScope[h], delegateeExpiry[h]), sessionNonce)`, different `delegateeCredCommitment` values necessarily produce different nullifiers under CR-Poseidon. The challenge space was vacuous.

The correct privacy guarantee is a **preimage resistance game** — the nullifiers are opaque tags that the auditor cannot invert:

```
Setup: Challenger generates CRS. Challenger executes a legitimate
       delegation chain of length n, producing a ChainAuditProof π
       with public output vector (finalScopeCommitment, chainLength,
       auditDigest, allDelegateesMerkleRoot, delegationNullifier[0..n-1]).

       Challenger additionally gives A:
       - The on-chain delegation nullifier registry N (containing the
         n nullifiers plus nullifiers from other unrelated delegations)
       - The on-chain agent Merkle tree (all enrolled credential commitments)
       - All public inputs (initialScopeCommitment, sessionNonce,
         auditNonce, currentTimestamp)

Phase 1: A may adaptively query an oracle that produces additional
         ChainAuditProof proofs for chains of A's choosing (chosen-
         proof attack — models an auditor who can request audit proofs
         for other chains to attempt cross-correlation).

Win condition: A outputs a tuple (h*, identity*) where:
  - h* ∈ [0, n) is a hop index, AND
  - identity* = (modelHash, operatorPubkeyAx, operatorPubkeyAy,
                 permissionBitmask, expiryTimestamp) is the claimed
                 credential fields of the delegatee at hop h*

A wins if identity* matches the actual delegatee at hop h*.

Claim: Pr[A wins] ≤ 1/|S| + negl(λ) where |S| is the number of
       enrolled agents in the Merkle tree (the anonymity set), under
       ZK-Groth16/PLONK + PI-Poseidon (preimage resistance).
```

**Precision on what GAME-HIDE captures**: The auditor learns the nullifier vector — these are deterministic, unique identifiers for specific delegation events. Under PI-Poseidon (Poseidon preimage resistance), the nullifier `Poseidon2(delegationToken, sessionNonce)` reveals nothing about `delegationToken`'s structure, and therefore nothing about `delegateeCredCommitment`, `delegateeScope`, or any other private field composing the token. The auditor also sees these nullifiers in the on-chain registry, but the on-chain record of a delegation event (written by the original `Delegation` circuit proof) consists only of the nullifier, `newScopeCommitment`, and `delegateeMerkleRoot` — all of which are Poseidon commitments hiding participant identity.

**Information-theoretic decomposition of what the auditor learns:**

| Public output | What it reveals | What it hides |
|---|---|---|
| `chainLength` | Number of hops | Nothing beyond this count |
| `finalScopeCommitment` | Poseidon2(terminal scope, terminal cred commitment) | Both inputs (PI-Poseidon) |
| `delegationNullifier[h]` | That delegation event h occurred on-chain | Participant identity, scope values, expiry (PI-Poseidon) |
| `allDelegateesMerkleRoot` | Which agent tree snapshot was used | Which specific leaves participated |
| `auditDigest` | Binding of all above to `auditNonce` | No additional information |

**Cross-nullifier correlation**: An auditor who observes nullifiers from multiple audit proofs can determine whether two proofs share a hop (same nullifier appears in both output vectors). This is inherent and intentional — it prevents the same delegation from being counted toward compliance in two different audit contexts. It does NOT reveal participant identity; it reveals only that "the same delegation event" appears in both chains. The anonymity set for participant identity remains the full set of enrolled agents.

**Why indistinguishability fails and preimage resistance suffices**: An IND-style game would require two chains producing identical public outputs but differing in private inputs. Since nullifiers are deterministic functions of delegation tokens (which incorporate participant identity), any two chains with different participants necessarily have different public output vectors. This is not a privacy failure — it is the necessary consequence of GAME-FAITHFUL's requirement that each hop be uniquely identifiable for registry lookup. The privacy guarantee is that the unique identifier (nullifier) is *opaque*: it serves as a lookup key without revealing the record's contents. This is analogous to a database primary key that enables joins without exposing row data — the key's existence is public; its semantic content is hidden behind Poseidon preimage resistance.

### Game 3: Chain forgery (`GAME-FORGE`)

```
Setup: Challenger enrolls agents, creates a legitimate chain anchored
       at on-chain initialScopeCommitment.

Phase 1: A may observe proofs from legitimate delegations.

Win condition: A produces a valid proof π where the initialScopeCommitment
  does not correspond to any on-chain handshake seed, OR the chain
  includes a delegatee whose credentialCommitment is not in the agent
  Merkle tree.

Claim: Pr[A wins] ≤ negl(λ) under Poseidon collision resistance +
       Groth16 knowledge soundness.
```

### Game 4: Shadow-chain prevention (`GAME-FAITHFUL`)

```
Setup: Challenger generates CRS. The on-chain delegation nullifier
       registry N contains exactly the nullifiers recorded from
       legitimate Delegation circuit executions.

Phase 1: A may observe legitimate delegation proofs, audit proofs,
         and on-chain state. A may create legitimate delegations
         (enrolling agents, executing Delegation circuit proofs).

Win condition: A produces a valid ChainAuditProof π such that:
  (a) Verify(vk, π, pubInputs) = 1, AND
  (b) there exists some active hop h (h < chainLength) where
      delegationNullifier[h] ∉ N
      (i.e., at least one hop in the audit proof was never
       actually executed as an on-chain delegation)

Claim: Pr[A wins] ≤ negl(λ) under CR-Poseidon + KS-Groth16 +
       integrity of the on-chain nullifier registry.
```

The game captures "shadow-chain forgery": an adversary fabricates a valid-looking audit proof over a delegation chain that never actually happened on-chain. Without GAME-FAITHFUL, an adversary could construct a syntactically valid witness (satisfying narrowing, EdDSA signatures, Merkle proofs) for a chain that was never executed through the registry — the circuit would accept, but the chain would be a fiction. GAME-FAITHFUL closes this gap by requiring each hop's nullifier to exist in the on-chain registry, binding the audit proof to real delegation events.

### Tension between GAME-HIDE and GAME-FAITHFUL (resolved)

GAME-FAITHFUL requires delegation nullifiers to be public outputs (for registry lookup). GAME-HIDE requires participant identities to remain hidden. These are NOT in conflict because the nullifier is a one-way commitment to the delegation event:

- **GAME-FAITHFUL path**: nullifier is public → auditor looks it up in the registry → confirms hop occurred. ✓
- **GAME-HIDE path**: nullifier = Poseidon2(delegationToken, sessionNonce) → under PI-Poseidon, auditor cannot recover delegationToken → cannot recover delegateeCredCommitment → cannot identify participant. ✓

The design achieves both by exploiting the asymmetry between *existence verification* (checking membership in a set, which requires only the element) and *content extraction* (recovering the preimage, which requires breaking Poseidon). The on-chain registry stores nullifiers as opaque keys; the audit proof demonstrates their presence; neither operation reveals the underlying delegation parameters.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **DL-BJJ**: Discrete logarithm hardness on Baby Jubjub (secures EdDSA signatures on delegation tokens).
2. **CR-Poseidon**: Collision resistance of Poseidon over BN128 scalar field (secures scope commitments, chain linking, credential commitments, delegation nullifier uniqueness).
3. **PI-Poseidon**: Preimage resistance of Poseidon over BN128 scalar field (secures participant privacy — nullifiers do not reveal their inputs). Note: CR-Poseidon implies PI-Poseidon in the standard model, but we name it separately for clarity in the GAME-HIDE reduction.
4. **KS-Groth16**: Knowledge soundness of Groth16 under the q-PKE assumption in the algebraic group model (secures extraction of valid witness from any accepting proof).
5. **ZK-Groth16**: Perfect zero-knowledge of Groth16 (secures witness hiding — proof transcript reveals nothing about private inputs beyond what public outputs determine).
6. **ROM**: Random oracle model for Fiat-Shamir in PLONK (if PLONK variant is used).
7. **REG-INTEGRITY**: The on-chain delegation nullifier registry is append-only and accepts writes only from the verified `Delegation` circuit execution path in the registry contract (smart contract correctness assumption, not a cryptographic assumption).

### Reduction sketch for GAME-NARROW

Suppose adversary `A` wins GAME-NARROW with non-negligible probability `ε`. By KS-Groth16, the knowledge extractor `E` extracts a valid witness `w` from `A`'s proof with probability ≥ `ε - negl(λ)`. The witness contains `delegatorScope[h]` and `delegateeScope[h]` for each active hop. The circuit enforces `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for all `i` — meaning every bit set in `delegateeScope` must also be set in `delegatorScope`. If the extracted witness violates this, it fails the circuit constraints, contradicting the proof's validity. Therefore `A` cannot win except with negligible probability.

### Reduction sketch for GAME-HIDE

Suppose adversary `A` wins GAME-HIDE with probability `> 1/|S| + negl(λ)` — i.e., `A` identifies the delegatee at some hop `h*` better than random guessing over the anonymity set `S` of enrolled agents.

`A`'s view consists of: (1) the proof π, and (2) the public output vector including `delegationNullifier[h*]`.

**From (1)**: By ZK-Groth16 (or ZK-PLONK under ROM), the proof π is a simulation independent of the witness. It reveals zero bits about `delegateeCredCommitment[h*]`, `delegateeScope[h*]`, or any other private input. Therefore π contributes no advantage.

**From (2)**: `delegationNullifier[h*] = Poseidon2(delegationToken_h*, sessionNonce)` where `delegationToken_h* = Poseidon4(prevScopeCommitment_h*, delegateeCredCommitment[h*], delegateeScope[h*], delegateeExpiry[h*])`. To extract `delegateeCredCommitment[h*]` from the nullifier, `A` must:

- First invert `Poseidon2` to recover `delegationToken_h*` from `(nullifier, sessionNonce)` — this requires breaking PI-Poseidon (even knowing `sessionNonce`, the second preimage is a Poseidon4 output uniformly distributed over the field, so the pair (delegationToken, sessionNonce) is not trivially invertible; the adversary must find which field element `x` satisfies `Poseidon2(x, sessionNonce) = nullifier`, which is a preimage query on Poseidon2's first input).
- Then invert `Poseidon4` to recover `delegateeCredCommitment[h*]` from the token — a second preimage inversion.

Under PI-Poseidon, each inversion succeeds with at most negligible probability. Therefore:

```
Pr[A wins] ≤ 1/|S| + Adv^PI-Poseidon(A) ≤ 1/|S| + negl(λ)
```

**Remark on the `sessionNonce`-known setting**: The auditor knows `sessionNonce` (it is a public input). This means the Poseidon2 inversion is a *partial* preimage problem: given `(y, x₂)`, find `x₁` such that `Poseidon2(x₁, x₂) = y`. Under the standard algebraic analysis of Poseidon (full-round security margin with α=5 S-boxes over BN128), partial preimage resistance holds at the same security level as full preimage resistance — the known input does not reduce the algebraic degree of the system below the security margin. This is a well-studied property of algebraic hashes designed for ZK contexts.

### Reduction sketch for GAME-FORGE

Suppose `A` produces a proof anchored at a scope commitment `sc*` not on-chain. The circuit enforces `Poseidon2(rootScope, rootCredCommitment) === initialScopeCommitment`. By KS-Groth16, the extractor recovers `(rootScope, rootCredCommitment)` such that their Poseidon2 hash equals `sc*`. If `sc*` was never stored on-chain, then either: (a) `A` found a Poseidon collision mapping different inputs to a legitimate on-chain commitment — contradicting CR-Poseidon, or (b) the verifier rejects because `initialScopeCommitment` is a public input checked against on-chain state. Similarly, a phantom delegatee requires a Merkle proof against `allDelegateesMerkleRoot`, which the verifier checks against the on-chain agent root history buffer.

### Reduction sketch for GAME-FAITHFUL

Suppose adversary `A` wins GAME-FAITHFUL with non-negligible probability `ε` — i.e., `A` produces a valid `ChainAuditProof` where some active hop `h` has `delegationNullifier[h] ∉ N` (the on-chain nullifier registry).

By KS-Groth16 (or KS-PLONK under ROM), the knowledge extractor `E` extracts a valid witness `w` with probability ≥ `ε - negl(λ)`. From `w`, the extractor recovers for hop `h`:

- `delegationToken_h = Poseidon4(runningScopeCommitment_h, delegateeCredCommitment[h], delegateeScope[h], delegateeExpiry[h])`
- `delegationNullifier[h] = Poseidon2(delegationToken_h, sessionNonce)`

The circuit constrains this computation, so the extracted nullifier is deterministic given the extracted witness and the public `sessionNonce`.

Now, `delegationNullifier[h] ∉ N` means that no legitimate `Delegation` circuit execution ever produced this nullifier. A legitimate execution computes `nullifier = Poseidon2(token, sessionNonce)` with the same `sessionNonce` (a public input shared between the original delegation and the audit proof). Two cases:

**(a)** The extracted `delegationToken_h` was never the output of a legitimate delegation. Then `A` has constructed a valid EdDSA signature (verified by constraint 2g) on a delegation token that was never signed by the delegator. By DL-BJJ, forging an EdDSA signature on a new message is hard. Unless `A` controls the delegator's private key — but by the game setup, `A` controls at most `MAX_HOPS - 1` agents, so at least one delegator is honest. If `A` controls the delegator for hop `h`, the delegation could be legitimate but unrecorded — however, under REG-INTEGRITY, every verified `Delegation` proof writes its nullifier to `N`, so a delegation that passed on-chain verification MUST have its nullifier in `N`. A delegation that never went through on-chain verification was never a legitimate delegation.

**(b)** The extracted `delegationToken_h` matches a legitimate delegation's token, but hashing with `sessionNonce` yields a different nullifier. This requires `Poseidon2(token, sessionNonce) ≠ Poseidon2(token, sessionNonce)` — a contradiction since Poseidon is deterministic. Alternatively, if `sessionNonce` differs between the audit proof and the original delegation, the nullifiers diverge by design: the audit proof's `sessionNonce` is a public input that the auditor verifies matches the on-chain handshake session. A mismatched `sessionNonce` means the audit proof claims to cover a session it does not — caught by the auditor's check of `initialScopeCommitment` against `lastScopeCommitment[sessionNonce]`.

Therefore `Pr[A wins] ≤ negl(λ)`.

**Relationship between GAME-FORGE and GAME-FAITHFUL**: GAME-FORGE prevents fabrication of the chain's *anchor* (fake `initialScopeCommitment`). GAME-FAITHFUL prevents fabrication of the chain's *body* (individual hops that were never executed on-chain). Together they ensure the audit proof is faithful end-to-end: the anchor is real and every hop is real.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Composable Delegation |
| Chain linking | `previousScopeCommitment` public input → circuit re-derives from private delegator scope + cred | §4.2 Delegation Circuit, constraint 2 |
| Scope narrowing | Bitwise subset check: `delegateeBits[i] * (1 - delegatorBits[i]) === 0` | §4.2 constraint 3 |
| Cumulative bit encoding | Bits 4→3→2 implication constraints | §4.2 constraint 4 |
| Delegation token | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | §4.2 constraint 6 |
| EdDSA authorization | `EdDSAPoseidonVerifier` on Baby Jubjub | §4.2 constraint 7 |
| Delegatee enrollment | `BinaryMerkleRoot(MAX_DEPTH)` against agent tree | §4.2 constraint 8 |
| Expiry narrowing | `LessEqThan(64)` | §4.2 constraint 5 |
| Delegation nullifier | `Poseidon2(delegationTokenHash, sessionNonce)` — per-hop, public output | §4.2 delegationNullifier output |
| Chain anchor | `lastScopeCommitment[sessionNonce]` on-chain mapping | §4.1 chain seed |
| Audit binding | `Poseidon4(initial, final, length, auditNonce)` | New: binds audit artifact to session |
| Nullifier registry check | Auditor verifies each `delegationNullifier[h]` exists on-chain | New: GAME-FAITHFUL binding |

The `ChainAuditProof` circuit composes exactly the same per-hop constraints as the existing `Delegation` circuit (§4.2) but executes them iteratively over `MAX_HOPS` slots within a single circuit, producing a single proof that covers the entire chain. The per-hop delegation nullifiers are recomputed inside the circuit using the same formula as the original `Delegation` circuit (`Poseidon2(delegationToken, sessionNonce)`) and surfaced as public outputs, enabling the auditor to cross-reference each hop against the on-chain nullifier registry without learning anything about the hop's participants or permissions.

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints per instance | Instances per hop | Subtotal |
|--------|------------------------|-------------------|----------|
| `EdDSAPoseidonVerifier` | ~10,000 | 1 | 10,000 |
| `BinaryMerkleRoot(20)` | ~5,000 | 1 | 5,000 |
| `Poseidon2` | ~300 | 3 (chain link + new scope + nullifier) | 900 |
| `Poseidon4` | ~600 | 1 (delegation token) | 600 |
| `Num2Bits(64)` | ~64 | 4 (scopes + expiries) | 256 |
| Bitwise subset (64 muls) | ~64 | 1 | 64 |
| Cumulative encoding | ~3 | 1 | 3 |
| `LessEqThan(64)` + `LessThan(64)` | ~200 | 2 | 400 |
| Conditional mux (active flag) | ~500 | 1 | 500 |
| **Per-hop total** | | | **~17,723** |

### Full circuit

| Configuration | Hops | Total constraints | Public outputs | Proving system | Proving time target |
|--------------|------|-------------------|----------------|----------------|-------------------|
| Standard (8 hops) | 8 | ~141,800 | 4 + 8 nullifiers = 12 | PLONK (universal setup) | < 5s (agent-class) |
| Compact (4 hops) | 4 | ~70,900 | 4 + 4 nullifiers = 8 | PLONK | < 3s |
| Extended (16 hops) | 16 | ~283,600 | 4 + 16 nullifiers = 20 | PLONK | < 12s |

All configurations fit within `pot16.ptau` (2^16 = 65,536 for 4-hop; 2^18 for 8-hop; 2^19 for 16-hop). The 8-hop standard configuration requires a `pot18.ptau` ceremony or universal PLONK SRS of matching size.

**Constraint delta from prior version**: +300 constraints per hop (one additional `Poseidon2` for nullifier recomputation) and +MAX_HOPS public output signals. Negligible impact on proving time (~1.7% increase for 8-hop configuration).

**Proving system choice**: PLONK with universal setup. The audit proof is an agent-class circuit (no human secret involved), and PLONK avoids a per-circuit trusted setup ceremony. The auditor verifies against a PLONK verifier contract at a distinct address from the Groth16 human verifier, per spec §2.3.

**Verification**: PLONK on-chain verification ~300K gas (single pairing check + polynomial evaluation). The additional public outputs (8 nullifier field elements) increase calldata cost by ~2K gas (256 bytes) but do not affect the pairing computation.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), the largest US credit union with 13M+ members, subject to NCUA examination and GENIUS Act compliance for stablecoin operations.

**Pipeline**: A member initiates a stablecoin transfer via an AI assistant. The pipeline traverses 4 hops:

1. **Root agent** (member-facing chatbot, `FINANCIAL_MEDIUM | READ_DATA | WRITE_DATA` = bits 0,1,3) receives the request.
2. **KYC tool agent** (delegated `READ_DATA | ACCESS_PII` = bits 0,7) to verify member identity — scope narrowed from root (lost financial bits, gained PII bit only if root had it; in practice root carries bit 7 too, delegation narrows to just 0+7).
3. **Compliance agent** (delegated `READ_DATA | FINANCIAL_SMALL` = bits 0,2) to check sanctions screening — further narrowed.
4. **Settlement agent** (delegated `FINANCIAL_SMALL` = bit 2 only) to execute the on-chain transfer — maximally narrowed.

**Audit trigger**: NCUA examiner requests proof that the stablecoin transfer pipeline respected least-privilege at every hop.

**What the auditor receives**:
- A single PLONK proof (`ChainAuditProof` with 4 active hops)
- Public signals: `initialScopeCommitment` (verifiable against on-chain handshake record), `finalScopeCommitment` (matches settlement agent's scope commitment on-chain), `chainLength = 4`, `auditDigest`, `allDelegateesMerkleRoot` (verifiable against on-chain agent root history), `delegationNullifier[0..3]` (4 non-zero nullifiers, verifiable against on-chain delegation nullifier registry), `delegationNullifier[4..7] = 0` (inactive padding)

**Auditor verification steps** (GAME-FAITHFUL check):
1. Confirm `initialScopeCommitment` matches `lastScopeCommitment[sessionNonce]` on-chain.
2. Confirm `allDelegateesMerkleRoot` is in the agent root history buffer.
3. For each `h ∈ {0,1,2,3}`: look up `delegationNullifier[h]` in the on-chain delegation nullifier registry. All four MUST be present — confirming each delegation hop was actually executed through the verified `Delegation` circuit, not fabricated.
4. Confirm `delegationNullifier[4..7]` are all zero.
5. Verify the PLONK proof against the verifier contract.

**What the auditor learns**:
- The chain had 4 hops
- Every hop narrowed monotonically (cryptographic certainty, not AS-trust)
- Every delegatee was an enrolled agent (Merkle root matches on-chain)
- Every delegation was authorized by the prior hop's credential holder (EdDSA)
- No credential in the chain was expired at proof time
- Every hop corresponds to an actual on-chain delegation event (nullifiers confirmed in registry)

**What the auditor does NOT learn**:
- Which agents participated (nullifiers are opaque Poseidon hashes; under PI-Poseidon, the auditor cannot recover `delegateeCredCommitment` from any nullifier even though `sessionNonce` is known)
- What permissions any hop held (scope values are private inputs hidden by ZK)
- Which model hashes or operators were involved
- The internal structure of Navy Federal's AI pipeline

**Privacy quantification**: With ~500 enrolled agents in NFCU's agent Merkle tree, the adversary's best strategy for identifying any single hop's participant is random guessing: Pr[correct] ≤ 1/500 + negl(λ) per GAME-HIDE. For the journalist/whistleblower variant below, a public agent registry with ~10,000 enrolled agents provides a correspondingly larger anonymity set.

**Whistleblower variant**: A journalist's AI agent chain (journalist → source-agent → anonymizing-relay → publication-tool) produces the same audit proof structure. The auditor (e.g., an editorial compliance system) verifies that no hop exceeded its mandate and that each hop actually occurred (via nullifier registry lookup), but cannot identify the source agent or any intermediate relay. The GAME-HIDE guarantee ensures that even a colluding auditor cannot invert nullifiers to recover participant identities. The GAME-FAITHFUL guarantee ensures that the journalist cannot fabricate phantom hops to inflate the apparent chain length or claim compliance for a pipeline that never executed.

## 8. Why the baseline cannot match

| Capability | Baseline (RFC 8693 + BBS+ + WIMSE) | ChainAuditProof |
|-----------|-------------------------------------|-----------------|
| **Prove narrowing without disclosing scopes** | Impossible. BBS+ hides claim values but cannot prove ordering/subset relationships over hidden bitmasks. Auditor must see scope values or trust AS. | Proven in-circuit via bitwise subset constraints over private inputs. Auditor sees only the scope commitments (Poseidon hashes), never the bitmasks. |
| **Hide intermediate participants** | Impossible. RFC 8693 `act` chain is plaintext. BBS+ operates per-credential, not across a multi-issuer chain. No mechanism to prove "N hops, all legitimate" without naming each hop. | All participant identities (credential commitments, public keys, model hashes) are private inputs. PI-Poseidon ensures nullifiers (the only per-hop public outputs) cannot be inverted to recover identities. Auditor's best attack is random guessing over the anonymity set (GAME-HIDE). |
| **Prove each hop actually occurred (anti-shadow-chain)** | Partially possible. AS logs record each token exchange, but the auditor must trust the AS log integrity. A compromised or absent AS provides no proof. Cross-org chains have no unified log. | Per-hop delegation nullifiers are public outputs verified against the append-only on-chain nullifier registry (GAME-FAITHFUL). No trusted log server — the registry is the chain's own execution record, written only by verified Delegation proofs. |
| **Work without Authorization Server** | Impossible. RFC 8693 narrowing enforcement is AS-resident. Offline audit requires AS policy log or AS-signed attestation. AS compromise breaks the guarantee. | Self-contained proof. No trusted third party. The circuit IS the enforcement — knowledge soundness means a valid proof implies valid narrowing, regardless of any server's state. |
| **Cross-org without shared trust anchor** | Requires federation (WIMSE) for workload attestation, but no unified narrowing-proof authority. Each org's AS enforces its own policy; no single artifact proves cross-org narrowing. | Single proof covers the entire chain regardless of organizational boundaries. Each hop's delegator signs with their own EdDSA key; the circuit verifies all signatures. No shared AS needed. Per-hop nullifiers are all checked against the same on-chain registry regardless of organizational origin. |
| **Journalist/source anonymity** | Impossible. SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-vs-RS correlation but not AS/auditor correlation via `act` chain. | Intermediate nodes are private inputs. Nullifiers are opaque under PI-Poseidon — even a malicious auditor with knowledge of `sessionNonce` cannot perform partial preimage inversion (GAME-HIDE). Anonymity set = all enrolled agents. |
| **In-circuit enforcement at presentation** | Impossible. AS enforces at issuance; no runtime check at presentation. Token accepted by any RS that validates the signature. | Narrowing is proven at proof-generation time. The proof cannot exist without valid narrowing — there is no "valid proof of invalid narrowing" (GAME-NARROW, by knowledge soundness). |
| **Expiry liveness** | Token expiry is a claim in the JWT; auditor must inspect it. Expired tokens can be presented if RS doesn't check. | `currentTimestamp < delegateeExpiry` enforced in-circuit for every hop. Proof generation fails if any hop is expired at audit time. |
| **Shadow-chain prevention** | Requires auditor to trust AS execution logs. A rogue agent could claim delegations that never passed through the AS. No cryptographic binding between "delegation happened" and "audit proof covers it." | GAME-FAITHFUL: each hop's delegation nullifier is recomputed in-circuit and exposed as a public output. The auditor verifies each nullifier exists in the on-chain registry — a registry written only by verified Delegation circuit proofs. Fabricating a hop that never occurred requires forging an EdDSA signature AND producing a nullifier that passes the registry check, both of which are computationally infeasible. |

**The fundamental gap**: The baseline's proof-of-narrowing lives in the Authorization Server's policy log — an attestation model. Bolyra's `ChainAuditProof` makes narrowing a mathematical invariant: a valid proof *cannot exist* unless every hop narrowed, every delegation was signed, every delegatee was enrolled, and every hop was faithfully executed on-chain (GAME-FAITHFUL). This is the difference between "the AS says it checked" and "the laws of arithmetic guarantee it, and every hop's existence is independently verifiable against an append-only registry." The privacy model is precisely characterized: nullifiers serve as opaque, non-invertible lookup keys (PI-Poseidon) rather than identity-leaking plaintext chains, achieving participant anonymity within the enrolled agent set without sacrificing the faithful-execution guarantee.
