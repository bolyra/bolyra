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

```
Setup: Challenger generates CRS. Two delegation chains C0, C1 of the
       same length with identical (initialScopeCommitment,
       finalScopeCommitment, chainLength, delegationNullifier[0..MAX_HOPS-1])
       but different intermediate participants and scopes.

Challenge: Challenger flips coin b ∈ {0,1}, proves ChainAuditProof
           on C_b, gives π to A.

Win condition: A guesses b.

Claim: |Pr[A guesses correctly] - 1/2| ≤ negl(λ) under zero-knowledge
       property of Groth16/PLONK.

Note: The delegationNullifier values are deterministic functions of
(delegationToken, sessionNonce). For GAME-HIDE to hold, C0 and C1
must share the same delegation tokens at every hop (and hence the same
nullifiers). This is satisfiable: two chains can have different
intermediate participant identities (different credentialCommitments
and public keys) but identical delegation tokens, since the delegation
token is Poseidon4(prevScopeCommitment, delegateeCredCommitment,
delegateeScope, delegateeExpiry) — if the delegateeCredCommitment
differs but the token inputs are held equal, the participants differ
while the nullifier is preserved. In practice, GAME-HIDE guarantees
that the auditor cannot learn WHO participated beyond what the
nullifiers (opaque field elements) reveal; linkage of nullifiers to
real-world identities requires breaking Poseidon preimage resistance.
```

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

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **DL-BJJ**: Discrete logarithm hardness on Baby Jubjub (secures EdDSA signatures on delegation tokens).
2. **CR-Poseidon**: Collision resistance of Poseidon over BN128 scalar field (secures scope commitments, chain linking, credential commitments, delegation nullifier uniqueness).
3. **KS-Groth16**: Knowledge soundness of Groth16 under the q-PKE assumption in the algebraic group model (secures extraction of valid witness from any accepting proof).
4. **ZK-Groth16**: Perfect zero-knowledge of Groth16 (secures participant/scope hiding).
5. **ROM**: Random oracle model for Fiat-Shamir in PLONK (if PLONK variant is used).
6. **REG-INTEGRITY**: The on-chain delegation nullifier registry is append-only and accepts writes only from the verified `Delegation` circuit execution path in the registry contract (smart contract correctness assumption, not a cryptographic assumption).

### Reduction sketch for GAME-NARROW

Suppose adversary `A` wins GAME-NARROW with non-negligible probability `ε`. By KS-Groth16, the knowledge extractor `E` extracts a valid witness `w` from `A`'s proof with probability ≥ `ε - negl(λ)`. The witness contains `delegatorScope[h]` and `delegateeScope[h]` for each active hop. The circuit enforces `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for all `i` — meaning every bit set in `delegateeScope` must also be set in `delegatorScope`. If the extracted witness violates this, it fails the circuit constraints, contradicting the proof's validity. Therefore `A` cannot win except with negligible probability.

### Reduction sketch for GAME-HIDE

Suppose adversary `A` distinguishes chains `C0` and `C1` with advantage `ε`. The intermediate scopes, participants, credentials, signatures, and Merkle proofs are all private inputs. By ZK-Groth16, the proof is a perfect simulation independent of the witness. The public outputs — `initialScopeCommitment`, `finalScopeCommitment`, `chainLength`, `auditDigest`, `allDelegateesMerkleRoot`, and `delegationNullifier[0..MAX_HOPS-1]` — are identical for `C0` and `C1` by construction. Therefore `ε = 0`.

**Privacy note on delegation nullifiers as public outputs**: Each `delegationNullifier[h] = Poseidon2(delegationToken, sessionNonce)` is a deterministic hash. Under CR-Poseidon (modeled as a random oracle), the nullifier reveals nothing about `delegationToken` beyond its identity — it is a pseudorandom tag. An adversary who observes the nullifier cannot recover the delegation token (Poseidon preimage resistance), and therefore cannot recover `delegateeScope`, `delegateeCredCommitment`, or any other private field composing the token. The nullifier's sole function is to serve as a unique, opaque identifier that the auditor can look up in the on-chain registry to confirm the hop occurred. Cross-hop linkage (correlating which nullifiers belong to the same chain) is inherent in the audit proof's public output vector, but this reveals only that these hops form a chain — the same information conveyed by `chainLength`. No participant identity or scope value is leaked.

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
- Which agents participated (no identity leakage — nullifiers are opaque Poseidon hashes)
- What permissions any hop held (scope values hidden)
- Which model hashes or operators were involved
- The internal structure of Navy Federal's AI pipeline

**Whistleblower variant**: A journalist's AI agent chain (journalist → source-agent → anonymizing-relay → publication-tool) produces the same audit proof structure. The auditor (e.g., an editorial compliance system) verifies that no hop exceeded its mandate and that each hop actually occurred (via nullifier registry lookup), but cannot identify the source agent or any intermediate relay. The `GAME-HIDE` guarantee ensures that even a colluding auditor learns nothing about intermediate participants. The `GAME-FAITHFUL` guarantee ensures that the journalist cannot fabricate phantom hops to inflate the apparent chain length or claim compliance for a pipeline that never executed.

## 8. Why the baseline cannot match

| Capability | Baseline (RFC 8693 + BBS+ + WIMSE) | ChainAuditProof |
|-----------|-------------------------------------|-----------------|
| **Prove narrowing without disclosing scopes** | Impossible. BBS+ hides claim values but cannot prove ordering/subset relationships over hidden bitmasks. Auditor must see scope values or trust AS. | Proven in-circuit via bitwise subset constraints over private inputs. Auditor sees only the scope commitments (Poseidon hashes), never the bitmasks. |
| **Hide intermediate participants** | Impossible. RFC 8693 `act` chain is plaintext. BBS+ operates per-credential, not across a multi-issuer chain. No mechanism to prove "N hops, all legitimate" without naming each hop. | All participant identities (credential commitments, public keys, model hashes) are private inputs. ZK property guarantees no leakage (GAME-HIDE). |
| **Prove each hop actually occurred (anti-shadow-chain)** | Partially possible. AS logs record each token exchange, but the auditor must trust the AS log integrity. A compromised or absent AS provides no proof. Cross-org chains have no unified log. | Per-hop delegation nullifiers are public outputs verified against the append-only on-chain nullifier registry (GAME-FAITHFUL). No trusted log server — the registry is the chain's own execution record, written only by verified Delegation proofs. |
| **Work without Authorization Server** | Impossible. RFC 8693 narrowing enforcement is AS-resident. Offline audit requires AS policy log or AS-signed attestation. AS compromise breaks the guarantee. | Self-contained proof. No trusted third party. The circuit IS the enforcement — knowledge soundness means a valid proof implies valid narrowing, regardless of any server's state. |
| **Cross-org without shared trust anchor** | Requires federation (WIMSE) for workload attestation, but no unified narrowing-proof authority. Each org's AS enforces its own policy; no single artifact proves cross-org narrowing. | Single proof covers the entire chain regardless of organizational boundaries. Each hop's delegator signs with their own EdDSA key; the circuit verifies all signatures. No shared AS needed. Per-hop nullifiers are all checked against the same on-chain registry regardless of organizational origin. |
| **Journalist/source anonymity** | Impossible. SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-vs-RS correlation but not AS/auditor correlation via `act` chain. | Intermediate nodes are private inputs. Even a malicious auditor (GAME-HIDE) cannot identify any participant beyond what the public signals reveal (chain length and opaque nullifiers). |
| **In-circuit enforcement at presentation** | Impossible. AS enforces at issuance; no runtime check at presentation. Token accepted by any RS that validates the signature. | Narrowing is proven at proof-generation time. The proof cannot exist without valid narrowing — there is no "valid proof of invalid narrowing" (GAME-NARROW, by knowledge soundness). |
| **Expiry liveness** | Token expiry is a claim in the JWT; auditor must inspect it. Expired tokens can be presented if RS doesn't check. | `currentTimestamp < delegateeExpiry` enforced in-circuit for every hop. Proof generation fails if any hop is expired at audit time. |
| **Shadow-chain prevention** | Requires auditor to trust AS execution logs. A rogue agent could claim delegations that never passed through the AS. No cryptographic binding between "delegation happened" and "audit proof covers it." | GAME-FAITHFUL: each hop's delegation nullifier is recomputed in-circuit and exposed as a public output. The auditor verifies each nullifier exists in the on-chain registry — a registry written only by verified Delegation circuit proofs. Fabricating a hop that never occurred requires forging an EdDSA signature AND producing a nullifier that passes the registry check, both of which are computationally infeasible. |

**The fundamental gap**: The baseline's proof-of-narrowing lives in the Authorization Server's policy log — an attestation model. Bolyra's `ChainAuditProof` makes narrowing a mathematical invariant: a valid proof *cannot exist* unless every hop narrowed, every delegation was signed, every delegatee was enrolled, and every hop was faithfully executed on-chain (GAME-FAITHFUL). This is the difference between "the AS says it checked" and "the laws of arithmetic guarantee it, and every hop's existence is independently verifiable against an append-only registry."
