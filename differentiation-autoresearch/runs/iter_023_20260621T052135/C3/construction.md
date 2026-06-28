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
| `auditNonce` | field | Fresh auditor-chosen nonce binding this audit proof |
| `currentTimestamp` | uint64 | Auditor-supplied current time |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `finalScopeCommitment` | field | Terminal scope commitment of chain |
| `chainLength` | uint8 | Number of active hops |
| `auditDigest` | field | `Poseidon4(initialScopeCommitment, finalScopeCommitment, chainLength, auditNonce)` |
| `allDelegateesMerkleRoot` | field | Agent tree root (uniform across hops) |

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

        // 2i. Advance running state
        runningScopeCommitment = Poseidon2(delegateeScope[h],
                                            delegateeCredCommitment[h])
        runningChainLength += 1

    else:
        // Inactive hop: no constraints, values ignored

// 3. Bind outputs
finalScopeCommitment <== runningScopeCommitment
chainLength <== runningChainLength
auditDigest <== Poseidon4(initialScopeCommitment, finalScopeCommitment,
                           chainLength, auditNonce)
```

### Gadget inventory

| Gadget | Source | Invocations |
|--------|--------|-------------|
| `Poseidon2` | circomlib | 2 × MAX_HOPS + 2 |
| `Poseidon4` | circomlib | MAX_HOPS + 1 |
| `Num2Bits(64)` | circomlib | 4 × MAX_HOPS |
| `EdDSAPoseidonVerifier` | circomlib | MAX_HOPS |
| `BinaryMerkleRoot(20)` | @zk-kit | MAX_HOPS |
| `LessThan(64)` / `LessEqThan(64)` | circomlib | 2 × MAX_HOPS |

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
       finalScopeCommitment, chainLength) but different intermediate
       participants and scopes.

Challenge: Challenger flips coin b ∈ {0,1}, proves ChainAuditProof
           on C_b, gives π to A.

Win condition: A guesses b.

Claim: |Pr[A guesses correctly] - 1/2| ≤ negl(λ) under zero-knowledge
       property of Groth16/PLONK.
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

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **DL-BJJ**: Discrete logarithm hardness on Baby Jubjub (secures EdDSA signatures on delegation tokens).
2. **CR-Poseidon**: Collision resistance of Poseidon over BN128 scalar field (secures scope commitments, chain linking, credential commitments).
3. **KS-Groth16**: Knowledge soundness of Groth16 under the q-PKE assumption in the algebraic group model (secures extraction of valid witness from any accepting proof).
4. **ZK-Groth16**: Perfect zero-knowledge of Groth16 (secures participant/scope hiding).
5. **ROM**: Random oracle model for Fiat-Shamir in PLONK (if PLONK variant is used).

### Reduction sketch for GAME-NARROW

Suppose adversary `A` wins GAME-NARROW with non-negligible probability `ε`. By KS-Groth16, the knowledge extractor `E` extracts a valid witness `w` from `A`'s proof with probability ≥ `ε - negl(λ)`. The witness contains `delegatorScope[h]` and `delegateeScope[h]` for each active hop. The circuit enforces `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for all `i` — meaning every bit set in `delegateeScope` must also be set in `delegatorScope`. If the extracted witness violates this, it fails the circuit constraints, contradicting the proof's validity. Therefore `A` cannot win except with negligible probability.

### Reduction sketch for GAME-HIDE

Suppose adversary `A` distinguishes chains `C0` and `C1` with advantage `ε`. The intermediate scopes, participants, credentials, signatures, and Merkle proofs are all private inputs. By ZK-Groth16, the proof is a perfect simulation independent of the witness. The public outputs — `initialScopeCommitment`, `finalScopeCommitment`, `chainLength`, `auditDigest`, `allDelegateesMerkleRoot` — are identical for `C0` and `C1` by construction. Therefore `ε = 0`.

### Reduction sketch for GAME-FORGE

Suppose `A` produces a proof anchored at a scope commitment `sc*` not on-chain. The circuit enforces `Poseidon2(rootScope, rootCredCommitment) === initialScopeCommitment`. By KS-Groth16, the extractor recovers `(rootScope, rootCredCommitment)` such that their Poseidon2 hash equals `sc*`. If `sc*` was never stored on-chain, then either: (a) `A` found a Poseidon collision mapping different inputs to a legitimate on-chain commitment — contradicting CR-Poseidon, or (b) the verifier rejects because `initialScopeCommitment` is a public input checked against on-chain state. Similarly, a phantom delegatee requires a Merkle proof against `allDelegateesMerkleRoot`, which the verifier checks against the on-chain agent root history buffer.

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
| Nullifier (per-hop) | `Poseidon2(delegationTokenHash, sessionNonce)` | §4.2 delegationNullifier output |
| Chain anchor | `lastScopeCommitment[sessionNonce]` on-chain mapping | §4.1 chain seed |
| Audit binding | `Poseidon4(initial, final, length, auditNonce)` | New: binds audit artifact to session |

The `ChainAuditProof` circuit composes exactly the same per-hop constraints as the existing `Delegation` circuit (§4.2) but executes them iteratively over `MAX_HOPS` slots within a single circuit, producing a single proof that covers the entire chain.

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints per instance | Instances per hop | Subtotal |
|--------|------------------------|-------------------|----------|
| `EdDSAPoseidonVerifier` | ~10,000 | 1 | 10,000 |
| `BinaryMerkleRoot(20)` | ~5,000 | 1 | 5,000 |
| `Poseidon2` | ~300 | 2 (chain link + new scope) | 600 |
| `Poseidon4` | ~600 | 1 (delegation token) | 600 |
| `Num2Bits(64)` | ~64 | 4 (scopes + expiries) | 256 |
| Bitwise subset (64 muls) | ~64 | 1 | 64 |
| Cumulative encoding | ~3 | 1 | 3 |
| `LessEqThan(64)` + `LessThan(64)` | ~200 | 2 | 400 |
| Conditional mux (active flag) | ~500 | 1 | 500 |
| **Per-hop total** | | | **~17,423** |

### Full circuit

| Configuration | Hops | Total constraints | Proving system | Proving time target |
|--------------|------|-------------------|----------------|-------------------|
| Standard (8 hops) | 8 | ~139,400 | PLONK (universal setup) | < 5s (agent-class) |
| Compact (4 hops) | 4 | ~69,700 | PLONK | < 3s |
| Extended (16 hops) | 16 | ~278,800 | PLONK | < 12s |

All configurations fit within `pot16.ptau` (2^16 = 65,536 for 4-hop; 2^18 for 8-hop; 2^19 for 16-hop). The 8-hop standard configuration requires a `pot18.ptau` ceremony or universal PLONK SRS of matching size.

**Proving system choice**: PLONK with universal setup. The audit proof is an agent-class circuit (no human secret involved), and PLONK avoids a per-circuit trusted setup ceremony. The auditor verifies against a PLONK verifier contract at a distinct address from the Groth16 human verifier, per spec §2.3.

**Verification**: PLONK on-chain verification ~300K gas (single pairing check + polynomial evaluation).

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
- Public signals: `initialScopeCommitment` (verifiable against on-chain handshake record), `finalScopeCommitment` (matches settlement agent's scope commitment on-chain), `chainLength = 4`, `auditDigest`, `allDelegateesMerkleRoot` (verifiable against on-chain agent root history)

**What the auditor learns**:
- The chain had 4 hops
- Every hop narrowed monotonically (cryptographic certainty, not AS-trust)
- Every delegatee was an enrolled agent (Merkle root matches on-chain)
- Every delegation was authorized by the prior hop's credential holder (EdDSA)
- No credential in the chain was expired at proof time

**What the auditor does NOT learn**:
- Which agents participated (no identity leakage)
- What permissions any hop held (scope values hidden)
- Which model hashes or operators were involved
- The internal structure of Navy Federal's AI pipeline

**Whistleblower variant**: A journalist's AI agent chain (journalist → source-agent → anonymizing-relay → publication-tool) produces the same audit proof structure. The auditor (e.g., an editorial compliance system) verifies that no hop exceeded its mandate, but cannot identify the source agent or any intermediate relay. The `GAME-HIDE` guarantee ensures that even a colluding auditor learns nothing about intermediate participants.

## 8. Why the baseline cannot match

| Capability | Baseline (RFC 8693 + BBS+ + WIMSE) | ChainAuditProof |
|-----------|-------------------------------------|-----------------|
| **Prove narrowing without disclosing scopes** | Impossible. BBS+ hides claim values but cannot prove ordering/subset relationships over hidden bitmasks. Auditor must see scope values or trust AS. | Proven in-circuit via bitwise subset constraints over private inputs. Auditor sees only the scope commitments (Poseidon hashes), never the bitmasks. |
| **Hide intermediate participants** | Impossible. RFC 8693 `act` chain is plaintext. BBS+ operates per-credential, not across a multi-issuer chain. No mechanism to prove "N hops, all legitimate" without naming each hop. | All participant identities (credential commitments, public keys, model hashes) are private inputs. ZK property guarantees no leakage (GAME-HIDE). |
| **Work without Authorization Server** | Impossible. RFC 8693 narrowing enforcement is AS-resident. Offline audit requires AS policy log or AS-signed attestation. AS compromise breaks the guarantee. | Self-contained proof. No trusted third party. The circuit IS the enforcement — knowledge soundness means a valid proof implies valid narrowing, regardless of any server's state. |
| **Cross-org without shared trust anchor** | Requires federation (WIMSE) for workload attestation, but no unified narrowing-proof authority. Each org's AS enforces its own policy; no single artifact proves cross-org narrowing. | Single proof covers the entire chain regardless of organizational boundaries. Each hop's delegator signs with their own EdDSA key; the circuit verifies all signatures. No shared AS needed. |
| **Journalist/source anonymity** | Impossible. SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-vs-RS correlation but not AS/auditor correlation via `act` chain. | Intermediate nodes are private inputs. Even a malicious auditor (GAME-HIDE) cannot identify any participant beyond what the public signals reveal (chain length and endpoint commitments). |
| **In-circuit enforcement at presentation** | Impossible. AS enforces at issuance; no runtime check at presentation. Token accepted by any RS that validates the signature. | Narrowing is proven at proof-generation time. The proof cannot exist without valid narrowing — there is no "valid proof of invalid narrowing" (GAME-NARROW, by knowledge soundness). |
| **Expiry liveness** | Token expiry is a claim in the JWT; auditor must inspect it. Expired tokens can be presented if RS doesn't check. | `currentTimestamp < delegateeExpiry` enforced in-circuit for every hop. Proof generation fails if any hop is expired at audit time. |

**The fundamental gap**: The baseline's proof-of-narrowing lives in the Authorization Server's policy log — an attestation model. Bolyra's `ChainAuditProof` makes narrowing a mathematical invariant: a valid proof *cannot exist* unless every hop narrowed, every delegation was signed, and every delegatee was enrolled. This is the difference between "the AS says it checked" and "the laws of arithmetic guarantee it."
