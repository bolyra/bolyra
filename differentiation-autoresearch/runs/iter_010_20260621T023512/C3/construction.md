# Construction

## 1. Statement of claim

An auditor verifies that an N-hop delegation chain (N ≤ 8) narrowed permissions monotonically at every hop, with every participant enrolled in the agent Merkle tree and every expiry non-increasing, **without learning any intermediate scope values, participant identities, or credential commitments**. The auditor receives a single PLONK proof and four public signals: the root scope commitment, the terminal scope commitment, the chain length, and a chain-integrity digest. This applies to multi-tool AI pipelines, cross-org agent handoffs, and whistleblower-safe delegation chains alike.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `DelegationAuditRollup(MAX_HOPS=8, MAX_DEPTH=20)`

An iterative circuit that unrolls up to 8 delegation hops inside a single proof. Hops beyond the actual chain length are masked out via a selector bit.

#### Blinded scope commitments

The standard Bolyra scope commitment `Poseidon2(permissionBitmask, credentialCommitment)` is vulnerable to brute-force inversion when the scope domain is small. With 8 permission bits, only 256 valid bitmasks exist (fewer after cumulative-bit filtering reduces this to ~192). If credential commitments are publicly enumerable from the on-chain Merkle tree (at most 2^20 leaves), an adversary can precompute `Poseidon2(s, c)` for all `(s, c)` pairs and match against observed scope commitments.

To close this gap, every scope commitment in the audit rollup includes a **per-hop blinding salt** — a 254-bit random field element chosen by the prover at proof generation time:

```
blindedScopeCommitment[h] = Poseidon3(permissionBitmask[h], credentialCommitment[h], blindingSalt[h])
```

The blinding salt is a private input that never appears in any public signal. Chain linking uses blinded commitments throughout: each hop's delegator re-derives the blinded commitment using their own salt, and the circuit checks equality against the previous hop's blinded output.

The root and terminal scope commitments exposed as public signals are **also blinded**, so no public signal is invertible by enumeration. The prover (the entity assembling the audit proof from the full chain witness) chooses all salts.

**Compatibility note:** The blinded scope commitment is used **only within the `DelegationAuditRollup` circuit**. The per-hop `Delegation` circuit specified in the Bolyra protocol (§4.2) continues to use the unblinded `Poseidon2(permissionBitmask, credentialCommitment)` for on-chain chain-linking during live delegation. The rollup circuit re-derives both forms internally: it checks each hop's unblinded commitment against the delegation token signature (which was signed over unblinded values at delegation time), then independently computes the blinded commitment for inter-hop linking within the audit proof. This means existing delegation chains require **no protocol changes** — blinding is applied at audit-proof generation time only.

**Private inputs (per hop h ∈ [0, MAX_HOPS)):**

| Signal | Type | Description |
|--------|------|-------------|
| `active[h]` | bit | 1 if hop h is real, 0 if padding |
| `delegatorScope[h]` | 64-bit | Delegator permission bitmask |
| `delegateeScope[h]` | 64-bit | Delegatee permission bitmask |
| `delegatorExpiry[h]` | 64-bit | Delegator expiry timestamp |
| `delegateeExpiry[h]` | 64-bit | Delegatee expiry timestamp |
| `delegatorCredCommitment[h]` | field | Delegator's Poseidon5 credential hash |
| `delegateeCredCommitment[h]` | field | Delegatee's Poseidon5 credential hash |
| `delegatorPubkeyAx[h]`, `delegatorPubkeyAy[h]` | field | Delegator EdDSA pubkey |
| `sigR8x[h]`, `sigR8y[h]`, `sigS[h]` | field | Delegator signature on delegation token |
| `delegateeMerkleProofLength[h]` | field | Merkle proof depth |
| `delegateeMerkleProofIndex[h]` | field | Leaf index |
| `delegateeMerkleProofSiblings[h][MAX_DEPTH]` | field[] | Merkle siblings |
| `delegatorBlindingSalt[h]` | field | 254-bit random salt for delegator's blinded scope commitment |
| `delegateeBlindingSalt[h]` | field | 254-bit random salt for delegatee's blinded scope commitment |

**Private inputs (global):**

| Signal | Type | Description |
|--------|------|-------------|
| `rootScope` | 64-bit | Permission bitmask at chain root |
| `rootCredCommitment` | field | Root delegator's credential commitment |
| `rootBlindingSalt` | field | Blinding salt for root scope commitment |

**Public inputs:**

| Index | Signal | Description |
|-------|--------|-------------|
| 0 | `rootScopeCommitment` | Poseidon3(rootScope, rootCredCommitment, rootBlindingSalt) — blinded chain anchor |
| 1 | `terminalScopeCommitment` | Final hop's blinded newScopeCommitment |
| 2 | `chainLength` | Number of active hops (1..8) |
| 3 | `auditSessionNonce` | Binds this audit proof to a specific audit session |

**Public outputs:**

| Index | Signal | Description |
|-------|--------|-------------|
| 4 | `chainIntegrityDigest` | Poseidon over all delegation nullifiers — unique chain fingerprint |
| 5 | `terminalMerkleRoot` | Merkle root of the terminal delegatee — auditor checks against on-chain root history |

### Gadgets and constraints (per hop h):

```
// --- Range checks ---
Num2Bits(64)(delegatorScope[h])
Num2Bits(64)(delegateeScope[h])
Num2Bits(64)(delegatorExpiry[h])
Num2Bits(64)(delegateeExpiry[h])

// --- Scope subset (monotonic narrowing) ---
// For each bit i in [0,64): active[h] * delegateeBits[i] * (1 - delegatorBits[i]) === 0
// When active=1, delegatee can only set bits that delegator has set.

// --- Cumulative bit encoding on delegatee scope ---
// active[h] * delegateeBits[4] * (1 - delegateeBits[3]) === 0
// active[h] * delegateeBits[4] * (1 - delegateeBits[2]) === 0
// active[h] * delegateeBits[3] * (1 - delegateeBits[2]) === 0

// --- Expiry narrowing ---
// active[h] * (delegateeExpiry[h] <= delegatorExpiry[h]) via LessEqThan(64)

// --- Unblinded scope commitment (for delegation token signature verification) ---
// unblidedDelegatorSC[h] = Poseidon2(delegatorScope[h], delegatorCredCommitment[h])

// --- Delegation token & EdDSA (uses UNBLINDED commitment, matching what was signed at delegation time) ---
// prevUnblindedCommitment[0] = Poseidon2(rootScope, rootCredCommitment)
// For h > 0: prevUnblindedCommitment[h] = Poseidon2(delegatorScope[h], delegatorCredCommitment[h])
//   (delegator at hop h is delegatee at hop h-1; the circuit checks delegatorCredCommitment[h] = delegateeCredCommitment[h-1])
// delegationToken[h] = Poseidon4(prevUnblindedCommitment[h], delegateeCredCommitment[h], delegateeScope[h], delegateeExpiry[h])
// active[h] => EdDSAPoseidonVerifier(delegatorPubkeyAx[h], delegatorPubkeyAy[h], delegationToken[h], sig[h])

// --- Blinded chain linking (uses BLINDED commitments for inter-hop linking within the audit proof) ---
// blindedPrevCommitment[0] = rootScopeCommitment (public input, already blinded)
// For h > 0: blindedPrevCommitment[h] = blindedNewScopeCommitment[h-1]
// blindedDelegatorSC[h] = Poseidon3(delegatorScope[h], delegatorCredCommitment[h], delegatorBlindingSalt[h])
// Constraint: active[h] * (blindedDelegatorSC[h] - blindedPrevCommitment[h]) === 0

// --- Delegatee enrollment ---
// active[h] => BinaryMerkleRoot(MAX_DEPTH)(delegateeCredCommitment[h], proof[h]) = delegateeMerkleRoot[h]
// On-chain: auditor checks terminalMerkleRoot (last active hop) against agent root history buffer.

// --- Blinded new scope commitment ---
// blindedNewScopeCommitment[h] = Poseidon3(delegateeScope[h], delegateeCredCommitment[h], delegateeBlindingSalt[h])

// --- Delegation nullifier ---
// delegationNullifier[h] = Poseidon2(delegationToken[h], auditSessionNonce)
```

**Global constraints:**

```
// Active hops must be contiguous: active[h] >= active[h+1]
// chainLength = sum(active[h])
// Delegator-delegatee consistency: for h > 0, active[h] => delegatorCredCommitment[h] = delegateeCredCommitment[h-1]
// terminalScopeCommitment = blindedNewScopeCommitment[chainLength - 1] (muxed by active flags)
// terminalMerkleRoot = delegateeMerkleRoot[chainLength - 1]
// chainIntegrityDigest = Poseidon(delegationNullifier[0], ..., delegationNullifier[MAX_HOPS-1])
//   (inactive nullifiers are zeroed, producing a deterministic padding)
// Root blinded commitment check: Poseidon3(rootScope, rootCredCommitment, rootBlindingSalt) === rootScopeCommitment
```

### Why PLONK

This circuit serves an audit function (agent-side, not human-side). Per the Bolyra spec, PLONK with universal setup is the OPTIONAL proving system for agent/delegation circuits. The `DelegationAuditRollup` uses PLONK to avoid a per-circuit trusted setup ceremony for this new circuit — the universal `pot16.ptau` SRS suffices.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary **A** controls up to N-1 of N agents in the delegation chain and may collude with any subset of chain participants. **A** additionally has read access to all public signals, on-chain state (including the full agent Merkle tree and all enrolled credential commitments), and the audit proof itself. **A** may be:

- A **malicious delegator** attempting to produce a valid audit proof for a chain where some hop expanded scope.
- A **curious auditor** attempting to extract intermediate scopes or participant identities from the proof and public signals.
- A **chain participant** attempting to repudiate their involvement after the fact.

### Game 1: Scope Expansion Forgery (Soundness)

```
GAME ScopeExpansionForgery(λ):
  1. Challenger C sets up the CRS (PLONK universal SRS).
  2. A chooses N agents, enrolls them in the agent Merkle tree.
  3. A produces delegatorScope[h], delegateeScope[h] for each hop.
  4. A outputs a proof π with public signals (rootSC, termSC, len, nonce, digest, root).
  5. A wins if:
     - Verifier accepts π, AND
     - ∃ hop h where delegateeScope[h] & ~delegatorScope[h] ≠ 0
       (i.e., some bit is SET in delegatee but NOT in delegator)
```

**Claim:** Pr[A wins] ≤ negl(λ) under knowledge soundness of PLONK + Poseidon collision resistance.

### Game 2: Intermediate Scope Extraction (Zero-Knowledge)

```
GAME ScopeExtraction(λ):
  1. Challenger C publishes the agent Merkle tree (all credential commitments are public).
  2. Prover P generates a valid chain with scopes S[0..N] and per-hop blinding salts r[0..N].
  3. Auditor A receives π and public signals (rootScopeCommitment, terminalScopeCommitment,
     chainLength, auditSessionNonce, chainIntegrityDigest, terminalMerkleRoot).
  4. A has full read access to the on-chain agent Merkle tree (all enrolled credential commitments).
  5. A outputs a guess Ŝ[h] for any intermediate scope value h ∈ (0, N).
  6. A wins if Ŝ[h] = S[h].
```

**Claim:** Pr[A wins] ≤ negl(λ), specifically bounded by the advantage of distinguishing Poseidon3 from a random oracle under unknown salt.

**Analysis of the bound.** Without blinding, the adversary faces a domain of only ~192 valid scope bitmasks (256 total 8-bit values minus those violating cumulative-bit constraints) × |enrolled agents| credential commitments. For a tree with 1,000 enrolled agents, this is ~192,000 candidate pairs — trivially brute-forceable against `Poseidon2(scope, credCommitment)` in milliseconds. The unblinded Game 2 bound of 1/2^64 was **incorrect** because it assumed uniform distribution over 64-bit bitmasks, whereas the protocol's 8-bit permission model and public credential tree reduce the effective entropy to ~17.5 bits (log₂(192,000)).

With the per-hop blinding salt `r[h]` drawn uniformly from F_p (a ~254-bit field), the scope commitment becomes `Poseidon3(scope, credCommitment, r[h])`. To brute-force, the adversary must guess both the scope (~8 bits), the credential commitment (known, but which one among |enrolled|), **and** the 254-bit salt. The salt is never revealed: it is a private circuit input, protected by the zero-knowledge property of PLONK (A4). Under A4, the auditor's view is simulatable without knowledge of any private input including the salt. The adversary gains no information about `r[h]` from the proof, and preimage search over `Poseidon3` with an unknown 254-bit input is infeasible under A2 (Poseidon collision resistance implies preimage resistance for computationally bounded adversaries).

The root and terminal scope commitments (public signals 0 and 1) are also blinded with their own salts, preventing the adversary from using the endpoints as brute-force oracles. Even if the adversary knows the root agent's identity and guesses the root scope correctly, confirming the guess requires knowing `rootBlindingSalt`, which is private.

### Game 3: Participant Deanonymization (Zero-Knowledge)

```
GAME ParticipantDeanon(λ):
  1. Challenger C publishes the agent Merkle tree (all credential commitments are public).
  2. Prover P generates a valid chain with K enrolled agents and per-hop blinding salts.
  3. Auditor A receives π and public signals.
  4. A outputs a guess of which enrolled agent occupies hop h.
  5. A wins if the guess is correct.
```

**Claim:** Pr[A wins] ≤ 1/|enrolled agents| + negl(λ) under ZK of PLONK (A4) and Poseidon preimage resistance (A2).

**Analysis.** Participant identity at hop h enters the public view only through the blinded scope commitment `Poseidon3(scope, credCommitment, salt)`. Even with full knowledge of all credential commitments in the tree, the adversary cannot test a candidate `(scope, credCommitment)` pair against the blinded commitment without knowing the salt. The `terminalMerkleRoot` (public signal 5) reveals the Merkle root at the time of terminal delegatee enrollment, but this root corresponds to the entire tree — it does not identify which leaf. Under A4, the proof itself leaks nothing beyond the public signals.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Instantiation |
|----|-----------|---------------|
| A1 | Knowledge soundness of PLONK | Marlin/PLONK extraction in the Algebraic Group Model + ROM |
| A2 | Collision resistance of Poseidon | Over BN254 scalar field, ≥128-bit security at t=5 (Poseidon5), t=3 (Poseidon3), and t=2 (Poseidon2) |
| A3 | Discrete logarithm on Baby Jubjub | Hardness of DLP in the ≈251-bit prime-order subgroup |
| A4 | Zero-knowledge of PLONK | Honest-verifier ZK in ROM; simulator constructs accepting transcript without witness |
| A5 | PRF security of Poseidon | Poseidon2(key, input) is indistinguishable from random under unknown key |

### Reduction sketch: Soundness (Game 1)

**Theorem.** If A wins Game 1 with non-negligible probability, then we break A1 or A2.

*Proof sketch.*

1. Suppose A produces a valid proof π where hop h has `delegateeScope[h] & ~delegatorScope[h] ≠ 0`.
2. By knowledge soundness (A1), extract the witness from π. The extracted witness includes `delegatorScope[h]` and `delegateeScope[h]` with their bit decompositions.
3. The circuit enforces `active[h] * delegateeBits[i] * (1 - delegatorBits[i]) === 0` for all i. With `active[h]=1`, this means `delegateeBits[i]=1 ⟹ delegatorBits[i]=1`.
4. If the extracted bits satisfy the constraint but `delegateeScope[h] & ~delegatorScope[h] ≠ 0`, then the bit decomposition does not match the field element — which requires finding a Poseidon collision (the scope commitment binds the field element to its bits via `Num2Bits(64)`). This contradicts A2.
5. Alternatively, if the extractor fails, this contradicts A1. ∎

**Note on blinding and soundness.** The addition of blinding salts does not weaken soundness. The scope subset constraint operates on the raw `delegatorScope[h]` and `delegateeScope[h]` field elements and their bit decompositions — these are private inputs independent of the blinding salts. The blinding salt affects only the blinded scope commitment used for chain linking, not the narrowing arithmetic. The unblinded commitment `Poseidon2(delegatorScope[h], delegatorCredCommitment[h])` is still computed internally for delegation token construction and EdDSA verification, ensuring signature validity over the original (unblinded) delegation token.

### Reduction sketch: Zero-Knowledge (Games 2 & 3)

**Theorem.** Games 2 and 3 reduce to A4 + A2.

*Proof sketch.*

1. By the ZK property of PLONK (A4), there exists a simulator S that produces an accepting proof and transcript given only the public signals, without access to any private input (including blinding salts).
2. The auditor's view in the real protocol is computationally indistinguishable from S's output.
3. In the simulated view, intermediate scopes appear only inside blinded scope commitments `Poseidon3(scope, credCommitment, blindingSalt)`. Recovering `scope` requires finding a preimage of Poseidon3 with an unknown 254-bit salt coordinate. Even with knowledge of all candidate `(scope, credCommitment)` pairs from the public Merkle tree, the adversary must enumerate over the ~254-bit salt space per candidate — a total of ~192 × |enrolled| × 2^254 evaluations. This is computationally infeasible, reducing to preimage resistance of Poseidon (implied by A2).
4. The public root and terminal scope commitments are also blinded, so they cannot serve as brute-force oracles even when the adversary guesses the endpoint identities.
5. The `chainIntegrityDigest` is a Poseidon hash of delegation nullifiers. Each nullifier is `Poseidon2(delegationToken, auditSessionNonce)`. The delegation token includes the **unblinded** `previousScopeCommitment`, but this value is a private input never exposed publicly. Under A5 (Poseidon as PRF keyed by the unknown `delegationToken`), individual nullifiers are pseudorandom, and the digest reveals nothing about intermediate identities. ∎

### Why A5 (PRF) is no longer the primary ZK defense

In the prior construction without blinding, the Game 2 bound relied on Poseidon PRF security (A5) to argue that scope commitments looked random. This was insufficient: the "key" (`credentialCommitment`) is publicly enumerable from the Merkle tree, and the "input" (`scope`) has only ~8 bits of entropy, so PRF security does not apply — the adversary can evaluate the function on all inputs. The blinding salt construction shifts the defense to preimage resistance of Poseidon3 (A2) with a 254-bit unknown coordinate, which holds regardless of whether the other inputs are known.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope commitment (live delegation) | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Composable Delegation |
| Blinded scope commitment (audit rollup) | `Poseidon3(permissionBitmask, credentialCommitment, blindingSalt)` | Extension for audit — Poseidon at t=3, same field |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` | §3.2 Agent Proof |
| Delegation token | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | §4.2 Delegation Circuit (uses unblinded prevScopeCommitment) |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | §2.2 Cryptographic Primitives |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 | §2.2, §4.2 |
| Delegation nullifier | `Poseidon2(delegationTokenHash, sessionNonce)` | §4.2 Delegation Circuit |
| Cumulative bit encoding | Bits 4⟹3⟹2 implication constraints | §3.2 constraint 6 |
| Scope subset | `delegateeBits[i] * (1 - delegatorBits[i]) === 0` | §4.2 constraint 3 |
| Proving system | PLONK with universal SRS (`pot16.ptau`) | §2.3 — OPTIONAL for Delegation |
| Root history buffer | 30-entry circular buffer, checked for `terminalMerkleRoot` | §2.1 |

**One new primitive variant is introduced:** `Poseidon3` (Poseidon at arity 3) for blinded scope commitments. This is not a new hash function — it is the same Poseidon algebraic hash over BN254, instantiated at `t=3` instead of `t=2`. The Poseidon specification defines security parameters for all arities; `t=3` at the BN254 field provides ≥128-bit collision resistance with the standard round count. All other primitives are unchanged from the Bolyra spec.

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(64) × 4 (scopes + expiries) | 256 |
| Scope subset (64 AND gates) | 128 |
| Cumulative bit (3 constraints) | 3 |
| LessEqThan(64) for expiry | ~130 |
| Poseidon2 (unblinded delegator scope commitment for delegation token) | ~300 |
| Poseidon3 (blinded delegator scope commitment for chain linking) | ~400 |
| Poseidon4 (delegation token) | ~500 |
| Poseidon3 (blinded new scope commitment) | ~400 |
| Poseidon2 (delegation nullifier) | ~300 |
| EdDSAPoseidonVerifier | ~4,500 |
| BinaryMerkleRoot(20) with Poseidon2 | ~6,000 |
| Active-hop selector multiplexing | ~100 |
| **Per-hop total** | **~13,000** |

### Global constraints

| Gadget | Constraints |
|--------|------------|
| Contiguity enforcement (7 comparisons) | ~50 |
| Chain length accumulator | ~20 |
| Terminal mux (select by chainLength) | ~200 |
| Poseidon over 8 nullifiers (chain integrity digest) | ~1,500 |
| Root blinded scope commitment check (Poseidon3) | ~400 |
| Delegator-delegatee credential consistency (7 equality checks) | ~50 |
| **Global total** | **~2,200** |

### Total

- **8 hops × 13,000 + 2,200 ≈ 106,200 constraints**
- Fits within 2^17 = 131,072 constraint budget (compatible with `pot16.ptau` at depth 17)
- **PLONK proving time target: < 5 seconds** (agent-class circuit, per Bolyra spec)
- Verification: single PLONK verification on-chain (~300K gas, comparable to Groth16)
- Overhead vs. prior (unblinded) construction: ~4,100 additional constraints (~4%) from Poseidon3 calls (one blinded delegator SC + one blinded delegatee SC per hop, plus root check). Well within the 2^17 budget.

For chains ≤ 4 hops (the common case), a `DelegationAuditRollup(MAX_HOPS=4)` variant at ~54,200 constraints proves in < 2.5 seconds.

## 7. Concrete deployment scenario

### Scenario: Multi-Tool AI Pipeline Audit at Navy Federal Credit Union

**Stakeholder:** Navy Federal Credit Union (NFCU), the largest US credit union (13M+ members), subject to NCUA examination and GENIUS Act compliance requirements for any stablecoin or digital asset services.

**Setup:** NFCU deploys an AI-assisted member service pipeline:

1. **Root agent** (Member Service AI) holds permissions `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bits 0,1,2,7 = bitmask `0b10000111 = 0x87`). Signed by NFCU's operator key and enrolled in Bolyra's agent Merkle tree.

2. **Hop 1:** Root agent delegates to a **KYC Verification Tool** with narrowed scope `READ_DATA | ACCESS_PII` (bits 0,7 = `0x81`). Financial permissions stripped.

3. **Hop 2:** KYC tool delegates to an **Address Validation Microservice** (third-party, cross-org) with scope `READ_DATA` only (bit 0 = `0x01`). PII access stripped — the microservice sees only a hashed address query.

4. **Hop 3:** Address validation delegates to a **USPS API Agent** with scope `READ_DATA` (`0x01`), same tier, expiry narrowed to 60 seconds.

**The brute-force threat in practice:** Without blinding, an NCUA examiner (or any party with access to the proof and the public Merkle tree) could enumerate all ~192 valid scope bitmasks against each of the ~50 enrolled NFCU agent credential commitments, compute `Poseidon2(scope, credCommitment)` for each pair (~9,600 evaluations), and compare against the public `rootScopeCommitment` and `terminalScopeCommitment`. This would identify the root and terminal agents and their exact permissions in under a second, defeating the privacy claim entirely.

**With blinded commitments:** The same examiner sees `Poseidon3(0x87, credCommRoot, r_root)` as the root scope commitment. Even knowing that the root agent is likely one of NFCU's ~50 agents and guessing the scope is `0x87`, the examiner cannot confirm without the 254-bit salt `r_root`. The brute-force space is 2^254 per candidate — computationally infeasible.

**Audit event:** An NCUA examiner reviews NFCU's AI delegation practices. The examiner must verify:
- Every delegation hop narrowed or maintained scope (never expanded)
- No intermediate agent exceeded its mandate
- The chain terminated with minimal permissions
- PII access was confined to authorized hops

**Without Bolyra (baseline):** The examiner must either (a) access the RFC 8693 Authorization Server logs and see all intermediate scope values and participant SPIFFE IDs, or (b) trust NFCU's self-attestation. Option (a) exposes proprietary pipeline architecture and vendor relationships to a government examiner. Option (b) provides no cryptographic assurance.

**With DelegationAuditRollup:** NFCU generates a single PLONK proof. The NCUA examiner receives:

| Public signal | Value | What examiner learns |
|---------------|-------|---------------------|
| `rootScopeCommitment` | `Poseidon3(0x87, credCommRoot, r_root)` | "Chain started from an enrolled agent with some scope" — cannot invert |
| `terminalScopeCommitment` | `Poseidon3(0x01, credCommUSPS, r_term)` | "Chain ended with a different enrolled agent with narrower scope" — cannot invert |
| `chainLength` | 4 | "Four hops occurred" |
| `auditSessionNonce` | (fresh) | Binds to this specific audit |
| `chainIntegrityDigest` | hash | Unique fingerprint — same chain always produces same digest per nonce |
| `terminalMerkleRoot` | root | Examiner checks against on-chain root history |

The examiner verifies the PLONK proof against the on-chain verifier contract. The proof cryptographically guarantees monotonic narrowing at every hop. The examiner learns **nothing** about intermediate scopes (`0x81`, `0x01`), participant identities, vendor relationships, or pipeline architecture — and **cannot brute-force the public scope commitments** because each is salted with 254 bits of entropy.

**Whistleblower variant:** A journalist receives a delegation chain from a source inside a financial institution. The source generates a `DelegationAuditRollup` proof showing that an AI agent was granted `FINANCIAL_UNLIMITED` permissions and delegated them without narrowing. The journalist can verify this proof on-chain without learning who the source is, which agents were involved, or which institution — only that the chain exists, is anchored in a valid Merkle root, and violated (or upheld) narrowing policy. The blinding salts ensure that even an adversary with the full on-chain agent registry cannot correlate the proof's scope commitments to specific enrolled agents.

## 8. Why the baseline cannot match

| Capability | DelegationAuditRollup | RFC 8693 + BBS+ + WIMSE |
|-----------|----------------------|------------------------|
| **Prove monotonic narrowing over hidden scopes** | Yes — in-circuit bitwise subset constraint at every hop, scopes are private inputs, scope commitments are blinded with per-hop 254-bit salts | No — BBS+ hides claim values but cannot prove `scope_n ⊆ scope_{n-1}` over hidden bitmasks. Auditor must see scope values or trust AS assertion. |
| **Resist brute-force scope recovery** | Yes — blinded Poseidon3 commitments with 254-bit salt; ~192 valid scopes × |enrolled| credential commitments is irrelevant when salt is unknown | No — if BBS+ reveals scope predicates, the small scope domain (~192 values) leaks the bitmask via elimination; if it hides them, it cannot prove ordering |
| **Hide intermediate participants** | Yes — all credential commitments and Merkle paths are private inputs; blinding salts prevent correlation with public Merkle tree leaves; only terminal Merkle root is public | No — RFC 8693 `act` chain is plaintext; BBS+ operates per-credential, not across a multi-issuer chain |
| **Offline-verifiable without AS** | Yes — proof verifies against on-chain PLONK verifier; no AS needed at audit time | No — RFC 8693 narrowing enforcement lives at the AS; auditor must query or trust AS |
| **Cross-org chain in single artifact** | Yes — all hops (including cross-org) are rolled into one proof with one verification | No — cross-org requires federated AS or WIMSE trust anchor that sees all scopes |
| **Journalist/whistleblower anonymity** | Yes — prover generates proof without revealing any participant or institution identity; blinding prevents Merkle tree correlation | No — SPIFFE IDs and `act` chain identify participants; no mechanism for chain-level anonymity |
| **In-circuit enforcement at audit time** | Yes — narrowing is re-proven inside the circuit at audit time, not merely asserted from issuance-time logs | No — AS enforces at issuance; after issuance, only RS-level policy checks apply |
| **Repudiation resistance without identity disclosure** | Yes — each hop's EdDSA signature is verified inside the circuit; the delegation nullifier is deterministic per chain per audit session | Partial — DPoP binds tokens to keys, but proving the binding to an auditor requires disclosing the key |
| **Single proof for N hops** | Yes — one PLONK proof covers 1-8 hops, O(1) verification | No — auditor must inspect N tokens/credentials individually; verification is O(N) |

**The structural gap is irreducible:** BBS+ selective disclosure operates within a single multi-message signature. It cannot express cross-credential arithmetic relationships (like bitwise subset across two hidden bitmasks from different issuers). RFC 8693 delegates enforcement to the AS, making it a mandatory trusted third party. WIMSE provides workload attestation but not scope arithmetic. No composition of these standards produces a single offline-verifiable artifact proving monotonic narrowing over hidden intermediate state across organizational boundaries. The `DelegationAuditRollup` circuit closes this gap by moving the narrowing proof into the constraint system itself, where all intermediate values are private witnesses and the only public outputs are the chain endpoints, length, and integrity digest. The per-hop blinding salt ensures that the small scope domain (~192 valid bitmasks under cumulative-bit constraints) and public credential tree cannot be exploited for brute-force inversion of scope commitments — a gap that would remain even if BBS+ were extended with range predicates, since those predicates would still operate within the ~192-value scope domain without a blinding mechanism.
