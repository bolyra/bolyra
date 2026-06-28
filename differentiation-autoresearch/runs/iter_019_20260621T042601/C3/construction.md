# Construction

## 1. Statement of claim

An auditor verifies that an N-hop delegation chain narrowed permissions monotonically — every hop's scope is a bitwise subset of its predecessor's, every hop's expiry is no later, and every delegatee is an enrolled agent — without learning any intermediate scope values, participant identities, or credential commitments. The only public outputs are the chain seed (from the initial handshake), the final scope commitment, the chain length, and a replay-detection digest. The construction applies to multi-tool AI pipelines, cross-org agent handoffs, and journalist/source delegation chains where intermediate node anonymity is mandatory.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationAuditChain(MAX_HOPS, MAX_DEPTH)`

**Parameters:** MAX_HOPS = 4, MAX_DEPTH = 20 (matching agent Merkle tree depth).

**Private inputs (per hop i ∈ [0, MAX_HOPS)):**

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScope[i]` | 64-bit | Delegator permission bitmask at hop i |
| `delegateeScope[i]` | 64-bit | Delegatee permission bitmask at hop i |
| `delegatorExpiry[i]` | 64-bit | Delegator expiry timestamp |
| `delegateeExpiry[i]` | 64-bit | Delegatee expiry timestamp |
| `delegatorCredCommitment[i]` | field | Delegator's Poseidon5 credential commitment |
| `delegateeCredCommitment[i]` | field | Delegatee's Poseidon5 credential commitment |
| `delegatorPubkeyAx[i]`, `delegatorPubkeyAy[i]` | field | Delegator EdDSA public key |
| `sigR8x[i]`, `sigR8y[i]`, `sigS[i]` | field | Delegator EdDSA signature over delegation token |
| `delegateeMerkleProofLength[i]` | field | Merkle proof depth |
| `delegateeMerkleProofIndex[i]` | field | Leaf index |
| `delegateeMerkleProofSiblings[i][MAX_DEPTH]` | field[] | Sibling hashes |
| `hopActive[i]` | bit | 1 if hop i is active, 0 if padding |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `chainSeedScopeCommitment` | Scope commitment from the initial handshake (on-chain) |
| `sessionNonce` | Session binding value |
| `currentTimestamp` | Verifier-supplied current time |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `finalScopeCommitment` | Poseidon2(delegateeScope[last], delegateeCredCommitment[last]) |
| `chainLength` | Count of active hops (sum of hopActive bits) |
| `auditDigest` | Poseidon chain of per-hop nullifiers (replay detection) |
| `narrowingValid` | 1 if all active hops satisfy monotonic narrowing |

### Gadgets used

1. **Poseidon2, Poseidon4, Poseidon5** — standard Bolyra hash gadgets for scope commitments, delegation tokens, and credential commitments.
2. **EdDSAPoseidonVerifier** — verifies delegator signature over delegation token per hop.
3. **BinaryMerkleRoot(MAX_DEPTH)** — proves delegatee enrollment in agent tree.
4. **Num2Bits(64)** — range checks on scopes, expiries.
5. **LessEqThan(64)** — expiry narrowing comparison.
6. **Bitwise subset gate** — `delegateeBits[j] * (1 - delegatorBits[j]) === 0` for each bit j ∈ [0, 64).
7. **Cumulative bit encoding gate** — enforces implication rules on bits 2/3/4.
8. **Conditional constraint multiplexer** — gates all per-hop constraints on `hopActive[i]`, so inactive hops impose no requirements beyond padding consistency.

### Constraint logic (per active hop i)

```
// 0. Boolean enforcement and contiguous-prefix constraint
hopActive[i] * (1 - hopActive[i]) === 0          // hopActive is 0 or 1
if i > 0:
    hopActive[i] * (1 - hopActive[i-1]) === 0     // CONTIGUOUS PREFIX:
                                                   // hop i active ⟹ hop i-1 active

// 1. Range checks
Num2Bits(64)(delegatorScope[i])
Num2Bits(64)(delegateeScope[i])
Num2Bits(64)(delegatorExpiry[i])
Num2Bits(64)(delegateeExpiry[i])

// 2. Chain linking — connects hop i to previous state
let expectedPrev = Poseidon2(delegatorScope[i], delegatorCredCommitment[i])
if i == 0:
    hopActive[i] * (expectedPrev - chainSeedScopeCommitment) === 0
else:
    let prevOut = Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])
    hopActive[i] * (expectedPrev - prevOut) === 0

// 3. Bitwise subset (scope narrowing)
for j in 0..64:
    hopActive[i] * delegateeBits[j] * (1 - delegatorBits[j]) === 0

// 4. Cumulative bit encoding on delegatee scope
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[3]) === 0
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[2]) === 0
hopActive[i] * delegateeBits[3] * (1 - delegateeBits[2]) === 0

// 5. Expiry narrowing
hopActive[i] * LessEqThan(64)(delegateeExpiry[i], delegatorExpiry[i]) === 1

// 6. Delegation token and EdDSA signature
let token = Poseidon4(expectedPrev, delegateeCredCommitment[i],
                       delegateeScope[i], delegateeExpiry[i])
hopActive[i] * EdDSAPoseidonVerifier(
    delegatorPubkeyAx[i], delegatorPubkeyAy[i],
    token, sigR8x[i], sigR8y[i], sigS[i]) === 1

// 7. Delegatee enrollment
let root_i = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[i], merkleProof[i])
// root_i is consumed internally, not output — auditor never sees it

// 8. Per-hop nullifier for audit digest
let hopNullifier = Poseidon2(token, sessionNonce)
```

### Contiguous-prefix invariant

The constraint `hopActive[i] * (1 - hopActive[i-1]) === 0` for all i > 0 enforces that the active hops form a contiguous prefix of the hop array. Concretely:

- If `hopActive[i] = 1` then `hopActive[i-1]` must equal 1.
- By induction, `hopActive[k] = 1` for any k implies `hopActive[j] = 1` for all j < k.
- The only valid activation patterns are: `[0,0,0,0]`, `[1,0,0,0]`, `[1,1,0,0]`, `[1,1,1,0]`, `[1,1,1,1]`.

This prevents **non-contiguous hop splicing** (Attack 1): without this constraint, an adversary could set `hopActive = [1, 0, 1, 0]`, causing hop 1 to be unchecked while hop 2's chain-linking constraint is gated off by `hopActive[2] = 1` but references a `prevOut` from hop 1 whose scope narrowing was never enforced. The contiguous-prefix rule eliminates this by ensuring every active hop has an active, fully-constrained predecessor.

Combined with the boolean constraint `hopActive[i] * (1 - hopActive[i]) === 0`, this yields exactly `MAX_HOPS + 1` valid configurations, each representing a contiguous prefix of length 0 through MAX_HOPS.

The constraint cost is negligible: one multiplication gate per hop for i > 0, totaling 3 additional constraints for MAX_HOPS = 4.

### Audit digest computation

The audit digest chains per-hop nullifiers into a single value the auditor can check against an on-chain replay registry:

```
auditDigest[0] = hopNullifier[0]
for i in 1..MAX_HOPS:
    auditDigest[i] = hopActive[i] ?
        Poseidon2(auditDigest[i-1], hopNullifier[i]) :
        auditDigest[i-1]
auditDigest = auditDigest[MAX_HOPS - 1]
```

### Final scope commitment

```
// Walk backward from last active hop
finalScopeCommitment = Poseidon2(delegateeScope[lastActive],
                                  delegateeCredCommitment[lastActive])
```

Where `lastActive` is determined by the highest index where `hopActive[i] = 1`. Because active hops now form a contiguous prefix, `lastActive = chainLength - 1`, which simplifies implementation: the prover selects the output of hop `chainLength - 1` via a multiplexer over the known-contiguous prefix.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:
- Up to N-1 of N participants in the delegation chain (colluding delegators/delegatees).
- The auditor's query interface (A can submit arbitrary public inputs).
- Network observation of all proof transcripts.

The adversary sees:
- All public outputs: `finalScopeCommitment`, `chainLength`, `auditDigest`, `narrowingValid`.
- The `chainSeedScopeCommitment` and `sessionNonce` (public inputs).
- The PLONK/Groth16 proof π.

The adversary does NOT control:
- The Poseidon hash function (modeled as random oracle in security argument).
- The CRS/SRS (trusted setup assumption for Groth16; universal setup for PLONK).
- The on-chain verifier contract.

### Security games

**Game 1 — Narrowing Soundness:** A wins if it produces a valid proof π where some active hop i has `delegateeScope[i] ⊄ delegatorScope[i]` (a delegatee permission bit is set that the delegator's permission bit is not).

**Game 1a — Non-Contiguous Splice (subsumed by Game 1 after fix):** A wins if it produces a valid proof π with a non-contiguous `hopActive` pattern (e.g., `[1, 0, 1, 0]`) that allows an unchecked hop to appear between two checked hops, enabling a scope expansion that the auditor cannot detect. *This attack is now precluded by the contiguous-prefix constraint: `hopActive[i] * (1 - hopActive[i-1]) === 0` for i > 0 forces all active hops into a gapless prefix, ensuring every active hop's narrowing constraints are enforced and chain-linked to its predecessor.*

**Game 2 — Participant Privacy:** A (playing as auditor) wins if, given two candidate chains C₀ and C₁ with identical (chainLength, finalScopeCommitment, chainSeedScopeCommitment) but different intermediate participants, A can distinguish which chain produced the proof with advantage > negligible.

**Game 3 — Scope Privacy:** A (playing as auditor) wins if, given proof π and all public outputs, A can recover any intermediate `delegatorScope[i]` or `delegateeScope[i]` for 0 ≤ i < chainLength with probability > 1/2^64 + negl(λ).

**Game 4 — Chain Integrity:** A wins if it produces a valid proof π where the chain of scope commitments does not form a contiguous sequence starting from `chainSeedScopeCommitment`, i.e., the prover "splices in" a hop that was not authorized by the delegator at that position.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **A1: Knowledge soundness of Groth16** (resp. PLONK) in the algebraic group model. Any PPT prover that produces a valid proof knows a witness satisfying all circuit constraints.
- **A2: Collision resistance of Poseidon** over the BN254 scalar field with the concrete instantiation used by Bolyra (t=3 for Poseidon2, t=5 for Poseidon4, t=6 for Poseidon5). Modeled as a random oracle for the PRF arguments.
- **A3: Discrete logarithm hardness on Baby Jubjub** (subgroup of order l ≈ 2^251 embedded in BN254).
- **A4: Existential unforgeability of EdDSA-Poseidon** under chosen-message attack, reduced to A3.

### Reduction sketches

**Theorem 1 (Narrowing Soundness).** If A wins Game 1 with non-negligible probability, then either (a) knowledge soundness of the proving system is broken (contradicting A1), or (b) A found a Poseidon collision for the scope commitment (contradicting A2).

*Sketch:* By A1, a valid proof implies the prover knows values satisfying all constraints. Constraint (3) enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` for every bit j in every active hop. If any delegatee bit is set where the delegator bit is not, this constraint evaluates to a nonzero value, which the verifier rejects. The constraint is gated on `hopActive[i]`, so it applies to all declared-active hops. The contiguous-prefix constraint (constraint 0, second line) ensures that no active hop can exist without all preceding hops also being active — this forecloses the non-contiguous splice vector where an adversary skips enforcement on an intermediate hop by setting its `hopActive` to 0 while activating a later hop. Since the prefix is contiguous, the chain-linking constraint (2) at each active hop i references a fully-constrained predecessor: either `chainSeedScopeCommitment` (at i=0) or the output of hop i-1 (which is itself active and therefore narrowing-checked). Scope cannot be inflated between hops without breaking the Poseidon2 preimage (requiring a collision, contradicting A2).

**Corollary 1a (Non-Contiguous Splice Prevention).** The contiguous-prefix constraint `hopActive[i] * (1 - hopActive[i-1]) === 0` combined with the boolean constraint `hopActive[i] * (1 - hopActive[i]) === 0` restricts the witness space to exactly MAX_HOPS + 1 valid activation patterns (contiguous prefixes of length 0 through MAX_HOPS). Any witness with a gap in the `hopActive` vector fails the contiguous-prefix constraint at the first gap-to-active transition, producing a nonzero constraint that the verifier rejects. No cryptographic assumption is needed for this property — it is a purely algebraic consequence of the constraint system.

**Theorem 2 (Participant Privacy).** Game 2 reduces to zero-knowledge of the proving system.

*Sketch:* All participant identities — `delegatorCredCommitment[i]`, `delegateeCredCommitment[i]`, `delegatorPubkeyAx/Ay[i]` — are private inputs. By the zero-knowledge property of Groth16/PLONK, the proof reveals nothing about private inputs beyond what is implied by the public outputs. Since both candidate chains C₀ and C₁ share identical public outputs by game definition, the simulator produces indistinguishable transcripts.

**Theorem 3 (Scope Privacy).** Game 3 reduces to Poseidon preimage resistance (implied by A2).

*Sketch:* The only public output related to scope is `finalScopeCommitment = Poseidon2(delegateeScope[last], delegateeCredCommitment[last])`. Recovering `delegateeScope[last]` requires inverting Poseidon2, which contradicts collision resistance (and, under ROM, preimage resistance). Intermediate scopes are strictly private inputs and are covered by the ZK argument in Theorem 2.

**Theorem 4 (Chain Integrity).** If A wins Game 4, then either A1 or A2 is broken.

*Sketch:* Constraint (2) requires `Poseidon2(delegatorScope[i], delegatorCredCommitment[i]) = previousScopeCommitment` for each active hop. At hop 0, `previousScopeCommitment = chainSeedScopeCommitment` (a public input anchored on-chain from the handshake). The contiguous-prefix invariant guarantees that every hop between 0 and the last active hop is itself active, so the chain-linking constraint is enforced without gaps. Splicing in an unauthorized hop requires producing a `(delegatorScope, delegatorCredCommitment)` pair that hashes to the on-chain scope commitment without possessing the original delegator's credential — this is a Poseidon preimage attack (contradicting A2). The EdDSA signature constraint (6) further requires the delegator's private key to sign the delegation token, so even a Poseidon preimage would not suffice without also forging an EdDSA signature (contradicting A4).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4, Identity-Bound Scope Commitment Chain |
| Delegation token | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | §4.2, Delegation Circuit, constraint 6 |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | §3.2, Agent Proof Specification |
| EdDSA signature | EdDSA on Baby Jubjub over Poseidon hash | §2, Cryptographic Primitives |
| Merkle membership | BinaryMerkleRoot(20) with Poseidon2 node hash | §2, Merkle Tree |
| Nullifier | `Poseidon2(delegationToken, sessionNonce)` | §1, Terminology (adapted for delegation) |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | §3.2, AgentPolicy constraint 6 |
| Proving system | PLONK with universal setup (pot16.ptau) | §2, Proving Systems (PLONK OPTIONAL for Delegation) |
| Chain seed | `lastScopeCommitment[sessionNonce]` from on-chain registry | §4, step 1 |
| Replay prevention | `auditDigest` checked against on-chain used-audit-digest mapping | New — extends §3.1 nonce freshness pattern |

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints | Count per hop |
|--------|-------------|---------------|
| Num2Bits(64) × 4 (scopes + expiries) | 256 | 256 |
| Poseidon2 (chain linking) | ~300 | 300 |
| Poseidon4 (delegation token) | ~600 | 600 |
| Bitwise subset (64 multiply gates) | 64 | 64 |
| Cumulative bit encoding (3 gates) | 3 | 3 |
| LessEqThan(64) (expiry) | ~130 | 130 |
| EdDSAPoseidonVerifier | ~5,500 | 5,500 |
| BinaryMerkleRoot(20) | ~6,000 | 6,000 |
| Poseidon2 (hop nullifier) | ~300 | 300 |
| Conditional gating (hopActive mux) | ~200 | 200 |
| Boolean + contiguous-prefix | 2 | 2 |
| **Subtotal per hop** | | **~13,355** |

### Aggregate circuit

| Component | Constraints |
|-----------|-------------|
| 4 hops × 13,355 | 53,420 |
| Audit digest chain (3 Poseidon2 + mux) | ~1,100 |
| Final scope commitment selection | ~500 |
| Chain length summation | ~20 |
| **Total** | **~55,040** |

This fits within the 2^16 = 65,536 constraint budget of `pot16.ptau`. The contiguous-prefix constraint adds 3 multiplication gates total (one per hop for i ∈ {1, 2, 3}), a negligible 0.005% increase over the prior estimate.

### Proving time targets

| Proving system | Target | Rationale |
|---|---|---|
| PLONK (agent/delegation family) | < 5 seconds | Matches Bolyra PLONK agent target; universal setup avoids per-circuit ceremony |
| Groth16 (optional, if ceremony run) | < 8 seconds | Larger circuit than single Delegation but well within 15s human budget |

For production deployments with rapidsnark, expect ~1.5s Groth16 / ~3s PLONK on commodity hardware based on Bolyra benchmark ratios at the 50K-constraint scale.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder:** Navy Federal Credit Union (NFCU), the largest US credit union with 13M+ members, regulated by NCUA.

**Setting:** NFCU deploys an AI agent pipeline for member loan processing:

1. **Hop 0 (Handshake):** A member authenticates via Bolyra mutual handshake. The member's human proof establishes identity; the front-desk agent's AgentPolicy proof establishes `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bits 0,1,2,7 = 0b10000111). The agent's scope commitment becomes the chain seed.

2. **Hop 1:** Front-desk agent delegates to a credit-scoring agent with narrowed scope `READ_DATA | FINANCIAL_SMALL` (bits 0,2 = 0b00000101). PII access is stripped. Expiry narrowed from 24h to 1h.

3. **Hop 2:** Credit-scoring agent delegates to a rate-lookup agent with scope `READ_DATA` only (bit 0 = 0b00000001). Financial permissions stripped entirely. Expiry narrowed to 15 minutes.

4. **Hop 3:** Rate-lookup agent delegates to a market-data agent with scope `READ_DATA` (bit 0 = 0b00000001). Expiry narrowed to 5 minutes. Cross-org hop — market data is provided by a third-party fintech.

**Audit event:** NCUA examiner requests proof that no agent in the pipeline exceeded its authorized scope and that permissions narrowed monotonically, without NFCU revealing the specific permission bitmasks at each hop (which encode internal authorization policy — competitive intelligence) or the identities of the specific agent instances (which encode infrastructure topology).

**What the examiner receives:**
- `chainSeedScopeCommitment`: the on-chain anchor from the handshake (verifiable against the registry)
- `finalScopeCommitment`: the terminal agent's scope commitment
- `chainLength = 3`
- `auditDigest`: a single hash the examiner checks against the on-chain replay registry
- `narrowingValid = 1`
- The PLONK proof π

**What the examiner does NOT receive:**
- Any intermediate scope bitmask (0b10000111, 0b00000101, 0b00000001)
- Any credential commitment, operator public key, or model hash
- Any Merkle proof path revealing tree position
- The identity of the third-party fintech at hop 3

**Verification:** The examiner calls `DelegationAuditVerifier.verifyProof(π, publicSignals)` on-chain or off-chain (the verifier contract is public). Verification is O(1) regardless of chain length — a single pairing check for Groth16 or a single polynomial commitment check for PLONK.

### Why the contiguous-prefix constraint matters for this scenario

Without the contiguous-prefix constraint, a malicious prover could construct a witness with `hopActive = [1, 0, 1, 0]`, declaring hops 0 and 2 as active while marking hop 1 as inactive. Hop 1's narrowing constraints would be gated off, allowing the credit-scoring agent (hop 1) to hold *any* permissions — including scope expansion beyond the front-desk agent's bitmask — without detection. The auditor would see `chainLength = 2` and `narrowingValid = 1`, believing only two properly-narrowed hops occurred, while the actual chain had three hops with an unchecked middle segment. The contiguous-prefix constraint eliminates this vector entirely: if hop 2 is active, hop 1 must be active, and therefore hop 1's narrowing constraints are enforced.

### Journalist/source variant

A journalist's AI agent delegates to a source's AI agent through two intermediary agents (editorial tool, secure drop tool). The auditor (editorial board) verifies the delegation chain narrowed correctly without learning the source's agent identity or the intermediary tool identities. The `auditDigest` prevents the same chain from being replayed in a different editorial context. Intermediate node anonymity is cryptographically guaranteed by the ZK property — even a compromised auditor learns nothing about hops 1 and 2.

## 8. Why the baseline cannot match

| Capability | DelegationAuditChain | RFC 8693 + BBS+ + WIMSE |
|---|---|---|
| **Prove monotonic narrowing over hidden scopes** | In-circuit bitwise subset constraint on private inputs; auditor sees only `narrowingValid = 1`. Contiguous-prefix invariant ensures no hop can be skipped to evade narrowing enforcement. | Requires disclosing scope values to auditor or trusting AS attestation. BBS+ hides individual claims but cannot prove ordering/containment relationships over hidden bitmasks. |
| **Hide intermediate participants** | All credential commitments, public keys, and Merkle paths are private inputs; ZK property guarantees zero leakage | RFC 8693 `act` chain is plaintext. BBS+ operates within a single credential, not across a multi-issuer chain. WIMSE SPIFFE IDs are stable identifiers visible to verifiers. |
| **No trusted third party** | Proof is self-verifying against on-chain state. No AS, no federation anchor. Anyone with the verifier contract can check. | RFC 8693 narrowing enforcement lives at the AS. Auditor must trust or query the AS. AS compromise breaks the guarantee. |
| **Cross-org without shared trust anchor** | Each hop's delegatee enrollment is proven against the global agent Merkle tree. No per-org AS or federation required. The third-party fintech at hop 3 is just another enrolled agent. | Cross-org delegation requires shared AS or WIMSE federation trust anchor that sees all scopes. No standard produces a single cross-org narrowing artifact. |
| **Journalist/source anonymity** | Intermediate nodes are private inputs with information-theoretic hiding (in the ZK model). Even a malicious auditor with unbounded compute learns nothing. | OIDC PPIDs prevent RS-vs-RS correlation but not AS or auditor correlation via `act` chain. No mechanism to prove "a legitimate holder participated" without identifying them. |
| **In-circuit enforcement at verification time** | Narrowing is proven at proof-generation time AND verified at proof-verification time. The contiguous-prefix constraint ensures the proof is invalid if *any* hop — including intermediate hops — violated narrowing. No runtime policy check needed. | AS enforces narrowing only at token issuance. After issuance, a token can be presented to any accepting RS with no runtime narrowing check unless the RS independently validates. |
| **O(1) verification regardless of chain length** | Single pairing check (Groth16) or polynomial check (PLONK). Verification cost is constant whether the chain has 1 hop or 4. | Auditor must walk the `act` tree, verify each BBS+ derived proof, and check each WIMSE attestation. Verification is O(N) in chain length. |
| **Replay prevention without identity exposure** | `auditDigest` — a Poseidon hash chain of per-hop nullifiers — is checked against an on-chain registry. The nullifiers themselves stay hidden. | RFC 9449 DPoP sender-constrains tokens but the key thumbprint is visible. Replay detection requires examining token contents. |

The fundamental gap is structural: the baseline's narrowing guarantee is an **assertion by a trusted authority** (the AS), while DelegationAuditChain's narrowing guarantee is a **mathematical proof over hidden values**. No composition of RFC 8693, BBS+, and WIMSE can produce a proof of an arithmetic relationship (bitwise subset) over values that are simultaneously hidden from the verifier — this requires a circuit, which is precisely what this construction provides.
