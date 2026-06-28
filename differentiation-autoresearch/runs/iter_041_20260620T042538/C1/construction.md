# Construction

## 1. Statement of claim

An AI agent holding a 64-bit cumulative permission bitmask proves to a resource server (RS) that `permissionBitmask & requiredMask == requiredMask` — i.e., every bit the RS demands is set — without the RS learning any other bit of the bitmask, without any Authorization Server (AS) roundtrip at proof time, and in a setting where the AS itself may be adversarial (lying about or withholding the agent's actual permissions). The proof is constant-size (3 G1 + 1 G2 elements for Groth16, or ~192 bytes) regardless of bitmask width, and binds to the agent's runtime model identity (model hash, operator key, credential commitment).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, and W3C VC + BBS+ can simultaneously achieve AS-blindness, adversarial-AS soundness, bitwise predicate evaluation over a committed bitmask with implication closure, constant-size proof, and runtime model binding.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `SelectiveScopeProof`

This is a specialization of the existing `AgentPolicy` circuit that makes the selective-disclosure property explicit as a standalone verifiable artifact an RS can check without the full handshake.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Poseidon hash of the model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration (Unix) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint | Actual Merkle proof depth |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Merkle sibling hashes |
| `blindingNonce` | field | Random per-presentation blinding for unlinkability |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Verifier-attested current time |
| `agentMerkleRoot` | field | On-chain agent tree root (RS reads from registry) |
| `sessionNonce` | field | Fresh per-request nonce from RS |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeSatisfied` | bit | Always 1 if proof verifies (forced by constraint) |
| `blindedNullifier` | field | `Poseidon2(Poseidon2(credentialCommitment, sessionNonce), blindingNonce)` |
| `scopeCommitment` | field | `Poseidon2(permissionBitmask, credentialCommitment)` |

### Constraint system (gadgets)

```
// G1: Range checks
permBits[64] = Num2Bits(64)(permissionBitmask)
reqBits[64]  = Num2Bits(64)(requiredScopeMask)
Num2Bits(64)(expiryTimestamp)
Num2Bits(64)(currentTimestamp)

// G2: Credential commitment
credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx,
    operatorPubkeyAy, permissionBitmask, expiryTimestamp)

// G3: EdDSA signature verification (operator signed this credential)
EdDSAPoseidonVerifier(
    enabled=1,
    Ax=operatorPubkeyAx, Ay=operatorPubkeyAy,
    S=sigS, R8x=sigR8x, R8y=sigR8y,
    M=credentialCommitment
)

// G4: Merkle membership (credential is enrolled on-chain)
computedRoot = BinaryMerkleRoot(20)(
    leaf=credentialCommitment,
    depth=merkleProofLength,
    index=merkleProofIndex,
    siblings=merkleProofSiblings
)
computedRoot === agentMerkleRoot

// G5: Selective scope satisfaction (bitwise predicate)
for i in 0..63:
    reqBits[i] * (1 - permBits[i]) === 0
// Every required bit must be present in the actual bitmask.
// The RS learns ONLY that the predicate holds, not which
// unrequired bits are set.

// G6: Cumulative bit implication closure
permBits[4] * (1 - permBits[3]) === 0
permBits[4] * (1 - permBits[2]) === 0
permBits[3] * (1 - permBits[2]) === 0

// G7: Expiry check
LessThan(64)(currentTimestamp, expiryTimestamp) === 1

// G8: Nullifier (replay prevention)
rawNullifier = Poseidon2(credentialCommitment, sessionNonce)
blindedNullifier = Poseidon2(rawNullifier, blindingNonce)

// G9: Scope commitment (for optional delegation chain entry)
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)

// G10: Force public output
scopeSatisfied <== 1  // tautological if proof verifies
```

### Verification protocol (RS-side)

1. RS generates fresh `sessionNonce`, reads `agentMerkleRoot` from on-chain registry (or a cached signed root).
2. RS sends `(requiredScopeMask, currentTimestamp, agentMerkleRoot, sessionNonce)` to the agent.
3. Agent generates Groth16 proof π using private credential data.
4. Agent sends `(π, pubSignals)` to RS.
5. RS verifies: `Groth16.Verify(vkey, pubSignals, π)` — checks that `agentMerkleRoot` matches on-chain, `sessionNonce` matches its challenge, `currentTimestamp` is within tolerance, and `scopeSatisfied == 1`.
6. No AS was contacted. RS is convinced.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:

- The Authorization Server (can forge introspection responses, lie about scope)
- Network between agent and RS (can intercept, replay, modify messages)
- Up to `n - 1` colluding agents in the Merkle tree
- Observation of all prior proof transcripts to/from this RS and other RSes

The adversary does NOT control:

- The on-chain registry contract (Merkle roots are public, immutable once posted)
- The Groth16 CRS (trusted setup is assumed honest)
- The agent's EdDSA private key or secret credential fields

### Security game: Selective Scope Unforgeability

**Game SSU(λ):**

1. Challenger runs `Setup(1^λ)` → CRS, deploys registry with empty agent tree.
2. Challenger enrolls `n` agents with known credential commitments.
3. A is given the CRS, the verification key, all public signals from prior proofs, and oracle access to an adversarial AS.
4. A outputs `(π*, pubSignals*)` for a `requiredScopeMask*` and a `sessionNonce*` it has not queried before.
5. A wins if `Groth16.Verify(vkey, pubSignals*, π*) = 1` AND the credential commitment embedded in the proof either:
   - (a) is not a leaf in the agent Merkle tree at root `agentMerkleRoot*`, OR
   - (b) corresponds to an agent whose actual `permissionBitmask & requiredScopeMask* ≠ requiredScopeMask*`, OR
   - (c) corresponds to an agent whose credential has expired (`expiryTimestamp ≤ currentTimestamp*`).

**Claim:** `Pr[A wins SSU(λ)] ≤ negl(λ)` under the assumptions in §4.

### Security game: Scope Privacy

**Game SP(λ):**

1. Challenger enrolls two agents with bitmasks `b₀` and `b₁` such that `b₀ & requiredMask == requiredMask` and `b₁ & requiredMask == requiredMask` but `b₀ ≠ b₁`.
2. Challenger flips coin `c ∈ {0, 1}`, generates proof `π_c` for agent `c`.
3. A is given `(π_c, pubSignals)` and must output guess `c'`.
4. A wins if `c' = c`.

**Claim:** `|Pr[c' = c] - 1/2| ≤ negl(λ)` — the proof reveals nothing about which unrequired bits are set.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Application |
|----|-----------|-------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + algebraic group model) | Extracting valid witness from any accepting proof |
| A2 | **Collision resistance of Poseidon** over BN254 scalar field | Binding of credential commitment, scope commitment, nullifier |
| A3 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability — cannot forge operator signature |
| A4 | **Zero-knowledge property of Groth16** (simulation-based) | Unrequired permission bits are hidden from verifier |

### Reduction sketch for SSU

Suppose adversary A wins SSU with non-negligible probability ε.

**Case (a) — non-member proof:** By A1 (knowledge soundness), we can extract a witness containing `credentialCommitment` and a valid Merkle proof to `agentMerkleRoot*`. If `credentialCommitment` is not a leaf, we have found a Poseidon collision in the Merkle path computation (the extracted path authenticates a non-existent leaf to a valid root). This contradicts A2.

**Case (b) — scope violation:** The extracted witness contains `permissionBitmask` and `requiredScopeMask`. Constraint G5 forces `reqBits[i] * (1 - permBits[i]) === 0` for all i. If the predicate fails on the actual bitmask, the constraint is unsatisfied — the proof should not verify. An accepting proof with an unsatisfied constraint breaks knowledge soundness (A1).

**Case (c) — expired credential:** Constraint G7 forces `currentTimestamp < expiryTimestamp` via LessThan(64). Same argument as case (b) via A1.

### Reduction sketch for SP

By the zero-knowledge property of Groth16 (A4), there exists a simulator S that, given only the public signals (which include `requiredScopeMask` but NOT `permissionBitmask`), produces proofs computationally indistinguishable from real proofs. Since `permissionBitmask` is a private input and does not appear in any public output (the `scopeCommitment` output hides it behind Poseidon, and different bitmasks with the same required bits produce different scope commitments but the adversary cannot invert Poseidon by A2), distinguishing `b₀` from `b₁` requires either breaking ZK (A4) or inverting Poseidon (A2).

Note on `scopeCommitment`: this output does leak a deterministic function of `permissionBitmask`. If the RS sees multiple presentations with different `scopeCommitment` values, it learns they come from agents with different (bitmask, credential) pairs, but not which bits differ. If full unlinkability is required, the `blindedNullifier` construction (G8) provides per-session randomization, and `scopeCommitment` can be omitted from the public outputs when delegation chaining is not needed.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---------------------|-----------------|--------|
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` | `AgentPolicy` circuit, spec §3.2 |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | Spec §2 (Terminology) |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Spec §2.2 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Spec §2.2 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | Spec §3.2 |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | Spec §3.2, CLAUDE.md permissions model |
| Proving system | Groth16 (REQUIRED) with PLONK as OPTIONAL alternative | Spec §2.3 |
| On-chain root | Agent root history buffer (30-entry circular) | Spec §3.1 |

The `SelectiveScopeProof` circuit is a refactored `AgentPolicy` — same constraint set but packaged for standalone RS verification without the mutual handshake wrapper. All gadgets reuse existing Bolyra circuit components. No new primitives are introduced.

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|--------|----------------------|
| `Num2Bits(64)` × 4 (bitmask, reqMask, expiry, timestamp) | 256 |
| `Poseidon5` (credential commitment) | ~300 |
| `EdDSAPoseidonVerifier` | ~6,500 |
| `BinaryMerkleRoot(20)` (20 Poseidon2 hashes + muxes) | ~3,200 |
| Scope satisfaction (64 multiplication constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon2` × 3 (nullifier, blinded nullifier, scope commitment) | ~450 |
| **Total** | **~10,900** |

This fits well within `pot16.ptau` (2^16 = 65,536 constraint capacity).

**Proving time targets:**

- Groth16 (snarkjs, browser/Node): ~3–5s on commodity hardware (10.9K constraints is modest)
- Groth16 (rapidsnark, native): <500ms
- PLONK alternative: <2s (rapidsnark), <5s (snarkjs) — within agent budget

**Proof size:** 3 G1 + 1 G2 = 192 bytes (Groth16). Constant regardless of bitmask width — a 64-bit mask and a hypothetical 1024-bit mask produce identically sized proofs (the wider mask adds only linear constraints, not proof size).

## 7. Concrete deployment scenario

**Stakeholder:** Navy Federal Credit Union (NFCU) — largest US credit union, 13M+ members.

**Scenario:** NFCU deploys an AI agent gateway for member-facing financial operations. Agents act on behalf of members (balance inquiries, bill pay, loan applications). NFCU's compliance team requires that an agent proves it holds `FINANCIAL_SMALL` (bit 2) authorization before accessing the bill-pay API, but NFCU's bill-pay RS must NOT learn whether the agent also holds `ACCESS_PII` (bit 7) or `SIGN_ON_BEHALF` (bit 5) — those permissions are relevant to other NFCU services but would create a liability if logged by the bill-pay service under GLBA §501(b) data minimization requirements.

**Current pain (RFC 7662 path):** NFCU's AS returns a scope string `"financial_small"` to the bill-pay RS via introspection. But:

1. The AS is a single point of trust — if the AS is compromised, it can silently escalate an agent's scope or deny legitimate agents.
2. The AS must maintain per-RS filtering policies for every (agent, RS) pair. With 50 internal services and 10,000 enrolled agents, the policy table has 500,000 entries.
3. BBS+ selective disclosure could hide individual claims, but cannot evaluate the cumulative-bit implication (`FINANCIAL_SMALL` requires bit 2, which `FINANCIAL_MEDIUM` at bit 3 implies). BBS+ treats claims as independent — it has no bitwise AND with implication closure.

**Bolyra path:** The agent generates a `SelectiveScopeProof` with `requiredScopeMask = 0x04` (bit 2). The bill-pay RS verifies the Groth16 proof against the on-chain Merkle root. The RS learns: (1) the agent is enrolled, (2) bit 2 is set, (3) the credential is unexpired, (4) an authorized operator signed the credential. The RS does NOT learn bits 0, 1, 3–7. No AS was contacted. The proof is 192 bytes. The agent's full permission state never leaves the agent's local proving environment.

**Compliance win:** GLBA data minimization is satisfied cryptographically, not by AS policy configuration. An auditor can verify the circuit constraints enforce minimum disclosure — no human policy-table maintenance required.

## 8. Why the baseline cannot match

| Property | SelectiveScopeProof | RFC 7662 + BBS+ Baseline | Gap |
|----------|--------------------|--------------------------|----|
| **AS-blind presentation** | Agent proves directly to RS. No AS roundtrip. AS is never contacted at proof time. | AS must issue the token and define the introspection response. Even cached JWT introspection required AS at issuance. Agent cannot choose disclosure subset at runtime without AS pre-configuring it. | Architectural: ZK proof is self-contained; OAuth is AS-mediated by design. |
| **Adversarial-AS soundness** | Proof validity depends on on-chain Merkle root and Groth16 soundness. A malicious AS cannot forge a credential commitment in the tree without the operator's EdDSA key. RS trusts math, not the AS. | RS trusts the AS's signed assertion. Malicious AS can lie about scope membership. RS has no independent verification path. | Fundamental: OAuth introspection is an assertion protocol; Bolyra is a proof protocol. |
| **Bitwise predicate with implication closure** | Constraint G5 evaluates `reqBits[i] * (1 - permBits[i]) === 0` for all 64 bits inside the proof. Constraint G6 enforces cumulative encoding (bit 4 → bits 3, 2). The predicate is evaluated over committed private data. | BBS+ supports equality/range predicates over individual claims. It does not support bitwise AND over a multi-bit field, nor implication closure across hierarchical permission tiers. Each BBS+ claim is independent. | Expressiveness: BBS+ predicates are per-claim; Bolyra predicates are over a committed bitfield with structural invariants. |
| **Constant-size proof** | 192 bytes (Groth16). Invariant to bitmask width. A 64-bit and 1024-bit permission space produce same proof size. | JWT introspection response grows with scope count. BBS+ derived proof grows as `O(|disclosed claims|)`. For 2^64 theoretical permissions, scope enumeration is infeasible. | Complexity-theoretic: ZK proof size is determined by the proving system, not the statement's input size. |
| **Runtime model identity binding** | `credentialCommitment = Poseidon5(modelHash, Ax, Ay, bitmask, expiry)` — the proof cryptographically commits to which model, which operator key, and which permission state. | `client_id` is a static string. No binding to model hash or runtime operator key at inference time. DPoP binds to a key but not to model identity. | Semantic: OAuth has no concept of "which model is running right now." |
| **Cross-RS unlinkability** | `blindedNullifier = Poseidon2(rawNullifier, blindingNonce)` — each presentation uses a fresh blinding nonce. Two presentations of the same credential to different RSes are unlinkable (under Poseidon PRF assumption). No AS-level correlation since AS is not contacted. | BBS+ presentations are unlinkable at the RS layer, but the AS that issued the credential can correlate issuance events. Removing AS from the loop entirely is not possible in the OAuth model. | Partial overlap with BBS+ at RS layer, but Bolyra eliminates AS-layer correlation entirely. |

**The core impossibility:** RFC 7662 and its extensions are *assertion protocols* — the RS believes what a trusted party (AS) tells it. Bolyra's `SelectiveScopeProof` is a *proof protocol* — the RS verifies a mathematical statement about committed data. No amount of composing assertion protocols produces proof-level guarantees in the adversarial-AS model, because the trust anchor is the AS itself. When the AS is the adversary, assertions are worthless. Groth16 knowledge soundness holds regardless of who issued the credential, because the proof extracts to a valid witness or the Merkle root doesn't match the on-chain state.
