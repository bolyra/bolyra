# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies an RS-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of `permissionBitmask` beyond the predicate outcome. The proof is:

- **AS-blind**: generated locally by the agent with no authorization-server roundtrip at presentation time.
- **Constant-size**: a single Groth16 or PLONK proof (~128 or ~256 bytes) regardless of bitmask width or predicate complexity.
- **Runtime-adaptive**: the RS chooses `requiredScopeMask` at the moment of the request; the agent proves satisfaction against whatever mask is demanded without reissuance.
- **Adversarial-AS-resilient**: the RS trusts the on-chain Merkle root and the proving system's knowledge soundness, not the AS's attestation. A compromised AS cannot forge scope satisfaction proofs for agents it did not enroll.
- **Model-identity-bound**: the proof commits to the agent's `modelHash`, `operatorPubKey`, and `permissionBitmask` via a Poseidon5 credential commitment, binding scope satisfaction to a specific runtime identity.

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, and W3C VC/BBS+ can simultaneously achieve all five properties.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `AgentPolicy(MAX_DEPTH=20)`

The construction uses the Bolyra `AgentPolicy` circuit as specified in `draft-bolyra-mutual-zkp-auth-01`, Section 4.2, with three hardening modifications over the base spec: (1) the scope commitment output is session-randomized to prevent cross-presentation linkability, (2) the Merkle leaf is a blinded commitment rather than the raw credential commitment, preventing on-chain observers from recovering `credentialCommitment`, and (3) both the nullifier and scope commitment incorporate the agent's `blindingFactor`, preventing the enrollment authority (operator) from computing these values and breaking Scope Privacy even when operator=AS.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | [0, 2^64) | Agent's full 64-bit permission bitfield |
| `expiryTimestamp` | [0, 2^64) | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `blindingFactor` | F_p | **Per-credential random blinding value** — chosen at enrollment by the agent, kept secret from operator and AS |
| `merkleProofLength` | ≤ 20 | Actual Merkle depth |
| `merkleProofIndex` | [0, 2^20) | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes, zero-padded |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | [0, 2^64) | RS-chosen predicate: which bits must be set |
| `currentTimestamp` | [0, 2^64) | Verifier-supplied wall-clock time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `nullifierHash` | F_p | `Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` — **blinding-hardened** |
| `scopeCommitment` | F_p | `Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)` — **blinding-hardened** |

### Gadgets and constraints

1. **Range checks** — `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. Prevents field-overflow attacks where values ≥ 2^64 pass the circuit but overflow Solidity `uint64`.

2. **Credential commitment** — `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. Binds scope to runtime model identity.

3. **EdDSA signature verification** — `EdDSAPoseidonVerifier(operatorPubKey, credentialCommitment, sig)`. Proves the operator authorized this credential.

4. **Blinded leaf commitment** — `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`. The on-chain Merkle tree stores `leafCommitment`, not `credentialCommitment`. This is the critical privacy hardening: `credentialCommitment` never appears on-chain in the clear. The `blindingFactor` is a random field element chosen by the agent at enrollment time and kept as part of the agent's private credential material alongside the EdDSA signature components.

   **Enrollment protocol (hardened with ZKPoK — see `EnrollmentIntegrity` circuit below):** At enrollment, the agent computes `credentialCommitment` as before, then computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` locally. Before submitting `leafCommitment` to the on-chain registry, the agent generates an `EnrollmentIntegrity` proof π_enroll proving in zero knowledge that `leafCommitment` is correctly formed from a valid, operator-signed credential commitment. The registry's `enroll()` function accepts `(leafCommitment, operatorPubkeyAx, operatorPubkeyAy, π_enroll)` and verifies π_enroll on-chain before inserting `leafCommitment` into the Merkle tree. This prevents insertion of arbitrary leaves — every leaf in the tree is guaranteed to be the blinding of a legitimately signed credential.

5. **Merkle membership** — `BinaryMerkleRoot(20)` with `leafCommitment` as leaf. Proves enrollment in the on-chain agent registry. Note the leaf is the blinded commitment, not the raw credential commitment.

6. **Scope satisfaction (the core selective-disclosure gadget):**
   ```
   permBits[64] = Num2Bits(64)(permissionBitmask)
   reqBits[64]  = Num2Bits(64)(requiredScopeMask)
   for i in [0, 64):
       reqBits[i] * (1 - permBits[i]) === 0
   ```
   This is equivalent to `requiredScopeMask & permissionBitmask == requiredScopeMask`. The RS learns only that the predicate holds, not which additional bits are set.

7. **Cumulative-bit implication closure:**
   ```
   permBits[4] * (1 - permBits[3]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_MEDIUM
   permBits[4] * (1 - permBits[2]) === 0   // FINANCIAL_UNLIMITED → FINANCIAL_SMALL
   permBits[3] * (1 - permBits[2]) === 0   // FINANCIAL_MEDIUM   → FINANCIAL_SMALL
   ```
   Enforces tier hierarchy inside the circuit, not as a policy-layer convention.

8. **Expiry** — `LessThan(64)(currentTimestamp, expiryTimestamp)`. Credential must be live.

9. **Nullifier (blinding-hardened)** — `Poseidon3(credentialCommitment, blindingFactor, sessionNonce)`. Replay detection per session. The inclusion of `blindingFactor` is the critical hardening over the prior construction: even an adversary who knows `credentialCommitment` (e.g., the operator who signed it, or an AS that colluded with the operator at issuance) cannot compute the nullifier without `blindingFactor`. Note: `credentialCommitment` and `blindingFactor` are both private intermediate values — `credentialCommitment` is not on-chain (only `leafCommitment` is) and `blindingFactor` is agent-local. The nullifier therefore leaks neither, since `sessionNonce` is fresh per request and Poseidon3 acts as a PRF under the unknown `blindingFactor` (A5).

10. **Scope commitment (blinding-hardened)** — `Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)`. By including both `blindingFactor` (unknown to the operator/AS) and `sessionNonce` (fresh per request), two presentations by the same agent to different RSes produce distinct `scopeCommitment` values, and no party other than the agent can compute or predict any `scopeCommitment` value.

    **Delegation chain impact:** The on-chain registry stores `(scopeCommitment, sessionNonce)` as the delegation chain seed. The Delegation circuit's chain-linking constraint becomes `Poseidon4(delegatorScope, delegatorCredCommitment, delegatorBlindingFactor, previousSessionNonce) == previousScopeCommitment`, where `previousSessionNonce` and `delegatorBlindingFactor` are supplied as additional private/public inputs respectively. The Delegation circuit also requires a blinded-leaf check: `leafCommitment = Poseidon2(delegateeCredCommitment, delegateeBlindingFactor)` for the delegatee's Merkle membership, with `delegateeBlindingFactor` as an additional private input.

### Circuit: `EnrollmentIntegrity` (new — enrollment-time ZKPoK)

This circuit is verified on-chain at enrollment time, before a leaf is inserted into the agent Merkle tree. It proves that the submitted `leafCommitment` is correctly derived from an operator-signed credential commitment, without revealing the credential fields or blinding factor. This closes the enrollment integrity gap: without this circuit, the registry's `enroll()` function would accept any field element as a leaf, allowing an adversary to insert garbage leaves (denial-of-service on tree capacity) or strategically chosen leaves designed to create Merkle root collisions or other attacks.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of model identifier |
| `permissionBitmask` | [0, 2^64) | Agent's 64-bit permission bitfield |
| `expiryTimestamp` | [0, 2^64) | Credential expiration (Unix seconds) |
| `blindingFactor` | F_p | Agent-chosen blinding value |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `leafCommitment` | F_p | `Poseidon2(credentialCommitment, blindingFactor)` |

**Gadgets and constraints:**

1. **Range checks** — `Num2Bits(64)` on `permissionBitmask` and `expiryTimestamp`. Same overflow prevention as `AgentPolicy`.

2. **Cumulative-bit implication closure** — same three constraints as `AgentPolicy`. Prevents enrollment of credentials with inconsistent permission hierarchies (e.g., `FINANCIAL_UNLIMITED` without `FINANCIAL_MEDIUM`). This is enforced at enrollment time, not just at presentation time, ensuring the Merkle tree never contains a credential that would fail the implication check later.
   ```
   permBits[4] * (1 - permBits[3]) === 0
   permBits[4] * (1 - permBits[2]) === 0
   permBits[3] * (1 - permBits[2]) === 0
   ```

3. **Credential commitment** — `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. Identical computation to `AgentPolicy` constraint 2. Note: `operatorPubkeyAx` and `operatorPubkeyAy` are public inputs here — the registry needs to know which operator authorized this credential (for operator-key governance, e.g., operator key rotation or revocation).

4. **EdDSA signature verification** — `EdDSAPoseidonVerifier(operatorPubKey, credentialCommitment, sig)`. Proves the credential was authorized by the named operator. Identical to `AgentPolicy` constraint 3.

5. **Blinded leaf commitment** — `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`. This is the public output. The circuit proves that the output is structurally correct: it is the Poseidon2 of a valid, operator-signed credential commitment and an agent-chosen blinding factor.

**Why the operator public key is a public input:** The registry contract MAY maintain an allowlist of authorized operator public keys. By making `(operatorPubkeyAx, operatorPubkeyAy)` public, the registry can enforce operator governance on-chain — only leaves signed by authorized operators are admitted to the tree. This does not compromise privacy: the operator's identity is already known at enrollment time (it is the entity submitting the enrollment transaction or authorizing the agent to do so). The private credential fields (`modelHash`, `permissionBitmask`, `expiryTimestamp`, `blindingFactor`) remain hidden.

**On-chain registry change:** The registry's `enroll()` function signature changes from:

```solidity
function enroll(uint256 leafCommitment) external
```

to:

```solidity
function enroll(
    uint256 leafCommitment,
    uint256 operatorPubkeyAx,
    uint256 operatorPubkeyAy,
    uint256[2] calldata proofA,
    uint256[2][2] calldata proofB,
    uint256[2] calldata proofC
) external
```

The function verifies the `EnrollmentIntegrity` proof via the deployed Groth16 verifier contract for this circuit, checks that `(operatorPubkeyAx, operatorPubkeyAy)` is in the authorized-operator set (if governance is enabled), and only then inserts `leafCommitment` into the Merkle tree. The proof's public output (`leafCommitment`) is checked against the `leafCommitment` argument to prevent substitution attacks.

### Verification protocol (RS perspective)

1. RS generates fresh `sessionNonce`, selects `requiredScopeMask` for the requested resource, reads `currentTimestamp`.
2. Agent receives `(requiredScopeMask, currentTimestamp, sessionNonce)` as public inputs.
3. Agent generates proof π locally using private credential material (including `blindingFactor`). **No AS contact.**
4. RS receives `(π, publicSignals[6])`.
5. RS checks:
   - `agentMerkleRoot` ∈ on-chain root history buffer (last 30 roots).
   - `nullifierHash` is fresh (not in used-nonce mapping).
   - `requiredScopeMask` matches what the RS specified.
   - `currentTimestamp` is within acceptable clock skew (e.g., ±30 seconds).
   - Groth16/PLONK verification passes.
6. RS accepts. It learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`. The `scopeCommitment` is opaque and session-unique — the RS cannot correlate it with any other presentation. The `nullifierHash` is likewise session-unique and cannot be traced to any on-chain leaf or to any credential commitment known to the operator.

**Enrollment integrity guarantee consumed at verification time:** The RS does not verify the `EnrollmentIntegrity` proof — that was verified on-chain at enrollment time. The RS's trust in `agentMerkleRoot` (step 5, first check) transitively inherits enrollment integrity: every leaf in the tree was admitted only after a valid `EnrollmentIntegrity` proof was verified by the registry contract. This is the key architectural point — enrollment-time verification is amortized across all subsequent presentations.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The authorization server (AS) — can issue arbitrary tokens, lie about scope membership, collude with other parties. **Crucially, the AS may be the same entity as the operator**, meaning A knows `credentialCommitment` for all agents it enrolled (since it signed them).
- The network between agent and RS — can observe, delay, and replay messages.
- Up to `N-1` of `N` enrolled agents' credential material (corruption threshold).
- Any number of RS endpoints (for cross-RS linkability attacks).
- **Full read access to on-chain state** — including all Merkle tree leaves (which are blinded `leafCommitment` values), all emitted enrollment events, root history, and nonce mappings.
- **The enrollment transaction submission channel** — the adversary may attempt to call the registry's `enroll()` function directly with arbitrary `leafCommitment` values.

The adversary does NOT control:
- The on-chain Merkle root (secured by the underlying L1/L2 consensus).
- The Groth16/PLONK trusted setup (honest-majority ceremony assumption).
- The agent's `blindingFactor` — this is the sole secret the agent holds independent of the operator/AS. Even when operator=AS, the `blindingFactor` is chosen by the agent at enrollment time and never transmitted to the operator, AS, or registry.

**Protocol invariant on `blindingFactor` independence:** The enrollment protocol MUST ensure that `blindingFactor` is generated locally by the agent and never disclosed to the operator or AS. The operator signs `credentialCommitment` (which does not contain `blindingFactor`); the agent then independently computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` and submits `leafCommitment` to the registry alongside an `EnrollmentIntegrity` proof. The operator need not (and must not) learn `blindingFactor` at any point. This is enforced architecturally: the EdDSA signature covers `credentialCommitment`, not `leafCommitment`, so the operator has no reason or ability to participate in blinding-factor generation.

**Protocol invariant on enrollment integrity (new):** The on-chain registry MUST reject any `enroll()` call whose `EnrollmentIntegrity` proof does not verify. This ensures that every leaf in the Merkle tree satisfies the following structural property: there exist `(modelHash, operatorPubKey, permissionBitmask, expiryTimestamp, blindingFactor, sig)` such that (a) `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`, (b) `EdDSA.Verify(operatorPubKey, credentialCommitment, sig) = 1`, (c) `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, and (d) `permissionBitmask` satisfies cumulative-bit implication closure. Without this invariant, the SSU game's reduction (§4) would have an additional case: an adversary inserts a malformed leaf into the tree and later produces a proof against it. The `EnrollmentIntegrity` circuit closes this gap by ensuring malformed leaves are never admitted.

### Game: Selective Scope Unforgeability (SSU)

```
Game SSU(λ):
  1. Setup: Generate CRS for AgentPolicy and EnrollmentIntegrity circuits.
     Deploy on-chain registry with EnrollmentIntegrity verifier gate.
  2. Enrollment: Challenger enrolls honest agent with credential
     (modelHash, operatorPubKey, permissionBitmask*, expiryTimestamp)
     into the Merkle tree. The leaf inserted on-chain is
     leafCommitment = Poseidon2(credentialCommitment*, blindingFactor*),
     where blindingFactor* is chosen uniformly at random by the challenger.
     The challenger produces a valid EnrollmentIntegrity proof π_enroll
     that the registry verifies before inserting the leaf.
  3. Query phase: A may:
     a. Request proofs for any (requiredScopeMask, sessionNonce) where
        permissionBitmask* & requiredScopeMask == requiredScopeMask.
     b. Corrupt any other enrolled agent (obtaining their full credential
        material including blindingFactor).
     c. Compromise the AS entirely.
     d. Read all on-chain state including leafCommitment values.
     e. Attempt to enroll additional agents via the registry's enroll()
        function — each attempt requires a valid EnrollmentIntegrity proof
        (the registry enforces this).
  4. Forgery: A outputs (π*, pubSignals*) for a requiredScopeMask* where
     permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*
     (i.e., the honest agent does NOT satisfy the predicate).
  5. A wins if the on-chain verifier accepts (π*, pubSignals*) with
     agentMerkleRoot matching a valid root containing the honest agent's
     blinded leaf.
```

**Claim:** No PPT adversary wins SSU with non-negligible probability under the assumptions in §4.

**Note on the enrollment integrity strengthening:** In the prior construction, step 3e was unrestricted — the adversary could insert arbitrary leaves. This opened a subtle attack vector: the adversary inserts a carefully crafted leaf `L` that is not the blinding of any operator-signed credential, then produces an `AgentPolicy` proof against a tree root containing `L`. The `AgentPolicy` circuit would verify (it checks Merkle membership, EdDSA signature, and scope satisfaction internally), but the leaf in the tree would not correspond to the credential commitment the circuit witness claims. This is not an attack against `AgentPolicy` soundness (the extracted witness would still contain a valid credential), but it is an attack against *tree integrity*: the tree would contain leaves that waste capacity and whose provenance is unaccountable. More critically, if the registry supports operator-key governance (only authorized operators may enroll agents), then without `EnrollmentIntegrity`, the governance check is unenforceable — anyone could insert any leaf. The `EnrollmentIntegrity` circuit binds governance to the enrollment proof: the operator public key is a public input, and the registry checks it against the authorized set.

### Game: Scope Privacy (SP) — hardened against operator=AS collusion

The prior construction's SP game was vulnerable when the operator and AS are the same entity (or collude): the operator signs `credentialCommitment` during enrollment, so it knows `credentialCommitment` for both challenge agents. Even with blinded on-chain leaves, the operator-AS adversary could compute `Poseidon2(credCommitment_i, sessionNonce)` for each candidate and compare against the public `nullifierHash` output to identify the prover with probability 1.

The blinding-hardened nullifier and scope commitment eliminate this attack: both now incorporate `blindingFactor`, which is unknown to the operator/AS.

```
Game SP(λ):
  1. Setup: as above (including EnrollmentIntegrity verifier on registry).
  2. Challenger enrolls two agents with bitmasks b₀, b₁ where
     b₀ & requiredScopeMask == requiredScopeMask AND
     b₁ & requiredScopeMask == requiredScopeMask
     (both satisfy the predicate, but differ in other bits).
     On-chain leaves are leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)
     and leafCommitment₁ = Poseidon2(credCommitment₁, blind₁).
     Both enrollments include valid EnrollmentIntegrity proofs.
     The operator (possibly = AS) receives credCommitment₀ and
     credCommitment₁ during the signing phase.
  3. Challenger flips coin c ∈ {0,1}, generates proof πc for agent c
     with a fresh sessionNonce chosen by the challenger.
  4. A receives (πc, publicSignals) and has:
     - Full read access to on-chain state (leafCommitment₀, leafCommitment₁).
     - Knowledge of credCommitment₀ and credCommitment₁ (as operator/AS).
     - The EnrollmentIntegrity proofs for both agents (these are on-chain
       transaction data and thus public — but they reveal only leafCommitment
       and operatorPubKey as public signals, not the credential fields or
       blindingFactor, by the zero-knowledge property of Groth16).
     - Does NOT know blind₀ or blind₁.
  5. A outputs guess c'.
  6. A wins if c' = c.
```

**Why the adversary cannot win — even when operator=AS:**

The adversary's view consists of:

- **Operator knowledge:** `credCommitment₀` and `credCommitment₁` (signed both during enrollment). Also knows `b₀` and `b₁` (embedded in the credential commitments).
- **On-chain:** `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and `leafCommitment₁ = Poseidon2(credCommitment₁, blind₁)`.
- **Enrollment proofs (π_enroll₀, π_enroll₁):** By the zero-knowledge property of Groth16 (A6), these proofs reveal nothing about `modelHash`, `permissionBitmask`, `expiryTimestamp`, `blindingFactor`, or the EdDSA signature beyond the public signals (`leafCommitment` and `operatorPubKey`), which the adversary already knows. The enrollment proofs therefore provide no additional distinguishing information.
- **Public signals from the presentation proof:**
  - `agentMerkleRoot`: identical for both candidates (same tree).
  - `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`: the adversary knows `credCommitment₀`, `credCommitment₁`, and `sessionNonce`, but does NOT know `blind₀` or `blind₁`. Computing `Poseidon3(credCommitment_i, blind_i, sessionNonce)` for either candidate requires `blind_i`.
  - `scopeCommitment = Poseidon4(b_c, credCommitment_c, blind_c, sessionNonce)`: same obstruction — requires `blind_c`.
  - `requiredScopeMask`, `currentTimestamp`, `sessionNonce`: identical for both candidates by game construction.

- **Attack via nullifierHash (the attack that broke the prior construction):** The adversary attempts to compute `Poseidon3(credCommitment₀, blind₀, sessionNonce)` and compare against `nullifierHash`. But `blind₀` is unknown. The adversary knows `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and knows `credCommitment₀`. In principle, the adversary could try to recover `blind₀` from `leafCommitment₀` given `credCommitment₀` — this is a Poseidon preimage attack on the second input given the first input, which contradicts A3 (Poseidon preimage resistance). Specifically, finding `x` such that `Poseidon2(credCommitment₀, x) = leafCommitment₀` is exactly the preimage problem for Poseidon2 with one input fixed.

- **Attack via enrollment proof transcript:** The adversary examines the `EnrollmentIntegrity` proof π_enroll_c hoping to extract `blind_c`. By A6, the Groth16 proof is zero-knowledge — it reveals nothing about the private witness beyond the public signals. The public signals are `leafCommitment` (already known) and `operatorPubKey` (already known). No information about `blind_c` leaks from the enrollment proof.

- **Attack via scopeCommitment:** Requires `blind_c`, same obstruction.

- **Cross-referencing leafCommitment against nullifierHash:** The adversary knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)` and `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`. Even knowing `credCommitment_i`, correlating these requires `blind_i`. Under A5 (Poseidon PRF, keyed by `blind_c`), the outputs `Poseidon2(credCommitment_c, blind_c)` and `Poseidon3(credCommitment_c, blind_c, sessionNonce)` are computationally independent to an adversary who does not know `blind_c`.

- **Brute-force on blindingFactor:** `blindingFactor` is a uniformly random element of F_p (≈254 bits). Exhaustive search is infeasible.

**Claim:** Pr[A wins SP] ≤ 1/2 + negl(λ) under Poseidon preimage resistance (A3), Poseidon PRF (A5), and Groth16 zero-knowledge (A6). This holds even when the adversary is the operator and/or AS and knows all `credentialCommitment` values.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Where used |
|----|-----------|------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) | SSU game — extracting witness from valid proof; **Enrollment integrity — extracting witness from enrollment proof** |
| A2 | **Knowledge soundness of PLONK** (universal SRS, ROM) | SSU game (PLONK variant) |
| A3 | **Poseidon collision resistance and preimage resistance** over BN254 scalar field | Merkle membership, credential commitment binding, blinded leaf hiding, **blindingFactor recovery resistance (SP game, operator=AS case)**, **enrollment integrity — credential commitment uniqueness** |
| A4 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability, operator key binding |
| A5 | **Poseidon acts as a PRF** when keyed by the secret / blindingFactor / credential commitment | Nullifier unlinkability across sessions, independence of blinded leaf from nullifier, **operator=AS resistance in SP game** |
| A6 | **Zero-knowledge property of Groth16/PLONK** | Scope Privacy game — Merkle path hiding, **enrollment proof transcript hiding (SP game)** |

### Reduction sketch for SSU (strengthened with enrollment integrity)

1. Suppose A wins SSU with non-negligible probability ε.
2. By A1 (Groth16 knowledge soundness), extract witness `w = (modelHash, operatorPubKey, permissionBitmask', expiryTimestamp, sig, blindingFactor', merkleProof)` from π*.
3. The circuit enforces `reqBits[i] * (1 - permBits'[i]) === 0` for all i ∈ [0,64). So `permissionBitmask' & requiredScopeMask* == requiredScopeMask*`.
4. The circuit enforces `credentialCommitment' = Poseidon5(modelHash, ..., permissionBitmask', expiryTimestamp)`.
5. The circuit enforces `leafCommitment' = Poseidon2(credentialCommitment', blindingFactor')`.
6. The circuit enforces Merkle membership of `leafCommitment'` under `agentMerkleRoot`.
7. Since `agentMerkleRoot` matches a valid on-chain root containing the honest agent's blinded leaf:
   - If `leafCommitment' = leafCommitment*` (honest agent's blinded leaf), then by Poseidon collision resistance (A3) on the blinded-leaf hash, `(credentialCommitment', blindingFactor') = (credentialCommitment*, blindingFactor*)`. Then by Poseidon collision resistance (A3) on the credential commitment hash, `permissionBitmask' = permissionBitmask*`. But we assumed `permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*`. Contradiction.
   - If `leafCommitment' ≠ leafCommitment*`, then A used a different leaf. **By the enrollment integrity invariant**, every leaf in the tree was admitted only after a valid `EnrollmentIntegrity` proof was verified on-chain. By A1 (knowledge soundness of Groth16 applied to the enrollment proof), the extracted enrollment witness for that leaf contains a valid operator EdDSA signature over a well-formed credential commitment with a permission bitmask satisfying cumulative-bit implication closure. Therefore the leaf corresponds to a legitimately enrolled agent — either a corrupted agent (step 3b allows this) or an agent enrolled by the adversary through a valid enrollment. In either case, the adversary is proving scope satisfaction for a credential it controls, not forging against the honest agent's credential. This is not a win condition for SSU (which requires forgery against the honest agent's predicate satisfaction).
8. Therefore ε is negligible. ∎

**Note on the enrollment integrity strengthening (step 7, second case):** Without the `EnrollmentIntegrity` circuit, the adversary in step 7's second case could have inserted an arbitrary leaf `L` into the tree without proving that `L` is the blinding of an operator-signed credential. The `AgentPolicy` circuit would still extract a valid witness (by knowledge soundness), so the SSU reduction would still hold at the cryptographic level. However, the enrollment integrity invariant provides a stronger *compositional* guarantee: the tree itself is well-formed, and every leaf is accountable to a specific operator. This matters for the deployment scenario (§7), where the registry operator needs assurance that tree capacity is consumed only by legitimately authorized agents, and for operator-key governance, where the registry restricts enrollment to a set of authorized operator keys. Without `EnrollmentIntegrity`, these governance properties would be unenforceable.

### Reduction sketch for SP (hardened against operator=AS)

The prior construction's SP argument was broken when operator=AS: the operator knows `credentialCommitment` for both challenge agents (having signed them) and could compute `Poseidon2(credCommitment_i, sessionNonce)` for each, comparing against the public `nullifierHash` to win with probability 1. The blinding-hardened construction interposes `blindingFactor` — unknown to the operator — into both `nullifierHash` and `scopeCommitment`, eliminating this attack.

**Argument:**

1. The adversary (as operator/AS) knows `credCommitment₀`, `credCommitment₁`, `b₀`, `b₁`, and all public inputs including `sessionNonce`. The adversary also reads `leafCommitment₀` and `leafCommitment₁` from on-chain state. The adversary has the `EnrollmentIntegrity` proof transcripts for both agents (on-chain). The adversary does NOT know `blind₀` or `blind₁`.

2. The public signals from proof πc are:
   - `agentMerkleRoot`: identical for both candidates (same tree).
   - `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`: to evaluate this for candidate i, the adversary needs `blind_i`.
   - `scopeCommitment = Poseidon4(b_c, credCommitment_c, blind_c, sessionNonce)`: same obstruction.
   - `requiredScopeMask`, `currentTimestamp`, `sessionNonce`: identical for both candidates.

3. **Recovery of `blind_i` from `leafCommitment_i`:** The adversary knows `credCommitment_i` and `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)`. Recovering `blind_i` requires finding `x` such that `Poseidon2(credCommitment_i, x) = leafCommitment_i`. This is a preimage problem on the second input of Poseidon2 with the first input fixed — precisely the setting covered by A3 (Poseidon preimage resistance). Under A3, no PPT adversary can recover `blind_i`.

4. **Recovery of `blind_i` from the enrollment proof transcript:** The adversary has π_enroll_i, whose public signals are `leafCommitment_i`, `operatorPubkeyAx`, and `operatorPubkeyAy` — all already known to the adversary. By A6 (Groth16 zero-knowledge), the proof reveals nothing about the private witness (`modelHash`, `permissionBitmask`, `expiryTimestamp`, `blindingFactor`, `sig`) beyond the public signals. Therefore π_enroll_i provides no information about `blind_i`.

5. **Distinguishing without `blind_i`:** Without `blind_c`, the adversary cannot compute `Poseidon3(credCommitment_c, blind_c, sessionNonce)` for either candidate. The adversary's view of `nullifierHash` is a Poseidon3 evaluation under the unknown key `blind_c`. Under A5 (Poseidon PRF keyed by `blind_c`), the function `f(credCommitment, sessionNonce) = Poseidon3(credCommitment, blind_c, sessionNonce)` is a pseudorandom function from the adversary's perspective. Two evaluations under different keys (`blind₀` vs `blind₁`) are computationally indistinguishable from random — the adversary cannot determine which key produced the observed output.

6. **Cross-referencing `leafCommitment_i` against `nullifierHash`:** The adversary knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)` and `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`. Even with `credCommitment_i` known, correlating the two Poseidon evaluations requires `blind_i` as a common link. Under A5 (PRF keyed by `blind_c`), the outputs are computationally independent from the adversary's perspective.

7. By A6 (Groth16 zero-knowledge), the presentation proof π itself reveals nothing about the witness beyond the public signals — in particular, the Merkle proof path (which leaf index was used) is hidden.

8. Therefore Pr[A wins SP] ≤ 1/2 + negl(λ). ∎

**Multi-session extension:** Even across multiple presentations by the same agent, each `nullifierHash` and `scopeCommitment` incorporates a fresh `sessionNonce`, producing distinct values per session. Cross-session correlation would require recovering `blindingFactor` to verify that two nullifiers share the same `(credentialCommitment, blindingFactor)` prefix — which requires breaking A3. The blinding factor remains constant across sessions (it is per-credential, not per-session), but it is never exposed: it appears only as a private witness inside the circuit and is protected by Poseidon preimage resistance at the `leafCommitment` layer.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Hash function | Poseidon over BN254 scalar field | §2.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | §4.2 |
| Blinded leaf commitment | `Poseidon2(credentialCommitment, blindingFactor)` — replaces raw leaf | §4.2 (hardened) |
| Enrollment integrity proof | `EnrollmentIntegrity` circuit — ZKPoK at enrollment time | New (this refinement) |
| Scope satisfaction | Bitwise AND via `Num2Bits(64)` + per-bit constraint | §4.2, constraint 5 |
| Cumulative-bit closure | Implication constraints on bits 2/3/4 | §4.2, constraint 6 |
| Operator binding | `EdDSAPoseidonVerifier` on Baby Jubjub | §4.2, constraint 3 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash, leaf = blinded commitment | §4.2, constraint 4 |
| Nullifier | `Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` — **blinding-hardened** | §4.2 (hardened) |
| Scope commitment | `Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)` — **blinding-hardened** | §3, §4.2 (hardened) |
| Proving system (primary) | Groth16 with project `pot16.ptau` Phase 1 | §2.3 |
| Proving system (optional) | PLONK universal setup | §2.3 |
| Root history | 30-entry circular buffer on-chain | §2.1 |

**Spec divergence notes:**
1. The IETF draft (§3, §4.2) defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. This construction upgrades to `Poseidon4` with `blindingFactor` and `sessionNonce` as additional inputs.
2. The IETF draft defines `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`. This construction upgrades to `Poseidon3` with `blindingFactor` as an additional input.
3. The IETF draft inserts `credentialCommitment` directly as the Merkle leaf. This construction interposes a blinding layer: `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` is inserted instead. The blinding factor is agent-local and never transmitted to the AS, operator, or registry — only `leafCommitment` is submitted at enrollment.
4. **New in this refinement:** The IETF draft's enrollment is an unguarded Merkle insertion. This construction gates enrollment behind an on-chain `EnrollmentIntegrity` proof verification, ensuring every leaf is the blinding of an operator-signed, cumulative-bit-valid credential. The circuit uses only existing Bolyra primitives (Poseidon5, Poseidon2, EdDSAPoseidonVerifier, Num2Bits).
5. All changes are backwards-compatible with the on-chain registry interface: the registry stores field elements as leaves regardless of their internal structure, and `sessionNonce` is already stored per handshake. The `enroll()` function gains proof verification parameters but the Merkle tree structure is unchanged. The Delegation circuit's chain-linking constraint is updated to `Poseidon4(delegatorScope, delegatorCredCommitment, delegatorBlindingFactor, previousSessionNonce) == previousScopeCommitment`, with `delegatorBlindingFactor` as an additional private input. Delegatee enrollment uses `leafCommitment = Poseidon2(delegateeCredCommitment, delegateeBlindingFactor)`.

## 6. Circuit cost estimate

### Constraint breakdown for `AgentPolicy(MAX_DEPTH=20)`

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Num2Bits(64)` × 3 (bitmask, expiry, timestamp) | 192 |
| `Poseidon5` (credential commitment) | ~1,200 |
| `EdDSAPoseidonVerifier` | ~6,500 |
| `Poseidon2` (blinded leaf commitment) | ~300 |
| `BinaryMerkleRoot(20)` (20 × Poseidon2 + MUX) | ~12,000 |
| Scope satisfaction (64 per-bit constraints) | 64 |
| Cumulative-bit implication (3 constraints) | 3 |
| `LessThan(64)` (expiry check) | ~130 |
| `Poseidon3` (blinding-hardened nullifier) | ~300 |
| `Poseidon4` (blinding-hardened scopeCommitment) | ~450 |
| **Total** | **~21,139** |

### Constraint breakdown for `EnrollmentIntegrity` (new)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Num2Bits(64)` × 2 (bitmask, expiry) | 128 |
| Cumulative-bit implication (3 constraints) | 3 |
| `Poseidon5` (credential commitment) | ~1,200 |
| `EdDSAPoseidonVerifier` | ~6,500 |
| `Poseidon2` (blinded leaf commitment) | ~300 |
| **Total** | **~8,131** |

The `EnrollmentIntegrity` circuit is significantly smaller than `AgentPolicy` because it omits the Merkle tree traversal (the leaf has not been inserted yet), scope satisfaction check, expiry comparison, and session-bound nullifier/scope-commitment outputs. It is a pure well-formedness proof: "this leaf is the blinding of a signed, valid credential."

Both circuits fit comfortably under 2^16 = 65,536 constraints; `pot16.ptau` sufficiency is unchanged. The `EnrollmentIntegrity` circuit requires its own Groth16 Phase 2 ceremony (a separate `.zkey` file), but uses the same Phase 1 `pot16.ptau`.

### Proving time targets

| Circuit | Proving system | Target | Platform | When |
|---------|---------------|--------|----------|------|
| `AgentPolicy` | Groth16 (snarkjs, WASM) | < 5 s | Browser / Node.js | Each RS request |
| `AgentPolicy` | Groth16 (rapidsnark, native) | < 0.5 s | Server-side agent | Each RS request |
| `AgentPolicy` | PLONK (snarkjs) | < 5 s | Server-side agent | Each RS request |
| `EnrollmentIntegrity` | Groth16 (snarkjs, WASM) | < 2 s | Browser / Node.js | Once per enrollment |
| `EnrollmentIntegrity` | Groth16 (rapidsnark, native) | < 0.2 s | Server-side agent | Once per enrollment |

The `EnrollmentIntegrity` proof is generated once at enrollment time — its cost is amortized across all subsequent presentations. Even in the slowest case (browser WASM), 2 seconds is negligible for an enrollment operation.

### Proof size

| Circuit | System | Proof size | Public signals |
|---------|--------|-----------|---------------|
| `AgentPolicy` | Groth16 | 128 bytes | 6 × 32 bytes = 192 bytes |
| `AgentPolicy` | PLONK | ~256 bytes | 6 × 32 bytes = 192 bytes |
| `EnrollmentIntegrity` | Groth16 | 128 bytes | 3 × 32 bytes = 96 bytes |

**AgentPolicy on-wire total: 320–448 bytes** (unchanged from prior construction). The `EnrollmentIntegrity` proof adds 128 + 96 = 224 bytes to the enrollment transaction, a one-time cost.

## 7. Concrete deployment scenario

### Scenario: Federated Credit Union Agent Authorization

**Stakeholder:** A CUSO (Credit Union Service Organization) operating a shared data platform across 200 member credit unions, regulated under NCUA §701.27 (third-party due diligence).

**Setup:**
- Each credit union operates AI agents (loan underwriting, fraud detection, member service) with varying permission levels.
- The CUSO's shared platform hosts APIs for member PII lookup, transaction history, and inter-CU wire initiation.
- Permissions span 8 tiers (Bolyra's cumulative-bit encoding): `READ_DATA` through `ACCESS_PII`.

**Problem the baseline cannot solve:**
- The CUSO cannot run a single centralized AS trusted by all 200 CUs — each CU's compliance officer insists on independent credential issuance.
- An agent from CU-A accessing CU-B's member data via the shared platform must prove `READ_DATA ∧ ACCESS_PII` without revealing that it also holds `FINANCIAL_UNLIMITED` (a competitive signal).
- The CUSO platform (RS) must verify authorization without trusting any individual CU's AS — a CU could be compromised and issue inflated tokens.
- **Operator=AS privacy (addressed by blinding hardening):** In the CUSO federated model, each CU acts as both the operator (signing agent credentials) and the AS (issuing authorization). Without blinding-hardened nullifiers and scope commitments, a CU that enrolled two of its own agents could determine which of them made a specific API call by computing `Poseidon2(credCommitment_i, sessionNonce)` for each and comparing against the public `nullifierHash`. This breaks intra-CU agent privacy — a CU's compliance department could track individual agent behavior even when the platform is designed to provide anonymous authorization. With blinding-hardened public signals, the CU-as-operator knows `credCommitment` but not `blindingFactor`, so it cannot compute `Poseidon3(credCommitment, blindingFactor, sessionNonce)`. Each agent maintains privacy from its own operator/AS.

**Bolyra deployment (with enrollment integrity hardening):**
1. The CUSO deploys the on-chain registry with both the `AgentPolicy` and `EnrollmentIntegrity` Groth16 verifier contracts. The registry's `enroll()` function is gated by `EnrollmentIntegrity` proof verification. The CUSO maintains an authorized-operator-key set, initially populated with each member CU's operator public key.
2. Each CU enrolls its agents by: (a) the CU's operator signs `credentialCommitment` with its EdDSA key, (b) the agent locally generates `blindingFactor` and computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, (c) the agent generates an `EnrollmentIntegrity` proof proving that `leafCommitment` is the blinding of a credential signed by the CU's operator key, (d) the enrollment transaction submits `(leafCommitment, operatorPubKey, π_enroll)` to the registry, which verifies the proof and checks the operator key against the authorized set before inserting the leaf.
3. **Enrollment integrity guarantee in the CUSO context:** Without the `EnrollmentIntegrity` circuit, a compromised CU could insert arbitrary leaves into the shared tree — consuming tree capacity (griefing the other 199 CUs) or inserting leaves that bypass the operator-key governance check. With the circuit, every leaf is provably the blinding of a credential signed by an authorized operator. The CUSO's compliance team can audit operator-key governance (which CU keys are authorized) without being able to determine what permissions any specific leaf encodes.
4. When CU-A's fraud-detection agent calls the CUSO platform's `/member/transactions` endpoint, the platform returns `requiredScopeMask = 0b10000001` (bits 0 and 7: `READ_DATA | ACCESS_PII`).
5. The agent generates a Groth16 proof locally (rapidsnark, < 0.5 s) proving its bitmask satisfies the mask. The CUSO platform learns only that the predicate holds — not whether the agent also holds `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, or `SUB_DELEGATE`. The `scopeCommitment` and `nullifierHash` are unique to this session and cannot be correlated with on-chain enrollment data, prior accesses, or the operator's knowledge of the credential commitment.
6. The platform checks `agentMerkleRoot` against the on-chain root history buffer. No AS is contacted. No CU's AS is trusted. The platform's trust in the root transitively inherits enrollment integrity — every leaf was verified at insertion.
7. The agent's credential expiry is enforced inside the circuit. Revocation is handled by updating the Merkle tree (removing the blinded leaf).

**Regulatory value:** NCUA examiners can audit the on-chain enrollment registry (verifying that agents are enrolled by authorized operator keys via the `EnrollmentIntegrity` proof) without being able to correlate enrollment entries with individual API access events. Even the enrolling CU itself — acting as operator and AS — cannot perform this correlation without the agent's `blindingFactor`. This separation satisfies both NCUA §701.27 third-party due diligence (the registry proves agents are enrolled by authorized operators, with enrollment integrity cryptographically enforced) and GLBA §501(b) safeguard requirements (individual access patterns remain private). The blinding-hardened construction ensures that even a subpoena for on-chain data *and* operator records does not reveal which enrolled agent made which API call — that linkage requires the agent's private `blindingFactor`, which can be disclosed per-agent under appropriate legal process without compromising other agents' privacy.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8707 + DPoP + BBS+) fails on six properties that this construction achieves simultaneously. No subset or composition of the baseline stack can close these gaps.

### Gap 1: AS-blind presentation

In the baseline, the AS is the sole authority that determines and attests to the agent's scope. Even with jwt-introspection-response caching, the AS was contacted at issuance and at first introspection. The agent cannot present a selective scope proof to a *new* RS without the AS having been involved for that audience (RFC 8707 requires audience-specific token issuance). BBS+ allows holder-driven selective disclosure over discrete claims, but the AS still issues the original BBS+ signature — a compromised AS can refuse to sign, or sign incorrect claims.

**Bolyra construction:** The agent generates proofs locally against an on-chain Merkle root. The operator signed the credential at enrollment time; no AS is contacted at presentation time. The agent chooses which `requiredScopeMask` to prove against at runtime, without reissuance.

### Gap 2: Runtime-adaptive bitmask predicate with implication closure

The baseline's scope model is string-based (`scope: "read write financial_small"`). Predicate evaluation is string-set membership, not bitwise Boolean logic. BBS+ supports equality and range predicates over hidden attributes, but bitwise AND over a 64-bit field with implication closure (bit 4 ⟹ bits 3 and 2) requires arithmetic-circuit-level evaluation. No BBS+ extension in `draft-irtf-cfrg-bbs-signatures` or `vc-di-bbs` supports this.

**Bolyra construction:** The `AgentPolicy` circuit evaluates `reqBits[i] * (1 - permBits[i]) === 0` for all 64 bits and enforces cumulative-bit implication constraints inside the R1CS. The predicate is evaluated over the hidden bitmask at proof time, not fixed at issuance.

### Gap 3: Adversarial-AS model

The baseline's trust anchor is the AS's signing key. A compromised AS can assert that an agent holds scopes it does not, or deny scopes it does hold. The RS has no cryptographic recourse — it verifies only that "the AS said X," not that X is true.

**Bolyra construction:** The trust anchor is the on-chain Merkle root (consensus-secured) and the Groth16 knowledge soundness guarantee. The proof extracts a witness containing a valid credential commitment that is a leaf (blinded) in the tree. No party — including the entity that enrolled the agent — can forge a proof for a bitmask that does not satisfy the predicate without breaking Poseidon collision resistance or Groth16 soundness. The AS is not in the trust path. **Enrollment integrity hardening (this refinement)** further strengthens adversarial-AS resilience: even a compromised AS cannot insert malformed or unsigned leaves into the tree, because every insertion requires a valid `EnrollmentIntegrity` proof. The AS can enroll agents with whatever permissions it chooses (this is the AS's prerogative), but it cannot insert leaves that are not the blinding of a properly signed credential — the tree's structural integrity is cryptographically enforced, not policy-enforced.

### Gap 4: Constant-size proof regardless of permission-space cardinality

In the baseline, jwt-introspection-response size scales linearly with disclosed scopes. BBS+ derived proof size scales with `O(|disclosed|)`. For a permission space with 64 independent bits (2^64 theoretical combinations), enumeration-based approaches are infeasible.

**Bolyra construction:** The Groth16 proof is 128 bytes. The PLONK proof is ~256 bytes. Neither depends on the number of bits in `permissionBitmask`, the number of bits set in `requiredScopeMask`, or the cardinality of the permission space.

### Gap 5: Cryptographic binding to runtime model identity

The baseline's `client_id` is a static string registered at the AS. It does not bind the token to a specific model hash, operator key, or permission state at the moment of a specific API call.

**Bolyra construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` binds the scope proof to a specific model, a specific operator, and a specific permission state. The EdDSA signature over this commitment proves the operator authorized this exact combination. **Enrollment integrity hardening** ensures this binding is verified at enrollment time — the `EnrollmentIntegrity` circuit recomputes `Poseidon5` and verifies the EdDSA signature inside the proof, so the on-chain leaf is guaranteed to encode a valid model-identity binding, not just any field element.

### Gap 6: Full credential privacy from all parties including the operator/AS

BBS+ presentations are unlinkable at the RS layer. However, the issuer (AS/operator) who signed the credential knows the full credential content. In any system where the credential identifier or commitment is used as input to deterministic functions producing public outputs, the issuer can compute those outputs and correlate presentations. This is not a BBS+-specific limitation — it is a fundamental property of any credential system where the issuer knows the credential content.

**Bolyra construction (blinding-hardened):** Both `nullifierHash = Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` and `scopeCommitment = Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)` incorporate `blindingFactor`, which is generated solely by the agent and never disclosed to the operator, AS, or any other party. The operator knows `credentialCommitment` but cannot compute either public signal without `blindingFactor`. The on-chain observer sees only `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, from which recovering `blindingFactor` requires breaking Poseidon preimage resistance (A3). The `EnrollmentIntegrity` proof transcript (on-chain) is zero-knowledge (A6) and reveals only `leafCommitment` and `operatorPubKey` — no additional information about `blindingFactor` leaks from enrollment. Privacy holds against the operator, the AS (even when operator=AS), the RS, and all on-chain observers simultaneously.

BBS+ cannot match this property because the issuer always knows the signed credential content and can correlate any deterministic function of that content with public presentation artifacts. The Bolyra construction introduces an agent-controlled secret (`blindingFactor`) that the issuer never sees, creating a cryptographic separation between issuance knowledge and presentation artifacts that has no analog in the BBS+ architecture.

### Summary: simultaneous achievement

| Property | RFC 7662 stack | BBS+ layer | Bolyra AgentPolicy |
|----------|---------------|------------|-------------------|
| AS-blind presentation | No | No (AS signs credential) | **Yes** |
| Runtime-adaptive bitmask predicate | No | Partial (no bitwise AND) | **Yes** |
| Adversarial-AS resilience | No | No (AS trust anchor) | **Yes** |
| Constant-size proof | No | O(\|disclosed\|) | **Yes** (128–256 bytes) |
| Model-identity binding | No | No | **Yes** |
| Full credential privacy (incl. operator/AS) | No | No (issuer knows content) | **Yes** |
| Enrollment integrity (tree well-formedness) | N/A (no tree) | N/A (no tree) | **Yes** (EnrollmentIntegrity ZKPoK) |
| All properties simultaneously | **Impossible** | **Impossible** | **Yes** |

The baseline can achieve subsets (BBS+ gives selective disclosure; DPoP gives sender binding; jwt-introspection-response gives offline verification), but no composition achieves all six. The fundamental barrier is architectural: the baseline stack trusts the AS as the scope authority, while this construction trusts the proving system and the on-chain enrollment root. These are incompatible trust models — you cannot retrofit AS-independence onto a stack whose security definition requires AS honesty. The blinding-hardened construction closes the last remaining gap where operator/AS knowledge of `credentialCommitment` compromised the privacy guarantee, and the enrollment integrity hardening ensures the on-chain tree — the construction's trust anchor — admits only well-formed, operator-signed, cumulative-bit-valid leaves, achieving cryptographic separation between enrollment authority knowledge and presentation artifacts without introducing any additional trusted party, ceremony, or on-chain storage beyond a single additional Groth16 verifier contract.
