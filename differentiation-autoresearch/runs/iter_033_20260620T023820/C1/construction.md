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

**Protocol invariant on enrollment integrity:** The on-chain registry MUST reject any `enroll()` call whose `EnrollmentIntegrity` proof does not verify. This ensures that every leaf in the Merkle tree satisfies the following structural property: there exist `(modelHash, operatorPubKey, permissionBitmask, expiryTimestamp, blindingFactor, sig)` such that (a) `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`, (b) `EdDSA.Verify(operatorPubKey, credentialCommitment, sig) = 1`, (c) `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, and (d) `permissionBitmask` satisfies cumulative-bit implication closure. Without this invariant, the SSU game's reduction (§4) would have an additional case: an adversary inserts a malformed leaf into the tree and later produces a proof against it. The `EnrollmentIntegrity` circuit closes this gap by ensuring malformed leaves are never admitted.

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

- **Joint-output correlation attack (the attack that A5 must formally exclude):** The adversary has *two* outputs computed under the same `blind_c`: the on-chain `leafCommitment_c = Poseidon2(credCommitment_c, blind_c)` and the presentation-time `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`. Both share `(credCommitment_c, blind_c)` as common inputs. Even though recovering `blind_c` from either output alone is hard (A3), the adversary might hope to *correlate* the two outputs without recovering `blind_c` — for example, by detecting a statistical relationship between `Poseidon2(x, k)` and `Poseidon3(x, k, n)` for the same `(x, k)`. This is precisely the attack that assumption A5 (Joint-Output Poseidon PRF, defined formally in §4) excludes: under A5, the triple `(Poseidon2(x, k), Poseidon3(x, k, n), Poseidon4(w, x, k, n))` is computationally indistinguishable from three independent random values, even when `x`, `w`, and `n` are adversary-chosen. The formal game JOPRF (§4) captures this joint-output setting with adaptive queries, ensuring that no PPT adversary can exploit the shared key `k = blind_c` across different Poseidon arities.

- **Brute-force on blindingFactor:** `blindingFactor` is a uniformly random element of F_p (≈254 bits). Exhaustive search is infeasible.

**Claim:** Pr[A wins SP] ≤ 1/2 + negl(λ) under Joint-Output Poseidon PRF security (A5), Poseidon preimage resistance (A3), and Groth16 zero-knowledge (A6). This holds even when the adversary is the operator and/or AS and knows all `credentialCommitment` values. The formal reduction is in §4.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Formal game | Where used |
|----|-----------|-------------|------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) | Standard AGM+ROM extraction | SSU game — extracting witness from valid proof; Enrollment integrity — extracting witness from enrollment proof |
| A2 | **Knowledge soundness of PLONK** (universal SRS, ROM) | Standard AGM+ROM extraction | SSU game (PLONK variant) |
| A3 | **Poseidon collision resistance and preimage resistance** over BN254 scalar field | Standard CR/Preimage games | Merkle membership, credential commitment binding, blinded leaf hiding, blindingFactor recovery resistance (SP game, operator=AS case), enrollment integrity — credential commitment uniqueness |
| A4 | **Discrete logarithm hardness on Baby Jubjub** | Standard DL game | EdDSA unforgeability, operator key binding |
| A5 | **Joint-Output Poseidon PRF (JOPRF)** — Poseidon evaluations under a shared secret key are jointly indistinguishable from random, even across different arities | Game JOPRF(λ) defined below | SP game — joint indistinguishability of `(leafCommitment, nullifierHash, scopeCommitment)` under shared `blindingFactor`; cross-session unlinkability |
| A6 | **Zero-knowledge property of Groth16/PLONK** | Standard simulator-based ZK | Scope Privacy game — Merkle path hiding, enrollment proof transcript hiding (SP game) |

### Formal definition of A5: Joint-Output Poseidon PRF (JOPRF)

**Motivation.** The SP game's reduction requires that an adversary who observes `Poseidon2(x, k)`, `Poseidon3(x, k, n)`, and `Poseidon4(w, x, k, n)` — all sharing the same unknown key `k` and adversary-known inputs `x, w, n` — cannot distinguish these from independent random values. A standard single-oracle PRF definition is insufficient because: (a) it does not cover correlated evaluations across different Poseidon arities sharing the same key, and (b) it does not model the adversary's ability to choose `x`, `w`, `n` adaptively while observing outputs from all three oracles. The JOPRF game below formalizes the exact joint-output structure that appears in the construction, where `k = blindingFactor`, `x = credentialCommitment`, `w = permissionBitmask`, and `n = sessionNonce`.

```
Game JOPRF(λ):
  1. Setup: Sample key k ←$ F_p uniformly at random.
     Flip coin b ←$ {0, 1}.
     If b = 0 (real world):
       O₂(x)       := Poseidon2(x, k)
       O₃(x, n)    := Poseidon3(x, k, n)
       O₄(w, x, n) := Poseidon4(w, x, k, n)
     If b = 1 (ideal world):
       O₂, O₃, O₄ are independent lazy-sampled random functions
       of matching input arity (O₂ : F_p → F_p, O₃ : F_p² → F_p,
       O₄ : F_p³ → F_p), consistent across repeated queries with
       the same inputs.

  2. Query phase: A makes adaptive queries to any of (O₂, O₃, O₄)
     with adversary-chosen inputs. Total query count q = poly(λ).

  3. Output: A outputs guess b'.

  4. Advantage: Adv^JOPRF_Poseidon(A) := |Pr[b' = b] - 1/2|.
```

**Assumption A5:** For all PPT adversaries A, `Adv^JOPRF_Poseidon(A) ≤ negl(λ)`.

**Discussion of A5's relationship to standard assumptions:**

1. **Subsumes single-oracle PRF.** Restricting the adversary to query only O₃ (with key in the second position) recovers the standard PRF game for Poseidon3 keyed by the second argument. A5 is strictly stronger.

2. **Why single-oracle PRF is insufficient.** In the SP game, the adversary simultaneously observes `leafCommitment = Poseidon2(credCommitment_c, blind_c)` (from on-chain enrollment) and `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)` (from the presentation proof). These are evaluations of *different functions* (Poseidon2 vs Poseidon3) at *overlapping inputs* sharing the same key `blind_c`. A standard PRF game for Poseidon3 does not model the adversary's access to `Poseidon2(·, k)` as a side channel. If Poseidon2 and Poseidon3 were structurally related — for instance, if `Poseidon3(x, k, n) = Poseidon2(Poseidon2(x, k), n)` — then an O₂ query would yield a prefix of the O₃ computation, trivially breaking PRF security. Poseidon's actual round-function structure does not exhibit this composition, but ruling out subtler correlations requires the joint game.

3. **Plausibility argument.** Poseidon with different input arities uses *different MDS matrices, different round constants, and different internal state widths* (Poseidon2 uses a `t=3` state, Poseidon3 uses `t=4`, Poseidon4 uses `t=5`). The round constants are derived independently per arity via a CSPRNG seeded with `(p, t, alpha, M, rounds_f, rounds_p)` where `t` differs. The full-round/partial-round structure processes inputs through distinct permutations π₂, π₃, π₄ over different-dimensional state spaces. This structural independence — different permutations over different state dimensions with independently derived constants — is the basis for treating cross-arity evaluations as uncorrelated. No known algebraic attack on Poseidon exploits cross-arity correlations, and the Poseidon authors' security analysis (Grassi et al., 2019) models each arity as an independent permutation. A5 formalizes this independence as a falsifiable assumption.

4. **Relationship to the Random Permutation Model (RPM).** In the ideal-permutation model — where Poseidon's internal permutation for each arity is modeled as an independent random permutation — JOPRF holds unconditionally (up to a birthday-bound term `O(q²/|F_p|)` from lazy sampling collisions). A5 is the concrete-instantiation analog: it posits that Poseidon's algebraic permutation inherits this independence in the standard model, for PPT adversaries.

5. **Falsifiability.** A5 is a concrete, falsifiable assumption: any algebraic relation `R(Poseidon2(x, k), Poseidon3(x, k, n)) = 0` holding for all `k` with adversary-known `(x, n)` would constitute a break. The Poseidon hash analysis literature (Grassi et al., Keller & Rosemarin, Bariant et al.) has not identified any such relation across arities.

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

### Reduction sketch for SP (hardened against operator=AS — now grounded in JOPRF)

The prior construction's SP argument relied on an informal statement that "Poseidon acts as a PRF keyed by blindingFactor" without defining a game that covers the joint-output structure. This refinement replaces that hand-wave with a formal reduction to the JOPRF game (A5), which explicitly models the adversary's access to correlated Poseidon outputs across arities.

**Reduction: SP-adversary → JOPRF-distinguisher.**

Given a PPT adversary A that wins SP with advantage ε, we construct a PPT distinguisher D that wins JOPRF with advantage ≥ ε/2.

**Construction of D:**

1. D receives oracle access to `(O₂, O₃, O₄)` from the JOPRF challenger (either real Poseidon evaluations under a shared random key `k`, or independent random functions).

2. D plays the role of the SP challenger. D must enroll two agents and present a proof for one of them.

3. **Enrollment simulation:** D chooses two credential tuples `(modelHash₀, operatorKey₀, b₀, expiry₀)` and `(modelHash₁, operatorKey₁, b₁, expiry₁)` satisfying the SP game requirements (both satisfy the predicate, differ in other bits). D computes `credCommitment₀ = Poseidon5(...)` and `credCommitment₁ = Poseidon5(...)` directly (these computations do not involve `k`). D then queries:
   - `leafCommitment₀ = O₂(credCommitment₀)` — in the real world this equals `Poseidon2(credCommitment₀, k)`.
   - `leafCommitment₁ = O₂(credCommitment₁)` — similarly.

   D publishes `(leafCommitment₀, leafCommitment₁)` as on-chain state and provides `credCommitment₀`, `credCommitment₁` to the adversary A (simulating operator/AS knowledge).

4. **Enrollment proof simulation:** D must provide `EnrollmentIntegrity` proofs π_enroll₀ and π_enroll₁ to the adversary (they are on-chain). By A6 (Groth16 zero-knowledge), D invokes the Groth16 simulator to produce simulated proofs that are computationally indistinguishable from real proofs. The simulated proofs have the correct public signals (`leafCommitment_i`, `operatorPubKey_i`) but reveal nothing about the witness — in particular, nothing about `blindingFactor`. The key insight: D does not need to know `k` (= `blindingFactor`) to simulate these proofs, because the Groth16 simulator operates only on public signals and the CRS, not on the witness. The `leafCommitment_i` values are obtained from O₂ queries, so the public signals are correctly formed regardless of whether O₂ is real or random.

5. **Challenge phase:** D flips coin `c ∈ {0, 1}`, chooses a fresh `sessionNonce`, and computes:
   - `nullifierHash_c = O₃(credCommitment_c, sessionNonce)` — in the real world, `Poseidon3(credCommitment_c, k, sessionNonce)`.
   - `scopeCommitment_c = O₄(b_c, credCommitment_c, sessionNonce)` — in the real world, `Poseidon4(b_c, credCommitment_c, k, sessionNonce)`.

   D constructs the public signals `(agentMerkleRoot, nullifierHash_c, scopeCommitment_c, requiredScopeMask, currentTimestamp, sessionNonce)` and uses the Groth16 simulator (A6) to produce a simulated proof πc. D sends `(πc, publicSignals)` to A.

6. **Extraction:** A outputs guess `c'`. D outputs `c'` as its JOPRF guess `b'` — but with a twist: D's goal is to determine whether the oracles are real or random, not to guess `c`. D proceeds as follows:

   D runs the SP game *twice* internally (rewinding A):
   - In run 1: D sets `c = 0`, obtains A's guess `c'₁`.
   - In run 2: D sets `c = 1`, obtains A's guess `c'₂`.

   If the oracles are **real** (b = 0): the adversary's view is a valid SP game, so by hypothesis `Pr[c'₁ = 0] ≥ 1/2 + ε` and `Pr[c'₂ = 1] ≥ 1/2 + ε`. The adversary's guesses correlate with the actual coin — its behavior differs between `c = 0` and `c = 1`.

   If the oracles are **random** (b = 1): `nullifierHash_c` and `scopeCommitment_c` are uniformly random and independent of `c` (since O₃ and O₄ are random functions). The only remaining signal is `agentMerkleRoot`, which is the same for both candidates (same tree). The simulated proof πc is zero-knowledge and therefore independent of the witness. The adversary's view is *identical* for `c = 0` and `c = 1` — formally, the distribution of `(leafCommitment₀, leafCommitment₁, πc, publicSignals)` is the same for both coins. Therefore `Pr[c'₁ = 0] = Pr[c'₂ = 1] = 1/2`.

   D distinguishes: if `c'₁ = 0` AND `c'₂ = 1`, output `b' = 0` (real). Otherwise, output `b' = 1` (random). Standard analysis gives `Adv^JOPRF(D) ≥ ε²/2`, which is non-negligible if ε is.

   **Simplified (without rewinding):** Alternatively, D runs A once with a random `c`, obtains `c'`, and outputs `b' = 0` if `c' = c`, else `b' = 1`. Then:
   - If b = 0 (real): `Pr[c' = c] ≥ 1/2 + ε`, so `Pr[b' = 0] ≥ 1/2 + ε`.
   - If b = 1 (random): `Pr[c' = c] = 1/2` (view is independent of `c`), so `Pr[b' = 0] = 1/2`.
   - Therefore `Adv^JOPRF(D) = |Pr[b'=0 | b=0] - Pr[b'=0 | b=1]| ≥ ε`.

7. Therefore `ε ≤ Adv^JOPRF(D) ≤ negl(λ)` by A5. ∎

**What this reduction closes.** The prior construction's SP argument asserted in prose that "`Poseidon3` acts as a pseudorandom function from the adversary's perspective" and that "`leafCommitment` and `nullifierHash` are computationally independent under A5." This was a hand-wave for two reasons: (a) A5 was never defined as a game, and (b) the standard single-oracle PRF definition does not model the adversary's simultaneous access to `Poseidon2(x, k)` (via on-chain leaves) and `Poseidon3(x, k, n)` (via presentation proofs). The JOPRF game and the reduction above replace both hand-waves with a tight, falsifiable statement: if *any* correlation between the on-chain `leafCommitment` and the presentation-time `nullifierHash` or `scopeCommitment` exists — even a subtle one exploiting Poseidon's algebraic structure across arities — then JOPRF is broken. The reduction accounts for the exact data the adversary sees: both `O₂` outputs (both enrollment leaves), all `O₃`/`O₄` outputs (all presentation proofs), the zero-knowledge enrollment proofs, and the adversary's knowledge of `credentialCommitment` values (as operator/AS).

**Multi-session extension:** Even across multiple presentations by the same agent, each `nullifierHash` and `scopeCommitment` incorporates a fresh `sessionNonce`, producing distinct values per session. In the JOPRF model, each presentation corresponds to a fresh `O₃` and `O₄` query with a new nonce — by A5, each output is independently pseudorandom. Cross-session correlation would require finding a relation between `O₃(x, n₁)` and `O₃(x, n₂)` for different nonces `n₁, n₂` — which is exactly what JOPRF security prohibits (the adversary makes multiple adaptive queries and still cannot distinguish from random). The blinding factor remains constant across sessions (it is per-credential, not per-session), but this is precisely the JOPRF key `k` — the game models a *fixed* key with adaptive queries over varying inputs.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Hash function | Poseidon over BN254 scalar field | §2.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | §4.2 |
| Blinded leaf commitment | `Poseidon2(credentialCommitment, blindingFactor)` — replaces raw leaf | §4.2 (hardened) |
| Enrollment integrity proof | `EnrollmentIntegrity` circuit — ZKPoK at enrollment time | New (prior refinement) |
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
4. The IETF draft's enrollment is an unguarded Merkle insertion. This construction gates enrollment behind an on-chain `EnrollmentIntegrity` proof verification, ensuring every leaf is the blinding of an operator-signed, cumulative-bit-valid credential. The circuit uses only existing Bolyra primitives (Poseidon5, Poseidon2, EdDSAPoseidonVerifier, Num2Bits).
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

### Constraint breakdown for `EnrollmentIntegrity`

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
- **Joint-output correlation in the CUSO context (addressed by JOPRF):** Each CU-as-operator sees `leafCommitment = Poseidon2(credCommitment, blind)` at enrollment time (on-chain) and `nullifierHash = Poseidon3(credCommitment, blind, sessionNonce)` at each API call (from the CUSO platform's audit log, if shared with the CU under NCUA examination requirements). A CU attempting to de-anonymize its agents' API calls would try to correlate these two values — which is precisely the attack JOPRF (A5) excludes. The formal game ensures that even with adaptive access to both the enrollment-time and presentation-time Poseidon evaluations, the CU cannot link them.

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

**Bolyra construction:** The trust anchor is the on-chain Merkle root (consensus-secured) and the Groth16 knowledge soundness guarantee. The proof extracts a witness containing a valid credential commitment that is a leaf (blinded) in the tree. No party — including the entity that enrolled the agent — can forge a proof for a bitmask that does not satisfy the predicate without breaking Poseidon collision resistance or Groth16 soundness. The AS is not in the trust path. **Enrollment integrity hardening** further strengthens adversarial-AS resilience: even a compromised AS cannot insert malformed or unsigned leaves into the tree, because every insertion requires a valid `EnrollmentIntegrity` proof. The AS can enroll agents with whatever permissions it chooses (this is the AS's prerogative), but it cannot insert leaves that are not the blinding of a properly signed credential — the tree's structural integrity is cryptographically enforced, not policy-enforced.

### Gap 4: Constant-size proof regardless of permission-space cardinality

In the baseline, jwt-introspection-response size scales linearly with disclosed scopes. BBS+ derived proof size scales with `O(|disclosed|)`. For a permission space with 64 independent bits (2^64 theoretical combinations), enumeration-based approaches are infeasible.

**Bolyra construction:** The Groth16 proof is 128 bytes. The PLONK proof is ~256 bytes. Neither depends on the number of bits in `permissionBitmask`, the number of bits set in `requiredScopeMask`, or the cardinality of the permission space.

### Gap 5: Cryptographic binding to runtime model identity

The baseline's `client_id` is a static string registered at the AS. It does not bind the token to a specific model hash, operator key, or permission state at the moment of a specific API call.

**Bolyra construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` binds the scope proof to a specific model, a specific operator, and a specific permission state. The EdDSA signature over this commitment proves the operator authorized this exact combination. **Enrollment integrity hardening** ensures this binding is verified at enrollment time — the `EnrollmentIntegrity` circuit recomputes `Poseidon5` and verifies the EdDSA signature inside the proof, so the on-chain leaf is guaranteed to encode a valid model-identity binding, not just any field element.

### Gap 6: Full credential privacy from all parties including the operator/AS — with formally grounded joint-output security

BBS+ presentations are unlinkable at the RS layer. However, the issuer (AS/operator) who signed the credential knows the full credential content. In any system where the credential identifier or commitment is used as input to deterministic functions producing public outputs, the issuer can compute those outputs and correlate presentations. This is not a BBS+-specific limitation — it is a fundamental property of any credential system where the issuer knows the credential content.

**Bolyra construction (blinding-hardened, JOPRF-grounded):** Both `nullifierHash = Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` and `scopeCommitment = Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)` incorporate `blindingFactor`, which is generated solely by the agent and never disclosed to the operator, AS, or any other party. The operator knows `credentialCommitment` but cannot compute either public signal without `blindingFactor`. The on-chain observer sees only `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, from which recovering `blindingFactor` requires breaking Poseidon preimage resistance (A3). The `EnrollmentIntegrity` proof transcript (on-chain) is zero-knowledge (A6) and reveals only `leafCommitment` and `operatorPubKey` — no additional information about `blindingFactor` leaks from enrollment.

**Critically, the joint availability of `leafCommitment` (enrollment-time `Poseidon2` output) and `nullifierHash` (presentation-time `Poseidon3` output) does not help the adversary.** The prior construction asserted this informally; this refinement grounds it in the JOPRF game (A5, §4), which formally models an adversary with adaptive oracle access to `Poseidon2(·, k)`, `Poseidon3(·, k, ·)`, and `Poseidon4(·, ·, k, ·)` under the same key `k = blindingFactor`. The reduction in §4 shows that any SP advantage implies a JOPRF advantage, and A5 bounds the latter to negligible.

BBS+ cannot match this property because the issuer always knows the signed credential content and can correlate any deterministic function of that content with public presentation artifacts. The Bolyra construction introduces an agent-controlled secret (`blindingFactor`) that the issuer never sees, creating a cryptographic separation between issuance knowledge and presentation artifacts that has no analog in the BBS+ architecture — and this separation is now formally grounded in a named, falsifiable assumption (JOPRF) with a tight reduction, not a prose assertion.

### Summary: simultaneous achievement

| Property | RFC 7662 stack | BBS+ layer | Bolyra AgentPolicy |
|----------|---------------|------------|-------------------|
| AS-blind presentation | No | No (AS signs credential) | **Yes** |
| Runtime-adaptive bitmask predicate | No | Partial (no bitwise AND) | **Yes** |
| Adversarial-AS resilience | No | No (AS trust anchor) | **Yes** |
| Constant-size proof | No | O(\|disclosed\|) | **Yes** (128–256 bytes) |
| Model-identity binding | No | No | **Yes** |
| Full credential privacy (incl. operator/AS) | No | No (issuer knows content) | **Yes** (JOPRF-grounded) |
| Enrollment integrity (tree well-formedness) | N/A (no tree) | N/A (no tree) | **Yes** (EnrollmentIntegrity ZKPoK) |
| All properties simultaneously | **Impossible** | **Impossible** | **Yes** |

The baseline can achieve subsets (BBS+ gives selective disclosure; DPoP gives sender binding; jwt-introspection-response gives offline verification), but no composition achieves all six. The fundamental barrier is architectural: the baseline stack trusts the AS as the scope authority, while this construction trusts the proving system and the on-chain enrollment root. These are incompatible trust models — you cannot retrofit AS-independence onto a stack whose security definition requires AS honesty. The blinding-hardened construction closes the last remaining gap where operator/AS knowledge of `credentialCommitment` compromised the privacy guarantee, and the enrollment integrity hardening ensures the on-chain tree — the construction's trust anchor — admits only well-formed, operator-signed, cumulative-bit-valid leaves. The JOPRF assumption (A5) replaces the prior construction's informal PRF hand-wave with a formally defined, falsifiable game that exactly captures the joint-output structure the adversary encounters — correlated Poseidon evaluations across arities 2, 3, and 4 under a shared secret key — achieving cryptographic separation between enrollment authority knowledge and presentation artifacts without introducing any additional trusted party, ceremony, or on-chain storage beyond a single additional Groth16 verifier contract.
