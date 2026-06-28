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

   **Enrollment protocol change:** At enrollment, the agent computes `credentialCommitment` as before, then computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` locally and submits only `leafCommitment` to the on-chain registry for Merkle insertion. The operator's EdDSA signature still covers `credentialCommitment` (not `leafCommitment`) — this ensures the blinding factor is agent-chosen and not operator-controlled, preserving the agent's privacy even against its own operator.

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

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The authorization server (AS) — can issue arbitrary tokens, lie about scope membership, collude with other parties. **Crucially, the AS may be the same entity as the operator**, meaning A knows `credentialCommitment` for all agents it enrolled (since it signed them).
- The network between agent and RS — can observe, delay, and replay messages.
- Up to `N-1` of `N` enrolled agents' credential material (corruption threshold).
- Any number of RS endpoints (for cross-RS linkability attacks).
- **Full read access to on-chain state** — including all Merkle tree leaves (which are blinded `leafCommitment` values), all emitted enrollment events, root history, and nonce mappings.

The adversary does NOT control:
- The on-chain Merkle root (secured by the underlying L1/L2 consensus).
- The Groth16/PLONK trusted setup (honest-majority ceremony assumption).
- The agent's `blindingFactor` — this is the sole secret the agent holds independent of the operator/AS. Even when operator=AS, the `blindingFactor` is chosen by the agent at enrollment time and never transmitted to the operator, AS, or registry.

**Protocol invariant on `blindingFactor` independence:** The enrollment protocol MUST ensure that `blindingFactor` is generated locally by the agent and never disclosed to the operator or AS. The operator signs `credentialCommitment` (which does not contain `blindingFactor`); the agent then independently computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` and submits `leafCommitment` to the registry. The operator need not (and must not) learn `blindingFactor` at any point. This is enforced architecturally: the EdDSA signature covers `credentialCommitment`, not `leafCommitment`, so the operator has no reason or ability to participate in blinding-factor generation.

### Game: Selective Scope Unforgeability (SSU)

```
Game SSU(λ):
  1. Setup: Generate CRS for AgentPolicy circuit. Deploy on-chain registry.
  2. Enrollment: Challenger enrolls honest agent with credential
     (modelHash, operatorPubKey, permissionBitmask*, expiryTimestamp)
     into the Merkle tree. The leaf inserted on-chain is
     leafCommitment = Poseidon2(credentialCommitment*, blindingFactor*),
     where blindingFactor* is chosen uniformly at random by the challenger.
  3. Query phase: A may:
     a. Request proofs for any (requiredScopeMask, sessionNonce) where
        permissionBitmask* & requiredScopeMask == requiredScopeMask.
     b. Corrupt any other enrolled agent (obtaining their full credential
        material including blindingFactor).
     c. Compromise the AS entirely.
     d. Read all on-chain state including leafCommitment values.
  4. Forgery: A outputs (π*, pubSignals*) for a requiredScopeMask* where
     permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*
     (i.e., the honest agent does NOT satisfy the predicate).
  5. A wins if the on-chain verifier accepts (π*, pubSignals*) with
     agentMerkleRoot matching a valid root containing the honest agent's
     blinded leaf.
```

**Claim:** No PPT adversary wins SSU with non-negligible probability under the assumptions in §4.

### Game: Scope Privacy (SP) — hardened against operator=AS collusion

The prior construction's SP game was vulnerable when the operator and AS are the same entity (or collude): the operator signs `credentialCommitment` during enrollment, so it knows `credentialCommitment` for both challenge agents. Even with blinded on-chain leaves, the operator-AS adversary could compute `Poseidon2(credCommitment_i, sessionNonce)` for each candidate and compare against the public `nullifierHash` output to identify the prover with probability 1.

The blinding-hardened nullifier and scope commitment eliminate this attack: both now incorporate `blindingFactor`, which is unknown to the operator/AS.

```
Game SP(λ):
  1. Setup: as above.
  2. Challenger enrolls two agents with bitmasks b₀, b₁ where
     b₀ & requiredScopeMask == requiredScopeMask AND
     b₁ & requiredScopeMask == requiredScopeMask
     (both satisfy the predicate, but differ in other bits).
     On-chain leaves are leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)
     and leafCommitment₁ = Poseidon2(credCommitment₁, blind₁).
     The operator (possibly = AS) receives credCommitment₀ and
     credCommitment₁ during the signing phase.
  3. Challenger flips coin c ∈ {0,1}, generates proof πc for agent c
     with a fresh sessionNonce chosen by the challenger.
  4. A receives (πc, publicSignals) and has:
     - Full read access to on-chain state (leafCommitment₀, leafCommitment₁).
     - Knowledge of credCommitment₀ and credCommitment₁ (as operator/AS).
     - Does NOT know blind₀ or blind₁.
  5. A outputs guess c'.
  6. A wins if c' = c.
```

**Why the adversary cannot win — even when operator=AS:**

The adversary's view consists of:

- **Operator knowledge:** `credCommitment₀` and `credCommitment₁` (signed both during enrollment). Also knows `b₀` and `b₁` (embedded in the credential commitments).
- **On-chain:** `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and `leafCommitment₁ = Poseidon2(credCommitment₁, blind₁)`.
- **Public signals from the proof:**
  - `agentMerkleRoot`: identical for both candidates (same tree).
  - `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`: the adversary knows `credCommitment₀`, `credCommitment₁`, and `sessionNonce`, but does NOT know `blind₀` or `blind₁`. Computing `Poseidon3(credCommitment_i, blind_i, sessionNonce)` for either candidate requires `blind_i`.
  - `scopeCommitment = Poseidon4(b_c, credCommitment_c, blind_c, sessionNonce)`: same obstruction — requires `blind_c`.
  - `requiredScopeMask`, `currentTimestamp`, `sessionNonce`: identical for both candidates by game construction.

- **Attack via nullifierHash (the attack that broke the prior construction):** The adversary attempts to compute `Poseidon3(credCommitment₀, blind₀, sessionNonce)` and compare against `nullifierHash`. But `blind₀` is unknown. The adversary knows `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and knows `credCommitment₀`. In principle, the adversary could try to recover `blind₀` from `leafCommitment₀` given `credCommitment₀` — this is a Poseidon preimage attack on the second input given the first input, which contradicts A3 (Poseidon preimage resistance). Specifically, finding `x` such that `Poseidon2(credCommitment₀, x) = leafCommitment₀` is exactly the preimage problem for Poseidon2 with one input fixed.

- **Attack via scopeCommitment:** Requires `blind_c`, same obstruction.

- **Cross-referencing leafCommitment against nullifierHash:** The adversary knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)` and `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`. Even knowing `credCommitment_i`, correlating these requires `blind_i`. Under A5 (Poseidon PRF, keyed by `blind_c`), the outputs `Poseidon2(credCommitment_c, blind_c)` and `Poseidon3(credCommitment_c, blind_c, sessionNonce)` are computationally independent to an adversary who does not know `blind_c`.

- **Brute-force on blindingFactor:** `blindingFactor` is a uniformly random element of F_p (≈254 bits). Exhaustive search is infeasible.

**Claim:** Pr[A wins SP] ≤ 1/2 + negl(λ) under Poseidon preimage resistance (A3), Poseidon PRF (A5), and Groth16 zero-knowledge (A6). This holds even when the adversary is the operator and/or AS and knows all `credentialCommitment` values.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Where used |
|----|-----------|------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) | SSU game — extracting witness from valid proof |
| A2 | **Knowledge soundness of PLONK** (universal SRS, ROM) | SSU game (PLONK variant) |
| A3 | **Poseidon collision resistance and preimage resistance** over BN254 scalar field | Merkle membership, credential commitment binding, blinded leaf hiding, **blindingFactor recovery resistance (SP game, operator=AS case)** |
| A4 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability, operator key binding |
| A5 | **Poseidon acts as a PRF** when keyed by the secret / blindingFactor / credential commitment | Nullifier unlinkability across sessions, independence of blinded leaf from nullifier, **operator=AS resistance in SP game** |
| A6 | **Zero-knowledge property of Groth16/PLONK** | Scope Privacy game — Merkle path hiding |

### Reduction sketch for SSU

1. Suppose A wins SSU with non-negligible probability ε.
2. By A1 (Groth16 knowledge soundness), extract witness `w = (modelHash, operatorPubKey, permissionBitmask', expiryTimestamp, sig, blindingFactor', merkleProof)` from π*.
3. The circuit enforces `reqBits[i] * (1 - permBits'[i]) === 0` for all i ∈ [0,64). So `permissionBitmask' & requiredScopeMask* == requiredScopeMask*`.
4. The circuit enforces `credentialCommitment' = Poseidon5(modelHash, ..., permissionBitmask', expiryTimestamp)`.
5. The circuit enforces `leafCommitment' = Poseidon2(credentialCommitment', blindingFactor')`.
6. The circuit enforces Merkle membership of `leafCommitment'` under `agentMerkleRoot`.
7. Since `agentMerkleRoot` matches a valid on-chain root containing the honest agent's blinded leaf:
   - If `leafCommitment' = leafCommitment*` (honest agent's blinded leaf), then by Poseidon collision resistance (A3) on the blinded-leaf hash, `(credentialCommitment', blindingFactor') = (credentialCommitment*, blindingFactor*)`. Then by Poseidon collision resistance (A3) on the credential commitment hash, `permissionBitmask' = permissionBitmask*`. But we assumed `permissionBitmask* & requiredScopeMask* ≠ requiredScopeMask*`. Contradiction.
   - If `leafCommitment' ≠ leafCommitment*`, then A used a different leaf — either a legitimately enrolled agent with a satisfying bitmask (not a forgery against the honest agent) or a Merkle collision (contradicts A3).
8. Therefore ε is negligible. ∎

### Reduction sketch for SP (hardened against operator=AS)

The prior construction's SP argument was broken when operator=AS: the operator knows `credentialCommitment` for both challenge agents (having signed them) and could compute `Poseidon2(credCommitment_i, sessionNonce)` for each, comparing against the public `nullifierHash` to win with probability 1. The blinding-hardened construction interposes `blindingFactor` — unknown to the operator — into both `nullifierHash` and `scopeCommitment`, eliminating this attack.

**Argument:**

1. The adversary (as operator/AS) knows `credCommitment₀`, `credCommitment₁`, `b₀`, `b₁`, and all public inputs including `sessionNonce`. The adversary also reads `leafCommitment₀` and `leafCommitment₁` from on-chain state. The adversary does NOT know `blind₀` or `blind₁`.

2. The public signals from proof πc are:
   - `agentMerkleRoot`: identical for both candidates (same tree).
   - `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`: to evaluate this for candidate i, the adversary needs `blind_i`.
   - `scopeCommitment = Poseidon4(b_c, credCommitment_c, blind_c, sessionNonce)`: same obstruction.
   - `requiredScopeMask`, `currentTimestamp`, `sessionNonce`: identical for both candidates.

3. **Recovery of `blind_i` from `leafCommitment_i`:** The adversary knows `credCommitment_i` and `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)`. Recovering `blind_i` requires finding `x` such that `Poseidon2(credCommitment_i, x) = leafCommitment_i`. This is a preimage problem on the second input of Poseidon2 with the first input fixed — precisely the setting covered by A3 (Poseidon preimage resistance). Under A3, no PPT adversary can recover `blind_i`.

4. **Distinguishing without `blind_i`:** Without `blind_c`, the adversary cannot compute `Poseidon3(credCommitment_c, blind_c, sessionNonce)` for either candidate. The adversary's view of `nullifierHash` is a Poseidon3 evaluation under the unknown key `blind_c`. Under A5 (Poseidon PRF keyed by `blind_c`), the function `f(credCommitment, sessionNonce) = Poseidon3(credCommitment, blind_c, sessionNonce)` is a pseudorandom function from the adversary's perspective. Two evaluations under different keys (`blind₀` vs `blind₁`) are computationally indistinguishable from random — the adversary cannot determine which key produced the observed output.

5. **Cross-referencing `leafCommitment_i` against `nullifierHash`:** The adversary knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)` and `nullifierHash = Poseidon3(credCommitment_c, blind_c, sessionNonce)`. Even with `credCommitment_i` known, correlating the two Poseidon evaluations requires `blind_i` as a common link. Under A5 (PRF keyed by `blind_c`), the outputs are computationally independent from the adversary's perspective.

6. By A6 (Groth16 zero-knowledge), the proof π itself reveals nothing about the witness beyond the public signals — in particular, the Merkle proof path (which leaf index was used) is hidden.

7. Therefore Pr[A wins SP] ≤ 1/2 + negl(λ). ∎

**Multi-session extension:** Even across multiple presentations by the same agent, each `nullifierHash` and `scopeCommitment` incorporates a fresh `sessionNonce`, producing distinct values per session. Cross-session correlation would require recovering `blindingFactor` to verify that two nullifiers share the same `(credentialCommitment, blindingFactor)` prefix — which requires breaking A3. The blinding factor remains constant across sessions (it is per-credential, not per-session), but it is never exposed: it appears only as a private witness inside the circuit and is protected by Poseidon preimage resistance at the `leafCommitment` layer.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Hash function | Poseidon over BN254 scalar field | §2.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | §4.2 |
| Blinded leaf commitment | `Poseidon2(credentialCommitment, blindingFactor)` — replaces raw leaf | §4.2 (hardened) |
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
4. All three changes are backwards-compatible with the on-chain registry interface: the registry stores field elements as leaves regardless of their internal structure, and `sessionNonce` is already stored per handshake. The Delegation circuit's chain-linking constraint is updated to `Poseidon4(delegatorScope, delegatorCredCommitment, delegatorBlindingFactor, previousSessionNonce) == previousScopeCommitment`, with `delegatorBlindingFactor` as an additional private input. Delegatee enrollment uses `leafCommitment = Poseidon2(delegateeCredCommitment, delegateeBlindingFactor)`.

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

The blinding-hardened nullifier upgrades from `Poseidon2` (~300) to `Poseidon3` (~300, negligible change for the Poseidon round structure at this arity). The scope commitment upgrades from `Poseidon3` (~300) to `Poseidon4` (~450, one additional round). Net increase: ~150 constraints over the prior construction. Total remains comfortably under 2^16 = 65,536 constraints; `pot16.ptau` sufficiency is unchanged.

### Proving time targets

| Proving system | Target | Platform |
|---------------|--------|----------|
| Groth16 (snarkjs, WASM) | < 5 s | Browser / Node.js |
| Groth16 (rapidsnark, native) | < 0.5 s | Server-side agent |
| PLONK (snarkjs) | < 5 s | Server-side agent |

### Proof size

| System | Proof size | Public signals |
|--------|-----------|---------------|
| Groth16 | 128 bytes (3 G1 + 1 G2 point, compressed) | 6 × 32 bytes = 192 bytes |
| PLONK | ~256 bytes | 6 × 32 bytes = 192 bytes |

**Total on-wire: 320–448 bytes.** The public signal count is unchanged — `blindingFactor` is a private input, and the blinded leaf commitment is an internal wire (not a public output). The circuit's public interface remains identical: `(agentMerkleRoot, nullifierHash, scopeCommitment, requiredScopeMask, currentTimestamp, sessionNonce)`.

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
- **Operator=AS privacy (addressed by this refinement):** In the CUSO federated model, each CU acts as both the operator (signing agent credentials) and the AS (issuing authorization). Without blinding-hardened nullifiers and scope commitments, a CU that enrolled two of its own agents could determine which of them made a specific API call by computing `Poseidon2(credCommitment_i, sessionNonce)` for each and comparing against the public `nullifierHash`. This breaks intra-CU agent privacy — a CU's compliance department could track individual agent behavior even when the platform is designed to provide anonymous authorization. With blinding-hardened public signals, the CU-as-operator knows `credCommitment` but not `blindingFactor`, so it cannot compute `Poseidon3(credCommitment, blindingFactor, sessionNonce)`. Each agent maintains privacy from its own operator/AS.

**Bolyra deployment:**
1. Each CU enrolls its agents into the shared Bolyra agent Merkle tree (deployed on Base Sepolia, graduating to Base mainnet). At enrollment, the agent locally generates `blindingFactor`, computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, and submits only `leafCommitment` to the registry. The CU (operator) signs `credentialCommitment` but never learns `blindingFactor`.
2. When CU-A's fraud-detection agent calls the CUSO platform's `/member/transactions` endpoint, the platform returns `requiredScopeMask = 0b10000001` (bits 0 and 7: `READ_DATA | ACCESS_PII`).
3. The agent generates a Groth16 proof locally (rapidsnark, < 0.5 s) proving its bitmask satisfies the mask. The CUSO platform learns only that the predicate holds — not whether the agent also holds `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, or `SUB_DELEGATE`. The `scopeCommitment` and `nullifierHash` are unique to this session and cannot be correlated with on-chain enrollment data, prior accesses, or the operator's knowledge of the credential commitment.
4. The platform checks `agentMerkleRoot` against the on-chain root history buffer. No AS is contacted. No CU's AS is trusted.
5. The agent's credential expiry is enforced inside the circuit. Revocation is handled by updating the Merkle tree (removing the blinded leaf).

**Regulatory value:** NCUA examiners can audit the on-chain enrollment registry (verifying that CUs are enrolling agents with proper operator signatures) without being able to correlate enrollment entries with individual API access events. Even the enrolling CU itself — acting as operator and AS — cannot perform this correlation without the agent's `blindingFactor`. This separation satisfies both NCUA §701.27 third-party due diligence (the registry proves agents are enrolled) and GLBA §501(b) safeguard requirements (individual access patterns remain private). The blinding-hardened construction ensures that even a subpoena for on-chain data *and* operator records does not reveal which enrolled agent made which API call — that linkage requires the agent's private `blindingFactor`, which can be disclosed per-agent under appropriate legal process without compromising other agents' privacy.

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

**Bolyra construction:** The trust anchor is the on-chain Merkle root (consensus-secured) and the Groth16 knowledge soundness guarantee. The proof extracts a witness containing a valid credential commitment that is a leaf (blinded) in the tree. No party — including the entity that enrolled the agent — can forge a proof for a bitmask that does not satisfy the predicate without breaking Poseidon collision resistance or Groth16 soundness. The AS is not in the trust path.

### Gap 4: Constant-size proof regardless of permission-space cardinality

In the baseline, jwt-introspection-response size scales linearly with disclosed scopes. BBS+ derived proof size scales with `O(|disclosed|)`. For a permission space with 64 independent bits (2^64 theoretical combinations), enumeration-based approaches are infeasible.

**Bolyra construction:** The Groth16 proof is 128 bytes. The PLONK proof is ~256 bytes. Neither depends on the number of bits in `permissionBitmask`, the number of bits set in `requiredScopeMask`, or the cardinality of the permission space.

### Gap 5: Cryptographic binding to runtime model identity

The baseline's `client_id` is a static string registered at the AS. It does not bind the token to a specific model hash, operator key, or permission state at the moment of a specific API call.

**Bolyra construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)` binds the scope proof to a specific model, a specific operator, and a specific permission state. The EdDSA signature over this commitment proves the operator authorized this exact combination.

### Gap 6 (hardened in this refinement): Full credential privacy from all parties including the operator/AS

BBS+ presentations are unlinkable at the RS layer. However, the issuer (AS/operator) who signed the credential knows the full credential content. In any system where the credential identifier or commitment is used as input to deterministic functions producing public outputs, the issuer can compute those outputs and correlate presentations. This is not a BBS+-specific limitation — it is a fundamental property of any credential system where the issuer knows the credential content.

The prior Bolyra construction had this exact vulnerability: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` used `credentialCommitment` (known to the operator who signed it) and `sessionNonce` (public), so the operator could compute the nullifier for any session and correlate proofs.

**Bolyra construction (blinding-hardened):** Both `nullifierHash = Poseidon3(credentialCommitment, blindingFactor, sessionNonce)` and `scopeCommitment = Poseidon4(permissionBitmask, credentialCommitment, blindingFactor, sessionNonce)` incorporate `blindingFactor`, which is generated solely by the agent and never disclosed to the operator, AS, or any other party. The operator knows `credentialCommitment` but cannot compute either public signal without `blindingFactor`. The on-chain observer sees only `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, from which recovering `blindingFactor` requires breaking Poseidon preimage resistance (A3). Privacy holds against the operator, the AS (even when operator=AS), the RS, and all on-chain observers simultaneously.

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
| All six simultaneously | **Impossible** | **Impossible** | **Yes** |

The baseline can achieve subsets (BBS+ gives selective disclosure; DPoP gives sender binding; jwt-introspection-response gives offline verification), but no composition achieves all six. The fundamental barrier is architectural: the baseline stack trusts the AS as the scope authority, while this construction trusts the proving system and the on-chain enrollment root. These are incompatible trust models — you cannot retrofit AS-independence onto a stack whose security definition requires AS honesty. The blinding-hardened construction closes the last remaining gap where operator/AS knowledge of `credentialCommitment` compromised the privacy guarantee, achieving cryptographic separation between enrollment authority knowledge and presentation artifacts without introducing any additional trusted party, ceremony, or on-chain storage.
