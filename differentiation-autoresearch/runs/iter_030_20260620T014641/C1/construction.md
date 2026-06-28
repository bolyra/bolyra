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

The construction uses the Bolyra `AgentPolicy` circuit as specified in `draft-bolyra-mutual-zkp-auth-01`, Section 4.2, with two hardening modifications over the base spec: (1) the scope commitment output is session-randomized to prevent cross-presentation linkability, and (2) the Merkle leaf is a blinded commitment rather than the raw credential commitment, preventing on-chain observers from recovering `credentialCommitment` and breaking the Scope Privacy game.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Poseidon hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | [0, 2^64) | Agent's full 64-bit permission bitfield |
| `expiryTimestamp` | [0, 2^64) | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `blindingFactor` | F_p | **Per-credential random blinding value** — chosen at enrollment, kept secret |
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
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)` — **session-randomized** |

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

9. **Nullifier** — `Poseidon2(credentialCommitment, sessionNonce)`. Replay detection per session. Note: `credentialCommitment` is a private intermediate value — it is not on-chain (only `leafCommitment` is). The nullifier therefore does not leak `credentialCommitment` because `sessionNonce` is fresh per request and Poseidon acts as a PRF (A5).

10. **Session-randomized scope commitment** — `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`. By including `sessionNonce` (which is fresh per request), two presentations by the same agent to different RSes produce distinct `scopeCommitment` values.

    **Delegation chain impact:** Unchanged from prior construction. The on-chain registry stores `(scopeCommitment, sessionNonce)` as the delegation chain seed. The Delegation circuit's chain-linking constraint becomes `Poseidon3(delegatorScope, delegatorCredCommitment, previousSessionNonce) == previousScopeCommitment`, where `previousSessionNonce` is supplied as an additional public input. The Delegation circuit also requires an updated blinded-leaf check: `leafCommitment = Poseidon2(delegateeCredCommitment, delegateeBlindingFactor)` for the delegatee's Merkle membership, with `delegateeBlindingFactor` as an additional private input.

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
6. RS accepts. It learns nothing about `permissionBitmask` beyond `permissionBitmask & requiredScopeMask == requiredScopeMask`. The `scopeCommitment` is opaque and session-unique — the RS cannot correlate it with any other presentation. The `nullifierHash` is likewise session-unique and cannot be traced to any on-chain leaf.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The authorization server (AS) — can issue arbitrary tokens, lie about scope membership, collude with other parties.
- The network between agent and RS — can observe, delay, and replay messages.
- Up to `N-1` of `N` enrolled agents' credential material (corruption threshold).
- Any number of RS endpoints (for cross-RS linkability attacks).
- **Full read access to on-chain state** — including all Merkle tree leaves (which are blinded `leafCommitment` values), all emitted enrollment events, root history, and nonce mappings.

The adversary does NOT control:
- The on-chain Merkle root (secured by the underlying L1/L2 consensus).
- The Groth16/PLONK trusted setup (honest-majority ceremony assumption).
- The agent's private credential fields — including `blindingFactor` — for the honest agent under test.

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

### Game: Scope Privacy (SP) — hardened with blinded leaves

The prior construction's SP game was broken despite session-randomized scope commitments: `credentialCommitment` was stored as a Merkle leaf on-chain, so the adversary could read both candidates' credential commitments from chain events and compute `Poseidon2(credCommitment_c, sessionNonce)` for each candidate, comparing against the public `nullifierHash` output to identify the prover with probability 1.

The blinded-leaf construction eliminates this attack: the on-chain leaf is `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, and `credentialCommitment` never appears in the clear on-chain or in any public signal.

```
Game SP(λ):
  1. Setup: as above.
  2. Challenger enrolls two agents with bitmasks b₀, b₁ where
     b₀ & requiredScopeMask == requiredScopeMask AND
     b₁ & requiredScopeMask == requiredScopeMask
     (both satisfy the predicate, but differ in other bits).
     On-chain leaves are leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)
     and leafCommitment₁ = Poseidon2(credCommitment₁, blind₁).
  3. Challenger flips coin c ∈ {0,1}, generates proof πc for agent c
     with a fresh sessionNonce chosen by the challenger.
  4. A receives (πc, publicSignals) and has full read access to on-chain
     state (including leafCommitment₀ and leafCommitment₁, but NOT
     credCommitment₀, credCommitment₁, blind₀, or blind₁).
  5. A outputs guess c'.
  6. A wins if c' = c.
```

**Why the adversary cannot win:** The adversary's view consists of:

- **On-chain:** `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and `leafCommitment₁ = Poseidon2(credCommitment₁, blind₁)`. Under Poseidon preimage resistance (A3), the adversary cannot recover `credCommitment₀` or `credCommitment₁` from these values.
- **Public signals from the proof:** `agentMerkleRoot` (same tree for both), `nullifierHash = Poseidon2(credCommitment_c, sessionNonce)`, `scopeCommitment = Poseidon3(b_c, credCommitment_c, sessionNonce)`, and the three public inputs (identical for both candidates by game construction).
- **Attack via nullifierHash:** The adversary would need to check whether `nullifierHash == Poseidon2(credCommitment₀, sessionNonce)` or `Poseidon2(credCommitment₁, sessionNonce)`. But `credCommitment₀` and `credCommitment₁` are unknown — they are hidden behind the blinded leaves. Computing them requires inverting `Poseidon2(·, blind_i)` on the known `leafCommitment_i`, which contradicts A3.
- **Attack via scopeCommitment:** Same argument — requires `credCommitment_c`, which is hidden.
- **Attack via agentMerkleRoot + Merkle proof path:** The proof is zero-knowledge (A6), so the Merkle proof path (including which leaf was used) is hidden.
- **Cross-referencing leafCommitment against nullifierHash:** The adversary knows `leafCommitment_i = Poseidon2(credCommitment_i, blind_i)` and `nullifierHash = Poseidon2(credCommitment_c, sessionNonce)`. These are two Poseidon2 evaluations with different second inputs (`blind_i` vs `sessionNonce`) and a shared first input (`credCommitment_c`). Without knowing `credCommitment_c`, the adversary cannot verify consistency between a `leafCommitment` and the `nullifierHash`. Under the Poseidon PRF assumption (A5, keyed by the unknown `credCommitment`), outputs under different "tweaks" (`blind` vs `sessionNonce`) are computationally independent.

**Claim:** Pr[A wins SP] ≤ 1/2 + negl(λ) under Poseidon preimage resistance (A3), Poseidon PRF (A5), and Groth16 zero-knowledge (A6).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

| ID | Assumption | Where used |
|----|-----------|------------|
| A1 | **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) | SSU game — extracting witness from valid proof |
| A2 | **Knowledge soundness of PLONK** (universal SRS, ROM) | SSU game (PLONK variant) |
| A3 | **Poseidon collision resistance and preimage resistance** over BN254 scalar field | Merkle membership, credential commitment binding, blinded leaf hiding, scope commitment unlinkability |
| A4 | **Discrete logarithm hardness on Baby Jubjub** | EdDSA unforgeability, operator key binding |
| A5 | **Poseidon acts as a PRF** when keyed by the secret / credential commitment | Nullifier unlinkability across sessions, independence of blinded leaf from nullifier |
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

### Reduction sketch for SP (hardened with blinded leaves)

The prior construction's SP argument was flawed because `credentialCommitment` was directly visible as an on-chain Merkle leaf. An adversary could read both candidates' credential commitments from chain state and compute `Poseidon2(credCommitment_i, sessionNonce)` for each, comparing against the public `nullifierHash` to win with probability 1. The blinded-leaf construction eliminates this by ensuring `credentialCommitment` never appears in the clear.

**Argument:**

1. The adversary's on-chain view contains `leafCommitment₀ = Poseidon2(credCommitment₀, blind₀)` and `leafCommitment₁ = Poseidon2(credCommitment₁, blind₁)`. Under A3 (preimage resistance), recovering `credCommitment_i` from `leafCommitment_i` is infeasible without `blind_i`.

2. The public signals from proof πc are:
   - `agentMerkleRoot`: identical for both candidates (same tree).
   - `nullifierHash = Poseidon2(credCommitment_c, sessionNonce)`: the adversary cannot evaluate this for either candidate without knowing `credCommitment_c`.
   - `scopeCommitment = Poseidon3(b_c, credCommitment_c, sessionNonce)`: same obstruction.
   - `requiredScopeMask`, `currentTimestamp`, `sessionNonce`: identical for both candidates by game construction.

3. The adversary's only distinguishing strategy requires computing `Poseidon2(credCommitment_i, sessionNonce)` for i ∈ {0,1} and comparing against `nullifierHash`. This requires `credCommitment_i`, which requires inverting `Poseidon2(·, blind_i)` on `leafCommitment_i` — contradicting A3.

4. An alternative strategy: the adversary tries to correlate `leafCommitment_c` with `nullifierHash` without recovering `credCommitment_c`. Both values are Poseidon2 evaluations with `credCommitment_c` as the first input but different second inputs (`blind_c` vs `sessionNonce`). Under A5 (Poseidon PRF, keyed by `credCommitment_c`), these outputs are computationally independent. The adversary gains no information about which `leafCommitment` corresponds to the proof.

5. By A6 (Groth16 zero-knowledge), the proof π itself reveals nothing about the witness beyond the public signals — in particular, the Merkle proof path (which leaf index was used) is hidden.

6. Therefore Pr[A wins SP] ≤ 1/2 + negl(λ). ∎

**Multi-session extension:** Even across multiple presentations by the same agent, each `nullifierHash` and `scopeCommitment` incorporates a fresh `sessionNonce`, producing distinct values. Cross-session correlation requires recovering `credentialCommitment` to verify consistency — which requires breaking A3 on the blinded leaf. The blinding factor remains constant across sessions (it is per-credential, not per-session), but it is never exposed: it appears only as a private witness inside the circuit.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Hash function | Poseidon over BN254 scalar field | §2.2 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` | §4.2 |
| Blinded leaf commitment | `Poseidon2(credentialCommitment, blindingFactor)` — **new: replaces raw leaf** | §4.2 (hardened) |
| Scope satisfaction | Bitwise AND via `Num2Bits(64)` + per-bit constraint | §4.2, constraint 5 |
| Cumulative-bit closure | Implication constraints on bits 2/3/4 | §4.2, constraint 6 |
| Operator binding | `EdDSAPoseidonVerifier` on Baby Jubjub | §4.2, constraint 3 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash, **leaf = blinded commitment** | §4.2, constraint 4 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | §4.2 |
| Scope commitment | `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)` — **session-randomized** | §3, §4.2 |
| Proving system (primary) | Groth16 with project `pot16.ptau` Phase 1 | §2.3 |
| Proving system (optional) | PLONK universal setup | §2.3 |
| Root history | 30-entry circular buffer on-chain | §2.1 |

**Spec divergence notes:**
1. The IETF draft (§3, §4.2) defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. This construction upgrades to `Poseidon3` with `sessionNonce` as the third input.
2. The IETF draft inserts `credentialCommitment` directly as the Merkle leaf. This construction interposes a blinding layer: `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` is inserted instead. The blinding factor is agent-local and never transmitted to the AS, operator, or registry — only `leafCommitment` is submitted at enrollment.
3. Both changes are backwards-compatible with the on-chain registry interface: the registry stores field elements as leaves regardless of their internal structure, and `sessionNonce` is already stored per handshake. The Delegation circuit's chain-linking and delegatee enrollment constraints are updated analogously (delegatee leaf = `Poseidon2(delegateeCredCommitment, delegateeBlindingFactor)`).

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
| `Poseidon2` (nullifier) | ~300 |
| `Poseidon3` (session-randomized scopeCommitment) | ~300 |
| **Total** | **~21,000** |

The blinded-leaf `Poseidon2` adds ~300 constraints over the prior construction. The total remains comfortably under 2^16 = 65,536 constraints; `pot16.ptau` sufficiency is unchanged.

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

**Total on-wire: 320–448 bytes.** The public signal count is unchanged — the blinding factor is a private input, and the blinded leaf commitment is an internal wire (not a public output). The circuit's public interface remains identical: `(agentMerkleRoot, nullifierHash, scopeCommitment, requiredScopeMask, currentTimestamp, sessionNonce)`.

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
- **On-chain privacy (addressed by this refinement):** Without blinded leaves, any on-chain observer (including competing CUs, regulators browsing block explorers, or the CUSO platform operator itself) could read credential commitments from enrollment events and correlate them against proof public signals. A competing CU-B could observe CU-A's enrollment transaction, extract `credentialCommitment`, and later compute `Poseidon2(credentialCommitment, sessionNonce)` for any observed proof to determine whether CU-A's agent made that request — completely breaking the privacy guarantee. With blinded leaves, the enrollment transaction reveals only `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, which is computationally indistinguishable from random. CU-B cannot link enrollment events to proof presentations without the blinding factor.

**Bolyra deployment:**
1. Each CU enrolls its agents into the shared Bolyra agent Merkle tree (deployed on Base Sepolia, graduating to Base mainnet). At enrollment, the agent locally computes `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)` and submits only `leafCommitment` to the registry. The `blindingFactor` is stored alongside the agent's private key material and never transmitted.
2. When CU-A's fraud-detection agent calls the CUSO platform's `/member/transactions` endpoint, the platform returns `requiredScopeMask = 0b10000001` (bits 0 and 7: `READ_DATA | ACCESS_PII`).
3. The agent generates a Groth16 proof locally (rapidsnark, < 0.5 s) proving its bitmask satisfies the mask. The CUSO platform learns only that the predicate holds — not whether the agent also holds `FINANCIAL_UNLIMITED`, `SIGN_ON_BEHALF`, or `SUB_DELEGATE`. The `scopeCommitment` and `nullifierHash` are unique to this session and cannot be correlated with on-chain enrollment data or prior accesses.
4. The platform checks `agentMerkleRoot` against the on-chain root history buffer. No AS is contacted. No CU's AS is trusted.
5. The agent's credential expiry is enforced inside the circuit. Revocation is handled by updating the Merkle tree (removing the blinded leaf).

**Regulatory value:** NCUA examiners can audit the on-chain enrollment registry (verifying that CUs are enrolling agents with proper operator signatures) without being able to correlate enrollment entries with individual API access events. This separation satisfies both NCUA §701.27 third-party due diligence (the registry proves agents are enrolled) and GLBA §501(b) safeguard requirements (individual access patterns remain private). The blinded-leaf construction ensures that even a subpoena for on-chain data does not reveal which enrolled agent made which API call — that linkage requires the agent's private `blindingFactor`, which can be disclosed per-agent under appropriate legal process without compromising other agents' privacy.

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

### Gap 6 (hardened in this refinement): Full credential privacy from on-chain observers

BBS+ presentations are unlinkable at the RS layer. However, any credential system that stores credential identifiers on a public ledger (or that relies on a public registry for revocation status) exposes those identifiers to on-chain observers. In the prior Bolyra construction, `credentialCommitment` was stored as a Merkle leaf in the clear, enabling any chain observer to compute candidate nullifier hashes and break the SP game. This is not unique to ZK constructions — any system that publishes credential identifiers faces the same linkability risk when those identifiers are used as inputs to deterministic functions with public outputs.

**Bolyra construction (blinded leaves):** The on-chain leaf is `leafCommitment = Poseidon2(credentialCommitment, blindingFactor)`, where `blindingFactor` is known only to the agent. The credential commitment — which encodes the agent's model hash, operator key, permission bitmask, and expiry — never appears on-chain. All public outputs of the proof (`nullifierHash`, `scopeCommitment`) depend on `credentialCommitment` combined with a fresh `sessionNonce`, and `credentialCommitment` is hidden behind both the blinding layer (on-chain) and the zero-knowledge property (in proofs). An on-chain observer sees only uniformly-distributed field elements at every layer: enrollment leaves, nullifiers, and scope commitments. Correlating any two of these requires recovering `credentialCommitment`, which requires breaking Poseidon preimage resistance (A3).

BBS+ achieves RS-layer unlinkability through signature randomization, but the credential itself (or its identifier in a revocation registry) remains a linkable artifact at the issuer and registry layers. The Bolyra blinded-leaf construction achieves unlinkability at all layers — RS, AS, and on-chain observer — simultaneously, without relying on any trusted party for randomization.

### Summary: simultaneous achievement

| Property | RFC 7662 stack | BBS+ layer | Bolyra AgentPolicy |
|----------|---------------|------------|-------------------|
| AS-blind presentation | No | No (AS signs credential) | **Yes** |
| Runtime-adaptive bitmask predicate | No | Partial (no bitwise AND) | **Yes** |
| Adversarial-AS resilience | No | No (AS trust anchor) | **Yes** |
| Constant-size proof | No | O(\|disclosed\|) | **Yes** (128–256 bytes) |
| Model-identity binding | No | No | **Yes** |
| Full credential privacy (all layers) | No | RS-layer only | **Yes** |
| All six simultaneously | **Impossible** | **Impossible** | **Yes** |

The baseline can achieve subsets (BBS+ gives selective disclosure; DPoP gives sender binding; jwt-introspection-response gives offline verification), but no composition achieves all six. The fundamental barrier is architectural: the baseline stack trusts the AS as the scope authority, while this construction trusts the proving system and the on-chain enrollment root. These are incompatible trust models — you cannot retrofit AS-independence onto a stack whose security definition requires AS honesty. The blinded-leaf construction closes the last remaining gap where on-chain transparency compromised the privacy guarantee, achieving information-theoretic separation between enrollment identity and presentation identity without introducing any additional trusted party, ceremony, or on-chain storage.
