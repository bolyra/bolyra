It seems file write permissions aren't being granted for this path. Could you approve the write permission so I can save the `construction.md`? Alternatively, here's the complete construction output:

---

# Construction

## 1. Statement of claim

An AI agent proves that its private 64-bit permission bitmask satisfies an RS-specified required-scope mask (`permissionBitmask & requiredMask == requiredMask`) without revealing `permissionBitmask`, without any AS roundtrip at proof time, with a constant-size proof regardless of bitmask width, and with cryptographic assurance that a semi-trusted AS cannot fabricate the underlying permission grant — properties that no configuration of RFC 7662, JWT introspection response, RFC 8693, RFC 8707, DPoP, or W3C VC + BBS+ selective disclosure can match individually or simultaneously.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `SelectiveScopeProof` (PLONK, agent-side)

Extends the Bolyra `AgentPolicy` circuit with RS-specified runtime predicate evaluation and an independent operator registry membership check for adversarial-AS resistance.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of agent model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield (hidden from RS) |
| `expiryTimestamp` | uint64 | Credential expiration Unix timestamp |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature components |
| `merkleProofLength` | uint | Actual Merkle depth |
| `merkleProofIndex` | uint | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Merkle siblings (padded to depth 20) |
| `opRegistryProofLength` | uint | Operator registry Merkle depth |
| `opRegistryProofIndex` | uint | Operator registry leaf index |
| `opRegistryProofSiblings[20]` | F_p[20] | Operator registry Merkle siblings |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits (runtime) |
| `currentTimestamp` | uint64 | Current time from verifier |
| `sessionNonce` | F_p | Session binding |
| `operatorRegistryRoot` | F_p | Merkle root of operator public key registry |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Credential tree root |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` |

**Constraints (in order):**

1. **Range checks**: `Num2Bits(64)` on `permissionBitmask` → `permBits[0..63]`, `requiredScopeMask` → `reqBits[0..63]`, `expiryTimestamp`, `currentTimestamp`

2. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`

3. **Operator EdDSA signature**: EdDSAPoseidonVerifier over `credentialCommitment` using `(operatorPubkeyAx, operatorPubkeyAy)` — binds the permission bitmask to a specific operator's signing key

4. **Operator registry membership**: `operatorLeaf = Poseidon2(operatorPubkeyAx, operatorPubkeyAy)`, prove membership in operator registry tree with root `operatorRegistryRoot` — **adversarial-AS defense**

5. **Credential Merkle membership**: `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf → `agentMerkleRoot`

6. **Bitmask predicate evaluation**: `for i in [0, 64): reqBits[i] * (1 - permBits[i]) === 0` — enforces `requiredScopeMask & permissionBitmask == requiredScopeMask`

7. **Cumulative bit encoding**: `permBits[4] * (1 - permBits[3]) === 0`, `permBits[4] * (1 - permBits[2]) === 0`, `permBits[3] * (1 - permBits[2]) === 0`

8. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`

9. **Nullifier**: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`

10. **Scope commitment**: `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`

### Enrollment Protocol (one-time)

Operator registers its public key in an on-chain **Operator Registry Merkle Tree** (depth 20, Poseidon2). Independent of the AS. RS pins `operatorRegistryRoot` as public input.

### Presentation Protocol (per-request)

1. RS sends `(requiredScopeMask, currentTimestamp, sessionNonce)` to agent.
2. Agent generates PLONK proof with private credential + RS-specified public inputs.
3. RS verifies against `operatorRegistryRoot` and `agentMerkleRoot` from chain. No AS contact.

## 3. Threat model (adversary capabilities, game definition)

**Adversaries:**
- **Semi-trusted AS (A_AS):** Controls credential issuance. May inflate permissions or forge credentials. Cannot corrupt operator registry.
- **Colluding RS (A_RS):** Receives proofs. May try to extract full `permissionBitmask` or link proofs.
- **Network observer (A_net):** Sees on-chain transcripts. May attempt linkability.

**Game SSU (Selective Scope Unforgeability):**
1. Challenger enrolls operator with credential `P*`.
2. Adversary gets `pk_op`, roots, and proof oracle.
3. Adversary wins by producing valid proof for `requiredScopeMask*` where `P* & requiredScopeMask* != requiredScopeMask*`.

**Game SSP (Scope Privacy):**
1. Challenger holds credentials `P_0, P_1` both satisfying challenge mask `M`.
2. Flips coin `b`, proves with `P_b`.
3. Adversary wins if `Pr[b' = b] > 1/2 + negl(lambda)`.

**Game AFR (AS-Fabrication Resistance):**
1. Operator registry has keys `{pk_1, ..., pk_n}`.
2. Malicious AS (no `sk_i`) wins by producing valid proof against `operatorRegistryRoot`.

## 4. Security argument (named assumption + reduction sketch)

**Assumptions:**
- **A1:** Knowledge soundness of PLONK (AGM + ROM)
- **A2:** Collision resistance of Poseidon over BN254
- **A3:** Discrete log hardness on Baby Jubjub
- **A4:** EU-CMA of EdDSA-Poseidon (reduces to A3 + ROM)

**SSU reduction:** Extract witness via A1. Constraint 6 forces `permissionBitmask' != P*`. Constraint 3 forces valid EdDSA on `credentialCommitment' != credentialCommitment` (by A2). New valid signature breaks EU-CMA (A4).

**AFR reduction:** Extract witness via A1. Constraint 4 forces operator leaf under `operatorRegistryRoot`. By A2, matches enrolled `pk_i`. Valid EdDSA under `pk_i` without `sk_i` breaks EU-CMA (A4).

**SSP reduction:** PLONK ZK property — transcript simulatable from public signals. `permissionBitmask` private. Distinguishing requires inverting Poseidon (A2) or breaking ZK simulator.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Permission bitmask | 64-bit cumulative bit encoding | AgentPolicy constraints 5-6 |
| Bitmask predicate | `reqBits[i] * (1 - permBits[i]) === 0` | AgentPolicy constraint 5 |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` | AgentPolicy constraint 2 |
| Operator signature | EdDSAPoseidonVerifier on Baby Jubjub | AgentPolicy constraint 3 |
| Credential Merkle | BinaryMerkleRoot(20) with Poseidon2 | AgentPolicy constraint 4 |
| Nullifier | `Poseidon2(credentialCommitment, sessionNonce)` | AgentPolicy nullifier |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | Delegation chain seed |
| Session binding | `sessionNonce` public input | Handshake step 1 |
| Proving system | PLONK universal setup | Spec section 3.3 |
| Expiry | `LessThan(64)` | AgentPolicy constraint 7 |

**Extension:** Operator Registry Merkle Tree — second on-chain LIMT (depth 20, Poseidon2), `Poseidon2(opAx, opAy)` leaves, 30-entry root history buffer.

## 6. Circuit cost estimate

| Gadget | Constraints |
|--------|------------|
| `Num2Bits(64)` x 4 | 256 |
| `Poseidon5` (credential) | ~300 |
| `EdDSAPoseidonVerifier` | ~4,500 |
| `BinaryMerkleRoot(20)` x 2 | ~2,600 |
| `Poseidon2` x 3 | ~180 |
| Bitmask AND (64 muls) | 64 |
| Cumulative encoding | 3 |
| `LessThan(64)` | ~130 |
| **Total** | **~8,033** |

Proving: < 5s PLONK (agent). Verification: O(1), ~768 bytes, ~200K gas EVM.

## 7. Concrete deployment scenario

### Stakeholder: State Employees' Credit Union (SECU), North Carolina

SECU deploys AI agents across 260+ branches with 64-bit policy space: branch tiers (bits 0-4 cumulative), products (bits 5-15), dollar thresholds (bits 16-31), regulatory flags (bits 32-47: BSA/AML, OFAC, FCRA, ECOA), audit (bits 48-63).

**Problem:** OAuth AS is a hot-path bottleneck. Compliance needs cryptographic proof that FCRA-accessing agents hold FCRA permission *independent of AS integrity* — a compromised AS could grant unauthorized FCRA access, creating liability under 15 U.S.C. 1681.

**Flow:** RS specifies `requiredScopeMask = 0x0000_0001_0000_0020` (FCRA + tier-2). Agent proves in <5s without revealing full permissions. RS verifies against on-chain roots — no AS contact. Compromised AS cannot forge without enrolled operator's EdDSA key. NCUA examiners verify every FCRA event has a ZK proof — authorization assurance independent of AS integrity.

## 8. Why the baseline cannot match

Five independent structural gaps:

1. **No bitmask predicate:** BBS+ is claim-granular. Cannot evaluate `bitmask & mask == mask` over hidden integers. Encoding 2^64 permissions as BBS+ messages is infeasible. Circuit does it in 64 constraints.

2. **No adversarial-AS resistance:** BBS+ verification confirms internal consistency with issuer signature — malicious AS can claim anything. Circuit requires operator registry membership (separate trust root).

3. **No runtime-adaptive predicates:** BBS+ claims fixed at issuance. `requiredScopeMask` as a PLONK public input evaluates predicates unknown to the issuer. Impossible with static signatures.

4. **No constant-size proof:** BBS+ is O(N) in claims. PLONK is O(1) (~768 bytes) regardless of bitmask width.

5. **No AS-blind presentation:** BBS+ requires AS to encode all permissions. Circuit presentation is fully AS-blind — AS learns nothing about which RS, which mask, or that a proof occurred.

**Formal separation:** BBS+ is selective disclosure over signed messages — a strict special case of committed-input circuit evaluation. Bitmask intersection over hidden integers has no representation in the selective disclosure model without an external NIZK, at which point the construction is no longer BBS+.
