# Construction

## 1. Statement of claim

Same agent accessing different Resource Server (RS) instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that:
- issues all credentials,
- observes all token-issuance requests with their timestamps,
- colludes with any subset of RSes,
- attempts to reconstruct per-agent cross-RS traffic graphs.

Formally: no PPT adversary controlling the AS and up to n−1 of n RSes can distinguish, with non-negligible advantage, whether two authorization presentations at distinct RSes originate from the same agent or from two independent agents enrolled in the same Merkle tree.

## 2. Construction (gadgets, circuits, public/private inputs)

### Core idea: scope-domain nullifiers with blinded credential presentation

Each RS is assigned a unique `scopeId` (e.g., hash of the RS's domain). When an agent authenticates to RS_i, it produces a ZK proof that:
1. It holds a valid, operator-signed credential enrolled in the agent Merkle tree.
2. Its permissions satisfy the RS's required scope mask.
3. The nullifier is derived as `Poseidon2(scopeId_i, credentialSecret)` — deterministic per (agent, RS) but unlinkable across RSes.
4. No credential commitment, operator key, or model hash is revealed.

The AS never sees which RS the agent targets because the agent produces the proof locally and presents it directly to the RS (or via a relay). The AS's role is limited to enrollment (adding leaves to the Merkle tree); it is not on the proving path.

### New circuit: `AgentScopeAuth`

**Private inputs:**
- `modelHash`: hash of model identifier
- `operatorPubkeyAx`, `operatorPubkeyAy`: operator EdDSA public key (Baby Jubjub)
- `permissionBitmask`: 64-bit permission bitfield
- `expiryTimestamp`: credential expiry (Unix timestamp)
- `sigR8x`, `sigR8y`, `sigS`: operator EdDSA signature over credential commitment
- `credentialSecret`: per-agent secret scalar (Baby Jubjub subgroup order), range-checked to [0, 2^251)
- `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[MAX_DEPTH]`: Merkle inclusion proof
- `blindingNonce`: random field element chosen fresh per presentation (for randomizing the proof output and preventing timing correlation of deterministic signals)

**Public inputs:**
- `scopeId`: RS-specific domain identifier
- `requiredScopeMask`: policy-required permission bits
- `currentTimestamp`: verifier-supplied current time
- `agentMerkleRoot`: on-chain agent tree root (verified against root history buffer)

**Public outputs:**
- `scopeNullifier`: `Poseidon2(scopeId, credentialSecret)` — deterministic per (agent, scope), enables double-auth detection within a single RS, unlinkable across RSes
- `blindedScopeCommitment`: `Poseidon3(permissionBitmask, credentialCommitment, blindingNonce)` — randomized per presentation so even the same agent at the same RS on two sessions produces distinct scope commitments
- `expiryFlag`: 1 if `currentTimestamp < expiryTimestamp`, else 0 (constrained via LessThan(64))

### Circuit constraints (AgentScopeAuth)

1. **Secret range**: `Num2Bits(251)` on `credentialSecret`, ensuring it lies in [0, 2^251).
2. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA signature**: `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)` — proves the operator endorsed this credential without revealing the operator's key.
4. **Merkle membership**: `BinaryMerkleRoot(MAX_DEPTH)` with `credentialCommitment` as leaf must equal `agentMerkleRoot`.
5. **Scope satisfaction**: for each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding**: `bits[4]*(1-bits[3]) === 0`, `bits[4]*(1-bits[2]) === 0`, `bits[3]*(1-bits[2]) === 0`.
7. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scope nullifier**: `scopeNullifier = Poseidon2(scopeId, credentialSecret)`.
9. **Blinded scope commitment**: `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingNonce)`.

### Protocol flow (AS-free verification)

1. Agent obtains credential from AS once (enrollment: operator signs credential, AS adds commitment to Merkle tree). This is the only AS interaction.
2. Agent locally generates `AgentScopeAuth` proof for target RS_i using `scopeId_i`.
3. Agent sends `(proof, scopeNullifier, blindedScopeCommitment, agentMerkleRoot, scopeId, requiredScopeMask, currentTimestamp)` directly to RS_i (or to an on-chain verifier).
4. RS_i (or on-chain contract) verifies:
   - `agentMerkleRoot` is in the root history buffer.
   - `scopeNullifier` has not been used within the current session window (replay prevention).
   - PLONK/Groth16 proof is valid.
   - `expiryFlag == 1`.
5. RS_i accepts. The AS is never contacted. No token is issued.

### Anti-timing construction: batched proof submission

To defeat AS timing correlation (observing when an agent fetches the latest Merkle root), the protocol defines:
- **Root caching**: agents cache the Merkle root at enrollment time and at periodic sync intervals (e.g., every 6 hours). The 30-entry root history buffer tolerates stale roots.
- **Batched root refresh**: agents fetch root updates in fixed-size batches via a public bulletin board (e.g., on-chain event logs), not via AS API calls. The AS cannot distinguish which root an agent uses.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (full state: enrollment records, issuance logs, timing)
- Up to n−1 of n Resource Servers (full state: received proofs, nullifiers, timing)
- Network-level observation of agent-to-RS communication metadata (but not TLS payload)

The adversary does NOT control:
- The agent's local proving environment (no side-channel access to private inputs)
- The on-chain Merkle tree contract (public, immutable state)
- The Poseidon hash function or Baby Jubjub discrete log (computational assumptions)

### IND-UNL-AS game

**Setup**: Challenger enrolls N ≥ 2 agents in the Merkle tree. Adversary A selects two target RSes: RS_a and RS_b (both controlled by A).

**Challenge**: Challenger flips bit b ∈ {0,1}.
- If b = 0: Agent_0 authenticates to RS_a, Agent_1 authenticates to RS_b.
- If b = 1: Agent_0 authenticates to RS_b, Agent_1 authenticates to RS_a.

Challenger provides A with both resulting proofs and all public outputs.

**Adversary wins**: A outputs b' = b.

**Advantage**: `Adv_A = |Pr[b' = b] - 1/2|`

**Claim**: For all PPT adversaries A, `Adv_A ≤ negl(λ)` under the assumptions in §4.

### Side-channel scope

The game above covers the cryptographic core. Timing side channels are addressed by the batched root refresh mechanism (§2). Network-level metadata (IP addresses, TLS fingerprints) is outside the protocol's scope and must be mitigated by transport-layer mechanisms (Tor, mixnets, VPNs).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security** (A-PRF): Poseidon2, Poseidon3, Poseidon5 are pseudorandom functions over the BN254 scalar field. Specifically, `Poseidon2(scopeId, ·)` is a PRF keyed by `credentialSecret`.
2. **Discrete logarithm hardness on Baby Jubjub** (A-DL): Given `(Ax, Ay) = BabyPbk(s)`, no PPT adversary can recover `s`.
3. **Poseidon collision resistance** (A-CR): Finding `(x, y) ≠ (x', y')` such that `Poseidon2(x, y) = Poseidon2(x', y')` is computationally infeasible.
4. **Knowledge soundness of Groth16** (A-KS-G16): In the generic group model + random oracle model, Groth16 proofs are knowledge-sound — a valid proof implies the prover knows a satisfying witness.
5. **Knowledge soundness of PLONK** (A-KS-PLONK): Under ROM, PLONK proofs are knowledge-sound.
6. **Zero-knowledge property** (A-ZK): Groth16 and PLONK are computationally zero-knowledge — the proof reveals nothing about private inputs beyond the truth of the statement.

### Reduction sketch

**Theorem**: If A wins the IND-UNL-AS game with non-negligible advantage, then either A-PRF or A-ZK is broken.

**Proof sketch**:

1. **Nullifier unlinkability**: The adversary sees `scopeNullifier_a = Poseidon2(scopeId_a, credentialSecret_j)` and `scopeNullifier_b = Poseidon2(scopeId_b, credentialSecret_k)` where `scopeId_a ≠ scopeId_b`. By A-PRF, the outputs of `Poseidon2(scopeId_a, ·)` and `Poseidon2(scopeId_b, ·)` are computationally indistinguishable from random, even when the adversary knows both `scopeId` values. Therefore the adversary cannot determine whether `j = k` (same agent) or `j ≠ k` (different agents) from the nullifiers.

2. **Blinded scope commitment unlinkability**: Each presentation uses a fresh `blindingNonce`, so `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingNonce)` is a fresh random-looking value per presentation, even if the underlying credential is the same. By A-PRF (keyed on blindingNonce), two blinded commitments from the same agent are indistinguishable from two commitments from different agents.

3. **Proof transcript unlinkability**: By A-ZK, the proof π reveals nothing about the private witness (credentialSecret, operator key, model hash, Merkle path). Two proofs from the same agent are simulatable without the witness, hence indistinguishable from proofs by different agents.

4. **Merkle root leakage**: Both agents use the same `agentMerkleRoot` (public). This reveals nothing about which leaf was used (Merkle membership proofs are zero-knowledge by A-ZK).

5. **Combining**: The adversary's view consists of `(scopeNullifier, blindedScopeCommitment, proof, agentMerkleRoot, scopeId, requiredScopeMask, currentTimestamp)` for each RS. By steps 1–4, each component is either independent of agent identity or computationally indistinguishable between the two challenge worlds. By a standard hybrid argument, `Adv_A ≤ Adv_PRF + Adv_ZK + negl(λ)`.

### Delegation chain privacy

When delegation is used, the `AgentScopeAuth` circuit is applied at the leaf delegatee. The delegation chain itself is verified separately (via `Delegation` circuit hops), but the final RS-facing presentation uses the delegatee's own `credentialSecret` and `scopeId`-bound nullifier. The AS sees delegation hops at enrollment time but not at RS-authentication time. Cross-scope unlinkability holds for delegated agents by the same argument.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| `credentialCommitment` | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | draft-bolyra §3.2, AgentPolicy circuit |
| `scopeNullifier` | `Poseidon2(scopeId, credentialSecret)` | Analogous to human nullifier `Poseidon2(scope, secret)` — same pattern, agent domain |
| `blindedScopeCommitment` | `Poseidon3(permBitmask, credentialCommitment, blindingNonce)` | Extension of `scopeCommitment = Poseidon2(permBitmask, credentialCommitment)` with blinding |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | draft-bolyra §2.2 |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | draft-bolyra §2.2 |
| Cumulative bit encoding | bits[4]→bits[3]→bits[2] implication constraints | draft-bolyra §3.2 step 6 |
| Root history buffer | 30-entry circular buffer on-chain | draft-bolyra §2.1 |
| Proving system | PLONK (universal setup, no per-circuit ceremony) for `AgentScopeAuth` | draft-bolyra §2.3 allows PLONK for agent circuits |

**Note on `credentialSecret`**: This is a new per-agent secret scalar (Baby Jubjub subgroup order), distinct from the operator's signing key. It is generated at agent enrollment time and known only to the agent. It serves the same role as the human `secret` in `HumanUniqueness` — enabling scope-bound nullifier derivation without revealing identity.

## 6. Circuit cost estimate

### AgentScopeAuth constraint breakdown

| Gadget | Estimated constraints |
|---|---|
| `Num2Bits(251)` — credentialSecret range | ~251 |
| `Poseidon5` — credential commitment | ~1,500 |
| `EdDSAPoseidonVerifier` | ~6,000 |
| `BinaryMerkleRoot(20)` — 20 levels × ~350 | ~7,000 |
| `Num2Bits(64)` × 3 — permBitmask, expiry, currentTimestamp | ~192 |
| Scope satisfaction — 64 multiplication constraints | ~64 |
| Cumulative bit encoding — 3 constraints | ~3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scope nullifier | ~500 |
| `Poseidon3` — blinded scope commitment | ~750 |
| **Total** | **~16,390** |

This fits within `pot16.ptau` (2^16 = 65,536 constraints).

### Proving time targets

| Proving system | Target | Rationale |
|---|---|---|
| PLONK (primary) | < 3s on consumer hardware | Agent-facing, universal setup, no per-circuit ceremony |
| Groth16 (optional) | < 2s on consumer hardware | Smaller proof, but requires circuit-specific ceremony |
| PLONK via rapidsnark | < 500ms | Production path with native prover |

The circuit is comparable in size to the existing `AgentPolicy` circuit (~15K constraints) and well within the benchmarked proving times in `circuits/scripts/bench_rapidsnark.js`.

## 7. Concrete deployment scenario

### Credit union cross-merchant agent authorization

**Stakeholder**: Navy Federal Credit Union (NFCU), acting as both the credential issuer (AS) and a regulated financial institution subject to GLBA and Reg E.

**Scenario**: A NFCU member deploys an AI agent (e.g., a budgeting assistant) that interacts with multiple merchant RSes — Amazon, Costco, a local pharmacy — to check prices, initiate payments, and manage subscriptions. Under current OAuth/OIDC architecture, NFCU-as-AS sees every token issuance: "Member #12345's agent requested access to Amazon at 14:02, Costco at 14:07, CVS Pharmacy at 14:15." This builds a complete merchant interaction graph.

**With AgentScopeAuth**:

1. **Enrollment (one-time)**: NFCU issues the agent a signed credential with `permissionBitmask = 0b00000101` (READ_DATA + FINANCIAL_SMALL). The agent generates a `credentialSecret` locally. NFCU adds the credential commitment to the on-chain Merkle tree. NFCU knows the agent exists but this is the last time it is involved.

2. **Authentication to Amazon (scopeId = Poseidon("amazon.com"))**: Agent locally generates an `AgentScopeAuth` proof. Sends `(proof, scopeNullifier_amazon, blindedScopeCommitment, agentMerkleRoot)` to Amazon's verifier. Amazon checks the proof on-chain (or locally with the verification key). Amazon sees a valid agent with READ_DATA + FINANCIAL_SMALL permissions, expiry in the future, enrolled in the NFCU tree. Amazon does NOT see the operator key, model hash, or any identifier linkable to the agent's Amazon nullifier at Costco.

3. **Authentication to Costco (scopeId = Poseidon("costco.com"))**: Same flow, different `scopeId`. `scopeNullifier_costco = Poseidon2(Poseidon("costco.com"), credentialSecret)`. Completely unlinkable to `scopeNullifier_amazon` by A-PRF.

4. **NFCU (AS) sees**: Nothing after enrollment. No token issuance requests. No scope queries. No timing signals. The agent proved membership in the NFCU tree without contacting NFCU.

5. **Colluding Amazon + NFCU**: Amazon shares `scopeNullifier_amazon` with NFCU. NFCU cannot map it back to any enrolled agent because NFCU does not know the agent's `credentialSecret` (only the credential commitment, which is a one-way Poseidon5 hash). By A-CR and A-PRF, NFCU cannot brute-force the mapping without inverting Poseidon.

### Healthcare variant

**Stakeholder**: Kaiser Permanente, acting as primary care issuer.

A patient delegates a scoped credential (READ_DATA only) to a specialist referral agent. The agent authenticates to LabCorp (scopeId = "labcorp") and Radiology Associates (scopeId = "radassoc") independently. Kaiser cannot learn which downstream providers the patient visited, even if Kaiser colludes with one of them. The delegation chain (via `Delegation` circuit) narrows permissions but the final RS-facing presentation uses `AgentScopeAuth` with RS-specific nullifiers.

## 8. Why the baseline cannot match

| Dimension | Baseline (PPID + RFC 8707 + DPoP + BBS+) | AgentScopeAuth |
|---|---|---|
| **AS visibility at auth time** | AS issues every token; sees agent, RS, scope, timestamp for every request | AS is not contacted after enrollment; zero per-request visibility |
| **AS + RS collusion** | AS holds PPID mapping; trivially deanonymizes any RS it colludes with | AS has no mapping from scopeNullifier to agent; Poseidon PRF prevents brute-force |
| **Formal security definition** | None. No RFC defines an IND-UNL-AS game or equivalent | IND-UNL-AS game defined (§3) with reduction to Poseidon PRF + ZK (§4) |
| **Scope correlation at AS** | AS sees requested scope for every RS at token-issuance time | scopeId is embedded in the proof, never sent to AS |
| **Delegation chain privacy** | RFC 8693 requires AS roundtrip per hop; AS sees full chain topology | Delegation circuit proves scope narrowing in ZK; final RS auth via AgentScopeAuth hides chain origin |
| **Timing side channels** | DPoP includes timestamps visible to AS; no batching mechanism | Root caching + batched refresh; AS never sees per-RS timing |
| **Nullifier domain separation** | Not applicable — no nullifier concept | `Poseidon2(scopeId, credentialSecret)` produces cryptographically independent nullifiers per RS, provably unlinkable under PRF assumption |
| **Issuer anonymity** | BBS+ exposes issuer public key in every derived proof | Operator key is a private circuit input; never revealed to RS |

The baseline's fundamental architectural limitation is that the AS is on the critical path for every authorization. Removing the AS from per-request authentication is not achievable by layering additional OAuth/OIDC extensions — it requires replacing the token-issuance model with a local-proving model. The `AgentScopeAuth` circuit achieves this by shifting verification from "AS vouches for agent" to "agent proves its own enrollment," making the AS structurally unable to observe or correlate cross-RS traffic.
