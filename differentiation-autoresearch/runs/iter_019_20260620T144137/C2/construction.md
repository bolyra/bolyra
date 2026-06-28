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
4. The `credentialSecret` used for nullifier derivation is the same secret committed inside the enrolled credential commitment — preventing nullifier splitting and credential hijacking.
5. No credential commitment, operator key, or model hash is revealed.

The AS never sees which RS the agent targets because the agent produces the proof locally and presents it directly to the RS (or via a relay). The AS's role is limited to enrollment (adding leaves to the Merkle tree); it is not on the proving path.

### Credential commitment binding (hardened)

The credential commitment now includes `credentialSecret` as a sixth input:

```
credentialCommitment = Poseidon6(modelHash, operatorPubkeyAx, operatorPubkeyAy,
                                 permissionBitmask, expiryTimestamp, credentialSecret)
```

This binds the nullifier-generating secret to the enrolled Merkle leaf. The operator signs this commitment at enrollment time, meaning the operator endorses the specific secret the agent will use for all future nullifier derivations. Without this binding, an attacker who obtains a valid credential commitment (public on-chain as a Merkle leaf) could pair it with an arbitrary secret, producing valid proofs with attacker-controlled nullifiers — breaking both sybil detection (nullifier splitting) and authorization integrity (credential hijacking).

**Enrollment change**: At enrollment, the agent generates `credentialSecret` locally, computes `credentialCommitment` with all six inputs, and presents the commitment to the operator for signing. The operator signs the commitment (not the individual fields), so the operator never learns `credentialSecret` — it is absorbed into the Poseidon6 hash. The AS receives only the signed commitment for Merkle insertion.

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
2. **Credential commitment (bound to secret)**: `credentialCommitment = Poseidon6(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp, credentialSecret)`. This is the hardened binding — the same Poseidon6 hash that was signed by the operator and enrolled in the Merkle tree now includes `credentialSecret`, so the circuit enforces that the nullifier-generating secret is the one committed at enrollment.
3. **EdDSA signature**: `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)` — proves the operator endorsed this credential (including the bound secret) without revealing the operator's key.
4. **Merkle membership**: `BinaryMerkleRoot(MAX_DEPTH)` with `credentialCommitment` as leaf must equal `agentMerkleRoot`.
5. **Scope satisfaction**: for each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding**: `bits[4]*(1-bits[3]) === 0`, `bits[4]*(1-bits[2]) === 0`, `bits[3]*(1-bits[2]) === 0`.
7. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scope nullifier**: `scopeNullifier = Poseidon2(scopeId, credentialSecret)`. Because constraint 2 forces `credentialSecret` to be the same value inside the enrolled commitment, an agent cannot use an alternative secret to produce a second unlinkable nullifier for the same RS — any valid proof at RS_i from credential C always yields the same `scopeNullifier`.
9. **Blinded scope commitment**: `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingNonce)`.

### Why Poseidon6 and not a separate binding constraint

An alternative design would keep Poseidon5 for the credential commitment and add a separate binding hash (e.g., `secretBinding = Poseidon2(credentialCommitment, credentialSecret)` enrolled as a second leaf). This was rejected because:

- **Single-leaf enrollment**: Poseidon6 keeps one leaf per agent in the Merkle tree, preserving the existing tree structure and root history buffer semantics.
- **No additional Merkle tree**: A separate binding hash would require either a second tree (doubling on-chain storage) or a two-leaf-per-agent scheme (complicating tree management).
- **Operator endorsement covers the secret**: The operator signs `credentialCommitment` which now includes the secret. If the secret were bound separately, the operator would need to sign two values or the binding would be unauthenticated.
- **Constraint efficiency**: Poseidon6 costs ~300 constraints more than Poseidon5 (~1,800 vs ~1,500). A separate Poseidon2 binding + equality check would cost ~550 constraints and add verification complexity.

### Protocol flow (AS-free verification)

1. Agent obtains credential from AS once (enrollment: agent generates `credentialSecret`, computes `credentialCommitment = Poseidon6(...)` including the secret, operator signs the commitment, AS adds commitment to Merkle tree). This is the only AS interaction. The AS sees the commitment but not `credentialSecret` (it is inside the hash).
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

**Setup**: Challenger enrolls N ≥ 2 agents in the Merkle tree. Each agent's `credentialCommitment` is computed via `Poseidon6(modelHash, opAx, opAy, permBitmask, expiry, credentialSecret)`, binding the secret to the enrolled leaf. Adversary A selects two target RSes: RS_a and RS_b (both controlled by A).

**Challenge**: Challenger flips bit b ∈ {0,1}.
- If b = 0: Agent_0 authenticates to RS_a, Agent_1 authenticates to RS_b.
- If b = 1: Agent_0 authenticates to RS_b, Agent_1 authenticates to RS_a.

Challenger provides A with both resulting proofs and all public outputs.

**Adversary wins**: A outputs b' = b.

**Advantage**: `Adv_A = |Pr[b' = b] - 1/2|`

**Claim**: For all PPT adversaries A, `Adv_A ≤ negl(λ)` under the assumptions in §4.

### Soundness under secret binding

The Poseidon6 binding closes two attacks that the Poseidon5 construction left open:

1. **Nullifier splitting**: Without secret binding, an attacker holding a valid credential commitment `C` (visible on-chain as a Merkle leaf) could construct a proof using `C` as the leaf but an arbitrary `credentialSecret' ≠ credentialSecret`. The Merkle proof would pass (the leaf matches), but `scopeNullifier = Poseidon2(scopeId, credentialSecret')` would be a fresh nullifier unlinked to the legitimate agent's nullifier at the same RS. This enables a single credential to produce unbounded distinct nullifiers per RS, defeating sybil detection. With Poseidon6, the circuit recomputes `C' = Poseidon6(..., credentialSecret)` and checks `C' == leaf`. Using a different secret produces a different commitment that is not in the tree — the Merkle proof fails.

2. **Credential hijacking**: Without secret binding, an attacker who observes a valid `credentialCommitment` on-chain could use it as their Merkle leaf, supply their own `credentialSecret`, and produce valid proofs at any RS. The attacker would not need the operator signature (they could forge a different credential with the same commitment — but actually they cannot because Poseidon5 is collision-resistant). More precisely: the attack requires finding `(modelHash', opKey', perm', exp')` such that `Poseidon5(modelHash', opKey'.Ax, opKey'.Ay, perm', exp') = C` for the target commitment `C`. This is blocked by A-CR even without secret binding. However, with Poseidon6 binding, even if an attacker could somehow produce a colliding Poseidon5 value, they would still need the correct `credentialSecret` to match the Poseidon6 commitment — adding defense in depth.

The primary soundness motivation is nullifier splitting prevention. The Poseidon6 binding makes `credentialSecret` part of the authenticated enrollment, ensuring one secret per credential per Merkle leaf.

### Side-channel scope

The game above covers the cryptographic core. Timing side channels are addressed by the batched root refresh mechanism (§2). Network-level metadata (IP addresses, TLS fingerprints) is outside the protocol's scope and must be mitigated by transport-layer mechanisms (Tor, mixnets, VPNs).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security** (A-PRF): Poseidon2, Poseidon3, Poseidon5, Poseidon6 are pseudorandom functions over the BN254 scalar field. Specifically, `Poseidon2(scopeId, ·)` is a PRF keyed by `credentialSecret`.
2. **Discrete logarithm hardness on Baby Jubjub** (A-DL): Given `(Ax, Ay) = BabyPbk(s)`, no PPT adversary can recover `s`.
3. **Poseidon collision resistance** (A-CR): Finding distinct inputs that produce the same Poseidon output is computationally infeasible. This applies to all arities used: Poseidon2, Poseidon3, Poseidon5, Poseidon6.
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

5. **Nullifier splitting excluded by Poseidon6 binding**: Knowledge soundness (A-KS-G16 or A-KS-PLONK) guarantees the prover knows a witness satisfying all constraints. Constraint 2 forces `credentialCommitment = Poseidon6(..., credentialSecret)`, and constraint 4 forces this commitment to be a leaf in the Merkle tree. Therefore, the `credentialSecret` used in the nullifier (constraint 8) is the unique secret enrolled in the tree for that credential. An adversary cannot produce a valid proof using a different secret without either (a) finding a Poseidon6 collision (breaking A-CR) or (b) breaking knowledge soundness. This ensures each credential produces exactly one nullifier per scopeId, which is essential for the IND-UNL-AS game's well-definedness: without it, an agent could present with different secrets at different RSes, trivially winning the game by making its own presentations unlinkable even within the same RS.

6. **Combining**: The adversary's view consists of `(scopeNullifier, blindedScopeCommitment, proof, agentMerkleRoot, scopeId, requiredScopeMask, currentTimestamp)` for each RS. By steps 1–4, each component is either independent of agent identity or computationally indistinguishable between the two challenge worlds. By a standard hybrid argument, `Adv_A ≤ Adv_PRF + Adv_ZK + negl(λ)`.

### Delegation chain privacy

When delegation is used, the `AgentScopeAuth` circuit is applied at the leaf delegatee. The delegatee's own `credentialCommitment` is computed with Poseidon6 (including the delegatee's `credentialSecret`), so the same binding holds. The delegation chain itself is verified separately (via `Delegation` circuit hops), but the final RS-facing presentation uses the delegatee's own `credentialSecret` and `scopeId`-bound nullifier. The AS sees delegation hops at enrollment time but not at RS-authentication time. Cross-scope unlinkability holds for delegated agents by the same argument.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| `credentialCommitment` | `Poseidon6(modelHash, opPubAx, opPubAy, permBitmask, expiry, credentialSecret)` | Extension of draft-bolyra §3.2 Poseidon5 — adds 6th input for secret binding |
| `scopeNullifier` | `Poseidon2(scopeId, credentialSecret)` | Analogous to human nullifier `Poseidon2(scope, secret)` — same pattern, agent domain |
| `blindedScopeCommitment` | `Poseidon3(permBitmask, credentialCommitment, blindingNonce)` | Extension of `scopeCommitment = Poseidon2(permBitmask, credentialCommitment)` with blinding |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | draft-bolyra §2.2 |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | draft-bolyra §2.2 |
| Cumulative bit encoding | bits[4]→bits[3]→bits[2] implication constraints | draft-bolyra §3.2 step 6 |
| Root history buffer | 30-entry circular buffer on-chain | draft-bolyra §2.1 |
| Proving system | PLONK (universal setup, no per-circuit ceremony) for `AgentScopeAuth` | draft-bolyra §2.3 allows PLONK for agent circuits |

**Note on `credentialSecret`**: This is a per-agent secret scalar (Baby Jubjub subgroup order), generated at enrollment time and known only to the agent. It serves the same role as the human `secret` in `HumanUniqueness` — enabling scope-bound nullifier derivation without revealing identity. The Poseidon6 binding ensures it is the same secret committed at enrollment, preventing nullifier splitting.

**Note on Poseidon6 compatibility**: The Bolyra spec (draft-bolyra §2.2) mandates Poseidon over the BN254 scalar field but does not restrict arity. The circomlib Poseidon template supports arities 1–16. Using arity 6 requires no new primitives — only a wider Poseidon round configuration, which is a parameterization of the existing hash, not a new function.

**Migration from Poseidon5**: Existing `AgentPolicy` credentials using Poseidon5 commitments would not be compatible with `AgentScopeAuth`. This is acceptable because `AgentScopeAuth` is a new circuit for cross-scope authentication; the existing `AgentPolicy` circuit continues to serve the mutual handshake flow as specified in draft-bolyra §3.2. Agents that need cross-scope unlinkability re-enroll with a Poseidon6 commitment. The Merkle tree can hold both Poseidon5 and Poseidon6 leaves (they are just field elements); only the circuit determines which format it accepts.

## 6. Circuit cost estimate

### AgentScopeAuth constraint breakdown

| Gadget | Estimated constraints |
|---|---|
| `Num2Bits(251)` — credentialSecret range | ~251 |
| `Poseidon6` — credential commitment (bound to secret) | ~1,800 |
| `EdDSAPoseidonVerifier` | ~6,000 |
| `BinaryMerkleRoot(20)` — 20 levels × ~350 | ~7,000 |
| `Num2Bits(64)` × 3 — permBitmask, expiry, currentTimestamp | ~192 |
| Scope satisfaction — 64 multiplication constraints | ~64 |
| Cumulative bit encoding — 3 constraints | ~3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scope nullifier | ~500 |
| `Poseidon3` — blinded scope commitment | ~750 |
| **Total** | **~16,690** |

The Poseidon5 → Poseidon6 change adds ~300 constraints (one additional Poseidon round). This remains well within `pot16.ptau` (2^16 = 65,536 constraints).

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

**With AgentScopeAuth (Poseidon6-bound credentials)**:

1. **Enrollment (one-time)**: The agent generates `credentialSecret` locally. It computes `credentialCommitment = Poseidon6(modelHash, opAx, opAy, permBitmask, expiry, credentialSecret)`. NFCU's operator signs this commitment (the operator sees only the hash, not `credentialSecret`). NFCU adds the commitment to the on-chain Merkle tree. This is the last AS interaction.

2. **Authentication to Amazon (scopeId = Poseidon("amazon.com"))**: Agent locally generates an `AgentScopeAuth` proof. The circuit internally verifies that `credentialSecret` is the same value baked into the enrolled Poseidon6 commitment. Sends `(proof, scopeNullifier_amazon, blindedScopeCommitment, agentMerkleRoot)` to Amazon's verifier. Amazon sees a valid agent with READ_DATA + FINANCIAL_SMALL permissions, expiry in the future, enrolled in the NFCU tree. Amazon does NOT see the operator key, model hash, or any identifier linkable to the agent's nullifier at Costco.

3. **Authentication to Costco (scopeId = Poseidon("costco.com"))**: Same flow, different `scopeId`. `scopeNullifier_costco = Poseidon2(Poseidon("costco.com"), credentialSecret)`. Completely unlinkable to `scopeNullifier_amazon` by A-PRF. The Poseidon6 binding guarantees this is the same `credentialSecret` used at Amazon — the agent cannot split its identity by using different secrets at different RSes.

4. **NFCU (AS) sees**: Nothing after enrollment. No token issuance requests. No scope queries. No timing signals. The agent proved membership in the NFCU tree without contacting NFCU.

5. **Colluding Amazon + NFCU**: Amazon shares `scopeNullifier_amazon` with NFCU. NFCU cannot map it back to any enrolled agent because NFCU does not know `credentialSecret` (it was hashed inside the Poseidon6 commitment before NFCU ever saw it). By A-CR and A-PRF, NFCU cannot brute-force the mapping without inverting Poseidon.

6. **Why Poseidon6 matters here**: Without secret binding, a rogue agent could enroll once but use different secrets at Amazon and Costco, generating unrelated nullifiers. If the sybil-detection policy says "one agent per RS," the rogue agent would bypass it by presenting with a fresh secret at each RS. With Poseidon6, the circuit forces the same `credentialSecret` that was committed at enrollment, so one credential = one nullifier per RS, and sybil detection holds.

### Healthcare variant

**Stakeholder**: Kaiser Permanente, acting as primary care issuer.

A patient delegates a scoped credential (READ_DATA only) to a specialist referral agent. The delegatee re-enrolls with a Poseidon6 commitment binding its own `credentialSecret`. The agent authenticates to LabCorp (scopeId = "labcorp") and Radiology Associates (scopeId = "radassoc") independently. Kaiser cannot learn which downstream providers the patient visited, even if Kaiser colludes with one of them. The delegation chain (via `Delegation` circuit) narrows permissions but the final RS-facing presentation uses `AgentScopeAuth` with the delegatee's Poseidon6-bound secret and RS-specific nullifiers.

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
| **Sybil-resistant nullifiers** | No mechanism; bearer tokens are freely duplicable | Poseidon6 binding ensures one `credentialSecret` per enrolled credential — one nullifier per (agent, RS) pair, enforced in-circuit |

The baseline's fundamental architectural limitation is that the AS is on the critical path for every authorization. Removing the AS from per-request authentication is not achievable by layering additional OAuth/OIDC extensions — it requires replacing the token-issuance model with a local-proving model. The `AgentScopeAuth` circuit achieves this by shifting verification from "AS vouches for agent" to "agent proves its own enrollment," making the AS structurally unable to observe or correlate cross-RS traffic. The Poseidon6 secret binding further ensures that this local-proving model maintains soundness: one enrolled credential produces exactly one nullifier per RS, preventing identity splitting that would undermine the unlinkability guarantee's preconditions.
