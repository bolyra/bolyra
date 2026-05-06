# Construction

## 1. Statement of claim

Same agent accessing different RS instances produces cryptographically unlinkable authorizations even under an adversarial AS that controls enrollment, logs all Merkle-tree updates, and colludes with any subset of RS instances. The construction provides a formal IND-UNL-AS game definition and achieves negligible adversary advantage under the Poseidon PRF assumption on BN254.

## 2. Construction (gadgets, circuits, public/private inputs)

### Architecture: AS-blind per-RS authorization

The AS is relegated to **enrollment only**. Per-RS authorization bypasses the AS entirely: the agent generates a PLONK proof directly presentable to the RS (or verified on-chain), eliminating the token-issuance channel that the baseline cannot protect.

### New circuit: `ScopedAccess` (PLONK, agent-side)

This circuit proves: "I am an enrolled agent with sufficient permissions for this RS's scope, and here is a scope-bound nullifier that prevents double-access within this scope-epoch, but reveals nothing linkable across scopes."

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentSecret` | F_p | Agent's long-term secret scalar (Baby Jubjub) |
| `modelHash` | F_p | Hash of agent model identifier |
| `operatorPubkeyAx, operatorPubkeyAy` | F_p | Operator EdDSA public key |
| `permissionBitmask` | 64-bit | Agent's actual permission bits |
| `expiryTimestamp` | 64-bit | Credential expiry |
| `sigR8x, sigR8y, sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofIndex, merkleProofLength, merkleProofSiblings[20]` | - | Merkle inclusion proof |
| `epochSalt` | F_p | Per-epoch randomness committed on-chain |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., Poseidon hash of RS domain) |
| `requiredScopeMask` | 64-bit | Minimum permission bits required by this RS |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `epochCommitment` | F_p | Poseidon2(epochSalt, scopeId) — committed on-chain at epoch start |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against root history buffer) |
| `scopeNullifier` | F_p | Poseidon2(scopeId, agentSecret) — unlinkable across scopes |
| `epochBinding` | F_p | Poseidon2(scopeNullifier, epochSalt) — replay prevention within epoch |

**Constraints:**

1. **Secret range**: `Num2Bits(251)` on `agentSecret`, ensuring `agentSecret ∈ [0, 2^251)`.
2. **Agent public key derivation**: `(Ax, Ay) = BabyPbk(agentSecret)`.
3. **Credential commitment**: `credComm = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
4. **EdDSA signature verification**: `EdDSAPoseidonVerifier((operatorPubkeyAx, operatorPubkeyAy), credComm, (sigR8x, sigR8y, sigS))`.
5. **Merkle membership**: `BinaryMerkleRoot(20)` with `credComm` as leaf produces `agentMerkleRoot`.
6. **Scope satisfaction**: For each bit `i ∈ [0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`.
7. **Cumulative bit encoding**: `permBits[4]*(1-permBits[3]) === 0`, `permBits[4]*(1-permBits[2]) === 0`, `permBits[3]*(1-permBits[2]) === 0`.
8. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
9. **Scope nullifier**: `scopeNullifier = Poseidon2(scopeId, agentSecret)` — deterministic per (scope, agent), independent of credential fields.
10. **Epoch binding**: `epochBinding = Poseidon2(scopeNullifier, epochSalt)`.
11. **Epoch commitment check**: `epochCommitment === Poseidon2(epochSalt, scopeId)` — proves the agent used the correct epoch salt without revealing it to the verifier independently of the proof.
12. **Range checks**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.

### Key design choices

- **`agentSecret` replaces `credentialCommitment` in the nullifier.** The Bolyra spec's agent nullifier is `Poseidon2(credentialCommitment, sessionNonce)`. This leaks structure: the credentialCommitment is deterministic per agent enrollment, so an AS that enrolled the agent knows it. Our nullifier uses the agent's *secret scalar* (never revealed to the AS) as the binding element, making the nullifier a PRF output keyed by the secret.

- **No AS roundtrip per RS access.** The agent proves directly to the RS. The RS checks the proof against the on-chain Merkle root and nullifier set. The AS never sees which RS was accessed.

- **Epoch salt for replay prevention.** Each scope-epoch pair gets a fresh on-chain salt. The `epochBinding` is published (not the raw nullifier to the chain if off-chain verification is used), preventing replay within the epoch while the `scopeNullifier` remains constant per (scope, agent) for sybil detection.

### Integration with existing Bolyra handshake

The `ScopedAccess` circuit is invoked **after** the mutual handshake. The handshake establishes mutual authentication (human + agent). Subsequent RS accesses use `ScopedAccess` proofs without further AS involvement:

1. Handshake: Human + Agent authenticate via existing `HumanUniqueness` + `AgentPolicy` circuits → session established.
2. RS access: Agent generates `ScopedAccess` proof per RS, presented directly to the RS or verified on-chain.
3. Delegation: If the agent delegates to a sub-agent, the existing `Delegation` circuit narrows scope. The sub-agent then uses `ScopedAccess` with its own `agentSecret` and delegated `permissionBitmask`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary **A** controls the Authorization Server (AS) and may:

- **Enrollment omniscience**: Observe all enrollment transactions, including credential commitments, operator public keys, and Merkle tree updates.
- **Log retention**: Maintain complete logs of all handshake verifications (human nullifiers, agent nullifiers, session nonces, scope commitments).
- **RS collusion**: Collude with up to `n-1` of `n` RS instances, receiving their access logs (scopeNullifiers, epochBindings, timestamps, proof transcripts).
- **Nonce manipulation**: Supply adversarially chosen `scopeId` values, `epochCommitment` values, and timestamps.
- **Timing observation**: Observe sub-millisecond timing of on-chain proof verifications.
- **Adaptive queries**: Choose challenge agents and scopes adaptively after observing the system.

The adversary **cannot**:

- Extract the agent's secret scalar (stored in a secure enclave or TEE on the agent's host).
- Break the knowledge soundness of the PLONK proving system.
- Find collisions in Poseidon over BN254.

### Game: IND-UNL-AS (Indistinguishability under Unlinkability against Adversarial AS)

**Setup**: Challenger enrolls `q` agents with secrets `s_1, ..., s_q` in the agent Merkle tree. Adversary A receives all credential commitments and the full Merkle tree.

**Phase 1 (Adaptive queries)**: A may request `ScopedAccess` proofs for any (agent `i`, scope `j`) pair. A receives the public outputs `(agentMerkleRoot, scopeNullifier, epochBinding)` for each query.

**Challenge**: A selects two distinct agents `i_0, i_1` and two distinct scopes `j_0, j_1` such that A has not previously queried `(i_0, j_0)`, `(i_0, j_1)`, `(i_1, j_0)`, or `(i_1, j_1)`. Challenger flips bit `b ←$ {0,1}`:

- If `b = 0`: Challenger returns `(π_A, π_B)` where `π_A` is a `ScopedAccess` proof for `(i_0, j_0)` and `π_B` is for `(i_0, j_1)` (same agent, two scopes).
- If `b = 1`: Challenger returns `(π_A, π_B)` where `π_A` is a `ScopedAccess` proof for `(i_0, j_0)` and `π_B` is for `(i_1, j_1)` (different agents, two scopes).

**Phase 2**: A may make additional adaptive queries (excluding the four challenge pairs).

**Output**: A outputs `b'`. A wins if `b' = b`.

**Advantage**: `Adv^{IND-UNL-AS}_A = |Pr[b' = b] - 1/2|`

**Claim**: For all PPT adversaries A, `Adv^{IND-UNL-AS}_A ≤ Adv^{PRF}_{Poseidon} + Adv^{KS}_{PLONK}` where `Adv^{PRF}_{Poseidon}` is the advantage in distinguishing Poseidon2 from a random function and `Adv^{KS}_{PLONK}` is the knowledge-soundness advantage against the PLONK proving system.

### Side-channel threat: Timing

**Mitigation**: The `epochBinding` batching mechanism. Rather than submitting proofs to the chain in real-time, agents submit `epochBinding` values to a **shuffled batch contract** at epoch boundaries (e.g., every 15 minutes). The contract accepts a batch of `epochBinding` values, shuffles insertion order via a commit-reveal scheme, and records them atomically. This breaks temporal correlation between RS access time and on-chain observation time.

Formally: let `T_access` be the real access time and `T_chain` be the on-chain recording time. The batching ensures `T_chain - T_access ∈ [0, epoch_length]` uniformly, providing `epoch_length` seconds of timing ambiguity.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon-PRF**: Poseidon2 keyed by a uniformly random field element is indistinguishable from a random function. Formally: for `k ←$ F_p`, no PPT distinguisher can separate `Poseidon2(·, k)` from `RF(·)` with non-negligible advantage.

2. **PLONK knowledge soundness**: The PLONK proving system (with universal setup) satisfies knowledge soundness: for any PPT prover producing a valid proof, there exists a PPT extractor that recovers a valid witness.

3. **Discrete log on Baby Jubjub**: Given `(Ax, Ay) = BabyPbk(s)`, no PPT adversary can recover `s`.

4. **Poseidon collision resistance**: No PPT adversary can find distinct inputs `(x_1, ..., x_n) ≠ (y_1, ..., y_n)` such that `Poseidon_n(x_1, ..., x_n) = Poseidon_n(y_1, ..., y_n)`.

### Reduction sketch: IND-UNL-AS → Poseidon-PRF

**Theorem**: If there exists a PPT adversary A winning IND-UNL-AS with advantage ε, then there exists a PPT adversary B breaking Poseidon-PRF with advantage ≥ ε/2.

**Proof sketch**:

1. **Hybrid 0**: Real IND-UNL-AS game with `b = 0`. Challenge proofs use `scopeNullifier_A = Poseidon2(j_0, s_{i_0})` and `scopeNullifier_B = Poseidon2(j_1, s_{i_0})`.

2. **Hybrid 1**: Replace `Poseidon2(·, s_{i_0})` with a truly random function `RF_0(·)`. By Poseidon-PRF assumption, |Pr[A wins in H0] - Pr[A wins in H1]| ≤ Adv^{PRF}_{Poseidon}.

3. **Hybrid 2**: Real IND-UNL-AS game with `b = 1`. Challenge proofs use `scopeNullifier_A = Poseidon2(j_0, s_{i_0})` and `scopeNullifier_B = Poseidon2(j_1, s_{i_1})`.

4. **Hybrid 3**: Replace `Poseidon2(·, s_{i_0})` with `RF_0(·)` and `Poseidon2(·, s_{i_1})` with `RF_1(·)`. Cost: 2 · Adv^{PRF}_{Poseidon}.

5. **Hybrids 1 and 3 are identically distributed**: In both, the adversary sees `(RF_0(j_0), RF_?(j_1))` where `RF_?` is either `RF_0` or an independent `RF_1`. But since `j_0 ≠ j_1`, the output `RF_0(j_1)` is an independent random value (random function on a fresh input), making H1 and H3 identical.

6. **Conclusion**: A's advantage collapses: `ε ≤ 2 · Adv^{PRF}_{Poseidon} + Adv^{KS}_{PLONK}`. The PLONK knowledge soundness term covers the case where the adversary forges proofs without a valid witness.

### Why the AS's enrollment knowledge doesn't help

The AS knows `credComm_i = Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` for each agent `i`. But `credComm_i` does not contain `agentSecret`. The secret is generated independently by the agent and never transmitted. The public key `(Ax, Ay) = BabyPbk(agentSecret)` is embedded in the credential commitment only as the *operator* key — the `agentSecret` is a separate, agent-held scalar not derivable from the operator key (different key pair). Thus, knowing `credComm_i` gives zero information about the PRF key used in nullifier generation.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope nullifier `Poseidon2(scopeId, agentSecret)` | `nullifier = Poseidon(scope_id, secret)` | Terminology: Nullifier (human form, adapted for agent) |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permBitmask, expiry)` | §4.2 Agent Proof: constraint 2 |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | §3.2 Cryptographic Primitives |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | §3.2: Lean Incremental Merkle Tree, depth 20 |
| Scope satisfaction bitmask check | `requiredBits[i] * (1 - permBits[i]) === 0` | §4.2 Agent Proof: constraint 5 |
| Cumulative bit encoding | Tier implication constraints on bits [2,3,4] | §4.2 Agent Proof: constraint 6 |
| Epoch binding | `Poseidon2(scopeNullifier, epochSalt)` | Extension of nonce binding pattern: `Poseidon2(nullifierHash, sessionNonce)` from §4.1 |
| Proving system | PLONK with universal setup (agent circuit) | §3.3: Agent circuits use PLONK |
| On-chain root verification | Root history buffer (30-entry circular) | §3.1: Root History Buffer |
| Range checks | `Num2Bits(64)` for timestamps/bitmasks, `Num2Bits(251)` for secret | §4.1 constraint 1, §4.2 constraint 1 |

## 6. Circuit cost estimate

### Constraint breakdown for `ScopedAccess`

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Num2Bits(251)` — secret range | 251 |
| `BabyPbk` — public key derivation | ~1,500 |
| `Poseidon5` — credential commitment | ~1,200 (5-input Poseidon, ~240 per round × 5 rounds) |
| `EdDSAPoseidonVerifier` | ~4,000 (signature check on Baby Jubjub) |
| `BinaryMerkleRoot(20)` — 20 levels × Poseidon2 | ~4,800 (20 × ~240) |
| `Num2Bits(64)` × 3 — range checks | 192 |
| Scope satisfaction — 64 bit constraints | 64 |
| Cumulative encoding — 3 constraints | 3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scope nullifier | ~240 |
| `Poseidon2` — epoch binding | ~240 |
| `Poseidon2` — epoch commitment check | ~240 |
| **Total** | **~12,860** |

### Proving time targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| PLONK proving time (agent) | < 3 seconds | Well under the 5s PLONK agent budget; ~13K constraints on BN254 with modern PLONK (e.g., halo2 or snarkjs PLONK) |
| Verification gas (on-chain) | ~300K gas | Standard PLONK verification on EVM |
| Proof size | ~768 bytes | Standard PLONK proof |
| Trusted setup | Universal (no circuit-specific ceremony) | Per Bolyra spec §3.3 |

### Comparison to existing Bolyra circuits

| Circuit | Constraints | Proving system |
|---------|------------|---------------|
| `HumanUniqueness` (spec) | ~7,000 | Groth16 |
| `AgentPolicy` (spec) | ~12,000 | PLONK |
| `ScopedAccess` (this construction) | ~12,860 | PLONK |
| `Delegation` (spec) | ~14,000 | PLONK |

The `ScopedAccess` circuit is comparable in size to the existing `AgentPolicy` circuit, adding only the scope nullifier derivation (~480 constraints for two Poseidon2 calls) and replacing the session-nonce-based nullifier with a secret-keyed one.

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent — merchant graph hidden from CU-as-AS

**Stakeholders:**

- **State Employees' Credit Union (SECU)** — operates the AS, enrolls member agents.
- **Member agent** — acts on behalf of a SECU member, accessing merchant RS instances.
- **Merchant RS instances** — Auto dealership (RS-A), Healthcare provider (RS-B), Grocery chain (RS-C).

**Problem**: Under the baseline (OIDC + BBS+), SECU-as-AS sees every token request: "Member X's agent accessed Auto Dealer at 2:14pm, then Healthcare at 2:31pm, then Grocery at 5:02pm." This reconstructs the member's merchant graph — a privacy violation the member never consented to.

**Deployment flow:**

1. **Enrollment (one-time)**: SECU enrolls the member's agent in the Bolyra agent Merkle tree. SECU knows `credComm` and the operator public key. The agent generates `agentSecret` locally — SECU never sees it.

2. **Handshake (session start)**: Member authenticates via `HumanUniqueness` Groth16 proof. Agent authenticates via standard `AgentPolicy` PLONK proof. Both proofs verified on-chain atomically. SECU observes the handshake (it's on-chain) but this is a one-time session event, not per-RS.

3. **Merchant access (per-RS, AS-blind)**:
   - Agent accesses Auto Dealer (RS-A): generates `ScopedAccess` proof with `scopeId = Poseidon("auto-dealer.example.com")`. Produces `scopeNullifier_A = Poseidon2(scopeId_A, agentSecret)`. Proof sent directly to RS-A (or verified on-chain via batch contract).
   - Agent accesses Healthcare (RS-B): generates `ScopedAccess` proof with `scopeId = Poseidon("health.example.com")`. Produces `scopeNullifier_B = Poseidon2(scopeId_B, agentSecret)`.
   - Agent accesses Grocery (RS-C): `scopeNullifier_C = Poseidon2(scopeId_C, agentSecret)`.

4. **What SECU sees**: The enrollment and handshake. For subsequent RS accesses, SECU sees **nothing** — the proofs are verified against the public Merkle root without AS involvement.

5. **What colluding RS-A + RS-B see**: `scopeNullifier_A` and `scopeNullifier_B`. By the IND-UNL-AS reduction, these are computationally indistinguishable from outputs of independent random functions. RS-A and RS-B cannot determine whether they served the same agent.

6. **Epoch-based sybil prevention**: Within a single scope-epoch (e.g., 15-minute window at the Auto Dealer), the agent's `scopeNullifier_A` is deterministic — preventing the agent from accessing the same RS twice in the same epoch under different guises. Across epochs, `epochBinding` changes (new `epochSalt`), providing fresh replay prevention.

7. **Regulatory audit**: A regulator can verify that an agent presented a valid `ScopedAccess` proof to a specific RS at a specific epoch by checking the on-chain `epochBinding` record. The regulator cannot link across scopes without the agent's cooperation (the agent can voluntarily reveal `agentSecret` to prove or disprove cross-scope access).

## 8. Why the baseline cannot match

| Capability | This construction | Baseline (BBS+ / PPID / DPoP) |
|-----------|-------------------|-------------------------------|
| **AS cannot see per-RS access** | AS is not involved in per-RS authorization. Agent proves directly to RS via `ScopedAccess` proof. AS sees only enrollment + handshake. | AS issues every token. Every RS access requires an AS roundtrip. AS reconstructs full traffic graph from its own logs. |
| **Formal IND-UNL-AS game** | Defined (§3). Adversary controls AS, colludes with RS subset. Advantage bounded by Poseidon-PRF + PLONK-KS. | No formal game exists. BBS+ unlinkability excludes the issuer as adversary. OIDC PPID has no game-based definition. |
| **Scope-keyed nullifier separation** | `scopeNullifier = Poseidon2(scopeId, agentSecret)`. Different scopes → computationally unlinkable nullifiers. Keyed by a secret the AS never learns. | No nullifier concept. AS-issued PPIDs are AS-controlled pseudonyms — the AS holds the mapping table and can trivially reverse them. |
| **Timing side-channel resistance** | Epoch-batched submission with commit-reveal shuffle. Access time and chain-recording time are decorrelated by up to `epoch_length`. | No timing mitigation in any referenced spec (RFC 7662, 8707, 9449, BBS+ draft). Sub-second AS log correlation is trivial. |
| **AS-supplied nonce independence** | No AS-supplied nonces in per-RS flow. `epochSalt` is committed on-chain at epoch start and verified inside the circuit — the AS cannot pattern it per-agent. | RFC 9449 DPoP nonces are AS-issued. Adversarial AS can embed agent-identifying structure in nonces. |
| **Proof of non-access** | Agent can prove `scopeNullifier` for scope `j` does NOT appear in the on-chain nullifier set for a given epoch range. Merkle non-membership proof against the nullifier accumulator. | Impossible. No nullifier set exists. Non-access claims require trusting the AS's logs — the same AS whose adversarial behavior is the threat. |
| **Reduction to named assumption** | Security reduces to Poseidon-PRF (well-studied algebraic hash, 128-bit security target on BN254) + PLONK knowledge soundness. | BBS+ security reduces to q-SDH in pairing groups, but the unlinkability game explicitly assumes an honest issuer. No reduction exists for adversarial-issuer unlinkability. |

**The fundamental architectural gap**: The baseline's unlinkability is a property *between verifiers* that *trusts the issuer*. This construction's unlinkability is a property *against the issuer* — the AS is the adversary, and the protocol is designed so the AS lacks the information (agent secret) and the channel (no per-RS roundtrip) to correlate. No combination of BBS+, PPID, DPoP, or resource indicators can close this gap because they all require the AS to participate in every authorization event.
