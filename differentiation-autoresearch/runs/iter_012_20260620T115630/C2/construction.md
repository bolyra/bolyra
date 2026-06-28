# Construction

## 1. Statement of claim

Same agent accessing different Resource Server (RS) instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that controls token issuance, observes all protocol messages, and colludes with any subset of RSes to correlate per-agent traffic graphs. Unlinkability holds for both the agent identity and the human principal behind any delegation chain. The construction provides a formal IND-UNL-AS game with a concrete reduction to Poseidon pseudorandomness on BN254 and knowledge soundness of Groth16/PLONK.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Scope-Blinded Agent Authorization Circuit: `AgentScopeAuth`

This circuit extends the existing `AgentPolicy` circuit with scope-specific nullifier derivation that produces per-RS unlinkable authorization tokens. The key insight: the agent derives a *scope-specific pseudonym* and *scope-specific nullifier* such that two authorizations for different scopes are computationally indistinguishable from authorizations by two independent agents.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentSecret` | F_p | Agent's long-term EdDSA secret scalar |
| `modelHash` | F_p | Hash of agent model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator public key coordinates |
| `permissionBitmask` | 64-bit | Agent's full permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | F_p | Actual Merkle depth |
| `merkleProofIndex` | F_p | Leaf index |
| `merkleProofSiblings[20]` | F_p[] | Merkle siblings padded to depth 20 |
| `scopeBlindingNonce` | F_p | Per-scope random blinding factor (generated client-side, stored locally) |
| `rsIdentifier` | F_p | Resource Server scope identifier (Poseidon hash of RS URI) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | Required permission bits for this RS |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Merkle root for enrollment verification |
| `scopeNullifier` | F_p | `Poseidon2(rsIdentifier, Poseidon2(agentSecret, scopeBlindingNonce))` |
| `scopePseudonym` | F_p | `Poseidon2(rsIdentifier, agentSecret)` — stable per-RS identity |
| `sessionBinding` | F_p | `Poseidon2(scopeNullifier, sessionNonce)` |
| `blindedScopeCommitment` | F_p | `Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, Poseidon2(rsIdentifier, scopeBlindingNonce)))` |
| `rsCommitment` | F_p | `Poseidon2(rsIdentifier, scopeBlindingNonce)` — RS-verifiable audience binding |

**Verification model — hybrid off-chain/on-chain:**

The `AgentScopeAuth` proof is NOT verified on-chain as a monolithic transaction. Instead, verification is split:

1. **Off-chain at the RS.** The agent presents the SNARK proof and all public signals to the RS, plus reveals `rsIdentifier` and `scopeBlindingNonce` in a private channel (TLS). The RS:
   - Verifies the SNARK proof against the PLONK verification key.
   - Checks `rsIdentifier` matches its own identity.
   - Checks `rsCommitment == Poseidon2(rsIdentifier, scopeBlindingNonce)`.
   - Checks `requiredScopeMask` matches its own policy.
   - Reads `agentMerkleRoot` from on-chain state (view call) and confirms it is in the root history buffer.

2. **On-chain (state mutation only).** The RS (or a shared relayer) submits a lightweight registration transaction containing only `(scopeNullifier, sessionBinding, agentMerkleRoot)`. The registry:
   - Checks `agentMerkleRoot` is in the root history buffer.
   - Checks `scopeNullifier` has not been used (replay prevention).
   - Records `scopeNullifier` as used.
   - Stores `blindedScopeCommitment` as the delegation chain seed (if delegation will follow), indexed by `sessionBinding`.

This split is critical: `rsIdentifier`, `requiredScopeMask`, `scopeBlindingNonce`, and the proof itself never appear in on-chain calldata. The AS, even with full chain observation, sees only `(scopeNullifier, sessionBinding, agentMerkleRoot)` — three pseudorandom field elements that reveal nothing about which RS was contacted.

**Constraints (in addition to standard `AgentPolicy` constraints):**

1. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`
2. **EdDSA verification:** `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)` — proves operator authorization
3. **Merkle membership:** `BinaryMerkleRoot(20, credentialCommitment, proof) == agentMerkleRoot`
4. **Scope satisfaction:** `∀i ∈ [0,64): requiredBits[i] * (1 - permBits[i]) === 0`
5. **Cumulative bit encoding:** bits 4→3, 4→2, 3→2 implication constraints
6. **Expiry check:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`
7. **Scope-specific derived secret:** `derivedSecret = Poseidon2(agentSecret, scopeBlindingNonce)`
8. **Scope nullifier:** `scopeNullifier = Poseidon2(rsIdentifier, derivedSecret)` — deterministic per (agent, RS, blindingNonce), unlinkable across RS values
9. **Scope pseudonym:** `scopePseudonym = Poseidon2(rsIdentifier, agentSecret)` — stable identifier within a single RS for session continuity
10. **Session binding:** `sessionBinding = Poseidon2(scopeNullifier, sessionNonce)` — replay prevention
11. **RS commitment:** `rsCommitment = Poseidon2(rsIdentifier, scopeBlindingNonce)` — enables the RS to verify the proof is audience-bound to it without rsIdentifier appearing in any public output that the AS observes on-chain
12. **Blinded scope commitment:** `blindedScopeCommitment = Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsCommitment))` — scope commitment blinded by both rsIdentifier and scopeBlindingNonce; the AS knows credentialCommitment (from the Merkle tree) but cannot dictionary-attack rsIdentifier out of this value because rsCommitment = Poseidon2(rsIdentifier, scopeBlindingNonce) is pseudorandom under unknown scopeBlindingNonce
13. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`

**Dictionary attack resistance on blindedScopeCommitment:** In the prior version, `blindedScopeCommitment = Poseidon2(perm, Poseidon2(credComm, rsIdentifier))` was vulnerable to an AS that knows `credentialCommitment` (public on-chain as a Merkle leaf) enumerating `(rsIdentifier, perm)` pairs — with 256 possible permission values and a bounded set of known RSes, this is tractable. The revised construction hashes through `rsCommitment = Poseidon2(rsIdentifier, scopeBlindingNonce)` instead, making the inner value pseudorandom under unknown `scopeBlindingNonce`. The AS would need to break Poseidon PRF to recover `rsIdentifier`.

### 2.2 Scope-Blinded Delegation Circuit: `ScopeBlindedDelegation`

Extends the `Delegation` circuit so that delegation hops also produce RS-specific outputs, preventing an adversarial AS from learning the delegation topology across scopes.

**Private inputs:** Same as `Delegation` circuit, plus:

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScopeBlindingNonce` | F_p | Delegator's scope blinding factor |
| `delegateeScopeBlindingNonce` | F_p | Delegatee's scope blinding factor |
| `rsIdentifier` | F_p | Target RS identifier (private, same as in `AgentScopeAuth`) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `previousBlindedScopeCommitment` | F_p | Chain-linking value from prior hop (RS-blinded) |
| `sessionNonce` | F_p | Session binding |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `newBlindedScopeCommitment` | F_p | `Poseidon2(delegateeScope, Poseidon2(delegateeCredCommitment, Poseidon2(rsIdentifier, delegateeScopeBlindingNonce)))` |
| `delegationNullifier` | F_p | `Poseidon2(delegationTokenHash, sessionNonce)` |
| `delegateeMerkleRoot` | F_p | Delegatee enrollment root |

**Key constraint (chain linking with RS blinding):**

```
Poseidon2(delegatorScope, Poseidon2(delegatorCredCommitment, Poseidon2(rsIdentifier, delegatorScopeBlindingNonce))) == previousBlindedScopeCommitment
```

This ensures the delegation chain is RS-specific and dictionary-attack resistant: a chain constructed for RS-A cannot be reused for RS-B, and the chain structure observed on-chain reveals nothing about which RS was targeted because the inner commitment is blinded by `delegatorScopeBlindingNonce`.

**Verification model:** Same hybrid split as `AgentScopeAuth`. The delegation proof is verified off-chain by the RS (which knows `rsIdentifier`). Only `(delegationNullifier, delegateeMerkleRoot, newBlindedScopeCommitment)` are submitted on-chain for state mutation.

### 2.3 Oblivious Nonce Issuance Protocol

To eliminate the AS from the per-request hot path entirely, the construction uses a **batch blind nonce commitment** scheme:

1. At enrollment time, the AS issues a batch of `N` blinded nonce commitments: `blindedNonces[i] = Poseidon2(nonce_i, blindingFactor_i)` where `blindingFactor_i` is known only to the agent.
2. The agent stores the pre-images locally.
3. At authorization time, the agent selects an unused nonce, uses it as `sessionNonce`, and includes its opening in the proof's private inputs.
4. The on-chain registry validates nonce freshness against the commitment set — no AS interaction needed per-request.

This removes the AS from the timing side channel entirely. The AS sees only the batch issuance event, not individual authorization timings.

### 2.4 Gadget Summary

| Gadget | Reused from Bolyra | New |
|--------|-------------------|-----|
| `BinaryMerkleRoot(20)` | Yes | — |
| `EdDSAPoseidonVerifier` | Yes | — |
| `Poseidon2`, `Poseidon5` | Yes | — |
| `Num2Bits(64)`, `Num2Bits(251)` | Yes | — |
| `LessThan(64)` | Yes | — |
| `ScopeDerivedSecret` | — | `Poseidon2(agentSecret, scopeBlindingNonce)` |
| `ScopeNullifier` | — | `Poseidon2(rsIdentifier, derivedSecret)` |
| `ScopePseudonym` | — | `Poseidon2(rsIdentifier, agentSecret)` |
| `RSCommitment` | — | `Poseidon2(rsIdentifier, scopeBlindingNonce)` |
| `BlindedScopeCommitment` | — | `Poseidon2(perm, Poseidon2(credComm, rsCommitment))` |

## 3. Threat model (adversary capabilities, game definition)

### 3.1 Adversary Capabilities

The adversary A controls:

- **The Authorization Server (AS):** Full access to all issuance logs, token metadata, scope requests, timing information. Can modify issuance behavior (selective delays, tagging). Knows all `credentialCommitment` values (they are Merkle leaves published on-chain).
- **A coalition of up to (n-1) out of n Resource Servers:** Receives all authorization proofs, public signals, and timing from colluding RSes. Each colluding RS knows its own `rsIdentifier` and receives `scopeBlindingNonce` as part of the off-chain verification protocol.
- **On-chain data:** Full access to all emitted events, stored nullifiers, Merkle roots, and blinded scope commitments. Critically: the on-chain footprint of `AgentScopeAuth` contains only `(scopeNullifier, sessionBinding, agentMerkleRoot)` — no proof bytes, no `rsIdentifier`, no `requiredScopeMask`, no `rsCommitment`.
- **Network observation:** Can observe message sizes and coarse timing of on-chain registration transactions (but not the off-chain proof delivery from agent to RS, which occurs over TLS).

The adversary **cannot:**

- Break the discrete log assumption on Baby Jubjub (cannot recover `agentSecret` from public keys or pseudonyms).
- Find Poseidon collisions or distinguish Poseidon outputs from random (PRF assumption).
- Break knowledge soundness of Groth16/PLONK (cannot forge proofs without valid witnesses).
- Compromise the agent's local storage (the `scopeBlindingNonce` and `agentSecret` remain private).
- Observe the TLS channel between agent and RS (standard network assumption; compromising the RS is modeled via the RS coalition).

**AS + RS collusion model:** When the AS colludes with RS-A, the AS learns `rsIdentifier_A` and `scopeBlindingNonce` for RS-A's sessions (from RS-A's off-chain verification logs). The AS can then compute `rsCommitment_A = Poseidon2(rsIdentifier_A, scopeBlindingNonce)`. However, this reveals nothing about authorizations at RS-B (the non-colluding RS), because RS-B's authorizations use a different `rsIdentifier` and an independently sampled `scopeBlindingNonce`. The AS cannot correlate RS-A and RS-B authorizations without breaking Poseidon PRF.

### 3.2 IND-UNL-AS Game

**Game `IND-UNL-AS(λ)`:**

1. **Setup.** Challenger generates system parameters: Poseidon parameters, BabyJubjub generator, circuit CRS (Groth16 proving/verifying keys). Challenger enrolls `m` agents into the agent Merkle tree.

2. **Phase 1 (Learning).** Adversary A adaptively queries an oracle `Authorize(agentId, rsId, requiredScope, timestamp)` that returns:
   - **On-chain observable output:** `(agentMerkleRoot, scopeNullifier, sessionBinding)` — what the AS sees from chain observation.
   - **RS-visible output (for colluding RSes):** `(scopePseudonym, blindedScopeCommitment, rsCommitment, requiredScopeMask, rsIdentifier, scopeBlindingNonce)` — what a colluding RS can share with the AS.
   
   A may query this oracle polynomially many times.

3. **Challenge.** A selects two agents `agent_0`, `agent_1` and a challenge RS `rs*` such that:
   - Both agents have valid credentials satisfying `rs*`'s required scope
   - `rs*` is non-colluding: A has **not** previously queried `Authorize(agent_0, rs*, ·, ·)` or `Authorize(agent_1, rs*, ·, ·)`, and the RS coalition does not include `rs*`
   
   Challenger flips bit `b ←$ {0,1}`, generates the authorization for `agent_b` at `rs*`, and returns **only the on-chain observable output** `(agentMerkleRoot, scopeNullifier*, sessionBinding*)` to A (since `rs*` is non-colluding, A does not receive RS-visible output).

4. **Phase 2 (Continued Learning).** A may continue querying `Authorize` for any `(agentId, rsId)` except `(agent_0, rs*)` and `(agent_1, rs*)`.

5. **Guess.** A outputs `b'`. A wins if `b' = b`.

**Advantage:** `Adv^{IND-UNL-AS}_A(λ) = |Pr[b' = b] - 1/2|`

**Definition:** The scheme satisfies **cross-scope agent unlinkability** if for all PPT adversaries A: `Adv^{IND-UNL-AS}_A(λ) ≤ negl(λ)`.

**Note on the game's RS restriction:** The challenge RS `rs*` must be non-colluding. If `rs*` itself colludes with the AS, then `rs*` reveals `scopeBlindingNonce` and `rsIdentifier` to the AS, allowing the AS to recompute all derived values and trivially identify the agent. This is inherent — unlinkability against an adversary that controls both endpoints of a communication is information-theoretically impossible. The game captures the meaningful threat: an adversarial AS attempting to correlate an agent's activity at a non-colluding RS with activity observed elsewhere.

### 3.3 Extended Game: IND-UNL-DELEG (Delegation Chain Unlinkability)

Same structure as IND-UNL-AS, but the challenge query involves a delegation chain of depth `d`. A wins by determining which of two delegation chains (rooted at `human_0` or `human_1`, through `agent_0` or `agent_1`) produced the terminal authorization at `rs*`. The `blindedScopeCommitment` chain is RS-blinded and on-chain state contains only blinded values, so cross-RS chain correlation requires breaking the same assumptions.

## 4. Security argument (named assumption + reduction sketch)

### 4.1 Named Assumptions

- **A1: Poseidon PRF (BN254).** Poseidon2 is a pseudorandom function: no PPT distinguisher can tell `Poseidon2(k, ·)` from a random function with advantage better than `negl(λ)`, where `k` is a uniformly random key in F_p.
- **A2: Discrete Log on Baby Jubjub.** Given `(G, aG)` on the Baby Jubjub curve, no PPT algorithm can recover `a` with non-negligible probability.
- **A3: Knowledge Soundness of Groth16 (ROM).** In the random oracle model with trusted setup, the Groth16 proof system for `AgentScopeAuth` is knowledge-sound: any PPT prover producing a valid proof knows a valid witness.
- **A4: Poseidon Collision Resistance.** No PPT algorithm can find `(x, x')` with `x ≠ x'` such that `Poseidon(x) = Poseidon(x')` with non-negligible probability.

### 4.2 Reduction Sketch

**Theorem.** If A1 holds, then for all PPT adversaries A: `Adv^{IND-UNL-AS}_A(λ) ≤ 2 · Adv^{PRF}_{Poseidon2}(λ)`.

**Proof sketch.**

1. **Hybrid H0:** Real game. The challenge authorization uses `agent_b` with secret `s_b` and scope blinding nonce `r_b` (freshly sampled for `rs*`). The on-chain observable output includes:
   - `scopeNullifier* = Poseidon2(rs*, Poseidon2(s_b, r_b))`
   - `sessionBinding* = Poseidon2(scopeNullifier*, sessionNonce)`
   - `agentMerkleRoot` (shared across all agents in the same tree — independent of `b`)
   
   Note: `scopePseudonym`, `blindedScopeCommitment`, and `rsCommitment` are NOT in the on-chain output and `rs*` is non-colluding, so A never sees them.

2. **Hybrid H1:** Replace `Poseidon2(s_b, ·)` with a truly random function `f_b(·)`. By A1 (Poseidon PRF with key `s_b`), `|Pr[A wins in H0] - Pr[A wins in H1]| ≤ Adv^{PRF}(λ)`.

3. **Hybrid H2:** In H1, `derivedSecret* = f_b(r_b)` is a uniformly random field element (since `r_b` is freshly sampled for `rs*` and `f_b` is random). Therefore `scopeNullifier* = Poseidon2(rs*, f_b(r_b))` is indistinguishable from random by a second application of A1 (keyed by the random `f_b(r_b)`). `sessionBinding*` inherits this indistinguishability.

4. In H2, the on-chain observable output `(agentMerkleRoot, scopeNullifier*, sessionBinding*)` consists of one value independent of `b` and two values computationally indistinguishable from uniform random. A's advantage is 0.

5. **Triangle inequality:** `Adv^{IND-UNL-AS}_A(λ) ≤ |H0 - H1| + |H1 - H2| ≤ 2 · Adv^{PRF}(λ)`.

**Why the reduction is tight under hybrid verification:** The critical property enabling this reduction is that the AS only observes the on-chain registration transaction, which contains `(scopeNullifier, sessionBinding, agentMerkleRoot)`. The AS does not observe `rsCommitment`, `blindedScopeCommitment`, `scopePseudonym`, or the proof itself — these are delivered off-chain to the RS over TLS. Since `rs*` is non-colluding, these values never reach the AS. The reduction therefore only needs to argue about three on-chain field elements, not six public outputs, making the hybrid cleaner.

**Dictionary attack resistance of off-chain outputs (defense in depth):** Even if an RS leaks its verification logs (captured by the game's colluding-RS model), the `blindedScopeCommitment` resists dictionary attack. The AS knows `credentialCommitment` (on-chain) but `blindedScopeCommitment = Poseidon2(perm, Poseidon2(credComm, Poseidon2(rsIdentifier, scopeBlindingNonce)))`. The inner `Poseidon2(rsIdentifier, scopeBlindingNonce)` is pseudorandom under unknown `scopeBlindingNonce` (A1), so the AS cannot enumerate `(rsIdentifier, perm)` pairs to match. This provides defense in depth: even partial RS compromise does not enable cross-RS correlation of blinded scope commitments from non-colluding RSes.

**Delegation chain extension:** For a chain of depth `d`, each hop introduces one additional PRF application. By a standard hybrid argument over the `d` hops, `Adv^{IND-UNL-DELEG}_A(λ) ≤ 2d · Adv^{PRF}(λ)`, which remains negligible for polynomial `d`.

### 4.3 Side Channel Treatment

**Timing:** The oblivious nonce issuance protocol (§2.3) eliminates AS-observable per-request timing. The AS sees only batch nonce issuance, which is uniform across agents. On-chain registration transactions are observable but attributable only to the relayer, not the agent identity. Agents SHOULD submit registrations through a shared relayer that batches submissions on fixed intervals (e.g., every block).

**Proof size:** All Groth16 proofs are exactly 3 group elements (256 bytes). PLONK proofs are fixed-size per circuit. No proof-size side channel exists. Importantly, proof bytes are delivered off-chain to the RS — they never appear in on-chain calldata, eliminating a potential fingerprinting vector.

**On-chain calldata size:** Every on-chain registration transaction contains exactly 3 field elements `(scopeNullifier, sessionBinding, agentMerkleRoot)` regardless of agent identity, permission level, or RS. No cardinality side channel in the on-chain footprint.

**Off-chain message size:** The off-chain proof delivery to the RS contains the fixed-size PLONK proof plus 6 public outputs plus `(rsIdentifier, scopeBlindingNonce)`. This is a fixed-size message for all agents and RSes. No message-size side channel.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Agent credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | draft-bolyra §4.2 |
| Scope-specific nullifier | `Poseidon2(rsIdentifier, Poseidon2(agentSecret, scopeBlindingNonce))` | Extends nullifier = `Poseidon2(scope_id, secret)` pattern from §1.2 |
| Scope pseudonym | `Poseidon2(rsIdentifier, agentSecret)` | Analogous to human `nullifierHash = Poseidon2(scope, secret)` from HumanUniqueness |
| RS commitment | `Poseidon2(rsIdentifier, scopeBlindingNonce)` | New — audience-binding commitment; RS verifies off-chain |
| Blinded scope commitment | `Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsCommitment))` | Extends `scopeCommitment = Poseidon2(perm, credComm)` from §4.1 with dictionary-attack-resistant RS blinding |
| Session binding | `Poseidon2(scopeNullifier, sessionNonce)` | Same pattern as `nonceBinding = Poseidon2(nullifierHash, sessionNonce)` from HumanUniqueness |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | draft-bolyra §4.2 constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 | draft-bolyra §3.2 |
| Permission encoding | 8-bit cumulative bitmask with implication constraints | draft-bolyra §5 (bits 2→3→4 chain) |
| Delegation chain linking | `Poseidon2(delegatorScope, Poseidon2(delegatorCredComm, Poseidon2(rsId, delegatorBlindingNonce)))` | Extends §4 chain linking with dictionary-attack-resistant RS blinding |
| Proving system (agent) | PLONK with universal setup (pot16.ptau) | draft-bolyra §3.3 |
| Proving system (human) | Groth16 reusing Semaphore v4 ceremony | draft-bolyra §3.3 |

## 6. Circuit cost estimate

### `AgentScopeAuth` (PLONK)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| `Poseidon5` (credential commitment) | ~1,500 |
| `EdDSAPoseidonVerifier` | ~8,000 |
| `BinaryMerkleRoot(20)` with 20× Poseidon2 | ~15,000 |
| `Num2Bits(64)` × 3 (perm, expiry, timestamp) | ~192 |
| `LessThan(64)` (expiry check) | ~130 |
| Scope satisfaction (64 bit constraints) | ~64 |
| Cumulative bit encoding (3 constraints) | ~3 |
| `Poseidon2` × 6 (derivedSecret, scopeNullifier, scopePseudonym, sessionBinding, rsCommitment, blindedScopeCommitment) | ~4,500 |
| `Poseidon2` × 1 (inner hash for blindedScopeCommitment) | ~750 |
| **Total** | **~30,150** |

Fits within 2^15 = 32,768 constraint budget (pot16.ptau supports 2^16). PLONK proving time target: **<3s** on modern hardware (M-series Mac or server CPU). Well within the <5s PLONK agent target.

### `ScopeBlindedDelegation` (PLONK)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Base `Delegation` circuit constraints | ~28,000 |
| Additional `Poseidon2` × 3 (two RS-blinded scope commitments + rsIdentifier blinding) | ~2,250 |
| **Total** | **~30,250** |

Also fits within 2^15. PLONK proving time target: **<3s**.

### `HumanUniqueness` (Groth16, unchanged)

No modification needed. Existing circuit at ~21,000 constraints. Proving time: **<12s** (Groth16 with rapidsnark).

## 7. Concrete deployment scenario

### Credit Union Cross-Merchant Agent Privacy

**Stakeholder:** Navy Federal Credit Union (NFCU) — 13M+ members, largest US credit union.

**Setup:** NFCU operates as the AS for its members' AI agents. Members delegate financial agents to interact with merchant RSes (Amazon, Costco, local car dealers). NFCU must comply with NCUA Reg E and the CFPB's proposed agent-authorization rules while simultaneously being unable to learn members' merchant activity graphs (privacy obligation under GLBA §502).

**Deployment flow:**

1. **Enrollment.** Member enrolls their AI agent via NFCU's portal. NFCU's operator key signs the agent's credential commitment with `permissionBitmask = 0b00000100` (FINANCIAL_SMALL, <$100). Credential is inserted into NFCU's agent Merkle tree (on Base Sepolia, later Base mainnet).

2. **Batch nonce issuance.** At enrollment, NFCU issues a batch of 100 blinded nonce commitments. The agent stores the openings locally. This is the last time NFCU interacts with the agent per-RS.

3. **Authorization at Amazon RS.** Agent generates `AgentScopeAuth` proof with `rsIdentifier = Poseidon("amazon.com/bolyra/rs")` as a **private input**. Agent sends the proof plus `(rsIdentifier, scopeBlindingNonce)` to Amazon over TLS. Amazon verifies the PLONK proof off-chain, confirms `rsCommitment` matches, and checks `agentMerkleRoot` against on-chain state. Amazon (or a relayer) posts `(scopeNullifier, sessionBinding, agentMerkleRoot)` on-chain for replay prevention. NFCU sees the on-chain transaction but learns nothing — three pseudorandom field elements with no RS-identifying information.

4. **Authorization at Costco RS.** Same agent generates a separate proof with `rsIdentifier = Poseidon("costco.com/bolyra/rs")` and a fresh `scopeBlindingNonce`. Costco receives entirely different public signals. On-chain, NFCU sees another three pseudorandom field elements. By IND-UNL-AS, NFCU cannot determine whether the Amazon and Costco on-chain registrations came from the same member — or even that they are related to merchant activity at all.

5. **Delegation.** Member delegates from FINANCIAL_SMALL to a sub-agent with READ_DATA only (`0b00000001`) for a price-comparison service. The delegation uses `ScopeBlindedDelegation` with `rsIdentifier` as a private input for the comparison service's RS. The delegation proof is verified off-chain by the comparison service. Only `(delegationNullifier, delegateeMerkleRoot, newBlindedScopeCommitment)` appear on-chain. NFCU cannot correlate the sub-delegation to the parent agent's merchant activity.

**Regulatory compliance:** NFCU proves to NCUA examiners that it *cannot* build merchant graphs (cryptographic guarantee, not policy promise). The hybrid verification model means no RS-identifying data ever touches the chain — NFCU's on-chain visibility is limited to pseudorandom nullifiers. This exceeds GLBA §502 requirements and preempts CFPB enforcement actions on agent-mediated purchase tracking.

**Healthcare variant:** UnitedHealthcare (AS) delegates member agents to specialist providers (RSes). The delegation chain proves referral authorization without revealing to UHC which specialists the member visited — satisfying HIPAA minimum necessary standard through cryptographic enforcement rather than access controls.

## 8. Why the baseline cannot match

### Structural impossibility 1: AS is the issuer

In OAuth/OIDC, every token is issued by the AS. The AS sees `(agent_id, rs_id, scope, timestamp)` for every authorization. PPID hides `sub` from RSes but not from the AS itself. **No configuration of PPID, DPoP, RFC 8707, or BBS+ removes the AS from the issuance hot path.** The AS's correlation advantage is 1.0 by construction — it has perfect knowledge.

Bolyra's `AgentScopeAuth` eliminates AS involvement at authorization time entirely. The agent generates the proof client-side using pre-issued credentials. The AS never sees which RS the agent contacts. The on-chain registration transaction contains only `(scopeNullifier, sessionBinding, agentMerkleRoot)` — three pseudorandom field elements with no RS-identifying information in calldata. `rsIdentifier` is a private circuit input that never appears on-chain. The AS's advantage is bounded by `2 · Adv^{PRF}_{Poseidon2}(λ)` ≈ 0.

### Structural impossibility 2: No scope blinding in OAuth

RFC 8707 binds tokens to RS audiences, but the AS sees the requested `resource` parameter at issuance time. There is no mechanism in any OAuth RFC to blind the RS identifier from the AS. Even with BBS+ selective disclosure, the AS knows which RS the credential was requested for because the AS issued it.

Bolyra's scope nullifier `Poseidon2(rsIdentifier, derivedSecret)` is computed client-side with `rsIdentifier` as a private circuit input. The `rsIdentifier` never appears in any on-chain data. The RS verifies audience binding off-chain via `rsCommitment = Poseidon2(rsIdentifier, scopeBlindingNonce)`, which the AS cannot dictionary-attack because `scopeBlindingNonce` is unknown to the AS (it is a private circuit input delivered to the RS over TLS, and the challenge RS is non-colluding).

### Structural impossibility 3: No formal security definition

The baseline has no IND-UNL-AS game or equivalent. BBS+ multi-show unlinkability operates only at the holder-to-verifier layer — it says nothing about issuer-level correlation. No RFC defines an adversarial model where the AS is the attacker.

Bolyra provides the IND-UNL-AS game (§3.2) with a concrete reduction to Poseidon PRF security (§4.2), giving a falsifiable, peer-reviewable security claim. The game explicitly models the AS's on-chain view (limited to three pseudorandom field elements per authorization) and the colluding-RS channel, with a clean separation that makes the reduction tight.

### Structural impossibility 4: Delegation chain topology leaks

RFC 8693 Token Exchange requires an AS roundtrip per delegation hop. The AS sees every actor/subject token pair and can reconstruct the full chain topology. There is no mechanism to hide hop structure.

Bolyra's `ScopeBlindedDelegation` circuit proves chain integrity in ZK with RS-blinded scope commitments. `rsIdentifier` is private in the delegation circuit. The AS sees only `(delegationNullifier, delegateeMerkleRoot, newBlindedScopeCommitment)` on-chain — the `newBlindedScopeCommitment` is blinded by both `rsIdentifier` and `scopeBlindingNonce`, making it dictionary-attack resistant even though the AS knows `credentialCommitment` values from the Merkle tree.

### Structural impossibility 5: Timing side channels are unmitigated

The baseline requires real-time AS interaction for token issuance. Request timing at the AS perfectly correlates with agent activity at RSes. No RFC mandates batching, padding, or oblivious issuance.

Bolyra's batch blind nonce commitment scheme (§2.3) front-loads AS interaction to enrollment time. Per-authorization timing is invisible to the AS. On-chain submission timing is attributable only to the relayer, not the agent.

### Summary

| Property | Baseline (PPID+8707+DPoP+BBS+) | Bolyra AgentScopeAuth |
|----------|-------------------------------|----------------------|
| AS learns which RS agent contacts | Yes (issuance-time) | No (rsIdentifier is private input; on-chain data is 3 pseudorandom field elements) |
| RS-to-RS subject correlation | Prevented (PPID) | Prevented (scope pseudonym) |
| AS+RS collusion correlation | Trivial (AS has full graph) | Bounded by `Adv^{PRF}(λ)` at non-colluding RSes; inherently broken at colluding RS (§3.2 note) |
| Formal security game | None | IND-UNL-AS with reduction |
| Delegation chain privacy from AS | None (8693 is AS-observable) | Full (ZK delegation, RS-blinded, dictionary-attack resistant) |
| Timing side channel resistance | None | Batch nonce pre-issuance |
| Scope blinding from AS | Impossible (AS sees `resource`) | Enforced (rsIdentifier is private circuit input, never in calldata) |
| Dictionary attack on blinded commitments | N/A | Resistant (inner hash includes scopeBlindingNonce unknown to AS) |
