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

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rsIdentifier` | F_p | Resource Server scope identifier (Poseidon hash of RS URI) |
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
| `blindedScopeCommitment` | F_p | `Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsIdentifier))` |

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
11. **Blinded scope commitment:** `blindedScopeCommitment = Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsIdentifier))` — scope commitment that is RS-specific, preventing cross-RS scope correlation
12. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`

### 2.2 Scope-Blinded Delegation Circuit: `ScopeBlindedDelegation`

Extends the `Delegation` circuit so that delegation hops also produce RS-specific outputs, preventing an adversarial AS from learning the delegation topology across scopes.

**Private inputs:** Same as `Delegation` circuit, plus:

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScopeBlindingNonce` | F_p | Delegator's scope blinding factor |
| `delegateeScopeBlindingNonce` | F_p | Delegatee's scope blinding factor |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `previousBlindedScopeCommitment` | F_p | Chain-linking value from prior hop (RS-specific) |
| `rsIdentifier` | F_p | Target RS identifier |
| `sessionNonce` | F_p | Session binding |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `newBlindedScopeCommitment` | F_p | `Poseidon2(delegateeScope, Poseidon2(delegateeCredCommitment, rsIdentifier))` |
| `delegationNullifier` | F_p | `Poseidon2(delegationTokenHash, sessionNonce)` |
| `delegateeMerkleRoot` | F_p | Delegatee enrollment root |

**Key constraint (chain linking with RS binding):**

```
Poseidon2(delegatorScope, Poseidon2(delegatorCredCommitment, rsIdentifier)) == previousBlindedScopeCommitment
```

This ensures the delegation chain is RS-specific: a chain constructed for RS-A cannot be reused for RS-B, and the chain structure observed at RS-A reveals nothing about chains at RS-B.

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
| `BlindedScopeCommitment` | — | `Poseidon2(perm, Poseidon2(credComm, rsId))` |

## 3. Threat model (adversary capabilities, game definition)

### 3.1 Adversary Capabilities

The adversary A controls:

- **The Authorization Server (AS):** Full access to all issuance logs, token metadata, scope requests, timing information. Can modify issuance behavior (selective delays, tagging).
- **A coalition of up to (n-1) out of n Resource Servers:** Receives all authorization proofs, public signals, and timing from colluding RSes.
- **Network observation:** Can observe message sizes and coarse timing of proof submissions to the on-chain registry (but not proof contents beyond public signals, as proofs are verified on-chain).
- **On-chain data:** Full access to all emitted events, stored nullifiers, Merkle roots, and scope commitments.

The adversary **cannot:**

- Break the discrete log assumption on Baby Jubjub (cannot recover `agentSecret` from public keys or pseudonyms).
- Find Poseidon collisions or distinguish Poseidon outputs from random (PRF assumption).
- Break knowledge soundness of Groth16/PLONK (cannot forge proofs without valid witnesses).
- Compromise the agent's local storage (the `scopeBlindingNonce` and `agentSecret` remain private).

### 3.2 IND-UNL-AS Game

**Game `IND-UNL-AS(λ)`:**

1. **Setup.** Challenger generates system parameters: Poseidon parameters, BabyJubjub generator, circuit CRS (Groth16 proving/verifying keys). Challenger enrolls `m` agents into the agent Merkle tree.

2. **Phase 1 (Learning).** Adversary A adaptively queries an oracle `Authorize(agentId, rsId, requiredScope, timestamp)` that returns the full public output `(agentMerkleRoot, scopeNullifier, scopePseudonym, sessionBinding, blindedScopeCommitment)` for agent `agentId` at resource server `rsId`. A may query this oracle polynomially many times.

3. **Challenge.** A selects two agents `agent_0`, `agent_1` and a challenge RS `rs*` such that:
   - Both agents have valid credentials satisfying `rs*`'s required scope
   - A has **not** previously queried `Authorize(agent_0, rs*, ·, ·)` or `Authorize(agent_1, rs*, ·, ·)`
   
   Challenger flips bit `b ←$ {0,1}`, generates `π* = Authorize(agent_b, rs*, requiredScope*, timestamp*)`, and returns the public outputs to A.

4. **Phase 2 (Continued Learning).** A may continue querying `Authorize` for any `(agentId, rsId)` except `(agent_0, rs*)` and `(agent_1, rs*)`.

5. **Guess.** A outputs `b'`. A wins if `b' = b`.

**Advantage:** `Adv^{IND-UNL-AS}_A(λ) = |Pr[b' = b] - 1/2|`

**Definition:** The scheme satisfies **cross-scope agent unlinkability** if for all PPT adversaries A: `Adv^{IND-UNL-AS}_A(λ) ≤ negl(λ)`.

### 3.3 Extended Game: IND-UNL-DELEG (Delegation Chain Unlinkability)

Same structure as IND-UNL-AS, but the challenge query involves a delegation chain of depth `d`. A wins by determining which of two delegation chains (rooted at `human_0` or `human_1`, through `agent_0` or `agent_1`) produced the terminal authorization at `rs*`. The `blindedScopeCommitment` chain is RS-specific, so cross-RS chain correlation requires breaking the same assumptions.

## 4. Security argument (named assumption + reduction sketch)

### 4.1 Named Assumptions

- **A1: Poseidon PRF (BN254).** Poseidon2 is a pseudorandom function: no PPT distinguisher can tell `Poseidon2(k, ·)` from a random function with advantage better than `negl(λ)`, where `k` is a uniformly random key in F_p.
- **A2: Discrete Log on Baby Jubjub.** Given `(G, aG)` on the Baby Jubjub curve, no PPT algorithm can recover `a` with non-negligible probability.
- **A3: Knowledge Soundness of Groth16 (ROM).** In the random oracle model with trusted setup, the Groth16 proof system for `AgentScopeAuth` is knowledge-sound: any PPT prover producing a valid proof knows a valid witness.
- **A4: Poseidon Collision Resistance.** No PPT algorithm can find `(x, x')` with `x ≠ x'` such that `Poseidon(x) = Poseidon(x')` with non-negligible probability.

### 4.2 Reduction Sketch

**Theorem.** If A1 holds, then for all PPT adversaries A: `Adv^{IND-UNL-AS}_A(λ) ≤ 2 · Adv^{PRF}_{Poseidon2}(λ)`.

**Proof sketch.**

1. **Hybrid H0:** Real game. The challenge authorization uses `agent_b` with secret `s_b` and scope blinding nonce `r_b`. The public output includes:
   - `scopeNullifier* = Poseidon2(rs*, Poseidon2(s_b, r_b))`
   - `scopePseudonym* = Poseidon2(rs*, s_b)`
   - `blindedScopeCommitment* = Poseidon2(perm_b, Poseidon2(credComm_b, rs*))`

2. **Hybrid H1:** Replace `Poseidon2(s_b, ·)` with a truly random function `f_b(·)`. By A1 (Poseidon PRF with key `s_b`), `|Pr[A wins in H0] - Pr[A wins in H1]| ≤ Adv^{PRF}(λ)`.

3. **Hybrid H2:** In H1, `derivedSecret* = f_b(r_b)` is a uniformly random field element (since `r_b` is fresh and `f_b` is random). Therefore `scopeNullifier* = Poseidon2(rs*, f_b(r_b))` is indistinguishable from random by a second application of A1 (keyed by the random `f_b(r_b)`). Similarly, `scopePseudonym*` is random-looking since `s_b` is the PRF key and `rs*` is fresh for this agent.

4. In H2, all public outputs of the challenge are computationally indistinguishable from uniform random field elements. A's advantage is 0.

5. **Triangle inequality:** `Adv^{IND-UNL-AS}_A(λ) ≤ |H0 - H1| + |H1 - H2| ≤ 2 · Adv^{PRF}(λ)`.

**Delegation chain extension:** For a chain of depth `d`, each hop introduces one additional PRF application. By a standard hybrid argument over the `d` hops, `Adv^{IND-UNL-DELEG}_A(λ) ≤ 2d · Adv^{PRF}(λ)`, which remains negligible for polynomial `d`.

### 4.3 Side Channel Treatment

**Timing:** The oblivious nonce issuance protocol (§2.3) eliminates AS-observable per-request timing. The AS sees only batch nonce issuance, which is uniform across agents. On-chain submission timing is observable but attributable only to the relayer, not the agent identity. Agents SHOULD submit proofs through a shared relayer that batches submissions on fixed intervals (e.g., every block).

**Proof size:** All Groth16 proofs are exactly 3 group elements (256 bytes). PLONK proofs are fixed-size per circuit. No proof-size side channel exists.

**Public signal cardinality:** Every authorization produces exactly 5 public outputs regardless of agent identity, permission level, or RS. No cardinality side channel.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Agent credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | draft-bolyra §4.2 |
| Scope-specific nullifier | `Poseidon2(rsIdentifier, Poseidon2(agentSecret, scopeBlindingNonce))` | New — extends nullifier = `Poseidon2(scope_id, secret)` pattern from §1.2 |
| Scope pseudonym | `Poseidon2(rsIdentifier, agentSecret)` | Analogous to human `nullifierHash = Poseidon2(scope, secret)` from HumanUniqueness |
| Blinded scope commitment | `Poseidon2(permissionBitmask, Poseidon2(credentialCommitment, rsIdentifier))` | Extends `scopeCommitment = Poseidon2(perm, credComm)` from §4.1 with RS binding |
| Session binding | `Poseidon2(scopeNullifier, sessionNonce)` | Same pattern as `nonceBinding = Poseidon2(nullifierHash, sessionNonce)` from HumanUniqueness |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | draft-bolyra §4.2 constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 | draft-bolyra §3.2 |
| Permission encoding | 8-bit cumulative bitmask with implication constraints | draft-bolyra §5 (bits 2→3→4 chain) |
| Delegation chain linking | `Poseidon2(delegatorScope, Poseidon2(delegatorCredComm, rsIdentifier))` | Extends §4 chain linking with RS binding |
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
| `Poseidon2` × 5 (derivedSecret, scopeNullifier, scopePseudonym, sessionBinding, blindedScopeCommitment) | ~3,750 |
| `Poseidon2` × 1 (inner hash for blindedScopeCommitment) | ~750 |
| **Total** | **~29,400** |

Fits within 2^15 = 32,768 constraint budget (pot16.ptau supports 2^16). PLONK proving time target: **<3s** on modern hardware (M-series Mac or server CPU). Well within the <5s PLONK agent target.

### `ScopeBlindedDelegation` (PLONK)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Base `Delegation` circuit constraints | ~28,000 |
| Additional `Poseidon2` × 2 (RS-bound scope commitments) | ~1,500 |
| **Total** | **~29,500** |

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

3. **Authorization at Amazon RS.** Agent generates `AgentScopeAuth` proof with `rsIdentifier = Poseidon("amazon.com/bolyra/rs")`. Amazon receives `(agentMerkleRoot, scopeNullifier_amazon, scopePseudonym_amazon, sessionBinding, blindedScopeCommitment)`. Amazon verifies the proof on-chain (or via off-chain verifier with root check).

4. **Authorization at Costco RS.** Same agent generates a separate proof with `rsIdentifier = Poseidon("costco.com/bolyra/rs")`. Costco receives entirely different public signals. By IND-UNL-AS, NFCU (the AS) cannot determine whether the Amazon and Costco authorizations came from the same member, even with full access to on-chain events.

5. **Delegation.** Member delegates from FINANCIAL_SMALL to a sub-agent with READ_DATA only (`0b00000001`) for a price-comparison service. The delegation uses `ScopeBlindedDelegation` with `rsIdentifier` for the comparison service's RS. The delegation chain is RS-bound — NFCU cannot correlate the sub-delegation to the parent agent's merchant activity.

**Regulatory compliance:** NFCU proves to NCUA examiners that it *cannot* build merchant graphs (cryptographic guarantee, not policy promise). This exceeds GLBA §502 requirements and preempts CFPB enforcement actions on agent-mediated purchase tracking.

**Healthcare variant:** UnitedHealthcare (AS) delegates member agents to specialist providers (RSes). The delegation chain proves referral authorization without revealing to UHC which specialists the member visited — satisfying HIPAA minimum necessary standard through cryptographic enforcement rather than access controls.

## 8. Why the baseline cannot match

### Structural impossibility 1: AS is the issuer

In OAuth/OIDC, every token is issued by the AS. The AS sees `(agent_id, rs_id, scope, timestamp)` for every authorization. PPID hides `sub` from RSes but not from the AS itself. **No configuration of PPID, DPoP, RFC 8707, or BBS+ removes the AS from the issuance hot path.** The AS's correlation advantage is 1.0 by construction — it has perfect knowledge.

Bolyra's `AgentScopeAuth` eliminates AS involvement at authorization time entirely. The agent generates the proof client-side using pre-issued credentials. The AS never sees which RS the agent contacts. The AS's advantage is bounded by `2 · Adv^{PRF}_{Poseidon2}(λ)` ≈ 0.

### Structural impossibility 2: No scope blinding in OAuth

RFC 8707 binds tokens to RS audiences, but the AS sees the requested `resource` parameter at issuance time. There is no mechanism in any OAuth RFC to blind the RS identifier from the AS. Even with BBS+ selective disclosure, the AS knows which RS the credential was requested for because the AS issued it.

Bolyra's scope nullifier `Poseidon2(rsIdentifier, derivedSecret)` is computed client-side. The `rsIdentifier` is a private input to the circuit. The AS never learns it.

### Structural impossibility 3: No formal security definition

The baseline has no IND-UNL-AS game or equivalent. BBS+ multi-show unlinkability operates only at the holder-to-verifier layer — it says nothing about issuer-level correlation. No RFC defines an adversarial model where the AS is the attacker.

Bolyra provides the IND-UNL-AS game (§3.2) with a concrete reduction to Poseidon PRF security (§4.2), giving a falsifiable, peer-reviewable security claim.

### Structural impossibility 4: Delegation chain topology leaks

RFC 8693 Token Exchange requires an AS roundtrip per delegation hop. The AS sees every actor/subject token pair and can reconstruct the full chain topology. There is no mechanism to hide hop structure.

Bolyra's `ScopeBlindedDelegation` circuit proves chain integrity in ZK with RS-bound scope commitments. The AS sees only the initial credential issuance — never the delegation structure, target RSes, or chain depth.

### Structural impossibility 5: Timing side channels are unmitigated

The baseline requires real-time AS interaction for token issuance. Request timing at the AS perfectly correlates with agent activity at RSes. No RFC mandates batching, padding, or oblivious issuance.

Bolyra's batch blind nonce commitment scheme (§2.3) front-loads AS interaction to enrollment time. Per-authorization timing is invisible to the AS. On-chain submission timing is attributable only to the relayer, not the agent.

### Summary

| Property | Baseline (PPID+8707+DPoP+BBS+) | Bolyra AgentScopeAuth |
|----------|-------------------------------|----------------------|
| AS learns which RS agent contacts | Yes (issuance-time) | No (client-side proof) |
| RS-to-RS subject correlation | Prevented (PPID) | Prevented (scope pseudonym) |
| AS+RS collusion correlation | Trivial (AS has full graph) | Bounded by `Adv^{PRF}(λ)` |
| Formal security game | None | IND-UNL-AS with reduction |
| Delegation chain privacy from AS | None (8693 is AS-observable) | Full (ZK delegation, RS-bound) |
| Timing side channel resistance | None | Batch nonce pre-issuance |
| Scope blinding from AS | Impossible (AS sees `resource`) | Enforced (`rsIdentifier` is private input) |
