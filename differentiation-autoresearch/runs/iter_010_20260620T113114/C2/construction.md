# Construction

## 1. Statement of claim

Same agent accessing different Resource Server instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that actively attempts to correlate per-agent traffic graphs. Formally: no PPT adversary controlling the AS and colluding with any subset of RSes can distinguish whether two scope-specific authorization proofs originate from the same agent or two distinct agents, except with negligible advantage.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopedAgentAuth`

This circuit replaces direct AgentPolicy invocations for cross-scope scenarios. It derives a **scope-specific pseudonym** and **scope-specific nullifier** that are unlinkable across scopes.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentSecret` | F_p | Agent's long-term secret scalar (Baby Jubjub) |
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key |
| `permissionBitmask` | 64-bit | Permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credentialCommitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |
| `blindingNonce` | F_p | Per-presentation randomness for pseudonym blinding |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | Identifier for the target RS / resource scope |
| `requiredScopeMask` | 64-bit | Policy-required permission bits |
| `currentTimestamp` | 64-bit | Verifier-provided current time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (verified against root history buffer) |
| `scopedNullifier` | F_p | `Poseidon2(scopeId, agentSecret)` — deterministic per (agent, scope) |
| `scopedPseudonym` | F_p | `Poseidon3(scopeId, agentSecret, blindingNonce)` — unlinkable across scopes, unlinkable across presentations within same scope |
| `nonceBinding` | F_p | `Poseidon2(scopedNullifier, sessionNonce)` — replay prevention |

**Circuit constraints:**

1. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. `Num2Bits(251)` on `agentSecret`.
2. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA verification:** `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)` — proves the operator endorsed this credential.
4. **Merkle membership:** `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf produces `agentMerkleRoot`.
5. **Scope satisfaction:** For each bit `i` in `[0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:**
   - `bitmaskBits[4] * (1 - bitmaskBits[3]) === 0`
   - `bitmaskBits[4] * (1 - bitmaskBits[2]) === 0`
   - `bitmaskBits[3] * (1 - bitmaskBits[2]) === 0`
7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scoped nullifier:** `scopedNullifier = Poseidon2(scopeId, agentSecret)`.
9. **Scoped pseudonym:** `scopedPseudonym = Poseidon3(scopeId, agentSecret, blindingNonce)`.
10. **Nonce binding:** `nonceBinding = Poseidon2(scopedNullifier, sessionNonce)`.

### Protocol flow (cross-scope agent authorization)

1. Agent holds `agentSecret` and an operator-signed credential enrolled in the agent Merkle tree.
2. To access RS-A (scopeId = `hash("RS-A")`), agent generates a `ScopedAgentAuth` proof with fresh `blindingNonce_A` and `sessionNonce_A`. RS-A receives `(scopedNullifier_A, scopedPseudonym_A, nonceBinding_A, agentMerkleRoot)`.
3. To access RS-B (scopeId = `hash("RS-B")`), agent generates a separate proof with `blindingNonce_B` and `sessionNonce_B`. RS-B receives `(scopedNullifier_B, scopedPseudonym_B, nonceBinding_B, agentMerkleRoot)`.
4. Each RS verifies the proof on-chain (or off-chain with the PLONK verifier). The AS is never contacted.
5. `scopedNullifier_A ≠ scopedNullifier_B` (different `scopeId`), so RS-A and RS-B cannot correlate. The AS never sees either proof.

### Timing side-channel mitigation: batch token pre-generation

The agent pre-generates `K` proofs for anticipated scopes in a single batch during a low-activity window, then presents them at access time. The AS (if it observes any network layer) sees a single burst of proof-generation activity rather than per-RS timed requests. The `blindingNonce` ensures even pre-generated proofs for the same scope are unlinkable across presentations.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary `A` controls:
- The Authorization Server (full compromise: sees all token requests, can log all metadata)
- Up to `k - 1` of `k` Resource Servers (colluding subset)
- Network-level timing observations of proof submissions
- All public signals from all proofs

The adversary does NOT control:
- The agent's local device (cannot extract `agentSecret` or `blindingNonce`)
- The on-chain Merkle tree integrity (honest smart contract)
- The Poseidon hash function (assumed collision-resistant and PRF-secure)

### IND-UNL-AS game

**Setup:** Challenger enrolls `n ≥ 2` agents in the Merkle tree. Each agent `i` has secret `s_i` and a valid credential.

**Challenge phase:**
1. `A` chooses two distinct agents `(agent_0, agent_1)` and two distinct scopes `(scope_A, scope_B)`.
2. Challenger flips bit `b ← {0, 1}`.
3. If `b = 0`: Challenger generates proof `π_A` for `agent_0` at `scope_A` and `π_B` for `agent_0` at `scope_B`.
4. If `b = 1`: Challenger generates proof `π_A` for `agent_0` at `scope_A` and `π_B` for `agent_1` at `scope_B`.
5. Both proofs use fresh, independent `blindingNonce` and `sessionNonce` values.
6. `A` receives `(π_A, π_B)` including all public signals.

**Winning condition:** `A` outputs `b'`. Advantage = `|Pr[b' = b] - 1/2|`.

**Claim:** Under Poseidon PRF security and Groth16/PLONK zero-knowledge, the advantage is negligible in the security parameter.

### Extended game: timing-aware adversary

Same as above, but `A` also receives timestamps `(t_A, t_B)` of proof submission. Mitigation: batch pre-generation makes `t_A, t_B` independent of the challenge bit (proofs are generated in a single batch, presented at application-determined times).

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

| ID | Assumption | Usage |
|----|-----------|-------|
| A1 | **Poseidon PRF security** over BN254 scalar field | Scoped nullifier and pseudonym unlinkability |
| A2 | **Poseidon collision resistance** over BN254 scalar field | Credential commitment binding, Merkle integrity |
| A3 | **Knowledge soundness of Groth16** (BN254 pairing) | Cannot forge proofs without valid witness |
| A4 | **Zero-knowledge property of Groth16/PLONK** | Private inputs hidden from verifier |
| A5 | **Discrete log hardness on Baby Jubjub** | Cannot recover `agentSecret` from public key |

### Reduction sketch

**Theorem:** If `A` wins IND-UNL-AS with non-negligible advantage `ε`, then we construct `B` that breaks Poseidon PRF security with advantage `ε - negl(λ)`.

**Proof sketch:**

1. **Simulator setup:** `B` receives a PRF challenge oracle `O` (either `Poseidon2(scopeId, s*)` for unknown key `s*`, or a truly random function). `B` embeds `s*` as the secret of one challenge agent.

2. **Simulation of proofs:** For the challenge agent, `B` queries `O(scope_A)` and `O(scope_B)` to obtain `scopedNullifier` values. The `scopedPseudonym` additionally incorporates `blindingNonce` — by A4 (zero-knowledge), the proof hides all private inputs, so `B` can simulate proofs using the Groth16/PLONK simulator.

3. **Reduction:** If `O` is the real PRF keyed by `s*`, then `scopedNullifier_A = Poseidon2(scope_A, s*)` and `scopedNullifier_B = Poseidon2(scope_B, s*)` are outputs of the same PRF on different inputs. If `O` is random, then `scopedNullifier_A` and `scopedNullifier_B` are independent random values — indistinguishable from two different agents' nullifiers.

4. **Conclusion:** `A`'s ability to distinguish `b = 0` (same agent, both scopes) from `b = 1` (different agents) reduces to distinguishing PRF outputs from random. By A1, this advantage is negligible.

**Pseudonym unlinkability** follows similarly: `scopedPseudonym = Poseidon3(scopeId, agentSecret, blindingNonce)` is a PRF output keyed by `(agentSecret, blindingNonce)` over `scopeId`. Since `blindingNonce` is fresh and private per presentation, even two presentations to the same scope are unlinkable (by A1 + A4).

**Soundness** (cannot authorize without valid credential): By A3, a valid proof implies knowledge of a witness satisfying all constraints — including Merkle membership, EdDSA signature, scope satisfaction, and expiry. No PPT prover can produce a valid proof without a registered, unexpired, operator-signed credential whose permissions satisfy the required scope.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| `agentSecret` range check | `Num2Bits(251)` | HumanUniqueness S1.1 pattern |
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)` | AgentPolicy §4.2, constraint 2 |
| Operator signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | AgentPolicy §4.2, constraint 3 |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Both circuits, depth 20 tree |
| Scoped nullifier | `Poseidon2(scopeId, agentSecret)` — mirrors human pattern `Poseidon2(scope, secret)` | HumanUniqueness S1.2, adapted for agents |
| Scoped pseudonym | `Poseidon3(scopeId, agentSecret, blindingNonce)` — new | Extension of nullifier with blinding |
| Nonce binding | `Poseidon2(scopedNullifier, sessionNonce)` | HumanUniqueness S1.3 pattern |
| Scope satisfaction | Bitwise AND check, cumulative encoding | AgentPolicy §4.2, constraints 5–6 |
| Expiry enforcement | `LessThan(64)` | AgentPolicy §4.2, constraint 7 |
| On-chain verification | Groth16 verifier (REQUIRED), PLONK verifier (OPTIONAL) | §3.3 proving systems |
| Root history buffer | 30-entry circular buffer | Registry §3.1 |
| Delegation compatibility | `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` can still be computed inside `ScopedAgentAuth` as an auxiliary output for chains that need it | Delegation §5.2 |

**Key architectural point:** The existing `AgentPolicy` circuit computes `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`. This nullifier is **scope-independent** — the same `credentialCommitment` appears in every proof regardless of which RS is targeted. An adversarial AS that sees two proofs from the same agent (even with different `sessionNonce`) can correlate them by observing that the credential commitment (hidden inside the proof) produces nullifiers whose relationship to the session nonces is consistent. `ScopedAgentAuth` replaces this with `Poseidon2(scopeId, agentSecret)`, making the nullifier scope-dependent and breaking the correlation channel.

## 6. Circuit cost estimate

### Constraint breakdown

| Gadget | Estimated constraints |
|--------|----------------------|
| `Num2Bits(251)` — agentSecret range | 251 |
| `Num2Bits(64)` × 3 — permBitmask, expiry, currentTimestamp | 192 |
| `Poseidon5` — credential commitment | ~1,500 |
| `EdDSAPoseidonVerifier` | ~6,200 |
| `BinaryMerkleRoot(20)` — 20 × Poseidon2 + MUX | ~16,000 |
| Scope satisfaction — 64 bit checks | 128 |
| Cumulative bit encoding — 3 constraints | 3 |
| `LessThan(64)` — expiry check | ~130 |
| `Poseidon2` — scoped nullifier | ~750 |
| `Poseidon3` — scoped pseudonym | ~1,100 |
| `Poseidon2` — nonce binding | ~750 |
| **Total** | **~27,000** |

### Proving time targets

| Proving system | Target | Rationale |
|---------------|--------|-----------|
| Groth16 (snarkjs, browser) | < 8s | Within AgentPolicy budget; 27K constraints vs ~25K for existing AgentPolicy |
| Groth16 (rapidsnark, server) | < 0.5s | Native prover, production path |
| PLONK (snarkjs) | < 5s | OPTIONAL path, universal setup |

### SRS compatibility

27,000 constraints < 2^16 = 65,536. The existing `pot16.ptau` SRS is sufficient. No new ceremony required beyond a circuit-specific Groth16 Phase 2.

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent

**Stakeholders:**
- **Mountain West Federal Credit Union** (AS / issuer) — enrolls member agents
- **RS-A: AutoPay Merchants** — agent pays for gas, groceries
- **RS-B: HealthFirst Pharmacy** — agent fills prescriptions

**Problem:** Mountain West FCU, acting as the AS, must not learn that a member who pays at AutoPay also fills prescriptions at HealthFirst. Under the OAuth/OIDC baseline, the CU sees every token request (RS, scope, timestamp) and can reconstruct the member's merchant + pharmacy graph.

**Deployment with ScopedAgentAuth:**

1. **Enrollment:** Mountain West enrolls member agents into the Bolyra agent Merkle tree. Each agent receives an operator-signed credential with `permissionBitmask = 0b00000101` (READ_DATA + FINANCIAL_SMALL).

2. **Authorization for AutoPay (scopeId = Poseidon("autopay.merchants.io")):**
   - Agent generates `ScopedAgentAuth` proof locally with `blindingNonce_1`.
   - Public outputs: `scopedNullifier_autopay`, `scopedPseudonym_autopay`, `nonceBinding_autopay`, `agentMerkleRoot`.
   - Agent submits proof directly to AutoPay's on-chain verifier (or AutoPay verifies off-chain against the registry root).
   - Mountain West CU is never contacted. It sees nothing.

3. **Authorization for HealthFirst (scopeId = Poseidon("healthfirst.pharmacy.net")):**
   - Agent generates a separate proof with `blindingNonce_2`.
   - Public outputs: `scopedNullifier_healthfirst`, `scopedPseudonym_healthfirst`, `nonceBinding_healthfirst`, `agentMerkleRoot`.
   - HealthFirst verifies independently.

4. **Unlinkability guarantee:**
   - `scopedNullifier_autopay = Poseidon2(Poseidon("autopay.merchants.io"), agentSecret)`
   - `scopedNullifier_healthfirst = Poseidon2(Poseidon("healthfirst.pharmacy.net"), agentSecret)`
   - These are outputs of a PRF on different inputs. Under Poseidon PRF security, they are computationally indistinguishable from random — no party (AS, AutoPay, HealthFirst, or any collusion) can determine they originate from the same agent.
   - The `scopedPseudonym` values additionally incorporate fresh `blindingNonce`, making even repeated visits to the same RS unlinkable across sessions.

5. **Sybil prevention within scope:** AutoPay can use `scopedNullifier_autopay` for rate-limiting (same nullifier = same agent within this scope). HealthFirst independently uses `scopedNullifier_healthfirst`. Neither nullifier leaks cross-scope identity.

6. **Timing resistance:** The agent pre-generates proofs for anticipated scopes during a nightly batch (e.g., 10 proofs for the week's expected RS set). Presentation times are decoupled from generation times.

### Healthcare variant

**Stakeholders:**
- **BlueCross BlueShield of Tennessee** (AS / issuer)
- **RS-A: Dr. Smith (PCP)** — primary care
- **RS-B: Vanderbilt Radiology** — imaging referral

A member's agent is delegated credentials by Dr. Smith to obtain imaging at Vanderbilt. Under the baseline, BlueCross sees the referral chain (token exchange via RFC 8693). Under Bolyra, the delegation circuit produces a `newScopeCommitment` that chains to Vanderbilt's scope without revealing to BlueCross that the member visited radiology at all. The `ScopedAgentAuth` proof at Vanderbilt uses `scopeId = Poseidon("vanderbilt.radiology")`, producing a nullifier unlinkable to the PCP visit.

## 8. Why the baseline cannot match

| Structural limitation | Baseline behavior | ScopedAgentAuth behavior |
|----------------------|-------------------|--------------------------|
| **AS sees every authorization** | Every token request traverses the AS. The AS logs (agent_id, RS, scope, timestamp) for every access. PPID hides `sub` from RSes but the AS holds the mapping table and sees all requests. | Agent generates proofs locally. The AS is never contacted at authorization time. Zero AS-visible events per access. |
| **Issuer public key in every presentation** | BBS+ derived proofs expose the issuer's public key. A colluding AS/issuer can self-identify across all presentations. | The operator's public key is a **private input** to the circuit. The proof reveals nothing about the issuer. |
| **Scope correlation at the AS** | RFC 8707 audience-binds tokens, but the AS sees the `resource` parameter at issuance. An AS observing `scope=merchant-read` then `scope=pharmacy-read` trivially correlates. | `scopeId` is a public input to the **verifier**, not the issuer. The AS never sees which scope was requested. |
| **Delegation chain visible to AS** | RFC 8693 Token Exchange requires AS roundtrips at every hop. The AS sees the full delegation topology. | Delegation proofs chain via `scopeCommitment` values. The AS sees neither the chain nor the delegatee's target scope. |
| **No formal unlinkability definition** | No RFC or W3C spec defines an IND-UNL-AS game. BBS+ multi-show unlinkability is holder-to-verifier only. | IND-UNL-AS game defined (§3). Security reduction to Poseidon PRF (§4). Formal guarantee against AS-level adversary. |
| **Timing side channel** | DPoP requires fresh `jti` + timestamps per request, leaking request timing to the AS. No batching or oblivious issuance spec exists. | Batch pre-generation decouples proof creation from presentation. `blindingNonce` ensures pre-generated proofs are unlinkable even if generation timing is observed. |
| **Nullifier is scope-independent** | Not applicable (baseline has no nullifiers). But even the existing Bolyra `AgentPolicy` circuit uses `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`, which is scope-independent and could leak cross-scope correlation to a sophisticated observer. | `scopedNullifier = Poseidon2(scopeId, agentSecret)` is scope-dependent by construction. Different scopes → different nullifiers → no correlation channel. |

**The fundamental asymmetry:** The OAuth/OIDC baseline is architecturally incapable of hiding authorization events from the AS because the AS is the issuer of every token. Removing the AS from the issuance path is not a configuration change — it requires replacing the authorization primitive with client-side proof generation against a public state commitment (the Merkle root). This is exactly what `ScopedAgentAuth` does: it moves authorization from an AS-mediated token-issuance model to a self-sovereign proof-generation model where the only shared state is the on-chain Merkle root, which reveals nothing about individual agents' access patterns.
