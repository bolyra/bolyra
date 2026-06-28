Now I have the full prior construction from iter_037. The gap: Theorem 3 (added in iter_039/040 but only as summaries) claimed "No AS-side filter can produce a predicate proof over inputs the AS does not observe at filter time." But BBS+ selective disclosure is a counterexample — the *holder* (not AS) performs disclosure without AS involvement. The real impossibility is about arbitrary predicates unknown at issuance, not AS-observation.

Let me produce the refined construction:

# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies a verifier-specified AND-mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of `permissionBitmask` beyond predicate satisfaction. The proof is:

- **AS-blind**: generated entirely by the agent at presentation time with zero Authorization Server (AS) involvement.
- **Runtime-adaptive**: the RS specifies `requiredScopeMask` at request time; no token was pre-issued for this specific predicate.
- **Constant-size**: the Groth16/PLONK proof is ~192 bytes (Groth16) or ~576 bytes (PLONK) regardless of bitmask width or predicate complexity.
- **Sound under adversarial AS**: even if the AS is fully compromised, it cannot forge a proof for permissions the operator never signed, nor can it suppress an agent's legitimately-held permissions.

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, or BBS+ can achieve all four properties simultaneously.

## 2. Construction (gadgets, circuits, public/private inputs)

### Core circuit: `SelectiveScopeProof`

This is the AgentPolicy circuit from the Bolyra spec with one hardening modification: the `scopeCommitment` output is session-bound via `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)` instead of the spec's `Poseidon2(permissionBitmask, credentialCommitment)`. This eliminates a deterministic cross-session tracking handle while preserving delegation chain linkability (since delegation chains are already session-scoped on-chain, indexed by `sessionNonce`).

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key (Baby Jubjub) |
| `permissionBitmask` | 64-bit | Full permission bitfield (NEVER revealed) |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | RS-specified predicate mask |
| `currentTimestamp` | 64-bit | Verifier-provided wall clock |
| `sessionNonce` | F_p | Fresh session identifier |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | On-chain verifiable root |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)` — session-bound |

### Gadgets (all standard Bolyra primitives)

1. **Num2Bits(64)** on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp` — range checks preventing field overflow.
2. **Poseidon5** — `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSAPoseidonVerifier** — verifies operator signature over `credentialCommitment` using `(operatorPubkeyAx, operatorPubkeyAy)`.
4. **BinaryMerkleRoot(20)** — proves `credentialCommitment` is a leaf in the agent Merkle tree.
5. **Bitwise AND-mask check** — for each bit `i ∈ [0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`. This is the selective scope predicate: every required bit must be set, but unrequired bits are unconstrained and hidden.
6. **Cumulative bit enforcement** — `bits[4]*(1-bits[3]) === 0`, `bits[4]*(1-bits[2]) === 0`, `bits[3]*(1-bits[2]) === 0`. Ensures implication closure (FINANCIAL_UNLIMITED ⇒ FINANCIAL_MEDIUM ⇒ FINANCIAL_SMALL).
7. **LessThan(64)** — `currentTimestamp < expiryTimestamp`.
8. **Poseidon2** — `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`.
9. **Poseidon3** — `scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`. The additional `sessionNonce` input ensures that the same agent presenting the same credential to two different sessions produces distinct, unlinkable `scopeCommitment` values.

### Why Poseidon3 instead of Poseidon2 for scopeCommitment

The spec's original `Poseidon2(permissionBitmask, credentialCommitment)` is deterministic across sessions. If the same agent authenticates to RS_A in session s₁ and RS_B in session s₂, both RSes observe the same `scopeCommitment`. Two colluding RSes can correlate on this value and link the agent's presentations — a direct violation of cross-RS unlinkability.

Adding `sessionNonce` as a third Poseidon input costs exactly one additional field multiplication chain (~25 constraints) and makes `scopeCommitment` fresh per session. The delegation chain is unaffected because:

- The on-chain registry already indexes `lastScopeCommitment` by `sessionNonce` (spec §5).
- The delegation circuit's chain-linking constraint (`Poseidon_n(delegatorScope, delegatorCredCommitment, ...) == previousScopeCommitment`) operates within a single session context. The delegator's proof and the delegatee's proof share the same `sessionNonce`, so the session-bound scope commitment chains correctly within that session.
- Cross-session delegation is not a protocol operation — delegation chains do not span sessions.

### Presentation protocol

```
1. RS generates fresh sessionNonce, sends (requiredScopeMask, currentTimestamp, sessionNonce) to agent.
2. Agent generates PLONK proof π locally using its private credential.
   — No AS contact. No token refresh. No introspection endpoint.
3. Agent sends (π, agentMerkleRoot, nullifierHash, scopeCommitment, requiredScopeMask, currentTimestamp, sessionNonce) to RS.
4. RS verifies:
   a. agentMerkleRoot ∈ on-chain root history buffer (30-entry window)
   b. PLONK.Verify(vk, publicSignals, π) = true
   c. nullifierHash not in used-nonce set (replay prevention)
   d. currentTimestamp is within acceptable clock skew
5. RS learns: "this agent holds a valid, unexpired, operator-signed credential enrolled in the Bolyra tree, and its permission bitmask satisfies my required mask." RS learns NOTHING else about the agent's identity, operator, model, or remaining permissions.
```

Note: `scopeCommitment` in the presentation is now session-specific. Two RSes comparing notes across different sessions see distinct `scopeCommitment` values and cannot correlate them to the same agent without breaking Poseidon preimage resistance.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:

- The Authorization Server (AS) completely — can read/modify its database, forge introspection responses, selectively deny service.
- The network between agent and RS (eavesdrop, replay, MITM).
- Up to `n - 1` colluding RSes that share transcripts (including all public signals from their respective sessions).

The adversary does NOT control:

- The agent's private credential fields (modelHash, operatorPubkey, permissionBitmask, etc.).
- The operator's EdDSA signing key.
- The on-chain Merkle tree smart contract (public, append-only, consensus-protected).
- The BN128 pairing or Baby Jubjub discrete log problem.
- The session nonces generated by honest RSes (each RS generates its own fresh nonce).

### Game: Selective Scope Unforgeability (SSU)

```
Game SSU(λ):
  1. Setup: Challenger runs Bolyra setup, deploys agent Merkle tree on-chain.
     Challenger enrolls honest agent with credential (modelHash*, opPk*, permBitmask*, expiry*).
  2. Adversary A (controlling AS) receives: the Merkle root, the PLONK/Groth16 verification key,
     all public signals from any number of prior valid presentations by the honest agent.
  3. Challenge: Challenger samples requiredScopeMask* such that
     permBitmask* & requiredScopeMask* ≠ requiredScopeMask*
     (i.e., the honest agent does NOT satisfy this predicate).
  4. A wins if it produces (π, publicSignals) such that:
     a. PLONK.Verify(vk, publicSignals, π) = true
     b. publicSignals.agentMerkleRoot ∈ root history buffer
     c. publicSignals.requiredScopeMask = requiredScopeMask*
  5. SSU-advantage: Adv_SSU(A) = Pr[A wins]
```

### Game: Selective Scope Zero-Knowledge (SSZK)

```
Game SSZK(λ):
  1. Setup: Challenger enrolls two agents with credentials C0, C1 where:
     - C0.permBitmask & requiredScopeMask = requiredScopeMask (C0 satisfies)
     - C1.permBitmask & requiredScopeMask = requiredScopeMask (C1 satisfies)
     - C0.permBitmask ≠ C1.permBitmask (different full permission sets)
     Both agents are enrolled in the same Merkle tree.
  2. Challenger flips coin b ∈ {0, 1}.
  3. A (controlling AS + up to n-1 colluding RSes) adaptively issues up to q
     presentation queries. For each query j, A specifies (requiredScopeMask_j,
     currentTimestamp_j, sessionNonce_j) where each sessionNonce_j is fresh.
     Challenger returns (π_j, agentMerkleRoot, nullifierHash_j, scopeCommitment_j,
     requiredScopeMask_j, currentTimestamp_j, sessionNonce_j) computed using C_b.
  4. A outputs guess b'.
  5. SSZK-advantage: Adv_SSZK(A) = |Pr[b' = b] - 1/2|
```

**Key strengthening over prior version**: The SSZK game now grants A *multiple adaptive queries* across different sessions with distinct nonces, modeling colluding RSes that pool transcripts. The session-bound `scopeCommitment` ensures each query's public signals are independently distributed.

**Note on nullifierHash**: `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)` is also session-bound, so distinct sessions produce distinct nullifiers. However, if the same agent presents to the same session (same `sessionNonce`), the nullifier is deterministic — this is by design for replay detection, not a correlation leak, since the RS already knows it issued that nonce.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **A1**: Knowledge soundness of Groth16 (BN128 pairing) / PLONK (polynomial commitment scheme).
- **A2**: Collision resistance of Poseidon over the BN254 scalar field. This implies preimage resistance and PRF security under the algebraic group model.
- **A3**: Discrete logarithm hardness on Baby Jubjub (EdDSA unforgeability).
- **A4**: Random Oracle Model (ROM) for Fiat-Shamir in PLONK; Groth16 uses CRS model.

### Theorem 1 (SSU security)

**Claim**: If A wins the SSU game with non-negligible advantage, then either (a) knowledge soundness of PLONK/Groth16 is broken, (b) Poseidon collision resistance is broken, or (c) EdDSA on Baby Jubjub is forgeable.

**Reduction sketch**:

1. Suppose A produces a valid proof π for `requiredScopeMask*` that the honest agent cannot satisfy.
2. By knowledge soundness (A1), extract witness `w = (modelHash, opPkAx, opPkAy, permBitmask', expiry, sig, merkleProof)`.
3. The circuit enforces `requiredBits[i] * (1 - permBits'[i]) === 0` for all i. So `permBitmask' & requiredScopeMask* == requiredScopeMask*`.
4. The circuit enforces `credCommitment' = Poseidon5(modelHash, opPkAx, opPkAy, permBitmask', expiry)` and Merkle membership of `credCommitment'`.
5. Case (i): `credCommitment'` equals the honest agent's `credCommitment*` but `permBitmask' ≠ permBitmask*`. Then `Poseidon5(... permBitmask' ...) = Poseidon5(... permBitmask* ...)` — a Poseidon collision, breaking A2.
6. Case (ii): `credCommitment'` is a different enrolled credential. Then A forged the operator's EdDSA signature over a new credential commitment (breaking A3), or inserted a new leaf into the on-chain tree (breaking consensus, outside model).
7. Case (iii): `credCommitment'` is not in the tree but the Merkle proof verifies. This is a Poseidon collision on internal tree nodes, breaking A2.

**Note**: The session-bound `scopeCommitment` change does not affect SSU security. The unforgeability argument depends only on the credential commitment, EdDSA signature, and Merkle membership constraints — none of which involve `scopeCommitment`.

### Theorem 2 (SSZK security)

**Claim**: `Adv_SSZK(A) ≤ negl(λ)` under the zero-knowledge property of Groth16/PLONK and the PRF security of Poseidon.

**Reduction sketch**:

1. `permissionBitmask` is a private input. By the zero-knowledge property, the proof reveals nothing about private inputs beyond what the public signals imply.
2. The public signals per session j are: `agentMerkleRoot`, `nullifierHash_j`, `scopeCommitment_j`, `requiredScopeMask_j`, `currentTimestamp_j`, `sessionNonce_j`.
3. **Cross-session unlinkability of nullifierHash**: `nullifierHash_j = Poseidon2(credCommitment_b, sessionNonce_j)`. Since each `sessionNonce_j` is fresh and Poseidon is a PRF under A2, the sequence `{nullifierHash_j}` is computationally indistinguishable from random for each candidate credential. The adversary cannot correlate nullifiers across sessions to determine whether the same credential was used.
4. **Cross-session unlinkability of scopeCommitment**: `scopeCommitment_j = Poseidon3(permBitmask_b, credCommitment_b, sessionNonce_j)`. The `sessionNonce_j` input ensures each `scopeCommitment_j` is a fresh PRF evaluation. Two colluding RSes observing `scopeCommitment_1` and `scopeCommitment_2` from different sessions cannot determine whether the same `(permBitmask, credCommitment)` pair produced both values — this requires inverting Poseidon or distinguishing it from a random function, breaking A2.
   - **This is the critical fix**: Under the prior construction where `scopeCommitment = Poseidon2(permBitmask, credCommitment)`, the value was deterministic across sessions. If C0 and C1 have different `(permBitmask, credCommitment)` pairs, an adversary issuing two queries would observe whether `scopeCommitment_1 == scopeCommitment_2`, immediately identifying that the same credential was used and enabling a trivial distinguishing attack (Adv_SSZK = 1). The session-bound construction eliminates this channel entirely.
5. **agentMerkleRoot**: Both C0 and C1 are enrolled in the same tree, so the root is identical regardless of b. This signal leaks nothing.
6. A's view across all q queries is simulatable: for each query, the PLONK/Groth16 simulator produces an indistinguishable proof, and the public signals `(nullifierHash_j, scopeCommitment_j)` are PRF evaluations keyed by the hidden credential and indexed by the fresh `sessionNonce_j`.
7. Therefore: `Adv_SSZK(A) ≤ q · Adv_PRF(A') + Adv_ZK(A'') + negl(λ)`, where `Adv_PRF` is the advantage against Poseidon as a PRF and `Adv_ZK` is the advantage against the zero-knowledge property of Groth16/PLONK. Both are negligible under A1 and A2.

### Theorem 3 (Predicate-agnostic selective proof impossibility)

**Claim**: Let `F` be any credential system where (i) an issuer signs a credential containing attributes `a_1, ..., a_k` at issuance time, and (ii) a verifier specifies a predicate `P` at presentation time. If `P` is drawn from an arbitrary class `C` that includes predicates not expressible as Boolean combinations of individual attribute equalities and range checks — in particular, bitwise AND over a committed multi-bit field with implication closure — then no assertion-based credential system (where the verifier's acceptance depends on a signature chain rooted at the issuer) can produce a verifier-checkable proof of `P(a_1, ..., a_k) = true` for predicates in `C` without either:

  (a) the issuer pre-computing and signing a separate assertion for each `P ∈ C` the verifier might request (exponential in the number of predicate parameters), or

  (b) the issuer being online at presentation time to evaluate `P` on demand.

**Proof sketch**:

1. **The predicate class boundary.** Define `C_BBS` as the class of predicates natively supported by BBS+ with NIZK extensions: equality of hidden attributes, range proofs on individual hidden attributes, and Boolean AND/OR over these. `C_BBS` is the strongest predicate class achievable by any assertion-based selective disclosure scheme in the literature. The critical predicate `P_AND(b, m) = (b & m == m)` where `b` is a 64-bit field and `m` is verifier-chosen, combined with implication closure (`bit[4] ⇒ bit[3] ⇒ bit[2]`), is NOT in `C_BBS`. It requires evaluating 64 parallel bit-level constraints with cross-bit dependencies over a *single committed attribute* — not 64 independent attributes.

2. **Why decomposition doesn't help.** One might decompose the 64-bit bitmask into 64 individual BBS+ message slots at issuance. Then each bit becomes an independent attribute, and the verifier requests disclosure of the required bits. But this fails in two ways: (a) disclosed bits are revealed in the clear — the verifier learns the *values* of the required bits, not just that the predicate holds, violating zero-knowledge for the AND-mask predicate (the verifier should learn only that `b & m == m`, not which specific unrequired bits are set among the required positions); and (b) implication closure (`bit[4] ⇒ bit[3]`) cannot be enforced by BBS+ — the issuer must verify it at issuance, but the verifier has no cryptographic proof that the issuer checked it, only trust in the issuer's correctness. Under the adversarial-AS model, this trust is insufficient.

3. **Why issuer pre-computation is infeasible.** For a 64-bit mask, there are 2^64 possible `requiredScopeMask` values. Pre-signing an assertion for each would require the issuer to produce and the holder to store 2^64 signatures. Even restricting to the 8 defined permission bits, the implication-closure constraints create 2^8 = 256 valid bitmask configurations, and the verifier may request any of 2^8 possible masks — yielding up to 256 × 256 = 65,536 predicate evaluations to pre-sign. This is technically feasible for 8 bits but does not scale: the construction's claim holds for the general 64-bit space, and the protocol's design accommodates future permission expansion without re-issuance.

4. **Why online issuers reduce to option (b).** If the issuer evaluates `P` on demand at presentation time, the issuer is in the hot path — this is exactly the RFC 7662 introspection model that the AS-blind property excludes.

5. **Connection to BBS+ selective disclosure.** BBS+ is the strongest counterexample to the naive version of this theorem ("no system can produce proofs without AS observation"). BBS+ *does* allow holder-driven selective disclosure without issuer involvement at presentation time. But BBS+ selective disclosure operates over a fixed predicate class `C_BBS`. The predicate `P_AND` with implication closure falls outside `C_BBS`. This is not an implementation gap — it is a fundamental limitation of the algebraic structure of BBS+ (pairing-based, operating over individual message slots). Extending BBS+ to support arbitrary arithmetic predicates over committed attributes would require embedding an arithmetic circuit verifier inside the BBS+ proof — which is precisely what a zkSNARK is.

**Corollary 3.1 (Suppression resistance)**: Under Theorem 3, a compromised issuer in a BBS+ system can issue a credential with `bit[4] = 1, bit[3] = 0` (violating implication closure). The holder can present this credential, and the verifier — who can only check individual disclosed bits or rely on issuer-asserted structure — has no cryptographic guarantee that the implication invariant holds. In Bolyra, the circuit enforces `bits[4]*(1-bits[3]) === 0` at proving time; a malformed bitmask produces no valid proof.

**Corollary 3.2 (Predicate composition)**: Bolyra's arithmetic circuit can evaluate any predicate expressible as a polynomial constraint system over the bitmask bits — including AND-mask, threshold ("at least k of these 8 bits are set"), weighted sums, and arbitrary Boolean formulas — without re-issuance. BBS+ requires a new NIZK extension for each predicate class, and no BBS+ extension covers the intersection of bitwise AND + implication closure + zero-knowledge (hiding which required bits matched).

### Why the adversarial-AS model holds

The critical observation: **no step in the presentation protocol requires AS participation or AS-issued assertions**. The credential's validity derives from:

- Operator signature (EdDSA, verified in-circuit) — the AS cannot forge this.
- Merkle membership (on-chain root, public) — the AS cannot modify the tree without a transaction visible to all.
- Permission predicate (evaluated in-circuit) — the AS has no input to this computation.

A compromised AS can refuse to enroll new agents (denial of service), but it cannot:

- Forge proofs for permissions an agent doesn't hold (SSU security).
- Learn which permissions an agent revealed to which RS (SSZK security).
- Retroactively revoke a presentation already verified on-chain (immutability).
- Correlate presentations across RSes via public signals (session-bound outputs).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Permission encoding | 64-bit cumulative bitmask with implication closure | `permissionBitmask`, §4.2 |
| Credential binding | `Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)` | `credentialCommitment`, §3 |
| Operator authentication | EdDSA on Baby Jubjub over `credentialCommitment` | `EdDSAPoseidonVerifier`, §4.3 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Agent Merkle tree, §3.1 |
| Predicate evaluation | Bitwise AND-mask check in-circuit | AgentPolicy constraint 5, §4.3 |
| Scope commitment (session-bound) | `Poseidon3(permBitmask, credCommitment, sessionNonce)` | Hardened from spec §5 `Poseidon2` — adds `sessionNonce` for cross-session unlinkability |
| Replay prevention | `Poseidon2(credCommitment, sessionNonce)` | `nullifierHash`, §4.3 |
| Proving system | PLONK (agent, no per-circuit ceremony) or Groth16 | §3.2 |
| On-chain root anchor | 30-entry root history buffer | §3.1 |

**Spec deviation note**: The spec defines `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)`. This construction uses `Poseidon3(permissionBitmask, credentialCommitment, sessionNonce)`. The change is backwards-compatible with the delegation chain mechanism because `lastScopeCommitment` is already stored on-chain indexed by `sessionNonce`, and delegation hops within a session share the same nonce. The delegation circuit's chain-linking constraint must correspondingly use `Poseidon3(delegatorScope, delegatorCredCommitment, sessionNonce) == previousScopeCommitment`, with `sessionNonce` available as a public input to the delegation circuit.

## 6. Circuit cost estimate

### Constraint breakdown (AgentPolicy / SelectiveScopeProof)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(64) × 3 (bitmask, expiry, timestamp) | 192 |
| Poseidon5 (credential commitment) | ~300 |
| EdDSAPoseidonVerifier | ~4,500 |
| BinaryMerkleRoot(20) with Poseidon2 × 20 levels | ~3,000 |
| Bitwise AND-mask check (64 multiplications) | 64 |
| Cumulative bit enforcement (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon2 (nullifierHash) | ~150 |
| Poseidon3 (scopeCommitment, session-bound) | ~175 |
| **Total** | **~8,514** |

**Delta from prior construction**: +~25 constraints (Poseidon3 vs Poseidon2 for scopeCommitment — one additional field element in the sponge). This is negligible: 0.3% increase, well within the same power-of-two bucket (2^14).

### Proving time targets

| System | Constraint budget | Target proving time | Proof size |
|--------|------------------|--------------------:|--------:|
| Groth16 (BN128) | ~8,514 (~2^14) | < 3s (snarkjs), < 0.5s (rapidsnark) | 192 B |
| PLONK (universal SRS) | ~8,514 | < 5s (snarkjs) | ~576 B |

Both are well within the `pot16.ptau` (2^16) ceremony. Verification on-chain: ~230K gas (Groth16) via EIP-196/197 precompiles.

### Comparison to BBS+ selective disclosure

A BBS+ presentation over 64 individual permission claims requires ~64 group exponentiations (~25 ms) and produces a proof linear in the number of hidden claims. The ZK proof is constant-size and constant-time regardless of which or how many bits are checked or hidden. BBS+ also provides no mechanism for session-binding the derived proof's structure — two BBS+ presentations of the same credential with the same disclosed claim set are linkable by the proof structure itself unless the holder randomizes the credential identifier, which BBS+ supports but which does not extend to the permission predicate evaluation.

## 7. Concrete deployment scenario

### Stakeholder: Navy Federal Credit Union (NFCU) — AI agent portfolio management

**Context**: NFCU deploys AI agents to manage member investment portfolios. Agents interact with multiple resource servers: a market data service, a trade execution engine, and a compliance reporting system. Each RS requires different permission subsets.

**Problem without Bolyra**: NFCU's OAuth AS issues tokens with full scope strings. The trade execution RS receives `scope: "read_data write_data financial_medium sign_on_behalf"` — revealing to the trade engine that this agent can also sign on behalf of members, information the trade engine has no business knowing. A compromised trade engine now knows to target this agent for escalation attacks. Worse: if two RSes compare introspection responses, they can trivially determine that the same agent accessed both services.

**With Selective Scope Proof (session-bound)**:

1. **Enrollment**: NFCU's operator signs agent credentials with `permissionBitmask = 0b00101111` (READ_DATA + WRITE_DATA + FINANCIAL_SMALL + FINANCIAL_MEDIUM + SIGN_ON_BEHALF). Credential commitment enrolled in the Bolyra agent Merkle tree.

2. **Market data request**: The market data RS specifies `requiredScopeMask = 0b00000001` (READ_DATA only) with a fresh `sessionNonce_1`. Agent generates a PLONK proof in <0.5s (rapidsnark). RS learns: "this agent can read data." RS sees `scopeCommitment_1 = Poseidon3(0b00101111, credCommitment, sessionNonce_1)` — a value unique to this session.

3. **Trade execution**: The trade engine specifies `requiredScopeMask = 0b00001111` with a different `sessionNonce_2`. Agent proves satisfaction. Trade engine sees `scopeCommitment_2 = Poseidon3(0b00101111, credCommitment, sessionNonce_2)`. Because `sessionNonce_2 ≠ sessionNonce_1`, `scopeCommitment_2 ≠ scopeCommitment_1`. **The market data RS and trade engine cannot correlate these presentations even if they collude** — linking requires inverting Poseidon3 to recover the shared `(permBitmask, credCommitment)` pair.

4. **AS compromise**: If NFCU's OAuth AS is breached, the attacker cannot:
   - Forge proofs granting agents permissions the operator didn't sign (EdDSA unforgeability).
   - Learn which permission subsets agents revealed to which RSes (zero-knowledge).
   - Issue introspection responses claiming an agent lacks permissions it actually holds (the RS doesn't query the AS at all).
   - Correlate the agent's presentations across RSes by comparing public signals (session-bound scopeCommitment and nullifierHash).

5. **Regulatory audit**: The compliance RS specifies `requiredScopeMask = 0b10000000` (ACCESS_PII). The agent's proof FAILS (bit 7 is not set in `0b00101111`). The RS gets a cryptographic denial — not an AS policy decision that could be overridden by a compromised AS administrator.

**Scale**: With 64-bit bitmask, NFCU can encode 2^64 theoretical permission combinations. The proof remains 192 bytes and <0.5s regardless. An OAuth scope string enumerating even 2^16 permission combinations would be 64 KB per introspection response.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + BBS+ VCs) fails on four independent axes. Each failure is structural, not a gap in current implementations.

### Failure 1: Predicate-agnostic runtime evaluation is structurally impossible in assertion-based systems

**Theorem 3** establishes that the fundamental barrier is not whether the AS observes the bitmask (BBS+ shows a holder can disclose without AS involvement) but whether the *predicate class* is fixed at issuance or open-ended at presentation.

BBS+ selective disclosure — the strongest non-ZK baseline — supports a fixed predicate class `C_BBS`: equality and range checks on individual message slots, plus Boolean combinations thereof. The predicate `P_AND(b, m) = (b & m == m)` with implication closure over a committed multi-bit field falls outside `C_BBS`. This is algebraically fundamental: BBS+ operates over individual group elements in the signed message vector; cross-slot arithmetic (bitwise AND across bits packed into a single committed field, with cross-bit implication constraints) has no representation in the BBS+ proof structure.

**Bolyra's construction** evaluates `P_AND` as 64 parallel R1CS constraints (`requiredBits[i] * (1 - permBits[i]) === 0`) plus 3 implication-closure constraints, all inside the arithmetic circuit. The RS specifies `requiredScopeMask` as a public input at verification time. The predicate was never anticipated at issuance — any mask the RS invents works without re-issuance or issuer contact.

### Failure 2: Runtime-adaptive bitmask predicates are inexpressible

OAuth scopes are string-typed. `scope: "read write financial_small"` is not a bitmask — it's a set of opaque labels. The RS cannot evaluate `permissionBitmask & requiredMask == requiredMask` because no bitmask exists in the token. The AS would need to pre-compute and sign every possible mask conjunction the RS might request.

BBS+ supports equality and range predicates on individual hidden attributes but does not support bitwise AND across a multi-attribute field with implication closure. `bit[4] ⇒ bit[3] ⇒ bit[2]` is a circuit-level constraint that has no BBS+ analog.

**Bolyra's construction**: The predicate `requiredBits[i] * (1 - permBits[i]) === 0` is evaluated inside the arithmetic circuit. The RS specifies `requiredScopeMask` as a public input at request time. No pre-issuance is needed. The agent evaluates any mask the RS presents, including masks the AS never anticipated.

### Failure 3: The adversarial-AS game has no baseline solution

The entire RFC 7662 stack assumes a trusted AS. Theorem 1 (SSU) proves that Bolyra's construction is unforgeable even when the AS is fully adversarial. The reduction is to knowledge soundness of PLONK/Groth16, Poseidon collision resistance, and EdDSA unforgeability — none of which involve the AS.

In the baseline, a compromised AS can:

- Return `{"active": false}` for a valid token (denial of legitimate access).
- Return `{"active": true, "scope": "admin"}` for a token that never had admin scope (privilege escalation).
- Correlate all introspection requests to build a complete access log.

No combination of DPoP, RFC 8707, or BBS+ prevents these attacks because the RS's trust anchor is the AS's signature, and the AS controls that signature. BBS+ moves selective disclosure to the holder, but the *structural integrity* of the credential (e.g., implication closure) remains asserted by the issuer with no cryptographic enforcement at the verifier — per Corollary 3.1, a compromised issuer can violate invariants the verifier cannot detect.

### Failure 4: Cross-RS unlinkability is unachievable in the baseline

**This is the structural gap the session-bound construction closes.**

BBS+ presentations are unlinkable at the RS layer *per-presentation* — two BBS+ derived proofs of the same credential cannot be correlated by comparing the proofs themselves. However:

- **The AS knows everything**: The BBS+ issuer (AS) signed the original credential and can correlate issuance events. PPID (OIDC Core §8.1) prevents RS-vs-RS `sub` correlation but does not prevent AS-level correlation.
- **Scope structure leaks**: If two RSes request the same subset of BBS+ claims and the agent discloses the same claims, the disclosed *values* (permission labels) are identical and linkable. BBS+ hides undisclosed claims but reveals disclosed ones in the clear.
- **No session binding on credential structure**: BBS+ does not bind the derived proof to a session nonce in a way that makes the proof's public outputs unlinkable across sessions. The selective disclosure envelope changes, but the disclosed claim values remain stable.

**Bolyra's construction**: `scopeCommitment = Poseidon3(permBitmask, credCommitment, sessionNonce)` produces a fresh, pseudorandom output per session. Even if two RSes request identical `requiredScopeMask` values and the agent satisfies both, the `scopeCommitment` values differ (different `sessionNonce`) and cannot be correlated without breaking Poseidon PRF security. Similarly, `nullifierHash = Poseidon2(credCommitment, sessionNonce)` is session-fresh. The only public signal that is stable across sessions is `agentMerkleRoot`, which is shared by all enrolled agents and reveals nothing about the individual agent.

### Summary of structural impossibilities

| Property | Theorem | RFC 7662 + BBS+ baseline | Bolyra Selective Scope Proof |
|----------|---------|--------------------------|------------------------------|
| Predicate-agnostic runtime evaluation | Thm 3 | Fixed predicate class `C_BBS` at issuance; `P_AND` + implication closure outside `C_BBS` | Arbitrary R1CS predicate via public input `requiredScopeMask` |
| AS involvement at presentation | Thm 3 | Required for predicates outside `C_BBS`; BBS+ avoids AS only within `C_BBS` | None (on-chain root + in-circuit EdDSA) |
| Adversarial AS resilience | Thm 1 | None — AS/issuer signature is the only guarantee; structural invariants unenforceable (Cor 3.1) | SSU-secure under Poseidon CR + EdDSA + PLONK/Groth16 soundness |
| Proof size | — | O(hidden claims) for BBS+; O(scope strings) for JWT | O(1) — 192 bytes (Groth16), 576 bytes (PLONK) |
| Implication closure enforcement | Cor 3.1 | Issuer-asserted only; verifier cannot detect violations | Enforced in arithmetic circuit (cumulative bit constraints) |
| Model identity binding | — | `client_id` string, no cryptographic binding | `credentialCommitment` includes `modelHash` + operator pubkey |
| Cross-RS unlinkability | Thm 2 | BBS+ unlinkable at RS layer, but AS correlates; disclosed values linkable across RSes | Session-bound `scopeCommitment` + `nullifierHash` — unlinkable across sessions under Poseidon PRF |
