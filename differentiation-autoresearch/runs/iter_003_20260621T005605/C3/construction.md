# Construction

## 1. Statement of claim

An auditor verifies that a multi-hop delegation chain narrowed permissions monotonically — without learning any intermediate scope values, participant identities, or credential commitments — using a single PLONK proof that internalizes all chain state. The construction applies to any pipeline where each hop is a tool call, cross-org agent handoff, or whistleblower-protected relay, not only to regulatory audit.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationAuditRollup(MAX_HOPS)`

Unrolled fixed-depth circuit that processes up to MAX_HOPS delegation hops inline. All intermediate chain state is private; only endpoints and policy satisfaction are public.

**Private inputs (per hop `i` in `[0, MAX_HOPS)`):**

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScope[i]` | 64-bit | Delegator permission bitmask at hop i |
| `delegateeScope[i]` | 64-bit | Delegatee permission bitmask at hop i |
| `delegatorCredCommitment[i]` | field | Delegator's Poseidon5 credential commitment |
| `delegateeCredCommitment[i]` | field | Delegatee's Poseidon5 credential commitment |
| `delegateeExpiry[i]` | 64-bit | Delegatee expiry timestamp |
| `delegatorExpiry[i]` | 64-bit | Delegator expiry timestamp |

**Private inputs (global):**

| Signal | Type | Description |
|--------|------|-------------|
| `logBlindingSalt` | field | Random blinding salt chosen by the chain initiator at handshake time. Used as the first argument to the initial log accumulator hash, replacing the deterministic constant `0`. |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Chain seed from the initial handshake (stored on-chain by the registry) |
| `auditPolicyMask` | Minimum permission bits the terminal delegatee must satisfy |
| `minExpiry` | Minimum acceptable terminal expiry (auditor-set floor) |
| `sessionNonce` | Binds the audit proof to the delegation session |
| `executionLogDigest` | Running Poseidon hash chain of all on-chain scope commitment events (read from registry) |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `chainLength` | Number of active hops (in `[1, MAX_HOPS]`) |
| `terminalScopeCommitment` | `Poseidon2(delegateeScope[chainLength-1], delegateeCredCommitment[chainLength-1])` |
| `auditDigest` | `Poseidon3(rootScopeCommitment, terminalScopeCommitment, chainLength)` — non-repudiation anchor |

### On-chain execution log

The Bolyra registry already stores `lastScopeCommitment` per session nonce at each delegation hop (§4 of the spec). The registry is extended with a single additional field per session:

```
mapping(uint256 => uint256) public delegationLogDigest;
```

**Update rule (in the existing `verifyHandshake` and `verifyDelegation` functions):**

- After handshake (hop 0 seed): The chain initiator provides a `blindedLogSeed` (a `uint256`) as an additional argument to `verifyHandshake`. The registry stores it directly: `delegationLogDigest[nonce] = blindedLogSeed`. The registry does NOT compute or verify the relationship between `blindedLogSeed` and `rootScopeCommitment` — integrity is enforced by the audit circuit at proof time. The initiator computes `blindedLogSeed = Poseidon2(r, rootScopeCommitment)` off-chain, where `r` is a cryptographically random field element kept private.
- After each delegation hop that writes `newScopeCommitment`: `delegationLogDigest[nonce] = Poseidon2(delegationLogDigest[nonce], newScopeCommitment)`

This is a single Poseidon2 hash appended to an existing on-chain write path — no additional storage slots per hop, no new events, no log array. The digest is a running hash accumulator: append-only, O(1) storage. The only change from the prior construction is that the initial seed is caller-provided rather than registry-computed.

**Why the registry need not verify `blindedLogSeed`:** If the initiator provides a malformed seed (one not equal to `Poseidon2(r, rootScopeCommitment)` for any `r`), the audit circuit will fail: the circuit computes `logAcc[0] = Poseidon2(logBlindingSalt, rootScopeCommitment)` and the resulting hash chain will not match the on-chain `executionLogDigest` unless the prover finds `(r', rsc')` such that `Poseidon2(r', rsc') = blindedLogSeed` and `rsc'` passes the chain-linking constraint against the actual `rootScopeCommitment` — which requires a Poseidon collision. No valid audit proof can be produced from a malformed seed.

**Constraints (per hop `i`):**

1. **Range checks:** `Num2Bits(64)` on `delegatorScope[i]`, `delegateeScope[i]`, `delegateeExpiry[i]`, `delegatorExpiry[i]`.

2. **Chain linking (hop 0):** `Poseidon2(delegatorScope[0], delegatorCredCommitment[0]) === rootScopeCommitment`.

3. **Chain linking (hop i > 0):** `Poseidon2(delegatorScope[i], delegatorCredCommitment[i]) === Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])`. The delegator at hop i must be the delegatee of hop i-1.

4. **Scope narrowing:** For each bit `j` in `[0, 64)`: `delegateeBits[i][j] * (1 - delegatorBits[i][j]) === 0`. No bit set in the delegatee scope can be unset in the delegator scope.

5. **Cumulative bit encoding on delegatee scope:**
   - `delegateeBits[i][4] * (1 - delegateeBits[i][3]) === 0`
   - `delegateeBits[i][4] * (1 - delegateeBits[i][2]) === 0`
   - `delegateeBits[i][3] * (1 - delegateeBits[i][2]) === 0`

6. **Expiry narrowing:** `delegateeExpiry[i] <= delegatorExpiry[i]` via `LessEqThan(64)`.

7. **Hop activation:** A selector signal `active[i]` is computed as `i < chainLength` (enforced via `LessThan(log2(MAX_HOPS)+1)`). Inactive hops are constrained to identity pass-through: `delegateeScope[i] === delegatorScope[i]` and `delegateeCredCommitment[i] === delegatorCredCommitment[i]` when `active[i] === 0`. Active-hop constraints (narrowing, expiry, chain linking) are gated on `active[i] === 1`.

8. **Terminal policy satisfaction:** For each bit `j` in `[0, 64)`: `auditPolicyBits[j] * (1 - terminalDelegateeBits[j]) === 0`. The terminal delegatee's scope must include all bits required by the audit policy.

9. **Terminal expiry floor:** `terminalExpiry >= minExpiry` via `LessEqThan(64)` on the final active hop's `delegateeExpiry`.

10. **Audit digest:** `auditDigest = Poseidon3(rootScopeCommitment, terminalScopeCommitment, chainLength)`.

11. **Execution log completeness:** The circuit computes a running hash accumulator over scope commitments derived from the witness, using the private `logBlindingSalt` as the initial seed, then constrains it against the public input `executionLogDigest`:

    ```
    logAcc[0] = Poseidon2(logBlindingSalt, rootScopeCommitment)
    for i in [0, MAX_HOPS):
      scopeComm[i] = Poseidon2(delegateeScope[i], delegateeCredCommitment[i])
      logAcc[i+1] = active[i] ? Poseidon2(logAcc[i], scopeComm[i]) : logAcc[i]
    logAcc[chainLength] === executionLogDigest
    ```

    The initial accumulator value `Poseidon2(logBlindingSalt, rootScopeCommitment)` uses the private blinding salt instead of the deterministic constant `0`. This prevents an auditor from enumerating candidate `rootScopeCommitment` values against the on-chain digest: without knowing `logBlindingSalt`, the auditor cannot compute the initial accumulator state, and therefore cannot determine which handshake seeded the chain even given the full set of K candidate roots.

    The final accumulator value (selected at index `chainLength` via a `MultiMux1` over MAX_HOPS+1 candidates) must equal the public input `executionLogDigest`. Since `executionLogDigest` is read from on-chain state — written incrementally by the registry during actual delegation execution — the prover cannot omit, reorder, or fabricate hops.

    The Mux1 selection for the final accumulator uses `chainLength` as the selector over the array `logAcc[0..MAX_HOPS]`, implemented as a `MAX_HOPS+1`-way multiplexer (a standard `QuinSelector`-style gadget reduced to `MAX_HOPS+1` equality checks plus conditional selection, ~3 constraints per candidate).

**Gadgets used:**

- `Poseidon2`, `Poseidon3` — Poseidon algebraic hash (BN128 scalar field)
- `Num2Bits(64)` — range decomposition
- `LessThan`, `LessEqThan` — comparator gadgets (64-bit)
- `Mux1` — conditional multiplexer for hop activation gating
- `QuinSelector` (or equivalent) — select `logAcc[chainLength]` from the accumulator array

### Verification flow

1. Auditor obtains `rootScopeCommitment` and `executionLogDigest` from on-chain registry (both indexed by session nonce — `lastScopeCommitment` at chain seed and `delegationLogDigest` at current state).
2. The chain participant (or any relay) generates the `DelegationAuditRollup` PLONK proof with all intermediate state — including `logBlindingSalt` — as private witness.
3. Auditor verifies the single PLONK proof on-chain or off-chain. The auditor learns: the chain has `chainLength` hops, the terminal scope satisfies `auditPolicyMask`, the terminal expiry exceeds `minExpiry`, the chain links back to the handshake root, **and the proof covers exactly the hops that were executed on-chain** — nothing else.

### Journalist/source variant

For whistleblower-safe chains, the `rootScopeCommitment` can itself be hidden. An additional wrapper proves `rootScopeCommitment` is one of `K` known chain seeds (a small Merkle tree of recent handshake roots), revealing only the Merkle root of the handshake set. This adds one `BinaryMerkleRoot(depth)` gadget over the rootScopeCommitment as a leaf.

The `executionLogDigest` is a public input but does not reveal which handshake root seeded the chain: the digest is a hash chain starting from `Poseidon2(logBlindingSalt, rootScopeCommitment)`, and recovering `rootScopeCommitment` requires inverting Poseidon over an unknown two-argument preimage. Critically, the blinding salt `logBlindingSalt` is drawn uniformly from the ~254-bit BN128 scalar field and is known only to the chain initiator. Even if the auditor knows all `K` candidate `rootScopeCommitment` values and can read the on-chain `delegationLogDigest` (including its initial value from transaction history), they cannot test any candidate: computing `Poseidon2(?, rsc_i)` requires the salt, and brute-forcing a ~254-bit field element is computationally infeasible. The initial accumulator value is indistinguishable from a random field element to the auditor.

In the non-journalist (standard audit) case, the blinding salt provides no additional privacy burden: the `rootScopeCommitment` is already a public input, so the auditor does not need to recover it from the digest. The salt is simply an opaque private witness value that the circuit uses to match the on-chain accumulator.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary `A` controls:

- Up to `MAX_HOPS - 1` intermediate agents in the delegation chain (colluding)
- All public signals visible to the auditor
- The on-chain registry state (read access), **including historical storage values from transaction traces** (the adversary can observe the initial `delegationLogDigest` value written at handshake time)

The adversary does NOT control:

- The Poseidon hash function (modeled as a random oracle for collision resistance arguments)
- The PLONK proving system (knowledge soundness holds)
- The root delegator's secret key
- The `logBlindingSalt` chosen by the chain initiator (drawn uniformly from `F_p`, ~254 bits of entropy)
- The on-chain registry's write path (delegation log updates are executed by the registry contract atomically with each `verifyDelegation` call; the adversary cannot forge, skip, or reorder log entries without controlling the contract itself)

### Game: Audit Forgery Game

1. **Setup:** Challenger enrolls `n` agents in the agent Merkle tree with known credential commitments and scopes. Challenger creates a valid delegation chain of length `k` where hop `j` has `delegateeScope[j] = S_j` and `S_j ⊆ S_{j-1}` (monotonic narrowing holds). The chain initiator draws `logBlindingSalt` uniformly at random from `F_p` and provides `blindedLogSeed = Poseidon2(logBlindingSalt, rootScopeCommitment)` to the registry. The registry records `executionLogDigest` incrementally.

2. **Challenge:** Adversary `A` is given `rootScopeCommitment`, `terminalScopeCommitment`, `chainLength`, `auditPolicyMask`, `executionLogDigest`, and the PLONK verification key.

3. **Win condition (forgery):** `A` produces a valid `DelegationAuditRollup` proof where EITHER:
   - (a) **Narrowing violation:** There exists some hop `i` in the witness where `delegateeScope[i] ⊄ delegatorScope[i]` (a bit is set in delegatee but not in delegator), OR
   - (b) **Chain break:** The witness scope commitments do not form a linked chain back to `rootScopeCommitment`, OR
   - (c) **Policy evasion:** The terminal scope does not satisfy `auditPolicyMask` but the proof verifies.

4. **Win condition (incompleteness):** `A` produces a valid proof whose witness contains a strict subsequence of the actual delegation hops — i.e., the `chainLength` in the proof is less than the number of hops recorded in the on-chain execution log, or the witness substitutes different hops than those executed.

5. **Win condition (deanonymization):** `A`, acting as auditor, outputs any intermediate `delegatorScope[i]`, `delegateeScope[i]`, or `credentialCommitment[i]` for `0 < i < chainLength - 1`.

6. **Win condition (chain identification — journalist variant):** `A`, acting as auditor in the journalist variant, is given `K` candidate `rootScopeCommitment` values (one of which is the true chain seed) and the on-chain `delegationLogDigest` (including its initial value from transaction history). `A` outputs the index of the true `rootScopeCommitment` with probability greater than `1/K + negl(λ)`.

**Security goal:** No PPT adversary wins any condition with non-negligible advantage.

### Why the blinding salt is necessary for condition 6

Without the blinding salt (i.e., with the prior construction's `logAcc[0] = Poseidon2(0, rootScopeCommitment)`), the initial `delegationLogDigest` value is a deterministic function of `rootScopeCommitment` with a known constant. An adversary with read access to on-chain storage history can compute `Poseidon2(0, rsc_i)` for each of the `K` candidates in O(K) time and compare against the stored initial digest, trivially winning condition 6 with probability 1. The blinding salt makes the initial digest computationally indistinguishable from random, reducing the adversary's advantage to `negl(λ)` under the PRF assumption on Poseidon (implied by CR-Poseidon in the random oracle model).

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon collision resistance (CR-Poseidon):** No PPT adversary can find `(x, x')` with `x ≠ x'` such that `Poseidon(x) = Poseidon(x')`, over the BN128 scalar field.
2. **Poseidon second-preimage resistance (SPR-Poseidon):** Given `y = Poseidon(x)`, no PPT adversary can find `x' ≠ x` such that `Poseidon(x') = y`. (Implied by CR-Poseidon but stated separately for the log-binding argument.)
3. **Poseidon pseudorandomness (PRF-Poseidon):** `Poseidon2(r, ·)` is indistinguishable from a random function when `r` is drawn uniformly from `F_p`. This follows from modeling Poseidon as a random oracle over the BN128 scalar field; it is the standard assumption used in Semaphore's nullifier unlinkability argument.
4. **Knowledge soundness of PLONK (KS-PLONK):** For any valid proof, there exists an extractor that recovers a satisfying witness with overwhelming probability (in the algebraic group model + random oracle model).
5. **Zero-knowledge of PLONK (ZK-PLONK):** The proof reveals nothing about the witness beyond the public signals (simulation-based ZK in the ROM).

### Reduction sketch

**Theorem (Audit soundness):** If `A` wins the Audit Forgery Game (forgery variant) with advantage `ε`, then either (a) CR-Poseidon is broken with advantage `≥ ε/MAX_HOPS`, or (b) KS-PLONK is broken with advantage `≥ ε`.

**Proof sketch:**

- By KS-PLONK, extract witness `w = {delegatorScope[i], delegateeScope[i], delegatorCredCommitment[i], delegateeCredCommitment[i], logBlindingSalt}` for all hops from any valid proof.
- **Narrowing violation (win-a):** The circuit enforces `delegateeBits[i][j] * (1 - delegatorBits[i][j]) === 0` for all `j`. A satisfying witness with `delegateeScope[i] ⊄ delegatorScope[i]` violates this constraint. By KS-PLONK, no valid proof exists for an unsatisfying witness.
- **Chain break (win-b):** Suppose the extracted witness has `Poseidon2(delegatorScope[i], delegatorCredCommitment[i]) ≠ Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])` for some `i`, yet the circuit accepts. The circuit constrains these to be equal. If both sides produce the same output from different preimages, we have a Poseidon collision — contradicting CR-Poseidon.
- **Policy evasion (win-c):** Same argument as narrowing violation — the terminal policy check is an explicit circuit constraint.

**Theorem (Audit completeness):** If `A` wins the incompleteness condition (win condition 4) with advantage `ε`, then either (a) CR-Poseidon is broken with advantage `≥ ε`, or (b) KS-PLONK is broken with advantage `≥ ε`.

**Proof sketch:**

- By KS-PLONK, extract the witness including `logBlindingSalt`. The circuit computes `logAcc[0] = Poseidon2(logBlindingSalt, rootScopeCommitment)` and then a running Poseidon2 hash chain over the witness's scope commitments, constraining the final value (at index `chainLength`) to equal `executionLogDigest`.
- The on-chain `executionLogDigest` was computed as `Poseidon2(... Poseidon2(Poseidon2(blindedLogSeed, sc_0), sc_1) ..., sc_{k-1})` where `blindedLogSeed = Poseidon2(logBlindingSalt, rootScopeCommitment)`.
- **Hop omission:** If the witness contains fewer hops than `k`, the in-circuit hash chain has fewer Poseidon2 applications. Producing the same digest from a shorter chain requires finding a second preimage of the intermediate accumulator state — contradicting SPR-Poseidon (which follows from CR-Poseidon).
- **Hop substitution:** If the witness substitutes a different scope commitment at some hop `i` (i.e., `sc'_i ≠ sc_i`), then `Poseidon2(logAcc[i], sc'_i) = Poseidon2(logAcc[i], sc_i)` must hold for the hash chains to converge, which is a Poseidon collision — contradicting CR-Poseidon. If the chains diverge at hop `i`, they must re-converge at some later hop `j` by the same collision argument.
- **Hop reordering:** Poseidon2 is not commutative in general. Reordering scope commitments produces a different hash chain value. Matching the on-chain digest from a reordered chain requires a Poseidon collision.
- **Salt mismatch:** If the prover uses a `logBlindingSalt'` ≠ `logBlindingSalt` (the actual salt used at handshake time), then `Poseidon2(logBlindingSalt', rootScopeCommitment) ≠ Poseidon2(logBlindingSalt, rootScopeCommitment)` (unless Poseidon has a collision), and the hash chain diverges at the first step. Re-convergence requires a Poseidon collision at a later step.

Therefore, the proof covers exactly the hops recorded on-chain, in the order they were recorded, using the same blinding salt the initiator committed to.

**Theorem (Audit privacy):** No PPT auditor can recover intermediate scopes or credential commitments from the proof and public signals, assuming ZK-PLONK and CR-Poseidon.

**Proof sketch:** By ZK-PLONK, there exists a simulator `S` that produces proofs indistinguishable from real proofs given only the public signals. The `logBlindingSalt` is a private witness element; `executionLogDigest` is a Poseidon hash chain seeded with `Poseidon2(logBlindingSalt, rootScopeCommitment)` — recovering either the salt or individual scope commitments from the digest requires inverting Poseidon (contradicting CR-Poseidon as a one-way function). Since all intermediate values are private witness elements not derivable from any public signal, `S` need not know them.

**Theorem (Chain identification resistance — journalist variant):** No PPT adversary wins condition 6 with advantage greater than `negl(λ)`, assuming PRF-Poseidon.

**Proof sketch:**

- The adversary observes the initial `delegationLogDigest` value `d_0 = Poseidon2(logBlindingSalt, rootScopeCommitment)` from on-chain storage history, and knows all `K` candidate `rootScopeCommitment` values `{rsc_1, ..., rsc_K}`.
- To identify the true `rsc_j`, the adversary must distinguish `Poseidon2(r, rsc_j)` from `Poseidon2(r, rsc_i)` for `i ≠ j`, where `r = logBlindingSalt` is unknown and drawn uniformly from `F_p`.
- By PRF-Poseidon, `Poseidon2(r, ·)` is computationally indistinguishable from a random function when `r` is uniform. Therefore `d_0 = Poseidon2(r, rsc_j)` is indistinguishable from a uniformly random field element, independent of `rsc_j`. The adversary's advantage in guessing `j` is at most `negl(λ)`.
- The subsequent digest values `d_1, d_2, ...` are computed as `Poseidon2(d_{i-1}, sc_i)` where `sc_i` are scope commitments that are also visible on-chain (as `lastScopeCommitment` updates). However, since `d_0` is pseudorandom, `d_1 = Poseidon2(d_0, sc_1)` is also pseudorandom (by a hybrid argument over Poseidon's PRF property), and this propagates through the chain. No intermediate or final digest value leaks information about which `rsc_j` seeded the chain.

**Comparison to prior construction:** In the prior construction, `d_0 = Poseidon2(0, rsc_j)` with a known constant `0`. The adversary computes `Poseidon2(0, rsc_i)` for all `K` candidates and matches against `d_0`, winning condition 6 with probability 1. The blinding salt eliminates this attack.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Identity-Bound Scope Commitment Chain |
| Chain linking | Scope commitment equality across hops | Delegation circuit constraint 2 |
| Scope narrowing | Bitwise subset via `delegateeBits[j] * (1 - delegatorBits[j]) === 0` | Delegation circuit constraint 3 |
| Cumulative bit encoding | Financial tier implication (bits 2-3-4) | AgentPolicy constraint 6, Delegation constraint 4 |
| Permission bitmask | 8-bit (spec) / 64-bit (circuit-level) cumulative encoding | §Permissions Model |
| Expiry narrowing | `LessEqThan(64)` | Delegation circuit constraint 5 |
| Proving system | PLONK with universal setup (no per-audit-circuit ceremony) | §Proving Systems — OPTIONAL for Delegation |
| Root scope commitment | Stored on-chain by registry at handshake | §4: `lastScopeCommitment` mapping |
| Execution log digest | `Poseidon2` hash chain over scope commitments, stored on-chain | Extension to registry's `verifyDelegation` write path |
| Log blinding salt | Private random field element, seeds the log accumulator via `Poseidon2(salt, rootScopeCommitment)` | New: provided by initiator at handshake, kept private for journalist variant |
| Session nonce | Public input binding proof to session | All circuits |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | §Agent Proof Specification |

The `DelegationAuditRollup` composes existing Bolyra delegation constraints without introducing new cryptographic primitives. The `logBlindingSalt` is a standard random field element — not a new primitive — used as an input to the already-specified `Poseidon2`. It reuses Poseidon2, Poseidon3, Num2Bits(64), LessEqThan(64), and the cumulative bit encoding — all already specified and implemented in the Delegation circuit. The on-chain storage extension adds one `uint256` per session (one storage slot), updated with a single Poseidon2 call per hop. The only registry interface change is that `verifyHandshake` accepts an additional `uint256 blindedLogSeed` argument instead of computing the initial digest internally.

## 6. Circuit cost estimate

**Parameters:** `MAX_HOPS = 8`, 64-bit scope bitmasks.

| Component | Constraints per hop | Total (8 hops) |
|-----------|-------------------|----------------|
| `Num2Bits(64)` × 4 (delegator/delegatee scope + expiries) | 256 | 2,048 |
| `Poseidon2` × 2 (chain link + new scope commitment) | ~500 | 4,000 |
| Scope narrowing (64 multiplication constraints) | 64 | 512 |
| Cumulative bit encoding (3 constraints) | 3 | 24 |
| `LessEqThan(64)` for expiry | ~130 | 1,040 |
| Hop activation (Mux1 gating per constraint set) | ~50 | 400 |
| `Poseidon2` × 1 (execution log accumulator per hop) | ~250 | 2,000 |
| Mux1 for log accumulator active/pass-through | ~3 | 24 |
| Terminal policy check (64 constraints) | — | 64 |
| `Poseidon3` audit digest | — | ~375 |
| `LessThan` for chainLength validation | — | ~20 |
| `QuinSelector` for final logAcc selection | — | ~27 |
| Equality check: logAcc[chainLength] === executionLogDigest | — | 1 |
| **Total** | | **~10,535** |

**Note on blinding salt cost:** The `logBlindingSalt` replaces the constant `0` as the first argument to the initial `Poseidon2(logBlindingSalt, rootScopeCommitment)` call. This is the same Poseidon2 invocation already counted in the log accumulator line — `logAcc[0]` computation. Replacing a constant with a private input adds zero constraints (the Poseidon2 gadget processes both cases identically). Total constraint count is unchanged from the prior construction.

**Proving time target:** PLONK agent-class, **< 5 seconds** (snarkjs PLONK on ~10,500 constraints completes in ~2.5s on commodity hardware; rapidsnark native < 0.7s). Well within the 2^16 constraint ceiling of `pot16.ptau`.

**On-chain cost of log maintenance:** One additional `Poseidon2` precompile call (or Solidity implementation) plus one `SSTORE` update per delegation hop. The `SSTORE` is a warm update (same slot, already written at handshake time), costing ~5,000 gas. The Poseidon2 computation costs ~25,000 gas in Solidity (or ~2,000 gas via a precompile on L2s like Base). Total overhead per hop: **~30,000 gas** — negligible relative to the existing delegation verification cost (~230,000 gas for proof verification). The handshake cost is unchanged: the registry stores the caller-provided `blindedLogSeed` directly (one `SSTORE`, ~22,000 gas cold) instead of computing `Poseidon2(0, rootScopeCommitment)` (~25,000 gas) — a net savings of ~3,000 gas at the handshake step.

**Verification:** Single PLONK proof verification: ~3ms off-chain, ~230K gas on-chain (BN128 pairing). Unchanged — the blinding salt adds no verification overhead (it is a private witness value, not a public signal).

**Journalist/source variant adds:** One `BinaryMerkleRoot(depth=10)` gadget (~2,500 constraints) for root anonymity set membership. Total: ~13,000 constraints, still < 5s PLONK.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder:** Navy Federal Credit Union (NFCU), the largest US credit union ($175B assets, 14M members), subject to NCUA examination and GENIUS Act stablecoin compliance.

**Pipeline:** A member initiates a stablecoin transfer via an AI assistant. The pipeline involves four agents:

| Hop | Agent | Delegated scope | Tool call |
|-----|-------|-----------------|-----------|
| 0 (root) | Member's personal AI assistant | `READ_DATA + WRITE_DATA + FINANCIAL_SMALL` (bits 0,1,2) | "Transfer $50 USDC to my savings" |
| 1 | NFCU routing agent | `READ_DATA + FINANCIAL_SMALL` (bits 0,2) | Queries member's account balance |
| 2 | AML/KYC compliance agent (third-party: Chainalysis) | `READ_DATA` (bit 0) | Screens the destination address |
| 3 | Settlement agent (cross-org: Circle) | `FINANCIAL_SMALL` (bit 2) | Executes the on-chain transfer |

**Audit requirement:** The NCUA examiner must verify:
1. Each hop in the pipeline narrowed permissions (no agent exceeded its mandate).
2. The terminal agent had `FINANCIAL_SMALL` authority.
3. **All hops are accounted for** — no intermediate hop was omitted from the proof (the examiner can compare `chainLength` in the proof against the expected pipeline depth, and the `executionLogDigest` guarantees the proof covers exactly what happened on-chain).
4. No intermediate scopes or agent identities are disclosed to the examiner (competitive sensitivity: NFCU does not want the examiner to learn that Chainalysis is their AML provider, or that Circle handles settlement).

**Flow:**

1. The member's AI assistant completes the handshake with NFCU's routing agent. The assistant draws a random blinding salt `r` and computes `blindedLogSeed = Poseidon2(r, rootScopeCommitment)` locally. The handshake transaction provides `blindedLogSeed` to the registry. The registry stores `rootScopeCommitment` (from the agent proof's public output) and `delegationLogDigest[nonce] = blindedLogSeed`. The assistant retains `r` for later audit proof generation.
2. Three delegation hops execute, each producing a per-hop Delegation proof (already in Bolyra spec). At each hop, the registry atomically updates `delegationLogDigest[nonce] = Poseidon2(prev, newScopeCommitment)`.
3. After the pipeline completes, any participant who knows `r` (or receives it from the initiator via a secure channel) generates a `DelegationAuditRollup` PLONK proof with all four hops' scope/credential data and `logBlindingSalt = r` as private witness.
4. The NCUA examiner reads `rootScopeCommitment` and `executionLogDigest` from the on-chain registry (both indexed by session nonce). They verify the single PLONK proof. They learn: chain has 4 hops, terminal scope includes `FINANCIAL_SMALL`, the chain links to a valid handshake root, monotonic narrowing held at every hop, **and the proof covers exactly the 4 hops that were recorded on-chain** (no synthetic shortcut chain). They learn nothing about which agents participated or what intermediate scopes were.

**Journalist/source variant with blinded seed:** A journalist directs an AI research agent through a source's anonymizing relay chain. The journalist's agent generates `r` at handshake time and provides `blindedLogSeed` to the registry. When the source's chain completes and an audit is requested, the audit proof hides `rootScopeCommitment` via Merkle membership over K recent handshake roots. The auditor reads `executionLogDigest` from the on-chain registry but cannot determine which of the K handshakes it corresponds to: the initial digest value `Poseidon2(r, rootScopeCommitment)` is indistinguishable from random without knowing `r`. Even with full blockchain history access, the auditor's advantage in identifying the true chain seed is negligible.

**Why this matters beyond regulatory niches:**
- The same proof works for a journalist directing an AI research agent through a source's agent chain — the blinded log seed ensures the on-chain footprint does not reveal which journalist-source relationship is being audited.
- The same proof works for a healthcare org auditing an AI referral chain across providers under HIPAA — the auditor confirms scope narrowing without learning which specialists or facilities were involved.
- The `auditPolicyMask` is caller-defined, not regulator-specific — any verifier can set the bar.

## 8. Why the baseline cannot match

| Bolyra DelegationAuditRollup capability | Best baseline attempt | Why it fails |
|-----------------------------------------|----------------------|--------------|
| **Prove monotonic narrowing over hidden scopes** | BBS+ selective disclosure on per-hop VCs | BBS+ can hide individual claim values but cannot prove an ordering relationship (`scope_n ⊆ scope_{n-1}`) over hidden bitmasks. There is no BBS+ predicate for bitwise subset containment. The auditor must either see the scope values or trust an AS assertion. The rollup circuit enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` over private witness values — the auditor never sees the bits. |
| **Hide all intermediate participants** | RFC 8693 `act` claim tree + BBS+ selective disclosure | The `act` chain is a chain of credentials from different issuers. BBS+ operates within a single multi-message signature from one issuer. There is no standard mechanism to selectively disclose "hop 3 existed" without revealing the `sub` claim at hop 3. The rollup circuit's private witness contains all `credentialCommitment[i]` values; the auditor sees only `rootScopeCommitment` and `terminalScopeCommitment`. |
| **Verify without a trusted Authorization Server** | RFC 8693 narrowing is AS-enforced at issuance | If the AS is compromised, colluding, or simply unavailable, the auditor has no independent verification. The rollup proof is self-contained: the PLONK verification key and the on-chain `rootScopeCommitment` are sufficient. No AS is in the trust path. |
| **Single artifact for cross-org chains** | WIMSE federation + per-org AS coordination | Cross-org delegation (NFCU → Chainalysis → Circle) requires either a shared AS or bilateral federation agreements. Each org's AS sees and logs the scopes traversing its domain. The rollup proof is a single artifact: one PLONK proof covers the entire cross-org chain. No federation infrastructure required. No org sees another org's internal scopes. |
| **Journalist/source anonymity with unlinkable on-chain footprint** | OIDC Pairwise Subject Identifiers (PPIDs) | PPIDs prevent RS-vs-RS correlation on `sub` but the AS and auditor still see the `act` chain. WIMSE SPIFFE IDs are stable identifiers visible to any verifier. The rollup's journalist variant hides `rootScopeCommitment` behind a Merkle membership proof, and the blinded log seed (`Poseidon2(logBlindingSalt, rootScopeCommitment)`) prevents the auditor from correlating the on-chain `executionLogDigest` against candidate handshake roots — even with full blockchain history access and knowledge of all K candidate roots. The baseline has no mechanism for blinding an audit trail's provenance against enumeration over a known candidate set. |
| **In-circuit enforcement at verification time** | AS enforces at issuance; RS enforces at presentation (separate systems) | The baseline splits enforcement across issuance-time (AS) and presentation-time (RS), with no cryptographic binding between them. A token issued with narrowed scope can be presented to a permissive RS that ignores scope. The rollup circuit binds narrowing enforcement to the proof itself — verification fails if any hop violated the subset constraint, regardless of what any RS accepts. |
| **Constant-size audit artifact regardless of chain length** | Audit artifact grows linearly with hops (nested `act` claims, per-hop VCs, per-hop WIMSE SVIDs) | An 8-hop RFC 8693 chain produces 8 nested tokens, 8 BBS+ derived proofs, and 8 WIMSE SVIDs. The rollup produces a single PLONK proof (~800 bytes) regardless of whether the chain has 1 hop or 8. |
| **Audit completeness without revealing chain contents** | AS-maintained audit log (RFC 7662 introspection + signed JWT introspection responses) | The baseline can log each delegation event at the AS and present signed introspection responses as evidence of completeness. But the auditor must *read* those responses to verify completeness — each response contains the scope, participant identity, and timestamp of that hop. There is no mechanism to prove "the audit covers all logged events" without disclosing the events themselves. The rollup binds to an on-chain Poseidon hash chain (`executionLogDigest`) seeded with a blinded initial value, committing to every hop's scope commitment without revealing any individual commitment or the chain's provenance. The circuit reproduces this hash chain from private witness data (including the blinding salt) and constrains equality with the on-chain value. The auditor verifies completeness by checking one public input against one on-chain value — learning nothing about what the log contains or which handshake initiated it. |

The fundamental gap: the baseline's privacy tools (BBS+ selective disclosure) operate on claim values within a single credential, while the audit problem requires proving a relational property (bitwise subset) across a chain of credentials from different issuers — all while hiding the chain's contents and provenance. The completeness gap compounds this: the baseline cannot even prove that a privacy-preserving audit covers all events without revealing those events. The blinded `executionLogDigest` is a hash-chain commitment with an unlinkable seed that the baseline has no analogue for — RFC 7662 introspection responses are readable or they are useless, and no amount of selective disclosure can hide which audit trail is being verified when the trail's on-chain footprint is deterministically linkable to its origin.
