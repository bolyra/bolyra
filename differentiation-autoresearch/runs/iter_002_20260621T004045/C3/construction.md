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

**Update rule (in the existing `verifyDelegation` function):**

- After handshake (hop 0 seed): `delegationLogDigest[nonce] = Poseidon2(0, rootScopeCommitment)`
- After each delegation hop that writes `newScopeCommitment`: `delegationLogDigest[nonce] = Poseidon2(delegationLogDigest[nonce], newScopeCommitment)`

This is a single Poseidon2 hash appended to an existing on-chain write path — no additional storage slots per hop, no new events, no log array. The digest is a running hash accumulator: append-only, O(1) storage.

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

11. **Execution log completeness (NEW):** The circuit computes a running hash accumulator over scope commitments derived from the witness, then constrains it against the public input `executionLogDigest`:

    ```
    logAcc[0] = Poseidon2(0, rootScopeCommitment)
    for i in [0, MAX_HOPS):
      scopeComm[i] = Poseidon2(delegateeScope[i], delegateeCredCommitment[i])
      logAcc[i+1] = active[i] ? Poseidon2(logAcc[i], scopeComm[i]) : logAcc[i]
    logAcc[chainLength] === executionLogDigest
    ```

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
2. The chain participant (or any relay) generates the `DelegationAuditRollup` PLONK proof with all intermediate state as private witness.
3. Auditor verifies the single PLONK proof on-chain or off-chain. The auditor learns: the chain has `chainLength` hops, the terminal scope satisfies `auditPolicyMask`, the terminal expiry exceeds `minExpiry`, the chain links back to the handshake root, **and the proof covers exactly the hops that were executed on-chain** — nothing else.

### Journalist/source variant

For whistleblower-safe chains, the `rootScopeCommitment` can itself be hidden. An additional wrapper proves `rootScopeCommitment` is one of `K` known chain seeds (a small Merkle tree of recent handshake roots), revealing only the Merkle root of the handshake set. This adds one `BinaryMerkleRoot(depth)` gadget over the rootScopeCommitment as a leaf. The `executionLogDigest` is still a public input — it does not reveal which handshake root seeded the chain (the digest is a hash chain starting from `Poseidon2(0, rootScopeCommitment)`, and recovering `rootScopeCommitment` from the digest requires inverting Poseidon). The auditor learns "a valid chain existed, covered all its on-chain hops, and narrowed monotonically" without learning which handshake initiated it.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary `A` controls:

- Up to `MAX_HOPS - 1` intermediate agents in the delegation chain (colluding)
- All public signals visible to the auditor
- The on-chain registry state (read access)

The adversary does NOT control:

- The Poseidon hash function (modeled as a random oracle for collision resistance arguments)
- The PLONK proving system (knowledge soundness holds)
- The root delegator's secret key
- The on-chain registry's write path (delegation log updates are executed by the registry contract atomically with each `verifyDelegation` call; the adversary cannot forge, skip, or reorder log entries without controlling the contract itself)

### Game: Audit Forgery Game

1. **Setup:** Challenger enrolls `n` agents in the agent Merkle tree with known credential commitments and scopes. Challenger creates a valid delegation chain of length `k` where hop `j` has `delegateeScope[j] = S_j` and `S_j ⊆ S_{j-1}` (monotonic narrowing holds). The registry records `executionLogDigest` incrementally.

2. **Challenge:** Adversary `A` is given `rootScopeCommitment`, `terminalScopeCommitment`, `chainLength`, `auditPolicyMask`, `executionLogDigest`, and the PLONK verification key.

3. **Win condition (forgery):** `A` produces a valid `DelegationAuditRollup` proof where EITHER:
   - (a) **Narrowing violation:** There exists some hop `i` in the witness where `delegateeScope[i] ⊄ delegatorScope[i]` (a bit is set in delegatee but not in delegator), OR
   - (b) **Chain break:** The witness scope commitments do not form a linked chain back to `rootScopeCommitment`, OR
   - (c) **Policy evasion:** The terminal scope does not satisfy `auditPolicyMask` but the proof verifies.

4. **Win condition (incompleteness):** `A` produces a valid proof whose witness contains a strict subsequence of the actual delegation hops — i.e., the `chainLength` in the proof is less than the number of hops recorded in the on-chain execution log, or the witness substitutes different hops than those executed.

5. **Win condition (deanonymization):** `A`, acting as auditor, outputs any intermediate `delegatorScope[i]`, `delegateeScope[i]`, or `credentialCommitment[i]` for `0 < i < chainLength - 1`.

**Security goal:** No PPT adversary wins with non-negligible advantage.

### Why incompleteness matters

Without the execution log binding, a colluding prover could construct a *synthetic* chain: fabricate a shorter chain from `rootScopeCommitment` to `terminalScopeCommitment` that monotonically narrows, while the *actual* chain contained a hop that violated narrowing (e.g., a rogue agent escalated permissions mid-chain, then a later hop re-narrowed). The synthetic chain would satisfy all scope-linking and narrowing constraints but would not reflect what actually happened. The `executionLogDigest` binding closes this gap: the prover must reproduce the exact hash chain the registry recorded, so any omission or substitution causes a constraint failure.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon collision resistance (CR-Poseidon):** No PPT adversary can find `(x, x')` with `x ≠ x'` such that `Poseidon(x) = Poseidon(x')`, over the BN128 scalar field.
2. **Poseidon second-preimage resistance (SPR-Poseidon):** Given `y = Poseidon(x)`, no PPT adversary can find `x' ≠ x` such that `Poseidon(x') = y`. (Implied by CR-Poseidon but stated separately for the log-binding argument.)
3. **Knowledge soundness of PLONK (KS-PLONK):** For any valid proof, there exists an extractor that recovers a satisfying witness with overwhelming probability (in the algebraic group model + random oracle model).
4. **Zero-knowledge of PLONK (ZK-PLONK):** The proof reveals nothing about the witness beyond the public signals (simulation-based ZK in the ROM).

### Reduction sketch

**Theorem (Audit soundness):** If `A` wins the Audit Forgery Game (forgery variant) with advantage `ε`, then either (a) CR-Poseidon is broken with advantage `≥ ε/MAX_HOPS`, or (b) KS-PLONK is broken with advantage `≥ ε`.

**Proof sketch:**

- By KS-PLONK, extract witness `w = {delegatorScope[i], delegateeScope[i], delegatorCredCommitment[i], delegateeCredCommitment[i]}` for all hops from any valid proof.
- **Narrowing violation (win-a):** The circuit enforces `delegateeBits[i][j] * (1 - delegatorBits[i][j]) === 0` for all `j`. A satisfying witness with `delegateeScope[i] ⊄ delegatorScope[i]` violates this constraint. By KS-PLONK, no valid proof exists for an unsatisfying witness.
- **Chain break (win-b):** Suppose the extracted witness has `Poseidon2(delegatorScope[i], delegatorCredCommitment[i]) ≠ Poseidon2(delegateeScope[i-1], delegateeCredCommitment[i-1])` for some `i`, yet the circuit accepts. The circuit constrains these to be equal. If both sides produce the same output from different preimages, we have a Poseidon collision — contradicting CR-Poseidon.
- **Policy evasion (win-c):** Same argument as narrowing violation — the terminal policy check is an explicit circuit constraint.

**Theorem (Audit completeness):** If `A` wins the incompleteness condition (win condition 4) with advantage `ε`, then either (a) CR-Poseidon is broken with advantage `≥ ε`, or (b) KS-PLONK is broken with advantage `≥ ε`.

**Proof sketch:**

- By KS-PLONK, extract the witness. The circuit computes `logAcc` as a Poseidon2 hash chain over the witness's scope commitments and constrains the final value (at index `chainLength`) to equal `executionLogDigest`.
- The on-chain `executionLogDigest` was computed as `Poseidon2(... Poseidon2(Poseidon2(0, sc_0), sc_1) ..., sc_{k-1})` over the `k` actual scope commitments `sc_0, ..., sc_{k-1}`.
- **Hop omission:** If the witness contains fewer hops than `k`, the in-circuit hash chain has fewer Poseidon2 applications. Producing the same digest from a shorter chain requires finding a second preimage of the intermediate accumulator state — contradicting SPR-Poseidon (which follows from CR-Poseidon).
- **Hop substitution:** If the witness substitutes a different scope commitment at some hop `i` (i.e., `sc'_i ≠ sc_i`), then `Poseidon2(logAcc[i], sc'_i) = Poseidon2(logAcc[i], sc_i)` must hold for the hash chains to converge, which is a Poseidon collision — contradicting CR-Poseidon. If the chains diverge at hop `i`, they must re-converge at some later hop `j` by the same collision argument.
- **Hop reordering:** Poseidon2 is not commutative in general. Reordering scope commitments produces a different hash chain value. Matching the on-chain digest from a reordered chain requires a Poseidon collision.

Therefore, the proof covers exactly the hops recorded on-chain, in the order they were recorded.

**Theorem (Audit privacy):** No PPT auditor can recover intermediate scopes or credential commitments from the proof and public signals, assuming ZK-PLONK.

**Proof sketch:** By ZK-PLONK, there exists a simulator `S` that produces proofs indistinguishable from real proofs given only the public signals. The new public input `executionLogDigest` is a Poseidon hash chain — recovering individual scope commitments from it requires inverting Poseidon (contradicting CR-Poseidon as a one-way function), so `executionLogDigest` does not leak intermediate state. Since intermediate scopes and credential commitments are private witness elements not derivable from any public signal, `S` need not know them. Therefore, no auditor learns anything beyond the public signals.

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
| Execution log digest | `Poseidon2` hash chain over scope commitments, stored on-chain (NEW) | Extension to registry's `verifyDelegation` write path |
| Session nonce | Public input binding proof to session | All circuits |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | §Agent Proof Specification |

The `DelegationAuditRollup` composes existing Bolyra delegation constraints without introducing new cryptographic primitives. It reuses Poseidon2, Poseidon3, Num2Bits(64), LessEqThan(64), and the cumulative bit encoding — all already specified and implemented in the Delegation circuit. The execution log digest uses only Poseidon2, which is already a core primitive. The on-chain storage extension adds one `uint256` per session (one storage slot), updated with a single Poseidon2 call per hop — the same hash function the registry already uses for scope commitments.

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
| `Poseidon2` × 1 (execution log accumulator per hop) (NEW) | ~250 | 2,000 |
| Mux1 for log accumulator active/pass-through (NEW) | ~3 | 24 |
| Terminal policy check (64 constraints) | — | 64 |
| `Poseidon3` audit digest | — | ~375 |
| `LessThan` for chainLength validation | — | ~20 |
| `QuinSelector` for final logAcc selection (NEW) | — | ~27 |
| Equality check: logAcc[chainLength] === executionLogDigest (NEW) | — | 1 |
| **Total** | | **~10,535** |

**Proving time target:** PLONK agent-class, **< 5 seconds** (snarkjs PLONK on ~10,500 constraints completes in ~2.5s on commodity hardware; rapidsnark native < 0.7s). Well within the 2^16 constraint ceiling of `pot16.ptau`.

**On-chain cost of log maintenance:** One additional `Poseidon2` precompile call (or Solidity implementation) plus one `SSTORE` update per delegation hop. The `SSTORE` is a warm update (same slot, already written at handshake time), costing ~5,000 gas. The Poseidon2 computation costs ~25,000 gas in Solidity (or ~2,000 gas via a precompile on L2s like Base). Total overhead per hop: **~30,000 gas** — negligible relative to the existing delegation verification cost (~230,000 gas for proof verification).

**Verification:** Single PLONK proof verification: ~3ms off-chain, ~230K gas on-chain (BN128 pairing). Unchanged from prior construction — the log binding adds no verification overhead (it is a circuit constraint, not an additional on-chain check).

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

1. The member's AI assistant completes the handshake with NFCU's routing agent. The registry stores `rootScopeCommitment` and initializes `delegationLogDigest[nonce] = Poseidon2(0, rootScopeCommitment)`.
2. Three delegation hops execute, each producing a per-hop Delegation proof (already in Bolyra spec). At each hop, the registry atomically updates `delegationLogDigest[nonce] = Poseidon2(prev, newScopeCommitment)`.
3. After the pipeline completes, any participant (or a designated auditor relay) generates a `DelegationAuditRollup` PLONK proof with all four hops' scope/credential data as private witness.
4. The NCUA examiner reads `rootScopeCommitment` and `executionLogDigest` from the on-chain registry (both indexed by session nonce). They verify the single PLONK proof. They learn: chain has 4 hops, terminal scope includes `FINANCIAL_SMALL`, the chain links to a valid handshake root, monotonic narrowing held at every hop, **and the proof covers exactly the 4 hops that were recorded on-chain** (no synthetic shortcut chain). They learn nothing about which agents participated or what intermediate scopes were.

**Why audit completeness matters here:** Without the execution log binding, a colluding set of agents could construct a synthetic 2-hop chain (root → terminal) that narrows monotonically, hiding the fact that hop 2 (the Chainalysis agent) was actually granted `WRITE_DATA` in violation of policy before hop 3 re-narrowed. The `executionLogDigest` makes this impossible: the proof must account for all 4 scope commitments the registry recorded, in order.

**Why this matters beyond regulatory niches:**
- The same proof works for a journalist directing an AI research agent through a source's agent chain (journalist/source scenario) — swap NFCU for a news organization and Chainalysis for a whistleblower's anonymizing relay.
- The same proof works for a healthcare org auditing an AI referral chain across providers under HIPAA — the auditor confirms scope narrowing without learning which specialists or facilities were involved.
- The `auditPolicyMask` is caller-defined, not regulator-specific — any verifier can set the bar.

## 8. Why the baseline cannot match

| Bolyra DelegationAuditRollup capability | Best baseline attempt | Why it fails |
|-----------------------------------------|----------------------|--------------|
| **Prove monotonic narrowing over hidden scopes** | BBS+ selective disclosure on per-hop VCs | BBS+ can hide individual claim values but cannot prove an ordering relationship (`scope_n ⊆ scope_{n-1}`) over hidden bitmasks. There is no BBS+ predicate for bitwise subset containment. The auditor must either see the scope values or trust an AS assertion. The rollup circuit enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` over private witness values — the auditor never sees the bits. |
| **Hide all intermediate participants** | RFC 8693 `act` claim tree + BBS+ selective disclosure | The `act` chain is a chain of credentials from different issuers. BBS+ operates within a single multi-message signature from one issuer. There is no standard mechanism to selectively disclose "hop 3 existed" without revealing the `sub` claim at hop 3. The rollup circuit's private witness contains all `credentialCommitment[i]` values; the auditor sees only `rootScopeCommitment` and `terminalScopeCommitment`. |
| **Verify without a trusted Authorization Server** | RFC 8693 narrowing is AS-enforced at issuance | If the AS is compromised, colluding, or simply unavailable, the auditor has no independent verification. The rollup proof is self-contained: the PLONK verification key and the on-chain `rootScopeCommitment` are sufficient. No AS is in the trust path. |
| **Single artifact for cross-org chains** | WIMSE federation + per-org AS coordination | Cross-org delegation (NFCU → Chainalysis → Circle) requires either a shared AS or bilateral federation agreements. Each org's AS sees and logs the scopes traversing its domain. The rollup proof is a single artifact: one PLONK proof covers the entire cross-org chain. No federation infrastructure required. No org sees another org's internal scopes. |
| **Journalist/source anonymity** | OIDC Pairwise Subject Identifiers (PPIDs) | PPIDs prevent RS-vs-RS correlation on `sub` but the AS and auditor still see the `act` chain. WIMSE SPIFFE IDs are stable identifiers visible to any verifier. The rollup's journalist variant hides even the `rootScopeCommitment` behind a Merkle membership proof over a set of recent handshake roots — the auditor learns "a valid chain existed" without learning which handshake initiated it. |
| **In-circuit enforcement at verification time** | AS enforces at issuance; RS enforces at presentation (separate systems) | The baseline splits enforcement across issuance-time (AS) and presentation-time (RS), with no cryptographic binding between them. A token issued with narrowed scope can be presented to a permissive RS that ignores scope. The rollup circuit binds narrowing enforcement to the proof itself — verification fails if any hop violated the subset constraint, regardless of what any RS accepts. |
| **Constant-size audit artifact regardless of chain length** | Audit artifact grows linearly with hops (nested `act` claims, per-hop VCs, per-hop WIMSE SVIDs) | An 8-hop RFC 8693 chain produces 8 nested tokens, 8 BBS+ derived proofs, and 8 WIMSE SVIDs. The rollup produces a single PLONK proof (~800 bytes) regardless of whether the chain has 1 hop or 8. |
| **Audit completeness without revealing chain contents (NEW)** | AS-maintained audit log (RFC 7662 introspection + signed JWT introspection responses) | The baseline can log each delegation event at the AS and present signed introspection responses as evidence of completeness. But the auditor must *read* those responses to verify completeness — each response contains the scope, participant identity, and timestamp of that hop. There is no mechanism to prove "the audit covers all logged events" without disclosing the events themselves. The rollup binds to an on-chain Poseidon hash chain (`executionLogDigest`) that commits to every hop's scope commitment without revealing any individual commitment. The circuit reproduces this hash chain from private witness data and constrains equality with the on-chain value. The auditor verifies completeness by checking one public input against one on-chain value — learning nothing about what the log contains. |

The fundamental gap: the baseline's privacy tools (BBS+ selective disclosure) operate on claim values within a single credential, while the audit problem requires proving a relational property (bitwise subset) across a chain of credentials from different issuers — all while hiding the chain's contents. The completeness gap compounds this: the baseline cannot even prove that a privacy-preserving audit covers all events without revealing those events. The `executionLogDigest` binding is a hash-chain commitment that the baseline has no analogue for — RFC 7662 introspection responses are readable or they are useless.
