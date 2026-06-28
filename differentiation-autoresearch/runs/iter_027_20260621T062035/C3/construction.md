# Construction

## 1. Statement of claim

An auditor verifies that a delegation chain of length N narrowed permissions monotonically at every hop, that each hop involved an enrolled agent, and that the terminal scope satisfies an auditor-specified minimum policy — all without learning any intermediate scope values, participant identities, credential commitments, or Merkle roots. The construction generalizes beyond regulatory audit to multi-tool AI pipelines and journalist/source agent chains.

## 2. Construction (gadgets, circuits, public/private inputs)

### On-chain accumulator (registry extension)

The Bolyra on-chain registry already records `lastScopeCommitment` after each delegation hop. To bind the audit proof to the *actually executed* chain, the registry additionally maintains a **chain accumulator** — a running Poseidon hash chain over all scope commitments emitted during delegation:

```
chainAccumulator_0 = rootScopeCommitment   (set at handshake time)
chainAccumulator_{i+1} = Poseidon2(chainAccumulator_i, newScopeCommitment_{i+1})
```

The registry stores `chainAccumulator` alongside `lastScopeCommitment` in the delegation state mapping, indexed by session nonce. Each `delegateHop()` call atomically updates both values. The final `chainAccumulator_N` is publicly readable on-chain after the chain completes.

This costs one additional Poseidon2 evaluation per hop on-chain (precompile-friendly, ~5K gas on BN254) and one additional `uint256` storage slot per active session.

### Circuit: DelegationAuditChain(MAX_CHAIN_LEN, MAX_DEPTH)

A single PLONK circuit that re-derives and re-checks the entire delegation chain internally from private witness data, producing a compact auditor-facing proof.

**Private inputs:**

- `chainLength`: actual number of hops (≤ MAX_CHAIN_LEN)
- `scopes[MAX_CHAIN_LEN + 1]`: permission bitmasks at each position (index 0 = root delegator, index chainLength = terminal delegatee). Each is 64-bit.
- `credCommitments[MAX_CHAIN_LEN + 1]`: credential commitments at each position
- `expiries[MAX_CHAIN_LEN + 1]`: expiry timestamps at each position
- `delegateeMerkleProofs[MAX_CHAIN_LEN]`: Merkle inclusion proofs for each delegatee (siblings, index, length — padded to MAX_DEPTH)

**Public inputs:**

- `rootScopeCommitment`: the scope commitment produced by the initial handshake (on-chain, already public)
- `terminalScopeCommitment`: the final scope commitment after the last hop (on-chain, already public)
- `chainAccumulator`: the on-chain running hash over all scope commitments (new — addresses execution binding)
- `auditPolicyMask`: minimum permission bits the auditor requires the terminal agent to hold (64-bit)
- `auditTimestamp`: current time for expiry checks
- `sessionNonce`: binds the audit proof to a specific session/request
- `agentTreeRoot`: current agent Merkle root (or any root in the history buffer)

**Public outputs:**

- `chainLengthOut`: number of hops in the chain
- `auditNullifier`: Poseidon2(rootScopeCommitment, sessionNonce) — prevents duplicate audits per session
- `narrowingValid`: 1 if all hops narrowed monotonically and satisfied cumulative bit encoding, 0 otherwise (always 1 for a valid proof; the circuit is unsatisfiable if narrowing fails)

**Constraints (enforced in-circuit):**

1. **Range checks:** Num2Bits(64) on each `scopes[i]`, `expiries[i]`. Num2Bits(log2(MAX_CHAIN_LEN)) on `chainLength`.

2. **Root scope commitment linkage:** `Poseidon2(scopes[0], credCommitments[0]) === rootScopeCommitment`. Binds the private chain to the on-chain handshake output.

3. **Terminal scope commitment linkage:** `Poseidon2(scopes[chainLength], credCommitments[chainLength]) === terminalScopeCommitment`. Binds the private chain to the on-chain final state.

4. **Per-hop scope narrowing (for i in 0..MAX_CHAIN_LEN-1, gated on i < chainLength):**
   - Bit-decompose `scopes[i]` and `scopes[i+1]` via Num2Bits(64).
   - For each bit j in [0, 64): `scopeBits[i+1][j] * (1 - scopeBits[i][j]) === 0`. (Delegatee bit set implies delegator bit set.)
   
5. **Per-hop cumulative bit encoding (gated on i < chainLength):**
   - `scopeBits[i+1][4] * (1 - scopeBits[i+1][3]) === 0`
   - `scopeBits[i+1][4] * (1 - scopeBits[i+1][2]) === 0`
   - `scopeBits[i+1][3] * (1 - scopeBits[i+1][2]) === 0`

6. **Per-hop scope commitment chain linking (for i in 0..MAX_CHAIN_LEN-1, gated on i < chainLength):**
   - `Poseidon2(scopes[i], credCommitments[i])` feeds forward as `previousScopeCommitment` for hop i.
   - `Poseidon2(scopes[i+1], credCommitments[i+1])` must equal the `newScopeCommitment` at hop i.
   - This mirrors the on-chain lastScopeCommitment chain but is verified entirely in-circuit from private data.

7. **Per-hop expiry narrowing (gated on i < chainLength):**
   - `LessEqThan(64)(expiries[i+1], expiries[i])`. Delegatee expiry ≤ delegator expiry.

8. **Terminal expiry validity:** `LessThan(64)(auditTimestamp, expiries[chainLength])`. The terminal credential has not expired.

9. **Per-hop delegatee enrollment (gated on i < chainLength):**
   - `BinaryMerkleRoot(MAX_DEPTH)(credCommitments[i+1], delegateeMerkleProofs[i])` must match `agentTreeRoot`. Proves each delegatee is enrolled without revealing which leaf.

10. **Audit policy satisfaction:** For each bit j in [0, 64): `auditPolicyBits[j] * (1 - terminalScopeBits[j]) === 0`. The terminal scope includes all bits required by the auditor's policy.

11. **Audit nullifier:** `auditNullifier = Poseidon2(rootScopeCommitment, sessionNonce)`.

12. **Execution binding via chain accumulator (new constraint):**
    - Compute `acc_0 = rootScopeCommitment` (already constrained by constraint 2 to match the on-chain value).
    - For i in 0..MAX_CHAIN_LEN-1, gated on i < chainLength:
      - `sc_{i+1} = Poseidon2(scopes[i+1], credCommitments[i+1])` (reuses the scope commitment already computed in constraint 6).
      - `acc_{i+1} = Poseidon2(acc_i, sc_{i+1})`.
    - For i ≥ chainLength: `acc_{i+1} = acc_i` (identity — inactive hops do not modify the accumulator).
    - Final check: `acc_{chainLength} === chainAccumulator` (the public input read from on-chain state).

    This constraint ensures the private witness chain is *the* chain that was recorded on-chain hop-by-hop, not merely *a* chain consistent with the root and terminal commitments.

13. **Inactive hop gating:** For indices i ≥ chainLength, all constraints are multiplexed to trivially satisfied form (multiply constraint by `isActive[i]` selector signal, where `isActive[i] = (i < chainLength)` computed via LessThan).

### Gadget inventory

| Gadget | Uses per proof | Source |
|---|---|---|
| Poseidon2 (scope commitments) | 2·(MAX_CHAIN_LEN+1) (chain-link pairs, reused by accumulator) | circomlib |
| Poseidon2 (chain accumulator) | MAX_CHAIN_LEN (one fold per hop) | circomlib |
| Poseidon2 (audit nullifier) | 1 | circomlib |
| Num2Bits(64) (scopes) | 2·(MAX_CHAIN_LEN+1) | circomlib |
| Num2Bits(64) (expiries) | MAX_CHAIN_LEN+1 | circomlib |
| LessThan / LessEqThan(64) | MAX_CHAIN_LEN + 1 (expiry narrowing + terminal expiry) | circomlib |
| BinaryMerkleRoot(MAX_DEPTH) | MAX_CHAIN_LEN (delegatee enrollment) | @zk-kit |
| LessThan(log2(MAX_CHAIN_LEN)) | MAX_CHAIN_LEN (active-hop selectors) | circomlib |
| Mux1 (accumulator gating) | MAX_CHAIN_LEN (active vs. pass-through) | circomlib |

### Why the accumulator is sufficient (and minimal)

The execution binding gap in the prior construction was: constraints 2 and 3 pin the chain endpoints to on-chain values, and constraint 6 ensures internal consistency, but nothing prevents the prover from fabricating a *different* internally-consistent chain between the same two endpoints. Two distinct chains `(s_0, c_0) → ... → (s_N, c_N)` and `(s_0, c_0) → ... → (s'_N, c'_N)` that happen to produce the same root and terminal scope commitments would both satisfy the old circuit.

The chain accumulator closes this gap because each intermediate scope commitment `sc_i` is folded into the running hash at delegation time and recorded on-chain. The accumulator is a commitment to the *ordered sequence* of scope commitments, not just the endpoints. Producing a valid proof with different intermediate values requires finding `sc'_1, ..., sc'_{N-1}` such that `Poseidon2(...Poseidon2(Poseidon2(sc_0, sc'_1), sc'_2)..., sc_N) = chainAccumulator` — a second-preimage attack on a Poseidon hash chain, which reduces to Poseidon collision resistance (see §4).

No additional on-chain data beyond the accumulator is needed. In particular, we do *not* need to publish individual intermediate scope commitments (which would leak chain structure to observers) or build a Merkle tree over them (which would add unnecessary complexity). The sequential hash chain is the minimal commitment that binds the audit proof to execution history.

## 3. Threat model (adversary capabilities, game definition)

**Game: Delegation Audit Forgery (DAF)**

Setup: Challenger runs the Bolyra registry with honest enrollment. A delegation chain of length N is executed on-chain with scope commitments `SC_0, ..., SC_N` and chain accumulator `ACC_N = Poseidon2(...Poseidon2(Poseidon2(SC_0, SC_1), SC_2)..., SC_N)`.

Adversary A controls:
- Any subset of agents in the chain (including colluding delegator-delegatee pairs)
- The auditor's view (A tries to fool the auditor)
- All public chain data (scope commitments, nullifiers, chain accumulator, on-chain events)

A does NOT control:
- The Poseidon hash function (modeled as random oracle for PRF properties)
- The Groth16/PLONK verifier (knowledge soundness holds)
- The Baby Jubjub discrete log problem
- The on-chain registry's accumulator updates (these are enforced by smart contract logic at each `delegateHop()` call; A cannot write arbitrary accumulator values)

A wins if any of:
1. **Narrowing forgery:** A produces a valid DelegationAuditChain proof where some hop i has `scopes[i+1] & ~scopes[i] ≠ 0` (delegatee gained a bit the delegator lacked).
2. **Chain substitution:** A produces a valid proof that verifies against the on-chain `rootScopeCommitment`, `terminalScopeCommitment`, *and* `chainAccumulator`, but uses a different sequence of intermediate scope commitments than the one actually recorded on-chain during execution.
3. **Enrollment bypass:** A produces a valid proof where some intermediate delegatee's `credCommitment` is not a leaf in the agent Merkle tree.

Note on the prior "chain injection" attack: the previous construction's threat model defined chain injection as producing a valid proof with different intermediate participants while matching only root and terminal scope commitments. That attack was feasible in principle because the circuit did not constrain intermediates against on-chain state. Constraint 12 (chain accumulator) now upgrades this to **chain substitution**, which requires breaking the Poseidon hash chain — a strictly harder game. The claim is no longer "a valid chain exists" but "the auditor verifies the chain that actually executed."

**Game: Delegation Audit Privacy (DAP)**

Setup: Same as above. Auditor V receives only the DelegationAuditChain proof and its public signals (which now include `chainAccumulator`).

V wins if V can determine:
1. Any intermediate scope value `scopes[i]` for 0 < i < N
2. Any intermediate credential commitment `credCommitments[i]` for 0 < i < N
3. Which Merkle leaf corresponds to any intermediate participant
4. The Merkle proof path (index) for any participant

V should learn only: chain length, the public root/terminal scope commitments (already on-chain), the chain accumulator (already on-chain), and whether the terminal scope satisfies the audit policy.

**Privacy impact of the chain accumulator:** The accumulator `ACC_N` is a single hash value that commits to the ordered sequence of scope commitments. It reveals no individual intermediate scope commitment because Poseidon is modeled as a random oracle — `ACC_N` is computationally indistinguishable from random given knowledge of only `SC_0` and `SC_N`. The accumulator is already stored on-chain (visible to anyone monitoring the registry), so including it as a public input to the audit circuit does not increase the auditor's information beyond what any chain observer already sees. This is a critical design point: the accumulator leaks no more than the on-chain events that produced it.

## 4. Security argument (named assumption + reduction sketch)

**Theorem (DAF soundness):** Under (i) knowledge soundness of PLONK in the algebraic group model + ROM, (ii) collision resistance of Poseidon over the BN254 scalar field, and (iii) hardness of the discrete logarithm problem on Baby Jubjub, no PPT adversary wins the DAF game with non-negligible probability.

**Reduction sketch:**

- **Narrowing forgery → PLONK knowledge soundness:** The extractor from PLONK knowledge soundness extracts a satisfying witness for the circuit. Constraint 4 (per-hop scope narrowing) directly encodes `delegateeBits[j] * (1 - delegatorBits[j]) === 0` for every bit. A satisfying witness with a non-narrowing hop violates the arithmetic constraint, contradicting extraction.

- **Chain substitution → Poseidon collision resistance:** Constraint 12 requires the in-circuit accumulator to match the on-chain `chainAccumulator`. The on-chain accumulator is computed as `ACC_N = fold(Poseidon2, SC_0, [SC_1, ..., SC_N])` where each `SC_i = Poseidon2(scopes[i], credCommitments[i])`. Suppose A uses a different intermediate sequence `SC'_1, ..., SC'_{N-1}` (with `SC'_j ≠ SC_j` for some j). There are two sub-cases:

  - *Same scope commitments, different underlying values:* If `SC'_j = SC_j` but `(scopes'_j, credComm'_j) ≠ (scopes_j, credComm_j)`, this is a direct Poseidon2 collision.
  - *Different scope commitments:* If `SC'_j ≠ SC_j` for some j, then A must find a sequence that folds to the same `ACC_N`. Define `f_k = Poseidon2(f_{k-1}, SC_k)` for the honest chain and `f'_k = Poseidon2(f'_{k-1}, SC'_k)` for the adversary's chain. Since `f_0 = f'_0 = SC_0` and `f_N = f'_N = ACC_N`, there exists a minimal index k where `f_{k-1} = f'_{k-1}` but `SC_k ≠ SC'_k`. Then `Poseidon2(f_{k-1}, SC_k) = f_k` and `Poseidon2(f'_{k-1}, SC'_k) = f'_k`. For the chains to reconverge at or before index N, there must exist some later index m where `f_m = f'_m`, which requires `Poseidon2(f_{m-1}, SC_m) = Poseidon2(f'_{m-1}, SC'_m)` with `(f_{m-1}, SC_m) ≠ (f'_{m-1}, SC'_m)` — again a Poseidon2 collision. If the chains never diverge on `SC` values but only on underlying `(scope, credComm)` pairs, the first sub-case applies.

- **Enrollment bypass → Merkle root preimage resistance:** Constraint 9 requires `BinaryMerkleRoot(credCommitments[i+1], proof_i) = agentTreeRoot`. Producing a valid Merkle proof for a non-enrolled credential commitment requires finding a preimage collision in the Poseidon-based Merkle tree, reducing to Poseidon collision resistance.

**Theorem (DAP zero-knowledge):** Under the zero-knowledge property of PLONK (simulator existence in ROM), the auditor learns nothing about private inputs beyond what is deducible from the public signals.

**Argument:** The PLONK simulator produces transcripts indistinguishable from real proofs without knowing the witness. The public signals are: `rootScopeCommitment`, `terminalScopeCommitment` (both already on-chain), `chainAccumulator` (already on-chain), `chainLengthOut`, `auditPolicyMask` (auditor-chosen), `auditTimestamp`, `sessionNonce`, `agentTreeRoot` (on-chain), `auditNullifier` (deterministic from public values), and `narrowingValid` (always 1). The chain accumulator is a sequential Poseidon hash that, under the random oracle model, reveals no information about individual intermediate scope commitments beyond what the endpoints already reveal. No intermediate scope, credential, or identity information appears in any public signal.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope commitment at each hop | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Identity-Bound Scope Commitment Chain |
| Chain accumulator (on-chain) | `Poseidon2(previousAccumulator, newScopeCommitment)` — sequential fold using Poseidon2 | §2 Cryptographic Primitives (Poseidon) |
| Chain accumulator (in-circuit) | Same Poseidon2 fold recomputed over private scope commitments | Constraint 12 of this construction |
| Per-hop narrowing check | Same bit constraint as Delegation circuit constraint 3 | §4 Delegation Circuit, constraint 3 |
| Cumulative bit encoding | Same 3-constraint block as AgentPolicy/Delegation | §3 AgentPolicy constraint 6, §4 Delegation constraint 4 |
| Delegatee enrollment proof | `BinaryMerkleRoot(MAX_DEPTH)` over agent tree | §4 Delegation constraint 8 |
| Permission bitmask encoding | 8-bit cumulative scheme (READ_DATA through ACCESS_PII) | §3 Permissions Model |
| Audit nullifier derivation | `Poseidon2(scopeCommitment, sessionNonce)` — same pattern as agent nullifier | §3 Agent nullifier |
| Proving system | PLONK (agent/delegation class — avoids per-circuit ceremony) | §2 Proving Systems |
| Curve and field | BN254 scalar field, Baby Jubjub embedded curve | §2 Cryptographic Primitives |
| On-chain registry extension | One additional `uint256 chainAccumulator` in delegation state mapping | §3 On-Chain Registry Contract |

## 6. Circuit cost estimate

Parameters: MAX_CHAIN_LEN = 8, MAX_DEPTH = 20.

| Component | Constraints per instance | Instances | Subtotal |
|---|---|---|---|
| Poseidon2 (scope commitments) | ~300 | 18 (9 positions × 2 for chain-link pairs) | ~5,400 |
| Poseidon2 (chain accumulator fold) | ~300 | 8 (one per hop) | ~2,400 |
| Poseidon2 (audit nullifier) | ~300 | 1 | ~300 |
| Num2Bits(64) (scopes) | ~64 | 18 | ~1,152 |
| Num2Bits(64) (expiries) | ~64 | 9 | ~576 |
| Bit-subset check (64 bits × 8 hops) | ~64 | 8 | ~512 |
| Cumulative encoding (3 constraints × 8 hops) | ~3 | 8 | ~24 |
| LessEqThan(64) (expiry narrowing) | ~130 | 9 | ~1,170 |
| BinaryMerkleRoot(20) (enrollment) | ~6,400 | 8 | ~51,200 |
| Active-hop selectors (LessThan + mux) | ~50 | 8 | ~400 |
| Mux1 (accumulator active/pass-through) | ~3 | 8 | ~24 |
| **Total** | | | **~63,158** |

This fits within 2^16 = 65,536 constraints (the existing `pot16.ptau` SRS). The chain accumulator adds ~2,424 constraints (~4% increase over the prior construction's ~60,734), well within headroom.

**Proving time target:** < 5 seconds (PLONK agent class). With rapidsnark on ~63K constraints, expected wall time is ~2–3 seconds.

**Verification:** PLONK verification is constant time (~3 ms on-chain, ~10K gas with precompiles). A single audit proof replaces N individual delegation proof re-verifications.

**On-chain cost of accumulator:** One additional Poseidon2 hash per delegation hop. Using the EIP-198/EIP-196 precompiles for BN254 arithmetic, this costs ~5K gas per hop — negligible relative to the existing delegation transaction cost (~200K gas for proof verification + state writes).

## 7. Concrete deployment scenario

**Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union**

Navy Federal Credit Union deploys an AI-agent pipeline for automated loan processing:

1. **Root agent** (loan officer's delegate): holds `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bits 0,1,2,7 = 0b10000111 = 0x87).
2. **Hop 1 → Credit pull agent**: delegated `READ_DATA | ACCESS_PII` (bits 0,7 = 0x81). Queries Equifax API.
3. **Hop 2 → Risk scoring agent**: delegated `READ_DATA` (bit 0 = 0x01). Runs internal model, no PII access.
4. **Hop 3 → Decision logging agent**: delegated `READ_DATA | WRITE_DATA` (bits 0,1 = 0x03). Writes to audit log.

**On-chain state after execution:**

- `rootScopeCommitment = SC_0` (from handshake)
- `lastScopeCommitment = SC_3` (after hop 3)
- `chainAccumulator = Poseidon2(Poseidon2(Poseidon2(SC_0, SC_1), SC_2), SC_3)` (folded at each hop)

The NCUA examiner needs to verify that no agent in the pipeline exceeded its mandate — specifically that the risk scoring agent never had PII access and no agent gained financial authority. But NCUA should not learn the internal pipeline structure (which vendors, which models, which agents) because that is proprietary operational detail.

**Audit flow:**

1. The credit union's compliance system holds the full private chain data (scopes, credential commitments, Merkle proofs).
2. The system generates a single `DelegationAuditChain` proof with:
   - `rootScopeCommitment` and `terminalScopeCommitment` from on-chain registry
   - `chainAccumulator` from on-chain registry (constraint 12 binds the proof to the executed chain)
   - `auditPolicyMask = 0x01` (examiner requires terminal agent holds at least READ_DATA)
   - `agentTreeRoot` from the on-chain agent registry
3. The NCUA examiner receives the proof and verifies it against the on-chain PLONK verifier.
4. The examiner learns: chain has 3 hops, narrowing was monotonic at every hop, the terminal agent satisfies the audit policy, and all agents were enrolled. The examiner also knows this is *the* chain that actually executed (not a fabricated alternative), because the proof is bound to the on-chain chain accumulator. The examiner does NOT learn which agents participated, what scopes each held, or the pipeline topology.

**Execution binding in practice:** Without the chain accumulator, a malicious credit union could execute a non-compliant pipeline (e.g., giving the risk scoring agent PII access) and then fabricate a compliant alternative chain that happens to share the same root and terminal scope commitments. The accumulator forecloses this: the on-chain contract recorded the actual intermediate scope commitments at delegation time, and the proof must reproduce the exact fold. Fabricating an alternative chain requires a Poseidon collision.

**Whistleblower variant:** A journalist's source delegates through a chain of 4 intermediary agents to deliver a document. The journalist's auditor verifies the chain narrowed correctly (the document agent had only READ_DATA) without learning the identity of any intermediary — protecting the source even from the journalist's own infrastructure. The chain accumulator ensures the auditor is verifying the real chain, not a sanitized version.

## 8. Why the baseline cannot match

| Property | Bolyra DelegationAuditChain | RFC 8693 + BBS+ + WIMSE baseline |
|---|---|---|
| **Narrowing proof without scope disclosure** | In-circuit: bit-subset constraint over hidden private inputs. Auditor sees only `narrowingValid = 1`. | Impossible without AS trust. BBS+ hides individual claims but cannot prove `scope_i+1 ⊆ scope_i` over hidden bitmasks — no arithmetic relation predicates in BBS+ spec. Auditor must see scopes or trust AS assertion. |
| **Execution binding without intermediate disclosure** | Chain accumulator commits to the exact sequence of intermediate scope commitments on-chain at delegation time. The audit circuit re-derives this accumulator from private witnesses and checks it against the on-chain value. The auditor is cryptographically guaranteed to be verifying the actually-executed chain, not a fabricated alternative — without seeing any intermediate value. | RFC 8693 has no equivalent. The AS policy log records intermediate states, but disclosing the log to the auditor reveals intermediate scopes and participants. BBS+ cannot selectively disclose "the hash chain over these hidden values matches a public commitment" — it has no circuit-level fold operation. The baseline must choose: disclose intermediates for execution binding, or hide intermediates and lose execution binding. It cannot do both. |
| **Intermediate participant hiding** | All credential commitments and Merkle proofs are private inputs. The chain accumulator folds over scope commitments (which are Poseidon hashes of scope + credential commitment), not over raw identities — it reveals no participant information under the random oracle model. | RFC 8693 `act` chain is plaintext. BBS+ operates on single credentials, not multi-issuer chains. Hiding intermediate participants requires re-signing the entire chain under one issuer, destroying the multi-party audit trail. |
| **No trusted third party** | Proof is self-verifying against on-chain state (scope commitments + chain accumulator). Auditor needs only the PLONK verifier contract and on-chain public values. No AS, no federation anchor. | RFC 8693 narrowing enforcement lives at the AS. Offline audit without AS access is impossible — the auditor must query or trust the AS policy log. AS compromise breaks all guarantees. |
| **Cross-org chain in single artifact** | A single PLONK proof covers chains spanning arbitrary organizations. Each hop's credential commitment references the shared agent Merkle tree. The chain accumulator is org-agnostic — it folds scope commitments regardless of which organization issued them. | Requires either a shared AS or WIMSE federation, both of which expose organizational boundaries to the auditor. No standard produces a single artifact proving cross-org narrowing without a common trust anchor. |
| **Journalist/source anonymity** | Intermediate agents are private witnesses. The chain accumulator is a single opaque hash value on-chain — it does not reveal chain length, participant count, or any structural information beyond what the root and terminal commitments already reveal. | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-RS correlation but not AS/auditor correlation. The `act` chain is fully visible to anyone holding the token. |
| **In-circuit enforcement at verification time** | Narrowing is enforced by arithmetic constraints — an invalid chain produces no valid proof. Execution binding is enforced by the accumulator constraint — a fabricated chain produces no valid proof. There is no "trust the issuer" step. | AS enforces narrowing at issuance time only. Post-issuance, tokens circulate without runtime narrowing checks unless each RS independently re-validates the entire `act` chain. |
| **Proof compactness** | Single constant-size PLONK proof (~768 bytes) regardless of chain length. The chain accumulator adds zero bytes to the proof — it is a public input read from on-chain state. | Audit artifact grows linearly: N tokens × M claims per token, each with BBS+ signatures. An 8-hop chain with selective disclosure produces ~8 derived VPs, each ~2–4 KB. |

The structural gap is irreducible: BBS+ provides selective disclosure of *attributes within a credential* but has no mechanism for *relational predicates across a chain of credentials from different issuers*, nor for *binding a proof to a specific execution trace without revealing that trace*. The baseline can hide individual values; it cannot simultaneously prove that hidden values satisfy an ordering constraint and that those values are the ones that actually executed. The DelegationAuditChain circuit with chain accumulator closes both gaps — ordering via in-circuit bit-subset constraints, execution binding via Poseidon hash chain verification — in a single constant-size proof.
