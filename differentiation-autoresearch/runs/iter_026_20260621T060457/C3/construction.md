# Construction

## 1. Statement of claim

An auditor verifies that a delegation chain of length N narrowed permissions monotonically at every hop, that each hop involved an enrolled agent, and that the terminal scope satisfies an auditor-specified minimum policy — all without learning any intermediate scope values, participant identities, credential commitments, or Merkle roots. The construction generalizes beyond regulatory audit to multi-tool AI pipelines and journalist/source agent chains.

## 2. Construction (gadgets, circuits, public/private inputs)

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

12. **Inactive hop gating:** For indices i ≥ chainLength, all constraints are multiplexed to trivially satisfied form (multiply constraint by `isActive[i]` selector signal, where `isActive[i] = (i < chainLength)` computed via LessThan).

### Gadget inventory

| Gadget | Uses per proof | Source |
|---|---|---|
| Poseidon2 | 2·(MAX_CHAIN_LEN+1) + 1 (scope commitments + nullifier) | circomlib |
| Num2Bits(64) | 2·(MAX_CHAIN_LEN+1) + MAX_CHAIN_LEN (scopes + expiries) | circomlib |
| LessThan / LessEqThan(64) | MAX_CHAIN_LEN + 1 (expiry narrowing + terminal expiry) | circomlib |
| BinaryMerkleRoot(MAX_DEPTH) | MAX_CHAIN_LEN (delegatee enrollment) | @zk-kit |
| LessThan(log2(MAX_CHAIN_LEN)) | MAX_CHAIN_LEN (active-hop selectors) | circomlib |

## 3. Threat model (adversary capabilities, game definition)

**Game: Delegation Audit Forgery (DAF)**

Setup: Challenger runs the Bolyra registry with honest enrollment. A delegation chain of length N is executed on-chain with scope commitments `SC_0, ..., SC_N`.

Adversary A controls:
- Any subset of agents in the chain (including colluding delegator-delegatee pairs)
- The auditor's view (A tries to fool the auditor)
- All public chain data (scope commitments, nullifiers, on-chain events)

A does NOT control:
- The Poseidon hash function (modeled as random oracle for PRF properties)
- The Groth16/PLONK verifier (knowledge soundness holds)
- The Baby Jubjub discrete log problem

A wins if any of:
1. **Narrowing forgery:** A produces a valid DelegationAuditChain proof where some hop i has `scopes[i+1] & ~scopes[i] ≠ 0` (delegatee gained a bit the delegator lacked).
2. **Chain injection:** A produces a valid proof linking to on-chain `rootScopeCommitment` and `terminalScopeCommitment` but using a different chain of intermediate participants than the one actually executed.
3. **Enrollment bypass:** A produces a valid proof where some intermediate delegatee's `credCommitment` is not a leaf in the agent Merkle tree.

**Game: Delegation Audit Privacy (DAP)**

Setup: Same as above. Auditor V receives only the DelegationAuditChain proof and its public signals.

V wins if V can determine:
1. Any intermediate scope value `scopes[i]` for 0 < i < N
2. Any intermediate credential commitment `credCommitments[i]` for 0 < i < N
3. Which Merkle leaf corresponds to any intermediate participant
4. The Merkle proof path (index) for any participant

V should learn only: chain length, the public root/terminal scope commitments (already on-chain), and whether the terminal scope satisfies the audit policy.

## 4. Security argument (named assumption + reduction sketch)

**Theorem (DAF soundness):** Under (i) knowledge soundness of PLONK in the algebraic group model + ROM, (ii) collision resistance of Poseidon over the BN254 scalar field, and (iii) hardness of the discrete logarithm problem on Baby Jubjub, no PPT adversary wins the DAF game with non-negligible probability.

**Reduction sketch:**

- **Narrowing forgery → PLONK knowledge soundness:** The extractor from PLONK knowledge soundness extracts a satisfying witness for the circuit. Constraint 4 (per-hop scope narrowing) directly encodes `delegateeBits[j] * (1 - delegatorBits[j]) === 0` for every bit. A satisfying witness with a non-narrowing hop violates the arithmetic constraint, contradicting extraction.

- **Chain injection → Poseidon collision resistance:** Constraints 2 and 3 bind the private chain endpoints to on-chain scope commitments. Constraint 6 chains intermediate scope commitments via `Poseidon2(scope, credComm)`. Producing a valid proof with different intermediate values that still chains from `rootScopeCommitment` to `terminalScopeCommitment` requires finding `(scope', credComm') ≠ (scope, credComm)` such that `Poseidon2(scope', credComm') = Poseidon2(scope, credComm)` at some hop — a Poseidon collision.

- **Enrollment bypass → Merkle root preimage resistance:** Constraint 9 requires `BinaryMerkleRoot(credCommitments[i+1], proof_i) = agentTreeRoot`. Producing a valid Merkle proof for a non-enrolled credential commitment requires finding a preimage collision in the Poseidon-based Merkle tree, reducing to Poseidon collision resistance.

**Theorem (DAP zero-knowledge):** Under the zero-knowledge property of PLONK (simulator existence in ROM), the auditor learns nothing about private inputs beyond what is deducible from the public signals.

**Argument:** The PLONK simulator produces transcripts indistinguishable from real proofs without knowing the witness. The public signals are: `rootScopeCommitment`, `terminalScopeCommitment` (both already on-chain), `chainLengthOut`, `auditPolicyMask` (auditor-chosen), `auditTimestamp`, `sessionNonce`, `agentTreeRoot` (on-chain), `auditNullifier` (deterministic from public values), and `narrowingValid` (always 1). No intermediate scope, credential, or identity information appears in any public signal.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope commitment at each hop | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Identity-Bound Scope Commitment Chain |
| Per-hop narrowing check | Same bit constraint as Delegation circuit constraint 3 | §4 Delegation Circuit, constraint 3 |
| Cumulative bit encoding | Same 3-constraint block as AgentPolicy/Delegation | §3 AgentPolicy constraint 6, §4 Delegation constraint 4 |
| Delegatee enrollment proof | `BinaryMerkleRoot(MAX_DEPTH)` over agent tree | §4 Delegation constraint 8 |
| Permission bitmask encoding | 8-bit cumulative scheme (READ_DATA through ACCESS_PII) | §3 Permissions Model |
| Audit nullifier derivation | `Poseidon2(scopeCommitment, sessionNonce)` — same pattern as agent nullifier | §3 Agent nullifier |
| Proving system | PLONK (agent/delegation class — avoids per-circuit ceremony) | §2 Proving Systems |
| Curve and field | BN254 scalar field, Baby Jubjub embedded curve | §2 Cryptographic Primitives |

## 6. Circuit cost estimate

Parameters: MAX_CHAIN_LEN = 8, MAX_DEPTH = 20.

| Component | Constraints per instance | Instances | Subtotal |
|---|---|---|---|
| Poseidon2 (scope commitments) | ~300 | 18 (9 positions × 2 for chain-link pairs) | ~5,400 |
| Poseidon2 (audit nullifier) | ~300 | 1 | ~300 |
| Num2Bits(64) (scopes) | ~64 | 18 | ~1,152 |
| Num2Bits(64) (expiries) | ~64 | 9 | ~576 |
| Bit-subset check (64 bits × 8 hops) | ~64 | 8 | ~512 |
| Cumulative encoding (3 constraints × 8 hops) | ~3 | 8 | ~24 |
| LessEqThan(64) (expiry narrowing) | ~130 | 9 | ~1,170 |
| BinaryMerkleRoot(20) (enrollment) | ~6,400 | 8 | ~51,200 |
| Active-hop selectors (LessThan + mux) | ~50 | 8 | ~400 |
| **Total** | | | **~60,734** |

This fits comfortably within 2^16 = 65,536 constraints (the existing `pot16.ptau` SRS).

**Proving time target:** < 5 seconds (PLONK agent class). With rapidsnark on ~60K constraints, expected wall time is ~2–3 seconds.

**Verification:** PLONK verification is constant time (~3 ms on-chain, ~10K gas with precompiles). A single audit proof replaces N individual delegation proof re-verifications.

## 7. Concrete deployment scenario

**Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union**

Navy Federal Credit Union deploys an AI-agent pipeline for automated loan processing:

1. **Root agent** (loan officer's delegate): holds `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bits 0,1,2,7 = 0b10000111 = 0x87).
2. **Hop 1 → Credit pull agent**: delegated `READ_DATA | ACCESS_PII` (bits 0,7 = 0x81). Queries Equifax API.
3. **Hop 2 → Risk scoring agent**: delegated `READ_DATA` (bit 0 = 0x01). Runs internal model, no PII access.
4. **Hop 3 → Decision logging agent**: delegated `READ_DATA | WRITE_DATA` (bits 0,1 = 0x03). Writes to audit log.

The NCUA examiner needs to verify that no agent in the pipeline exceeded its mandate — specifically that the risk scoring agent never had PII access and no agent gained financial authority. But NCUA should not learn the internal pipeline structure (which vendors, which models, which agents) because that is proprietary operational detail.

**Audit flow:**

1. The credit union's compliance system holds the full private chain data (scopes, credential commitments, Merkle proofs).
2. The system generates a single `DelegationAuditChain` proof with:
   - `rootScopeCommitment` and `terminalScopeCommitment` from on-chain registry
   - `auditPolicyMask = 0x01` (examiner requires terminal agent holds at least READ_DATA)
   - `agentTreeRoot` from the on-chain agent registry
3. The NCUA examiner receives the proof and verifies it against the on-chain PLONK verifier.
4. The examiner learns: chain has 3 hops, narrowing was monotonic at every hop, the terminal agent satisfies the audit policy, and all agents were enrolled. The examiner does NOT learn which agents participated, what scopes each held, or the pipeline topology.

**Whistleblower variant:** A journalist's source delegates through a chain of 4 intermediary agents to deliver a document. The journalist's auditor verifies the chain narrowed correctly (the document agent had only READ_DATA) without learning the identity of any intermediary — protecting the source even from the journalist's own infrastructure.

## 8. Why the baseline cannot match

| Property | Bolyra DelegationAuditChain | RFC 8693 + BBS+ + WIMSE baseline |
|---|---|---|
| **Narrowing proof without scope disclosure** | In-circuit: bit-subset constraint over hidden private inputs. Auditor sees only `narrowingValid = 1`. | Impossible without AS trust. BBS+ hides individual claims but cannot prove `scope_i+1 ⊆ scope_i` over hidden bitmasks — no arithmetic relation predicates in BBS+ spec. Auditor must see scopes or trust AS assertion. |
| **Intermediate participant hiding** | All credential commitments and Merkle proofs are private inputs. No public signal reveals any participant identity. | RFC 8693 `act` chain is plaintext. BBS+ operates on single credentials, not multi-issuer chains. Hiding intermediate participants requires re-signing the entire chain under one issuer, destroying the multi-party audit trail. |
| **No trusted third party** | Proof is self-verifying against on-chain state. Auditor needs only the PLONK verifier contract and the chain's public scope commitments (already on-chain). No AS, no federation anchor. | RFC 8693 narrowing enforcement lives at the AS. Offline audit without AS access is impossible — the auditor must query or trust the AS policy log. AS compromise breaks all guarantees. |
| **Cross-org chain in single artifact** | A single PLONK proof covers chains spanning arbitrary organizations. Each hop's credential commitment references the shared agent Merkle tree. No org-specific trust anchor needed. | Requires either a shared AS or WIMSE federation, both of which expose organizational boundaries to the auditor. No standard produces a single artifact proving cross-org narrowing without a common trust anchor. |
| **Journalist/source anonymity** | Intermediate agents are private witnesses. Even the chain length could be hidden (by setting MAX_CHAIN_LEN and padding with identity hops). The auditor cryptographically cannot correlate participants. | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-RS correlation but not AS/auditor correlation. The `act` chain is fully visible to anyone holding the token. |
| **In-circuit enforcement at verification time** | Narrowing is enforced by arithmetic constraints — an invalid chain produces no valid proof. There is no "trust the issuer" step. | AS enforces narrowing at issuance time only. Post-issuance, tokens circulate without runtime narrowing checks unless each RS independently re-validates the entire `act` chain. |
| **Proof compactness** | Single constant-size PLONK proof (~768 bytes) regardless of chain length. | Audit artifact grows linearly: N tokens × M claims per token, each with BBS+ signatures. An 8-hop chain with selective disclosure produces ~8 derived VPs, each ~2–4 KB. |

The structural gap is irreducible: BBS+ provides selective disclosure of *attributes within a credential* but has no mechanism for *relational predicates across a chain of credentials from different issuers*. The baseline can hide individual values; it cannot prove that hidden values satisfy an ordering constraint across multiple documents. The DelegationAuditChain circuit closes this gap by making the ordering constraint itself the subject of the proof.
