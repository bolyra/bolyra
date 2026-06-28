# Construction

## 1. Statement of claim

An auditor verifies that a delegation chain of arbitrary length narrowed monotonically — every hop's permission bitmask is a subset of its predecessor's — without learning any intermediate scope values, any intermediate participant identities, or the chain length. The proof is a single PLONK artifact verified in one on-chain call.

The baseline (RFC 8693 + BBS+ + WIMSE) cannot hide intermediate scopes during narrowing verification, cannot produce a single aggregated chain proof, and cannot conceal chain length. This construction closes all six gaps identified in the baseline analysis.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: `DelegationChainAudit(MAX_HOPS)`

**MAX_HOPS = 16** (covers practical multi-tool AI pipelines; pad shorter chains).

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `actualLength` | uint4 | True number of hops (1..MAX_HOPS) |
| `scopes[MAX_HOPS]` | uint64[] | Permission bitmask at each hop |
| `credCommitments[MAX_HOPS]` | field[] | Credential commitment at each hop |
| `expiries[MAX_HOPS]` | uint64[] | Expiry timestamp at each hop |
| `delegatorPubkeys[MAX_HOPS][2]` | field[][2] | (Ax, Ay) of delegator at each hop |
| `delegationSigs[MAX_HOPS][3]` | field[][3] | (R8x, R8y, S) EdDSA sig per hop |
| `salt` | field | Auditor-blinding salt for chain digest |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `auditSessionNonce` | field | Fresh nonce binding the audit proof |
| `policyFloor` | uint64 | Minimum permission bits the auditor requires the final hop to satisfy |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rootScopeCommitment` | field | Poseidon2(scopes[0], credCommitments[0]) — chain origin |
| `finalScopeCommitment` | field | Poseidon2(scopes[L-1], credCommitments[L-1]) — chain terminus |
| `chainDigest` | field | Poseidon(salt, Poseidon-chain of all scopeCommitments) |
| `auditNullifier` | field | Poseidon2(chainDigest, auditSessionNonce) — replay prevention |
| `narrowingHolds` | bit | 1 if ∀i: scope_{i+1} ⊆ scope_i and expiry_{i+1} ≤ expiry_i |
| `policyMet` | bit | 1 if finalScope satisfies policyFloor |

### Internal gadgets (all Circom 2 compatible)

**G1. Hop narrowing (per-hop, applied MAX_HOPS−1 times):**

```
for bit j in [0, 64):
    scopeBits_next[j] * (1 - scopeBits_curr[j]) === 0
```

Plus cumulative-bit encoding enforcement on each scope (bits 4→3→2 implication chain per Bolyra spec).

**G2. Expiry narrowing (per-hop):**

```
LessEqThan(64)(expiries[i+1], expiries[i])
```

**G3. Scope commitment computation (per-hop):**

```
scopeCommitment[i] = Poseidon2(scopes[i], credCommitments[i])
```

**G4. Chain linking (per-hop, i > 0):**

The delegation token at hop i is:

```
delegationToken[i] = Poseidon4(
    scopeCommitment[i-1],
    credCommitments[i],
    scopes[i],
    expiries[i]
)
```

EdDSAPoseidonVerifier verifies `delegationToken[i]` against `delegatorPubkeys[i]` and `delegationSigs[i]`.

**G5. Active-hop multiplexing (hides chain length):**

For each hop i, compute `isActive[i] = LessThan(5)(i, actualLength)`. Narrowing, expiry, chain-linking, and signature constraints are gated:

```
isActive[i] * (narrowingViolation[i]) === 0
isActive[i] * (expiryViolation[i]) === 0
isActive[i] * (chainLinkViolation[i]) === 0
```

Inactive hops (i ≥ actualLength) copy `scopes[actualLength-1]` and `credCommitments[actualLength-1]` via multiplexer, so all MAX_HOPS slots produce identical scope commitments in the tail — the auditor cannot distinguish a 3-hop chain from a 16-hop chain.

**G6. Chain digest (Poseidon chain hash):**

```
runningHash[0] = salt
for i in [0, MAX_HOPS):
    runningHash[i+1] = Poseidon2(runningHash[i], scopeCommitment[i])
chainDigest = runningHash[MAX_HOPS]
```

Because inactive hops repeat the final scope commitment, and the salt is private, the digest is a fixed-length commitment regardless of actual chain length.

**G7. Policy floor check:**

```
for bit j in [0, 64):
    policyFloorBits[j] * (1 - finalScopeBits[j]) === 0
policyMet = 1    // if constraint system is satisfiable
```

**G8. Aggregate narrowing flag:**

```
narrowingHolds = AND(isActive[i] → narrowing_ok[i]) for all i
```

Implemented as a product of per-hop pass/fail bits gated by isActive.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary $\mathcal{A}$ controls up to $n-1$ of $n$ participants in a delegation chain. $\mathcal{A}$ can:

- Choose arbitrary scope bitmasks, credential commitments, and expiry values for controlled participants.
- Observe the public outputs `(rootScopeCommitment, finalScopeCommitment, chainDigest, auditNullifier, narrowingHolds, policyMet)`.
- Interact with the on-chain verifier contract.
- Corrupt the auditor (auditor learns only public outputs).

$\mathcal{A}$ cannot:

- Break the discrete log assumption on Baby Jubjub (cannot forge EdDSA signatures of honest participants).
- Find Poseidon collisions.
- Break knowledge soundness of the PLONK proving system.

### Security game: CHAIN-NARROW-SOUNDNESS

1. Challenger sets up the Bolyra registry with enrolled agents.
2. $\mathcal{A}$ constructs a delegation chain and produces a `DelegationChainAudit` proof $\pi$ with public outputs where `narrowingHolds = 1`.
3. $\mathcal{A}$ wins if there exists some hop $i < \text{actualLength}$ such that $\text{scopes}[i+1] \not\subseteq \text{scopes}[i]$ (the chain did NOT actually narrow monotonically), yet the verifier accepts $\pi$.

### Security game: CHAIN-PRIVACY

1. Challenger generates two valid chains $C_0, C_1$ of potentially different lengths, with identical `(rootScopeCommitment, finalScopeCommitment, policyFloor)` and both satisfying monotonic narrowing.
2. Challenger flips bit $b$, generates proof $\pi_b$ from $C_b$.
3. $\mathcal{A}$ receives $\pi_b$ and all public outputs. $\mathcal{A}$ outputs guess $b'$.
4. $\mathcal{A}$ wins if $\Pr[b' = b] > 1/2 + \text{negl}(\lambda)$.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

- **A1**: Poseidon collision resistance over the BN128 scalar field.
- **A2**: Discrete log hardness on Baby Jubjub (EdDSA unforgeability).
- **A3**: Knowledge soundness of PLONK with universal SRS (in the algebraic group model + ROM).

### Theorem 1 (CHAIN-NARROW-SOUNDNESS)

Under A1, A2, and A3, no PPT adversary wins CHAIN-NARROW-SOUNDNESS with non-negligible probability.

**Reduction sketch**: Suppose $\mathcal{A}$ produces an accepting proof with `narrowingHolds = 1` but some hop violates narrowing. By A3, the PLONK extractor recovers a valid witness. The witness contains `scopes[i]` and `scopes[i+1]` for the violating hop where `isActive[i] = 1`. Gadget G1 enforces `scopeBits_next[j] * (1 - scopeBits_curr[j]) === 0` for all bits j when active. If the witness satisfies the constraint system, narrowing holds — contradiction. If the extractor fails, this breaks A3.

The chain-linking constraint (G4) uses EdDSA verification per hop. If $\mathcal{A}$ forges a delegation token signature for an honest participant's hop, this breaks A2. The scope commitment binding (G3) prevents scope substitution: changing a scope while keeping the same scope commitment requires a Poseidon collision, breaking A1.

### Theorem 2 (CHAIN-PRIVACY)

Under A3 (zero-knowledge property of PLONK), no PPT adversary wins CHAIN-PRIVACY with non-negligible probability.

**Reduction sketch**: The PLONK proof reveals nothing beyond the public outputs. Chain length is hidden because inactive hops produce identical scope commitments to the last active hop (G5), and the chain digest includes a private salt (G6), making the digest computationally indistinguishable between chains of different lengths with the same endpoints. The salt ensures the chain digest is a pseudorandom commitment under Poseidon's PRF properties (consequence of A1). Intermediate scopes and credential commitments are private inputs, hidden by PLONK's zero-knowledge guarantee.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope commitment per hop | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Composable Delegation |
| Delegation token hash | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | Delegation Circuit §4.2 |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | §2.2 Cryptographic Primitives |
| Cumulative bit encoding | Bits 4→3→2 implication constraints | §AgentPolicy constraint 6 |
| Nullifier derivation | `Poseidon2(chainDigest, auditSessionNonce)` | Nullifier pattern from §3 |
| Proving system | PLONK with universal SRS (agent-class circuit) | §2.3 — PLONK OPTIONAL for Delegation |
| Permission bitmask | 8-bit (extendable to 64-bit) cumulative encoding | Permissions Model |
| Chain digest | Poseidon iterative hash (standard Poseidon2 chain) | Uses Poseidon2 per spec |

All cryptographic operations stay within the BN128 scalar field. No new primitives are introduced.

## 6. Circuit cost estimate

### Constraint breakdown per hop

| Gadget | Constraints (approx) |
|---|---|
| Num2Bits(64) × 2 (scope + expiry) | 128 |
| Scope subset check (64 bit-AND constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| LessEqThan(64) for expiry narrowing | ~130 |
| Poseidon2 (scope commitment) | ~300 |
| Poseidon4 (delegation token) | ~600 |
| EdDSAPoseidonVerifier | ~5,500 |
| Active-hop multiplexer (2 field muxes + 3 gating) | ~20 |
| **Per-hop total** | **~6,745** |

### Full circuit

| Component | Constraints |
|---|---|
| 16 hops × 6,745 | 107,920 |
| 15 chain-link verifications (hop 0 has no predecessor) | (included above) |
| Chain digest (16 × Poseidon2) | 4,800 |
| Audit nullifier (1 × Poseidon2) | 300 |
| Policy floor check (64 bit-AND) | 64 |
| LessThan(5) for actualLength × 16 | 160 |
| **Total** | **~113,244** |

This fits within 2^17 (131,072) constraints. Uses `pot17.ptau` or the universal PLONK SRS at depth 17.

### Proving time targets

| Proving system | Target | Rationale |
|---|---|---|
| PLONK (agent-class) | < 4s | Agent-class circuit per spec; PLONK avoids per-circuit ceremony |
| PLONK with rapidsnark | < 1.5s | Native prover for production |

The circuit is within the PLONK agent proving time budget (< 5s spec target) even without rapidsnark.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI agent pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), the largest US credit union (13M+ members).

**Setup**: NFCU deploys an AI agent pipeline for member loan processing. The pipeline has 5 hops:

1. **Root agent** (member-facing chatbot): `FINANCIAL_MEDIUM | READ_DATA | WRITE_DATA` (bits 0,1,3 = bitmask `0b00001011`)
2. **Credit scoring tool**: `READ_DATA` only (bit 0 = `0b00000001`)
3. **Document verification tool**: `READ_DATA | ACCESS_PII` (bits 0,7 = `0b10000001`)
4. **Underwriting decision tool**: `READ_DATA` (bit 0 = `0b00000001`)
5. **Notification tool**: `READ_DATA | WRITE_DATA` (bits 0,1 = `0b00000011`)

Wait — hop 3 has `ACCESS_PII` (bit 7) which is not in the root agent's bitmask. The circuit would correctly set `narrowingHolds = 0`. The compliance officer catches the violation without seeing any intermediate participant identity or the specific scope values. Corrected pipeline:

1. **Root agent**: `READ_DATA | WRITE_DATA | ACCESS_PII` (bits 0,1,7 = `0b10000011`)
2. **Credit scoring tool**: `READ_DATA | ACCESS_PII` (bits 0,7 = `0b10000001`)
3. **Document verification tool**: `READ_DATA | ACCESS_PII` (bits 0,7 = `0b10000001`)
4. **Underwriting decision tool**: `READ_DATA` (bit 0 = `0b00000001`)
5. **Notification tool**: `WRITE_DATA` (bit 1 = `0b00000010`) — but this requires bit 0 to NOT be set while bit 1 is. Since there is no cumulative implication between bits 0 and 1, this is valid.

**Audit flow**:

1. NFCU's compliance officer (auditor) receives `auditSessionNonce` from the registry.
2. The pipeline operator generates a `DelegationChainAudit` proof with `policyFloor = 0b00000001` (auditor only needs to confirm final hop has at least `READ_DATA`).
3. The PLONK proof is submitted on-chain. The auditor sees:
   - `rootScopeCommitment`: opaque field element (cannot extract bitmask)
   - `finalScopeCommitment`: opaque field element
   - `narrowingHolds = 1`: chain narrowed monotonically
   - `policyMet = 1`: final hop meets the floor
   - `chainDigest`: opaque commitment to chain structure
   - `auditNullifier`: replay-prevention value
4. The auditor does NOT learn: how many hops, what permissions each hop had, which agents participated, or which tools were called.

**Whistleblower variant**: A journalist's source uses an agent pipeline (source → anonymizer agent → secure drop agent → journalist's retrieval agent). The same circuit proves the chain narrowed (each hop had fewer permissions than its predecessor) without revealing the source's identity, the anonymizer's identity, or the chain length to the auditor verifying the chain of custody.

**Cross-org handoff variant**: NFCU's loan pipeline hands off to a third-party appraisal service. The handoff is a delegation hop. The auditor at NCUA (the credit union regulator) verifies the full chain narrowed across organizational boundaries without learning which appraisal vendor was used — relevant for anti-steering compliance.

## 8. Why the baseline cannot match

| Capability | DelegationChainAudit (this construction) | RFC 8693 + BBS+ + WIMSE baseline |
|---|---|---|
| **Hide intermediate scopes from auditor** | All scopes are private inputs; auditor sees only root/final scope commitments (opaque Poseidon hashes) | BBS+ cannot produce subset-predicate proofs over hidden bitmask values. Auditor must see both scopes to verify narrowing. |
| **Hide intermediate participants** | Credential commitments are private inputs; chain linking is enforced in-circuit via EdDSA + Poseidon binding | BBS+ hides participant_id per hop but breaks cross-hop chain integrity — the auditor cannot verify hop N's credential was issued to hop N+1's presenter without seeing the linking attribute. |
| **Single aggregated proof** | One PLONK proof (~1.5 KB) for the entire chain, verified in one on-chain call (~250K gas) | Auditor must process O(n) artifacts: n RFC 8693 tokens or n BBS+ derived proofs. No aggregation mechanism exists in any current spec. |
| **Conceal chain length** | Active-hop multiplexing pads all chains to MAX_HOPS; private salt in chain digest makes short and long chains computationally indistinguishable | Hop count is visible from artifact count. No mechanism to hide chain length. |
| **AS-blind auditing** | No authorization server mediates delegation. All narrowing enforcement is in-circuit. The auditor verifies a proof, not AS-signed records. | RFC 8693 structurally requires the AS at every hop. A compromised/subpoenaed AS reconstructs the full chain. |
| **Whistleblower-safe intermediary concealment** | Every intermediate node is hidden from auditor, from other nodes (each sees only its delegator), and from the proof itself (ZK property of PLONK) | WIMSE binds workload identity to each hop (visible to verifier). BBS+ issuer knows each participant. No combination provides intermediary anonymity with chain integrity. |

**The fundamental gap**: the baseline's strongest tool (BBS+ selective disclosure) operates on individual credentials. It can hide attributes within a single credential presentation. But delegation chain audit requires a *cross-credential predicate* — proving a relationship between hidden values across multiple credentials. BBS+ has no mechanism for inter-credential predicates. Zero-knowledge circuits do this natively: the entire chain is the witness, and the circuit enforces predicates across all hops simultaneously, outputting only the aggregate result.
