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
| `blindingNonces[MAX_HOPS]` | field[] | Per-hop blinding nonce (≥128-bit entropy each) |
| `delegatorPubkeys[MAX_HOPS][2]` | field[][2] | (Ax, Ay) of delegator at each hop |
| `delegationSigs[MAX_HOPS][3]` | field[][3] | (R8x, R8y, S) EdDSA sig per hop |
| `salt` | field | Auditor-blinding salt for chain digest |
| `merkleProofIndex[MAX_HOPS]` | uint20[] | Leaf index per hop in agent Merkle tree |
| `merkleProofSiblings[MAX_HOPS][20]` | field[][20] | Merkle siblings per hop (depth 20, padded) |
| `merkleProofLength[MAX_HOPS]` | uint5[] | Actual Merkle proof depth per hop |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `auditSessionNonce` | field | Fresh nonce binding the audit proof |
| `policyFloor` | uint64 | Minimum permission bits the auditor requires the final hop to satisfy |
| `agentRegistryRoot` | field | On-chain agent Merkle tree root (from root history buffer) |
| `handshakeScopeCommitment` | field | Unblinded scope commitment from the handshake's `lastScopeCommitment` mapping — already on-chain, used for chain anchoring only |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rootScopeCommitment` | field | Poseidon3(scopes[0], credCommitments[0], blindingNonces[0]) — blinded chain origin |
| `finalScopeCommitment` | field | Poseidon3(scopes[L-1], credCommitments[L-1], blindingNonces[L-1]) — blinded chain terminus |
| `chainDigest` | field | Poseidon(salt, Poseidon-chain of all blinded scopeCommitments) |
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

**G3. Blinded scope commitment computation (per-hop):**

```
blindedScopeCommitment[i] = Poseidon3(scopes[i], credCommitments[i], blindingNonces[i])
```

Each `blindingNonces[i]` is a private field element with at least 128 bits of entropy. Because the blinding nonce is an unrestricted field element (no range check — it is a private input chosen by the prover), an adversary attempting brute-force inversion of a blinded scope commitment must search over the full BN128 scalar field (~2^254 values), not merely over the 256 × |enrolled agents| space that sufficed for the unblinded Poseidon2 commitment.

The circuit also computes unblinded scope commitments for internal chain-linking purposes:

```
unblindedScopeCommitment[i] = Poseidon2(scopes[i], credCommitments[i])
```

**G3a. Handshake anchoring:**

The circuit proves that the root hop's unblinded scope commitment matches the on-chain handshake seed, without exposing the unblinded value as a public output:

```
Poseidon2(scopes[0], credCommitments[0]) === handshakeScopeCommitment
```

This constraint binds the audit proof to a specific handshake stored on-chain. The `handshakeScopeCommitment` is a public input — the on-chain verifier checks it against the `lastScopeCommitment` mapping indexed by the original handshake's session nonce. Since this value is already stored on-chain from the handshake, making it a public input reveals no new information. The privacy gain is that the audit circuit's *output* `rootScopeCommitment` is the blinded version, which cannot be correlated with the on-chain seed by any observer who lacks the blinding nonce.

**G4. Chain linking (per-hop, i > 0):**

The delegation token at hop i uses the **unblinded** scope commitment of the predecessor (matching the Bolyra spec's delegation token format):

```
delegationToken[i] = Poseidon4(
    unblindedScopeCommitment[i-1],
    credCommitments[i],
    scopes[i],
    expiries[i]
)
```

EdDSAPoseidonVerifier verifies `delegationToken[i]` against `delegatorPubkeys[i]` and `delegationSigs[i]`.

The unblinded scope commitment is computed internally (G3) and never exposed as a public output. The delegation token format remains identical to the existing Bolyra `Delegation` circuit (spec §4.2), preserving compatibility: delegation tokens signed during the original per-hop delegation flow verify correctly inside the audit circuit without re-signing.

**G5. Active-hop multiplexing (hides chain length):**

For each hop i, compute `isActive[i] = LessThan(5)(i, actualLength)`. Narrowing, expiry, chain-linking, signature, and enrollment constraints are gated:

```
isActive[i] * (narrowingViolation[i]) === 0
isActive[i] * (expiryViolation[i]) === 0
isActive[i] * (chainLinkViolation[i]) === 0
isActive[i] * (enrollmentViolation[i]) === 0
```

Inactive hops (i ≥ actualLength) copy `scopes[actualLength-1]`, `credCommitments[actualLength-1]`, `blindingNonces[actualLength-1]`, and `merkleProofIndex[actualLength-1]` / `merkleProofSiblings[actualLength-1]` via multiplexer, so all MAX_HOPS slots produce identical blinded scope commitments and identical Merkle roots in the tail — the auditor cannot distinguish a 3-hop chain from a 16-hop chain.

**G6. Chain digest (Poseidon chain hash):**

```
runningHash[0] = salt
for i in [0, MAX_HOPS):
    runningHash[i+1] = Poseidon2(runningHash[i], blindedScopeCommitment[i])
chainDigest = runningHash[MAX_HOPS]
```

The chain digest uses **blinded** scope commitments. Because inactive hops repeat the final blinded scope commitment, and the salt is private, the digest is a fixed-length commitment regardless of actual chain length.

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

**G9. Registry enrollment (per-hop, applied MAX_HOPS times):**

Each hop's credential commitment must be a leaf in the on-chain agent Merkle tree:

```
computedRoot[i] = BinaryMerkleRoot(20)(
    credCommitments[i],
    merkleProofLength[i],
    merkleProofIndex[i],
    merkleProofSiblings[i]
)
enrollmentViolation[i] = IsNotEqual(computedRoot[i], agentRegistryRoot)
isActive[i] * enrollmentViolation[i] === 0
```

This reuses the same `BinaryMerkleRoot(MAX_DEPTH=20)` template used by the existing Bolyra `AgentPolicy` and `Delegation` circuits. The public input `agentRegistryRoot` is checked by the on-chain verifier against the agent root history buffer (the last 30 roots), exactly as done for individual delegation proofs today.

For inactive hops, the multiplexer copies the last active hop's Merkle proof data, so `computedRoot[i]` equals `agentRegistryRoot` trivially — no information about actual chain length leaks through the enrollment check.

**Why G9 is necessary:** Without registry binding, an adversary can construct a synthetic chain using fabricated credential commitments that are internally consistent (valid EdDSA signatures from attacker-controlled keys, valid scope narrowing) but correspond to no enrolled agent. This is the phantom root attack: the root hop's `credCommitment[0]` could be a self-signed credential never registered on-chain, and the entire chain would verify. G9 forces every active hop to prove enrollment against the same on-chain registry root, anchoring the proof to real registrations.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary $\mathcal{A}$ controls up to $n-1$ of $n$ participants in a delegation chain. $\mathcal{A}$ can:

- Choose arbitrary scope bitmasks, credential commitments, and expiry values for controlled participants.
- Generate fresh EdDSA key pairs and sign delegation tokens for controlled participants.
- Observe the public outputs `(rootScopeCommitment, finalScopeCommitment, chainDigest, auditNullifier, narrowingHolds, policyMet)` and the public inputs `(agentRegistryRoot, handshakeScopeCommitment)`.
- Enumerate all enrolled credential commitments from the on-chain agent Merkle tree (leaves are public upon enrollment).
- Enumerate all 256 possible 8-bit permission bitmask values (or all 2^64 values for 64-bit bitmasks).
- Interact with the on-chain verifier contract.
- Corrupt the auditor (auditor learns only public outputs and public inputs).

$\mathcal{A}$ cannot:

- Break the discrete log assumption on Baby Jubjub (cannot forge EdDSA signatures of honest participants).
- Find Poseidon collisions or Poseidon preimages.
- Break knowledge soundness of the PLONK proving system.
- Enroll arbitrary credential commitments in the agent Merkle tree (enrollment is permissioned by the registry contract — requires operator-signed credentials verified by the `AgentPolicy` circuit before insertion).

### Security game: CHAIN-NARROW-SOUNDNESS

1. Challenger sets up the Bolyra registry with enrolled agents. The agent Merkle tree root $R$ is published on-chain.
2. $\mathcal{A}$ constructs a delegation chain and produces a `DelegationChainAudit` proof $\pi$ with `agentRegistryRoot = R` (or any root in the history buffer) and `narrowingHolds = 1`.
3. $\mathcal{A}$ wins if **either**:
   - (a) There exists some hop $i < \text{actualLength}$ such that $\text{scopes}[i+1] \not\subseteq \text{scopes}[i]$, yet the verifier accepts $\pi$; **or**
   - (b) There exists some hop $i < \text{actualLength}$ such that $\text{credCommitments}[i]$ is not a leaf in the agent Merkle tree with root $R$, yet the verifier accepts $\pi$.

Condition (b) is the phantom-chain attack: $\mathcal{A}$ wins by producing an accepting proof over unenrolled entities.

### Security game: CHAIN-PRIVACY

1. Challenger generates two valid chains $C_0, C_1$ of potentially different lengths, with identical `(handshakeScopeCommitment, policyFloor, agentRegistryRoot)` and both satisfying monotonic narrowing, with all participants enrolled.
2. Challenger flips bit $b$, generates proof $\pi_b$ from $C_b$ with fresh `blindingNonces` and `salt`.
3. $\mathcal{A}$ receives $\pi_b$ and all public outputs and public inputs. $\mathcal{A}$ also has access to the full on-chain state (all enrolled credential commitments, all stored scope commitments from prior handshakes). $\mathcal{A}$ outputs guess $b'$.
4. $\mathcal{A}$ wins if $\Pr[b' = b] > 1/2 + \text{negl}(\lambda)$.

### Security game: SCOPE-COMMITMENT-HIDING

This game isolates the specific brute-force threat that blinding nonces address.

1. Challenger enrolls $N$ agents with credential commitments $\{cc_1, \ldots, cc_N\}$ in the on-chain Merkle tree. $\mathcal{A}$ knows all $cc_j$ (leaves are public).
2. Challenger picks $b \leftarrow \{0, 1\}$, two scope values $s_0, s_1$ (both valid 8-bit bitmasks), a credential commitment $cc^*$, and a uniformly random blinding nonce $r \leftarrow \mathbb{F}_p$.
3. Challenger gives $\mathcal{A}$ the value $C = \text{Poseidon3}(s_b, cc^*, r)$.
4. $\mathcal{A}$ outputs guess $b'$. $\mathcal{A}$ wins if $\Pr[b' = b] > 1/2 + \text{negl}(\lambda)$.

Without the blinding nonce, this game is trivially won: $\mathcal{A}$ computes $\text{Poseidon2}(s_0, cc^*)$ and $\text{Poseidon2}(s_1, cc^*)$ and checks which equals $C$. With the blinding nonce, winning requires inverting Poseidon on a hidden input — reducing to Poseidon preimage resistance.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

- **A1**: Poseidon collision resistance and preimage resistance over the BN128 scalar field.
- **A2**: Discrete log hardness on Baby Jubjub (EdDSA unforgeability).
- **A3**: Knowledge soundness of PLONK with universal SRS (in the algebraic group model + ROM).

### Theorem 1 (CHAIN-NARROW-SOUNDNESS)

Under A1, A2, and A3, no PPT adversary wins CHAIN-NARROW-SOUNDNESS with non-negligible probability.

**Reduction sketch**: Suppose $\mathcal{A}$ produces an accepting proof. By A3, the PLONK extractor recovers a valid witness.

*Case (a) — narrowing violation*: The witness contains `scopes[i]` and `scopes[i+1]` for the violating hop where `isActive[i] = 1`. Gadget G1 enforces `scopeBits_next[j] * (1 - scopeBits_curr[j]) === 0` for all bits j when active. If the witness satisfies the constraint system, narrowing holds — contradiction. If the extractor fails, this breaks A3.

*Case (b) — phantom chain*: The witness contains `credCommitments[i]`, `merkleProofIndex[i]`, and `merkleProofSiblings[i]` for some active hop where `credCommitments[i]` is not a leaf in the tree with root $R$. Gadget G9 enforces `BinaryMerkleRoot(credCommitments[i], proof) = agentRegistryRoot` when `isActive[i] = 1`. If the witness satisfies this constraint, then either `credCommitments[i]` is genuinely a leaf (contradiction with the assumption), or the Merkle proof maps a non-leaf to the correct root, which requires finding a Poseidon collision in the Merkle hash chain — breaking A1.

The chain-linking constraint (G4) uses EdDSA verification per hop. If $\mathcal{A}$ forges a delegation token signature for an honest participant's hop, this breaks A2. The scope commitment binding (G3) prevents scope substitution: changing a scope while keeping the same scope commitment requires a Poseidon collision, breaking A1.

**Combined with enrollment**: Even if an adversary can produce valid narrowing and valid EdDSA signatures (using self-generated keys), the Merkle inclusion check (G9) ensures those keys correspond to credentials actually enrolled in the registry. Self-signed, unenrolled credentials cannot produce a valid Merkle proof against the on-chain root.

### Theorem 2 (CHAIN-PRIVACY)

Under A3 (zero-knowledge property of PLONK) and A1 (Poseidon preimage resistance), no PPT adversary wins CHAIN-PRIVACY with non-negligible probability.

**Reduction sketch**: The PLONK proof reveals nothing beyond the public outputs. Chain length is hidden because inactive hops produce identical blinded scope commitments and identical Merkle roots to the last active hop (G5), and the chain digest includes a private salt (G6), making the digest computationally indistinguishable between chains of different lengths with the same endpoints. The Merkle proofs are private inputs — the adversary sees only `agentRegistryRoot` (a public input shared by both challenge chains), not which leaves were proven or how many distinct leaves were accessed. The salt ensures the chain digest is a pseudorandom commitment under Poseidon's PRF properties (consequence of A1). Intermediate scopes, credential commitments, blinding nonces, and Merkle proof paths are private inputs, hidden by PLONK's zero-knowledge guarantee.

The blinded public outputs `rootScopeCommitment` and `finalScopeCommitment` differ between $C_0$ and $C_1$ (due to fresh `blindingNonces`), but are computationally indistinguishable from random field elements under Poseidon's preimage resistance (A1): given $\text{Poseidon3}(s, cc, r)$ where $r$ is uniform over $\mathbb{F}_p$, distinguishing this from a random field element requires finding the preimage — which reduces to breaking A1.

### Theorem 3 (SCOPE-COMMITMENT-HIDING)

Under A1 (Poseidon preimage resistance), no PPT adversary wins SCOPE-COMMITMENT-HIDING with non-negligible probability.

**Reduction sketch**: To distinguish $\text{Poseidon3}(s_0, cc^*, r)$ from $\text{Poseidon3}(s_1, cc^*, r)$ for unknown uniform $r$, the adversary must recover $r$ from one evaluation and check the other — this is a preimage attack on Poseidon. Specifically, suppose $\mathcal{A}$ wins with advantage $\epsilon$. We construct a Poseidon preimage finder $\mathcal{B}$: given target $C$, $\mathcal{B}$ picks $s_0, s_1, cc^*$, runs $\mathcal{A}$ on $C$, and uses $\mathcal{A}$'s guess to determine which preimage structure produced $C$. If $\epsilon$ is non-negligible, $\mathcal{B}$ breaks Poseidon preimage resistance, contradicting A1.

**Quantitative hardness**: Without blinding, the search space is $|\text{scopes}| \times |\text{enrolled agents}| = 256 \times N$ where $N$ is the number of enrolled agents. For $N = 10{,}000$, this is $2.56 \times 10^6$ Poseidon evaluations — trivially computable. With blinding, the search space is $|\mathbb{F}_p| \approx 2^{254}$ per candidate (scope, credCommitment) pair, making brute-force infeasible even for a single pair.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Blinded scope commitment per hop | `Poseidon3(permissionBitmask, credentialCommitment, blindingNonce)` | Extension of §4 Composable Delegation — same inputs plus blinding nonce |
| Unblinded scope commitment (internal, for chain linking) | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Composable Delegation (unchanged) |
| Delegation token hash | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | Delegation Circuit §4.2 (uses unblinded scope commitment — unchanged from spec) |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | §2.2 Cryptographic Primitives |
| Cumulative bit encoding | Bits 4→3→2 implication constraints | §AgentPolicy constraint 6 |
| Nullifier derivation | `Poseidon2(chainDigest, auditSessionNonce)` | Nullifier pattern from §3 |
| Proving system | PLONK with universal SRS (agent-class circuit) | §2.3 — PLONK OPTIONAL for Delegation |
| Permission bitmask | 8-bit (extendable to 64-bit) cumulative encoding | Permissions Model |
| Chain digest | Poseidon iterative hash (standard Poseidon2 chain over blinded commitments) | Uses Poseidon2 per spec |
| Registry enrollment proof | `BinaryMerkleRoot(MAX_DEPTH=20)` with `credCommitment` as leaf | §4.2 Delegation Circuit constraint 8 |
| Agent root history buffer | 30-entry circular buffer checked by on-chain verifier | §2.1 System Architecture |
| Handshake anchoring | `Poseidon2(scopes[0], credCommitments[0]) === handshakeScopeCommitment` | §4 chain seed from `lastScopeCommitment` mapping |

All cryptographic operations stay within the BN128 scalar field. The only new primitive operation is Poseidon3 (3-input Poseidon), which is a standard arity variant of the same Poseidon hash already used throughout Bolyra. The delegation token format (G4) remains identical to the existing Bolyra `Delegation` circuit — delegation tokens signed during the original per-hop flow verify correctly inside the audit circuit without re-signing.

## 6. Circuit cost estimate

### Constraint breakdown per hop

| Gadget | Constraints (approx) |
|---|---|
| Num2Bits(64) × 2 (scope + expiry) | 128 |
| Scope subset check (64 bit-AND constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| LessEqThan(64) for expiry narrowing | ~130 |
| Poseidon3 (blinded scope commitment — G3) | ~400 |
| Poseidon2 (unblinded scope commitment — G3 internal) | ~300 |
| Poseidon4 (delegation token) | ~600 |
| EdDSAPoseidonVerifier | ~5,500 |
| BinaryMerkleRoot(20) for enrollment (G9) | ~6,000 |
| Active-hop multiplexer (4 field muxes + 4 gating) | ~30 |
| **Per-hop total** | **~13,155** |

### Full circuit

| Component | Constraints |
|---|---|
| 16 hops × 13,155 | 210,480 |
| 15 chain-link verifications (hop 0 has no predecessor) | (included above) |
| Handshake anchoring — G3a (1 × Poseidon2 + 1 equality) | ~301 |
| Chain digest (16 × Poseidon2 over blinded commitments) | 4,800 |
| Audit nullifier (1 × Poseidon2) | 300 |
| Policy floor check (64 bit-AND) | 64 |
| LessThan(5) for actualLength × 16 | 160 |
| **Total** | **~216,105** |

This fits within 2^18 (262,144) constraints. Uses `pot18.ptau` or the universal PLONK SRS at depth 18.

### Proving time targets

| Proving system | Target | Rationale |
|---|---|---|
| PLONK (agent-class) | < 5s | Agent-class circuit per spec; within spec budget even at 2^18 |
| PLONK with rapidsnark | < 2s | Native prover for production |

The constraint increase from ~209K to ~216K (+3.2% from blinding) is marginal — well within the same 2^18 SRS. The `pot18.ptau` file is a standard Powers of Tau artifact available from the Hermez/iden3 ceremony repository. Verification cost on-chain is unchanged — PLONK verification is constant-time regardless of circuit size.

### Cost of blinding (G3 change)

The switch from `Poseidon2` to `Poseidon3` for blinded scope commitments adds ~100 constraints per hop (Poseidon3 uses a t=4 state vs t=3 for Poseidon2). The additional `Poseidon2` for the unblinded internal commitment adds ~300 per hop. At 16 hops this is ~6,400 additional constraints over the unblinded construction, plus ~301 for the handshake anchoring check — a total of ~6,700 constraints (~3.2% overhead). This is the cost of defeating scope commitment brute-force inversion.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI agent pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), the largest US credit union (13M+ members).

**Setup**: NFCU deploys an AI agent pipeline for member loan processing. The pipeline has 5 hops:

1. **Root agent** (member-facing chatbot): `READ_DATA | WRITE_DATA | ACCESS_PII` (bits 0,1,7 = bitmask `0b10000011`)
2. **Credit scoring tool**: `READ_DATA | ACCESS_PII` (bits 0,7 = `0b10000001`)
3. **Document verification tool**: `READ_DATA | ACCESS_PII` (bits 0,7 = `0b10000001`)
4. **Underwriting decision tool**: `READ_DATA` (bit 0 = `0b00000001`)
5. **Notification tool**: `WRITE_DATA` (bit 1 = `0b00000010`)

All five agents are enrolled in the on-chain agent Merkle tree via the standard `AgentPolicy` circuit (operator-signed credentials verified at enrollment time). The agent registry root $R$ is the public input `agentRegistryRoot`.

**Brute-force threat (now blocked)**: Without blinding nonces, the public outputs `rootScopeCommitment = Poseidon2(0b10000011, cc_chatbot)` and `finalScopeCommitment = Poseidon2(0b00000010, cc_notification)` are invertible. An NCUA examiner, competitor, or litigation opponent who knows the ~500 enrolled credential commitments (public leaves in the Merkle tree) can compute `256 × 500 = 128,000` Poseidon2 evaluations (< 1 second on commodity hardware) and identify: (a) which agent is the root (the chatbot), (b) its exact permission bitmask, (c) which agent is the terminal hop (the notification tool), and (d) its exact permission bitmask. This defeats the privacy claim. With blinding nonces, each scope commitment is `Poseidon3(scope, cc, r)` where `r` is a 254-bit random field element — brute force requires ~2^254 evaluations per candidate, which is infeasible.

**Audit flow**:

1. NFCU's compliance officer (auditor) receives `auditSessionNonce` from the registry.
2. The pipeline operator generates a `DelegationChainAudit` proof with `policyFloor = 0b00000001`, `agentRegistryRoot = R`, and `handshakeScopeCommitment` set to the unblinded scope commitment stored on-chain from the original handshake session.
3. The on-chain verifier checks `agentRegistryRoot` against the root history buffer and `handshakeScopeCommitment` against the `lastScopeCommitment` mapping before verifying the PLONK proof.
4. The PLONK proof is verified on-chain. The auditor sees:
   - `rootScopeCommitment`: blinded — cannot extract bitmask or identify the agent even by enumeration
   - `finalScopeCommitment`: blinded — same protection
   - `narrowingHolds = 1`: chain narrowed monotonically
   - `policyMet = 1`: final hop meets the floor
   - `chainDigest`: opaque commitment to chain structure (uses blinded commitments internally)
   - `auditNullifier`: replay-prevention value
   - `handshakeScopeCommitment`: links to a specific handshake (this is already on-chain — no new information leaked)
   - `agentRegistryRoot`: confirms the proof is anchored to real enrolled agents
5. The auditor does NOT learn: how many hops, what permissions each hop had, which agents participated, or which tools were called. The blinded scope commitment outputs cannot be correlated with on-chain enrollment data.

**Phantom chain attack (blocked by G9)**: A malicious operator cannot construct a synthetic chain with fabricated credential commitments — every active hop must produce a valid Merkle inclusion proof against `agentRegistryRoot`.

**Whistleblower variant**: A journalist's source uses an agent pipeline (source → anonymizer agent → secure drop agent → journalist's retrieval agent). All agents are enrolled in the registry. The blinded scope commitments ensure that even an adversary with full access to on-chain state (all enrolled credential commitments) cannot determine which agents are the chain endpoints.

**Cross-org handoff variant**: NFCU's loan pipeline hands off to a third-party appraisal service. The auditor at NCUA verifies the full chain narrowed across organizational boundaries, with every hop anchored to a registered agent, without learning which appraisal vendor was used — and without being able to invert the scope commitments to identify the vendor's agent even by exhaustive search.

## 8. Why the baseline cannot match

| Capability | DelegationChainAudit (this construction) | RFC 8693 + BBS+ + WIMSE baseline |
|---|---|---|
| **Hide intermediate scopes from auditor** | All scopes are private inputs; auditor sees only blinded root/final scope commitments (Poseidon3 with per-hop blinding nonce — infeasible to invert) | BBS+ cannot produce subset-predicate proofs over hidden bitmask values. Auditor must see both scopes to verify narrowing. |
| **Hide intermediate participants** | Credential commitments are private inputs; chain linking is enforced in-circuit via EdDSA + Poseidon binding | BBS+ hides participant_id per hop but breaks cross-hop chain integrity — the auditor cannot verify hop N's credential was issued to hop N+1's presenter without seeing the linking attribute. |
| **Single aggregated proof** | One PLONK proof (~1.5 KB) for the entire chain, verified in one on-chain call (~300K gas) | Auditor must process O(n) artifacts: n RFC 8693 tokens or n BBS+ derived proofs. No aggregation mechanism exists in any current spec. |
| **Conceal chain length** | Active-hop multiplexing pads all chains to MAX_HOPS; private salt in chain digest makes short and long chains computationally indistinguishable | Hop count is visible from artifact count. No mechanism to hide chain length. |
| **AS-blind auditing** | No authorization server mediates delegation. All narrowing enforcement is in-circuit. The auditor verifies a proof, not AS-signed records. | RFC 8693 structurally requires the AS at every hop. A compromised/subpoenaed AS reconstructs the full chain. |
| **Whistleblower-safe intermediary concealment** | Every intermediate node is hidden from auditor, from other nodes (each sees only its delegator), and from the proof itself (ZK property of PLONK). Blinded scope commitments prevent endpoint deanonymization via on-chain enumeration. | WIMSE binds workload identity to each hop (visible to verifier). BBS+ issuer knows each participant. No combination provides intermediary anonymity with chain integrity. |
| **Anchor to real registrations** | Every active hop proves Merkle inclusion of its credential commitment against the on-chain agent registry root (G9). Phantom chains with fabricated credentials are rejected. | RFC 8693 relies on AS enrollment checks — but the AS is trusted, not cryptographically verified. A colluding AS can issue tokens for non-existent entities. BBS+ credentials require an issuer, but the issuer-to-registry binding is policy-based, not cryptographic. |
| **Scope commitment brute-force resistance** | Blinding nonces (254-bit entropy) make scope commitment inversion infeasible even given full on-chain state (all enrolled credentials + all 256 scope values). Cost: 3.2% constraint overhead. | Not applicable — baseline exposes scopes directly to the auditor. No scope commitment scheme exists to brute-force or protect. |

**The fundamental gap**: the baseline's strongest tool (BBS+ selective disclosure) operates on individual credentials. It can hide attributes within a single credential presentation. But delegation chain audit requires a *cross-credential predicate* — proving a relationship between hidden values across multiple credentials. BBS+ has no mechanism for inter-credential predicates. Zero-knowledge circuits do this natively: the entire chain is the witness, and the circuit enforces predicates across all hops simultaneously — including enrollment verification against a shared Merkle root and blinded scope commitment outputs — outputting only the aggregate result. The blinding nonce addition closes the last practical deanonymization vector: without it, the theoretical ZK privacy guarantee was undermined by the small enumeration space of scopes × enrolled agents.
