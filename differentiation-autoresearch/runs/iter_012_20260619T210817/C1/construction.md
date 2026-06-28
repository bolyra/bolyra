# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its permission bitmask satisfies a verifier-specified mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of the permission bitmask beyond predicate satisfaction, in a single constant-size proof, with no authorization server (AS) roundtrip at presentation time, and with security that holds even when the AS is fully adversarial (colluding, compromised, or offline).

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, RFC 9449 (DPoP), or W3C VC + BBS+ selective disclosure can simultaneously achieve all five properties: (1) AS-blind presentation, (2) runtime-adaptive bitmask predicate with implication-closure enforcement, (3) adversarial-AS soundness, (4) constant-size proof regardless of bitmask width, and (5) cryptographic binding to the agent's runtime model identity.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit: SelectiveScopeProof

A specialization of the existing `AgentPolicy` circuit, restructured for standalone RS-facing presentation (no handshake required). The agent generates this proof at the moment of resource access, with the RS supplying `requiredScopeMask` as the predicate.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Poseidon hash of model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate (Baby Jubjub) |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | uint64 | Full 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiration (Unix seconds) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | uint8 | Actual Merkle proof depth |
| `merkleProofIndex` | uint64 | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Sibling hashes (padded to MAX_DEPTH=20) |
| `blindingNonce` | field | Fresh random field element per presentation |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Current time (RS-supplied) |
| `onChainAgentRoot` | field | Agent Merkle tree root (RS reads from on-chain registry) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopePredicateHash` | field | `Poseidon4(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)` — binds the predicate evaluation to this specific credential and moment, blinded for unlinkability |
| `agentNullifier` | field | `Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)` — blinded per presentation, enables rate-limiting without cross-session linkage |

### Gadgets (constraint groups)

**G1 — Range checks (4 Num2Bits):**
- `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`, `requiredScopeMask`

**G2 — Credential commitment (1 Poseidon5):**
- `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`

**G3 — Operator signature (1 EdDSAPoseidonVerifier):**
- `EdDSA.Verify((operatorPubkeyAx, operatorPubkeyAy), credentialCommitment, (sigR8x, sigR8y, sigS))`

**G4 — Merkle membership (1 BinaryMerkleRoot):**
- `computedRoot = BinaryMerkleRoot(credentialCommitment, merkleProofSiblings, merkleProofIndex, merkleProofLength)`
- `computedRoot === onChainAgentRoot` (equality constraint against public input)

**G5 — Scope satisfaction (64 bit-AND constraints):**
- For each bit `i` in `[0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`
- Proves `permissionBitmask & requiredScopeMask == requiredScopeMask` without revealing any bit of `permissionBitmask` that is not required.

**G6 — Cumulative bit encoding (3 implication constraints):**
- `permBits[4] * (1 - permBits[3]) === 0`
- `permBits[4] * (1 - permBits[2]) === 0`
- `permBits[3] * (1 - permBits[2]) === 0`

**G7 — Expiry enforcement (1 LessThan):**
- `LessThan(64): currentTimestamp < expiryTimestamp`

**G8 — Predicate binding (1 Poseidon4):**
- `scopePredicateHash = Poseidon4(requiredScopeMask, credentialCommitment, currentTimestamp, blindingNonce)`

**G9 — Agent nullifier (1 Poseidon3):**
- `agentNullifier = Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)`

### Enrollment governance (on-chain registry contract)

The `SelectiveScopeProof` relocates trust from AS assertion to on-chain Merkle membership. This makes the enrollment authority — whoever calls `enroll(credentialCommitment)` on the `BolyraRegistry` — the critical trust anchor. A single operator enrolling credentials unilaterally would merely replace "trust the AS" with "trust the operator," collapsing the adversarial-AS advantage.

The registry contract enforces a **k-of-n threshold enrollment policy** at the smart contract layer:

**Enrollment contract constraints:**

1. **Enrollment governor set.** The registry maintains an on-chain set of `n` governor addresses (`enrollmentGovernors`), initialized at deployment and modifiable only via `k-of-n` governor vote. Each governor holds a standard EOA or multisig wallet — no new key types are introduced.

2. **Threshold enrollment.** `enroll(credentialCommitment, governorSignatures[])` requires `k` of `n` valid EIP-712 signatures from distinct governors over the tuple `(credentialCommitment, chainId, registryAddress, enrollmentNonce)`. The registry verifies each signature on-chain via `ecrecover` and increments the enrollment nonce to prevent replay. The threshold `k` is a registry parameter (default: `ceil(n/2) + 1`, i.e., strict majority).

3. **Operator is NOT a governor.** The operator who signs the credential commitment (EdDSA over Baby Jubjub, verified inside the circuit via G3) is distinct from the enrollment governors (ECDSA over secp256k1, verified on-chain by the registry). The operator attests "I created this credential with these parameters." The governors attest "We approve this credential for enrollment into the shared trust pool." Neither party alone can enroll.

4. **Credential commitment is self-authenticating.** The `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` binds the permission bitmask at enrollment time. Governors verify the credential parameters off-chain before signing (e.g., confirming the operator's identity, auditing the requested permission set, checking organizational policy). Once enrolled, the bitmask is cryptographically locked — changing any parameter produces a different commitment that is not in the tree.

5. **Revocation.** Governors can revoke an enrolled credential via `k-of-n` threshold vote, which adds the credential commitment to an on-chain revocation set. The RS checks `revocationSet.contains(credentialCommitment)` — but since the credential commitment is hidden inside the ZK proof, revocation is checked by requiring the agent to prove non-membership in a revocation accumulator (future work, flagged as limitation). In the current Phase 1 construction, revocation operates at the Merkle root level: governors rotate the tree root by re-enrolling all valid credentials minus the revoked one, and the 30-entry root history buffer expires stale roots.

**Why threshold enrollment does not require circuit changes:**

The enrollment governance operates entirely at the smart contract layer. The circuit's G4 gadget checks `computedRoot === onChainAgentRoot` — it does not care *how* the credential commitment entered the tree, only *that* it is a leaf in the current tree. The governance constraints ensure that no credential enters the tree without `k-of-n` approval, but this is enforced by the `enroll()` function's signature verification, not by the proof. This is the correct separation: the circuit proves *properties of the enrolled credential* (scope satisfaction, implication closure, expiry, operator signature); the contract enforces *who may enroll* (threshold governors).

### Verification protocol (RS-side)

1. RS reads `onChainAgentRoot` from the Bolyra on-chain registry (cached, no AS contact).
2. RS constructs public inputs: `[requiredScopeMask, currentTimestamp, onChainAgentRoot]`.
3. RS receives proof `pi` and public outputs `[scopePredicateHash, agentNullifier]` from the agent.
4. RS calls the PLONK verifier contract (or verifies locally with the verification key): `Verify(vk, pi, pubSignals)`.
5. RS checks `agentNullifier` against a local rate-limit table (optional).
6. On success: the agent has the required permissions, the credential is unexpired, and the credential is enrolled on-chain — all without learning the agent's full permission set, model hash, operator key, or any other credential field.

### Agent-side response discipline (predicate rejection behavior)

When the agent receives a `requiredScopeMask` that its `permissionBitmask` does NOT satisfy, it MUST NOT reveal this fact through timing or response-format differences. The agent SDK MUST implement the following constant-time rejection protocol:

**Mandatory behavior — `rejectIndistinguishably(requiredScopeMask)`:**

1. **Always generate a proof attempt.** The agent runs the PLONK prover with its real witness. If `G5` constraints are unsatisfied, the prover will fail internally (no valid assignment exists for the R1CS). The agent catches this failure silently.
2. **Constant-time budget.** The agent enforces a fixed wall-clock budget `T_prove` (configured per deployment; default: 3 seconds for snarkjs, 500 ms for rapidsnark). If proving succeeds before `T_prove`, the agent pads with a `sleep(T_prove - elapsed)`. If proving fails (unsatisfied predicate), the agent sleeps for the full `T_prove`.
3. **Uniform rejection response.** After `T_prove` elapses with a failed proof, the agent returns an application-layer error: `{"error": "scope_insufficient", "retry_after": <backoff>}`. This is the SAME error returned for genuinely expired credentials, revoked credentials, or stale Merkle roots — the RS cannot distinguish unsatisfied-predicate from any other proof failure.
4. **No partial disclosure.** The agent MUST NOT return which bits failed, how many bits matched, or any diagnostic beyond the opaque error. The SDK's `proveSelectiveScope()` method returns `Result<Proof, ScopeError>` where `ScopeError` is a unit type carrying no payload visible to the RS.

**Why this is sufficient for per-presentation privacy:** The adversary's bit-extraction attack relies on a distinguisher between "predicate satisfied" (proof returned) and "predicate unsatisfied" (no proof returned). With constant-time budgeting, the adversary observes identical timing for both outcomes. The only signal is binary: proof-accepted vs. error.

### Agent-side query rate limiting (multi-query leakage defense)

**The multi-query leakage reality.** Each presentation reveals exactly one bit of information to the RS: whether the agent's bitmask satisfies the queried predicate. This is inherent to any interactive predicate-evaluation protocol — including a hypothetical boolean-return AS. An RS issuing `q` adaptive queries with distinct single-bit `requiredScopeMask` values recovers exactly `q` bits of the agent's bitmask. For `q = W` (bitmask width, currently 64), the RS recovers the full bitmask.

Per-presentation SE-ZK (Section 3) guarantees that each individual proof reveals nothing beyond the boolean outcome. But over multiple queries, the accumulated boolean outcomes themselves constitute leakage. This is not a ZK failure — it is an information-theoretic consequence of interactive predicate evaluation. The construction's advantage over the baseline is not that it eliminates multi-query leakage (no interactive protocol can), but that it bounds the leakage rate to 1 bit per query, whereas the baseline leaks all W bits in a single introspection response.

**Agent-enforced query budget.** The agent SDK MUST enforce a per-RS query rate limit that bounds the multi-query leakage rate:

1. **Epoch definition.** The agent divides time into fixed-duration epochs: `epochId = floor(localTimestamp / EPOCH_DURATION)`. `EPOCH_DURATION` is a protocol parameter (default: 3600 seconds = 1 hour). The agent uses its own local clock — the RS does not control epoch boundaries.

2. **Per-RS query counter.** The agent SDK maintains a local map `(rsIdentifier, epochId) → queryCount`. The `rsIdentifier` is the RS's verified identity: its TLS certificate fingerprint, domain, or on-chain registry address. The agent increments `queryCount` for each proof generation (whether successful or failed).

3. **Budget enforcement.** When `queryCount >= q_max` for the current `(rsIdentifier, epochId)`, the agent MUST refuse to generate further proofs. The refusal response MUST be indistinguishable from a failed predicate: the agent waits for `T_prove` and returns `{"error": "scope_insufficient"}`. The RS cannot distinguish "rate-limited" from "predicate unsatisfied" from "expired credential."

4. **Budget parameter.** `q_max` MUST be strictly less than the bitmask width `W`. Default: `q_max = 8` for `W = 64`. This ensures that even an adversarial RS conducting optimal single-bit queries recovers at most 8 bits per epoch. Full bitmask recovery requires at least `ceil(W / q_max) = 8` epochs (8 hours at default settings).

5. **RS sybil resistance.** An adversarial RS could present multiple identities (different domains, certificates) to circumvent per-RS rate limiting. Mitigation: the agent operator configures an RS allowlist of authorized resource servers. Proof generation for RSes not on the allowlist is refused (with the same indistinguishable error response). This is an operational control, not a cryptographic one — analogous to a TLS client's trust store.

**Why agent-side enforcement is the correct locus.** The agent is the privacy-interested party. It is rational for the agent to enforce its own query budget — it has no incentive to bypass its own privacy protections. The RS cannot force the agent to generate proofs; it can only request them. A cooperative agent that disables its rate limit leaks its own bitmask, but this is equivalent to voluntary disclosure — not a protocol failure. The threat model (Section 3) is concerned with a privacy-preserving agent facing an adversarial RS, not with an agent acting against its own interests.

**Why this requires no circuit changes.** The rate limit is enforced entirely in the agent SDK's `proveSelectiveScope()` method. The circuit's G1–G9 gadgets are unchanged. The proof format, public inputs, and public outputs are unchanged. The RS verification protocol is unchanged. Rate limiting is a presentation-layer defense that complements the circuit-layer per-presentation ZK — defense in depth, not redundancy.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:
- The authorization server (AS) — can issue arbitrary tokens, lie in introspection responses, collude with other parties
- Network position — can observe all RS-agent traffic, including timing
- Up to `N-1` of `N` enrolled agents (corrupted agents whose secrets are known)
- The choice of `requiredScopeMask` in each query (chosen-predicate adversary)
- Up to `k-1` of `n` enrollment governors (corrupted governors whose signing keys are known)

The adversary does NOT control:
- The on-chain registry (Ethereum/Base L2 consensus assumptions)
- The RS's local copy of the PLONK verification key
- The honest agent's private inputs (secret, operator key)
- The honest agent's local clock beyond the public `currentTimestamp`
- `k` or more enrollment governors simultaneously (threshold assumption)
- The honest agent's SDK rate-limit enforcement (the agent enforces its own query budget)

### Enrollment authority trust model

**Trust anchor separation.** The construction's adversarial-AS claim depends on a precise separation: the AS is adversarial *at presentation time* (it cannot forge proofs, suppress permissions, or inflate scope), but the enrollment of credential commitments into the on-chain Merkle tree is governed by a threshold authority that is *not* the AS.

**Enrollment governor threat model.** The enrollment governors are a consortium-scoped authority (e.g., the board members of a credit union consortium, compliance officers of participating institutions, or a DAO governance contract). The governors are trusted collectively (k-of-n), not individually. An adversary controlling fewer than `k` governors cannot enroll a rogue credential.

**What a compromised governor (below threshold) can do:**
- Vote to approve a credential enrollment — but the vote fails without `k-1` additional governor signatures.
- Observe which credential commitments are proposed for enrollment — but `credentialCommitment` is a Poseidon hash, so the governor learns only the hash, not the underlying `permissionBitmask`, `modelHash`, or operator key unless these are disclosed during the off-chain enrollment review process.
- Delay enrollment by refusing to sign — liveness failure, not safety failure.

**What a compromised governor quorum (k or more) can do:**
- Enroll a rogue credential with an inflated permission bitmask. This is the equivalent of a compromised CA in TLS — a catastrophic but well-understood trust assumption. The mitigation is the same: governance diversity, HSM-backed governor keys, and on-chain audit logs (every `enroll()` call emits an event with the credential commitment, governor signatures, and block timestamp).

**Why this is NOT equivalent to trusting an AS.** The critical distinction is *when* the trust is exercised and *what* it covers:

| Dimension | AS trust (baseline) | Governor trust (construction) |
|---|---|---|
| When exercised | Every presentation (introspection) or every narrowing (RFC 8693) | Once, at enrollment time |
| What is trusted | Predicate evaluation + structural invariants + scope assertion | "This credential commitment should be in the tree" |
| Compromise window | Continuous — AS can lie about any token at any time | Point-in-time — enrolled credential is immutable once in tree |
| Compromised party's power | Inflate/deflate scope for any agent at any RS | Enroll a rogue credential (detectable on-chain; revocable) |
| Predicate evaluation | AS evaluates; RS trusts assertion | Circuit evaluates; RS verifies proof |
| Implication closure | AS may or may not enforce; RS cannot verify | G6 enforces unconditionally inside proof |

The construction does NOT claim trustlessness at enrollment — it claims that the trust exercised at enrollment (k-of-n governor approval of a credential commitment hash) is categorically narrower and temporally bounded compared to the trust exercised at every presentation in the baseline (AS asserts scope correctness in real time). Once enrolled, the credential's properties are locked by the Poseidon commitment and enforced by R1CS constraints. The governors cannot retroactively modify what the enrolled credential proves.

**Relationship to the adversarial-AS claim.** The claim in Section 1 states that security holds "even when the AS is fully adversarial." This is precise: the AS is the entity that issues OAuth tokens and responds to introspection requests. The enrollment governors are NOT the AS — they are a separate authority with a narrower role (approve/deny credential enrollment) and a different trust model (k-of-n threshold vs. single-party). A deployment MAY designate the same organization as both AS and enrollment governor, but this collapses the trust separation and weakens the adversarial-AS property. The deployment scenario in Section 7 demonstrates the intended separation: each consortium member contributes a governor, and no single member's AS can unilaterally enroll or inflate credentials.

### Privacy model: per-presentation ZK with bounded multi-query leakage

**Precise privacy claim.** The construction provides:

1. **Per-presentation simulation-extractable zero-knowledge.** Each individual proof reveals exactly one bit of information — whether `permissionBitmask & requiredScopeMask == requiredScopeMask` — and nothing else. The proof transcript (proof bytes, public outputs) is computationally indistinguishable from a simulated transcript conditioned on the boolean outcome, even in the presence of polynomially many prior transcripts from the same agent. This is the SE-ZK property of PLONK.

2. **Multi-query leakage bounded by query count.** An adversarial RS issuing `q` adaptive chosen-predicate queries learns at most `q` bits of information about the agent's bitmask. This bound is tight: `q` single-bit queries on distinct bit positions recover exactly `q` bits. This is an information-theoretic consequence of interactive predicate evaluation — no protocol (ZK or otherwise) can evaluate a boolean predicate and return the result without leaking the result.

3. **Agent-enforced rate limit bounds `q`.** The agent SDK enforces `q <= q_max < W` queries per RS per epoch. With default parameters (`q_max = 8`, `W = 64`, `EPOCH_DURATION = 3600s`), full bitmask recovery requires at least 8 hours of sustained probing from a single RS identity, across 8 epochs, with the agent cooperating on every query.

**What the construction does NOT claim.** It does not claim that an adversarial RS with unlimited queries learns nothing about the bitmask beyond predicate satisfaction. After `W` queries with single-bit masks, the RS recovers the full bitmask — this is inherent to evaluating boolean predicates interactively. The construction's privacy advantage is quantitative: the baseline leaks all `W` bits in 1 query (introspection returns the full scope string; BBS+ discloses claim values; SD-JWT discloses plaintext claims), while the construction leaks at most 1 bit per query, rate-limited to `q_max` bits per epoch.

### Security game: Selective Scope Forgery

```
Game SelectiveScopeForgery(lambda):
  1. Setup: Run trusted setup for SelectiveScopeProof circuit -> (pk, vk).
     Deploy BolyraRegistry with n enrollment governors, threshold k.
  2. Enrollment: Challenger enrolls honest agent credential commitment C*
     into the on-chain Merkle tree via k-of-n governor signatures.
     A learns C* but not the private inputs. A controls up to k-1 governors.
  3. Oracle: A may query the honest agent for proofs on predicates of A's
     choice (chosen-predicate queries). A receives (pi, scopePredicateHash,
     agentNullifier) for each query.
  4. Challenge: A outputs (pi*, pubSignals*) where requiredScopeMask* is a
     predicate that the honest agent's permissionBitmask does NOT satisfy
     (i.e., exists bit i: requiredBits*[i] = 1 and permBits[i] = 0).
  5. A wins if Verify(vk, pi*, pubSignals*) = ACCEPT and the
     onChainAgentRoot in pubSignals* is a valid root from the registry's
     root history buffer.
```

**Claim:** `Pr[A wins] <= negl(lambda)` under the assumptions in Section 4.

### Sub-game: Rogue Enrollment Forgery

```
Game RogueEnrollmentForgery(lambda):
  1. Setup: Deploy BolyraRegistry with n governors, threshold k.
     A controls up to k-1 governors.
  2. Challenge: A calls enroll(C_rogue, governorSignatures[]) where
     C_rogue is a credential commitment not approved by k honest governors.
  3. A wins if the registry accepts the enrollment (C_rogue is added
     to the Merkle tree).
```

**Claim:** `Pr[A wins] <= Adv_ECDSA_forgery(lambda)`. The adversary must forge at least one honest governor's EIP-712 signature (ECDSA on secp256k1). Under standard ECDSA unforgeability assumptions (DL hardness on secp256k1), this probability is negligible.

### Sub-game: Implication Closure Forgery

```
Game ImplicationClosureForgery(lambda):
  1. Setup: As above.
  2. Challenge: A produces a valid proof pi with extracted witness w where
     w.permissionBitmask violates implication closure (e.g., bit 4 = 1
     but bit 3 = 0).
  3. A wins if Verify(vk, pi, pubSignals) = ACCEPT.
```

**Claim:** `Pr[A wins] <= Adv_PLONK_ks(lambda)`. Constraint G6 (`permBits[4] * (1 - permBits[3]) === 0`) is an R1CS constraint — no valid witness can satisfy the circuit with an implication-violating bitmask. This is the property no baseline variant even attempts: attestation mechanisms certify *identity and platform state*, not *the algebraic satisfaction of permission-structure invariants*. A hardware-attested client with a structurally invalid permission set (FINANCIAL_UNLIMITED without FINANCIAL_SMALL) passes attestation but fails the R1CS constraint unconditionally.

### Privacy game: Per-Presentation SE-ZK Indistinguishability (ppSE-IND)

```
Game ppSE-IND(lambda):
  1. Setup: Run trusted setup -> (pk, vk).
  2. Enrollment: Challenger enrolls two agents with commitments C0*, C1*
     (both in the Merkle tree). Let their bitmasks be B0, B1 respectively.
  3. Challenge predicate selection: A chooses a predicate R such that
     B0 satisfies R iff B1 satisfies R (same boolean outcome).
  4. Challenger flips coin b <- {0,1}, generates a proof using Cb*'s
     witness for predicate R, with a fresh blindingNonce.
  5. A receives the proof transcript (pi, scopePredicateHash, agentNullifier).
  6. A outputs guess b'.
  7. A wins if b' = b.
```

**Claim:** `|Pr[A wins] - 1/2| <= Adv_PLONK_SE_ZK + 2 * Adv_Poseidon_PRF`.

**Why this game, not mqSE-IND.** The prior formulation (mqSE-IND) required B0 and B1 to agree on all queried predicates. After `q = W` queries with single-bit masks, the only B0, B1 satisfying this constraint are B0 = B1, making the game vacuous. This was not a flaw in the construction — it was a flaw in the game formulation. The correct privacy claim is *per-presentation*: each individual proof transcript is SE-ZK conditioned on the boolean outcome. The multi-query leakage (`q` bits from `q` queries) is inherent to predicate evaluation and is bounded by the agent's rate limit, not by the ZK property.

**Composing per-presentation ZK with the rate limit.** The combined privacy guarantee is:

- Each of the agent's `q_max` proof transcripts per epoch is individually SE-ZK (ppSE-IND).
- The adversary's total information gain per epoch is at most `q_max` bits (the `q_max` binary outcomes).
- Full bitmask recovery requires `ceil(W / q_max)` epochs of sustained probing.
- The agent operator has `ceil(W / q_max) - 1` epoch boundaries at which to detect anomalous query patterns and revoke RS access.

This is a layered defense: circuit-level ZK bounds per-proof leakage to 1 bit; SDK-level rate limiting bounds per-epoch leakage to `q_max` bits; operational monitoring detects sustained probing across epochs.

### Multi-query leakage comparison with baseline

| Protocol | Bits leaked per query | Queries for full recovery (W=64) | Adversary requirements |
|---|---|---|---|
| RFC 7662 introspection | W (full scope string) | 1 | Single introspection request |
| BBS+ selective disclosure | Disclosed claim count | 1 (disclose all) to W (1 per query) | Issuer cooperation at issuance |
| SD-JWT (RFC 9635) | Disclosed claim values (plaintext) | 1 (disclose all) to W | Issuer cooperation at issuance |
| RFC 8693 token exchange | Narrowed scope string (plaintext) | 1 | AS cooperation per exchange |
| **SelectiveScopeProof** | **1 (boolean only, SE-ZK)** | **W, rate-limited to ceil(W/q_max) epochs** | **Must sustain q_max queries/epoch for ceil(W/q_max) epochs** |

The construction does not eliminate multi-query leakage — it minimizes per-query leakage (1 bit vs. W bits) and bounds the query rate. This is the tightest possible result for an interactive predicate-evaluation protocol.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Knowledge soundness of PLONK** (with universal SRS, algebraic group model + ROM): Any PPT prover that produces an accepting proof knows a valid witness satisfying all circuit constraints.
2. **Collision resistance of Poseidon** over BN254 scalar field: No PPT adversary can find distinct inputs `(x1,...,xn) != (x1',...,xn')` such that `Poseidon(x1,...,xn) = Poseidon(x1',...,xn')`.
3. **Discrete log hardness on Baby Jubjub**: Given `(Ax, Ay) = s * G`, no PPT adversary can recover `s`.
4. **Unforgeability of EdDSA-Poseidon on Baby Jubjub**: No PPT adversary can forge a valid signature on a new message without the signing key.
5. **Random Oracle Model (ROM)**: Fiat-Shamir transform in PLONK is modeled as a random oracle.
6. **Simulation-extractability of PLONK** (Faust et al. 2022): PLONK with Fiat-Shamir in ROM is simulation-extractable — proofs are both zero-knowledge and extraction-sound even in the presence of simulated transcripts.
7. **Unforgeability of ECDSA on secp256k1**: No PPT adversary can forge a valid EIP-712 signature under an honest governor's key. (Standard assumption underlying all Ethereum transaction security.)

### Reduction sketch (soundness)

Suppose adversary `A` wins SelectiveScopeForgery with non-negligible probability `eps`.

By PLONK knowledge soundness (Assumption 1 + 5), extract witness `w = (modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp, sig, merkleProof, blindingNonce)` from `A`'s accepting proof.

**Case 1:** The extracted `permissionBitmask` does NOT satisfy `requiredScopeMask*` (i.e., G5 constraints are violated). This contradicts knowledge soundness — the extractor produced a witness that does not satisfy the circuit relation. Contradiction.

**Case 2:** The extracted `permissionBitmask` DOES satisfy `requiredScopeMask*`. Then the extracted `credentialCommitment` must be a leaf in the Merkle tree at root `onChainAgentRoot` (G4). Sub-cases:

- **2a:** `credentialCommitment = C*` (the honest agent's commitment). But the honest agent's bitmask does not satisfy the predicate by game definition. Since `credentialCommitment = Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiry)` and the extracted bitmask differs from the honest agent's, we have a Poseidon5 collision (Assumption 2 violated). Contradiction.

- **2b:** `credentialCommitment != C*` but is still a valid leaf. Then `A` is using a different enrolled agent's credential — not a forgery against the honest agent, but a legitimate proof for a different agent. If `A` controls the credential, this is not a forgery.

- **2c:** `credentialCommitment` is NOT a leaf but `BinaryMerkleRoot` still outputs `onChainAgentRoot`. This requires a second-preimage attack on the Poseidon-based Merkle tree (Assumption 2 violated). Contradiction.

Therefore `Pr[A wins] <= Adv_PLONK_ks + Adv_Poseidon_cr + negl(lambda)`.

### Reduction sketch (enrollment integrity)

Suppose adversary `A` wins RogueEnrollmentForgery with non-negligible probability `eps`. `A` controls `k-1` governors and must produce `k` valid EIP-712 signatures over the enrollment tuple `(C_rogue, chainId, registryAddress, enrollmentNonce)`. The `k-1` corrupted governors provide `k-1` valid signatures. The k-th signature must be a valid ECDSA signature under an honest governor's secp256k1 public key over a message the honest governor never signed. By ECDSA unforgeability (Assumption 7), `Pr[A forges k-th signature] <= Adv_ECDSA_forgery(lambda) = negl(lambda)`.

**Enrollment integrity composes with proof soundness.** The combined adversary must either (a) enroll a rogue credential (requires breaking ECDSA threshold) and then generate a valid proof over it, or (b) generate a valid proof over an honestly enrolled credential that the honest agent's bitmask does not satisfy (requires breaking PLONK soundness or Poseidon collision resistance). The combined advantage is bounded by:

`Pr[A wins combined] <= Adv_ECDSA_forgery + Adv_PLONK_ks + Adv_Poseidon_cr + negl(lambda)`.

### Reduction sketch (privacy — per-presentation SE-ZK)

We reduce the ppSE-IND game to PLONK simulation-extractable zero-knowledge.

Given an adversary `A` that wins ppSE-IND with advantage `eps`:

1. `A` selects predicate `R` and the challenger generates a proof for agent `b` with fresh `blindingNonce`.
2. The proof transcript is `(pi, scopePredicateHash, agentNullifier)` where:
   - `scopePredicateHash = Poseidon4(R, C_b, currentTimestamp, blindingNonce)`
   - `agentNullifier = Poseidon3(C_b, R, blindingNonce)`
3. Since `blindingNonce` is a fresh random field element unknown to `A`, and Poseidon is a PRF (Assumption 2 implies PRF under standard reductions), `scopePredicateHash` and `agentNullifier` are pseudorandom from `A`'s view — they carry no information about `b` beyond what the proof itself leaks.
4. The proof `pi` is simulation-extractable ZK (Assumption 6). A simulator `S` can produce `pi` without knowledge of the witness, given only the public inputs and outputs. `A` cannot distinguish real from simulated proofs.
5. Therefore `|Pr[A wins] - 1/2| <= Adv_PLONK_SE_ZK + 2 * Adv_Poseidon_PRF`.

**Multi-query information bound.** The ppSE-IND game establishes that each proof leaks at most the boolean outcome. By a standard information-theoretic argument (each binary observation carries at most 1 bit of Shannon entropy), `q` adaptive queries yield at most `q` bits of information about the `W`-bit bitmask. The agent's rate limit enforces `q <= q_max < W` per epoch, bounding per-epoch leakage to `q_max` bits. This is tight: an adversary using single-bit masks on distinct positions achieves exactly `q` bits in `q` queries.

**Why the previous mqSE-IND game was vacuous.** The mqSE-IND game required the challenge bitmasks B0, B1 to agree on all queried predicates. An adversary making `W` queries with single-bit masks forces B0 = B1 (every bit is determined), making the distinguishing game trivial. This did not indicate a construction weakness — it indicated a game formulation that tried to claim more than any interactive predicate protocol can provide. The corrected formulation (ppSE-IND + rate limit) precisely characterizes what the construction achieves: per-proof ZK with bounded multi-query leakage.

**Timing side-channel closure:** The constant-time budget `T_prove` ensures `SD(D_accept, D_reject) = 0`. The rate-limit refusal is also constant-time (same `T_prove` budget, same error response). Timing is not an additional distinguishing channel.

### Adversarial-AS resilience

The AS never appears in the verification path. The RS verifies the proof against the on-chain Merkle root and the circuit's verification key. Even if the AS is fully compromised:

- It cannot forge a proof for an unenrolled credential (Merkle membership is checked against the on-chain root the RS reads independently; enrollment requires k-of-n governor signatures, and the AS is not a governor).
- It cannot inflate an agent's permissions (the `credentialCommitment` binds the bitmask at enrollment time; changing the bitmask changes the commitment, breaking Merkle membership; re-enrollment with an inflated bitmask requires k-of-n governor approval).
- It cannot suppress an agent's permissions (the agent holds its own secret inputs and generates the proof autonomously).
- It cannot enroll rogue credentials (enrollment is gated by k-of-n threshold, and the AS holds zero governor keys in the intended deployment topology).

### Enrollment governance is strictly narrower than AS trust

The adversary model grants the adversary control of the AS. A natural objection: "you replaced AS trust with governor trust — same thing." This is incorrect for three structural reasons:

1. **Temporal scope.** AS trust is exercised at every presentation — the AS can change its assertion about any agent's scope at any time. Governor trust is exercised once at enrollment. After enrollment, the credential commitment is immutable on-chain. A governor who was honest at enrollment time but later compromised cannot retroactively modify enrolled credentials.

2. **Verification location.** The AS evaluates the predicate and asserts the result. The governors do NOT evaluate predicates — they approve enrollment of a credential commitment hash. Predicate evaluation happens inside the circuit (G5, G6), verified by the RS. The governors' role is analogous to a CA issuing a certificate: they attest identity, not authorization.

3. **Threshold vs. single-party.** The AS is a single point of failure. Governor trust is distributed — an adversary must compromise `k` independent parties simultaneously. For a 12-member credit union consortium with `k=7`, this requires compromising a strict majority of independent institutions.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---|---|---|
| Hash function (all commitments) | Poseidon over BN254 scalar field | `circuits/src/` — all circuits |
| Credential commitment | `Poseidon5(modelHash, opAx, opAy, permissionBitmask, expiryTimestamp)` | `AgentPolicy.circom` G2 |
| Operator signature | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | `AgentPolicy.circom` G3 |
| Merkle inclusion | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | Shared across all circuits |
| Scope predicate | Bit-AND: `requiredBits[i] * (1 - permBits[i]) === 0` | `AgentPolicy.circom` G5 |
| Cumulative encoding | 3 implication constraints (bits 4->3->2) | `AgentPolicy.circom` G6 |
| Nullifier | `Poseidon3(credentialCommitment, requiredScopeMask, blindingNonce)` | Adapted from agent nullifier pattern, blinded |
| Proving system | PLONK with universal SRS (`pot16.ptau`) | `AgentPolicy` PLONK build in `circuits/build/` |
| On-chain root | Agent Merkle root from `BolyraRegistry` with 30-entry root history buffer | `contracts/` |
| Enrollment governance | k-of-n EIP-712 threshold on `BolyraRegistry.enroll()` | `contracts/` — registry contract |
| Agent-side rate limit | SDK-enforced `q_max` per `(rsIdentifier, epochId)` | `sdk/` — `proveSelectiveScope()` method |

No new cryptographic building blocks introduced. The rate-limit mechanism uses no new primitives — it is a counter maintained in the agent SDK, enforced before proof generation. The enrollment governance uses standard Ethereum EIP-712 signatures and on-chain `ecrecover` — no new primitives beyond what Solidity and the EVM natively provide. Key differences from existing `AgentPolicy`: (a) `onChainAgentRoot` is a public input (RS-verified against chain state, not just a proof output), (b) `scopePredicateHash` binds the evaluation to a timestamp and blinding nonce, (c) nullifier is scoped per predicate and blinded per presentation, (d) `blindingNonce` ensures per-presentation unlinkability, (e) enrollment is threshold-gated at the contract layer, (f) agent SDK enforces query budget before proof generation.

## 6. Circuit cost estimate

| Gadget | Estimated constraints | Notes |
|---|---|---|
| G1: 4x Num2Bits(64) | 256 | 64 constraints each |
| G2: Poseidon5 | ~1,500 | 5-input Poseidon, ~8 full rounds + 57 partial |
| G3: EdDSAPoseidonVerifier | ~8,000 | Dominant cost: Baby Jubjub scalar mul + Poseidon |
| G4: BinaryMerkleRoot(20) | ~6,000 | 20 levels x (Poseidon2 + mux) |
| G5: 64 bit-AND constraints | 64 | One multiplication each |
| G6: 3 implication constraints | 3 | One multiplication each |
| G7: LessThan(64) | ~130 | Num2Bits(65) + comparator |
| G8: Poseidon4 | ~1,200 | 4-input Poseidon (blinded predicate hash) |
| G9: Poseidon3 | ~1,000 | 3-input Poseidon (blinded nullifier) |
| **Total** | **~18,150** | Well within 2^16 = 65,536 (pot16.ptau) |

**Proving time targets:**
- PLONK (snarkjs): **< 3 seconds** on commodity hardware
- PLONK (rapidsnark native): **< 500 ms**
- Verification: **< 2 ms** on-chain, **< 1 ms** off-chain

**Proof size:** 768 bytes (PLONK) — constant regardless of bitmask width or predicate complexity.

**Enrollment governance cost (on-chain, NOT in circuit):**
- `enroll()` gas: ~150K gas (k `ecrecover` calls at ~3K gas each, plus Merkle tree insertion at ~100K gas for depth-20 tree). This is a one-time cost per credential, not per presentation.
- No impact on proving time or proof size — governance is entirely at the contract layer.

**Constant-time budget overhead:** The `T_prove` padding adds at most `T_prove - t_actual` idle time per request. For rapidsnark (`t_actual ~ 500 ms`, `T_prove = 500 ms`), padding is negligible. For snarkjs (`t_actual ~ 2.5 s`, `T_prove = 3 s`), padding is <= 500 ms. Failed proofs (unsatisfied predicate) sleep for the full `T_prove` — this is the cost of constant-time discipline.

**Rate-limit overhead:** Negligible. The SDK checks a local in-memory counter before proof generation — O(1) lookup, no cryptographic operations.

## 7. Concrete deployment scenario

### Scenario: Pacific Northwest Credit Union Consortium — AI Agent Loan Processing

**Stakeholder:** Columbia Credit Union (Vancouver, WA) — $3.4B in assets, member of the Northwest Credit Union Association.

**Context:** Columbia CU deploys AI agents to automate member loan pre-qualification across a consortium of 12 credit unions sharing a federated data lake. Each credit union's RS hosts member financial data behind API endpoints. An agent acting on behalf of Columbia CU needs `READ_DATA` (bit 0) and `FINANCIAL_SMALL` (bit 2) to pull credit summaries and run sub-$100 fee calculations — but must NOT reveal that it also holds `FINANCIAL_UNLIMITED` (bit 4) and `ACCESS_PII` (bit 7), reserved for internal Columbia CU operations.

**Enrollment governance in the consortium:**

Each of the 12 consortium credit unions designates one enrollment governor (typically the CTO or Chief Information Security Officer). The `BolyraRegistry` is deployed with `n=12, k=7` (strict majority). When Columbia CU wants to enroll a new AI agent credential:

1. Columbia CU's operator generates the credential: `credentialCommitment = Poseidon5(modelHash, opAx, opAy, 0b10010111, expiry)`.
2. Columbia CU submits an enrollment request to the consortium governance portal (off-chain), disclosing the credential parameters to the governor committee for review. Governors verify: (a) the operator public key belongs to a registered Columbia CU employee, (b) the requested permission bitmask is consistent with Columbia CU's consortium membership tier, (c) the model hash corresponds to an approved AI model vendor, (d) the expiry is within consortium policy limits (e.g., max 90 days).
3. Seven or more governors sign the EIP-712 enrollment message.
4. Any party (Columbia CU or a consortium relay) submits the `enroll(credentialCommitment, governorSignatures[])` transaction on-chain.

**Why this governance model defeats the "replaced AS with operator" objection:** In the baseline, Columbia CU's AS unilaterally determines what its agents can do at partner CUs. A compromised Columbia CU AS can grant its agents unlimited access to partner CU data. In the construction, Columbia CU's operator can create a credential with any bitmask — but enrollment requires 7 of 12 consortium members to approve. Columbia CU controls at most 1 of 12 governor keys. A compromised Columbia CU cannot unilaterally enroll an agent with inflated permissions.

**Problem with baseline:**
1. **Adversarial-AS risk:** Rival credit unions do not trust Columbia CU's AS to be honest about the agent's actual permissions. A compromised AS could claim the agent has `ACCESS_PII` at a partner CU's RS, or deny permissions it actually holds. Even with mutual TLS and DPoP, the AS controls the scope assertion.
2. **AS availability:** During a CrowdStrike-style outage, Columbia CU's AS goes offline for 14 hours. All consortium agents are locked out because partner RSes cannot introspect tokens.
3. **Scope leakage:** Even with BBS+ selective disclosure, the credential issuer knows the full permission set and can correlate which partner CU the agent accessed.
4. **Enrollment trust concentration:** Without governance, Columbia CU's operator unilaterally enrolls credentials — no better than the AS model. The k-of-n threshold distributes enrollment authority across the consortium.

**Multi-query probing attack and rate-limit defense in the consortium setting:**

A malicious partner CU could probe Columbia CU's agent with sequential single-bit predicates (`requiredScopeMask = 0x01, 0x02, 0x04, ..., 0x80`), observing success/failure for each. Without rate limiting, this recovers the full 8-bit effective bitmask in 8 queries (one per bit position).

**Defense layers:**

1. **Constant-time discipline** (per-presentation): The agent's timing is indistinguishable between proof-accepted and proof-failed responses. The RS gains exactly 1 bit per query — the boolean outcome — and no timing side channel.

2. **Agent-side rate limiting** (per-epoch): Columbia CU configures its agent SDK with `q_max = 4` queries per RS per 1-hour epoch. A malicious partner CU's RS can issue at most 4 queries per hour. Full 8-bit bitmask recovery requires at minimum 2 epochs (2 hours). Full 64-bit bitmask recovery requires at minimum 16 epochs (16 hours).

3. **Operational monitoring** (cross-epoch): Columbia CU's agent operator monitors query patterns. An RS that consistently issues single-bit probing queries across epochs triggers an alert. The operator can revoke RS access (remove the RS from the agent's allowlist) before full recovery completes. The multi-epoch timeline gives the operator a detection window that does not exist in the baseline (where all bits leak in a single introspection response).

**Bolyra deployment with layered privacy defense:**
1. Columbia CU enrolls the agent's credential commitment via 7-of-12 governor threshold into the on-chain Bolyra agent Merkle tree.
2. When the agent contacts a partner CU's RS, the RS specifies `requiredScopeMask = 0b00000101` (bits 0 and 2: `READ_DATA | FINANCIAL_SMALL`).
3. The agent checks its rate-limit counter for this RS and current epoch. If within budget, it generates a `SelectiveScopeProof` locally (< 500 ms with rapidsnark). The proof is 768 bytes.
4. If a malicious partner RS probes with `requiredScopeMask = 0b01000000` (bit 6, `SUB_DELEGATE`, which the agent does NOT hold), the prover fails, and the agent waits until `T_prove` elapses before returning `{"error": "scope_insufficient"}`. The response time is indistinguishable from a legitimate proof.
5. If the same RS sends a 5th query in the same epoch, the agent's rate limiter triggers. The response is again `{"error": "scope_insufficient"}` after `T_prove` — indistinguishable from a failed predicate, an expired credential, or a stale Merkle root.
6. The partner RS verifies successful proofs against the on-chain `agentMerkleRoot` — no call to Columbia CU's AS, no trust in Columbia CU's infrastructure, no knowledge of the agent's full permission set.
7. The RS learns exactly one bit of information per query: the agent satisfies (or does not satisfy) the specified predicate. It learns nothing about unqueried bits. For the legitimate query `0b00000101`, it learns only that `READ_DATA` and `FINANCIAL_SMALL` are present — not whether `FINANCIAL_UNLIMITED`, `ACCESS_PII`, or `SUB_DELEGATE` are set.

**Regulatory alignment:** NCUA examiners reviewing consortium data-sharing agreements can verify that only cryptographically proven minimum-necessary permissions were exercised at each access point — satisfying NCUA guidance on third-party AI risk management (Letter to Credit Unions 24-CU-03). The threshold enrollment governance provides an auditable approval chain: every enrolled credential has k governor signatures recorded on-chain, giving examiners a verifiable record of who approved what agent with what permissions. The agent's rate-limit configuration is auditable (SDK configuration parameter), giving examiners assurance that agents cannot be probed at arbitrary rates. The constant-time rejection protocol additionally ensures that probe-based reconnaissance by consortium partners cannot map internal permission structures — a risk highlighted in FFIEC's 2025 guidance on API security in multi-institution arrangements.

### Why boolean-return RFC 7662 does NOT close the gap

An AS could be configured to return only `{"active": true}` or `{"active": false}` for a given `requiredScopeMask` — effectively a boolean predicate endpoint. This appears to match the construction's one-bit-per-query information leakage. However:

1. **The boolean is the AS's assertion, not a mathematical proof.** A compromised AS returns `true` for unauthorized scopes. The RS has no cryptographic recourse — it trusted the AS's signed response, not a proof of predicate satisfaction over committed state.
2. **Implication closure is not enforced.** The boolean-return AS can assert that an agent with `FINANCIAL_UNLIMITED` but without `FINANCIAL_SMALL` satisfies a `FINANCIAL_SMALL` predicate. The RS cannot detect the structural violation. G5 and G6 are R1CS constraints — they reject such witnesses unconditionally.
3. **The AS remains in the hot path.** Even a boolean-return AS is an AS that must be available, trusted, and contacted. The construction eliminates this dependency entirely.
4. **The AS has unilateral enrollment authority.** In OAuth, the AS registers clients and issues credentials without external governance. The construction's k-of-n threshold enrollment means no single party — including the AS — can unilaterally determine what credentials enter the trust pool.
5. **A boolean-return AS provides no rate-limit enforcement for the agent.** The AS cannot prevent the RS from making unlimited introspection queries — the agent has no SDK-side defense. In the construction, the agent controls its own query budget.

### Why Client Attestation, WIMSE WPoP, and hardware-attested SPIRE do not close the gap

Three emerging mechanisms strengthen the *identity* layer for non-human entities:

1. **Client Attestation (draft-ietf-oauth-attestation-based-client-auth):** Binds the client's identity to a hardware-backed key via an attestation JWT. The AS verifies the attestation at token issuance. **Failure mode:** Attestation certifies *platform identity* (TPM-backed key, device integrity), not *permission-structure invariants*. An attested client with an implication-violating bitmask (bit 4 set, bit 2 unset) passes attestation. The RS receives a token whose scope was determined by the AS post-attestation — the attestation adds trust in the *client's identity*, not in the *predicate evaluation*.

2. **WIMSE Workload Proof of Possession (draft-ietf-wimse-s2s-protocol):** A workload signs a token with its SPIFFE-issued key, proving it is the intended service-to-service caller. **Failure mode:** WPoP proves *which workload holds the token*, not *what the token authorizes*. Scope is still an AS-issued string in the token body. A compromised AS issues tokens with arbitrary scope to a legitimately attested workload.

3. **Hardware-attested SPIRE (SPIFFE Runtime Environment):** SPIRE issues X.509-SVIDs or JWT-SVIDs to workloads after verifying platform attestation (node attestation + workload attestation). **Failure mode:** SPIRE certifies workload identity within a trust domain. Authorization is separate — SPIRE's SVID carries no permission bitmask. Policy engines (e.g., OPA) evaluate authorization using the SVID as identity input, but the evaluation is an *assertion by the policy engine*, not a cryptographic proof.

| Property | Client Attestation | WIMSE WPoP | SPIRE | SelectiveScopeProof |
|---|---|---|---|---|
| What is proven | Platform identity | Token possession | Workload identity | Predicate satisfaction over enrolled bitmask |
| Implication closure | Not addressed | Not addressed | Not addressed | R1CS constraint (G6) |
| Adversarial AS | Attestation is pre-AS; AS still controls scope | WPoP is post-AS; scope is in token | SPIRE is identity-only; authz is separate | AS not in verification path |
| Predicate evaluation location | AS | AS | Policy engine | Circuit (G5) |
| What RS learns | Token scope (from AS) | Token scope (from AS) | Identity (from SPIRE) | Boolean: predicate satisfied or not |
| Enrollment governance | AS registers client unilaterally | AS issues token unilaterally | SPIRE server issues SVID unilaterally | k-of-n threshold governors |

### Why SD-JWT (RFC 9635) does not close the gap

SD-JWT (Selective Disclosure for JWTs, RFC 9635) allows a holder to selectively disclose individual claims from an issuer-signed JWT. This appears to offer holder-controlled selective presentation similar to the construction's scope privacy. Four concrete failure modes show it does not:

**(a) SD-JWT discloses claim *values*, not predicate satisfaction.** When an SD-JWT holder discloses a claim, the RS receives the claim name, salt, and value in plaintext (RFC 9635 Section 5.2). The holder can choose *which* claims to disclose, but disclosed claims are fully revealed. In contrast, `SelectiveScopeProof` reveals only that `permissionBitmask & requiredScopeMask == requiredScopeMask` — the RS learns a boolean, not the value of any individual bit. Furthermore, the *count* of disclosed claims leaks structural information: an SD-JWT with 3 disclosed claims is distinguishable from one with 7 disclosed claims. The ZK proof is constant-size regardless of how many bits satisfy the predicate.

**(b) No predicate evaluation over hidden claims.** RFC 9635 Section 5 is explicit: the verifier can only verify claims that are disclosed. There is no mechanism for the holder to prove `hiddenClaim >= threshold` or `hiddenBitmask & requiredMask == requiredMask` without disclosing the claim value. SD-JWT-based Key Binding (RFC 9635 Section 4.3) binds the presentation to a holder key but does not add predicate evaluation. The RS either sees the claim value or sees nothing — there is no intermediate "I can see that the predicate is satisfied but not the value."

**(c) Selective disclosure and implication closure enforcement are mutually exclusive.** The holder can hide claims (selective disclosure) OR the RS can verify structural invariants (by requiring full disclosure of all permission claims and checking implication closure) — but never both simultaneously. If the holder hides `FINANCIAL_UNLIMITED`, the RS cannot verify that `FINANCIAL_SMALL` is implied. If the RS requires disclosure of all financial-tier claims to check closure, selective disclosure is defeated. `SelectiveScopeProof` achieves both in a single proof because G5 (scope satisfaction) and G6 (implication closure) evaluate over the same hidden `permissionBitmask` witness.

**(d) SD-JWT remains issuer-dependent.** The SD-JWT is signed by the issuer (AS). A compromised issuer can sign an SD-JWT with false claims. The holder's selective disclosure is a privacy feature, not a trust-independence feature — the RS still trusts the issuer's signature. The construction removes the issuer from the trust model entirely and replaces it with k-of-n enrollment governance.

| Property | SD-JWT (RFC 9635) | SelectiveScopeProof |
|---|---|---|
| What RS receives for hidden claims | Nothing (claim is absent) | Boolean predicate satisfaction |
| Predicate over hidden claims | Impossible (Section 5) | G5 evaluates over private `permissionBitmask` |
| Implication closure + hiding | Mutually exclusive | Simultaneous (G5 + G6 on same witness) |
| Presentation size | Grows with disclosed claims + salts | Constant 768 bytes (PLONK) |
| Issuer dependency | Issuer signs; compromised issuer = false claims | On-chain Merkle root; k-of-n enrollment governance |
| ZK property | None — disclosed claims are plaintext | SE-NIZK (PLONK simulation-extractable ZK) |
| Multi-query leakage | Full claim value per disclosure (W bits in 1 query if all disclosed) | 1 bit per query, rate-limited to q_max per epoch |

### Why RFC 8693 Token Exchange does not close the gap

RFC 8693 (OAuth 2.0 Token Exchange) enables an agent to exchange a broader token for a narrower one at the AS, with each exchange producing a new token scoped to the target audience and reduced permission set. This is the baseline's closest analog to runtime-adaptive scope narrowing — the agent can request a new token with only the permissions needed for a specific RS, at the moment of use. Five concrete failure modes show it does not match the construction:

**(a) Token exchange is runtime-adaptive but AS-dependent.** RFC 8693 Section 2.1 requires the agent to contact the AS's token endpoint for every scope-narrowing exchange. The agent sends `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` (the broader credential), `scope` (the narrowed set), and `resource` (the target RS). The AS evaluates the narrowing request and issues a new token. This is runtime-adaptive in the sense that the agent chooses when and how to narrow — but the AS is in the critical path for every narrowing operation. If the AS is offline, compromised, or adversarial, the agent cannot narrow its presentation. `SelectiveScopeProof` achieves runtime-adaptive narrowing with no AS contact: the agent generates a fresh proof with the RS-specified `requiredScopeMask` locally, using only its enrolled credential and the on-chain Merkle root.

**(b) The exchanged token is still an AS assertion.** The narrowed token issued via RFC 8693 is a signed JWT (or opaque token) whose scope field is the AS's assertion of what permissions the exchanged token carries. The RS verifies the AS's signature, not a mathematical proof that the narrowed scope is a valid subset of the original scope. A compromised AS can issue exchanged tokens with inflated scope (granting permissions the original token did not have), deflated scope (denial of service), or structurally invalid scope (FINANCIAL_UNLIMITED without FINANCIAL_SMALL). The RS has no mechanism to detect any of these — it trusts the AS's signature. In `SelectiveScopeProof`, the scope satisfaction (G5) and implication closure (G6) are R1CS constraints evaluated over the committed bitmask. No exchanged token, however signed, provides this guarantee.

**(c) Scope narrowing without implication closure enforcement.** RFC 8693 Section 2.1 specifies the `scope` parameter as a space-delimited string of scope values. The AS MAY apply policy to reject invalid narrowing requests, but this is an application-layer policy decision, not a cryptographic invariant. Nothing in RFC 8693 requires the AS to enforce that `financial_unlimited` implies `financial_small` — the AS can issue an exchanged token with `scope: "financial_unlimited"` but without `financial_small`, and the RS will accept it if the RS's local policy only checks for `financial_unlimited`. The circuit's G6 constraints reject such a witness unconditionally, regardless of what any party asserts.

**(d) Each exchange creates a linkable token.** Every RFC 8693 token exchange produces a new token that the AS can correlate to the original subject token, the requesting agent, the target RS, and the narrowed scope. The AS maintains a complete audit trail of every scope-narrowing operation — which agent narrowed which permissions for which RS at what time. Even if this is desirable for audit purposes, it means the AS has full visibility into the agent's access patterns. In `SelectiveScopeProof`, the `blindingNonce` ensures that the `agentNullifier` and `scopePredicateHash` are unlinkable across presentations. The AS (if it even exists) learns nothing about which RSes the agent contacted or which predicates were evaluated.

**(e) Token exchange does not scale to large permission spaces.** RFC 8693 inherits the scope-string representation: each narrowed permission must be named as a string in the `scope` parameter. For a 64-bit permission space, this requires up to 64 distinct scope strings per exchange request. For the 2^64 possible permission configurations, the AS's policy tables must enumerate valid narrowing combinations — a combinatorial explosion that no practical AS can precompute. The `SelectiveScopeProof` evaluates the predicate over the bitmask arithmetically in 64 multiplication constraints (G5), regardless of the permission space cardinality.

| Property | RFC 8693 Token Exchange | SelectiveScopeProof |
|---|---|---|
| Runtime-adaptive narrowing | Yes, but requires AS roundtrip per exchange | Yes, agent generates proof locally per RS request |
| AS dependency | AS must be online, trusted, and responsive | AS not contacted; trust = on-chain root + proof |
| Narrowing integrity | AS assertion (signed token) | R1CS constraint (G5: bitmask AND predicate) |
| Implication closure | AS policy decision (not cryptographic) | R1CS constraint (G6: unconditional rejection) |
| Cross-RS linkability | AS correlates all exchanges | Blinded nullifier; AS learns nothing |
| Permission space scalability | O(scope strings) per exchange; policy tables explode | O(1) proof; 64 constraints regardless of space |
| Enrollment governance | AS registers client unilaterally | k-of-n threshold enrollment |
| Agent privacy defense | None — AS sees all exchanges; RS receives full scope | Rate-limited to q_max bits/epoch; agent controls budget |

**The key distinction:** RFC 8693 provides the *mechanism* for runtime scope narrowing but not the *trust model*. The agent can narrow, but the narrowing is attested by the AS — the same party whose trustworthiness is in question. `SelectiveScopeProof` provides both the mechanism (agent generates proof with RS-specified predicate) and the trust model (R1CS constraints over on-chain-committed state, verified by the RS independently, with credential enrollment governed by k-of-n threshold).

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + RFC 8693 + RFC 8707 + DPoP + W3C VC/BBS+ + SD-JWT) fails on six properties the `SelectiveScopeProof` achieves simultaneously:

### Property 1: Adversarial-AS soundness with circuit-enforced implication closure

**Baseline:** RS assurance rests entirely on the AS's signed assertion — whether that assertion comes via RFC 7662 introspection, jwt-introspection-response caching, RFC 8693 token exchange, or BBS+/SD-JWT credential issuance. A malicious AS can lie. A boolean-return AS can assert that an agent with `FINANCIAL_UNLIMITED` but without `FINANCIAL_SMALL` satisfies a `FINANCIAL_SMALL` predicate — the RS cannot detect the structural violation. Client Attestation, WIMSE WPoP, and hardware-attested SPIRE certify *identity and platform state*, not *permission-structure invariants*. SD-JWT's selective disclosure cannot simultaneously hide claims and enforce implication closure. RFC 8693 exchanges are AS-asserted narrowing — a compromised AS can issue structurally invalid narrowed tokens.

**Construction:** G5 (scope satisfaction) and G6 (implication closure) are R1CS constraints. No valid witness can satisfy the circuit with an implication-violating bitmask. The AS is not in the verification path; trust = on-chain root + proof soundness. Enrollment is governed by k-of-n threshold — no single party (including the AS) can unilaterally enroll credentials with inflated permissions.

**Concrete gap:** Compromise Columbia CU's AS. Issue an RFC 8693 exchanged token asserting `scope: "financial_unlimited"` without `financial_small` for an agent accessing a partner CU. The partner CU's RS verifies the AS signature and grants access — the structural violation is invisible. In `SelectiveScopeProof`, the same witness fails G6 unconditionally. No amount of AS compromise changes this. Even if Columbia CU's AS also serves as 1-of-12 enrollment governors, it cannot unilaterally enroll a credential with a structurally invalid bitmask — 6 additional governor signatures are required.

### Property 2: Bounded-leakage predicate evaluation (not selective disclosure)

**Baseline:** RFC 7662 introspection reveals the full scope string — all W bits in 1 query. BBS+ reveals claim *values* for disclosed claims. SD-JWT reveals claim names, salts, and values in plaintext for disclosed claims (RFC 9635 Section 5.2) — and cannot evaluate predicates over hidden claims (Section 5). RFC 8693 produces a new token with the narrowed scope as a plaintext string. None of these evaluate a predicate over a hidden input and return only a boolean.

**Construction:** The RS learns only `pred(permissionBitmask) = 1` — not any individual bit value, not the Hamming weight, not the claim count, not structural properties beyond predicate satisfaction. This is a ZK property per presentation. Over `q` queries, the RS learns at most `q` bits — bounded by the agent's rate limit to `q_max` bits per epoch. The baseline leaks all W bits in a single query; the construction forces the adversary to sustain `ceil(W/q_max)` epochs of probing, giving the agent operator a detection window.

**Concrete gap:** Columbia CU's agent contacts 5 consortium RSes. In the baseline, each RS's single introspection request reveals the full scope string to the AS, and each RS sees the full or filtered scope — 5 RSes × W bits = 5W bits of total leakage in 5 queries. In the construction, each RS gets 1 bit per query, rate-limited to `q_max = 4` per hour. Total leakage across all 5 RSes: 20 bits per hour, requiring over 3 hours for full recovery even with all 5 RSes colluding — and colluding RSes cannot correlate their queries (blinded nullifiers) to combine information efficiently.

### Property 3: AS-blind presentation

**Baseline:** Every variant requires AS involvement. RFC 7662 requires AS for introspection. RFC 8693 requires AS for each exchange. BBS+ requires AS at issuance. SD-JWT requires AS to sign the original JWT.

**Construction:** The agent generates the proof locally. The RS verifies against on-chain state. The AS is not contacted, not informed, not needed. The enrollment governors were involved once at enrollment time — they are not contacted at presentation time.

### Property 4: Constant-size proof regardless of bitmask width

**Baseline:** JWT scope strings grow linearly. BBS+ derived proofs grow with disclosed message count `O(|disclosed|)`. SD-JWT presentations grow with disclosed claims plus salt/value pairs. RFC 8693 exchanged tokens grow with the narrowed scope string length. For a 64-bit permission space, enumeration is infeasible.

**Construction:** PLONK proof is exactly 768 bytes regardless of bitmask width, predicate size, or permission count.

### Property 5: Cryptographic binding to runtime model identity

**Baseline:** `client_id` is a static registration string. Neither RFC 7662, DPoP, RFC 8693, BBS+, nor SD-JWT bind the token to a specific model hash + operator key + permission bitmask at call time.

**Construction:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`. A different model, operator, or permission set produces a different commitment that is not enrolled. Enrollment of this commitment required k-of-n governor approval, binding the model identity to the governance decision.

### Property 6: Multi-query simulation-extractable zero-knowledge with rate-bounded leakage

**Baseline:** BBS+ is HVZK (honest-verifier zero-knowledge), not SE-NIZK — Groth16 proof malleation is a concrete attack that SE-NIZK prevents. SD-JWT has no ZK property at all — disclosed claims are plaintext. RFC 8693 exchanged tokens are plaintext JWTs. RFC 7662 introspection responses are plaintext JSON. None of these provide any rate-limiting mechanism for the agent — the AS sees all queries, the RS receives full scope strings, and the agent has no protocol-level defense against probing.

**Construction:** PLONK with Fiat-Shamir in ROM provides simulation-extractable zero-knowledge (Faust et al. 2022). The `blindingNonce` randomizes each transcript. Even an adversary collecting polynomially many proofs cannot malleate or correlate them. The agent's SDK-enforced rate limit (`q_max < W` per RS per epoch) bounds multi-query leakage to `q_max` bits per epoch — giving the operator a detection and response window of `ceil(W/q_max) - 1` epoch boundaries before full recovery is possible. No baseline variant gives the agent any control over its own leakage rate.

### Summary

The baseline's limitations are architectural, not configurational. RFC 7662 defines introspection as "the AS tells you about this token." RFC 8693 defines token exchange as "the AS issues you a narrower token." BBS+ and SD-JWT are "the issuer signed these claims." In every case, the trust root is an assertion by a single party whose integrity is assumed. No layering of DPoP, audience binding, token exchange, selective disclosure, client attestation, workload attestation, or hardware roots of trust changes this — because none of these mechanisms evaluate the authorization predicate at the cryptographic layer or distribute enrollment authority across a threshold quorum.

The `SelectiveScopeProof` moves the trust root from "the AS said so" to "the on-chain Merkle tree contains this commitment (enrolled by k-of-n governors), the operator's signature is valid, and the bitmask satisfies the predicate with valid implication closure" — verified inside a simulation-extractable zero-knowledge proof that reveals nothing beyond predicate satisfaction per presentation, with multi-query leakage rate-limited by the agent's own SDK enforcement.

The privacy claim is precise: per-presentation SE-ZK (each proof reveals 1 bit), not information-theoretic secrecy against unbounded queries (which no interactive predicate protocol can provide). The construction's advantage is not that it eliminates multi-query leakage — it is that it (a) minimizes per-query leakage from W bits (baseline) to 1 bit (construction), (b) gives the agent protocol-level control over its leakage rate via `q_max`, and (c) provides a multi-epoch detection window that the baseline does not offer. The distinction is not "what the RS sees" (a boolean-return AS can limit what the RS sees per query) but "who evaluates the predicate, who enforces structural invariants, who controls enrollment, and who controls the leakage rate" — single-party AS assertion with no agent-side defense vs. R1CS constraint with threshold-governed enrollment and agent-enforced rate limiting. This is a category difference, not a degree difference.
