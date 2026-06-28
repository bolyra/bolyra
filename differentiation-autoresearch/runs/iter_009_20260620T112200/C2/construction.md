# Construction

## 1. Statement of claim

The same AI agent accessing N distinct Resource Servers (scopes) produces N authorization proofs such that no polynomial-time adversary controlling the Authorization Server — even one colluding with up to N−1 Resource Servers — can determine whether any two proofs originate from the same agent, except within the same scope where Sybil detection requires linkability.

Formally, we define the **IND-UNL-AS** game:

1. **Setup.** Challenger enrolls two agents A₀, A₁ in the agent Merkle tree with identical permission bitmasks and expiry.
2. **Challenge.** Adversary picks two distinct scope identifiers (sid₀, sid₁). Challenger flips bit b ← {0,1}, generates proof π₀ for agent A_b at scope sid₀ and proof π₁ for agent A_{1−b} at scope sid₁.
3. **Oracle.** Adversary has full AS oracle access: it sees all on-chain events, all Merkle roots, all public signals, and can request proofs for either agent at any scope of its choice (except the challenge scopes with the challenge agents).
4. **Output.** Adversary guesses b′. Advantage = |Pr[b′ = b] − 1/2|.

**Claim:** Under the construction below, the adversary's advantage is negligible in the security parameter λ, assuming Poseidon is a PRF over BN254 and Groth16/PLONK achieve knowledge soundness.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopeIsolatedAgentPolicy`

This circuit extends the existing `AgentPolicy` circuit with scope-isolated nullifiers, private scope binding, and **scope-bound commitment rerandomization**.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key (Baby Jubjub) |
| `operatorSecretKey` | F_p | Operator EdDSA secret scalar |
| `permissionBitmask` | 64-bit | Permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |
| `scopeId` | F_p | Target RS scope identifier (PRIVATE — this is the key change) |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | Policy requiring specific permission bits |
| `currentTimestamp` | 64-bit | Current time |
| `sessionNonce` | F_p | Session binding value |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, operatorSecretKey)` — deterministic per agent per scope, unlinkable across scopes |
| `scopeBoundCommitment` | F_p | `Poseidon3(permissionBitmask, credentialCommitment, scopeId)` — **scope-rerandomized**; replaces the prior scope-independent `scopeCommitment` |
| `scopeBinding` | F_p | `Poseidon3(scopeId, sessionNonce, agentMerkleRoot)` — scope-session binding for off-chain RS verification |

**Critical change from prior construction — scopeCommitment → scopeBoundCommitment:**

The prior construction published `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` as a public output. This value is **scope-independent**: the same agent with the same permissions produces an identical `scopeCommitment` at every scope. An adversary observing two proofs at different scopes with identical `scopeCommitment` values wins IND-UNL-AS with advantage 1.

The fix is to include `scopeId` in the commitment:

```
scopeBoundCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeId)
```

Since `scopeId` is a private input that differs per RS, the same agent produces distinct `scopeBoundCommitment` values at different scopes. Under the Poseidon-PRF assumption (keyed by `scopeId`), these values are computationally indistinguishable from independent random elements, closing the cross-scope fingerprinting vector.

**Circuit constraints (in addition to all existing AgentPolicy constraints):**

1. **Key consistency:** `(operatorPubkeyAx, operatorPubkeyAy) = BabyPbk(operatorSecretKey)` — proves the prover knows the secret key corresponding to the public key in the credential.
2. **Scope nullifier derivation:** `scopeNullifier = Poseidon2(scopeId, operatorSecretKey)`. This is a PRF keyed by the operator's secret, evaluated at the scope. Different scopes yield independent-looking outputs.
3. **Scope-bound commitment derivation:** `scopeBoundCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeId)`. This replaces the prior `Poseidon2(permissionBitmask, credentialCommitment)`. The inclusion of `scopeId` as the third input ensures the output is scope-dependent while preserving credential binding.
4. **Scope binding derivation:** `scopeBinding = Poseidon3(scopeId, sessionNonce, agentMerkleRoot)`. The RS can recompute this from known values to confirm the proof targets it.
5. All existing AgentPolicy constraints (credential commitment, EdDSA signature, Merkle membership, scope satisfaction, cumulative bit encoding, expiry check) are retained unchanged.

### Delegation circuit update

The delegation circuit's chain-linking constraint must mirror the rerandomized commitment. The delegator's previous output is now scope-bound, so the delegation circuit receives `scopeId` as an additional private input:

**Changed constraint (chain linking):**

```
Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeId) == previousScopeCommitment
```

This replaces the prior `Poseidon2(delegatorScope, delegatorCredCommitment) == previousScopeCommitment`.

**New delegation circuit private input:**

| Signal | Type | Description |
|--------|------|-------------|
| `delegatorScopeId` | F_p | Scope identifier of the delegator's prior hop |

**New delegation circuit public output (updated):**

```
newScopeCommitment = Poseidon3(delegateeScope, delegateeCredCommitment, delegateeScopeId)
```

Where `delegateeScopeId` is also a new private input. This ensures the delegation chain preserves scope isolation end-to-end: no public output in any hop is scope-independent.

All other delegation constraints (scope subset enforcement, cumulative bit encoding, expiry narrowing, delegation token signature, delegatee enrollment) are unchanged.

**Delegation cost delta:** Two Poseidon3 calls replace two Poseidon2 calls (+~300 constraints from the additional hash input routing). This is negligible against the existing ~14K delegation circuit.

### Verification protocol

**Off-chain path (primary — AS never sees per-RS traffic):**

1. Agent generates `ScopeIsolatedAgentPolicy` proof with RS's `scopeId` as private input.
2. Agent sends `(proof, publicSignals)` directly to the RS over a TLS channel.
3. RS recomputes `expectedScopeBinding = Poseidon3(myScopeId, sessionNonce, agentMerkleRoot)` and checks it matches `scopeBinding` from public outputs.
4. RS verifies the ZK proof against the verification key.
5. RS checks `scopeNullifier` against its local nullifier store for Sybil detection within its scope.
6. RS checks `agentMerkleRoot` against the on-chain root history buffer (read-only; no write).

**On-chain path (optional — for delegation chain seeding):**

1. Only the `scopeNullifier`, `scopeBoundCommitment`, and `agentMerkleRoot` are posted on-chain.
2. `scopeId` never appears on-chain. `scopeBinding` is verified off-chain by the RS only.
3. The on-chain registry stores `scopeNullifier` in a flat set: `mapping(bytes32 => bool) scopeNullifierUsed`. No scope-indexed mapping is used.
4. The delegation chain seed uses `scopeBoundCommitment` (scope-dependent), so two delegation chains initiated at different scopes are unlinkable even if they originate from the same agent.

### Batched submission gadget (timing side-channel mitigation)

To prevent an adversarial AS from correlating proof generation times across scopes:

- Agents MAY batch multiple scope proofs and submit them in a single transaction to a **batch relay contract**.
- The batch relay shuffles and posts nullifiers with uniform timing. Each nullifier is stored in a flat set (no scope-indexed mapping visible to observers).
- This converts the timing vector from per-request to per-batch (configurable batch window: 1–60 seconds).

## 3. Threat model (adversary capabilities, game definition)

**Adversary capabilities (AS-adversary):**

- Full control of the Authorization Server (if one exists in the deployment).
- Reads all on-chain state: Merkle roots, emitted events, nullifier mappings, scope-bound commitments.
- Observes all public signals from every proof posted on-chain.
- Colludes with up to N−1 of N Resource Servers (can share nullifiers, timing data, and proof artifacts).
- Can issue adaptive queries: request proofs from known agents at known scopes (chosen-scope attack).
- Passive network adversary: observes TLS metadata (IP, timing, packet sizes) but cannot break TLS.

**Adversary does NOT have:**

- The operator's EdDSA secret key (`operatorSecretKey`).
- The ability to break Poseidon preimage resistance or PRF security.
- The ability to extract witnesses from Groth16/PLONK proofs (knowledge soundness).

**IND-UNL-AS game (formal):**

```
Game IND-UNL-AS(λ):
  pp ← Setup(1^λ)
  (sk₀, pk₀, cred₀) ← KeyGen(pp); (sk₁, pk₁, cred₁) ← KeyGen(pp)
  Enroll(cred₀, tree); Enroll(cred₁, tree)
  
  // Adversary chooses challenge scopes
  (sid₀, sid₁) ← A^{Prove(·,·)}(pp, tree)
  
  b ←$ {0, 1}
  π₀ ← Prove(sk_b, sid₀, nonce₀)
  π₁ ← Prove(sk_{1-b}, sid₁, nonce₁)
  
  // Adversary sees ALL public signals: agentMerkleRoot,
  // scopeNullifier, scopeBoundCommitment, scopeBinding
  b' ← A^{Prove(·,·)}(pubSignals(π₀), pubSignals(π₁))
  
  return (b' = b)
  
Adv[A] = |Pr[b' = b] - 1/2|
```

The `Prove(·,·)` oracle allows the adversary to request proofs for any (agent, scope) pair except the challenge pairs `(b, sid₀)` and `(1−b, sid₁)`.

**Exhaustive public signal analysis for IND-UNL-AS leakage:**

Every public output must be verified scope-dependent or agent-independent:

| Public output | Scope-dependent? | Agent-dependent? | Cross-scope linkable? |
|---|---|---|---|
| `agentMerkleRoot` | No | No (shared tree root) | No — identical for all agents |
| `scopeNullifier` | Yes (PRF of scopeId) | Yes (keyed by sk) | No — PRF indistinguishability |
| `scopeBoundCommitment` | **Yes (includes scopeId)** | Yes (includes credComm) | **No — Poseidon3 with distinct scopeId inputs** |
| `scopeBinding` | Yes (includes scopeId) | No (deterministic from public values + scopeId) | No — scopeId is private |
| `requiredScopeMask` | Possibly | No | Policy-level; verifier-chosen, not agent-specific |
| `currentTimestamp` | No | No | No — shared clock |
| `sessionNonce` | Yes (fresh per session) | No | No — random |

The prior construction's `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` would have appeared in the "No" column for scope-dependence — a cross-scope fingerprint with advantage 1. The rerandomized `scopeBoundCommitment` now depends on `scopeId`, closing this vector.

**Security goal:** For all PPT adversaries A, `Adv[A] ≤ negl(λ)`.

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**

1. **Poseidon-PRF:** Poseidon2 and Poseidon3 are pseudorandom functions over the BN254 scalar field when one input is a uniformly random element unknown to the distinguisher. Specifically: for random key k, the function F_k(x) = Poseidon2(x, k) is computationally indistinguishable from a random function; likewise Poseidon3(a, b, k) keyed by k.
2. **DL-BabyJubjub:** The discrete logarithm problem is hard on the Baby Jubjub curve.
3. **Groth16-KS:** Groth16 proofs satisfy knowledge soundness (simulation extractability) under the q-PKE and q-SDH assumptions on BN254.
4. **PLONK-KS:** PLONK proofs satisfy knowledge soundness under the AGM + ROM.
5. **Poseidon-CR:** Poseidon is collision resistant over BN254.

**Reduction sketch (IND-UNL-AS → Poseidon-PRF):**

Suppose adversary A wins IND-UNL-AS with non-negligible advantage ε. We construct a PRF distinguisher B:

1. B receives oracle access to either F_k(·) = Poseidon2(·, k) for random k, or a truly random function R(·). B also receives a second oracle G_k(·, ·) = Poseidon3(·, ·, k) or a truly random function R'(·, ·), keyed by the same k (modeling scopeId-dependence through the shared secret key).
2. B simulates the IND-UNL-AS game. For the challenge agent (say agent b=0), B uses the PRF/random oracles to compute both `scopeNullifier` and `scopeBoundCommitment` instead of using Poseidon with sk₀ directly:
   - `scopeNullifier = F(sid)` (or R(sid))
   - `scopeBoundCommitment = G(permBitmask, credComm₀)` where the third argument (scopeId) is absorbed by the oracle key (or R'(permBitmask, credComm₀))
3. All other circuit constraints are simulated faithfully (B knows the setup and can generate valid proofs for both agents).
4. If the oracles are PRFs: the game is identical to a real IND-UNL-AS execution. A wins with advantage ε.
5. If the oracles are random: all scope-dependent public outputs for agent b=0 are uniformly random and independent of sk₀. No information about b leaks. A's advantage is 0.
6. Therefore B distinguishes PRF from random with advantage ε, contradicting Poseidon-PRF.

**Why the prior construction failed this reduction:** The prior `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` contained no scope-dependent input. In step 5, even when nullifiers are replaced by random values, `scopeCommitment` remains identical across scopes for the same agent. The adversary simply checks `scopeCommitment(π₀) == scopeCommitment(π₁)` to determine if both proofs come from the same agent — advantage 1. The rerandomized `scopeBoundCommitment` includes `scopeId` as an input, which is absorbed by the random oracle in step 5, making the output uniformly random per scope.

**Knowledge soundness binding:** An adversary that forges a proof (claims scope-isolated nullifier without knowing the secret key) breaks Groth16-KS or PLONK-KS, from which the witness (including `operatorSecretKey`) can be extracted, contradicting DL-BabyJubjub.

**Scope binding integrity:** An adversary that produces a valid `scopeBinding` for a scope it does not target must find a Poseidon3 collision or preimage, contradicting Poseidon-CR.

**Delegation chain unlinkability:** Because `scopeBoundCommitment` is now scope-dependent, two delegation chains seeded at different scopes produce distinct chain-linking values even for the same delegator. An adversary observing `previousScopeCommitment` values across delegation transactions at different scopes cannot link them to the same agent — the reduction to Poseidon-PRF applies identically to the delegation circuit's public outputs.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope nullifier hash | `Poseidon2(scopeId, operatorSecretKey)` | Mirrors human nullifier pattern: `Poseidon2(scope, secret)` from §4.2 |
| **Scope-bound commitment** | **`Poseidon3(permissionBitmask, credentialCommitment, scopeId)`** | **Extends** spec §6.1 `Poseidon2(permissionBitmask, credentialCommitment)` by adding `scopeId` as third input for cross-scope unlinkability |
| Scope binding | `Poseidon3(scopeId, sessionNonce, agentMerkleRoot)` | Analogous to human `nonceBinding = Poseidon2(nullifierHash, sessionNonce)` |
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)` | Unchanged from AgentPolicy spec §5.2 |
| Key consistency | `BabyPbk(operatorSecretKey) == (Ax, Ay)` | Standard Baby Jubjub scalar mult; already used in HumanUniqueness |
| EdDSA signature | `EdDSAPoseidonVerifier` over credential commitment | Unchanged from AgentPolicy |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Unchanged |
| Proving system | Groth16 (REQUIRED) + PLONK (OPTIONAL) | Per spec §3.3, agent circuits support both |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | Unchanged from AgentPolicy §5.2 |
| **Delegation chain linking** | **`Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeId)`** | **Updated** from spec §7.2 `Poseidon2(delegatorScope, delegatorCredCommitment)` to include scope for chain unlinkability |

**Change summary:** Exactly one primitive is modified — `scopeCommitment` gains a third Poseidon input (`scopeId`). No new primitive types are introduced. The Poseidon3 variant is already used elsewhere in the construction (scope binding). The delegation circuit gains one private input (`delegatorScopeId`) and updates one constraint formula.

## 6. Circuit cost estimate

**Constraint breakdown for `ScopeIsolatedAgentPolicy`:**

| Gadget | Constraints | Notes |
|--------|-------------|-------|
| Existing AgentPolicy body | ~12,500 | EdDSA verify (~4,400), Merkle(20) (~4,000), Poseidon5 (~1,500), scope check (64), cumulative bits (3), range checks (~1,500), expiry LessThan(64) (~200) |
| BabyPbk(operatorSecretKey) | ~2,000 | Baby Jubjub scalar mult (251 doublings + additions) |
| Num2Bits(251) for operatorSecretKey | ~251 | Range check on secret key |
| Poseidon2(scopeId, operatorSecretKey) | ~300 | Scope nullifier |
| Poseidon3(permBitmask, credComm, scopeId) | ~450 | **Scope-bound commitment (was ~300 for Poseidon2; +150 for third input)** |
| Poseidon3(scopeId, sessionNonce, agentMerkleRoot) | ~450 | Scope binding |
| **Total** | **~15,950** | Fits within pot16.ptau (2^16 = 65,536 constraints) |

**Delta from prior construction:** +150 constraints (Poseidon3 vs Poseidon2 for scope-bound commitment). Negligible.

**Delegation circuit delta:** +150 constraints per Poseidon3 call (×2 for chain-link recomputation and new output), +0 constraints for the additional private input routing. Total delegation circuit: ~14,300 → ~14,600. Still well within pot16.ptau.

**Proving time targets:**

| System | Target | Justification |
|--------|--------|---------------|
| Groth16 | < 3s (snarkjs), < 200ms (rapidsnark) | 16K constraints is well under the 2^16 ceiling; +150 constraints is sub-millisecond delta |
| PLONK | < 5s (snarkjs) | Per spec requirement for agent circuits |

**Verification cost (on-chain):** Groth16 verification remains ~230K gas (unchanged — same pairing check, same number of public signals: 4 outputs + 3 public inputs = 7 signals, but Groth16 verification cost is dominated by pairings, not signal count). PLONK verification ~350K gas.

## 7. Concrete deployment scenario

**Scenario: Cross-credit-union member agent — Navy Federal ↔ PenFed ↔ merchant network**

A member of Navy Federal Credit Union (NFCU) deploys an AI agent to:
- Scope A (`sid_nfcu`): Access NFCU account data (READ_DATA, permission bit 0)
- Scope B (`sid_penfed`): Transfer funds to PenFed account (FINANCIAL_SMALL, permission bit 2, implying bit 0)
- Scope C (`sid_merchant`): Pay a merchant via a fintech aggregator (FINANCIAL_SMALL)

**Without this construction (baseline):** NFCU acts as the AS. It issues tokens for all three scopes. It sees: the member's agent contacted PenFed (competitive intelligence), the member's agent paid merchant X (merchant graph). PPID hides the `sub` from PenFed/merchant but NFCU sees the full traffic graph.

**With this construction:**

1. The agent enrolls once in the Bolyra agent Merkle tree with NFCU as operator (credential signed by NFCU's operator key).
2. For each RS, the agent generates a `ScopeIsolatedAgentPolicy` proof:
   - `scopeNullifier_A = Poseidon2(sid_nfcu, agentSecret)` → sent to NFCU
   - `scopeNullifier_B = Poseidon2(sid_penfed, agentSecret)` → sent to PenFed
   - `scopeNullifier_C = Poseidon2(sid_merchant, agentSecret)` → sent to merchant
   - `scopeBoundCommitment_A = Poseidon3(permBitmask, credComm, sid_nfcu)` → visible to NFCU only
   - `scopeBoundCommitment_B = Poseidon3(permBitmask, credComm, sid_penfed)` → visible to PenFed only
   - `scopeBoundCommitment_C = Poseidon3(permBitmask, credComm, sid_merchant)` → visible to merchant only
3. Each RS verifies the proof off-chain, checks `scopeBinding` against its known `scopeId`.
4. NFCU (even as AS/operator/issuer) sees `scopeNullifier_A` and `scopeBoundCommitment_A`. It cannot link these to `scopeNullifier_B` or `scopeBoundCommitment_B` because both values are PRF outputs keyed by `agentSecret` (nullifier) or parameterized by private `scopeId` (commitment) — and NFCU does not know `sid_penfed`.
5. **Prior construction vulnerability:** If NFCU colluded with PenFed and both held the old scope-independent `scopeCommitment`, they could trivially match the agent across scopes by comparing commitment values. With `scopeBoundCommitment`, the values are `Poseidon3(same_perm, same_cred, sid_nfcu) ≠ Poseidon3(same_perm, same_cred, sid_penfed)` — unlinkable under Poseidon-PRF.
6. Timing correlation is mitigated by the batch relay: the agent submits nullifiers for A, B, C in a single batched transaction with a 10-second window.

**Healthcare variant:** A primary care provider (PCP) issues an agent credential. The agent visits Specialist-1 (scope: cardiology referral) and Specialist-2 (scope: dermatology referral). The PCP cannot reconstruct the referral network topology from on-chain data or from collusion with either specialist — neither `scopeNullifier` nor `scopeBoundCommitment` values correlate across specialist scopes.

## 8. Why the baseline cannot match

| Capability | Baseline (PPID + DPoP + BBS+) | This construction |
|---|---|---|
| **AS sees token issuance per RS** | Yes — every token request hits the AS with (agent_id, RS, scope, timestamp) | No — proofs are generated locally, verified off-chain by RS or on-chain without scope identity |
| **AS can correlate scope sequences** | Yes — AS logs scope=X for RS-A, scope=Y for RS-B and builds behavioral timeline | No — scopeId is a private circuit input; on-chain only sees unlinkable nullifiers and scope-bound commitments |
| **Colluding AS+RS can deanonymize** | Yes — AS holds PPID mapping table; any colluding RS can request the reverse mapping | No — PRF security of Poseidon2/3 makes cross-scope nullifier and commitment correlation computationally hard |
| **Cross-scope fingerprint via credential binding** | N/A (baseline has no equivalent) | **Closed** — prior `scopeCommitment` was scope-independent (advantage 1); `scopeBoundCommitment` includes `scopeId`, reducing advantage to negl(λ) |
| **Issuer identity leaks to verifier** | Yes — BBS+ exposes issuer public key in every derived proof | No — operator public key is a private input; only the Merkle root (aggregating all issuers) is public |
| **Delegation chain visible to AS** | Yes — RFC 8693 requires AS roundtrip per hop | No — delegation uses on-chain scope-bound commitment chain; AS is not in the loop |
| **Formal unlinkability guarantee** | None — no IND-UNL-AS game or equivalent exists in any RFC/W3C spec | Yes — IND-UNL-AS game defined with reduction to Poseidon-PRF; all public outputs verified scope-dependent |
| **Timing side-channel resistance** | None — DPoP timestamps leak request timing to AS | Batched submission with configurable window; uniform timing per batch |

**The structural impossibility:** The baseline requires the AS to issue every credential/token. This is not a misconfiguration — it is the definitional architecture of OAuth 2.0/OIDC. The AS is the root of trust and necessarily observes all issuance events. Bolyra's construction eliminates the AS from the per-request critical path entirely: the agent proves credential validity against a public Merkle root using a ZK proof, with scope identity hidden as a private witness. No standards-track mechanism in OAuth/OIDC can retrofit this property because the AS's role as token issuer is load-bearing — removing it breaks the security model. Bolyra's ZK construction makes the AS unnecessary for per-scope authorization while preserving the AS's role as credential issuer (enrollment-time only).

**The scopeCommitment fix is essential, not optional:** A construction that publishes a scope-independent credential-bound commitment as a public signal has a trivially exploitable cross-scope fingerprint — the adversary wins IND-UNL-AS with advantage 1 by comparing commitment values. No amount of nullifier rerandomization can compensate. The baseline's BBS+ derived proofs are unlinkable at the RS layer but the issuer holds the linking key. This construction's `scopeBoundCommitment` ensures that even a colluding set of RSes with full on-chain visibility cannot reconstruct agent identity across scopes — the linking key (`scopeId`) is private to the proof and distinct per RS.
