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

This circuit extends the existing `AgentPolicy` circuit with scope-isolated nullifiers and private scope binding.

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
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` — for delegation chain entry |
| `scopeBinding` | F_p | `Poseidon3(scopeId, sessionNonce, agentMerkleRoot)` — scope-session binding for off-chain RS verification |

**Circuit constraints (in addition to all existing AgentPolicy constraints):**

1. **Key consistency:** `(operatorPubkeyAx, operatorPubkeyAy) = BabyPbk(operatorSecretKey)` — proves the prover knows the secret key corresponding to the public key in the credential. This is the foundation of scope-isolated nullifiers.
2. **Scope nullifier derivation:** `scopeNullifier = Poseidon2(scopeId, operatorSecretKey)`. This is a PRF keyed by the operator's secret, evaluated at the scope. Different scopes yield independent-looking outputs.
3. **Scope binding derivation:** `scopeBinding = Poseidon3(scopeId, sessionNonce, agentMerkleRoot)`. The RS can recompute this from known values to confirm the proof targets it.
4. All existing AgentPolicy constraints (credential commitment, EdDSA signature, Merkle membership, scope satisfaction, cumulative bit encoding, expiry check) are retained unchanged.

### Verification protocol

**Off-chain path (primary — AS never sees per-RS traffic):**

1. Agent generates `ScopeIsolatedAgentPolicy` proof with RS's `scopeId` as private input.
2. Agent sends `(proof, publicSignals)` directly to the RS over a TLS channel.
3. RS recomputes `expectedScopeBinding = Poseidon3(myScopeId, sessionNonce, agentMerkleRoot)` and checks it matches `scopeBinding` from public outputs.
4. RS verifies the ZK proof against the verification key.
5. RS checks `scopeNullifier` against its local nullifier store for Sybil detection within its scope.
6. RS checks `agentMerkleRoot` against the on-chain root history buffer (read-only; no write).

**On-chain path (optional — for delegation chain seeding):**

1. Only the `scopeNullifier`, `scopeCommitment`, and `agentMerkleRoot` are posted on-chain.
2. `scopeId` never appears on-chain. `scopeBinding` is verified off-chain by the RS only.
3. The on-chain registry stores `scopeNullifier` in a per-scope nullifier mapping (but the scope identity is not revealed — the RS posts to a commitment-addressed slot: `mapping(bytes32 => bool) scopeNullifierUsed`).

### Batched submission gadget (timing side-channel mitigation)

To prevent an adversarial AS from correlating proof generation times across scopes:

- Agents MAY batch multiple scope proofs and submit them in a single transaction to a **batch relay contract**.
- The batch relay shuffles and posts nullifiers with uniform timing. Each nullifier is stored in a flat set (no scope-indexed mapping visible to observers).
- This converts the timing vector from per-request to per-batch (configurable batch window: 1–60 seconds).

## 3. Threat model (adversary capabilities, game definition)

**Adversary capabilities (AS-adversary):**

- Full control of the Authorization Server (if one exists in the deployment).
- Reads all on-chain state: Merkle roots, emitted events, nullifier mappings, scope commitments.
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
  
  // Adversary sees public signals only
  b' ← A^{Prove(·,·)}(pubSignals(π₀), pubSignals(π₁))
  
  return (b' = b)
  
Adv[A] = |Pr[b' = b] - 1/2|
```

The `Prove(·,·)` oracle allows the adversary to request proofs for any (agent, scope) pair except the challenge pairs `(b, sid₀)` and `(1−b, sid₁)`.

**Security goal:** For all PPT adversaries A, `Adv[A] ≤ negl(λ)`.

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**

1. **Poseidon-PRF:** Poseidon2 is a pseudorandom function over the BN254 scalar field when keyed by a uniformly random element. Specifically: for random key k, the function F_k(x) = Poseidon2(x, k) is computationally indistinguishable from a random function.
2. **DL-BabyJubjub:** The discrete logarithm problem is hard on the Baby Jubjub curve.
3. **Groth16-KS:** Groth16 proofs satisfy knowledge soundness (simulation extractability) under the q-PKE and q-SDH assumptions on BN254.
4. **PLONK-KS:** PLONK proofs satisfy knowledge soundness under the AGM + ROM.
5. **Poseidon-CR:** Poseidon is collision resistant over BN254.

**Reduction sketch (IND-UNL-AS → Poseidon-PRF):**

Suppose adversary A wins IND-UNL-AS with non-negligible advantage ε. We construct a PRF distinguisher B:

1. B receives oracle access to either F_k(·) = Poseidon2(·, k) for random k, or a truly random function R(·).
2. B simulates the IND-UNL-AS game. For the challenge agent (say agent b=0), B uses the PRF/random oracle to compute scopeNullifiers instead of Poseidon2(scopeId, sk₀).
3. All other circuit constraints are simulated faithfully (B knows the setup and can generate valid proofs for both agents).
4. If the oracle is the PRF: the game is identical to a real IND-UNL-AS execution. A wins with advantage ε.
5. If the oracle is random: `scopeNullifier₀ = R(sid₀)` and `scopeNullifier₁ = Poseidon2(sid₁, sk₁)` are independently random-looking. No information about b leaks. A's advantage is 0.
6. Therefore B distinguishes PRF from random with advantage ε, contradicting Poseidon-PRF.

**Knowledge soundness binding:** An adversary that forges a proof (claims scope-isolated nullifier without knowing the secret key) breaks Groth16-KS or PLONK-KS, from which the witness (including `operatorSecretKey`) can be extracted, contradicting DL-BabyJubjub.

**Scope binding integrity:** An adversary that produces a valid `scopeBinding` for a scope it does not target must find a Poseidon3 collision or preimage, contradicting Poseidon-CR.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope nullifier hash | `Poseidon2(scopeId, operatorSecretKey)` | Mirrors human nullifier pattern: `Poseidon2(scope, secret)` from §4.2 |
| Scope binding | `Poseidon3(scopeId, sessionNonce, agentMerkleRoot)` | New; analogous to human `nonceBinding = Poseidon2(nullifierHash, sessionNonce)` |
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, permBitmask, expiry)` | Unchanged from AgentPolicy spec §5.2 |
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | Unchanged from spec §6.1 |
| Key consistency | `BabyPbk(operatorSecretKey) == (Ax, Ay)` | Standard Baby Jubjub scalar mult; already used in HumanUniqueness |
| EdDSA signature | `EdDSAPoseidonVerifier` over credential commitment | Unchanged from AgentPolicy |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Unchanged |
| Proving system | Groth16 (REQUIRED) + PLONK (OPTIONAL) | Per spec §3.3, agent circuits support both |
| Cumulative bit encoding | Bits 2/3/4 implication constraints | Unchanged from AgentPolicy §5.2 |

**No new primitives introduced.** The construction reuses exactly the Bolyra primitive set. The only structural change is: (a) `operatorSecretKey` becomes a private input (previously only the public key was used), (b) `scopeId` moves from implicit (ambient) to explicit private circuit input, and (c) one new Poseidon2 call for the scope nullifier + one Poseidon3 call for scope binding.

## 6. Circuit cost estimate

**Constraint breakdown for `ScopeIsolatedAgentPolicy`:**

| Gadget | Constraints | Notes |
|--------|-------------|-------|
| Existing AgentPolicy body | ~12,500 | EdDSA verify (~4,400), Merkle(20) (~4,000), Poseidon5 (~1,500), scope check (64), cumulative bits (3), range checks (~1,500), expiry LessThan(64) (~200) |
| BabyPbk(operatorSecretKey) | ~2,000 | Baby Jubjub scalar mult (251 doublings + additions) |
| Num2Bits(251) for operatorSecretKey | ~251 | Range check on secret key |
| Poseidon2(scopeId, operatorSecretKey) | ~300 | Scope nullifier |
| Poseidon3(scopeId, sessionNonce, agentMerkleRoot) | ~450 | Scope binding |
| **Total** | **~15,500** | Fits within pot16.ptau (2^16 = 65,536 constraints) |

**Proving time targets:**

| System | Target | Justification |
|--------|--------|---------------|
| Groth16 | < 3s (snarkjs), < 200ms (rapidsnark) | 15.5K constraints is well under the 2^16 ceiling; existing AgentPolicy benchmarks show ~1.5s/snarkjs for 12.5K |
| PLONK | < 5s (snarkjs) | Per spec requirement for agent circuits |

**Verification cost (on-chain):** Groth16 verification remains ~230K gas (unchanged — same pairing check, 6 public signals). PLONK verification ~350K gas.

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
3. Each RS verifies the proof off-chain, checks `scopeBinding` against its known `scopeId`.
4. NFCU (even as AS/operator/issuer) sees only `scopeNullifier_A`. It cannot compute `scopeNullifier_B` or `scopeNullifier_C` without `agentSecret` (protected by Groth16/PLONK knowledge soundness + DL-BabyJubjub).
5. Even if NFCU colludes with the merchant, they hold `scopeNullifier_A` and `scopeNullifier_C` — these are outputs of a PRF on different inputs and are computationally unlinkable.
6. Timing correlation is mitigated by the batch relay: the agent submits nullifiers for A, B, C in a single batched transaction with a 10-second window.

**Healthcare variant:** A primary care provider (PCP) issues an agent credential. The agent visits Specialist-1 (scope: cardiology referral) and Specialist-2 (scope: dermatology referral). The PCP cannot reconstruct the referral network topology from on-chain data or from collusion with either specialist.

## 8. Why the baseline cannot match

| Capability | Baseline (PPID + DPoP + BBS+) | This construction |
|---|---|---|
| **AS sees token issuance per RS** | Yes — every token request hits the AS with (agent_id, RS, scope, timestamp) | No — proofs are generated locally, verified off-chain by RS or on-chain without scope identity |
| **AS can correlate scope sequences** | Yes — AS logs scope=X for RS-A, scope=Y for RS-B and builds behavioral timeline | No — scopeId is a private circuit input; on-chain only sees unlinkable nullifiers |
| **Colluding AS+RS can deanonymize** | Yes — AS holds PPID mapping table; any colluding RS can request the reverse mapping | No — PRF security of Poseidon2 makes cross-scope nullifier correlation computationally hard |
| **Issuer identity leaks to verifier** | Yes — BBS+ exposes issuer public key in every derived proof | No — operator public key is a private input; only the Merkle root (aggregating all issuers) is public |
| **Delegation chain visible to AS** | Yes — RFC 8693 requires AS roundtrip per hop | No — delegation uses on-chain scope commitment chain; AS is not in the loop |
| **Formal unlinkability guarantee** | None — no IND-UNL-AS game or equivalent exists in any RFC/W3C spec | Yes — IND-UNL-AS game defined with reduction to Poseidon-PRF |
| **Timing side-channel resistance** | None — DPoP timestamps leak request timing to AS | Batched submission with configurable window; uniform timing per batch |

**The structural impossibility:** The baseline requires the AS to issue every credential/token. This is not a misconfiguration — it is the definitional architecture of OAuth 2.0/OIDC. The AS is the root of trust and necessarily observes all issuance events. Bolyra's construction eliminates the AS from the per-request critical path entirely: the agent proves credential validity against a public Merkle root using a ZK proof, with scope identity hidden as a private witness. No standards-track mechanism in OAuth/OIDC can retrofit this property because the AS's role as token issuer is load-bearing — removing it breaks the security model. Bolyra's ZK construction makes the AS unnecessary for per-scope authorization while preserving the AS's role as credential issuer (enrollment-time only).
