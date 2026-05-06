# Construction

## 1. Statement of claim

Same agent accessing different RS instances produces cryptographically unlinkable authorizations even under an adversarial AS that colludes with any proper subset of resource servers and inspects its full issuance log, timing metadata, and token introspection history. Formally: no PPT adversary controlling the AS and up to (n-1) of n RS instances can win the IND-UNL-AS game with non-negligible advantage over 1/2.

## 2. Construction (gadgets, circuits, public/private inputs)

### Architecture: Two-phase authorization with AS-blind per-scope presentation

**Phase 1 — Enrollment handshake (existing Bolyra mutual handshake)**

The agent completes a standard Bolyra mutual handshake exactly once per session. This establishes credential validity and produces a scope commitment chain seed on-chain. The AS participates here and learns that *some* agent authenticated. The AS does NOT learn which RS instances the agent will subsequently access.

**Phase 2 — Scope-Isolated Presentation (new circuit: `ScopeIsolatedPresentation`)**

After the handshake, the agent generates a per-RS PLONK proof locally. Each RS verifies the proof against the on-chain agent Merkle root. The AS is not involved in Phase 2 at all — this is the structural break from OAuth.

### New primitive: Agent scope secret

Each agent holds an additional private scalar `agentScopeSecret` ∈ [0, 2^251), committed into the credential via an extended credential commitment:

```
extCredCommitment = Poseidon3(credentialCommitment, Poseidon2(agentScopeSecretAx, agentScopeSecretAy))
```

where `(agentScopeSecretAx, agentScopeSecretAy) = BabyPbk(agentScopeSecret)`. The `extCredCommitment` is the leaf enrolled in the agent Merkle tree. The operator signs `extCredCommitment` rather than the bare `credentialCommitment`. The `agentScopeSecret` is never revealed to the operator or AS.

### Circuit: ScopeIsolatedPresentation (PLONK)

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key |
| `permissionBitmask` | 64-bit | Permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiry |
| `agentScopeSecret` | 251-bit | Agent's unlinkability secret |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator signature over extCredCommitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., hash of RS URI) |
| `requiredScopeMask` | 64-bit | Minimum required permission bits |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `epochNonce` | F_p | Time-bucketed nonce (see §side-channel treatment) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, agentScopeSecret)` |
| `epochBinding` | F_p | `Poseidon2(scopeNullifier, epochNonce)` |

### Circuit constraints (ScopeIsolatedPresentation):

1. **Range checks**: `Num2Bits(251)` on `agentScopeSecret`; `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.

2. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.

3. **Scope secret commitment**: `(ssAx, ssAy) = BabyPbk(agentScopeSecret)`; `scopeSecretCommitment = Poseidon2(ssAx, ssAy)`.

4. **Extended credential commitment**: `extCredCommitment = Poseidon3(credentialCommitment, scopeSecretCommitment)`.

5. **EdDSA signature**: `EdDSAPoseidonVerifier(operatorPubkey, extCredCommitment, sig)` — proves operator authorized this agent including its scope secret commitment.

6. **Merkle membership**: `BinaryMerkleRoot(20)` with `extCredCommitment` as leaf MUST produce `agentMerkleRoot`.

7. **Scope satisfaction**: For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.

8. **Cumulative bit encoding**: `bitmaskBits[4] * (1 - bitmaskBits[3]) === 0`; `bitmaskBits[4] * (1 - bitmaskBits[2]) === 0`; `bitmaskBits[3] * (1 - bitmaskBits[2]) === 0`.

9. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.

10. **Scope nullifier**: `scopeNullifier = Poseidon2(scopeId, agentScopeSecret)`. Deterministic per (scope, agent). Unlinkable across scopes under Poseidon PRF assumption.

11. **Epoch binding**: `epochBinding = Poseidon2(scopeNullifier, epochNonce)`. Binds the presentation to a time epoch for replay detection.

### Per-scope nullifier separation property

For two distinct scopes `s_A ≠ s_B`:

```
nullifier_A = Poseidon2(s_A, agentScopeSecret)
nullifier_B = Poseidon2(s_B, agentScopeSecret)
```

Under the Poseidon PRF assumption (keyed by `agentScopeSecret`), `nullifier_A` and `nullifier_B` are computationally indistinguishable from independent random values to any party that does not know `agentScopeSecret`. The AS never learns `agentScopeSecret` — it is a private circuit input not revealed by the PLONK proof (zero-knowledge property) and not included in any value the operator or AS observes.

### Side-channel treatment: epoch nonces and batched verification

**Timing correlation**: The AS observes when the handshake occurs but not when per-scope presentations happen (Phase 2 is AS-free). To prevent RS-side timing correlation, presentations use an `epochNonce` derived from a coarse time bucket (e.g., 5-minute epoch). All presentations within an epoch share the same `epochNonce`, eliminating sub-epoch timing as a linkage signal. The epoch nonce is published on-chain or by a public randomness beacon, ensuring all agents in the epoch use the same value.

**Nonce freshness**: `scopeNullifier` is deterministic per (scopeId, agentScopeSecret), preventing replay within a scope. `epochBinding` rotates per epoch, so stale presentations from prior epochs are rejected. The RS maintains an `epochBinding` seen-set per epoch and rejects duplicates.

**Traffic volume**: An adversarial AS that also controls RS-A sees RS-A's access count but cannot correlate it with any specific agent's handshake, because Phase 2 does not transit the AS. Multiple agents' presentations are indistinguishable at the RS if they arrive within the same epoch.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (AS) completely: all issuance logs, timing data, internal state, and code
- Up to (n-1) of n RS instances: full access to received proofs, nullifiers, epoch bindings, and access patterns
- Network observation between the agent and all RS instances (but not the ability to break TLS — standard Dolev-Yao with encrypted channels)

The adversary does NOT control:
- The agent's local proving environment (the agent's `agentScopeSecret` remains private)
- The on-chain Merkle tree integrity (public, append-only)
- The PLONK verifier contract (assumed correct)

### IND-UNL-AS game definition

```
Game IND-UNL-AS(λ):

  Setup:
    1. Run Bolyra setup. Enroll m ≥ 2 agents in the agent Merkle tree.
    2. Adversary A selects two target scopes s₀, s₁ where s₀ ≠ s₁.
    3. Adversary A selects a challenge agent identity (enrolled, with
       agentScopeSecret unknown to A).

  Challenge:
    4. Challenger flips bit b ←$ {0, 1}.
    5. Challenger generates two ScopeIsolatedPresentation proofs:
       - π_left for scope s_b with epochNonce e
       - π_right for scope s_{1-b} with epochNonce e
    6. Challenger sends (π_left, π_right) to A.
       A also receives the public outputs:
       (agentMerkleRoot, scopeNullifier_left, epochBinding_left) and
       (agentMerkleRoot, scopeNullifier_right, epochBinding_right).
       A also receives the full AS issuance log from the handshake phase.

  Oracle access:
    7. A may adaptively request ScopeIsolatedPresentation proofs for
       ANY other agent or for the challenge agent on ANY scope other
       than {s₀, s₁}.

  Output:
    8. A outputs b' ∈ {0, 1}.
    A wins if b' = b.

  Advantage:
    Adv^{IND-UNL-AS}_A(λ) = |Pr[b' = b] - 1/2|
```

**Security requirement**: For all PPT adversaries A, `Adv^{IND-UNL-AS}_A(λ) ≤ negl(λ)`.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security**: Poseidon2, keyed by a uniformly random key k ∈ F_p, is a secure pseudorandom function. Formally: for all PPT distinguishers D, `|Pr[D^{Poseidon2(k,·)} = 1] - Pr[D^{R(·)} = 1]| ≤ negl(λ)` where R is a truly random function.

2. **PLONK knowledge soundness**: The PLONK proving system used for ScopeIsolatedPresentation satisfies knowledge soundness: for any PPT prover P* that produces an accepting proof, there exists a PPT extractor E that extracts a valid witness.

3. **PLONK zero-knowledge**: The PLONK proving system satisfies computational zero-knowledge: the proof reveals nothing about the witness beyond the truth of the statement.

4. **Discrete log hardness on Baby Jubjub**: Given `(G, agentScopeSecret · G)`, no PPT adversary can recover `agentScopeSecret` with non-negligible probability.

### Reduction sketch

**Theorem**: If Poseidon2 is a secure PRF and PLONK is zero-knowledge, then no PPT adversary wins the IND-UNL-AS game with non-negligible advantage.

**Proof sketch**:

*Step 1 (ZK simulation)*: Replace both challenge proofs (π_left, π_right) with simulated proofs using the PLONK simulator. By computational zero-knowledge, A's view is computationally indistinguishable. The simulated proofs carry the same public outputs but reveal no witness information. Cost: advantage loss ≤ `2 · Adv^{ZK}_{PLONK}(λ)`.

*Step 2 (PRF switch)*: The public outputs visible to A are `(scopeNullifier_left, scopeNullifier_right)` where:
- `scopeNullifier_left = Poseidon2(s_b, agentScopeSecret)`
- `scopeNullifier_right = Poseidon2(s_{1-b}, agentScopeSecret)`

Since `agentScopeSecret` is uniformly random in [0, 2^251) and unknown to A (it was never revealed — the operator signs `extCredCommitment` which commits to `BabyPbk(agentScopeSecret)` but does not reveal the scalar, and the ZK proof hides it), we invoke the Poseidon PRF assumption keyed by `agentScopeSecret`.

Replace `Poseidon2(agentScopeSecret, ·)` with a truly random function `R(·)`. Cost: advantage loss ≤ `Adv^{PRF}_{Poseidon}(λ)`.

*Step 3 (Information-theoretic argument)*: After the PRF switch, A sees `(R(s_b), R(s_{1-b}))` which is identically distributed to `(R(s_{1-b}), R(s_b))` for a truly random function R. The view is independent of b. A's advantage is exactly 0.

*Step 4 (AS log independence)*: The AS issuance log from Phase 1 contains the handshake proof (which uses a *different* nullifier: `Poseidon2(credentialCommitment, sessionNonce)`) and the scope commitment chain seed. Neither contains `agentScopeSecret` or any scope-specific information from Phase 2. The handshake nullifier is credential-bound, not scope-bound, and is the same regardless of which scopes the agent later accesses. The scope commitment from the handshake encodes the agent's *full* permission bitmask, not the specific RS being accessed. Therefore the AS log is independent of b.

*Step 5 (Epoch binding independence)*: `epochBinding = Poseidon2(scopeNullifier, epochNonce)`. Since `scopeNullifier` is already pseudorandom (Step 2) and `epochNonce` is public, `epochBinding` is also pseudorandom and independent across scopes. No additional advantage.

**Total advantage bound**:
```
Adv^{IND-UNL-AS}_A(λ) ≤ 2·Adv^{ZK}_{PLONK}(λ) + Adv^{PRF}_{Poseidon}(λ) ≤ negl(λ)
```

### Collusion resistance argument

When the AS colludes with RS-A (controlling RS-A's full state), the adversary sees:
- AS log: handshake nullifier, scope commitment seed, timing of handshake
- RS-A state: `scopeNullifier_A = Poseidon2(s_A, agentScopeSecret)`, `epochBinding_A`, proof π_A

The adversary does NOT see RS-B's `scopeNullifier_B` (RS-B is honest). Even if the adversary knows `scopeNullifier_A` and the `agentMerkleRoot`, recovering `agentScopeSecret` from `scopeNullifier_A = Poseidon2(s_A, agentScopeSecret)` requires inverting Poseidon2, which contradicts PRF security (a PRF is also one-way). Without `agentScopeSecret`, the adversary cannot compute `scopeNullifier_B = Poseidon2(s_B, agentScopeSecret)` and therefore cannot verify whether any nullifier observed at RS-B belongs to the challenge agent.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope nullifier `Poseidon2(scopeId, agentScopeSecret)` | Poseidon hash (BN128 scalar field) | §2 Cryptographic Primitives |
| Agent scope secret key derivation `BabyPbk(agentScopeSecret)` | EdDSA on Baby Jubjub | §2 Cryptographic Primitives |
| Extended credential commitment `Poseidon3(credComm, scopeSecretComm)` | Poseidon hash | §2 Cryptographic Primitives |
| Merkle membership proof | Lean Incremental Merkle Tree, depth 20, Poseidon2 node hash | §2 Cryptographic Primitives |
| Operator signature over extCredCommitment | EdDSA on Baby Jubjub (EdDSAPoseidonVerifier) | §4.2 Agent Proof Specification |
| ScopeIsolatedPresentation proving system | PLONK with universal setup | §2.3 Proving Systems (agent circuits use PLONK) |
| On-chain root verification | Root history buffer (30 entries) | §2.1 System Architecture |
| Epoch binding `Poseidon2(scopeNullifier, epochNonce)` | Poseidon hash | §2 Cryptographic Primitives |
| Scope satisfaction bit check | Cumulative bit encoding + per-bit constraint | §4.2 constraint 5–6 |
| Phase 1 handshake (enrollment proof) | Existing mutual handshake protocol | §3 Mutual Handshake Protocol |

No primitives outside the Bolyra specification are used. The `ScopeIsolatedPresentation` circuit composes existing Bolyra gadgets (Poseidon, BabyPbk, EdDSAPoseidonVerifier, BinaryMerkleRoot, Num2Bits, LessThan) in a new arrangement.

## 6. Circuit cost estimate

### ScopeIsolatedPresentation constraint breakdown

| Gadget | Count | Constraints per instance | Subtotal |
|--------|-------|------------------------|----------|
| `Num2Bits(251)` — agentScopeSecret range | 1 | 251 | 251 |
| `Num2Bits(64)` — permissionBitmask, expiryTimestamp, currentTimestamp | 3 | 64 | 192 |
| `Poseidon5` — credentialCommitment | 1 | ~1,500 | 1,500 |
| `BabyPbk` — scope secret pubkey | 1 | ~2,500 | 2,500 |
| `Poseidon2` — scopeSecretCommitment | 1 | ~300 | 300 |
| `Poseidon3` — extCredCommitment | 1 | ~450 | 450 |
| `EdDSAPoseidonVerifier` | 1 | ~5,000 | 5,000 |
| `BinaryMerkleRoot(20)` — 20 Poseidon2 hashes + mux | 1 | ~6,400 | 6,400 |
| Scope satisfaction (64 bit-checks) | 1 | ~200 | 200 |
| Cumulative bit encoding (3 constraints) | 1 | 3 | 3 |
| `LessThan(64)` — expiry check | 1 | ~130 | 130 |
| `Poseidon2` — scopeNullifier | 1 | ~300 | 300 |
| `Poseidon2` — epochBinding | 1 | ~300 | 300 |
| **Total** | | | **~17,526** |

### Proving time targets

| Proof | System | Constraints | Target | Device |
|-------|--------|-------------|--------|--------|
| ScopeIsolatedPresentation | PLONK | ~17,500 | < 3s | Server-side agent (M1/x86-64, 8 GB RAM) |
| HumanUniqueness (existing) | Groth16 | ~12,000 | < 15s | Client-side human (mobile/browser) |

PLONK universal setup: reuses existing Bolyra PLONK SRS (degree ≥ 2^15 sufficient). No circuit-specific ceremony required.

### Per-RS overhead

Each RS access requires one PLONK proof generation (~3s agent-side) and one on-chain or off-chain PLONK verification (~300k gas on-chain, or <50ms off-chain). For an agent accessing 5 RS instances per session, total additional proving time is ~15s, parallelizable across scopes.

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent — CU-as-AS must not see member merchant graph

**Stakeholders**:
- **State Employees' Credit Union (SECU)** — acts as AS, enrolls members and issues agent credentials
- **Member agent** — AI agent acting on behalf of a SECU member, accessing merchant services
- **Merchant RS instances** — Amazon Business (RS-A), Costco Business (RS-B), local auto dealer (RS-C)

**Problem**: SECU issues OAuth tokens today. When a member's agent accesses Amazon Business and Costco Business, SECU's AS log shows `{agent_42, scope: merchant:read, aud: amazon-biz, t: 14:03:01}` and `{agent_42, scope: merchant:read, aud: costco-biz, t: 14:03:47}`. SECU can reconstruct the member's full merchant spending graph. If SECU colludes with Amazon (e.g., a data-sharing partnership), they can confirm the member also shops at Costco by correlating the AS-side `sub` with Amazon's access log.

**Bolyra deployment**:

1. **Enrollment**: SECU enrolls the member's agent with credential `(modelHash, operatorPubkey, permissionBitmask=0b11100, expiry)`. The agent locally generates `agentScopeSecret`, computes `extCredCommitment`, and SECU's operator signs it. The `extCredCommitment` leaf is added to the on-chain agent Merkle tree. SECU knows the agent exists but does not know `agentScopeSecret`.

2. **Handshake (Phase 1)**: Member completes the Bolyra mutual handshake with their agent. SECU-as-AS observes the handshake event and the scope commitment chain seed. SECU learns: "agent_42 authenticated at 14:00:00." SECU does NOT learn which merchants the agent will access.

3. **Merchant access (Phase 2)**: The agent generates three `ScopeIsolatedPresentation` proofs:
   - For Amazon: `scopeNullifier_amazon = Poseidon2(H("amazon-biz"), agentScopeSecret)`
   - For Costco: `scopeNullifier_costco = Poseidon2(H("costco-biz"), agentScopeSecret)`
   - For auto dealer: `scopeNullifier_auto = Poseidon2(H("auto-dealer"), agentScopeSecret)`

   Each merchant verifies the proof against the on-chain Merkle root. No merchant contacts SECU. SECU's AS log shows only the handshake — zero per-merchant entries.

4. **Collusion resistance**: SECU partners with Amazon and receives Amazon's full access log including `scopeNullifier_amazon`. SECU cannot compute `scopeNullifier_costco` from this because it does not know `agentScopeSecret`. SECU cannot determine whether the agent that accessed Amazon also accessed Costco.

5. **Sybil resistance within scope**: Amazon sees the same `scopeNullifier_amazon` on every access by this agent within the same epoch, preventing the agent from creating multiple accounts or double-spending merchant credits.

**Regulatory alignment**: This satisfies NCUA §712 privacy requirements for credit union member financial data and aligns with the GENIUS Act's member data portability provisions — SECU provides identity infrastructure without gaining surveillance capability over member commerce.

## 8. Why the baseline cannot match

### Structural impossibility 1: AS observes every token issuance

In OAuth 2.0 / OIDC, every access token is minted by the AS. The AS necessarily sees the `aud` (audience), `scope`, and `sub` (subject) of every token it issues. RFC 8707 Resource Indicators *requires* the agent to declare the target RS to the AS at token request time. DPoP proof-of-possession is verified by the AS during token issuance. There is no OAuth flow where the agent obtains a per-RS token without the AS learning the target RS.

The Bolyra construction eliminates AS involvement in per-RS authorization entirely. Phase 2 proofs are generated locally by the agent and verified by the RS against public on-chain state. The AS has no role, no API call, no log entry, and no timing signal from Phase 2.

### Structural impossibility 2: PPID is AS-reversible

OIDC Pairwise Subject Identifiers are computed by the AS using a deterministic algorithm: `sub_pairwise = H(sector_id || local_sub || salt)`. The AS knows the salt, the local_sub, and the sector_id. The AS can trivially reverse any PPID it issued and correlate across sectors. PPID protects RS-vs-RS correlation only when the AS is honest — it provides zero protection in the IND-UNL-AS game where the AS is the adversary.

The Bolyra scope nullifier `Poseidon2(scopeId, agentScopeSecret)` uses `agentScopeSecret` which the AS never learns. The AS cannot compute, predict, or reverse any scope nullifier because it lacks the key.

### Structural impossibility 3: No formal security definition exists in the baseline

No OAuth, OIDC, or BBS+ specification defines an unlinkability game against an adversarial authorization server. The strongest formal guarantee in the baseline stack is BBS+ multi-presentation unlinkability (draft-irtf-cfrg-bbs-signatures §6), which models an adversarial *verifier*, not an adversarial *issuer*. The IND-UNL-AS game defined in this construction has no counterpart in any RFC or W3C specification.

### Structural impossibility 4: No nullifier separation primitive exists

The concept of a scope-bound nullifier — a value that is deterministic within a scope (enabling replay/sybil detection) but pseudorandom across scopes (enabling unlinkability) — requires a PRF keyed by a secret unknown to the AS. OAuth's `jti` (JWT ID) is AS-generated and AS-visible. DPoP's `jti` is agent-generated but sent to the AS during token binding. BBS+ credentials do not produce per-scope deterministic identifiers. No baseline primitive can express `f(scope, secret)` where `secret` is hidden from the issuer and `f` is deterministic.

### Structural impossibility 5: Side-channel silence requires AS removal

Timing correlation between token issuance events is inherent when the AS mediates every RS access. Even with constant-time token endpoints, the AS observes the *sequence* and *cadence* of token requests, which leaks the agent's access pattern. The Bolyra construction eliminates this channel entirely: Phase 2 has no AS interaction, so the AS observes zero timing signals correlated with RS access. The epoch nonce mechanism further eliminates RS-side sub-epoch timing correlation.

### Summary: Baseline ceiling vs. construction floor

| Property | Baseline (OIDC+PPID+DPoP+BBS+) | This construction |
|----------|-------------------------------|-------------------|
| AS sees which RS per token | Yes (structural) | No (Phase 2 is AS-free) |
| AS can reverse pseudonyms | Yes (PPID is AS-keyed) | No (nullifier is agent-keyed) |
| Formal IND-UNL-AS proof | Does not exist | Reduced to Poseidon PRF + PLONK ZK |
| Per-scope deterministic nullifier | Not expressible | `Poseidon2(scopeId, agentScopeSecret)` |
| Collusion resistance (AS + RS subset) | None (AS reverses PPID) | Proven: requires inverting Poseidon PRF |
| Timing side-channel treatment | No normative treatment | AS removed from per-RS flow; epoch bucketing |
