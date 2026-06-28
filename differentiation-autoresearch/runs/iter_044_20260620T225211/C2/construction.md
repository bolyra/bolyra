# Construction

## 1. Statement of claim

Same agent accessing different Resource Server scopes produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that issued the credential, colludes with any strict subset of RSes, and performs timing analysis on token-issuance events. Formally: no PPT adversary controlling the AS and up to (n−1) of n RSes can distinguish which of two challenge scopes a target agent authorized, with advantage better than negligible in the security parameter λ.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopeIsolatedAuth`

This circuit replaces the standard AgentPolicy flow when cross-scope unlinkability is required. The agent generates proofs **offline** after a one-time credential enrollment — the AS is never contacted at authorization time.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentSecret` | F_p | Agent's long-term secret scalar (Baby Jubjub subgroup) |
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key |
| `permissionBitmask` | uint64 | 8-bit cumulative permission encoding |
| `expiryTimestamp` | uint64 | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credentialCommitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |
| `blindingNonce` | F_p | Per-authorization randomness for rerandomized scope commitment |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., `Poseidon("merchant-api.example.com")`) |
| `requiredScopeMask` | uint64 | Required permission bits for this RS |
| `currentTimestamp` | uint64 | Verifier-supplied current time |
| `agentMerkleRoot` | F_p | On-chain agent tree root (from root history buffer) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopePseudonym` | F_p | `Poseidon(scopeId, agentSecret)` — deterministic per (agent, scope), unlinkable across scopes |
| `blindedScopeCommitment` | F_p | `Poseidon(scopeCommitment, blindingNonce)` — rerandomized per authorization |
| `authBinding` | F_p | `Poseidon(scopePseudonym, currentTimestamp, blindingNonce)` — replay prevention |

**Constraints (10 gadgets):**

1. **Secret range**: `Num2Bits(251)` on `agentSecret` — ensures `agentSecret ∈ [0, 2^251)`.
2. **Permission range**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.
3. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
4. **EdDSA signature verification**: `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)`.
5. **Merkle membership**: `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf must equal `agentMerkleRoot`.
6. **Scope satisfaction**: For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.
7. **Cumulative bit encoding**: Standard 3-constraint financial tier implications (bits 4→3→2).
8. **Expiry**: `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
9. **Scope pseudonym**: `scopePseudonym = Poseidon(scopeId, agentSecret)` — the core unlinkability primitive. Deterministic per (agent, scope) for sybil detection within a scope, but unlinkable across scopes under Poseidon PRF.
10. **Blinded scope commitment**: `scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)`, then `blindedScopeCommitment = Poseidon(scopeCommitment, blindingNonce)`. The blinding prevents the AS from correlating the scope commitment across authorizations.
11. **Auth binding**: `authBinding = Poseidon(scopePseudonym, currentTimestamp, blindingNonce)` — binds the authorization to a specific moment and prevents replay.

### Modified protocol flow (AS-offline authorization)

1. **Enrollment (one-time, AS-visible):** Agent registers `credentialCommitment` in the on-chain Merkle tree. The AS sees this event.
2. **Authorization (AS-invisible):** Agent generates `ScopeIsolatedAuth` proof locally using the RS's `scopeId`. No AS contact. The RS verifies the proof against the on-chain `agentMerkleRoot`.
3. **RS verification:** RS checks (a) `agentMerkleRoot` is in the root history buffer, (b) `scopePseudonym` is not revoked, (c) proof verifies, (d) `currentTimestamp` is fresh. The RS learns only the `scopePseudonym` — not the `credentialCommitment`, not the operator identity.

### Timing side-channel mitigation: batched root refresh

To prevent the AS from correlating agent activity by observing Merkle tree read patterns, the on-chain root history buffer is public and cached by all participants. Agents cache the current root locally and do not query the contract at authorization time. Root staleness is bounded by the 30-entry buffer window.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (AS) — full key material, enrollment logs, issuance history
- Up to (n−1) of n Resource Servers — full access to presented proofs, pseudonyms, timestamps
- Network-level observation of all authorization traffic (timing, message sizes)
- The on-chain state (public by definition)

The adversary does NOT control:
- The agent's local proving environment (agentSecret remains private)
- The remaining honest RS

### Game: IND-UNL-AS (Indistinguishability of Unlinkability against Adversarial AS)

```
Game IND-UNL-AS(λ):

  Setup:
    1. Challenger generates system parameters, deploys Merkle tree.
    2. Adversary A enrolls agents of its choice (controls operator keys).
    3. A selects a target agent a* and enrolls it honestly
       (A sees credentialCommitment_a* but not agentSecret_a*).

  Challenge:
    4. A selects two distinct scope identifiers (scopeId_0, scopeId_1)
       such that A does NOT control the RS for either scope.
    5. Challenger flips bit b ←$ {0, 1}.
    6. Challenger generates a ScopeIsolatedAuth proof for a*
       with scopeId = scopeId_b, fresh blindingNonce, fresh currentTimestamp.
    7. A receives: (scopePseudonym_b, blindedScopeCommitment_b, authBinding_b, proof_b).

  Queries:
    8. A may request proofs for a* on any scope ∉ {scopeId_0, scopeId_1} (adaptive).
    9. A may request proofs for any agent a ≠ a* on any scope (adaptive).

  Output:
    10. A outputs b'. A wins if b' = b.

  Advantage:
    Adv^{IND-UNL-AS}_A(λ) = |Pr[b' = b] - 1/2|
```

**Winning condition:** A distinguishes which of two scopes the target agent authorized.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security** over BN254 scalar field: `Poseidon(scopeId, agentSecret)` is computationally indistinguishable from a random function when `agentSecret` is uniform and unknown. (Algebraic hash PRF assumption — standard in Semaphore/Bolyra.)
2. **Poseidon collision resistance**: No PPT adversary can find `(x₁, x₂) ≠ (y₁, y₂)` with `Poseidon(x₁, x₂) = Poseidon(y₁, y₂)`.
3. **Knowledge soundness of PLONK** (universal SRS): The PLONK proof system satisfies knowledge soundness in the algebraic group model + random oracle model.
4. **Discrete log hardness on Baby Jubjub**: Given `(Ax, Ay) = agentSecret · G`, recovering `agentSecret` is infeasible.
5. **Zero-knowledge property of PLONK**: The proof reveals nothing beyond the truth of the statement.

### Reduction sketch

**Theorem:** If Poseidon is a secure PRF, then `Adv^{IND-UNL-AS}_A(λ)` is negligible.

**Proof sketch:**

1. **Pseudonym unlinkability reduces to Poseidon PRF.** Suppose A has non-negligible advantage in IND-UNL-AS. We construct a PRF distinguisher B:
   - B receives oracle access to either `F_k(·) = Poseidon(·, k)` for random k, or a truly random function R(·).
   - B simulates the IND-UNL-AS game, using `F_k(scopeId_b)` as `scopePseudonym_b`.
   - If A distinguishes `scopePseudonym_0` from `scopePseudonym_1`, B distinguishes `F_k` from R — contradicting PRF security.

2. **Blinded scope commitment hides scope content.** `blindedScopeCommitment = Poseidon(scopeCommitment, blindingNonce)` where `blindingNonce` is fresh per authorization. Under collision resistance, different `blindingNonce` values produce distinct outputs. Under PRF (keyed by `blindingNonce`), the output is pseudorandom and independent of `scopeCommitment`. The adversary gains no information about `permissionBitmask` or `credentialCommitment`.

3. **Auth binding does not leak scope.** `authBinding = Poseidon(scopePseudonym, currentTimestamp, blindingNonce)` — since `scopePseudonym` is already pseudorandom (step 1) and `blindingNonce` is fresh, `authBinding` is computationally independent of `scopeId`.

4. **Zero-knowledge of PLONK** ensures the proof itself leaks nothing beyond public outputs. All private inputs (agentSecret, credentialCommitment, permissionBitmask, Merkle path) remain hidden.

5. **Timing side channel.** The agent generates proofs locally without AS contact. The AS observes only the one-time enrollment. RS-side timing is visible only to the RS the agent contacts — not to the AS or other RSes (by the game's constraint that A controls at most n−1 RSes). The honest RS does not collude.

**Conclusion:** A's advantage is bounded by `Adv^{PRF}_{Poseidon}(λ) + Adv^{ZK}_{PLONK}(λ)`, both negligible.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| `scopePseudonym = Poseidon(scopeId, agentSecret)` | Identical structure to human `nullifierHash = Poseidon(scope, secret)` | HumanUniqueness §S1.2, P1.3 |
| `credentialCommitment = Poseidon5(...)` | Standard AgentPolicy credential commitment | AgentPolicy §constraint 2 |
| `EdDSAPoseidonVerifier` | Operator signature verification | AgentPolicy §constraint 3 |
| `BinaryMerkleRoot(20)` with Poseidon2 | Agent Merkle tree membership | AgentPolicy §constraint 4 |
| Cumulative bit encoding (bits 4→3→2) | Permission hierarchy enforcement | AgentPolicy §constraint 6 |
| `scopeCommitment = Poseidon(permissionBitmask, credentialCommitment)` | Identity-bound scope commitment | Delegation chain linking |
| Root history buffer (30 entries) | Staleness tolerance for offline proving | Registry specification |
| Proving system: PLONK (universal SRS) | AgentPolicy OPTIONAL proving system | Proving Systems §PLONK |

**Key insight:** The `scopePseudonym` gadget mirrors the existing `nullifierHash` in HumanUniqueness — `Poseidon(scope, secret)`. Cross-scope unlinkability for agents reuses the identical cryptographic pattern already proven for humans (Property P1.3). The construction extends P1.3 from the human circuit to the agent circuit, adding blinding and auth binding for the agent-specific requirements (expiry, operator signature, permission satisfaction).

## 6. Circuit cost estimate

| Gadget | Estimated constraints |
|---|---|
| Num2Bits(251) — secret range | ~251 |
| Num2Bits(64) × 3 — permission, expiry, timestamp | ~192 |
| Poseidon5 — credential commitment | ~1,500 |
| EdDSAPoseidonVerifier | ~7,500 |
| BinaryMerkleRoot(20) — 20 × Poseidon2 | ~6,000 |
| Scope satisfaction — 64 bit-check constraints | ~192 |
| Cumulative bit encoding — 3 constraints | 3 |
| LessThan(64) — expiry check | ~128 |
| Poseidon2 — scope pseudonym | ~300 |
| Poseidon2 — scope commitment | ~300 |
| Poseidon2 — blinded scope commitment | ~300 |
| Poseidon3 — auth binding | ~450 |
| **Total** | **~17,100** |

Fits within `pot16.ptau` (2^16 = 65,536 constraint capacity).

**Proving time targets:**
- PLONK agent proof: **~3.5s** (snarkjs WASM), **~0.8s** (rapidsnark native) — within the <5s PLONK agent target.
- Groth16 alternative: **~2.0s** (snarkjs), **~0.4s** (rapidsnark) — available if ceremony cost is acceptable.

## 7. Concrete deployment scenario

**Stakeholder:** Navy Federal Credit Union (NFCU) — 13M+ members, largest US credit union.

**Scenario:** A member deploys an AI agent to (1) negotiate auto loan rates at three competing credit unions (PenFed, USAA, SchoolsFirst), (2) compare insurance quotes at two providers, and (3) manage recurring bill payments at two merchants. NFCU acts as the AS that issued the member's agent credential.

**Threat:** NFCU, as the issuing AS, must not learn which competing credit unions the member is shopping rates at, which insurance providers the member uses, or the member's merchant graph. Under NCUA privacy regulations and the member's expectation of privacy, NFCU seeing "member M's agent contacted PenFed, then USAA, then Geico" would be a regulatory and trust violation.

**Deployment:**

1. **Enrollment:** Member's agent is enrolled on-chain with `credentialCommitment` in the Bolyra agent Merkle tree. NFCU sees the enrollment event but not the `agentSecret`.

2. **Authorization at PenFed (scopeId = Poseidon("penfed.org/auto-loans")):**
   - Agent generates `ScopeIsolatedAuth` proof locally.
   - PenFed receives `scopePseudonym_penfed`, verifies proof against on-chain root.
   - PenFed knows: "an agent with `FINANCIAL_SMALL` permission, valid credential, pseudonym X visited." PenFed does not know: which credit union issued the credential, the member's identity, or that the agent also visited USAA.

3. **Authorization at Geico (scopeId = Poseidon("geico.com/quotes")):**
   - Agent generates a separate proof with a different `scopeId`.
   - `scopePseudonym_geico ≠ scopePseudonym_penfed` — unlinkable by Poseidon PRF.
   - Geico cannot correlate with PenFed even if they share data.

4. **NFCU's view:** NFCU sees only the one-time enrollment. No token issuance requests, no scope requests, no timing signals. The agent proves directly to each RS. NFCU's advantage in IND-UNL-AS is negligible.

5. **Sybil prevention within scope:** If PenFed requires one-agent-per-member, the deterministic `scopePseudonym` serves as a scope-local identifier. The same agent visiting PenFed twice produces the same pseudonym — detectable. But PenFed cannot link this pseudonym to any other scope.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails at three structural levels that no configuration or layering can repair:

**1. AS is in the authorization hot path — architecturally unfixable.**
Every OAuth/OIDC token is issued by the AS at authorization time. The AS sees `(agent_id, scope, RS, timestamp)` for every authorization event. The Bolyra construction removes the AS from the authorization path entirely: after one-time enrollment, the agent generates proofs locally. This is not a feature gap — it is an architectural incompatibility. You cannot make the AS blind to requests it must sign.

**2. No pseudonym primitive that is both deterministic-per-scope and unlinkable-across-scopes.**
OIDC PPIDs are AS-computed: the AS holds the mapping table and can reverse any PPID. BBS+ derived proofs are unlinkable but non-deterministic — two presentations to the same RS produce different proof values, so the RS cannot detect sybil agents. Bolyra's `scopePseudonym = Poseidon(scopeId, agentSecret)` is simultaneously:
- Deterministic per (agent, scope) → sybil detection within a scope
- Unlinkable across scopes → privacy across RSes
- Not computable by the AS → AS cannot simulate or predict pseudonyms

No combination of PPID + BBS+ achieves all three properties.

**3. No formal security definition exists in the baseline.**
The baseline has no IND-UNL-AS game, no reduction to a named hardness assumption, and no proof that adversary advantage is bounded. BBS+ proves multi-show unlinkability at the holder-verifier layer only — not against the issuer. DPoP proves sender-constraint security — not traffic-graph privacy. The Bolyra construction provides a concrete game definition (§3) and a reduction to Poseidon PRF security (§4), which the baseline cannot replicate because the AS's structural position makes the game trivially winnable.

**4. Timing side channels are mitigated by architecture, not policy.**
The baseline acknowledges (§6 of baseline) that timing correlation is unmitigated. Adding batching or padding to OAuth token requests is a policy control that degrades performance and can be stripped. Bolyra's construction eliminates the timing channel structurally: the AS is never contacted at authorization time, so there are no token-issuance timestamps to correlate. The agent's proof generation is local and invisible to the network.
