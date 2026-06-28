# Construction

## 1. Statement of claim

The same AI agent accessing N distinct Resource Servers (RSes) produces N cryptographically unlinkable authorization proofs, such that even an adversarial Authorization Server (AS) — defined as the entity controlling the agent Merkle tree and observing all on-chain events — cannot determine whether two proofs originated from the same agent, provided they target different scopes. This holds even when the AS colludes with a strict subset of RSes.

The baseline (PPID + RFC 8707 + DPoP + BBS+) achieves RS-to-RS unlinkability only; the AS sees every token issuance and can reconstruct the full per-agent cross-RS traffic graph. This construction eliminates the AS from the authentication hot path entirely and binds unlinkability to a named cryptographic assumption.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopedAgentAuth`

This circuit replaces `AgentPolicy` when cross-scope unlinkability is required. It produces a **scope-specific nullifier** that is deterministic within a scope (for sybil detection) but unlinkable across scopes (for privacy).

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Hash of model identifier |
| `operatorPubkeyAx` | field | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | field | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | 64-bit | Cumulative permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration (Unix) |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature components |
| `merkleProofLength` | field | Actual Merkle proof depth |
| `merkleProofIndex` | field | Leaf index |
| `merkleProofSiblings[20]` | field[20] | Sibling hashes |
| `scopeBlinder` | field | Fresh random blinding factor per presentation |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | Policy-required permission bits |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `scopeId` | field | RS-specific scope identifier (e.g., Poseidon("RS-A-domain")) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | field | Computed Merkle root |
| `scopedNullifier` | field | `Poseidon2(scopeId, credentialCommitment)` |
| `blindedScopeTag` | field | `Poseidon2(scopeCommitment, scopeBlinder)` |

**Circuit constraints:**

1. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.
2. **Credential commitment:** `credCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA signature:** `EdDSAPoseidonVerifier(operatorPubkey, credCommitment, sig)`.
4. **Merkle membership:** `BinaryMerkleRoot(20, credCommitment, proof) == agentMerkleRoot`.
5. **Permission satisfaction:** `∀i ∈ [0,64): requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:** Standard Bolyra tier implications (bits 4→3→2).
7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scoped nullifier:** `scopedNullifier = Poseidon2(scopeId, credCommitment)`. This is the critical unlinkability gadget — `credCommitment` is private, so two nullifiers under different `scopeId` values are unlinkable without knowledge of `credCommitment`.
9. **Blinded scope tag:** `scopeCommitment = Poseidon2(permissionBitmask, credCommitment)`, then `blindedScopeTag = Poseidon2(scopeCommitment, scopeBlinder)`. The blinder ensures even two proofs to the same RS with the same permissions produce distinct public outputs.

### Verification architecture (AS removal)

The structural change: RS verifies the agent's proof **locally** using the PLONK/Groth16 verification key plus a Merkle root freshness check against the on-chain root history buffer. No token issuance request reaches the AS.

```
Agent                          RS-A                         On-chain Registry
  |                             |                                |
  |-- ZK proof (scopeId=A) --> |                                |
  |                             |-- read agentMerkleRoot -----> |
  |                             |<- root ∈ history buffer ------|
  |                             |                                |
  |                             | verify(proof, vkey)            |
  |                             | check scopedNullifier not used |
  |                             | store scopedNullifier locally  |
  |                             |                                |
  |<---- access granted -----  |                                |
```

The AS (enrollment authority / tree maintainer) sees only:
- Merkle root read events (shared across all agents and RSes)
- No nullifiers, no scope IDs, no proofs

RS-A sees only its own `scopedNullifier` and `blindedScopeTag`. RS-B sees entirely different values for the same agent.

### Nullifier storage

Each RS maintains its own nullifier set (scoped to its `scopeId`). On-chain nullifier storage is NOT required — the RS checks locally. This eliminates the on-chain event emission that would otherwise leak information to the AS.

For delegation chain scenarios, the existing `Delegation` circuit's `newScopeCommitment` output is replaced with an analogous `delegateeScopedNullifier = Poseidon2(scopeId, delegateeCredCommitment)` and a blinded delegation tag.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (enrollment authority, Merkle tree operator)
- Read access to all on-chain state (root history buffer, used nonces)
- A strict subset of RSes (up to N-1 of N total RSes)
- Timing observations of on-chain root queries

The adversary CANNOT:
- Break the discrete log problem on Baby Jubjub
- Find Poseidon collisions or distinguish Poseidon from a random oracle
- Corrupt the proving system (Groth16 knowledge soundness / PLONK)
- Observe the direct network channel between agent and non-colluding RS (standard network assumption; composable with TLS)

### IND-UNL-AS game

```
Game IND-UNL-AS(λ):
  1. Setup: Challenger runs Bolyra setup, generates agent Merkle tree T
     with ≥ 2 enrolled agents (credCommitment₀, credCommitment₁).
  2. Challenge: Adversary A selects two distinct scopeIds (s₀, s₁) and
     a challenge bit b ←$ {0,1}.
     Challenger generates proof π using credCommitment_b for scope s₀
     and credCommitment_b for scope s₁.
     (Same agent, two scopes.)
     Challenger also generates proof π' using credCommitment_{1-b} for scope s₀
     and credCommitment_b for scope s₁.
     (Different agents, two scopes.)
     A receives {(π, scopedNullifier, blindedScopeTag) for s₀,
                 (π_s1, scopedNullifier_s1, blindedScopeTag_s1) for s₁}
     from one of the two worlds (same agent or different agents).
  3. A outputs guess b'.
  4. A wins if b' = b.

Advantage: Adv^{IND-UNL-AS}_A(λ) = |Pr[b' = b] - 1/2|
```

**Claim:** For all PPT adversaries A, `Adv^{IND-UNL-AS}_A(λ) ≤ Adv^{PRF}_{Poseidon}(λ) + Adv^{KS}_{Groth16/PLONK}(λ)`, where `Adv^{PRF}` is the advantage in distinguishing Poseidon from a random function and `Adv^{KS}` is the advantage in breaking knowledge soundness.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF security** over BN254 scalar field: `Poseidon2(k, x)` is computationally indistinguishable from a random function when `k` is unknown to the adversary.
2. **Discrete log hardness on Baby Jubjub:** Given `(Ax, Ay) = BabyPbk(s)`, recovering `s` is infeasible.
3. **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) / **PLONK** (in the algebraic group model + ROM).
4. **Poseidon collision resistance:** Finding `(x₁, x₂) ≠ (y₁, y₂)` such that `Poseidon2(x₁, x₂) = Poseidon2(y₁, y₂)` is infeasible.

### Reduction sketch

**Theorem:** If Poseidon is a PRF and the proving system is knowledge-sound, then no PPT adversary wins IND-UNL-AS with non-negligible advantage.

**Proof sketch:**

1. **Nullifier unlinkability reduces to Poseidon PRF.** The scoped nullifier is `Poseidon2(scopeId, credCommitment)`. The adversary knows `scopeId` (public input) but not `credCommitment` (private). Under the PRF assumption with `credCommitment` as the key:
   - `Poseidon2(s₀, credCommitment)` and `Poseidon2(s₁, credCommitment)` are indistinguishable from independent random values.
   - Therefore, observing nullifiers under different scope IDs reveals nothing about whether the same `credCommitment` produced both.

2. **Blinded scope tag unlinkability reduces to Poseidon PRF.** `blindedScopeTag = Poseidon2(scopeCommitment, scopeBlinder)` where `scopeBlinder` is fresh random per presentation. Even if `scopeCommitment` is identical across two presentations, the outputs are indistinguishable from random (one-time pad structure under PRF).

3. **Proof transcript unlinkability reduces to zero-knowledge.** Groth16 proofs are perfect zero-knowledge (simulator produces identically distributed transcripts). PLONK proofs are honest-verifier zero-knowledge in the ROM. The proof π itself leaks nothing beyond the public signals, which are already shown unlinkable in steps 1-2.

4. **AS removal eliminates the issuance-time correlation vector.** Since the agent generates proofs locally and presents them directly to the RS, the AS observes no per-authentication events. The only observable is Merkle root reads, which are shared across all agents and carry no per-agent information. Formally: the AS's view is independent of which agent authenticates to which RS.

5. **Colluding RS resistance.** If the AS colludes with RS-A, it learns `scopedNullifier_A = Poseidon2(scopeId_A, credCommitment)`. To link this to RS-B's `scopedNullifier_B = Poseidon2(scopeId_B, credCommitment)`, the adversary must invert Poseidon to recover `credCommitment` from the known `(scopeId_A, scopedNullifier_A)` pair — which contradicts PRF security (equivalently, one-wayness, which is implied by PRF).

**QED (sketch).**

### Side-channel mitigations

| Side channel | Mitigation |
|---|---|
| **Timing of root queries** | RS batches root freshness checks on a fixed schedule (e.g., every 30s), decoupling authentication timing from on-chain reads |
| **Proof size fingerprinting** | All `ScopedAgentAuth` proofs have identical size (Groth16: 3 group elements; PLONK: fixed polynomial commitment count) |
| **Nonce freshness leakage** | `sessionNonce` is generated by the RS (not the AS) and never posted on-chain; RS-local nullifier storage |
| **Network-level correlation** | Out of scope; composable with standard TLS + onion routing if needed |

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Reference |
|---|---|---|
| Hash function (nullifier, commitments, scope tag) | Poseidon over BN254 scalar field | `circuits/src/`, spec §2 |
| Agent credential commitment | `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiry)` | AgentPolicy circuit, spec §4.2 |
| Scoped nullifier | `Poseidon2(scopeId, credentialCommitment)` | **New** — replaces session-bound nullifier for cross-scope use |
| Signature verification | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | circomlib component |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | Lean IMT, spec §3.2 |
| Cumulative bit encoding | Bits 4→3→2 implication constraints | `validateCumulativeBitEncoding()`, spec §4.2 |
| Proving system | Groth16 (REQUIRED) or PLONK (OPTIONAL) | spec §2.3 |
| Root history buffer | 30-entry circular buffer, read-only by RS | On-chain registry, spec §3.1 |
| Scope commitment (blinded) | `Poseidon2(Poseidon2(permBitmask, credCommitment), scopeBlinder)` | Extension of spec §1 scopeCommitment |

**Compatibility note:** The `ScopedAgentAuth` circuit is a drop-in replacement for `AgentPolicy` in flows requiring cross-scope unlinkability. The standard `AgentPolicy` remains valid for single-scope deployments. The `HumanUniqueness` circuit is unchanged — humans already have scope-specific nullifiers (`Poseidon2(scope, secret)`) by design.

## 6. Circuit cost estimate

| Component | Constraints (approx.) |
|---|---|
| Num2Bits(64) × 3 (permBitmask, expiry, currentTimestamp) | 192 |
| Poseidon5 (credential commitment) | ~1,200 |
| EdDSAPoseidonVerifier | ~4,000 |
| BinaryMerkleRoot (depth 20, Poseidon2 per level) | ~5,000 |
| Bit decomposition (64-bit) for permission satisfaction | 128 |
| Permission satisfaction (64 multiplications) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon2 (scoped nullifier) | ~300 |
| Poseidon2 (scope commitment) | ~300 |
| Poseidon2 (blinded scope tag) | ~300 |
| **Total** | **~11,617** |

Fits comfortably within 2^14 constraints (16,384). Uses `pot16.ptau` (2^16) for Groth16 Phase 2 ceremony.

**Proving time targets:**
- Groth16 (snarkjs, browser): < 8s
- Groth16 (rapidsnark, native): < 1.5s
- PLONK (snarkjs): < 5s

These are well within the Bolyra envelope (Groth16 human < 15s, PLONK agent < 5s).

## 7. Concrete deployment scenario

### Cross-credit-union member agent

**Stakeholder:** A federal credit union (e.g., Navy Federal, 13M members) operating as an Authorization Server under NCUA regulation.

**Scenario:** A member's AI agent autonomously pays merchants (RS-A: Amazon, RS-B: Costco, RS-C: a local pharmacy). The credit union, acting as AS, must facilitate these payments but is legally prohibited from constructing a member's merchant graph (FCRA §604, Reg V).

**Current baseline failure:** The credit union's OAuth AS sees every token issuance: `{member_id, RS=Amazon, scope=financial_small, t=14:32}`, `{member_id, RS=Costco, scope=financial_small, t=14:35}`. The member's merchant graph is trivially reconstructable from AS logs.

**Bolyra ScopedAgentAuth flow:**

1. **Enrollment (one-time):** Credit union enrolls the member's agent credential into the agent Merkle tree. `credCommitment = Poseidon5(modelHash, operatorPubkey, 0b00000100, expiry)` (bit 2 = FINANCIAL_SMALL). The credit union knows the agent exists but this is the last time it observes agent-specific data.

2. **Payment to Amazon (RS-A):**
   - Agent generates `ScopedAgentAuth` proof with `scopeId = Poseidon("amazon.com")`.
   - `scopedNullifier_A = Poseidon2(Poseidon("amazon.com"), credCommitment)`.
   - Agent sends proof directly to Amazon's payment endpoint.
   - Amazon reads latest `agentMerkleRoot` from on-chain registry (batched, every 30s).
   - Amazon verifies proof locally, checks nullifier not reused, grants payment.

3. **Payment to Costco (RS-B):**
   - Agent generates proof with `scopeId = Poseidon("costco.com")`.
   - `scopedNullifier_B = Poseidon2(Poseidon("costco.com"), credCommitment)`.
   - Entirely independent flow. `scopedNullifier_B ≠ scopedNullifier_A`.

4. **Credit union (AS) observes:** Only Merkle root read events (shared across all 13M members' agents). Zero per-agent, per-merchant data. Cannot reconstruct merchant graph.

5. **Amazon + credit union collude:** Amazon shares `scopedNullifier_A` with the credit union. The credit union cannot compute `scopedNullifier_B` for Costco because it would need `credCommitment` (private) to evaluate `Poseidon2(Poseidon("costco.com"), credCommitment)`. Recovering `credCommitment` from `scopedNullifier_A` requires inverting Poseidon — infeasible under PRF assumption.

### Healthcare delegation chain

**Stakeholder:** A regional health system (e.g., Intermountain Health) where a primary care provider delegates agent access to a specialist.

**Scenario:** Patient's agent is delegated from PCP (RS-A) to cardiologist (RS-B) to lab (RS-C). The health system AS must not learn the referral network topology.

Each delegation hop uses the `Delegation` circuit with scope-specific nullifiers: `delegateeScopedNullifier = Poseidon2(scopeId_specialist, delegateeCredCommitment)`. The chain-linking `previousScopeCommitment` is verified inside the ZK proof but never exposed to the AS. The health system sees only that delegation proofs are verified — not who delegated to whom or which specialists were involved.

## 8. Why the baseline cannot match

| Property | Baseline (PPID + RFC 8707 + DPoP + BBS+) | ScopedAgentAuth |
|---|---|---|
| **AS sees token issuance** | Yes — every token request goes through AS | No — agent generates proof locally, presents directly to RS |
| **AS can correlate by timing** | Yes — AS logs request timestamps | No — AS sees only batched root reads shared across all agents |
| **AS + RS collusion** | Trivial — AS holds PPID mapping, knows which sub maps to which RS | Requires inverting Poseidon (PRF-hard) to recover credCommitment from one scopedNullifier |
| **Formal unlinkability proof** | None — no IND-UNL-AS game defined in any RFC | Reduction to Poseidon PRF + Groth16/PLONK knowledge soundness |
| **Scope separation** | RFC 8707 binds audience but AS sees requested scope at issuance | scopeId is a public input to the circuit but the AS never observes the proof; RS verifies locally |
| **Delegation privacy** | RFC 8693 requires AS roundtrip per hop — AS sees full chain | Delegation circuit links hops via ZK-verified scope commitments; AS sees only that a delegation proof was verified |
| **Nullifier cross-scope linkability** | N/A (no nullifiers) — AS uses persistent member_id | `Poseidon2(scopeId, credCommitment)` is scope-specific; linking requires credCommitment recovery |
| **Side-channel resistance** | No RFC mandates batching/padding | Batched root reads, fixed proof sizes, RS-local nullifier storage |

**The structural impossibility:** The OAuth/OIDC baseline requires the AS to issue every token. This is not a misconfiguration — it is the protocol's architecture. No combination of PPIDs, DPoP proofs, or BBS+ selective disclosure removes the AS from the issuance path. The AS's view of `{agent, RS, scope, timestamp}` tuples is complete by construction.

Bolyra's `ScopedAgentAuth` eliminates this structural dependency. The agent is a self-sovereign prover: it generates a ZK proof using only its private credential and the public Merkle root, then presents it directly to the RS. The AS is architecturally absent from authentication. Its advantage in IND-UNL-AS is bounded by `Adv^{PRF}_{Poseidon}(λ)` — negligible under standard assumptions.
