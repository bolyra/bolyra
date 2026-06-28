# Construction

## 1. Statement of claim

The same AI agent accessing N distinct Resource Servers (RSes) produces N cryptographically unlinkable authorization proofs, such that even an adversarial Authorization Server (AS) — defined as the entity controlling the agent Merkle tree and observing all on-chain events — cannot determine whether two proofs originated from the same agent, provided they target different scopes. This holds even when the AS colludes with a strict subset of RSes.

The baseline (PPID + RFC 8707 + DPoP + BBS+) achieves RS-to-RS unlinkability only; the AS sees every token issuance and can reconstruct the full per-agent cross-RS traffic graph. This construction eliminates the AS from the authentication hot path entirely and binds unlinkability to a named cryptographic assumption.

## 2. Construction (gadgets, circuits, public/private inputs)

### Blind enrollment protocol

The existing construction's credential commitment `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiry)` is fully known to the AS at enrollment time, since the AS computes it from operator-submitted fields. This allows the AS to forward-evaluate `Poseidon2(scopeId, credCommitment)` for every enrolled agent and every candidate `scopeId`, breaking unlinkability in O(N) time per scope.

**Fix:** The agent generates a private secret `agentSecret` (256-bit random, reduced mod BN254 scalar field order). The credential commitment becomes:

```
credCommitment = Poseidon6(modelHash, operatorPubkeyAx, operatorPubkeyAy,
                           permissionBitmask, expiryTimestamp, agentSecret)
```

The AS never learns `agentSecret`. Enrollment proceeds via a **commit-then-insert** protocol:

1. **Agent-side:** The agent generates `agentSecret`, computes `credCommitment = Poseidon6(...)` locally, and obtains the operator's EdDSA signature over `credCommitment`.
2. **Submission:** The agent sends `(credCommitment, operatorSignature)` to the AS. The AS verifies the signature against the operator's registered public key but does NOT receive the preimage fields individually.
3. **Insertion:** The AS inserts `credCommitment` as a leaf in the agent Merkle tree. The AS knows a valid credential was enrolled (signature proves operator authorization) but cannot decompose the commitment.

**Operator key registration:** The operator's public key `(Ax, Ay)` is registered with the AS out-of-band (e.g., at operator onboarding). The AS can verify EdDSA signatures against registered keys without needing the key embedded in the commitment preimage.

**Why the AS cannot recover `agentSecret`:** The AS sees only `credCommitment` (a single field element). Even if the AS knows `modelHash`, `Ax`, `Ay`, `permissionBitmask`, and `expiryTimestamp` (e.g., from operator registration metadata), recovering `agentSecret` requires inverting Poseidon6 on the last input — which contradicts Poseidon preimage resistance.

**Why the AS cannot enumerate:** Without `agentSecret`, the AS cannot compute `credCommitment` and therefore cannot evaluate `Poseidon2(scopeId, credCommitment)`. The forward-evaluation attack is blocked at the root.

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
| `agentSecret` | field | Agent-generated blinding entropy (never revealed to AS) |
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
2. **Credential commitment (blinded):** `credCommitment = Poseidon6(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp, agentSecret)`.
3. **EdDSA signature:** `EdDSAPoseidonVerifier(operatorPubkey, credCommitment, sig)`.
4. **Merkle membership:** `BinaryMerkleRoot(20, credCommitment, proof) == agentMerkleRoot`.
5. **Permission satisfaction:** `∀i ∈ [0,64): requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:** Standard Bolyra tier implications (bits 4→3→2).
7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scoped nullifier:** `scopedNullifier = Poseidon2(scopeId, credCommitment)`. This is the critical unlinkability gadget — `credCommitment` is private (contains `agentSecret` unknown to AS), so two nullifiers under different `scopeId` values are unlinkable without knowledge of `credCommitment`.
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
- Opaque `credCommitment` values at enrollment time (no preimage)
- No nullifiers, no scope IDs, no proofs

RS-A sees only its own `scopedNullifier` and `blindedScopeTag`. RS-B sees entirely different values for the same agent.

### Nullifier storage

Each RS maintains its own nullifier set (scoped to its `scopeId`). On-chain nullifier storage is NOT required — the RS checks locally. This eliminates the on-chain event emission that would otherwise leak information to the AS.

For delegation chain scenarios, the existing `Delegation` circuit's `newScopeCommitment` output is replaced with an analogous `delegateeScopedNullifier = Poseidon2(scopeId, delegateeCredCommitment)` and a blinded delegation tag. The delegatee's `credCommitment` also uses `Poseidon6` with the delegatee's own `agentSecret`, preserving the blinding property through the chain.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (enrollment authority, Merkle tree operator)
- Read access to all on-chain state (root history buffer, used nonces)
- A strict subset of RSes (up to N-1 of N total RSes)
- Timing observations of on-chain root queries
- **All enrollment data:** the set of opaque `credCommitment` values inserted into the tree (but NOT their preimages, since the agent computes the commitment locally and submits only the hash)

The adversary CANNOT:
- Break the discrete log problem on Baby Jubjub
- Find Poseidon collisions or preimages, or distinguish Poseidon from a random oracle
- Corrupt the proving system (Groth16 knowledge soundness / PLONK)
- Observe the direct network channel between agent and non-colluding RS (standard network assumption; composable with TLS)
- Learn `agentSecret` (generated and held exclusively by the agent; never transmitted to the AS)

### Forward-evaluation attack (explicitly addressed)

**Attack:** The AS knows every `credCommitment_i` in the tree (it inserted them). For a target `scopeId`, it evaluates `Poseidon2(scopeId, credCommitment_i)` for all N enrolled agents and compares against an observed `scopedNullifier`.

**Defense:** Under blind enrollment, the AS inserts opaque commitments it cannot decompose. However, it DOES hold the set `{credCommitment_1, ..., credCommitment_N}` — it can still attempt the forward-evaluation attack using these known values directly.

**Critical insight:** This attack SUCCEEDS if the AS holds the set of enrolled commitments, because `scopedNullifier = Poseidon2(scopeId, credCommitment)` and the AS knows both `scopeId` (public) and `credCommitment` (inserted during enrollment). The blind enrollment hides the *preimage* of the commitment but not the commitment *value itself*.

**Resolution — nullifier salting:** The scoped nullifier must incorporate `agentSecret` directly, not just indirectly through `credCommitment`:

```
scopedNullifier = Poseidon3(scopeId, credCommitment, agentSecret)
```

Now the AS holds `{credCommitment_i}` and knows `scopeId`, but cannot evaluate the nullifier without `agentSecret_i` — which it never receives. Forward evaluation requires either (a) recovering `agentSecret_i` from `credCommitment_i` (Poseidon preimage resistance) or (b) brute-forcing the ~254-bit `agentSecret` space (computationally infeasible).

**Updated circuit constraint (replaces constraint 8):**

8. **Scoped nullifier (salted):** `scopedNullifier = Poseidon3(scopeId, credCommitment, agentSecret)`. The AS cannot evaluate this without `agentSecret`, even knowing `credCommitment` from enrollment.

### IND-UNL-AS game

```
Game IND-UNL-AS(λ):
  1. Setup: Challenger runs Bolyra setup, generates agent Merkle tree T
     with ≥ 2 enrolled agents. Adversary A (as AS) receives all
     credCommitment values {credCommitment_0, credCommitment_1, ...}
     inserted into the tree.
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

1. **Poseidon PRF security** over BN254 scalar field: `Poseidon(k, ...)` is computationally indistinguishable from a random function when any input position contains a value unknown to the adversary.
2. **Poseidon preimage resistance:** Given `y = Poseidon6(x_1, ..., x_6)` and `(x_1, ..., x_5)`, recovering `x_6` is infeasible.
3. **Discrete log hardness on Baby Jubjub:** Given `(Ax, Ay) = BabyPbk(s)`, recovering `s` is infeasible.
4. **Knowledge soundness of Groth16** (in the generic group model + random oracle model for Fiat-Shamir) / **PLONK** (in the algebraic group model + ROM).
5. **Poseidon collision resistance:** Finding `(x₁, ..., x_n) ≠ (y₁, ..., y_n)` such that `Poseidon_n(x₁, ..., x_n) = Poseidon_n(y₁, ..., y_n)` is infeasible.

### Reduction sketch

**Theorem:** If Poseidon is a PRF and the proving system is knowledge-sound, then no PPT adversary wins IND-UNL-AS with non-negligible advantage, even when the adversary holds all enrolled `credCommitment` values.

**Proof sketch:**

1. **Nullifier unlinkability reduces to Poseidon PRF (with agentSecret as key).** The scoped nullifier is `Poseidon3(scopeId, credCommitment, agentSecret)`. The adversary knows `scopeId` (public input) and `credCommitment` (from enrollment), but NOT `agentSecret`. Under the PRF assumption keyed on `agentSecret`:
   - `Poseidon3(s₀, credCommitment, agentSecret)` and `Poseidon3(s₁, credCommitment, agentSecret)` are indistinguishable from independent random values to any adversary without `agentSecret`.
   - Therefore, observing nullifiers under different scope IDs reveals nothing about whether the same agent produced both — even when the adversary can enumerate all `credCommitment` values in the tree.

2. **Forward-evaluation attack is blocked.** The adversary holds `{credCommitment_1, ..., credCommitment_N}` and observes `scopedNullifier = Poseidon3(scopeId, credCommitment_b, agentSecret_b)`. To test whether agent `i` produced this nullifier, the adversary must evaluate `Poseidon3(scopeId, credCommitment_i, agentSecret_i)`, but `agentSecret_i` is unknown. The adversary's advantage in guessing the correct agent reduces to:
   - Recovering `agentSecret_i` from `credCommitment_i = Poseidon6(..., agentSecret_i)`: contradicts Poseidon preimage resistance.
   - Distinguishing `Poseidon3(scopeId, credCommitment_i, agentSecret_i)` from random without `agentSecret_i`: contradicts PRF security.

3. **Blinded scope tag unlinkability reduces to Poseidon PRF.** `blindedScopeTag = Poseidon2(scopeCommitment, scopeBlinder)` where `scopeBlinder` is fresh random per presentation. Even if `scopeCommitment` is identical across two presentations, the outputs are indistinguishable from random (one-time pad structure under PRF).

4. **Proof transcript unlinkability reduces to zero-knowledge.** Groth16 proofs are perfect zero-knowledge (simulator produces identically distributed transcripts). PLONK proofs are honest-verifier zero-knowledge in the ROM. The proof π itself leaks nothing beyond the public signals, which are already shown unlinkable in steps 1-3.

5. **AS removal eliminates the issuance-time correlation vector.** Since the agent generates proofs locally and presents them directly to the RS, the AS observes no per-authentication events. The only observable is Merkle root reads, which are shared across all agents and carry no per-agent information. Formally: the AS's view is independent of which agent authenticates to which RS.

6. **Colluding RS resistance (strengthened).** If the AS colludes with RS-A, it learns `scopedNullifier_A = Poseidon3(scopeId_A, credCommitment, agentSecret)`. The AS also knows `credCommitment` (from enrollment). To link this to RS-B's `scopedNullifier_B = Poseidon3(scopeId_B, credCommitment, agentSecret)`, the adversary must recover `agentSecret` from `(scopeId_A, credCommitment, scopedNullifier_A)` — which contradicts Poseidon preimage resistance (one known output, one unknown input among three).

**QED (sketch).**

### Side-channel mitigations

| Side channel | Mitigation |
|---|---|
| **Timing of root queries** | RS batches root freshness checks on a fixed schedule (e.g., every 30s), decoupling authentication timing from on-chain reads |
| **Proof size fingerprinting** | All `ScopedAgentAuth` proofs have identical size (Groth16: 3 group elements; PLONK: fixed polynomial commitment count) |
| **Nonce freshness leakage** | `sessionNonce` is generated by the RS (not the AS) and never posted on-chain; RS-local nullifier storage |
| **Enrollment-time correlation** | Blind enrollment: agent submits opaque `credCommitment` + signature; AS cannot decompose commitment or derive `agentSecret` |
| **Network-level correlation** | Out of scope; composable with standard TLS + onion routing if needed |

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Reference |
|---|---|---|
| Hash function (nullifier, commitments, scope tag) | Poseidon over BN254 scalar field | `circuits/src/`, spec §2 |
| Agent credential commitment (blinded) | `Poseidon6(modelHash, Ax, Ay, permissionBitmask, expiry, agentSecret)` | **Extended** — adds 6th input for agent-side entropy |
| Scoped nullifier (salted) | `Poseidon3(scopeId, credentialCommitment, agentSecret)` | **New** — triple-input prevents AS forward evaluation |
| Signature verification | EdDSA on Baby Jubjub via `EdDSAPoseidonVerifier` | circomlib component |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 node hash | Lean IMT, spec §3.2 |
| Cumulative bit encoding | Bits 4→3→2 implication constraints | `validateCumulativeBitEncoding()`, spec §4.2 |
| Proving system | Groth16 (REQUIRED) or PLONK (OPTIONAL) | spec §2.3 |
| Root history buffer | 30-entry circular buffer, read-only by RS | On-chain registry, spec §3.1 |
| Scope commitment (blinded) | `Poseidon2(Poseidon2(permBitmask, credCommitment), scopeBlinder)` | Extension of spec §1 scopeCommitment |
| Blind enrollment | Agent computes `credCommitment` locally, submits `(credCommitment, sig)` to AS | **New** — AS inserts opaque leaf |

**Compatibility note:** The `ScopedAgentAuth` circuit is a drop-in replacement for `AgentPolicy` in flows requiring cross-scope unlinkability. The `Poseidon6` credential commitment is backward-compatible at the Merkle tree level (same leaf size — one field element). The standard `AgentPolicy` with `Poseidon5` remains valid for single-scope deployments where AS trust is acceptable. The `HumanUniqueness` circuit is unchanged — humans already have scope-specific nullifiers (`Poseidon2(scope, secret)`) by design, and their `secret` is never shared with the AS.

**Design symmetry:** The human circuit already has the correct structure — `nullifierHash = Poseidon2(scope, secret)` where `secret` is agent-side entropy unknown to the enrollment authority. The `agentSecret` fix brings the agent circuit into structural parity with the human circuit's privacy model.

## 6. Circuit cost estimate

| Component | Constraints (approx.) |
|---|---|
| Num2Bits(64) × 3 (permBitmask, expiry, currentTimestamp) | 192 |
| Poseidon6 (blinded credential commitment) | ~1,500 |
| EdDSAPoseidonVerifier | ~4,000 |
| BinaryMerkleRoot (depth 20, Poseidon2 per level) | ~5,000 |
| Bit decomposition (64-bit) for permission satisfaction | 128 |
| Permission satisfaction (64 multiplications) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon3 (salted scoped nullifier) | ~450 |
| Poseidon2 (scope commitment) | ~300 |
| Poseidon2 (blinded scope tag) | ~300 |
| **Total** | **~12,067** |

Fits comfortably within 2^14 constraints (16,384). Uses `pot16.ptau` (2^16) for Groth16 Phase 2 ceremony. The increase from the prior estimate (~11,617) is +450 constraints: ~300 from Poseidon6 vs Poseidon5 (one additional round) and ~150 from Poseidon3 vs Poseidon2 for the salted nullifier.

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

1. **Enrollment (one-time, blind):** The member's agent generates `agentSecret` locally and computes `credCommitment = Poseidon6(modelHash, operatorPubkey, 0b00000100, expiry, agentSecret)`. The operator signs `credCommitment` via EdDSA. The agent submits `(credCommitment, signature)` to the credit union. The credit union verifies the operator signature, confirms the operator is registered, and inserts `credCommitment` into the agent Merkle tree. **The credit union never learns `agentSecret` or the preimage decomposition.**

2. **Payment to Amazon (RS-A):**
   - Agent generates `ScopedAgentAuth` proof with `scopeId = Poseidon("amazon.com")`.
   - `scopedNullifier_A = Poseidon3(Poseidon("amazon.com"), credCommitment, agentSecret)`.
   - Agent sends proof directly to Amazon's payment endpoint.
   - Amazon reads latest `agentMerkleRoot` from on-chain registry (batched, every 30s).
   - Amazon verifies proof locally, checks nullifier not reused, grants payment.

3. **Payment to Costco (RS-B):**
   - Agent generates proof with `scopeId = Poseidon("costco.com")`.
   - `scopedNullifier_B = Poseidon3(Poseidon("costco.com"), credCommitment, agentSecret)`.
   - Entirely independent flow. `scopedNullifier_B ≠ scopedNullifier_A`.

4. **Credit union (AS) attempts forward evaluation:** The credit union holds `credCommitment` (inserted at enrollment). It attempts `Poseidon3(Poseidon("amazon.com"), credCommitment, ???)` — but cannot evaluate without `agentSecret`. Even with all 13M enrolled commitments and a target `scopeId`, the credit union cannot compute any agent's scoped nullifier.

5. **Amazon + credit union collude:** Amazon shares `scopedNullifier_A` with the credit union. The credit union knows `credCommitment` and `scopeId_A`. To recover `agentSecret`, it must invert `Poseidon3(scopeId_A, credCommitment, agentSecret) = scopedNullifier_A` — a preimage search over ~254-bit space. Infeasible under Poseidon preimage resistance.

### Healthcare delegation chain

**Stakeholder:** A regional health system (e.g., Intermountain Health) where a primary care provider delegates agent access to a specialist.

**Scenario:** Patient's agent is delegated from PCP (RS-A) to cardiologist (RS-B) to lab (RS-C). The health system AS must not learn the referral network topology.

Each delegation hop uses the `Delegation` circuit with salted scope-specific nullifiers: `delegateeScopedNullifier = Poseidon3(scopeId_specialist, delegateeCredCommitment, delegateeAgentSecret)`. The delegatee's `credCommitment` uses `Poseidon6` with its own `agentSecret`, so the health system AS — even holding both `delegateeCredCommitment` and `delegatorCredCommitment` from enrollment — cannot compute either party's scoped nullifiers. The chain-linking `previousScopeCommitment` is verified inside the ZK proof but never exposed to the AS. The health system sees only that delegation proofs are verified — not who delegated to whom or which specialists were involved.

## 8. Why the baseline cannot match

| Property | Baseline (PPID + RFC 8707 + DPoP + BBS+) | ScopedAgentAuth |
|---|---|---|
| **AS sees token issuance** | Yes — every token request goes through AS | No — agent generates proof locally, presents directly to RS |
| **AS can correlate by timing** | Yes — AS logs request timestamps | No — AS sees only batched root reads shared across all agents |
| **AS forward evaluation** | Trivial — AS holds member_id and can enumerate all RS pairings | Blocked — AS holds `credCommitment` but cannot evaluate `Poseidon3(scopeId, credCommitment, agentSecret)` without `agentSecret` |
| **AS + RS collusion** | Trivial — AS holds PPID mapping, knows which sub maps to which RS | Requires recovering `agentSecret` from one `(scopeId, credCommitment, scopedNullifier)` tuple — Poseidon preimage-hard |
| **Formal unlinkability proof** | None — no IND-UNL-AS game defined in any RFC | Reduction to Poseidon PRF (keyed on `agentSecret`) + Groth16/PLONK knowledge soundness |
| **Scope separation** | RFC 8707 binds audience but AS sees requested scope at issuance | scopeId is a public input to the circuit but the AS never observes the proof; RS verifies locally |
| **Delegation privacy** | RFC 8693 requires AS roundtrip per hop — AS sees full chain | Delegation circuit links hops via ZK-verified scope commitments; AS sees only that a delegation proof was verified |
| **Enrollment privacy** | AS sees all credential fields at issuance | Blind enrollment: AS receives opaque `credCommitment` + operator signature; cannot decompose |
| **Nullifier cross-scope linkability** | N/A (no nullifiers) — AS uses persistent member_id | `Poseidon3(scopeId, credCommitment, agentSecret)` is scope-specific; linking requires `agentSecret` recovery |
| **Side-channel resistance** | No RFC mandates batching/padding | Batched root reads, fixed proof sizes, RS-local nullifier storage, blind enrollment |

**The structural impossibility:** The OAuth/OIDC baseline requires the AS to issue every token. This is not a misconfiguration — it is the protocol's architecture. No combination of PPIDs, DPoP proofs, or BBS+ selective disclosure removes the AS from the issuance path. The AS's view of `{agent, RS, scope, timestamp}` tuples is complete by construction.

Bolyra's `ScopedAgentAuth` eliminates this structural dependency at two layers: (1) **authentication** — the agent is a self-sovereign prover presenting directly to the RS, and (2) **enrollment** — blind enrollment ensures the AS cannot reconstruct credential preimages or forward-evaluate nullifiers. The AS's advantage in IND-UNL-AS is bounded by `max(Adv^{PRF}_{Poseidon}(λ), Adv^{preimage}_{Poseidon}(λ))` — negligible under standard assumptions.
