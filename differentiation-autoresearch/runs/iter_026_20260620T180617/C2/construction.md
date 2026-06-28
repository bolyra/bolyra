# Construction

## 1. Statement of claim

The same AI agent, holding a single credential enrolled in the Bolyra agent Merkle tree, can produce authorizations for N distinct Resource Servers (scopes) such that no coalition of the Authorization Server and any strict subset of RSes can determine whether two authorizations originated from the same agent. This holds even when the AS issued the credential and observes all token-issuance metadata. Formally: no PPT adversary controlling the AS and up to N-1 RSes wins the IND-UNL-AS game (defined in §3) with advantage greater than negligible in the security parameter.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopedPresentation`

This circuit allows an agent to produce a scope-specific, unlinkable authorization proof. The AS never appears in the verification path — the agent proves directly to the RS using the on-chain Merkle root.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA pubkey x-coordinate |
| `operatorPubkeyAy` | F_p | Operator EdDSA pubkey y-coordinate |
| `permissionBitmask` | 64-bit | Full permission bitfield |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x, sigR8y, sigS` | F_p | Operator EdDSA signature over credential commitment |
| `scopeBlinder` | F_p | Per-scope random blinder (agent-generated, stored locally) |
| `merkleProofLength` | ≤20 | Actual Merkle depth |
| `merkleProofIndex` | ≤2^20 | Leaf index |
| `merkleProofSiblings[20]` | F_p[20] | Sibling hashes |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rsIdentifier` | F_p | On-chain registered RS identity (e.g., hash of RS domain or RS public key) |
| `scopeLabel` | F_p | RS-chosen scope descriptor (e.g., Poseidon("merchant-read")) |
| `requiredScopeMask` | 64-bit | Minimum permission bits the RS demands |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `presentationNonce` | F_p | Fresh per-request nonce from RS |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `scopeNullifier` | F_p | Poseidon2(scopeId, Poseidon2(credentialCommitment, scopeBlinder)) where scopeId is circuit-derived — deterministic per (agent, RS, scopeLabel) |
| `presentationBinding` | F_p | Poseidon2(scopeNullifier, presentationNonce) — replay prevention |
| `blindedScopeCommitment` | F_p | Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder) — unlinkable across scopes |

**Constraints (in order):**

1. **Range checks:** Num2Bits(64) on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.
2. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA signature verification:** `EdDSAPoseidonVerifier(operatorPubkeyAx, operatorPubkeyAy, sigR8x, sigR8y, sigS, credentialCommitment)` — proves operator authorized this credential.
4. **Merkle membership:** `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf produces `agentMerkleRoot`.
5. **Scope satisfaction:** For each bit i in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:**
   - `permBits[4] * (1 - permBits[3]) === 0`
   - `permBits[4] * (1 - permBits[2]) === 0`
   - `permBits[3] * (1 - permBits[2]) === 0`
7. **Expiry:** `currentTimestamp < expiryTimestamp` via LessThan(64).
8. **Scope ID binding:** `scopeId = Poseidon2(rsIdentifier, scopeLabel)`. This is the critical anti-collision constraint — two RSes with distinct `rsIdentifier` values CANNOT produce the same `scopeId` regardless of their `scopeLabel` choices (under P-CR). The agent does not accept `scopeId` as a free input; it is derived inside the circuit from the RS's registered identity.
9. **Scope nullifier derivation:** `innerHash = Poseidon2(credentialCommitment, scopeBlinder)`, then `scopeNullifier = Poseidon2(scopeId, innerHash)`.
10. **Presentation binding:** `presentationBinding = Poseidon2(scopeNullifier, presentationNonce)`.
11. **Blinded scope commitment:** `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)`.

### Key design decisions

**Scope ID binding (anti-collision):** The prior construction accepted `scopeId` as a free public input, which allowed adversarial RSes to choose identical `scopeId` values and force nullifier linkage. The fix is constraint 8: `scopeId` is computed inside the circuit as `Poseidon2(rsIdentifier, scopeLabel)`. Since `rsIdentifier` is an on-chain registered value unique to each RS (verified by the on-chain verifier or the application-layer RS registry), two distinct RSes cannot produce the same `scopeId` even if they collude on `scopeLabel`. This closes the gap at the circuit level — no application-layer defense is needed.

**rsIdentifier verification:** The on-chain verifier contract MUST maintain an RS registry mapping `rsIdentifier → registered(bool)`. An RS registers by submitting its identifier (e.g., `Poseidon2(domainHash, rsPubkeyHash)`) and proving ownership via an on-chain transaction from its registered address. The circuit does not enforce the registry check — it only enforces that `scopeId` is deterministically derived from `rsIdentifier`. The registry check is performed by the on-chain verifier's wrapper or the verifying RS itself. This separation is standard: the circuit guarantees structural integrity; the contract guarantees enrollment.

**scopeBlinder keying change:** The agent's `scopeBlinder` is now keyed per `(credentialCommitment, rsIdentifier, scopeLabel)` triple rather than per `scopeId`. In practice this is the same since `scopeId` is deterministic from the latter two, but making `rsIdentifier` explicit in the keying prevents an agent implementation from accidentally reusing blinders if two RSes happen to claim identical scopeLabels before the circuit catches the distinction.

**Scope blinder:** The agent generates one random `scopeBlinder` per (credential, rsIdentifier, scopeLabel) triple and stores it locally. This ensures:
- Same agent + same RS + same scopeLabel → same `scopeNullifier` (Sybil detection within a scope)
- Same agent + different RS (or different scopeLabel) → different `scopeNullifier` (unlinkability across scopes)
- The blinder is never revealed; it is a private input to the circuit

**No AS in the loop:** The RS verifies the PLONK/Groth16 proof directly against the on-chain `agentMerkleRoot`. The AS is not contacted at verification time. The credential was enrolled on-chain at issuance; subsequent presentations bypass the AS entirely.

**Delegation extension:** For delegated agents, replace `credentialCommitment` with the output of a preceding `Delegation` circuit proof. The `scopeNullifier` derivation remains identical, using the delegatee's credential commitment. Chain linking uses `blindedScopeCommitment` instead of the standard `scopeCommitment`, preserving unlinkability through delegation hops.

### Modified circuit: `ScopedDelegation`

Identical to the existing `Delegation` circuit except:
- The `newScopeCommitment` output is replaced with `blindedScopeCommitment = Poseidon3(delegateeScope, delegateeCredCommitment, delegateeScopeBlinder)`.
- Chain linking uses `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder) === previousBlindedScopeCommitment`.
- Adds `delegatorScopeBlinder` and `delegateeScopeBlinder` as private inputs.
- Scope ID binding applies identically: any `scopeId` used within delegation is derived as `Poseidon2(rsIdentifier, scopeLabel)`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:
- The Authorization Server (full state: issuance logs, credential database, timing of all requests)
- Up to N-1 of N Resource Servers (colluding RSes share all received proofs and metadata)
- Network-level observation of proof submission timing to the non-colluding RS
- **The `scopeLabel` values presented to agents by adversary-controlled RSes** (adversarial RSes may choose arbitrary scopeLabel values, including duplicating labels used by honest RSes)

The adversary does NOT control:
- The agent's local state (secret key, scope blinders)
- The on-chain smart contract logic (public, deterministic)
- The Groth16/PLONK proving system internals
- **The `rsIdentifier` of honest RSes** — each RS's identifier is bound to its on-chain registration. An adversary controlling RS-B cannot forge RS-A's `rsIdentifier`. This is the structural defense against scopeId collision: even if the adversary sets `scopeLabel_B = scopeLabel_A`, the circuit computes `scopeId_B = Poseidon2(rsIdentifier_B, scopeLabel_A) ≠ Poseidon2(rsIdentifier_A, scopeLabel_A) = scopeId_A` (under P-CR, since `rsIdentifier_B ≠ rsIdentifier_A`).

### ScopeId collision attack analysis

**Attack vector (now mitigated):** In the prior construction, `scopeId` was a free public input. Adversarial RS-B could set `scopeId_B = scopeId_A` (copying the honest RS-A's scope identifier). The agent, following its per-scopeId blinder policy, would reuse `scopeBlinder` and produce the same `scopeNullifier` at both RSes, enabling linkage.

**Mitigation:** Constraint 8 derives `scopeId` inside the circuit from `(rsIdentifier, scopeLabel)`. The adversary cannot force `scopeId` collision without either (a) forging `rsIdentifier_A` (violating on-chain registration integrity) or (b) finding a Poseidon2 collision where `Poseidon2(rsIdentifier_B, scopeLabel') = Poseidon2(rsIdentifier_A, scopeLabel_A)` for some `scopeLabel'` (violating P-CR). Both are hard assumptions already in the construction.

**Residual risk — compromised RS key:** If the adversary compromises RS-A's registration key and re-registers a malicious endpoint under the same `rsIdentifier`, the adversary can observe presentations at that scopeId. This is not a scopeId collision attack; it is RS compromise, which is outside the threat model (the adversary already controls up to N-1 RSes). The non-colluding RS's `rsIdentifier` remains unforged.

### Game 1: IND-UNL-AS (cross-agent indistinguishability)

**Setup:** Challenger enrolls two agents A₀, A₁ with identical `permissionBitmask` and `expiryTimestamp` in the agent Merkle tree. Both are issued valid credentials by the adversarial AS. Challenger registers N RSes with distinct `rsIdentifier` values.

**Phase 1:** Adversary A may request `ScopedPresentation` proofs from A₀ and A₁ for any (rsIdentifier, scopeLabel) pair of A's choosing. A receives the proofs and all public outputs. A may also specify arbitrary `scopeLabel` values for adversary-controlled RSes.

**Challenge:** A chooses a target (rsIdentifier*, scopeLabel*) not previously queried for either agent, where rsIdentifier* belongs to an honest (non-adversary-controlled) RS. Challenger flips bit b ∈ {0,1}, generates a `ScopedPresentation` proof from agent A_b for the derived `scopeId* = Poseidon2(rsIdentifier*, scopeLabel*)` with a fresh `presentationNonce`, and returns the proof and public outputs to A.

**Phase 2:** A may request additional proofs for any (rsIdentifier, scopeLabel) pair except (rsIdentifier*, scopeLabel*) for A₀ or A₁.

**Guess:** A outputs b' ∈ {0,1}. A wins if b' = b.

**Advantage:** Adv_IND-UNL-AS(A) = |Pr[b' = b] - 1/2|

**Claim:** For all PPT A, Adv_IND-UNL-AS(A) ≤ negl(λ), assuming Poseidon is a PRF, Poseidon is collision-resistant, and Groth16/PLONK satisfies zero-knowledge.

**Note on scopeId collision in this game:** The adversary may have queried A₀ or A₁ at adversary-controlled RSes using `scopeLabel*`. Because those queries used a different `rsIdentifier` (the adversary's, not rsIdentifier*), they produced a different `scopeId` and therefore a different `scopeNullifier`. No information about the agent's behavior at `scopeId*` leaks from those queries.

### Game 2: SES-UNL (cross-scope session unlinkability)

**Setup:** Challenger enrolls three agents A₀, A₁, A₂ with identical `permissionBitmask` and `expiryTimestamp` in the agent Merkle tree. All three are issued valid credentials by the adversarial AS. The three agents generate independent `scopeBlinder` values per (rsIdentifier, scopeLabel). Challenger registers N RSes with distinct `rsIdentifier` values.

**Phase 1 (adaptive queries):** A may request `ScopedPresentation` proofs from any of A₀, A₁, A₂ for any (rsIdentifier, scopeLabel). A receives all proofs and public outputs. This allows A to build traffic models, learn nullifier patterns within scopes, and attempt cross-scope correlation strategies. A may choose arbitrary `scopeLabel` values for adversary-controlled RSes.

**Challenge:** A chooses two distinct target pairs (rsIdentifier_α, scopeLabel_α) and (rsIdentifier_β, scopeLabel_β) such that the derived scopeIds are distinct, and neither pair was queried for agents A₀ or A₁ during Phase 1. At least one of rsIdentifier_α, rsIdentifier_β MUST belong to an honest RS. Challenger flips bit b ∈ {0,1}:
- If b = 0: generate proof π_α from A₀ at (rsIdentifier_α, scopeLabel_α), and proof π_β from A₀ at (rsIdentifier_β, scopeLabel_β) (same agent).
- If b = 1: generate proof π_α from A₀ at (rsIdentifier_α, scopeLabel_α), and proof π_β from A₁ at (rsIdentifier_β, scopeLabel_β) (different agents).

Both proofs use fresh `presentationNonce` values. A receives (π_α, public_outputs_α) and (π_β, public_outputs_β).

**Phase 2:** A may request additional proofs from any agent for any (rsIdentifier, scopeLabel), except: A may not query A₀ or A₁ at the challenge pairs. (A₂ may be queried at any scope, including the challenge scopes, to model the "N-1 colluding RSes" threat.)

**Guess:** A outputs b' ∈ {0,1}. A wins if b' = b.

**Advantage:** Adv_SES-UNL(A) = |Pr[b' = b] - 1/2|

**Claim:** For all PPT A, Adv_SES-UNL(A) ≤ negl(λ), under P-PRF, P-CR, and G16-ZK/PLONK-ZK.

**Why three agents:** A₂ serves as a "control" agent the adversary can query freely at challenge scopes, modeling a colluding RS that sees legitimate traffic from other agents. This prevents a trivially weak game where the adversary has no reference traffic at the challenge scopes.

**Why two fresh scopes:** If A had previously queried A₀ at (rsIdentifier_α, scopeLabel_α), it would know A₀'s `scopeNullifier` at that scope (it is deterministic), and could trivially link. The freshness restriction mirrors the real-world constraint that unlinkability holds for scopes where the adversary has not already observed the specific agent.

**Relationship to IND-UNL-AS:** IND-UNL-AS is a single-scope, two-agent game (vertical indistinguishability). SES-UNL is a two-scope, same-or-different-agent game (horizontal unlinkability). Together they close the claim: an adversary can neither identify which agent produced a proof at a given scope, nor correlate two proofs across scopes to a common agent.

### Timing side-channel extension (applies to both games)

Both games extend to timing by requiring the challenger to sample proof-generation time from a fixed distribution (uniform over a configurable window, e.g., [0, 500ms] jitter). The agent implementation MUST add random delay before submitting any proof to an RS. This is an application-layer requirement, not a circuit constraint.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF (P-PRF):** Poseidon2 and Poseidon3 are pseudorandom functions when keyed on a secret input. Specifically, for a random key k, the function x → Poseidon2(x, k) is computationally indistinguishable from a random function.
2. **Groth16 zero-knowledge (G16-ZK):** The Groth16 proving system satisfies computational zero-knowledge: the proof reveals nothing about private inputs beyond what is implied by the public inputs/outputs.
3. **PLONK zero-knowledge (PLONK-ZK):** Same property for PLONK proofs when used for `AgentPolicy`/`Delegation`.
4. **Poseidon collision resistance (P-CR):** Finding x ≠ x' such that Poseidon(x) = Poseidon(x') requires superpolynomial time. This now explicitly covers `Poseidon2(rsIdentifier, scopeLabel)` — distinct `rsIdentifier` values cannot produce colliding `scopeId` outputs.
5. **Discrete logarithm on Baby Jubjub (DL-BJJ):** Given (Ax, Ay) = BabyPbk(s), recovering s is hard.

### Reduction 1: IND-UNL-AS security

**Theorem:** If A wins IND-UNL-AS with non-negligible advantage ε, then we can construct either (a) a distinguisher B against P-PRF with advantage ε/2, (b) a distinguisher C against G16-ZK/PLONK-ZK with advantage ε/2, or (c) a collision finder D against P-CR.

**Proof sketch:**

1. **Hybrid H₀:** Real game. A interacts with agents A₀, A₁. `scopeId*` is derived inside the circuit as `Poseidon2(rsIdentifier*, scopeLabel*)`.

2. **Hybrid H₁:** Replace `scopeNullifier` computation for the challenge scope with a truly random value r. By P-PRF (keyed on the agent's `innerHash = Poseidon2(credentialCommitment, scopeBlinder)`, which is unknown to A), A cannot distinguish H₀ from H₁ unless A breaks P-PRF. The `innerHash` is distinct per-agent (different `credentialCommitment`) and per-scope (different `scopeBlinder`), so A has never seen the PRF evaluated at `scopeId*` for agent A_b. **Critical: even if A queried both agents at adversary-controlled RSes with matching `scopeLabel*`, those queries used different `rsIdentifier` values, producing different `scopeId` values. The PRF was never evaluated at the challenge `scopeId* = Poseidon2(rsIdentifier*, scopeLabel*)` — unless A finds a P-CR collision mapping a different (rsIdentifier, scopeLabel) pair to the same scopeId, which is negligible.**

3. **Hybrid H₂:** Replace the challenge proof π* with a simulated proof (using the Groth16/PLONK simulator). By G16-ZK/PLONK-ZK, A cannot distinguish H₁ from H₂.

4. In H₂, A receives a random `scopeNullifier`, a random-looking `presentationBinding` (derived from the random nullifier), a random-looking `blindedScopeCommitment` (blinded by the unknown `scopeBlinder`), a valid `agentMerkleRoot` (same for both agents since both are enrolled), and a simulated proof. None of these values depend on b. Therefore Adv(A) in H₂ = 0.

5. By the triangle inequality: ε ≤ Adv_P-PRF(B) + Adv_ZK(C) + Adv_P-CR(D).

### Reduction 2: SES-UNL security

**Theorem:** If A wins SES-UNL with non-negligible advantage ε, then we can construct either (a) a distinguisher B against P-PRF with advantage ε/4, (b) a distinguisher C against G16-ZK/PLONK-ZK with advantage ε/4, or (c) a collision finder D against P-CR.

**Proof sketch:**

1. **Hybrid H₀:** Real SES-UNL game. When b = 0, both challenge proofs use A₀'s credential; when b = 1, π_α uses A₀ and π_β uses A₁. Both `scopeId` values are circuit-derived from their respective (rsIdentifier, scopeLabel) pairs.

2. **Hybrid H₁:** Replace the `scopeNullifier` in π_α with a truly random value r_α. The PRF key for π_α is `innerHash_α = Poseidon2(credCommitment_A₀, scopeBlinder_{A₀, rsId_α, label_α})`. Since the challenge pair (rsIdentifier_α, scopeLabel_α) was not queried for A₀ in Phase 1, A has never seen this PRF output. Even if A queried A₀ at a different RS with the same scopeLabel_α, the circuit-derived `scopeId` differs (different rsIdentifier → different Poseidon2 output under P-CR), so the PRF was evaluated at a different point. By P-PRF: |Adv(H₀) - Adv(H₁)| ≤ Adv_P-PRF + Adv_P-CR.

3. **Hybrid H₂:** Replace the `scopeNullifier` in π_β with a truly random value r_β. When b = 0, the PRF key is `Poseidon2(credCommitment_A₀, scopeBlinder_{A₀, rsId_β, label_β})`; when b = 1, it is `Poseidon2(credCommitment_A₁, scopeBlinder_{A₁, rsId_β, label_β})`. In either case, A has never queried the PRF at `scopeId_β = Poseidon2(rsIdentifier_β, scopeLabel_β)` for the relevant agent. By P-PRF: |Adv(H₁) - Adv(H₂)| ≤ Adv_P-PRF + Adv_P-CR.

4. **Hybrid H₃:** Replace both challenge proofs with simulated proofs (Groth16/PLONK simulator). By G16-ZK/PLONK-ZK: |Adv(H₂) - Adv(H₃)| ≤ 2 · Adv_ZK.

5. **In H₃, A's view is independent of b.** Both `scopeNullifier` values are uniform random. The `presentationBinding` values are derived from independent random nullifiers with independent nonces — also random-looking. The `blindedScopeCommitment` values depend on `scopeBlinder` values that A never observes; in b = 0 they use `scopeBlinder_{A₀, rsId_α, label_α}` and `scopeBlinder_{A₀, rsId_β, label_β}` (two independent random values), while in b = 1 they use `scopeBlinder_{A₀, rsId_α, label_α}` and `scopeBlinder_{A₁, rsId_β, label_β}` (also two independent random values). Since `scopeBlinder` is drawn fresh per (agent, rsIdentifier, scopeLabel) triple, the `blindedScopeCommitment` distribution is identical in both worlds. The `agentMerkleRoot` is the same (all agents share one tree). The proofs are simulated. No public output distinguishes b = 0 from b = 1. Therefore Adv(A) in H₃ = 0.

6. By the triangle inequality: ε ≤ 2 · (Adv_P-PRF + Adv_P-CR) + 2 · Adv_ZK.

**Critical step explained (H₃, blindedScopeCommitment independence):** The potential linking surface is `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)`. In b = 0, the two challenge proofs share `credentialCommitment` (both from A₀), but use independent `scopeBlinder` values (one per (rsIdentifier, scopeLabel) triple). In b = 1, they have different `credentialCommitment` values AND different `scopeBlinder` values. Since Poseidon3 is a PRF keyed on `scopeBlinder` (which is fresh random and secret in both cases), both worlds produce computationally uniform outputs. The shared `credentialCommitment` in b = 0 is absorbed into the PRF input — it does not leak through the output. This is precisely why a per-scope blinder (rather than a single agent-wide blinder) is necessary: a shared blinder across scopes would make `blindedScopeCommitment` values deterministically related via the shared `credentialCommitment`, breaking SES-UNL.

**Cross-scope unlinkability follows from both games jointly:** IND-UNL-AS proves that a single presentation cannot be attributed to a specific agent. SES-UNL proves that two presentations at distinct scopes cannot be correlated to a common agent. Together, they establish that the adversary's view of any subset of an agent's cross-scope authorizations is computationally independent of the agent's identity — which is exactly the claim in §1.

### AS impotence (strengthened with scopeId binding)

The AS knows the `credentialCommitment` (it was enrolled on-chain). But it does not know any agent's `scopeBlinder`. Without the blinder, the AS cannot compute `innerHash`, and therefore cannot predict the `scopeNullifier` for any scope. The AS sees only the on-chain Merkle root and public enrollment events — it never sees presentation proofs (those go directly to the RS). **Additionally, even if the AS operates a malicious RS and attempts to replicate an honest RS's scopeLabel, the circuit-derived `scopeId` will differ (because `rsIdentifier` differs), so the AS's malicious RS cannot elicit the same `scopeNullifier` that the agent produces at the honest RS. This is the circuit-level defense against the scopeId collision attack.**

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` | §4.2 AgentPolicy circuit |
| Scope ID binding | `Poseidon2(rsIdentifier, scopeLabel)` — circuit-enforced, prevents RS collision | New — extends §2 scope pattern |
| Scope nullifier | `Poseidon2(scopeId, Poseidon2(credentialCommitment, scopeBlinder))` where `scopeId` is circuit-derived | New — extends §2 nullifier pattern |
| Presentation binding | `Poseidon2(scopeNullifier, presentationNonce)` | Mirrors §3.2 nonceBinding pattern |
| Blinded scope commitment | `Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)` | Extends §2 scopeCommitment |
| Operator signature | EdDSA on Baby Jubjub over `credentialCommitment` | §4.2 constraint 3 |
| Merkle membership | Lean Incremental Merkle Tree, depth 20, Poseidon2 node hash | §2.2 |
| Cumulative bit encoding | Bits 2/3/4 implication chain | §4.2 constraint 6 |
| Root history buffer | 30-entry circular buffer per tree | §2.1 |
| Proving system | PLONK for `ScopedPresentation` (no per-circuit ceremony); Groth16 for `HumanUniqueness` | §2.3 |

The `scopeBlinder` is the only new cryptographic element beyond the base protocol. The `rsIdentifier` is an organizational element (on-chain registry key) used as a public input; it introduces no new cryptographic primitive — it is a field element consumed by the existing Poseidon2 hash.

## 6. Circuit cost estimate

### `ScopedPresentation` constraint breakdown

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(64) × 3 (permissionBitmask, expiryTimestamp, currentTimestamp) | 192 |
| Poseidon5 (credential commitment) | ~550 |
| EdDSAPoseidonVerifier | ~5,200 |
| BinaryMerkleRoot(20) with Poseidon2 × 20 levels | ~5,600 |
| Scope satisfaction (64 bit-checks) | 128 |
| Cumulative bit encoding (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon2 (scopeId = Poseidon2(rsIdentifier, scopeLabel)) | ~280 |
| Poseidon2 (innerHash) | ~280 |
| Poseidon2 (scopeNullifier) | ~280 |
| Poseidon2 (presentationBinding) | ~280 |
| Poseidon3 (blindedScopeCommitment) | ~400 |
| **Total** | **~13,323** |

This fits within 2^14 = 16,384 constraints, compatible with `pot16.ptau`. The scopeId binding adds exactly one Poseidon2 call (~280 constraints) over the prior construction.

### `ScopedDelegation` constraint breakdown

Same as existing `Delegation` circuit (~14,500 constraints) plus:
- 2 additional Poseidon3 calls for blinded scope commitments: +800
- 1 additional Poseidon2 for scopeId binding: +280
- 2 additional private inputs (scope blinders): negligible

**Total:** ~15,580 constraints. Still within 2^14.

### Proving time targets

| Circuit | System | Target | Rationale |
|---------|--------|--------|-----------|
| `ScopedPresentation` | PLONK | <3s | Agent-facing, latency-sensitive; PLONK avoids ceremony |
| `ScopedPresentation` | Groth16 | <1.5s | Optional: faster proving, requires Phase 2 ceremony |
| `ScopedDelegation` | PLONK | <4s | Delegation is less latency-critical |
| `HumanUniqueness` | Groth16 | <15s | Unchanged from base protocol |

With rapidsnark on commodity hardware (M1/M2 Mac, 4-core x86 server), 13K-constraint Groth16 proves in ~0.8s and PLONK in ~2.5s based on existing Bolyra benchmarks (`circuits/scripts/bench_rapidsnark.js`). The additional ~280 constraints for scopeId binding have negligible impact on proving time.

## 7. Concrete deployment scenario

### Credit union cross-merchant unlinkability

**Stakeholder:** A federally chartered credit union (e.g., Navy Federal, 13M members) deploying Bolyra for member AI agents that interact with merchant RSes.

**Setup:**
- The CU operates as the credential issuer (enrolling member agents in the agent Merkle tree) and historically would serve as the OAuth AS.
- Member Alice delegates her agent to interact with: RS-A (Amazon merchant API), RS-B (pharmacy benefits), RS-C (auto insurance quote).
- Each RS registers an `rsIdentifier` on-chain: `rsId_Amazon = Poseidon2(hash("amazon.com"), amazonPubkeyHash)`, `rsId_Pharmacy = Poseidon2(hash("express-scripts.com"), pharmacyPubkeyHash)`, etc.
- The CU has a regulatory obligation under NCUA §701.36 to not surveil member transaction patterns beyond what is necessary for BSA/AML compliance.

**Flow:**
1. CU issues Alice's agent a credential: `permissionBitmask = 0b00000111` (READ_DATA + WRITE_DATA + FINANCIAL_SMALL). Credential is enrolled on-chain.
2. Alice's agent generates three `scopeBlinder` values: one each for (rsId_Amazon, "merchant-read"), (rsId_Pharmacy, "rx-benefits"), (rsId_Insurance, "quote-request"). Stored in agent's local secure enclave.
3. When Alice's agent contacts Amazon's RS:
   - Amazon provides `presentationNonce`, `rsIdentifier = rsId_Amazon`, and `scopeLabel = Poseidon("merchant-read")`.
   - The circuit computes `scopeId = Poseidon2(rsId_Amazon, scopeLabel)` internally — the agent cannot override this.
   - Agent generates `ScopedPresentation` proof (PLONK, ~2.5s).
   - Amazon verifies proof against on-chain `agentMerkleRoot`, checks `scopeNullifier` against its local double-spend set, verifies `presentationBinding` for replay prevention.
4. When the same agent contacts the pharmacy RS, a completely independent proof is generated with a different `scopeId` (different `rsIdentifier`), different `scopeNullifier`, and different `blindedScopeCommitment`.
5. **scopeId collision defense in action:** Suppose a malicious RS-D (controlled by the CU) registers `rsId_D` and sets `scopeLabel_D = Poseidon("merchant-read")` (copying Amazon's label). The circuit computes `scopeId_D = Poseidon2(rsId_D, scopeLabel_D) ≠ Poseidon2(rsId_Amazon, scopeLabel_D) = scopeId_Amazon` (since `rsId_D ≠ rsId_Amazon` and Poseidon2 is collision-resistant). The agent produces a different `scopeNullifier` at RS-D than at Amazon. The CU learns nothing about Alice's Amazon activity.
6. The CU (acting as former-AS) sees only: (a) it enrolled a credential at time T₀, and (b) the on-chain Merkle root. It does NOT see any presentation proofs — those flow directly agent→RS. It cannot compute the `scopeNullifier` for any RS because it does not know Alice's `scopeBlinder` values. It cannot force scopeId collision because the circuit binds scopeId to rsIdentifier.

**What is proven:**
- Amazon knows: "a valid agent with FINANCIAL_SMALL permission, enrolled in this Merkle tree, authorized this request." It does not know who Alice is, which CU issued the credential, or that the same agent also shops at the pharmacy.
- The pharmacy knows: the same type of statement, with a completely different nullifier.
- The CU knows: it enrolled N agents. It does not know which RSes any agent contacted. Even operating a malicious RS, it cannot elicit nullifiers matching any honest RS.
- A CU + Amazon coalition knows: the CU enrolled N agents; Amazon received M authorizations. They cannot match any of Amazon's M authorizations to specific agents in the CU's enrollment set (under P-PRF + P-CR + ZK).

**SES-UNL in practice:** Even if Amazon and the pharmacy collude (sharing all received proofs), they observe two transcripts with independent `scopeNullifier` values (guaranteed distinct by the circuit-derived `scopeId`), independent `blindedScopeCommitment` values, and independent simulated-equivalent proofs. By the SES-UNL reduction, they cannot determine whether Alice's Amazon proof and the pharmacy proof came from the same agent — the joint distribution is identical to one where two different agents produced them.

### Healthcare referral network privacy

**Stakeholder:** Kaiser Permanente (issuer) delegates agent credentials for patient referrals.

**Flow:** Patient's agent is delegated from Kaiser (primary) to an external specialist (RS-B) and a lab (RS-C). Each RS has a distinct `rsIdentifier` registered on-chain. Using `ScopedDelegation`, each delegation hop produces a `blindedScopeCommitment` that is unlinkable across providers. Kaiser cannot learn that the specialist referred the patient to the lab — the `scopeNullifier` at the lab is cryptographically independent of the one at the specialist (different `rsIdentifier` → different `scopeId` → different nullifier), and Kaiser never sees either. Even if Kaiser operates a shadow RS to try to elicit matching nullifiers, the circuit-derived `scopeId` ensures its shadow RS produces a distinct scope domain. Even if the specialist and lab collude, SES-UNL guarantees they cannot confirm the two presentations share a common delegated agent.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails against both the IND-UNL-AS and SES-UNL games on structural axes that no configuration or layering can fix:

**1. AS is in the issuance path — always.** Every OAuth token passes through the AS at issuance. The AS logs `(agent_id, RS, scope, timestamp)` for every token request. Bolyra's `ScopedPresentation` eliminates the AS from the presentation path entirely: the agent proves directly to the RS using the on-chain Merkle root. The AS sees only enrollment, never presentation.

**2. PPID protects the wrong party.** PPID hides the subject from RSes, not from the AS. The AS holds the PPID mapping table and can trivially reverse any PPID. Bolyra's `scopeNullifier` is derived from a per-scope blinder that the AS never learns — the AS cannot compute the nullifier for any scope.

**3. BBS+ does not provide issuer anonymity.** Every BBS+ derived proof exposes the issuer's public key. An AS that is also the issuer can identify its own credentials at any RS. In Bolyra, the operator's public key is a private input — the RS learns only that "some enrolled credential signed by some authorized operator satisfies the policy."

**4. Scope correlation at the AS is free in OAuth.** The AS observes every `scope` parameter in every token request. An adversarial AS can build a complete per-agent scope-access timeline. In Bolyra, the `scopeId` is computed inside the circuit from `(rsIdentifier, scopeLabel)` — the AS never sees either value (the proof goes directly to the RS).

**5. Colluding RSes can link sessions in the baseline.** BBS+ multi-show unlinkability prevents a single RS from linking two presentations of the same credential. However, two colluding RSes can compare the issuer public key, credential schema, and issuance timing to probabilistically link sessions. In Bolyra, the SES-UNL game formally proves that colluding RSes (even with AS assistance) cannot link cross-scope sessions: the `scopeNullifier`, `blindedScopeCommitment`, and proof are all computationally independent across scopes under P-PRF and G16-ZK/PLONK-ZK. No baseline component provides a formal session-unlinkability guarantee — BBS+ unlinkability holds only within a single verifier's view, not across colluding verifiers who share metadata.

**6. Delegation leaks chain topology in RFC 8693.** Every delegation hop requires an AS roundtrip, revealing the full chain. Bolyra's `ScopedDelegation` links hops via `blindedScopeCommitment` values that are unlinkable across scopes, with no AS involvement.

**7. No formal security definition exists in the baseline.** The baseline has no IND-UNL-AS game, no SES-UNL game, no reduction to named assumptions, and no proof of security against either cross-agent identification or cross-scope session linking by an adversarial AS. Bolyra's construction reduces both properties to the Poseidon PRF assumption, Poseidon collision resistance, and Groth16/PLONK zero-knowledge — all well-studied in the ZK literature. The security argument is falsifiable: break P-PRF, P-CR, or G16-ZK, and the construction falls; absent such a break, the advantage is negligible.

**8. No defense against scope-identifier collision attacks.** The baseline has no mechanism to prevent two RSes from requesting tokens with identical scope strings. In OAuth, if RS-B requests a token with `scope=merchant-read` (the same scope string used by RS-A), the AS happily issues it, and any correlation based on scope values succeeds. RFC 8707 binds the `aud` to an RS, but the `scope` parameter is a free-form string with no namespace enforcement. Bolyra's circuit-level `scopeId = Poseidon2(rsIdentifier, scopeLabel)` makes scope collision between distinct RSes computationally infeasible under P-CR — the RS's on-chain identity is cryptographically fused into the scope domain.
