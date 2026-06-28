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
| `scopeId` | F_p | RS-specific scope identifier (e.g., Poseidon("CU-A-merchant-read")) |
| `requiredScopeMask` | 64-bit | Minimum permission bits the RS demands |
| `currentTimestamp` | 64-bit | Verifier-supplied current time |
| `presentationNonce` | F_p | Fresh per-request nonce from RS |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root (checked against on-chain root history) |
| `scopeNullifier` | F_p | Poseidon2(scopeId, Poseidon2(credentialCommitment, scopeBlinder)) — deterministic per (agent, scope) |
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
8. **Scope nullifier derivation:** `innerHash = Poseidon2(credentialCommitment, scopeBlinder)`, then `scopeNullifier = Poseidon2(scopeId, innerHash)`.
9. **Presentation binding:** `presentationBinding = Poseidon2(scopeNullifier, presentationNonce)`.
10. **Blinded scope commitment:** `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)`.

### Key design decisions

**Scope blinder:** The agent generates one random `scopeBlinder` per (credential, scopeId) pair and stores it locally. This ensures:
- Same agent + same scope → same `scopeNullifier` (Sybil detection within a scope)
- Same agent + different scope → different `scopeNullifier` (unlinkability across scopes)
- The blinder is never revealed; it is a private input to the circuit

**No AS in the loop:** The RS verifies the PLONK/Groth16 proof directly against the on-chain `agentMerkleRoot`. The AS is not contacted at verification time. The credential was enrolled on-chain at issuance; subsequent presentations bypass the AS entirely.

**Delegation extension:** For delegated agents, replace `credentialCommitment` with the output of a preceding `Delegation` circuit proof. The `scopeNullifier` derivation remains identical, using the delegatee's credential commitment. Chain linking uses `blindedScopeCommitment` instead of the standard `scopeCommitment`, preserving unlinkability through delegation hops.

### Modified circuit: `ScopedDelegation`

Identical to the existing `Delegation` circuit except:
- The `newScopeCommitment` output is replaced with `blindedScopeCommitment = Poseidon3(delegateeScope, delegateeCredCommitment, delegateeScopeBlinder)`.
- Chain linking uses `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorScopeBlinder) === previousBlindedScopeCommitment`.
- Adds `delegatorScopeBlinder` and `delegateeScopeBlinder` as private inputs.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:
- The Authorization Server (full state: issuance logs, credential database, timing of all requests)
- Up to N-1 of N Resource Servers (colluding RSes share all received proofs and metadata)
- Network-level observation of proof submission timing to the non-colluding RS

The adversary does NOT control:
- The agent's local state (secret key, scope blinders)
- The on-chain smart contract logic (public, deterministic)
- The Groth16/PLONK proving system internals

### Game 1: IND-UNL-AS (cross-agent indistinguishability)

**Setup:** Challenger enrolls two agents A₀, A₁ with identical `permissionBitmask` and `expiryTimestamp` in the agent Merkle tree. Both are issued valid credentials by the adversarial AS.

**Phase 1:** Adversary A may request `ScopedPresentation` proofs from A₀ and A₁ for any scope of A's choosing. A receives the proofs and all public outputs.

**Challenge:** A chooses a target scope `scopeId*` not previously queried. Challenger flips bit b ∈ {0,1}, generates a `ScopedPresentation` proof from agent A_b for `scopeId*` with a fresh `presentationNonce`, and returns the proof and public outputs to A.

**Phase 2:** A may request additional proofs for any scope except `scopeId*`.

**Guess:** A outputs b' ∈ {0,1}. A wins if b' = b.

**Advantage:** Adv_IND-UNL-AS(A) = |Pr[b' = b] - 1/2|

**Claim:** For all PPT A, Adv_IND-UNL-AS(A) ≤ negl(λ), assuming Poseidon is a PRF and Groth16/PLONK satisfies zero-knowledge.

### Game 2: SES-UNL (cross-scope session unlinkability)

This game captures the distinct threat where an adversary observes two transcripts at two different scopes and attempts to determine whether they originated from the same agent. IND-UNL-AS covers "which agent produced this proof?"; SES-UNL covers "did the same agent produce both proofs?"

**Setup:** Challenger enrolls three agents A₀, A₁, A₂ with identical `permissionBitmask` and `expiryTimestamp` in the agent Merkle tree. All three are issued valid credentials by the adversarial AS. The three agents generate independent `scopeBlinder` values per scope.

**Phase 1 (adaptive queries):** A may request `ScopedPresentation` proofs from any of A₀, A₁, A₂ for any scope. A receives all proofs and public outputs. This allows A to build traffic models, learn nullifier patterns within scopes, and attempt cross-scope correlation strategies.

**Challenge:** A chooses two distinct target scopes `scopeId_α` and `scopeId_β`, neither of which was queried for agents A₀ or A₁ during Phase 1. Challenger flips bit b ∈ {0,1}:
- If b = 0: generate proof π_α from A₀ at `scopeId_α`, and proof π_β from A₀ at `scopeId_β` (same agent).
- If b = 1: generate proof π_α from A₀ at `scopeId_α`, and proof π_β from A₁ at `scopeId_β` (different agents).

Both proofs use fresh `presentationNonce` values. A receives (π_α, public_outputs_α) and (π_β, public_outputs_β).

**Phase 2:** A may request additional proofs from any agent for any scope, except: A may not query A₀ or A₁ at `scopeId_α` or `scopeId_β`. (A₂ may be queried at any scope, including the challenge scopes, to model the "N-1 colluding RSes" threat.)

**Guess:** A outputs b' ∈ {0,1}. A wins if b' = b.

**Advantage:** Adv_SES-UNL(A) = |Pr[b' = b] - 1/2|

**Claim:** For all PPT A, Adv_SES-UNL(A) ≤ negl(λ), under P-PRF and G16-ZK/PLONK-ZK.

**Why three agents:** A₂ serves as a "control" agent the adversary can query freely at challenge scopes, modeling a colluding RS that sees legitimate traffic from other agents. This prevents a trivially weak game where the adversary has no reference traffic at the challenge scopes.

**Why two fresh scopes:** If A had previously queried A₀ at `scopeId_α`, it would know A₀'s `scopeNullifier` at that scope (it is deterministic), and could trivially link. The freshness restriction mirrors the real-world constraint that unlinkability holds for scopes where the adversary has not already observed the specific agent.

**Relationship to IND-UNL-AS:** IND-UNL-AS is a single-scope, two-agent game (vertical indistinguishability). SES-UNL is a two-scope, same-or-different-agent game (horizontal unlinkability). Together they close the claim: an adversary can neither identify which agent produced a proof at a given scope, nor correlate two proofs across scopes to a common agent.

### Timing side-channel extension (applies to both games)

Both games extend to timing by requiring the challenger to sample proof-generation time from a fixed distribution (uniform over a configurable window, e.g., [0, 500ms] jitter). The agent implementation MUST add random delay before submitting any proof to an RS. This is an application-layer requirement, not a circuit constraint.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF (P-PRF):** Poseidon2 and Poseidon3 are pseudorandom functions when keyed on a secret input. Specifically, for a random key k, the function x → Poseidon2(x, k) is computationally indistinguishable from a random function.
2. **Groth16 zero-knowledge (G16-ZK):** The Groth16 proving system satisfies computational zero-knowledge: the proof reveals nothing about private inputs beyond what is implied by the public inputs/outputs.
3. **PLONK zero-knowledge (PLONK-ZK):** Same property for PLONK proofs when used for `AgentPolicy`/`Delegation`.
4. **Poseidon collision resistance (P-CR):** Finding x ≠ x' such that Poseidon(x) = Poseidon(x') requires superpolynomial time.
5. **Discrete logarithm on Baby Jubjub (DL-BJJ):** Given (Ax, Ay) = BabyPbk(s), recovering s is hard.

### Reduction 1: IND-UNL-AS security

**Theorem:** If A wins IND-UNL-AS with non-negligible advantage ε, then we can construct either (a) a distinguisher B against P-PRF with advantage ε/2, or (b) a distinguisher C against G16-ZK/PLONK-ZK with advantage ε/2.

**Proof sketch:**

1. **Hybrid H₀:** Real game. A interacts with agents A₀, A₁.

2. **Hybrid H₁:** Replace `scopeNullifier` computation for the challenge scope with a truly random value r. By P-PRF (keyed on the agent's `innerHash = Poseidon2(credentialCommitment, scopeBlinder)`, which is unknown to A), A cannot distinguish H₀ from H₁ unless A breaks P-PRF. The `innerHash` is distinct per-agent (different `credentialCommitment`) and per-scope (different `scopeBlinder`), so A has never seen the PRF evaluated at `scopeId*` for agent A_b.

3. **Hybrid H₂:** Replace the challenge proof π* with a simulated proof (using the Groth16/PLONK simulator). By G16-ZK/PLONK-ZK, A cannot distinguish H₁ from H₂.

4. In H₂, A receives a random `scopeNullifier`, a random-looking `presentationBinding` (derived from the random nullifier), a random-looking `blindedScopeCommitment` (blinded by the unknown `scopeBlinder`), a valid `agentMerkleRoot` (same for both agents since both are enrolled), and a simulated proof. None of these values depend on b. Therefore Adv(A) in H₂ = 0.

5. By the triangle inequality: ε ≤ Adv_P-PRF(B) + Adv_ZK(C).

### Reduction 2: SES-UNL security

**Theorem:** If A wins SES-UNL with non-negligible advantage ε, then we can construct either (a) a distinguisher B against P-PRF with advantage ε/4, or (b) a distinguisher C against G16-ZK/PLONK-ZK with advantage ε/4.

**Proof sketch:**

1. **Hybrid H₀:** Real SES-UNL game. When b = 0, both challenge proofs use A₀'s credential; when b = 1, π_α uses A₀ and π_β uses A₁.

2. **Hybrid H₁:** Replace the `scopeNullifier` in π_α with a truly random value r_α. The PRF key for π_α is `innerHash_α = Poseidon2(credCommitment_A₀, scopeBlinder_{A₀, scopeId_α})`. Since `scopeId_α` was not queried for A₀ in Phase 1, A has never seen this PRF output. By P-PRF: |Adv(H₀) - Adv(H₁)| ≤ Adv_P-PRF.

3. **Hybrid H₂:** Replace the `scopeNullifier` in π_β with a truly random value r_β. When b = 0, the PRF key is `Poseidon2(credCommitment_A₀, scopeBlinder_{A₀, scopeId_β})`; when b = 1, it is `Poseidon2(credCommitment_A₁, scopeBlinder_{A₁, scopeId_β})`. In either case, A has never queried the PRF at `scopeId_β` for the relevant agent. By P-PRF: |Adv(H₁) - Adv(H₂)| ≤ Adv_P-PRF.

4. **Hybrid H₃:** Replace both challenge proofs with simulated proofs (Groth16/PLONK simulator). By G16-ZK/PLONK-ZK: |Adv(H₂) - Adv(H₃)| ≤ 2 · Adv_ZK.

5. **In H₃, A's view is independent of b.** Both `scopeNullifier` values are uniform random. The `presentationBinding` values are derived from independent random nullifiers with independent nonces — also random-looking. The `blindedScopeCommitment` values depend on `scopeBlinder` values that A never observes; in b = 0 they use `scopeBlinder_{A₀, α}` and `scopeBlinder_{A₀, β}` (two independent random values), while in b = 1 they use `scopeBlinder_{A₀, α}` and `scopeBlinder_{A₁, β}` (also two independent random values). Since `scopeBlinder` is drawn fresh per (agent, scope) pair, the `blindedScopeCommitment` distribution is identical in both worlds. The `agentMerkleRoot` is the same (all agents share one tree). The proofs are simulated. No public output distinguishes b = 0 from b = 1. Therefore Adv(A) in H₃ = 0.

6. By the triangle inequality: ε ≤ 2 · Adv_P-PRF + 2 · Adv_ZK.

**Critical step explained (H₃, blindedScopeCommitment independence):** The potential linking surface is `blindedScopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)`. In b = 0, the two challenge proofs share `credentialCommitment` (both from A₀), but use independent `scopeBlinder` values (one per scope). In b = 1, they have different `credentialCommitment` values AND different `scopeBlinder` values. Since Poseidon3 is a PRF keyed on `scopeBlinder` (which is fresh random and secret in both cases), both worlds produce computationally uniform outputs. The shared `credentialCommitment` in b = 0 is absorbed into the PRF input — it does not leak through the output. This is precisely why a per-scope blinder (rather than a single agent-wide blinder) is necessary: a shared blinder across scopes would make `blindedScopeCommitment` values deterministically related via the shared `credentialCommitment`, breaking SES-UNL.

**Cross-scope unlinkability follows from both games jointly:** IND-UNL-AS proves that a single presentation cannot be attributed to a specific agent. SES-UNL proves that two presentations at distinct scopes cannot be correlated to a common agent. Together, they establish that the adversary's view of any subset of an agent's cross-scope authorizations is computationally independent of the agent's identity — which is exactly the claim in §1.

### AS impotence (unchanged, applies to both games)

The AS knows the `credentialCommitment` (it was enrolled on-chain). But it does not know any agent's `scopeBlinder`. Without the blinder, the AS cannot compute `innerHash`, and therefore cannot predict the `scopeNullifier` for any scope. The AS sees only the on-chain Merkle root and public enrollment events — it never sees presentation proofs (those go directly to the RS).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Credential commitment | `Poseidon5(modelHash, Ax, Ay, permissionBitmask, expiryTimestamp)` | §4.2 AgentPolicy circuit |
| Scope nullifier | `Poseidon2(scopeId, Poseidon2(credentialCommitment, scopeBlinder))` | New — extends §2 nullifier pattern |
| Presentation binding | `Poseidon2(scopeNullifier, presentationNonce)` | Mirrors §3.2 nonceBinding pattern |
| Blinded scope commitment | `Poseidon3(permissionBitmask, credentialCommitment, scopeBlinder)` | Extends §2 scopeCommitment |
| Operator signature | EdDSA on Baby Jubjub over `credentialCommitment` | §4.2 constraint 3 |
| Merkle membership | Lean Incremental Merkle Tree, depth 20, Poseidon2 node hash | §2.2 |
| Cumulative bit encoding | Bits 2/3/4 implication chain | §4.2 constraint 6 |
| Root history buffer | 30-entry circular buffer per tree | §2.1 |
| Proving system | PLONK for `ScopedPresentation` (no per-circuit ceremony); Groth16 for `HumanUniqueness` | §2.3 |

The `scopeBlinder` is the only new cryptographic element. It is a random field element generated locally by the agent per (credential, scope) pair. It maps naturally to the existing scope-commitment pattern — it is the randomized analogue of the deterministic `scopeCommitment` in the base protocol.

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
| Poseidon2 (innerHash) | ~280 |
| Poseidon2 (scopeNullifier) | ~280 |
| Poseidon2 (presentationBinding) | ~280 |
| Poseidon3 (blindedScopeCommitment) | ~400 |
| **Total** | **~13,043** |

This fits within 2^14 = 16,384 constraints, compatible with `pot16.ptau`.

### `ScopedDelegation` constraint breakdown

Same as existing `Delegation` circuit (~14,500 constraints) plus:
- 2 additional Poseidon3 calls for blinded scope commitments: +800
- 2 additional private inputs (scope blinders): negligible

**Total:** ~15,300 constraints. Still within 2^14.

### Proving time targets

| Circuit | System | Target | Rationale |
|---------|--------|--------|-----------|
| `ScopedPresentation` | PLONK | <3s | Agent-facing, latency-sensitive; PLONK avoids ceremony |
| `ScopedPresentation` | Groth16 | <1.5s | Optional: faster proving, requires Phase 2 ceremony |
| `ScopedDelegation` | PLONK | <4s | Delegation is less latency-critical |
| `HumanUniqueness` | Groth16 | <15s | Unchanged from base protocol |

With rapidsnark on commodity hardware (M1/M2 Mac, 4-core x86 server), 13K-constraint Groth16 proves in ~0.8s and PLONK in ~2.5s based on existing Bolyra benchmarks (`circuits/scripts/bench_rapidsnark.js`).

## 7. Concrete deployment scenario

### Credit union cross-merchant unlinkability

**Stakeholder:** A federally chartered credit union (e.g., Navy Federal, 13M members) deploying Bolyra for member AI agents that interact with merchant RSes.

**Setup:**
- The CU operates as the credential issuer (enrolling member agents in the agent Merkle tree) and historically would serve as the OAuth AS.
- Member Alice delegates her agent to interact with: RS-A (Amazon merchant API), RS-B (pharmacy benefits), RS-C (auto insurance quote).
- The CU has a regulatory obligation under NCUA §701.36 to not surveil member transaction patterns beyond what is necessary for BSA/AML compliance.

**Flow:**
1. CU issues Alice's agent a credential: `permissionBitmask = 0b00000111` (READ_DATA + WRITE_DATA + FINANCIAL_SMALL). Credential is enrolled on-chain.
2. Alice's agent generates three `scopeBlinder` values: one each for scopeId_Amazon, scopeId_Pharmacy, scopeId_Insurance. Stored in agent's local secure enclave.
3. When Alice's agent contacts Amazon's RS:
   - Amazon provides `presentationNonce` and `scopeId = Poseidon("amazon-merchant-v1")`.
   - Agent generates `ScopedPresentation` proof (PLONK, ~2.5s).
   - Amazon verifies proof against on-chain `agentMerkleRoot`, checks `scopeNullifier` against its local double-spend set, verifies `presentationBinding` for replay prevention.
4. When the same agent contacts the pharmacy RS, a completely independent proof is generated with a different `scopeNullifier` and `blindedScopeCommitment`.
5. The CU (acting as former-AS) sees only: (a) it enrolled a credential at time T₀, and (b) the on-chain Merkle root. It does NOT see any presentation proofs — those flow directly agent→RS. It cannot compute the `scopeNullifier` for any RS because it does not know Alice's `scopeBlinder` values.

**What is proven:**
- Amazon knows: "a valid agent with FINANCIAL_SMALL permission, enrolled in this Merkle tree, authorized this request." It does not know who Alice is, which CU issued the credential, or that the same agent also shops at the pharmacy.
- The pharmacy knows: the same type of statement, with a completely different nullifier.
- The CU knows: it enrolled N agents. It does not know which RSes any agent contacted.
- A CU + Amazon coalition knows: the CU enrolled N agents; Amazon received M authorizations. They cannot match any of Amazon's M authorizations to specific agents in the CU's enrollment set (under P-PRF + ZK).

**SES-UNL in practice:** Even if Amazon and the pharmacy collude (sharing all received proofs), they observe two transcripts with independent `scopeNullifier` values, independent `blindedScopeCommitment` values, and independent simulated-equivalent proofs. By the SES-UNL reduction, they cannot determine whether Alice's Amazon proof and the pharmacy proof came from the same agent — the joint distribution is identical to one where two different agents produced them.

### Healthcare referral network privacy

**Stakeholder:** Kaiser Permanente (issuer) delegates agent credentials for patient referrals.

**Flow:** Patient's agent is delegated from Kaiser (primary) to an external specialist (RS-B) and a lab (RS-C). Using `ScopedDelegation`, each delegation hop produces a `blindedScopeCommitment` that is unlinkable across providers. Kaiser cannot learn that the specialist referred the patient to the lab — the `scopeNullifier` at the lab is cryptographically independent of the one at the specialist, and Kaiser never sees either. Even if the specialist and lab collude, SES-UNL guarantees they cannot confirm the two presentations share a common delegated agent.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails against both the IND-UNL-AS and SES-UNL games on structural axes that no configuration or layering can fix:

**1. AS is in the issuance path — always.** Every OAuth token passes through the AS at issuance. The AS logs `(agent_id, RS, scope, timestamp)` for every token request. Bolyra's `ScopedPresentation` eliminates the AS from the presentation path entirely: the agent proves directly to the RS using the on-chain Merkle root. The AS sees only enrollment, never presentation.

**2. PPID protects the wrong party.** PPID hides the subject from RSes, not from the AS. The AS holds the PPID mapping table and can trivially reverse any PPID. Bolyra's `scopeNullifier` is derived from a per-scope blinder that the AS never learns — the AS cannot compute the nullifier for any scope.

**3. BBS+ does not provide issuer anonymity.** Every BBS+ derived proof exposes the issuer's public key. An AS that is also the issuer can identify its own credentials at any RS. In Bolyra, the operator's public key is a private input — the RS learns only that "some enrolled credential signed by some authorized operator satisfies the policy."

**4. Scope correlation at the AS is free in OAuth.** The AS observes every `scope` parameter in every token request. An adversarial AS can build a complete per-agent scope-access timeline. In Bolyra, the `scopeId` is a public input to the circuit but the AS never sees it — the proof is presented directly to the RS.

**5. Colluding RSes can link sessions in the baseline.** BBS+ multi-show unlinkability prevents a single RS from linking two presentations of the same credential. However, two colluding RSes can compare the issuer public key, credential schema, and issuance timing to probabilistically link sessions. In Bolyra, the SES-UNL game formally proves that colluding RSes (even with AS assistance) cannot link cross-scope sessions: the `scopeNullifier`, `blindedScopeCommitment`, and proof are all computationally independent across scopes under P-PRF and G16-ZK/PLONK-ZK. No baseline component provides a formal session-unlinkability guarantee — BBS+ unlinkability holds only within a single verifier's view, not across colluding verifiers who share metadata.

**6. Delegation leaks chain topology in RFC 8693.** Every delegation hop requires an AS roundtrip, revealing the full chain. Bolyra's `ScopedDelegation` links hops via `blindedScopeCommitment` values that are unlinkable across scopes, with no AS involvement.

**7. No formal security definition exists in the baseline.** The baseline has no IND-UNL-AS game, no SES-UNL game, no reduction to named assumptions, and no proof of security against either cross-agent identification or cross-scope session linking by an adversarial AS. Bolyra's construction reduces both properties to the Poseidon PRF assumption and Groth16/PLONK zero-knowledge — both well-studied in the ZK literature. The security argument is falsifiable: break P-PRF or G16-ZK, and the construction falls; absent such a break, the advantage is negligible.
