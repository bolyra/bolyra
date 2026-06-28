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

### IND-UNL-AS Game

**Setup:** Challenger enrolls two agents A₀, A₁ with identical `permissionBitmask` and `expiryTimestamp` in the agent Merkle tree. Both are issued valid credentials by the adversarial AS.

**Phase 1:** Adversary A may request `ScopedPresentation` proofs from A₀ and A₁ for any scope of A's choosing. A receives the proofs and all public outputs.

**Challenge:** A chooses a target scope `scopeId*` not previously queried. Challenger flips bit b ∈ {0,1}, generates a `ScopedPresentation` proof from agent A_b for `scopeId*` with a fresh `presentationNonce`, and returns the proof and public outputs to A.

**Phase 2:** A may request additional proofs for any scope except `scopeId*`.

**Guess:** A outputs b' ∈ {0,1}. A wins if b' = b.

**Advantage:** Adv_IND-UNL-AS(A) = |Pr[b' = b] - 1/2|

**Claim:** For all PPT A, Adv_IND-UNL-AS(A) ≤ negl(λ), assuming Poseidon is a PRF and Groth16/PLONK satisfies zero-knowledge.

### Timing side-channel extension

The game extends to timing by requiring the challenger to sample proof-generation time from a fixed distribution (uniform over a configurable window, e.g., [0, 500ms] jitter). The agent implementation MUST add random delay before submitting any proof to an RS. This is an application-layer requirement, not a circuit constraint.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

1. **Poseidon PRF (P-PRF):** Poseidon2 and Poseidon3 are pseudorandom functions when keyed on a secret input. Specifically, for a random key k, the function x → Poseidon2(x, k) is computationally indistinguishable from a random function.
2. **Groth16 zero-knowledge (G16-ZK):** The Groth16 proving system satisfies computational zero-knowledge: the proof reveals nothing about private inputs beyond what is implied by the public inputs/outputs.
3. **PLONK zero-knowledge (PLONK-ZK):** Same property for PLONK proofs when used for `AgentPolicy`/`Delegation`.
4. **Poseidon collision resistance (P-CR):** Finding x ≠ x' such that Poseidon(x) = Poseidon(x') requires superpolynomial time.
5. **Discrete logarithm on Baby Jubjub (DL-BJJ):** Given (Ax, Ay) = BabyPbk(s), recovering s is hard.

### Reduction sketch

**Theorem:** If A wins IND-UNL-AS with non-negligible advantage ε, then we can construct either (a) a distinguisher B against P-PRF with advantage ε/2, or (b) a distinguisher C against G16-ZK/PLONK-ZK with advantage ε/2.

**Proof sketch:**

1. **Hybrid H₀:** Real game. A interacts with agents A₀, A₁.

2. **Hybrid H₁:** Replace `scopeNullifier` computation for the challenge scope with a truly random value r. By P-PRF (keyed on the agent's `innerHash = Poseidon2(credentialCommitment, scopeBlinder)`, which is unknown to A), A cannot distinguish H₀ from H₁ unless A breaks P-PRF. The `innerHash` is distinct per-agent (different `credentialCommitment`) and per-scope (different `scopeBlinder`), so A has never seen the PRF evaluated at `scopeId*` for agent A_b.

3. **Hybrid H₂:** Replace the challenge proof π* with a simulated proof (using the Groth16/PLONK simulator). By G16-ZK/PLONK-ZK, A cannot distinguish H₁ from H₂.

4. In H₂, A receives a random `scopeNullifier`, a random-looking `presentationBinding` (derived from the random nullifier), a random-looking `blindedScopeCommitment` (blinded by the unknown `scopeBlinder`), a valid `agentMerkleRoot` (same for both agents since both are enrolled), and a simulated proof. None of these values depend on b. Therefore Adv(A) in H₂ = 0.

5. By the triangle inequality: ε ≤ Adv_P-PRF(B) + Adv_ZK(C).

**Cross-scope unlinkability follows:** Two presentations at different scopes produce different `scopeNullifier` values (different `scopeId` inputs to the PRF), different `blindedScopeCommitment` values (different `scopeBlinder`), and independent proofs. Under P-PRF, these are computationally independent of each other.

**AS impotence:** The AS knows the `credentialCommitment` (it was enrolled on-chain). But it does not know any agent's `scopeBlinder`. Without the blinder, the AS cannot compute `innerHash`, and therefore cannot predict the `scopeNullifier` for any scope. The AS sees only the on-chain Merkle root and public enrollment events — it never sees presentation proofs (those go directly to the RS).

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

### Healthcare referral network privacy

**Stakeholder:** Kaiser Permanente (issuer) delegates agent credentials for patient referrals.

**Flow:** Patient's agent is delegated from Kaiser (primary) to an external specialist (RS-B) and a lab (RS-C). Using `ScopedDelegation`, each delegation hop produces a `blindedScopeCommitment` that is unlinkable across providers. Kaiser cannot learn that the specialist referred the patient to the lab — the `scopeNullifier` at the lab is cryptographically independent of the one at the specialist, and Kaiser never sees either.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails against the IND-UNL-AS game on six structural axes that no configuration or layering can fix:

**1. AS is in the issuance path — always.** Every OAuth token passes through the AS at issuance. The AS logs `(agent_id, RS, scope, timestamp)` for every token request. Bolyra's `ScopedPresentation` eliminates the AS from the presentation path entirely: the agent proves directly to the RS using the on-chain Merkle root. The AS sees only enrollment, never presentation.

**2. PPID protects the wrong party.** PPID hides the subject from RSes, not from the AS. The AS holds the PPID mapping table and can trivially reverse any PPID. Bolyra's `scopeNullifier` is derived from a per-scope blinder that the AS never learns — the AS cannot compute the nullifier for any scope.

**3. BBS+ does not provide issuer anonymity.** Every BBS+ derived proof exposes the issuer's public key. An AS that is also the issuer can identify its own credentials at any RS. In Bolyra, the operator's public key is a private input — the RS learns only that "some enrolled credential signed by some authorized operator satisfies the policy."

**4. Scope correlation at the AS is free in OAuth.** The AS observes every `scope` parameter in every token request. An adversarial AS can build a complete per-agent scope-access timeline. In Bolyra, the `scopeId` is a public input to the circuit but the AS never sees it — the proof is presented directly to the RS.

**5. Delegation leaks chain topology in RFC 8693.** Every delegation hop requires an AS roundtrip, revealing the full chain. Bolyra's `ScopedDelegation` links hops via `blindedScopeCommitment` values that are unlinkable across scopes, with no AS involvement.

**6. No formal security definition exists in the baseline.** The baseline has no IND-UNL-AS game, no reduction to named assumptions, and no proof of security against an adversarial AS. Bolyra's construction reduces AS-unlinkability to the Poseidon PRF assumption and Groth16/PLONK zero-knowledge — both well-studied in the ZK literature. The security argument is falsifiable: break P-PRF or G16-ZK, and the construction falls; absent such a break, the advantage is negligible.
