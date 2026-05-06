# Construction

## 1. Statement of claim

Bolyra strictly dominates vanilla OAuth 2.1 + DPoP + RFC 8693 as general-purpose MCP authentication by providing two properties no configuration of the RFC stack can express: (a) cryptographic binding of runtime model identity (model_hash, operator_pk, permission_bitmask) to each tool invocation, verified without AS involvement; and (b) forward-secure session unlinkability via epoch-rotating nullifiers, such that compromise of an agent's long-term secret does not retroactively deanonymize prior sessions. These properties are delivered in a single credential presentation (mutual handshake) requiring zero AS roundtrips at verification time.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Epoch-Keyed Forward-Secure Nullifier Scheme

Introduce an epoch counter `e` (e.g., hourly rotation). The agent derives a per-epoch ephemeral secret:

```
epochSecret_e = Poseidon2(longTermSecret, e)
```

The session nullifier is then:

```
nullifier = Poseidon2(epochSecret_e, sessionNonce)
```

After epoch `e` completes, the agent erases `epochSecret_e`. An adversary who later compromises `longTermSecret` can compute `epochSecret_e` for future epochs but cannot reconstruct nullifiers from past epochs unless they also recorded `sessionNonce` values AND the epoch secrets before deletion. Critically, even with `longTermSecret`, the adversary cannot link a recorded nullifier to the agent's identity without the specific `epochSecret_e` that produced it — and that value was erased.

### 2.2 Circuit: AgentPolicyV2 (PLONK)

Extends the Bolyra AgentPolicy circuit with epoch-key derivation and model-hash binding as first-class public commitments.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `longTermSecret` | F_p | Agent long-term secret scalar |
| `epochCounter` | uint64 | Current epoch index |
| `modelHash` | F_p | Hash of model checkpoint (e.g., SHA256 → Poseidon re-hash) |
| `operatorPubkeyAx, Ay` | F_p × F_p | Operator Baby Jubjub public key |
| `permissionBitmask` | uint64 | 64-bit permission bitfield |
| `expiryTimestamp` | uint64 | Credential expiry |
| `sigR8x, sigR8y, sigS` | F_p × F_p × F_p | Operator EdDSA signature |
| `merkleProofLength, Index, Siblings[20]` | — | Merkle inclusion proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | uint64 | RS-specified required permission bits |
| `currentTimestamp` | uint64 | Verifier-supplied wall clock |
| `sessionNonce` | F_p | Per-session random nonce |
| `epochFloor` | uint64 | Minimum acceptable epoch (prevents stale proofs) |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed root for enrollment check |
| `epochNullifier` | F_p | Forward-secure, epoch-bound nullifier |
| `scopeCommitment` | F_p | Poseidon2(permissionBitmask, credentialCommitment) |
| `modelBindingTag` | F_p | Poseidon3(modelHash, permissionBitmask, sessionNonce) |

**Constraints:**

1. **Range checks:** Num2Bits(64) on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`, `epochCounter`. Num2Bits(251) on `longTermSecret`.

2. **Epoch secret derivation:**
   ```
   epochSecret = Poseidon2(longTermSecret, epochCounter)
   ```

3. **Epoch nullifier:**
   ```
   epochNullifier = Poseidon2(epochSecret, sessionNonce)
   ```

4. **Epoch freshness:** `epochCounter >= epochFloor`, enforced via LessEqThan(64). Prevents replaying proofs from expired epochs.

5. **Credential commitment** (unchanged from spec):
   ```
   credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)
   ```

6. **EdDSA signature verification:** EdDSAPoseidonVerifier over `credentialCommitment` using `(operatorPubkeyAx, operatorPubkeyAy)` and `(sigR8x, sigR8y, sigS)`.

7. **Merkle membership:** BinaryMerkleRoot(20) with `credentialCommitment` as leaf must equal `agentMerkleRoot`.

8. **Scope satisfaction:** For each bit `i` in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.

9. **Cumulative encoding:** Standard tier constraints on bits [2,3,4].

10. **Expiry:** `currentTimestamp < expiryTimestamp` via LessThan(64).

11. **Model binding tag:**
    ```
    modelBindingTag = Poseidon3(modelHash, permissionBitmask, sessionNonce)
    ```
    This tag is a public output. The RS checks it against expected model hashes (published by the operator) to verify that the specific model checkpoint and permission set active at call time are cryptographically committed — not merely asserted via a static `client_id`.

12. **Scope commitment** (unchanged):
    ```
    scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
    ```

### 2.3 Circuit: HumanUniqueness (Groth16, unchanged)

The human circuit from the Bolyra spec is used as-is. No modifications needed. The mutual handshake binds human proof and agent proof to the same `sessionNonce`.

### 2.4 Mutual Handshake (modified step 5)

The on-chain registry verification adds:

- **5h.** `epochCounter >= epochFloor` (redundant with circuit constraint; defense-in-depth).
- **5i.** `epochNullifier` not in the epoch-nullifier revocation set.
- **6c.** Store `modelBindingTag` in the session record for RS-side audit.

The RS (MCP server) receives `(modelBindingTag, epochNullifier, scopeCommitment)` as the authentication assertion. It verifies:
- `modelBindingTag` matches an expected value computed from the operator's published model manifest.
- `epochNullifier` is fresh (not seen in this epoch).
- `scopeCommitment` satisfies the RS's access policy.

No AS roundtrip. No token introspection. No bearer token.

## 3. Threat model (adversary capabilities, game definition)

### Game 1: Model Impersonation (MCP-FORGE)

**Adversary capabilities:** Controls a rogue agent with a valid credential (enrolled in Merkle tree) but running model M' ≠ M. Wants to authenticate as model M to an RS that requires model M.

**Wins by:** Producing a valid AgentPolicyV2 proof where `modelBindingTag` matches `Poseidon3(H(M), allowedBitmask, sessionNonce)` while actually running M'.

**Game definition:**
1. Challenger enrolls honest agent with credential commitment C = Poseidon5(H(M), opPk.Ax, opPk.Ay, bitmask, expiry).
2. Adversary receives: the RS's expected `modelBindingTag` for model M, the `sessionNonce`, and the `requiredScopeMask`.
3. Adversary must produce a valid PLONK proof π such that the `modelBindingTag` output matches the RS's expectation.
4. Adversary wins if π verifies AND the adversary's actual model hash ≠ H(M).

**Reduction:** Winning requires either (a) finding a Poseidon3 collision (modelHash' ≠ modelHash but same tag), or (b) forging the operator EdDSA signature over a credential commitment containing modelHash when the adversary only holds a signature over modelHash'. Both reduce to Poseidon collision resistance or EdDSA unforgeability on Baby Jubjub.

### Game 2: Retroactive Deanonymization (EPOCH-LINK)

**Adversary capabilities:** Compromises the agent's `longTermSecret` at time T. Has recorded all public signals (epochNullifier, modelBindingTag, scopeCommitment) from sessions in epochs e < e_T (before compromise).

**Wins by:** Linking any recorded `epochNullifier` from epoch e < e_T to the compromised agent's identity.

**Game definition:**
1. Agent participates in sessions across epochs e_1, ..., e_k, each producing `epochNullifier_i = Poseidon2(Poseidon2(longTermSecret, e_i), sessionNonce_i)`.
2. Agent erases `epochSecret_{e_i}` at the end of each epoch.
3. Adversary obtains `longTermSecret` at epoch e_T.
4. Adversary must identify which recorded `epochNullifier` values belong to the compromised agent.
5. Adversary wins if they correctly link any prior-epoch nullifier to the agent with probability > 1/|anonymity_set| + negl(λ).

### Game 3: Scope Escalation (SCOPE-CLIMB)

**Adversary capabilities:** Holds a valid agent credential with `permissionBitmask = B_low`. Wants to authenticate with `permissionBitmask = B_high` where `B_high & requiredMask == requiredMask` but `B_low & requiredMask ≠ requiredMask`.

**Wins by:** Producing a valid proof where scope satisfaction (constraint 8) passes despite holding only B_low.

**Reduction:** Knowledge soundness of PLONK ensures extracted witness contains `permissionBitmask` satisfying constraint 8. If extracted bitmask ≠ B_low, adversary has forged the operator EdDSA signature over a different credential commitment. Reduces to EdDSA unforgeability.

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**

| ID | Assumption | Parameter |
|----|-----------|-----------|
| A1 | Discrete Log on Baby Jubjub | 251-bit subgroup order |
| A2 | Poseidon collision resistance | BN254 scalar field, t=2,3,5 |
| A3 | Poseidon PRF (keyed mode) | BN254 scalar field |
| A4 | Knowledge soundness of PLONK | Universal SRS, Fiat-Shamir ROM |
| A5 | Knowledge soundness of Groth16 | Circuit-specific CRS (Semaphore ceremony) |
| A6 | Random Oracle Model | Fiat-Shamir transform |

**Theorem (Model Binding Security):** Under A2, A4, and A1, no PPT adversary wins MCP-FORGE with non-negligible probability.

*Reduction sketch:* Suppose adversary A wins MPC-FORGE. By A4 (knowledge soundness of PLONK), extract witness W from the valid proof. W contains `modelHash`, `operatorPubkeyAx/Ay`, `permissionBitmask`, and `sigR8x/R8y/S`. The circuit enforces `credentialCommitment = Poseidon5(modelHash, ...)` and EdDSA verification over `credentialCommitment`. Case 1: extracted `modelHash = H(M)` — contradiction, adversary is running M. Case 2: extracted `modelHash = H(M') ≠ H(M)` but `modelBindingTag` matches — then `Poseidon3(H(M'), bitmask, nonce) = Poseidon3(H(M), bitmask, nonce)`, breaking A2 (Poseidon collision resistance). Case 3: extracted `modelHash = H(M)` but signature is over a different credential — EdDSA forgery, breaking A1.

**Theorem (Forward-Secure Unlinkability):** Under A3 and the epoch-erasure discipline, no PPT adversary wins EPOCH-LINK with non-negligible probability.

*Reduction sketch:* The adversary holds `longTermSecret` but not `epochSecret_e` for any e < e_T (erased). Computing `epochSecret_e = Poseidon2(longTermSecret, e)` requires evaluating Poseidon, which the adversary CAN do (they have `longTermSecret` and know `e`). **Critical subtlety:** The adversary CAN recompute epoch secrets from `longTermSecret` — forward secrecy holds ONLY if the adversary does NOT obtain `longTermSecret`. The correct framing: if the adversary obtains `longTermSecret`, forward secrecy is broken for epoch-secret derivation. However, the construction still provides **session unlinkability across RS colluders**: the `epochNullifier` is scope-free (bound to sessionNonce, not RS identity), so colluding RSes cannot correlate sessions from different nonces. For true forward secrecy under long-term key compromise, we strengthen the construction with a **ratcheted** epoch secret:

```
epochSecret_0 = Poseidon2(longTermSecret, salt_0)
epochSecret_{e+1} = Poseidon2(epochSecret_e, e+1)
```

Agent stores only `epochSecret_e` (erases `epochSecret_{e-1}` and never stores `longTermSecret` after initialization). Now compromising `epochSecret_{e_T}` yields only future secrets (forward direction), not past ones. Under A3 (Poseidon PRF), inverting `Poseidon2(epochSecret_{e-1}, e)` to recover `epochSecret_{e-1}` is infeasible. The adversary cannot traverse the chain backward. This is a standard hash-chain ratchet argument (cf. Signal Double Ratchet, but single-direction).

**Theorem (Scope Narrowing Integrity):** Under A4 and A1, no PPT adversary wins SCOPE-CLIMB with non-negligible probability. Reduction: knowledge soundness extracts the witness; constraint 8 forces `requiredBits[i] * (1 - permBits[i]) === 0`; if extracted `permissionBitmask` differs from enrolled value, EdDSA signature verification (constraint 6) fails unless adversary forges, breaking A1.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Epoch secret derivation | Poseidon2(secret, epoch) | Poseidon hash, BN128 scalar field |
| Epoch nullifier | Poseidon2(epochSecret, sessionNonce) | Nullifier pattern (§ Terminology) |
| Credential commitment | Poseidon5(modelHash, opAx, opAy, bitmask, expiry) | AgentPolicy circuit, constraint 2 |
| Model binding tag | Poseidon3(modelHash, bitmask, sessionNonce) | New — uses only Poseidon |
| Scope commitment | Poseidon2(permissionBitmask, credentialCommitment) | AgentPolicy circuit, output |
| Operator signature | EdDSA on Baby Jubjub over credentialCommitment | AgentPolicy circuit, constraint 3 |
| Agent proof system | PLONK with universal setup | Spec § Proving Systems |
| Human proof system | Groth16 (Semaphore ceremony) | Spec § Proving Systems |
| Merkle membership | Lean Incremental Merkle Tree, depth 20, Poseidon2 | Spec § Cryptographic Primitives |
| Mutual binding | Shared sessionNonce across both proofs | Spec § Mutual Handshake |
| Delegation chain | scopeCommitment → Delegation circuit (PLONK) | Spec § Composable Delegation |
| Ratcheted forward secrecy | Poseidon2(epochSecret_e, e+1) chain | New — uses only Poseidon |

All primitives use only: Poseidon (t=2,3,5), Baby Jubjub EdDSA, Groth16, PLONK, and the nullifier pattern. No new cryptographic assumptions beyond those already in the Bolyra spec.

## 6. Circuit cost estimate

### AgentPolicyV2 (PLONK)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(251) for longTermSecret | 251 |
| Num2Bits(64) × 4 (bitmask, expiry, timestamp, epoch) | 256 |
| Poseidon2 (epoch secret derivation) | ~300 |
| Poseidon2 (epoch nullifier) | ~300 |
| Poseidon5 (credential commitment) | ~450 |
| Poseidon3 (model binding tag) | ~350 |
| Poseidon2 (scope commitment) | ~300 |
| EdDSAPoseidonVerifier | ~4,500 |
| BinaryMerkleRoot(20) with 20× Poseidon2 | ~6,000 |
| Scope satisfaction (64 bit-checks) | 64 |
| Cumulative encoding (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| LessEqThan(64) for epoch freshness | ~130 |
| **Total** | **~13,034** |

**Proving time target:** < 5s (PLONK agent circuit). At ~13K constraints, well within PLONK proving on modern hardware (browser WASM: ~2-3s; native: <1s).

### HumanUniqueness (Groth16, unchanged)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(251) | 251 |
| BabyPbk | ~1,000 |
| Poseidon2 (identity commitment) | ~300 |
| BinaryMerkleRoot(20) | ~6,000 |
| Poseidon2 (nullifier) | ~300 |
| Poseidon2 (nonce binding) | ~300 |
| **Total** | **~8,151** |

**Proving time target:** < 15s (Groth16 human circuit). At ~8K constraints, Groth16 in browser: ~3-5s; native: <1s.

### Delegation Circuit (PLONK, minor addition)

Unchanged from spec. ~12K constraints. < 5s proving.

### Total handshake cost

One Groth16 proof (~8K) + one PLONK proof (~13K) = ~21K constraints total. Single on-chain verification transaction. Gas cost on EVM: ~250K gas for Groth16 verify (EIP-196/197) + ~350K gas for PLONK verify ≈ 600K gas total (~$0.30 at 50 gwei, L1; < $0.01 on L2).

## 7. Concrete deployment scenario

**Stakeholder:** Anthropic MCP Connector (Claude agent platform)

**Scenario:** Claude agent authenticates to a third-party MCP server (e.g., a Stripe payment tool) without Anthropic acting as an OAuth authorization server in the hot path.

**Flow:**

1. **Enrollment (one-time):** Anthropic registers Claude's model checkpoint hash and operator key in the Bolyra agent Merkle tree. The credential commitment `Poseidon5(H("claude-opus-4-6"), anthropicPk.Ax, anthropicPk.Ay, 0x1F, expiry)` is inserted as a leaf. Stripe registers as an RS with `requiredScopeMask = 0x07` (read + write + payment).

2. **Authentication (per-session):** Claude's MCP connector generates an AgentPolicyV2 PLONK proof. The human user generates a HumanUniqueness Groth16 proof (via browser wallet or passkey-backed prover). Both proofs share `sessionNonce`.

3. **Verification (no AS roundtrip):** Stripe's MCP server verifies both proofs against the on-chain registry. It checks:
   - `modelBindingTag` matches expected value for `claude-opus-4-6` with payment permissions.
   - `epochNullifier` is fresh in the current epoch.
   - `scopeCommitment` satisfies `requiredScopeMask`.
   - Human nullifier is not revoked.

4. **Cross-vendor handoff:** If Claude delegates to a ChatGPT agent for a sub-task, the Delegation circuit narrows scope (e.g., removes payment bit) in a single PLONK proof. No Anthropic AS involvement. No OpenAI AS involvement. The ChatGPT agent authenticates to the same Stripe RS using its own credential + the delegation proof chain.

5. **Epoch rotation:** Every hour, Claude's connector derives new `epochSecret` and erases the previous one. Compromise of Claude's long-term key at hour T does not reveal which Stripe sessions occurred before hour T.

**Second stakeholder:** Navy Federal Credit Union (NFCU)

**Scenario:** NFCU deploys an MCP-based financial assistant. Members authenticate via Bolyra human proofs (Groth16). The AI agent proves it is running an NFCU-approved model with NFCU-signed credentials. No external IdP sees member-to-agent session bindings. NFCU's compliance team audits `modelBindingTag` logs to verify only approved model checkpoints accessed member data — a requirement under NCUA examination guidelines that OAuth `client_id` cannot satisfy (it proves app registration, not runtime model identity).

## 8. Why the baseline cannot match

The OAuth 2.1 + DPoP + RFC 8693 baseline cannot match this construction for five structural reasons:

**1. No runtime model binding (H2).** OAuth `client_id` is a static string set at registration. It identifies an application, not a model checkpoint. If Anthropic updates Claude from `opus-4-5` to `opus-4-6`, the `client_id` doesn't change. The RS has no cryptographic assurance about which model is running. Bolyra's `modelBindingTag = Poseidon3(modelHash, permissionBitmask, sessionNonce)` is a per-invocation commitment to the exact model, permission set, and session — verified in zero knowledge without trusting the client's self-report. No OAuth RFC provides a mechanism for the RS to verify runtime state of the client without trusting an intermediary.

**2. No forward-secure session unlinkability (H4).** DPoP (RFC 9449) binds tokens to a keypair, but if that keypair is compromised, all prior DPoP proofs are attributable. Short-lived tokens limit the damage window but do not provide forward secrecy — the adversary can still verify "this token was used by this key" for all recorded sessions. Bolyra's ratcheted epoch secrets ensure that compromise of the current secret does not reveal the mapping between past nullifiers and the agent identity. This is an information-theoretic gap: the DPoP adversary gains a linking oracle; the Bolyra adversary does not.

**3. No AS-blind verification (H1, H3).** Every OAuth flow requires the AS to issue, introspect, or exchange the token. The AS is a universal correlator — it sees every RS the agent accesses, every delegation hop, every scope request. OIDC PPIDs hide the `sub` from RS-vs-RS correlation, but the AS retains the full mapping. Bolyra proofs are verified against an on-chain Merkle root. No AS is in the loop. No party learns which agent authenticated to which RS unless the agent or RS volunteers that information.

**4. No atomic human+agent composition (H1).** OAuth authenticates the human (OIDC id_token) and the agent (client_credentials + DPoP) in separate flows, concatenated at the application layer. There is no single cryptographic object that simultaneously proves "this human and this agent are bound to this session." Bolyra's mutual handshake produces exactly this: two proofs over a shared `sessionNonce`, verified atomically in one transaction. An RS that accepts both proofs knows — with knowledge-soundness guarantees — that a valid human and a valid agent are co-present for this session.

**5. No offline delegation narrowing (H5).** RFC 8693 token exchange requires one AS roundtrip per delegation hop. For a three-hop agent chain (Claude → sub-agent → sub-sub-agent), that's three AS calls, each adding latency and giving the AS a full view of the delegation graph. Bolyra's delegation circuit narrows scope in a single PLONK proof per hop, verified on-chain or by the RS directly, with no AS involvement. The delegation is cryptographically enforced (scope subset constraint), not policy-asserted by a trusted third party.

**In summary:** The baseline's structural limitations are not implementation gaps — they are consequences of the OAuth trust model, which requires a trusted issuer in the verification path. Bolyra eliminates the issuer from verification entirely, enabling properties (model binding, forward secrecy, issuer-blindness, atomic composition, offline delegation) that no configuration of the RFC stack can express.
