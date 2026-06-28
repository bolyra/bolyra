# Construction

## 1. Statement of claim

Same agent accessing different Resource Server (RS) instances produces cryptographically unlinkable authorizations even under an adversarial Authorization Server (AS) that observes all proof submissions and actively attempts to correlate per-agent traffic graphs across scopes. Formally: no PPT adversary controlling the AS (and colluding with any subset of RSes) can distinguish whether two scope-specific proofs originated from the same agent or two independent agents, beyond negligible advantage.

## 2. Construction (gadgets, circuits, public/private inputs)

### Core idea

Replace the current AgentPolicy nullifier (`Poseidon(credentialCommitment, sessionNonce)`) with a **scope-partitioned nullifier** (`Poseidon(scopeId, credentialSecret)`) that mirrors the human circuit's cross-scope unlinkability property (P1.3 in FORMAL-PROPERTIES.md). The agent's `credentialSecret` — a scalar known only to the agent — acts as the PRF key; the `scopeId` acts as the PRF input. Different scopes yield independent pseudorandom nullifiers.

### New circuit: ScopedAgentPresentation

This circuit is used when an agent presents a credential to an RS. It is distinct from the handshake AgentPolicy circuit (which seeds delegation chains). The separation is critical: the handshake circuit outputs a `scopeCommitment` for chain-linking; the presentation circuit outputs only scope-specific, unlinkable artifacts.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `credentialSecret` | F_p (251-bit range-checked) | Agent's secret scalar, analogous to human `secret` |
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx` | F_p | Operator EdDSA public key x-coordinate |
| `operatorPubkeyAy` | F_p | Operator EdDSA public key y-coordinate |
| `permissionBitmask` | 64-bit | Credential permission bits |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x, sigR8y, sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength` | int | Actual Merkle depth |
| `merkleProofIndex` | int | Leaf index |
| `merkleProofSiblings[20]` | F_p[] | Sibling hashes |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `scopeId` | F_p | RS-specific scope identifier (e.g., Poseidon hash of RS domain) |
| `requiredScopeMask` | 64-bit | Required permission bits for this RS |
| `currentTimestamp` | 64-bit | Verifier-supplied wall-clock time |
| `sessionNonce` | F_p | Fresh per-request nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | Computed Merkle root |
| `scopeNullifier` | F_p | `Poseidon2(scopeId, credentialSecret)` — deterministic per (agent, scope) |
| `nonceBinding` | F_p | `Poseidon2(scopeNullifier, sessionNonce)` — replay prevention |

**Constraints:**

1. **Secret range**: `Num2Bits(251)` on `credentialSecret`, ensuring `credentialSecret ∈ [0, 2^251)`.
2. **Credential commitment**: `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **Secret binding**: `secretCommitment = Poseidon2(credentialCommitment, credentialSecret)`. This value is the leaf enrolled in the agent Merkle tree (replaces raw `credentialCommitment` as the leaf).
4. **EdDSA signature**: `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)` — operator signed the credential.
5. **Merkle membership**: `BinaryMerkleRoot(20)` with `secretCommitment` as leaf must equal `agentMerkleRoot`.
6. **Scope nullifier**: `scopeNullifier = Poseidon2(scopeId, credentialSecret)`. Deterministic per (agent, scope). Under Poseidon PRF, independent across different `scopeId` values.
7. **Nonce binding**: `nonceBinding = Poseidon2(scopeNullifier, sessionNonce)`. Binds proof to session.
8. **Scope satisfaction**: For each bit `i ∈ [0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`.
9. **Cumulative bit encoding**: Standard Bolyra tier constraints (bits 4→3→2).
10. **Expiry**: `LessThan(64)(currentTimestamp, expiryTimestamp)`.
11. **Range checks**: `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`.

**Gadgets used**: Poseidon2, Poseidon5, EdDSAPoseidonVerifier, BinaryMerkleRoot(20), Num2Bits(64), Num2Bits(251), LessThan(64).

### Enrollment change

The agent Merkle tree leaf becomes `secretCommitment = Poseidon2(credentialCommitment, credentialSecret)` instead of `credentialCommitment`. This is the minimal change that introduces the PRF key without altering the rest of the protocol. The `credentialSecret` is generated at credential creation time and stored alongside the credential.

### Handshake integration

The existing AgentPolicy circuit continues to seed delegation chains via `scopeCommitment`. A handshake proof and a ScopedPresentation proof are unlinkable by construction: they use different nullifier derivations (`Poseidon(credentialCommitment, sessionNonce)` vs `Poseidon(scopeId, credentialSecret)`) and different Merkle leaves (`credentialCommitment` vs `secretCommitment`). The two trees can share a root (by enrolling both values) or use separate trees. Using separate trees provides the strongest separation.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A controls:
- The Authorization Server (AS): sees all proof submission requests, controls nonce generation, can inject arbitrary `scopeId` values.
- An arbitrary subset of Resource Servers: can collect `(scopeNullifier, nonceBinding, agentMerkleRoot, sessionNonce, scopeId)` tuples from those RSes.
- Timing metadata: observes wall-clock times of all proof submissions.

The adversary does NOT control:
- The agent's local proving environment (cannot extract `credentialSecret`).
- The on-chain Merkle tree integrity (roots are publicly verifiable).

### IND-UNL-AS game

```
Game IND-UNL-AS(λ):
  1. Setup: Generate two agent credentials (cred₀, secret₀) and (cred₁, secret₁).
     Enroll both in the agent Merkle tree. Give A the tree root and all public parameters.
  2. Challenge: A chooses two scope identifiers scopeId_A and scopeId_B where scopeId_A ≠ scopeId_B.
  3. Challenger flips coin b ← {0, 1}.
     - If b = 0: Generate proof π_A using (cred₀, secret₀) for scopeId_A,
                  and proof π_B using (cred₀, secret₀) for scopeId_B.
       (Same agent, two scopes.)
     - If b = 1: Generate proof π_A using (cred₀, secret₀) for scopeId_A,
                  and proof π_B using (cred₁, secret₁) for scopeId_B.
       (Different agents, two scopes.)
  4. Give A the tuples (π_A, scopeNullifier_A, nonceBinding_A, root_A, scopeId_A)
     and (π_B, scopeNullifier_B, nonceBinding_B, root_B, scopeId_B).
  5. A outputs b'. A wins if b' = b.

Security: The protocol is IND-UNL-AS-secure if for all PPT A:
  |Pr[b' = b] - 1/2| ≤ negl(λ)
```

### Side-channel extension: IND-UNL-AS-T (timing-aware)

Same game, but the adversary also observes submission timestamps `(t_A, t_B)`. The protocol achieves IND-UNL-AS-T security when proofs are submitted through a batching relay that aggregates proofs from multiple agents into fixed-interval batches (e.g., 500ms epochs), eliminating per-agent timing signatures.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **A1: Poseidon PRF security** — `F_k(x) = Poseidon2(x, k)` is a pseudorandom function family keyed by `k = credentialSecret` over the BN254 scalar field.
- **A2: Poseidon collision resistance** — Finding `(x₁, x₂) ≠ (y₁, y₂)` with `Poseidon2(x₁, x₂) = Poseidon2(y₁, y₂)` requires `Ω(2^{128})` work.
- **A3: Knowledge soundness of Groth16** (for human circuit) / **PLONK** (for ScopedAgentPresentation) — in the generic group model / algebraic group model + ROM.
- **A4: Discrete log hardness on Baby Jubjub** — given `(Ax, Ay) = s · G`, recovering `s` requires `Ω(2^{125})` work.

### Reduction sketch (IND-UNL-AS → Poseidon PRF)

**Theorem**: If Poseidon2 is a secure PRF (A1) and the proving system is zero-knowledge (A3), then the ScopedAgentPresentation construction is IND-UNL-AS-secure.

**Proof sketch**:

1. **Nullifier indistinguishability from PRF**: In the b=0 case (same agent), the adversary sees `scopeNullifier_A = Poseidon2(scopeId_A, secret₀)` and `scopeNullifier_B = Poseidon2(scopeId_B, secret₀)`. These are two evaluations of a PRF keyed by `secret₀` on distinct inputs. By A1, these are computationally indistinguishable from two independent random field elements — exactly the distribution in the b=1 case where different secrets produce the nullifiers.

2. **Proof zero-knowledge**: By A3, the Groth16/PLONK proofs (π_A, π_B) are computationally zero-knowledge. They reveal nothing about private inputs (`credentialSecret`, `credentialCommitment`, Merkle path) beyond what the public outputs already convey.

3. **Nonce binding independence**: `nonceBinding = Poseidon2(scopeNullifier, sessionNonce)`. Since the nonces are fresh and the nullifiers are indistinguishable from random (step 1), nonce bindings carry no additional distinguishing information.

4. **Merkle root**: Both worlds use the same tree root (both agents are enrolled). The root leaks set membership, not individual identity.

5. **Reduction**: Suppose adversary A breaks IND-UNL-AS with advantage ε. Construct PRF distinguisher D: D receives an oracle O that is either `Poseidon2(·, secret₀)` or a random function. D runs the IND-UNL-AS game, using O to compute nullifiers in both the b=0 and b=1 cases. If O is the real PRF, D simulates b=0 perfectly. If O is random, D simulates b=1 perfectly. D outputs A's guess. Then D's advantage against the PRF ≥ ε, contradicting A1.

### Sybil detection preservation

Within a single scope, the nullifier `Poseidon2(scopeId, credentialSecret)` is deterministic. If the same agent presents twice to the same RS (same `scopeId`), both proofs yield the same `scopeNullifier`. The RS detects the duplicate. This preserves Sybil resistance within each scope while achieving unlinkability across scopes.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Scope nullifier | `Poseidon2(scopeId, credentialSecret)` | Mirrors human nullifier `Poseidon2(scope, secret)` from HumanUniqueness circuit §S1.2 |
| Nonce binding | `Poseidon2(scopeNullifier, sessionNonce)` | Identical pattern to human `nonceBinding` in §S1.3 |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiry)` | Unchanged from AgentPolicy spec |
| Secret commitment (new leaf) | `Poseidon2(credentialCommitment, credentialSecret)` | New; extends enrollment to bind a secret |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Standard Bolyra primitive |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Standard Bolyra LIMT, depth 20 |
| Scope satisfaction | Bitwise AND check, cumulative bit encoding | Same as AgentPolicy §constraint 5-6 |
| Proving system | PLONK (universal setup, no per-circuit ceremony) | Allowed by spec for agent circuits |
| On-chain verification | PLONK verifier contract, separate from Groth16 human verifier | Spec §Proving Systems: "distinct verifier contract addresses" |

## 6. Circuit cost estimate

| Component | Estimated constraints |
|---|---|
| `Num2Bits(251)` — secret range check | 251 |
| `Poseidon5` — credential commitment | ~300 |
| `Poseidon2` — secret commitment | ~200 |
| `EdDSAPoseidonVerifier` | ~5,500 |
| `BinaryMerkleRoot(20)` — 20 levels × Poseidon2 | ~4,000 |
| `Poseidon2` — scope nullifier | ~200 |
| `Poseidon2` — nonce binding | ~200 |
| `Num2Bits(64)` × 3 — range checks | 192 |
| `LessThan(64)` — expiry check | ~130 |
| Bitwise scope check (64 bits) | ~128 |
| Cumulative bit encoding (3 constraints) | 3 |
| **Total** | **~11,100** |

**Proving time target**: PLONK agent proof < 3s on commodity hardware (M1 Mac, snarkjs WASM). This is well within the 5s PLONK agent budget. With rapidsnark native prover, estimated < 400ms.

**Comparison to existing AgentPolicy**: The existing circuit is ~10,200 constraints. This adds ~900 constraints (the `Poseidon2` for secret commitment + `Num2Bits(251)` for secret range check). Marginal cost for a qualitative security upgrade.

**SRS**: Fits within `pot16.ptau` (2^16 = 65,536 constraint ceiling). No new ceremony required.

## 7. Concrete deployment scenario

### Credit union member agent — merchant graph privacy

**Stakeholder**: Pacific Northwest Credit Union (PNWCU), 45,000 members.

**Setup**: PNWCU operates as the AS for its members' AI agents. Members deploy personal finance agents that autonomously transact with merchants (RS instances): grocery chains, gas stations, subscription services. Each merchant registers a unique `scopeId = Poseidon(merchantDomain)`.

**Problem under baseline**: PNWCU, as the OAuth AS, sees every token issuance request. It knows that Member #12847's agent requested tokens for Costco (10:02am), Shell (10:14am), and Netflix (10:31am). Even with PPIDs, the AS holds the mapping table. PNWCU's analytics team can reconstruct complete merchant graphs per member — a regulatory liability under NCUA data minimization guidance and a competitive intelligence risk if PNWCU offers its own merchant partnerships.

**Bolyra deployment**:
1. PNWCU enrolls each member's agent by adding `secretCommitment = Poseidon2(credentialCommitment, credentialSecret)` to the agent Merkle tree (on Base Sepolia, then mainnet).
2. When the agent transacts with Costco (`scopeId = Poseidon("costco.com")`), it generates a ScopedAgentPresentation proof locally. Costco's verifier checks the proof on-chain (or via off-chain PLONK verification with the published vkey). The proof reveals `scopeNullifier_costco = Poseidon2(scopeId_costco, credentialSecret)`.
3. When the same agent transacts with Shell (`scopeId = Poseidon("shell.com")`), it produces `scopeNullifier_shell = Poseidon2(scopeId_shell, credentialSecret)`.
4. PNWCU, even if it monitors all on-chain verification events, sees two nullifiers that are computationally indistinguishable from independent random values. It cannot determine whether they came from the same agent or two different members.
5. Costco can detect if the same agent double-spends within its scope (same `scopeNullifier`), but cannot correlate with Shell's nullifier.

**Batching relay (timing mitigation)**: PNWCU deploys a simple relay that collects ScopedPresentation proofs from all member agents and submits them to the on-chain verifier in 500ms batches. Each batch contains 5-20 proofs from different agents, destroying per-agent timing signatures. The relay is stateless — it forwards proofs without inspecting private inputs.

**Outcome**: PNWCU achieves NCUA-compliant data minimization. Member merchant graphs are cryptographically private from the credit union itself. The CU retains aggregate statistics (total verified handshakes per epoch) for regulatory reporting without per-member granularity.

### Healthcare referral network privacy

**Stakeholder**: Regional health information exchange (HIE) operating across 12 provider organizations.

**Setup**: A patient's AI health agent carries a delegated credential (via Bolyra Delegation circuit) scoped to `READ_DATA | ACCESS_PII`. The agent presents this credential to multiple specialists (RS instances) during a referral chain.

**Problem under baseline**: The HIE acting as AS sees every token exchange hop. It can reconstruct the full referral topology: Patient → PCP → Cardiologist → Lab → Pharmacy. This leaks sensitive diagnostic inference (cardiology referral implies cardiac concern) to the HIE's data warehouse.

**Bolyra deployment**: Each specialist registers a `scopeId`. The agent produces a ScopedAgentPresentation for each specialist. The HIE sees only disconnected, unlinkable nullifiers. The referral network topology is private from the AS.

## 8. Why the baseline cannot match

The baseline's five structural failures are not configuration gaps — they are architectural impossibilities:

**1. The AS is in the issuance path (unfixable).** Every OAuth/OIDC token is minted by the AS. The AS necessarily learns (agent identity, target RS, scope, timestamp) at issuance time. No RFC can remove the AS from its own issuance loop. Bolyra's ScopedPresentation removes the AS from the critical path entirely: the agent proves credential validity directly to the RS using a ZK proof against the public Merkle root. The AS never participates in per-RS authorization.

**2. PPIDs hide `sub` from RSes, not from the AS (definitional).** OIDC PPIDs are computed by the AS — which holds the mapping table. The AS correlates PPIDs trivially. Bolyra's `scopeNullifier` is computed by the agent locally using its private `credentialSecret`. No entity other than the agent can link nullifiers across scopes, because doing so requires inverting a PRF.

**3. BBS+ unlinkability stops at the RS layer.** BBS+ derived proofs are unlinkable to each other — but the issuer (AS) signed the original credential and knows which agent holds it. If the AS colludes with any RS, it can match the BBS+ issuer key to the agent's identity. Bolyra's construction hides the credential commitment inside the ZK proof; the issuer (operator) signs the credential at enrollment time, but the ScopedPresentation circuit never reveals which credential was used.

**4. No formal security definition exists in the baseline.** No RFC defines an IND-UNL-AS game. The baseline offers informal separation properties but no reduction to named cryptographic assumptions. The construction above provides an explicit game definition and reduction to Poseidon PRF security.

**5. Timing correlation is unmitigated.** The baseline has no batching or padding mechanism. DPoP's `jti` and timestamp fields leak per-request timing to the AS. Bolyra's batching relay (500ms epochs, multi-agent aggregation) eliminates per-agent timing signatures. The relay is stateless and does not require trust — it handles only public proof artifacts.

**6. Delegation chains are AS-visible in the baseline.** RFC 8693 Token Exchange requires an AS roundtrip per delegation hop, exposing the full chain topology. Bolyra's Delegation circuit chains scope commitments on-chain without the AS learning which agents are in the chain or what scopes were narrowed.

**Quantitative gap**: The baseline's adversarial AS advantage in the IND-UNL-AS game is **1** (trivial win — the AS sees the agent's identity at token issuance). The construction's adversarial AS advantage is **negl(λ)** (bounded by Poseidon PRF security, ~2^{-128}). This is not an incremental improvement; it is a qualitative category change from no formal guarantee to cryptographic unlinkability.
