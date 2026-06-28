# Construction

## 1. Statement of claim

The same AI agent accessing *N* distinct Resource Servers produces *N* cryptographically unlinkable authorization proofs, such that an adversarial Authorization Server — even one colluding with any strict subset of the *N* RSes — cannot determine whether two authorizations originated from the same agent. Unlinkability holds under adaptive queries where the adversary chooses RS targets after observing prior proofs.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `ScopedAgentAuth`

This circuit replaces the per-RS token issuance step. Instead of requesting a token from the AS for each RS, the agent generates a ZK proof directly, which the RS verifies against the on-chain agent Merkle root.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | field | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | field | Operator EdDSA pubkey |
| `permissionBitmask` | 64-bit | Agent's full permission set |
| `expiryTimestamp` | 64-bit | Credential expiry |
| `sigR8x`, `sigR8y`, `sigS` | field | Operator EdDSA signature over credentialCommitment |
| `agentSecret` | field | Per-agent long-lived secret scalar (Baby Jubjub), range-checked to [0, 2^251) |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | field | Merkle inclusion proof |
| `scopeBlindingNonce` | field | Fresh random blinding value per proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `rsScopeId` | field | RS-specific scope identifier (domain-separated, e.g. Poseidon("RS-A")) |
| `requiredScopeMask` | 64-bit | Permission bits the RS demands |
| `currentTimestamp` | 64-bit | Verifier-supplied timestamp |
| `sessionNonce` | field | Per-request freshness nonce |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | field | Computed root for on-chain check |
| `scopeNullifier` | field | `Poseidon(rsScopeId, agentSecret)` — scope-specific, deterministic |
| `blindedSessionTag` | field | `Poseidon(scopeNullifier, sessionNonce, scopeBlindingNonce)` — per-request unique |
| `scopeCommitment` | field | `Poseidon(permissionBitmask, credentialCommitment)` — for delegation chain entry |

**Constraints enforced:**

1. **Range checks:** `Num2Bits(64)` on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp`. `Num2Bits(251)` on `agentSecret`.
2. **Credential commitment:** `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSA signature:** `EdDSAPoseidonVerifier(operatorPubkey, credentialCommitment, sig)`.
4. **Merkle membership:** `BinaryMerkleRoot(20)` with `credentialCommitment` as leaf equals `agentMerkleRoot`.
5. **Scope satisfaction:** For each bit *i* in [0, 64): `requiredBits[i] * (1 - permBits[i]) === 0`.
6. **Cumulative bit encoding:** `bits[4]*(1-bits[3]) === 0`, `bits[4]*(1-bits[2]) === 0`, `bits[3]*(1-bits[2]) === 0`.
7. **Expiry:** `currentTimestamp < expiryTimestamp` via `LessThan(64)`.
8. **Scope nullifier:** `scopeNullifier = Poseidon(rsScopeId, agentSecret)` — deterministic per (agent, RS).
9. **Blinded session tag:** `blindedSessionTag = Poseidon(scopeNullifier, sessionNonce, scopeBlindingNonce)` — unique per request, unlinkable across RSes.
10. **Secret-to-credential binding:** `agentSecretCommitment = Poseidon(agentSecret, credentialCommitment)` constrained internally (not output) to bind the long-lived secret to the enrolled credential, preventing secret reuse across credentials.

### Modified protocol flow (AS-free per-request path)

1. **Enrollment (one-time, AS-involved):** The AS issues a signed credential. The operator signs `credentialCommitment` with EdDSA. The credential commitment is inserted into the on-chain agent Merkle tree. The AS learns the credential exists but the `agentSecret` is generated client-side and never leaves the agent.

2. **Per-RS authorization (AS-free):** The agent generates a `ScopedAgentAuth` proof with the target RS's `rsScopeId`. The RS verifies the proof against the on-chain `agentMerkleRoot` directly. No AS roundtrip occurs.

3. **Sybil detection per RS:** Each RS stores seen `scopeNullifier` values. The same agent re-authenticating to the same RS produces the same `scopeNullifier`, enabling rate-limiting and session continuity within that RS. Different RSes see different nullifiers.

4. **Replay prevention:** The `blindedSessionTag` commits to a fresh `sessionNonce` (supplied by the RS) and a random `scopeBlindingNonce` (chosen by the agent). The RS checks `sessionNonce` freshness. The blinding nonce prevents the RS from testing whether two `blindedSessionTag` values across RSes share a common `scopeNullifier` prefix.

### Delegation extension: `ScopedDelegation`

Extends the existing `Delegation` circuit by replacing `delegationNullifier` with a scope-bound variant:

- `delegateeNullifier = Poseidon(rsScopeId, delegateeSecret)` where `delegateeSecret` is the delegatee agent's long-lived secret.
- Chain linking uses `previousScopeCommitment` as before.
- The delegatee's proof at a specific RS is unlinkable to the delegator's proof at the same or different RS.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary **A** controls:
- The Authorization Server (full compromise: sees all enrollment data, all credential commitments, all Merkle tree insertions)
- Up to *N-1* of *N* Resource Servers (colluding subset)
- Network-level metadata: timing of proof submissions, proof sizes, RS endpoints contacted

The adversary **cannot**:
- Break the knowledge soundness of Groth16/PLONK (generic group model + ROM)
- Invert Poseidon (collision resistance + PRF assumption over BN254 scalar field)
- Solve discrete log on Baby Jubjub
- Compromise the agent's local secret `agentSecret`

### IND-UNL-AS game

**Setup:** Challenger generates two agents (agent₀, agent₁) with valid enrolled credentials. Both satisfy the required scope for all target RSes.

**Phase 1 (adaptive queries):** A may request authorization proofs from either agent to any RS of A's choice. A receives the proof and all public signals.

**Challenge:** A chooses two distinct RSes (RS-A, RS-B) not yet queried in this combination. Challenger flips coin *b* ∈ {0,1}:
- If *b = 0*: agent₀ authenticates to RS-A, agent₁ authenticates to RS-B
- If *b = 1*: agent₀ authenticates to RS-B, agent₁ authenticates to RS-A

A receives both proofs and all public signals.

**Phase 2:** A may make additional adaptive queries (except repeating the challenge RSes with the challenge agents).

**Output:** A outputs bit *b'*. A wins if *b' = b*.

**Definition:** The scheme is **(t, ε)-IND-UNL-AS secure** if for all adversaries running in time *t*:

    |Pr[b' = b] - 1/2| ≤ ε

## 4. Security argument (named assumption + reduction sketch)

**Named assumptions:**
1. **Poseidon PRF (P-PRF):** Poseidon with a secret key input is indistinguishable from a random function. Formally: for secret key *k*, no PPT adversary can distinguish `Poseidon(x, k)` from a random oracle with non-negligible advantage.
2. **Knowledge soundness of Groth16** in the generic group model + ROM (Groth16-KS).
3. **Discrete log hardness on Baby Jubjub** (BJJ-DL).
4. **Poseidon collision resistance** (P-CR).

**Reduction sketch:**

Suppose adversary A breaks IND-UNL-AS with advantage ε. We construct a reduction B that breaks P-PRF:

1. B receives a PRF challenge oracle O(·) that is either `Poseidon(·, k*)` for unknown key `k*` or a random function.

2. B embeds `k*` as the `agentSecret` of one of the challenge agents. For the challenge phase:
   - `scopeNullifier_A = O(rsScopeId_A)` and `scopeNullifier_B = O(rsScopeId_B)`
   - If O is `Poseidon(·, k*)`, these are real scope nullifiers for one agent
   - If O is random, they are independent random values — identical to what a *different* agent would produce

3. B simulates the remaining proof components using Groth16-KS (the simulator can produce valid-looking proofs for the other signals given that Groth16 is zero-knowledge).

4. The `blindedSessionTag = Poseidon(scopeNullifier, sessionNonce, scopeBlindingNonce)` adds an additional layer: even if A could detect correlations in `scopeNullifier`, the random `scopeBlindingNonce` (private input, never revealed) masks it under P-PRF.

5. If A distinguishes challenge proofs with advantage ε, B distinguishes O from random with advantage ≥ ε/2 (standard hybrid argument over the two agents).

**Contradiction:** This violates P-PRF, so ε must be negligible.

**Timing side channel mitigation (non-cryptographic):** The construction does not cryptographically prevent timing analysis. Deployment-level mitigation requires fixed-interval proof batching (see §7). The formal game above considers computational indistinguishability of proof transcripts, not network timing.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Source |
|---|---|---|
| Scope nullifier derivation | `Poseidon2(rsScopeId, agentSecret)` | Same pattern as human nullifier `Poseidon2(scope, secret)` in HumanUniqueness |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permBitmask, expiry)` | Existing AgentPolicy circuit |
| EdDSA signature verification | `EdDSAPoseidonVerifier` on Baby Jubjub | Existing AgentPolicy circuit |
| Merkle membership | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Existing infrastructure, depth 20 |
| Scope commitment for delegation | `Poseidon2(permissionBitmask, credentialCommitment)` | Existing Delegation circuit |
| Cumulative bit enforcement | Bit implication constraints on bits 2/3/4 | Existing AgentPolicy + Delegation circuits |
| Blinded session tag | `Poseidon3(scopeNullifier, sessionNonce, scopeBlindingNonce)` | New — uses Poseidon with 3 inputs, supported by circomlib's Poseidon template |
| Agent secret range check | `Num2Bits(251)` | Same pattern as human secret range check in HumanUniqueness |
| On-chain root verification | Root history buffer (30-entry circular) | Existing on-chain registry |

The `agentSecret` pattern mirrors the human `secret` in HumanUniqueness — a Baby Jubjub scalar that never leaves the client, used as a PRF key for nullifier derivation. This is a direct extension of the existing human privacy model to agent identities.

## 6. Circuit cost estimate

| Component | Constraints (approx.) |
|---|---|
| Num2Bits(251) for agentSecret | 251 |
| Num2Bits(64) × 3 (permBitmask, expiry, timestamp) | 192 |
| Poseidon5 (credential commitment) | ~1,500 |
| EdDSAPoseidonVerifier | ~5,000 |
| BinaryMerkleRoot(20) with Poseidon2 | ~30,000 (20 × ~1,500) |
| Scope satisfaction (64-bit AND check) | 128 |
| Cumulative bit encoding | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon2 (scopeNullifier) | ~500 |
| Poseidon3 (blindedSessionTag) | ~750 |
| Poseidon2 (scopeCommitment) | ~500 |
| Poseidon2 (secret-credential binding) | ~500 |
| **Total** | **~39,500** |

This fits within the 2^16 constraint ceiling of `pot16.ptau` (65,536 constraints).

**Proving time targets:**
- PLONK (preferred for agents, no per-circuit ceremony): **< 4s** on commodity hardware (M1/M2 Mac or 4-core x86). PLONK at ~40K constraints benchmarks at 2–3s with snarkjs, under 1s with rapidsnark.
- Groth16 (alternative): **< 2s** with rapidsnark, **< 8s** with snarkjs.

Both are well within the PLONK agent target of < 5s.

## 7. Concrete deployment scenario

### Scenario: Cross-credit-union member agent

**Stakeholder:** A state-chartered credit union consortium (e.g., California Credit Union League, 140+ member CUs) where each CU operates as both an AS (issuing member credentials) and an RS (accepting payment/account queries).

**Problem:** Member Alice uses an AI agent to negotiate auto loan rates across CU-A, CU-B, and CU-C. Her home CU (CU-A) issued her agent's credential. Under OAuth/OIDC, CU-A's AS sees every token request — learning that Alice is rate-shopping CU-B and CU-C. CU-A could use this to preemptively match rates, discriminate on pricing, or sell the merchant graph to affiliates.

**Deployment:**

1. **Enrollment:** CU-A (as AS) issues Alice's agent credential. The operator (CU-A) signs the `credentialCommitment` with EdDSA. The commitment is inserted into the on-chain agent Merkle tree on Base Sepolia. Alice's agent generates `agentSecret` locally — CU-A never sees it.

2. **Rate query to CU-B:** Alice's agent generates a `ScopedAgentAuth` proof with `rsScopeId = Poseidon("cu-b.example.com")`, `requiredScopeMask = 0x05` (READ_DATA + FINANCIAL_SMALL). CU-B verifies the proof against the on-chain root. CU-B sees `scopeNullifier_B` — it knows this is a valid enrolled agent, can rate-limit, but cannot link to CU-A's records.

3. **Rate query to CU-C:** Same agent generates a proof with `rsScopeId = Poseidon("cu-c.example.com")`. CU-C sees `scopeNullifier_C ≠ scopeNullifier_B`. Even if CU-B and CU-C collude, they cannot determine these came from the same agent (IND-UNL-AS security).

4. **CU-A (adversarial AS) sees nothing:** No token issuance request occurs. CU-A sees the initial enrollment and the on-chain Merkle tree update (shared among all agents) but has no per-RS signal to correlate.

5. **Timing mitigation:** The consortium operates a batching relay that collects proof submissions from agents in 30-second windows and submits them in randomized order. This is a deployment-layer defense against network timing analysis — the cryptographic construction provides indistinguishability of proof *content*; the relay provides indistinguishability of proof *timing*.

6. **Sybil control:** Each CU (as RS) stores `scopeNullifier` values. If Alice's agent authenticates to CU-B twice, CU-B sees the same `scopeNullifier_B` and can enforce session continuity or rate limits. But CU-B cannot determine whether this agent also contacted CU-C.

### Healthcare variant

**Stakeholder:** A regional health information exchange (HIE) operating under HIPAA.

Alice's primary care physician (PCP) delegates her agent to request specialist referral records from three hospitals. Each hospital is an RS; the PCP's credential system is the AS. Under the existing `ScopedDelegation` extension, each delegation hop produces a scope-bound nullifier tied to the target hospital's `rsScopeId`. The PCP (AS) cannot reconstruct which hospitals the agent contacted, preserving referral network privacy — a HIPAA minimum-necessary principle alignment.

## 8. Why the baseline cannot match

The baseline (PPID + RFC 8707 + DPoP + BBS+) fails on four axes that this construction addresses:

**1. AS-layer unlinkability is structurally impossible in OAuth/OIDC.**
Every token in the OAuth stack requires an AS roundtrip at issuance time. The AS observes (agent_id, RS_target, scope, timestamp) for every authorization. PPIDs hide `sub` from RSes but not from the AS — the AS *is* the PPID mapping authority. In this construction, the AS is involved only at enrollment (one-time). Per-RS authorization is a client-side ZK proof verified directly by the RS against the on-chain root. The AS sees zero per-request signals.

**2. Scope-bound nullifiers have no OAuth analog.**
The construction produces `scopeNullifier = Poseidon(rsScopeId, agentSecret)` — a deterministic, scope-specific pseudonym that enables per-RS sybil detection without cross-RS linkability. In OAuth, the closest analog is PPID, but PPIDs are *assigned by the AS* (which knows the mapping). Here, the nullifier is *derived by the agent* from a secret the AS never possesses, and its unlinkability is a consequence of Poseidon PRF security — not an administrative policy.

**3. Colluding RS subsets gain no advantage.**
In the baseline, two RSes that share DPoP `jti` values, token issuance timestamps, or BBS+ issuer public keys can correlate. BBS+ hides *claims* but exposes the issuer key — a colluding AS+RS can trivially self-identify. In this construction, colluding RSes see different `scopeNullifier` values and different `blindedSessionTag` values. The `scopeBlindingNonce` (private, random per proof) prevents even offline brute-force matching of nullifiers across scopes, since the blinded tag is `Poseidon(scopeNullifier, sessionNonce, scopeBlindingNonce)` — a PRF evaluation that the RS cannot invert.

**4. Formal security definition exists.**
The baseline has no formal unlinkability definition. No RFC defines an IND-UNL-AS game. No BBS+ specification proves unlinkability against the issuer — only against verifiers. This construction defines the IND-UNL-AS game (§3), states the reduction to Poseidon PRF (§4), and the reduction is tight (advantage loss of factor 2 from the hybrid argument). The security guarantee is falsifiable: break the construction ⟹ break Poseidon PRF over BN254.

**5. Delegation chains are AS-invisible.**
In RFC 8693 token exchange, every delegation hop requires an AS roundtrip — the AS sees the full chain topology. In this construction, `ScopedDelegation` extends the scope commitment chain with scope-bound nullifiers. The delegatee's proof at any RS is unlinkable to the delegator's proof, and neither proof requires AS involvement. The AS sees one enrollment per agent; the delegation graph is private.

**6. Timing resistance is addressable.**
The baseline leaks token-request timing to the AS by design (DPoP requires fresh `jti` + timestamps at the AS). This construction moves the AS off the per-request path entirely, eliminating the primary timing channel. Residual network-level timing (proof submission to RS) is mitigable via batching relays — a deployment option unavailable in the baseline because the AS *must* be contacted per-request.
