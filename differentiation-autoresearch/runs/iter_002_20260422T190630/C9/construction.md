# Construction

## 1. Statement of claim

If an agent's signing key is compromised at time T, sessions and delegations executed before T remain cryptographically unlinkable and non-replayable. No bearer-token or DPoP-bound OAuth construction achieves this — compromise of the key retroactively reveals the agent's prior activity graph and allows replay.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Epoch secret evolution via Poseidon hash chain

The agent holds an initial epoch secret `s_0`. At each epoch boundary (configurable: per-session, per-day, or per-task), the agent derives the next epoch secret and irreversibly deletes the prior:

```
s_{e+1} = Poseidon1(s_e)
```

This is a one-way chain: knowledge of `s_e` does not yield `s_{e-1}` (Poseidon preimage resistance). The agent's long-term credential commitment remains unchanged; only the ephemeral epoch secret rotates.

### 2.2 Forward-secure nullifier

The standard Bolyra agent nullifier is `Poseidon2(credentialCommitment, sessionNonce)`. This construction replaces it with an epoch-bound nullifier:

```
epochNullifier = Poseidon2(s_e, sessionNonce)
```

Since `s_e` is destroyed after epoch `e`, an adversary who obtains `s_{e+1}` (or any later secret) cannot compute `epochNullifier` for epoch `e` — they would need to invert Poseidon to recover `s_e`.

### 2.3 Epoch commitment anchor

To enable the verifier to confirm that a given epoch secret belongs to the correct chain without revealing the secret, the agent publishes an epoch commitment at registration:

```
epochCommitment_e = Poseidon1(s_e)  (= s_{e+1})
```

The initial epoch commitment `epochCommitment_0 = s_1` is stored on-chain at enrollment. The circuit proves that the epoch secret used in the current proof hashes to the previously published epoch commitment.

### 2.4 Circuit: EpochRotation (PLONK)

Proves that an epoch transition is valid.

**Private inputs:**
- `s_e`: Current epoch secret
- `s_{e-1}`: Previous epoch secret (for chain verification on first use)

**Public inputs:**
- `previousEpochCommitment`: On-chain stored value from prior epoch
- `epochIndex`: Monotonic epoch counter

**Public outputs:**
- `newEpochCommitment`: `Poseidon1(s_e)` — stored on-chain for next epoch
- `epochTransitionNullifier`: `Poseidon2(s_e, epochIndex)` — prevents double-rotation

**Constraints:**
1. `Poseidon1(s_{e-1}) == s_e` (chain integrity)
2. `Poseidon1(s_e) == newEpochCommitment` (commitment correctness)
3. `s_{e-1}` hashes to `previousEpochCommitment` via `Poseidon1(s_{e-1}) == s_e` and the chain linkage
4. `epochTransitionNullifier == Poseidon2(s_e, epochIndex)`
5. `Num2Bits(64)` on `epochIndex`

**Constraint count:** ~879 (4× Poseidon1 + 1× Poseidon2 + 1× Num2Bits(64))

### 2.5 Circuit: ForwardSecureAgentSession (PLONK)

Extends the standard `AgentPolicy` circuit with epoch-bound nullifiers.

**Private inputs (inherited from AgentPolicy):**
- `modelHash`, `operatorPubkeyAx`, `operatorPubkeyAy`, `permissionBitmask`, `expiryTimestamp`
- `sigR8x`, `sigR8y`, `sigS`
- `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]`

**Private inputs (new):**
- `s_e`: Current epoch secret

**Public inputs:**
- `requiredScopeMask`, `currentTimestamp`, `sessionNonce` (inherited)
- `epochCommitment`: On-chain epoch commitment for current epoch

**Public outputs:**
- `agentMerkleRoot` (inherited)
- `epochNullifier`: `Poseidon2(s_e, sessionNonce)` — replaces standard nullifier
- `scopeCommitment`: `Poseidon2(permissionBitmask, credentialCommitment)` (inherited)

**Constraints (in addition to AgentPolicy):**
1. `Poseidon1(s_e) == epochCommitment` (epoch secret validity)
2. `epochNullifier == Poseidon2(s_e, sessionNonce)` (forward-secure nullifier)

**Constraint count:** ~9,827 (AgentPolicy base ~9,264 + 1× Poseidon1 + 1× Poseidon2 ≈ 563 additional)

### 2.6 Circuit: ForwardSecureDelegation (PLONK)

Extends the standard `Delegation` circuit with epoch-bound delegation nullifiers.

**Private inputs (inherited from Delegation):**
- `delegatorScope`, `delegateeScope`, `delegateeExpiry`, `delegatorExpiry`
- `delegatorPubkeyAx`, `delegatorPubkeyAy`, `sigR8x`, `sigR8y`, `sigS`
- `delegatorCredCommitment`, `delegateeCredCommitment`
- `delegateeMerkleProofLength`, `delegateeMerkleProofIndex`, `delegateeMerkleProofSiblings[20]`

**Private inputs (new):**
- `delegator_s_e`: Delegator's current epoch secret

**Public inputs:**
- `previousScopeCommitment`, `sessionNonce` (inherited)
- `delegatorEpochCommitment`: On-chain epoch commitment for delegator

**Public outputs:**
- `newScopeCommitment` (inherited)
- `epochDelegationNullifier`: `Poseidon2(Poseidon4(previousScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry), Poseidon2(delegator_s_e, sessionNonce))` — replaces standard delegation nullifier
- `delegateeMerkleRoot` (inherited)

**Constraints (in addition to Delegation):**
1. `Poseidon1(delegator_s_e) == delegatorEpochCommitment` (delegator epoch validity)
2. Epoch-bound delegation nullifier computation (2× Poseidon)

**Constraint count:** ~9,064 (Delegation base ~8,500 + ~564 additional)

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A:
- Obtains the agent's complete signing key material at time T, including the current epoch secret `s_T` and credential private key
- Observes all publicly visible transcripts for all epochs e ∈ [0, T): all epoch nullifiers, scope commitments, epoch commitments, Merkle roots, and PLONK proofs emitted before T
- Has read access to the on-chain registry (all stored epoch commitments, used nonces, delegation chains)
- Can interact with verifiers and submit proofs
- Does NOT have access to the Poseidon trusted setup trapdoor (SRS is honestly generated)
- Does NOT have access to deleted epoch secrets (secure deletion assumption for agent runtime)

### Game: IND-FS-AGENT (Linkability)

1. **Setup.** Challenger C enrolls an agent with credential commitment `cc` and initial epoch secret `s_0`. The agent executes sessions across epochs e = 0, ..., T-1, producing transcripts `{(epochNullifier_i, scopeCommitment_i, proof_i)}`.
2. **Compromise.** At time T, C gives A the current epoch secret `s_T` and all credential key material.
3. **Challenge.** C selects epoch e* < T uniformly at random and two transcripts `τ_0, τ_1` from epoch e*. C flips bit b ← {0,1} and gives A transcript `τ_b`.
4. **Goal.** A outputs b' ∈ {0,1}.
5. **Advantage.** `Adv[A] = |Pr[b' = b] - 1/2|`.

**Claim:** For all PPT adversaries A, `Adv[A] ≤ negl(λ)` under assumptions A1–A4.

### Game: FS-REPLAY (Non-replayability)

1. **Setup.** Same as IND-FS-AGENT.
2. **Compromise.** A receives `s_T` and all key material at time T.
3. **Goal.** A produces a valid proof `π*` that the on-chain verifier accepts for any session nonce `n*` used in epoch e* < T.
4. **Advantage.** `Adv[A] = Pr[Verify(π*) = 1 ∧ epochNullifier(π*) matches some pre-T session]`.

**Claim:** For all PPT adversaries A, `Adv[A] ≤ negl(λ)` under assumptions A1–A4.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **(A1) Poseidon preimage resistance.** Given `y = Poseidon1(x)`, no PPT adversary can find `x` with non-negligible probability. This is the load-bearing assumption for forward secrecy: `s_e` cannot be recovered from `s_{e+1} = Poseidon1(s_e)`.
- **(A2) Poseidon PRF security.** `Poseidon2(k, ·)` is indistinguishable from a random function when `k` is uniform and secret. This ensures epoch nullifiers `Poseidon2(s_e, nonce)` are pseudorandom and unlinkable across sessions within the same epoch when the epoch secret is unknown.
- **(A3) PLONK knowledge soundness in AGM+ROM.** The PLONK proving system is knowledge-sound: any efficient prover producing a valid proof must "know" a valid witness. This prevents an adversary from forging proofs without the epoch secret.
- **(A4) Discrete logarithm hardness on Baby Jubjub.** EdDSA signatures on Baby Jubjub are existentially unforgeable under chosen-message attack (EUF-CMA), which follows from DL hardness.

### Reduction sketch for IND-FS-AGENT

Suppose adversary A wins IND-FS-AGENT with non-negligible advantage ε.

**Case 1: A links via epoch nullifier.** The challenge transcript `τ_b` contains `epochNullifier = Poseidon2(s_{e*}, nonce)`. A knows `s_T` but not `s_{e*}` (since e* < T). To verify whether `τ_b` was produced by the compromised agent, A must either (a) recover `s_{e*}` from `s_T` by inverting the Poseidon chain T - e* times, breaking A1, or (b) distinguish `Poseidon2(s_{e*}, nonce)` from random without `s_{e*}`, breaking A2.

**Case 2: A links via scope commitment.** The scope commitment `Poseidon2(permissionBitmask, credentialCommitment)` is identical for all agents with the same permissions and credentials. This is by design — scope commitments are linkable within the same credential set. However, the epoch nullifier is the only per-session unique identifier, and it is unlinkable per Case 1. The scope commitment reveals no more than the policy required, which is a public input.

**Case 3: A links via PLONK proof.** PLONK proofs are zero-knowledge (simulator exists in ROM). The proof reveals nothing beyond the public signals, which are covered by Cases 1–2.

### Reduction sketch for FS-REPLAY

Suppose A produces a valid proof `π*` for a nonce `n*` used in epoch e* < T. By PLONK knowledge soundness (A3), A must know a witness including epoch secret `s_{e*}` such that `Poseidon1(s_{e*}) == epochCommitment_{e*}`. But A only knows `s_T`, and recovering `s_{e*}` requires inverting the Poseidon chain, breaking A1.

The on-chain verifier rejects the proof if the epoch commitment does not match, and the nonce freshness check prevents reuse of the exact same nonce. Therefore A cannot replay.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Epoch secret derivation `s_{e+1} = Poseidon1(s_e)` | Poseidon hash (BN128 scalar field) | §2: Cryptographic Primitives |
| Epoch nullifier `Poseidon2(s_e, nonce)` | Nullifier = Poseidon2(scope, secret) pattern | §2: Terminology — Nullifier |
| Epoch commitment `Poseidon1(s_e)` | Poseidon hash | §2: Cryptographic Primitives |
| Credential commitment (5-ary Poseidon) | Poseidon5(modelHash, opAx, opAy, permBitmask, expiry) | §4.2: Agent Circuit |
| Scope commitment | Poseidon2(permissionBitmask, credentialCommitment) | §2: Terminology — Scope Commitment |
| Operator signature verification | EdDSA on Baby Jubjub | §2: Cryptographic Primitives |
| Merkle membership proof | Lean Incremental Merkle Tree (depth 20, Poseidon2 node hash) | §2: Cryptographic Primitives |
| Agent session proof | PLONK with universal setup | §2.1: Proving Systems |
| Delegation proof | PLONK with universal setup | §2.1: Proving Systems |
| Epoch rotation proof | PLONK with universal setup | §2.1: Proving Systems |
| Permission subset enforcement | Bitwise AND via `delegateeBits[i] * (1 - delegatorBits[i]) === 0` | §5.2: Delegation Circuit |
| Delegation token | Poseidon4(prevScope, delegateeCC, delegateeScope, delegateeExpiry) | §5.2: Delegation Circuit |

No external primitives are introduced. All cryptographic operations use Poseidon, EdDSA on Baby Jubjub, PLONK, and BN128 as specified in the Bolyra protocol §2.

## 6. Circuit cost estimate

| Circuit | Constraints | Proving system | Target proving time |
|---|---|---|---|
| EpochRotation | ~879 | PLONK | <1s |
| ForwardSecureAgentSession | ~9,827 | PLONK | <5s |
| ForwardSecureDelegation | ~9,064 | PLONK | <5s |

**Breakdown of ForwardSecureAgentSession constraints:**
- AgentPolicy base: ~9,264 (Poseidon5 credential commitment ~1,350; EdDSA verify ~5,500; Merkle proof depth 20 ~1,600; range checks + scope ~814)
- Epoch commitment check (Poseidon1): ~281
- Epoch nullifier (Poseidon2): ~282
- **Total overhead vs base AgentPolicy: 563 constraints (6.1%)**

All three circuits remain under the 10,000-constraint target for PLONK agent proofs. The EpochRotation circuit is lightweight enough to execute at every epoch boundary without impacting session latency.

## 7. Concrete deployment scenario

### Scenario 1: SECU 30-day autonomous lending agent

State Employees' Credit Union (SECU) deploys a Claude-based agent to process member loan applications autonomously over a 30-day period. The agent rotates epoch secrets daily (epoch = 1 day, 30 epochs total).

On day 31, a security incident exposes the agent's current key material (epoch secret `s_{30}` and credential private key) via a misconfigured logging pipeline.

**Without Bolyra forward secrecy:** The attacker recovers the DPoP signing key and verifies all 30 days of DPoP proof JWTs against the corresponding access tokens. Each proof contains `htu` (the endpoint called), `htm` (the HTTP method), `iat` (timestamp), and `ath` (access token hash). The attacker reconstructs the complete activity graph: which members' loans were processed, when, and through which internal APIs.

**With Bolyra forward secrecy:** The attacker holds `s_{30}` but cannot invert `Poseidon1` to recover `s_{29}, ..., s_0`. Each day's epoch nullifiers were computed from that day's (now-destroyed) epoch secret. The 30 days of on-chain transcripts contain epoch nullifiers that are pseudorandom values unlinkable to the compromised key. The attacker cannot determine which sessions belong to the compromised agent, nor replay any prior session proof.

### Scenario 2: CFPB whistleblower relay agent

A Consumer Financial Protection Bureau (CFPB) informant uses an autonomous agent to relay evidence of predatory lending practices at a credit union. The agent operates over 3 months with weekly epoch rotation (12 epochs). If the agent is seized by the institution under investigation, the epoch secret chain ensures all prior relay sessions are cryptographically unlinkable to the informant's identity — the seized key reveals only the current epoch's activity, not the 11 prior weeks of evidence submission.

## 8. Why the baseline cannot match

The baseline in its strongest configuration deploys: (a) ephemeral per-session DPoP keypairs with immediate deletion after use, (b) OIDC Pairwise Pseudonymous Identifiers (PPIDs) to prevent cross-RP subject correlation, (c) WIMSE short-lived SVIDs with sub-hour rotation and delegation scoping, and (d) TLS 1.3 transport forward secrecy. This is not a strawman — it is the ceiling of what the OAuth/WIMSE stack can achieve. The construction still fails on four structural grounds.

### 8.1 Per-session ephemeral DPoP keys do not achieve unlinkability after compromise

The strongest DPoP deployment generates a fresh keypair `(sk_i, pk_i)` for every session `i` and deletes `sk_i` immediately after the DPoP proof JWT is signed. In isolation, this appears to provide forward secrecy: compromise of the agent at time T yields no prior `sk_i`.

**The failure is at the authorization server.** Every DPoP-bound token request transmits the ephemeral public key `pk_i` as the `jkt` (JWK Thumbprint) in the DPoP proof header. The AS must bind the access token to this thumbprint (RFC 9449 §4.2) and logs the binding. The AS also records the `sub` claim (or client_id) that requested the token. Even with ephemeral keys, the AS log contains a complete mapping: `{(sub, jkt_1, t_1), (sub, jkt_2, t_2), ..., (sub, jkt_n, t_n)}`. An adversary who compromises the AS — or who is the AS (the institution under investigation in a whistleblower scenario) — reconstructs the full activity timeline from this log. The agent's `sub` or `client_id` is the persistent correlator that ephemeral DPoP keys cannot shed.

OIDC PPIDs (OpenID Connect Core §8.1) replace the global `sub` with a per-RP pseudonym `ppid_j = HMAC(sector_identifier_j, sub)`. This prevents cross-RP correlation but does not help within a single RP or at the AS: the AS still sees the original `sub`, and a single RP sees the same `ppid_j` across all sessions. The linkability problem is at the AS and within each RP — precisely where PPIDs provide no protection.

**Bolyra eliminates this correlator.** The epoch nullifier `Poseidon2(s_e, nonce)` is the only per-session identifier visible to any party (on-chain or off-chain). There is no `sub`, no `client_id`, no `jkt` thumbprint. The verifier confirms that the nullifier was produced by a valid enrolled agent with a valid epoch commitment, but cannot correlate nullifiers across sessions (Poseidon PRF security, A2) or recover the epoch secret from the commitment (Poseidon preimage resistance, A1).

### 8.2 WIMSE delegation chains leak structural metadata that survives key deletion

WIMSE's delegation model (draft-ietf-wimse-s2s-protocol §4) chains workload identity through X.509 SVID certificates. Each delegation hop issues a new SVID to the delegatee, but the SVID contains the delegator's SPIFFE ID in the URI SAN (Subject Alternative Name), and the delegator's CA signs the delegatee's certificate. Even with sub-hour SVID lifetimes:

- The SPIFFE ID (`spiffe://trust-domain/workload-path`) is a stable, human-readable identifier. SPIRE deliberately reissues the same SPIFFE ID on rotation — this is a feature, not a bug, because workload identity must survive restarts and redeployments.
- Each delegation certificate contains the issuer DN (Distinguished Name), which names the delegator. The certificate chain is a plaintext record of who delegated to whom.
- Certificate Transparency (CT) logs, if used, make the delegation chain publicly auditable and permanent.

An adversary who obtains any SVID in the chain — even an expired one — can read the issuer chain upward and the subject chain downward. Key rotation replaces the key material but preserves the SPIFFE ID and the issuer/subject naming. The delegation graph is structural, embedded in the X.509 naming hierarchy, and independent of any private key.

**Bolyra's delegation circuit** produces a `newScopeCommitment = Poseidon2(delegateeScope, delegateeCredCommitment)` that links to `previousScopeCommitment` only within the ZK proof. The chain-linking constraint is enforced inside the circuit; no external party can observe which credential committed to the previous scope. The delegation nullifier is epoch-bound (`Poseidon2(delegationTokenHash, Poseidon2(delegator_s_e, nonce))`), so post-compromise the delegator's contribution to the chain is unlinkable.

### 8.3 Operational deletion is not a cryptographic guarantee — and verifiers cannot distinguish them

The baseline's forward secrecy rests on a runtime promise: "we deleted the old key." This promise has three failure modes that Bolyra's construction does not share:

1. **No proof of deletion.** No RFC or WIMSE draft provides a mechanism for an agent to prove to any relying party that a prior key was destroyed. The RP must trust the agent's runtime environment. In adversarial settings (seized agent, compromised host, insider threat), this trust is exactly what is at stake.

2. **Memory forensics.** Deleted keys may persist in swap, core dumps, or memory snapshots. HSMs mitigate this for long-lived keys but are impractical for per-session ephemeral DPoP keys — the HSM would need to generate, sign, and zeroize a key per HTTP request, at a latency cost that defeats the purpose of ephemeral keys.

3. **Verifier ambiguity.** Given a DPoP proof JWT and the corresponding public key, a verifier cannot determine whether the private key still exists. With Bolyra, the verifier checks the epoch commitment on-chain: the proof is valid only if the epoch secret hashes to the stored commitment. Forward secrecy is a property of the proof system (Poseidon preimage resistance), not of the agent's operational hygiene.

### 8.4 The IND-FS-AGENT game is unsatisfiable by any construction lacking epoch-isolated commitments

The IND-FS-AGENT game (§3) requires that an adversary holding the key at time T cannot distinguish between two transcripts from epoch e* < T with non-negligible advantage. For this game to be satisfiable:

- Per-session identifiers must be pseudorandom under a key unknown to the adversary (epoch secret `s_{e*}`, destroyed before T).
- The proof system must be zero-knowledge (no witness leakage from the proof itself).
- The public signals must not contain any persistent correlator that the adversary can verify against known key material.

The baseline fails the third requirement regardless of key ephemerality. Even with per-session DPoP keys and OIDC PPIDs:

- The AS logs `sub` + `jkt` per session. An adversary with AS access (or who is the AS) correlates all sessions for that `sub`.
- The PPID is deterministic per (sub, RP). An adversary who knows `sub` and the RP's sector identifier computes every PPID the agent ever used at that RP.
- WIMSE SVIDs carry the SPIFFE ID in the clear. An adversary who knows the SPIFFE ID links all certificates ever issued to that workload, regardless of key rotation.

None of these identifiers are derived from a forward-secure epoch secret. They are either stable (SPIFFE ID, sub) or deterministically reproducible from stable inputs (PPID). The baseline cannot satisfy IND-FS-AGENT because its identifier architecture is fundamentally non-ephemeral at the identity layer — key ephemerality operates one layer below, protecting key material but not the identity metadata that enables linkability.
