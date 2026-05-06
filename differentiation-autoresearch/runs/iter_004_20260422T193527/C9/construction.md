# Construction

## 1. Statement of claim

If an agent's signing key is compromised at time T, sessions and delegations executed before T remain cryptographically unlinkable and non-replayable. No bearer-token or DPoP-bound OAuth construction achieves this — compromise of the key retroactively reveals the agent's prior activity graph and allows replay.

## 2. Construction (gadgets, circuits, public/private inputs)

### 2.1 Epoch secret evolution via Poseidon hash chain

The agent holds an initial epoch secret `s_0`. At each epoch boundary, the agent derives the next epoch secret and irreversibly deletes the prior:

```
s_{e+1} = Poseidon1(s_e)
```

**Critical:** `s_{e+1}` is a private intermediate value that is NEVER published on-chain or included in any public signal.

### 2.2 Hiding epoch commitment with blinding randomness

At each epoch `e`, the agent samples fresh blinding randomness `r_e ←$ F_p` and computes a **hiding** commitment:

```
epochCommitment_e = Poseidon2(s_e, r_e)
```

The blinding factor `r_e` is destroyed alongside `s_e` at epoch transition. This separates the commitment (public, on-chain) from the derivation chain (private, never published). Without `r_e`, observing `epochCommitment_e` yields no information about `s_e`.

### 2.3 Forward-secure nullifier

```
epochNullifier = Poseidon2(s_e, sessionNonce)
```

Since `s_e` is destroyed after epoch `e`, an adversary who obtains `s_{e+1}` (or any later secret) cannot compute the nullifier — they would need to invert Poseidon.

### 2.4 Circuit: EpochRotation (PLONK)

Proves an epoch transition is valid, linking two hiding commitments via the private Poseidon chain.

**Private inputs:** `s_{e-1}`, `r_{e-1}`, `s_e` (derived), `r_e` (fresh)

**Public inputs:** `previousEpochCommitment`

**Public outputs:** `newEpochCommitment` = `Poseidon2(s_e, r_e)`

**Constraints:**
1. `Poseidon2(s_{e-1}, r_{e-1}) == previousEpochCommitment` (open previous hiding commitment)
2. `Poseidon1(s_{e-1}) == s_e` (chain integrity)
3. `Poseidon2(s_e, r_e) == newEpochCommitment` (new hiding commitment)

**Replay prevention:** The on-chain registry enforces single-use consumption of `previousEpochCommitment` via a mapping `consumedEpochCommitment[hash] → bool`. The registry MUST atomically set `consumedEpochCommitment[previousEpochCommitment] = true` and update `currentEpochCommitment[agentSlot] = newEpochCommitment`. This replaces the removed `epochTransitionNullifier` — chain structure provides replay prevention without exposing a value computable from `s_T`.

**Why `epochTransitionNullifier` was removed:** The prior construction published `epochTransitionNullifier = Poseidon2(s_e, epochIndex)` as a public output. An adversary holding `s_T` could compute `Poseidon2(s_T, T)`, match it against on-chain nullifiers to identify the epoch-T rotation transaction, then follow the `previousEpochCommitment` chain backward to identify all prior epoch commitments. This nullifier was a correlator computable from compromised material alone (no `r_e` needed), making it strictly more dangerous than the hiding commitment. Removing it forces the adversary to know both `s_T` and `r_T` to identify even the current epoch.

**Constraint count:** ~846 (2x Poseidon2 + 1x Poseidon1). Reduced from ~1,200 by removing the nullifier Poseidon2 and Num2Bits(64) on epochIndex.

### 2.5 Circuit: ForwardSecureAgentSession (PLONK)

Extends AgentPolicy with epoch-bound nullifiers and hiding commitments.

**New private inputs:** `s_e`, `r_e`

**New public input:** `epochCommitment` (on-chain hiding commitment)

**Public outputs (changed):** `epochNullifier = Poseidon2(s_e, sessionNonce)` replaces standard nullifier

**Additional constraints:**
1. `Poseidon2(s_e, r_e) == epochCommitment`
2. `epochNullifier == Poseidon2(s_e, sessionNonce)`

**Constraint count:** ~9,828 (AgentPolicy ~9,264 + 2x Poseidon2 ~564)

### 2.6 Circuit: ForwardSecureDelegation (PLONK)

Extends Delegation with epoch-bound delegation nullifiers.

**New private inputs:** `delegator_s_e`, `delegator_r_e`

**New public input:** `delegatorEpochCommitment`

**Additional constraints:**
1. `Poseidon2(delegator_s_e, delegator_r_e) == delegatorEpochCommitment`
2. Epoch-bound delegation nullifier computation

**Constraint count:** ~9,064 (Delegation ~8,500 + ~564)

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary A:
- Obtains `s_T` and credential private key at time T
- May or may not hold `r_T` (the current epoch's blinding factor, still live at compromise time)
- Observes all public transcripts for epochs e ∈ [0, T): epoch nullifiers, scope commitments, **hiding** epoch commitments `Poseidon2(s_e, r_e)`, Merkle roots, PLONK proofs
- Has full on-chain registry read access including archive node history
- Does NOT have deleted epoch secrets `s_e` for e < T or blinding factors `r_e` for e < T (secure deletion assumption)
- Does NOT have the PLONK SRS trapdoor

### Elimination of the epochTransitionNullifier correlator

The prior construction exposed `epochTransitionNullifier = Poseidon2(s_e, epochIndex)` as a public output of EpochRotation. This was fatally flawed: the adversary with `s_T` could compute `Poseidon2(s_T, T)` — requiring NO blinding factor — and match it on-chain. This identified the epoch-T rotation transaction, whose `previousEpochCommitment` field pointed to epoch T-1's commitment, enabling full backward chain traversal and linking all sessions across all epochs to the compromised agent.

The corrected construction removes this public output entirely. The adversary now requires BOTH `s_T` AND `r_T` to compute `epochCommitment_T = Poseidon2(s_T, r_T)` and identify the current epoch. This is a strictly weaker adversary position: `r_T` is independently sampled randomness that may or may not survive in memory at compromise time, whereas `epochIndex` was a public integer requiring zero additional knowledge.

### Residual: chain traversal via previousEpochCommitment linkage

If the adversary obtains both `(s_T, r_T)`, they can compute `epochCommitment_T` and identify the current epoch's on-chain commitment. The EpochRotation proof's `previousEpochCommitment` public input then reveals epoch T-1's commitment value, and archive node analysis can trace this chain backward.

This is a **weaker** linkage than the nullifier-based attack in three respects:
1. It requires `r_T` in addition to `s_T` (the nullifier required only `s_T`)
2. It is **mitigable by registry design**: the registry SHOULD overwrite `currentEpochCommitment` in-place and rotation transactions SHOULD be submitted via a relayer (standard ZK pattern, as in Tornado Cash); this forces the adversary to perform archive-node archaeology rather than simple on-chain scanning
3. It reveals only the epoch commitment *values*, not the session secrets within those epochs; session nullifiers `Poseidon2(s_e, nonce)` remain pseudorandom without `s_e`

**Honest limitation:** If the adversary recovers `(s_T, r_T)` AND has archive node access AND `epochCommitment` appears as a public input in session proofs, the adversary can correlate sessions to epochs and thus to the agent. Full mitigation of this residual would require an anonymity-set construction (epoch commitment membership in a Merkle tree of all active agents' commitments, verified inside the session proof) — a structural change deferred to a future iteration. The claim holds to the degree that `r_T` is destroyed before compromise or the relayer prevents chain identification.

### Game: IND-FS-AGENT (Linkability)

1. **Setup.** Challenger enrolls agent with `s_0`. Agent executes sessions across epochs 0..T-1.
2. **Compromise.** At T, adversary receives `s_T` and all credential key material. Adversary does NOT receive `r_T` (modeling immediate rotation or secure enclave isolation of blinding factors).
3. **Challenge.** Challenger picks e* < T, two transcripts from e*, flips b, gives τ_b.
4. **Goal.** Adversary outputs b'.
5. **Advantage.** `Adv[A] = |Pr[b'=b] - 1/2|`.

**Claim:** `Adv[A] ≤ negl(λ)` under A1–A5.

**Note on r_T exclusion from compromise:** The game models the security boundary at the epoch secret, not at runtime memory. If the adversary also obtains `r_T`, the claim degrades to requiring relayer-mediated rotation transactions (operational mitigation) rather than a pure cryptographic guarantee. The construction is strictly stronger than the baseline in either case, since the baseline leaks the full activity graph from key compromise alone with no blinding factor defense.

### Game: FS-REPLAY (Non-replayability)

1. **Setup/Compromise.** Same as above.
2. **Goal.** Adversary produces valid proof π* accepted by verifier for nonce used in epoch e* < T.

**Claim:** `Adv[A] ≤ negl(λ)` under A1–A5.

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **(A1) Poseidon preimage resistance.** Given `y = Poseidon1(x)`, finding `x` is hard. Load-bearing for forward secrecy.
- **(A2) Poseidon PRF security.** `Poseidon2(k, ·)` is indistinguishable from random when `k` is secret. Ensures epoch nullifiers are unlinkable.
- **(A3) PLONK knowledge soundness (AGM+ROM).** Valid proof implies known witness.
- **(A4) DL hardness on Baby Jubjub.** EdDSA is EUF-CMA.
- **(A5) Poseidon hiding under blinding.** `Poseidon2(s, r)` with uniform unknown `r` is indistinguishable from random. Follows from A2. Ensures on-chain epoch commitments leak nothing about `s_e`.

### Reduction: IND-FS-AGENT

**Case 1 (nullifier linkage).** τ_b contains `Poseidon2(s_{e*}, nonce)`. Adversary has `s_T` but not `s_{e*}`. Recovering `s_{e*}` breaks A1; distinguishing the nullifier from random breaks A2.

**Case 2 (epoch commitment linkage).** On-chain `epochCommitment_e = Poseidon2(s_e, r_e)` is visible. Adversary lacks both `s_e` (A1) and `r_e` (deleted). By A5, the commitment is indistinguishable from random — adversary cannot verify which commitments belong to the compromised chain. **The removed `epochTransitionNullifier` was the critical gap**: it was `Poseidon2(s_e, epochIndex)` with `epochIndex` public, meaning the adversary could compute it from `s_T` forward-derived values and match against on-chain data. With the nullifier removed, no public output of EpochRotation is computable from `s_T` alone — both outputs (`newEpochCommitment`) require the independently-sampled, destroyed `r_e`.

**Case 3 (scope commitment).** Reveals only policy (public input), not per-session identity.

**Case 4 (PLONK proof).** Zero-knowledge simulator exists in ROM.

**Case 5 (chain traversal without nullifier).** Without the `epochTransitionNullifier`, the adversary must identify `epochCommitment_T` to enter the chain. This requires `r_T` (excluded from compromise in the game definition). Even if `r_T` were available, backward traversal reveals only opaque commitments `epochCommitment_e` for e < T, each of which is hiding (A5). Linking sessions requires matching `epochCommitment` public inputs in session proofs, which — under the game's r_T exclusion — the adversary cannot initiate.

### Reduction: FS-REPLAY

By A3, valid proof requires witness `(s_{e*}, r_{e*})` opening `epochCommitment_{e*}`. Recovering `s_{e*}` from `s_T` breaks A1. Finding alternative `(s', r')` opening the same commitment breaks collision resistance.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| `s_{e+1} = Poseidon1(s_e)` | Poseidon (BN128) | §2: Crypto Primitives |
| `epochCommitment_e = Poseidon2(s_e, r_e)` | Poseidon (BN128) | §2: Crypto Primitives |
| `epochNullifier = Poseidon2(s_e, nonce)` | Nullifier pattern | §2: Terminology |
| Credential commitment | Poseidon5 | §4.2: Agent Circuit |
| Scope commitment | Poseidon2 | §2: Terminology |
| Operator signature | EdDSA/BabyJubjub | §2: Crypto Primitives |
| Merkle membership | LIMT depth 20 | §2: Crypto Primitives |
| All agent/delegation proofs | PLONK universal | §2.1: Proving Systems |
| Permission subset | Bitwise AND constraint | §5.2: Delegation |
| Delegation token | Poseidon4 | §5.2: Delegation |
| Replay prevention (EpochRotation) | On-chain consumption map | §3: On-Chain Registry |

No external primitives. `r_e` is a standard field element — no new primitive required. The removed `epochTransitionNullifier` eliminates one Poseidon2 computation and the `epochIndex` public input, simplifying the construction.

## 6. Circuit cost estimate

| Circuit | Constraints | System | Proving time |
|---|---|---|---|
| EpochRotation | ~846 | PLONK | <1s |
| ForwardSecureAgentSession | ~9,828 | PLONK | <5s |
| ForwardSecureDelegation | ~9,064 | PLONK | <5s |

**EpochRotation breakdown (revised):** 2x Poseidon2 (~564) + 1x Poseidon1 (~282) = ~846. Reduced from ~1,200 by removing the `epochTransitionNullifier` Poseidon2 (~282) and `Num2Bits(64)` on epochIndex (~33). The circuit is 30% smaller with a stronger security profile — fewer public outputs means a smaller attack surface.

**ForwardSecureAgentSession overhead:** 2x Poseidon2 (~564) over AgentPolicy base (~9,264) = 6.1% overhead. Unchanged from prior construction.

## 7. Concrete deployment scenario

### SECU 30-day autonomous lending agent

State Employees' Credit Union deploys a Claude agent for 30-day loan processing. Daily epoch rotation: agent samples `r_e`, publishes `Poseidon2(s_e, r_e)` via EpochRotation proof, deletes `(s_{e-1}, r_{e-1})`.

Day 31: key leak exposes `(s_{30})`. **With the nullifier removed**, the attacker cannot compute any value that matches an on-chain public output — `epochCommitment_{30} = Poseidon2(s_{30}, r_{30})` requires `r_{30}`, which was either destroyed at the epoch-30→31 transition or isolated in a secure enclave. The attacker has no entry point into the commitment chain. The 30 on-chain commitments `Poseidon2(s_e, r_e)` are indistinguishable from those of every other enrolled agent.

Contrast with the prior construction: the attacker would have computed `Poseidon2(s_{30}, 30)`, matched it on-chain, and walked the `previousEpochCommitment` chain backward through all 30 days.

### CFPB whistleblower relay agent

Informant's agent relays evidence over 12 weekly epochs. Seizure reveals only the current epoch secret. Without the `epochTransitionNullifier`, the seized `s_T` alone cannot identify any on-chain rotation transaction. The 12 hiding commitments are opaque, and the agent's activity is buried in the anonymity set of all agents using the registry.

## 8. Why the baseline cannot match

### 8.1 DPoP ephemeral keys don't achieve unlinkability

AS logs `sub + jkt` per session. Even with per-session ephemeral keys, adversary with AS access reconstructs full timeline. OIDC PPIDs don't help at the AS or within a single RP. Bolyra's epoch nullifier has no `sub`/`client_id`/`jkt` — correlating nullifiers breaks A2.

### 8.2 WIMSE delegation chains leak structural metadata

SPIFFE IDs are stable; SVID certificate chains contain issuer DNs in plaintext. Delegation graph is structural and key-independent. Bolyra's delegation linking is inside the ZK proof only.

### 8.3 Operational deletion ≠ cryptographic guarantee

No proof of deletion exists in any RFC. Memory forensics can recover "deleted" keys. Bolyra's security is a property of Poseidon preimage resistance + hiding commitments, not runtime hygiene. The removal of `epochTransitionNullifier` strengthens this: even if the adversary recovers `s_T` via memory forensics, they cannot identify the agent's chain without ALSO recovering `r_T` — two independent values must both survive forensic recovery, versus one in the prior construction.

### 8.4 IND-FS-AGENT requires hiding commitments with no computable correlators

The game requires that no public output be computable from compromised key material alone. The baseline fails this trivially: `jkt = SHA-256(JWK)` is deterministic from the key. The prior Bolyra construction also failed this via `epochTransitionNullifier = Poseidon2(s_e, epochIndex)`, which was computable from `s_T` + public epoch index. The corrected construction ensures every public output of EpochRotation depends on independently-sampled, destroyed blinding randomness `r_e` — no public signal is derivable from `s_T` alone. The baseline has no analog of blinding randomness in any RFC.
