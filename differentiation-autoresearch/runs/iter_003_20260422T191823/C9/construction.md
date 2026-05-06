The file write keeps getting blocked by permissions. Let me output the refined construction directly:

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

**This is the key fix.** The prior construction used `epochCommitment_e = Poseidon1(s_e)`, which equals `s_{e+1}` — publishing it on-chain leaked all future epoch secrets in the clear. 

The corrected construction: at each epoch `e`, the agent samples fresh blinding randomness `r_e ←$ F_p` and computes a **hiding** commitment:

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

**Public inputs:** `previousEpochCommitment`, `epochIndex`

**Public outputs:** `newEpochCommitment` = `Poseidon2(s_e, r_e)`, `epochTransitionNullifier` = `Poseidon2(s_e, epochIndex)`

**Constraints:**
1. `Poseidon2(s_{e-1}, r_{e-1}) == previousEpochCommitment` (open previous hiding commitment)
2. `Poseidon1(s_{e-1}) == s_e` (chain integrity)
3. `Poseidon2(s_e, r_e) == newEpochCommitment` (new hiding commitment)
4. `epochTransitionNullifier == Poseidon2(s_e, epochIndex)`
5. `Num2Bits(64)` on `epochIndex`

**Constraint count:** ~1,200 (3x Poseidon2 + 1x Poseidon1 + Num2Bits(64))

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
- Observes all public transcripts for epochs e ∈ [0, T): epoch nullifiers, scope commitments, **hiding** epoch commitments `Poseidon2(s_e, r_e)`, Merkle roots, PLONK proofs
- Has full on-chain registry read access
- Does NOT have deleted epoch secrets or blinding factors (secure deletion assumption)
- Does NOT have the PLONK SRS trapdoor

### Hiding commitment security note

The adversary holds `s_T` and observes `epochCommitment_e = Poseidon2(s_e, r_e)` for e < T. To link a commitment to the chain requires either `s_e` (inverting Poseidon1 backward from `s_T`, breaking A1) or `r_e` (destroyed). Without both, the commitment is indistinguishable from random (A5). The adversary cannot even identify which on-chain commitments belong to the compromised agent.

### Game: IND-FS-AGENT (Linkability)

1. **Setup.** Challenger enrolls agent with `s_0`. Agent executes sessions across epochs 0..T-1.
2. **Compromise.** At T, adversary receives `s_T` and all credential key material.
3. **Challenge.** Challenger picks e* < T, two transcripts from e*, flips b, gives τ_b.
4. **Goal.** Adversary outputs b'.
5. **Advantage.** `Adv[A] = |Pr[b'=b] - 1/2|`.

**Claim:** `Adv[A] ≤ negl(λ)` under A1–A5.

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

**Case 2 (epoch commitment linkage).** On-chain `epochCommitment_e = Poseidon2(s_e, r_e)` is visible. Adversary lacks both `s_e` (A1) and `r_e` (deleted). By A5, the commitment is indistinguishable from random — adversary cannot verify which commitments belong to the compromised chain. **This is the gap closed by the hiding commitment**: the prior construction's `Poseidon1(s_e) = s_{e+1}` was trivially linkable forward; now `Poseidon2(s_e, r_e)` with destroyed `r_e` is not.

**Case 3 (scope commitment).** Reveals only policy (public input), not per-session identity.

**Case 4 (PLONK proof).** Zero-knowledge simulator exists in ROM.

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

No external primitives. `r_e` is a standard field element — no new primitive required.

## 6. Circuit cost estimate

| Circuit | Constraints | System | Proving time |
|---|---|---|---|
| EpochRotation | ~1,200 | PLONK | <1s |
| ForwardSecureAgentSession | ~9,828 | PLONK | <5s |
| ForwardSecureDelegation | ~9,064 | PLONK | <5s |

**EpochRotation breakdown:** 3x Poseidon2 (~846) + 1x Poseidon1 (~281) + Num2Bits(64) (~33) = ~1,160. Overhead vs prior: +321 constraints (+37%) for the hiding commitment opening. Still well under 10k.

**ForwardSecureAgentSession overhead:** 2x Poseidon2 (~564) over AgentPolicy base (~9,264) = 6.1% overhead.

## 7. Concrete deployment scenario

### SECU 30-day autonomous lending agent

State Employees' Credit Union deploys a Claude agent for 30-day loan processing. Daily epoch rotation: agent samples `r_e`, publishes `Poseidon2(s_e, r_e)` via EpochRotation proof, deletes `(s_{e-1}, r_{e-1})`.

Day 31: key leak exposes `(s_{30}, r_{30})`. Attacker cannot invert Poseidon1 to get `s_{29}..s_0`, nor recover independently-sampled `r_{29}..r_0`. The 30 on-chain commitments `Poseidon2(s_e, r_e)` are opaque — attacker cannot even identify which commitments belong to the compromised agent, let alone link sessions.

### CFPB whistleblower relay agent

Informant's agent relays evidence over 12 weekly epochs. Seizure reveals only the current epoch. Hiding commitments for prior epochs are indistinguishable from any other enrolled agent's — adversary cannot identify which chain belongs to the seized agent.

## 8. Why the baseline cannot match

### 8.1 DPoP ephemeral keys don't achieve unlinkability

AS logs `sub + jkt` per session. Even with per-session ephemeral keys, adversary with AS access reconstructs full timeline. OIDC PPIDs don't help at the AS or within a single RP. Bolyra's epoch nullifier has no `sub`/`client_id`/`jkt` — correlating nullifiers breaks A2.

### 8.2 WIMSE delegation chains leak structural metadata

SPIFFE IDs are stable; SVID certificate chains contain issuer DNs in plaintext. Delegation graph is structural and key-independent. Bolyra's delegation linking is inside the ZK proof only.

### 8.3 Operational deletion ≠ cryptographic guarantee

No proof of deletion exists in any RFC. Memory forensics can recover "deleted" keys. Bolyra's security is a property of Poseidon preimage resistance + hiding commitments, not runtime hygiene.

### 8.4 IND-FS-AGENT requires epoch-isolated hiding commitments

The game requires: (a) pseudorandom per-session IDs under unknown key, (b) ZK proofs, (c) no persistent correlators, (d) on-chain commitments unlinkable to known key material. The baseline fails (c) via `sub`/SPIFFE ID and has no analog of (d). Hiding epoch commitments with destroyed blinding randomness — not just key rotation — are structurally necessary to satisfy the game.
