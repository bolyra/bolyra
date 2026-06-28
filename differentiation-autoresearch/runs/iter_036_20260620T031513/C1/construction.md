# Construction

## 1. Statement of claim

An AI agent proves to a resource server (RS) that its 64-bit permission bitmask satisfies a verifier-specified AND-mask predicate — `permissionBitmask & requiredScopeMask == requiredScopeMask` — without revealing any bits of `permissionBitmask` beyond predicate satisfaction. The proof is:

- **AS-blind**: generated entirely by the agent at presentation time with zero Authorization Server (AS) involvement.
- **Runtime-adaptive**: the RS specifies `requiredScopeMask` at request time; no token was pre-issued for this specific predicate.
- **Constant-size**: the Groth16/PLONK proof is ~192 bytes (Groth16) or ~576 bytes (PLONK) regardless of bitmask width or predicate complexity.
- **Sound under adversarial AS**: even if the AS is fully compromised, it cannot forge a proof for permissions the operator never signed, nor can it suppress an agent's legitimately-held permissions.

No composition of RFC 7662, jwt-introspection-response, RFC 8693, RFC 8707, DPoP, or BBS+ can achieve all four properties simultaneously.

## 2. Construction (gadgets, circuits, public/private inputs)

### Core circuit: `SelectiveScopeProof`

This is the AgentPolicy circuit from the Bolyra spec, evaluated specifically as a selective-disclosure primitive. No modifications to the circuit are needed — the construction's novelty is in the security model and the properties it derives from the existing constraints.

**Private inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `modelHash` | F_p | Hash of model identifier |
| `operatorPubkeyAx`, `operatorPubkeyAy` | F_p | Operator EdDSA public key (Baby Jubjub) |
| `permissionBitmask` | 64-bit | Full permission bitfield (NEVER revealed) |
| `expiryTimestamp` | 64-bit | Credential expiration |
| `sigR8x`, `sigR8y`, `sigS` | F_p | Operator EdDSA signature over credential commitment |
| `merkleProofLength`, `merkleProofIndex`, `merkleProofSiblings[20]` | — | Merkle inclusion proof |

**Public inputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `requiredScopeMask` | 64-bit | RS-specified predicate mask |
| `currentTimestamp` | 64-bit | Verifier-provided wall clock |
| `sessionNonce` | F_p | Fresh session identifier |

**Public outputs:**

| Signal | Type | Description |
|--------|------|-------------|
| `agentMerkleRoot` | F_p | On-chain verifiable root |
| `nullifierHash` | F_p | `Poseidon2(credentialCommitment, sessionNonce)` |
| `scopeCommitment` | F_p | `Poseidon2(permissionBitmask, credentialCommitment)` |

### Gadgets (all standard Bolyra primitives)

1. **Num2Bits(64)** on `permissionBitmask`, `expiryTimestamp`, `currentTimestamp` — range checks preventing field overflow.
2. **Poseidon5** — `credentialCommitment = Poseidon5(modelHash, operatorPubkeyAx, operatorPubkeyAy, permissionBitmask, expiryTimestamp)`.
3. **EdDSAPoseidonVerifier** — verifies operator signature over `credentialCommitment` using `(operatorPubkeyAx, operatorPubkeyAy)`.
4. **BinaryMerkleRoot(20)** — proves `credentialCommitment` is a leaf in the agent Merkle tree.
5. **Bitwise AND-mask check** — for each bit `i ∈ [0, 64)`: `requiredBits[i] * (1 - permBits[i]) === 0`. This is the selective scope predicate: every required bit must be set, but unrequired bits are unconstrained and hidden.
6. **Cumulative bit enforcement** — `bits[4]*(1-bits[3]) === 0`, `bits[4]*(1-bits[2]) === 0`, `bits[3]*(1-bits[2]) === 0`. Ensures implication closure (FINANCIAL_UNLIMITED ⇒ FINANCIAL_MEDIUM ⇒ FINANCIAL_SMALL).
7. **LessThan(64)** — `currentTimestamp < expiryTimestamp`.
8. **Poseidon2** — `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` and `nullifierHash = Poseidon2(credentialCommitment, sessionNonce)`.

### Presentation protocol

```
1. RS generates fresh sessionNonce, sends (requiredScopeMask, currentTimestamp, sessionNonce) to agent.
2. Agent generates PLONK proof π locally using its private credential.
   — No AS contact. No token refresh. No introspection endpoint.
3. Agent sends (π, agentMerkleRoot, nullifierHash, scopeCommitment, requiredScopeMask, currentTimestamp, sessionNonce) to RS.
4. RS verifies:
   a. agentMerkleRoot ∈ on-chain root history buffer (30-entry window)
   b. PLONK.Verify(vk, publicSignals, π) = true
   c. nullifierHash not in used-nonce set (replay prevention)
   d. currentTimestamp is within acceptable clock skew
5. RS learns: "this agent holds a valid, unexpired, operator-signed credential enrolled in the Bolyra tree, and its permission bitmask satisfies my required mask." RS learns NOTHING else about the agent's identity, operator, model, or remaining permissions.
```

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary A controls:

- The Authorization Server (AS) completely — can read/modify its database, forge introspection responses, selectively deny service.
- The network between agent and RS (eavesdrop, replay, MITM).
- Up to `n - 1` colluding RSes that share transcripts.

The adversary does NOT control:

- The agent's private credential fields (modelHash, operatorPubkey, permissionBitmask, etc.).
- The operator's EdDSA signing key.
- The on-chain Merkle tree smart contract (public, append-only, consensus-protected).
- The BN128 pairing or Baby Jubjub discrete log problem.

### Game: Selective Scope Unforgeability (SSU)

```
Game SSU(λ):
  1. Setup: Challenger runs Bolyra setup, deploys agent Merkle tree on-chain.
     Challenger enrolls honest agent with credential (modelHash*, opPk*, permBitmask*, expiry*).
  2. Adversary A (controlling AS) receives: the Merkle root, the PLONK/Groth16 verification key,
     all public signals from any number of prior valid presentations by the honest agent.
  3. Challenge: Challenger samples requiredScopeMask* such that
     permBitmask* & requiredScopeMask* ≠ requiredScopeMask*
     (i.e., the honest agent does NOT satisfy this predicate).
  4. A wins if it produces (π, publicSignals) such that:
     a. PLONK.Verify(vk, publicSignals, π) = true
     b. publicSignals.agentMerkleRoot ∈ root history buffer
     c. publicSignals.requiredScopeMask = requiredScopeMask*
  5. SSU-advantage: Adv_SSU(A) = Pr[A wins]
```

### Game: Selective Scope Zero-Knowledge (SSZK)

```
Game SSZK(λ):
  1. Setup: Challenger enrolls two agents with credentials C0, C1 where:
     - C0.permBitmask & requiredScopeMask = requiredScopeMask (C0 satisfies)
     - C1.permBitmask & requiredScopeMask = requiredScopeMask (C1 satisfies)
     - C0.permBitmask ≠ C1.permBitmask (different full permission sets)
  2. Challenger flips coin b ∈ {0, 1}, generates proof πb using Cb.
  3. Adversary A (controlling AS + colluding RSes) receives
     (πb, agentMerkleRoot, nullifierHash, scopeCommitment, requiredScopeMask, currentTimestamp, sessionNonce).
  4. A outputs guess b'.
  5. SSZK-advantage: Adv_SSZK(A) = |Pr[b' = b] - 1/2|
```

## 4. Security argument (named assumption + reduction sketch)

### Named assumptions

- **A1**: Knowledge soundness of Groth16 (BN128 pairing) / PLONK (polynomial commitment scheme).
- **A2**: Collision resistance of Poseidon over the BN254 scalar field.
- **A3**: Discrete logarithm hardness on Baby Jubjub (EdDSA unforgeability).
- **A4**: Random Oracle Model (ROM) for Fiat-Shamir in PLONK; Groth16 uses CRS model.

### Theorem 1 (SSU security)

**Claim**: If A wins the SSU game with non-negligible advantage, then either (a) knowledge soundness of PLONK/Groth16 is broken, (b) Poseidon collision resistance is broken, or (c) EdDSA on Baby Jubjub is forgeable.

**Reduction sketch**:

1. Suppose A produces a valid proof π for `requiredScopeMask*` that the honest agent cannot satisfy.
2. By knowledge soundness (A1), extract witness `w = (modelHash, opPkAx, opPkAy, permBitmask', expiry, sig, merkleProof)`.
3. The circuit enforces `requiredBits[i] * (1 - permBits'[i]) === 0` for all i. So `permBitmask' & requiredScopeMask* == requiredScopeMask*`.
4. The circuit enforces `credCommitment' = Poseidon5(modelHash, opPkAx, opPkAy, permBitmask', expiry)` and Merkle membership of `credCommitment'`.
5. Case (i): `credCommitment'` equals the honest agent's `credCommitment*` but `permBitmask' ≠ permBitmask*`. Then `Poseidon5(... permBitmask' ...) = Poseidon5(... permBitmask* ...)` — a Poseidon collision, breaking A2.
6. Case (ii): `credCommitment'` is a different enrolled credential. Then A forged the operator's EdDSA signature over a new credential commitment (breaking A3), or inserted a new leaf into the on-chain tree (breaking consensus, outside model).
7. Case (iii): `credCommitment'` is not in the tree but the Merkle proof verifies. This is a Poseidon collision on internal tree nodes, breaking A2.

### Theorem 2 (SSZK security)

**Claim**: `Adv_SSZK(A) ≤ negl(λ)` under the zero-knowledge property of Groth16/PLONK.

**Reduction sketch**:

1. `permissionBitmask` is a private input. By the zero-knowledge property, the proof reveals nothing about private inputs beyond what the public signals imply.
2. The public signals are: `agentMerkleRoot`, `nullifierHash`, `scopeCommitment`, `requiredScopeMask`, `currentTimestamp`, `sessionNonce`.
3. `nullifierHash = Poseidon2(credCommitment, sessionNonce)` — different credentials yield different nullifiers, but A sees at most one presentation per session (fresh nonce). Cross-session linking requires inverting Poseidon (breaking A2).
4. `scopeCommitment = Poseidon2(permBitmask, credCommitment)` — given Poseidon preimage resistance (A2), A cannot extract `permBitmask` from `scopeCommitment`.
5. A's view is simulatable: the PLONK/Groth16 simulator produces indistinguishable transcripts for any valid witness satisfying the public signals.
6. Therefore `Adv_SSZK(A) ≤ Adv_ZK(A) + negl(λ)`.

### Why the adversarial-AS model holds

The critical observation: **no step in the presentation protocol requires AS participation or AS-issued assertions**. The credential's validity derives from:

- Operator signature (EdDSA, verified in-circuit) — the AS cannot forge this.
- Merkle membership (on-chain root, public) — the AS cannot modify the tree without a transaction visible to all.
- Permission predicate (evaluated in-circuit) — the AS has no input to this computation.

A compromised AS can refuse to enroll new agents (denial of service), but it cannot:

- Forge proofs for permissions an agent doesn't hold (SSU security).
- Learn which permissions an agent revealed to which RS (SSZK security).
- Retroactively revoke a presentation already verified on-chain (immutability).

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---|---|---|
| Permission encoding | 64-bit cumulative bitmask with implication closure | `permissionBitmask`, §4.2 |
| Credential binding | `Poseidon5(modelHash, opPkAx, opPkAy, permBitmask, expiry)` | `credentialCommitment`, §3 |
| Operator authentication | EdDSA on Baby Jubjub over `credentialCommitment` | `EdDSAPoseidonVerifier`, §4.3 |
| Enrollment proof | `BinaryMerkleRoot(20)` with Poseidon2 node hash | Agent Merkle tree, §3.1 |
| Predicate evaluation | Bitwise AND-mask check in-circuit | AgentPolicy constraint 5, §4.3 |
| Scope commitment (chain entry) | `Poseidon2(permBitmask, credCommitment)` | `scopeCommitment`, §5 |
| Replay prevention | `Poseidon2(credCommitment, sessionNonce)` | `nullifierHash`, §4.3 |
| Proving system | PLONK (agent, no per-circuit ceremony) or Groth16 | §3.2 |
| On-chain root anchor | 30-entry root history buffer | §3.1 |

## 6. Circuit cost estimate

### Constraint breakdown (AgentPolicy / SelectiveScopeProof)

| Gadget | Constraints (approx.) |
|--------|----------------------|
| Num2Bits(64) × 3 (bitmask, expiry, timestamp) | 192 |
| Poseidon5 (credential commitment) | ~300 |
| EdDSAPoseidonVerifier | ~4,500 |
| BinaryMerkleRoot(20) with Poseidon2 × 20 levels | ~3,000 |
| Bitwise AND-mask check (64 multiplications) | 64 |
| Cumulative bit enforcement (3 constraints) | 3 |
| LessThan(64) for expiry | ~130 |
| Poseidon2 × 2 (scopeCommitment + nullifier) | ~300 |
| **Total** | **~8,500** |

### Proving time targets

| System | Constraint budget | Target proving time | Proof size |
|--------|------------------|--------------------:|--------:|
| Groth16 (BN128) | 8,500 (~2^14) | < 3s (snarkjs), < 0.5s (rapidsnark) | 192 B |
| PLONK (universal SRS) | 8,500 | < 5s (snarkjs) | ~576 B |

Both are well within the `pot16.ptau` (2^16) ceremony. Verification on-chain: ~230K gas (Groth16) via EIP-196/197 precompiles.

### Comparison to BBS+ selective disclosure

A BBS+ presentation over 64 individual permission claims requires ~64 group exponentiations (~25 ms) and produces a proof linear in the number of hidden claims. The ZK proof is constant-size and constant-time regardless of which or how many bits are checked.

## 7. Concrete deployment scenario

### Stakeholder: Navy Federal Credit Union (NFCU) — AI agent portfolio management

**Context**: NFCU deploys AI agents to manage member investment portfolios. Agents interact with multiple resource servers: a market data service, a trade execution engine, and a compliance reporting system. Each RS requires different permission subsets.

**Problem without Bolyra**: NFCU's OAuth AS issues tokens with full scope strings. The trade execution RS receives `scope: "read_data write_data financial_medium sign_on_behalf"` — revealing to the trade engine that this agent can also sign on behalf of members, information the trade engine has no business knowing. A compromised trade engine now knows to target this agent for escalation attacks.

**With Selective Scope Proof**:

1. **Enrollment**: NFCU's operator signs agent credentials with `permissionBitmask = 0b00101111` (READ_DATA + WRITE_DATA + FINANCIAL_SMALL + FINANCIAL_MEDIUM + SIGN_ON_BEHALF). Credential commitment enrolled in the Bolyra agent Merkle tree.

2. **Market data request**: The market data RS specifies `requiredScopeMask = 0b00000001` (READ_DATA only). Agent generates a PLONK proof in <0.5s (rapidsnark). RS learns: "this agent can read data." RS does NOT learn that the agent also has write, financial, or signing permissions.

3. **Trade execution**: The trade engine specifies `requiredScopeMask = 0b00001111` (READ + WRITE + FINANCIAL_SMALL + FINANCIAL_MEDIUM). Agent proves satisfaction. Trade engine does NOT learn about SIGN_ON_BEHALF capability.

4. **AS compromise**: If NFCU's OAuth AS is breached, the attacker cannot:
   - Forge proofs granting agents permissions the operator didn't sign (EdDSA unforgeability).
   - Learn which permission subsets agents revealed to which RSes (zero-knowledge).
   - Issue introspection responses claiming an agent lacks permissions it actually holds (the RS doesn't query the AS at all).

5. **Regulatory audit**: The compliance RS specifies `requiredScopeMask = 0b10000000` (ACCESS_PII). The agent's proof FAILS (bit 7 is not set in `0b00101111`). The RS gets a cryptographic denial — not an AS policy decision that could be overridden by a compromised AS administrator.

**Scale**: With 64-bit bitmask, NFCU can encode 2^64 theoretical permission combinations. The proof remains 192 bytes and <0.5s regardless. An OAuth scope string enumerating even 2^16 permission combinations would be 64 KB per introspection response.

## 8. Why the baseline cannot match

The baseline (RFC 7662 + jwt-introspection-response + BBS+ VCs) fails on four independent axes. Each failure is structural, not a gap in current implementations.

### Failure 1: AS-blind presentation is architecturally impossible

In every RFC 7662 variant, the AS is the authority that attests to scope. The jwt-introspection-response removes the AS from the *hot path* but not from the *trust path* — the RS trusts the AS's signed assertion. If the AS never issued an assertion for a particular predicate, the RS has no basis for accepting it.

**Bolyra's construction**: The agent generates its proof from a credential the *operator* signed (EdDSA in-circuit). The AS was involved only at enrollment (adding the leaf to the Merkle tree). At presentation time, the agent's proof is self-contained: Merkle root verification against on-chain state replaces AS attestation.

**Why BBS+ doesn't close this gap**: BBS+ selective disclosure still requires an issuer (the AS) to sign the original credential. The holder can selectively disclose claims, but the RS must trust that the issuer accurately represented the agent's permissions. A compromised issuer that signed a credential with wrong permissions has no cryptographic check against it in BBS+.

### Failure 2: Runtime-adaptive bitmask predicates are inexpressible

OAuth scopes are string-typed. `scope: "read write financial_small"` is not a bitmask — it's a set of opaque labels. The RS cannot evaluate `permissionBitmask & requiredMask == requiredMask` because no bitmask exists in the token. The AS would need to pre-compute and sign every possible mask conjunction the RS might request.

BBS+ supports equality and range predicates on individual hidden attributes but does not support bitwise AND across a multi-attribute field with implication closure. `bit[4] ⇒ bit[3] ⇒ bit[2]` is a circuit-level constraint that has no BBS+ analog.

**Bolyra's construction**: The predicate `requiredBits[i] * (1 - permBits[i]) === 0` is evaluated inside the arithmetic circuit. The RS specifies `requiredScopeMask` as a public input at request time. No pre-issuance is needed. The agent evaluates any mask the RS presents, including masks the AS never anticipated.

### Failure 3: The adversarial-AS game has no baseline solution

The entire RFC 7662 stack assumes a trusted AS. Theorem 1 (SSU) proves that Bolyra's construction is unforgeable even when the AS is fully adversarial. The reduction is to knowledge soundness of PLONK/Groth16, Poseidon collision resistance, and EdDSA unforgeability — none of which involve the AS.

In the baseline, a compromised AS can:

- Return `{"active": false}` for a valid token (denial of legitimate access).
- Return `{"active": true, "scope": "admin"}` for a token that never had admin scope (privilege escalation).
- Correlate all introspection requests to build a complete access log.

No combination of DPoP, RFC 8707, or BBS+ prevents these attacks because the RS's trust anchor is the AS's signature, and the AS controls that signature.

### Failure 4: Proof size scales with disclosure in BBS+, not in ZK

A BBS+ derived proof over `k` hidden messages out of `n` total messages has size `O(n - k)` group elements (for the undisclosed messages) plus `O(1)` for the core proof. For a 64-bit permission space modeled as 64 individual BBS+ messages, a presentation hiding 60 of 64 permissions produces a proof containing 60 group elements (~2.8 KB on BLS12-381).

Bolyra's Groth16 proof is exactly 3 group elements (192 bytes) regardless of how many of the 64 bits are checked or hidden. PLONK is ~576 bytes. Neither scales with bitmask width or predicate complexity.

### Summary of structural impossibilities

| Property | RFC 7662 + BBS+ baseline | Bolyra Selective Scope Proof |
|----------|--------------------------|------------------------------|
| AS involvement at presentation | Required (trust anchor) | None (on-chain root + in-circuit EdDSA) |
| Runtime-adaptive predicate | Must be pre-issued as scope string | RS specifies `requiredScopeMask` at request time |
| Adversarial AS resilience | None — AS signature is the only guarantee | SSU-secure under Poseidon CR + EdDSA + PLONK/Groth16 soundness |
| Proof size | O(hidden claims) for BBS+; O(scope strings) for JWT | O(1) — 192 bytes (Groth16), 576 bytes (PLONK) |
| Implication closure enforcement | Application-layer policy only | Enforced in arithmetic circuit (cumulative bit constraints) |
| Model identity binding | `client_id` string, no cryptographic binding | `credentialCommitment` includes `modelHash` + operator pubkey |
