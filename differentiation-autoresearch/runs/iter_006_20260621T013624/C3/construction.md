# Construction

## 1. Statement of claim

An auditor verifies that a multi-hop delegation chain narrowed permissions monotonically at every hop — without learning any intermediate scope values or participant identities — and the resulting proof is anchored to on-chain state so the auditor cannot be fed a fabricated chain. The construction applies to AI agent pipelines (tool-call chains), whistleblower-safe delegation, and cross-org agent handoff — not just narrow regulatory audit.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationChainAudit(MAX_HOPS)`

**Proving system**: PLONK (universal setup, no per-circuit ceremony — auditors can verify without trusting a circuit-specific ceremony)

**MAX_HOPS**: 8 (covers tool-call pipelines, journalist relay chains, cross-org handoffs)

#### Private inputs (per hop `i` in `0..MAX_HOPS-1`):

| Signal | Type | Description |
|--------|------|-------------|
| `scope[i]` | 64-bit | Permission bitmask at hop `i` |
| `credCommitment[i]` | field | Credential commitment of participant at hop `i` |
| `blindingSalt[i]` | field | Random blinding factor for scope commitment hiding (≥ 128 bits of entropy) |
| `delegationNullifier[i]` | field | Nullifier from the delegation proof at hop `i` |
| `hopActive[i]` | binary | 1 if hop exists, 0 for padding |

#### Public inputs:

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Blinded scope commitment from the initial handshake (on-chain, in `HandshakeVerified` event) |
| `chainLength` | Number of active delegation hops |
| `sessionNonce` | Binds to the originating handshake session |
| `auditPolicyMask` | Bitmask of permissions the auditor wants to confirm the terminal agent satisfies |

#### Public outputs:

| Signal | Description |
|--------|-------------|
| `narrowingValid` | 1 iff monotonic narrowing holds at every active hop |
| `policyOk` | 1 iff the terminal scope satisfies `auditPolicyMask` |
| `chainAnchor` | `PoseidonN(hopDigest[0], ..., hopDigest[MAX_HOPS-1])` where each `hopDigest[i] = Poseidon2(delegationNullifier[i], scopeCommit[i])` — binds each nullifier to its scope commitment, auditor cross-references each pair against on-chain `DelegationVerified` events |
| `terminalScopeCommitment` | Scope commitment at the final hop (auditor can verify it matches on-chain `lastScopeCommitment`) |

#### Constraints:

1. **Hop activation monotonicity**: `hopActive[i] * (1 - hopActive[i]) === 0` for all `i` (binary). For `i > 0`: `(hopActive[i-1] - hopActive[i]) * hopActive[i] === 0` (once deactivated, stays deactivated). `hopActive[0] === 1` (at least one hop).

2. **Chain length consistency**: `sum(hopActive[i]) === chainLength`.

3. **Blinded scope commitment reconstruction** (per active hop): `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])`. For `i = 0`: `scopeCommit[0] === rootScopeCommitment`. The blinding salt `blindingSalt[i]` is a per-hop random field element with at least 128 bits of entropy, chosen by the hop's delegator at delegation time. It makes the scope commitment computationally hiding even when `scope[i]` is drawn from a small domain (e.g., 8-bit bitmask → 256 values).

4. **Chain linking** (per active adjacent pair): for active hop `i > 0`: `scopeCommit[i-1]` is the `previousScopeCommitment` that was verified in the original delegation proof. Enforced by requiring the scope commitment sequence to match: `select(hopActive[i], scopeCommit[i-1], scopeCommit[i-1]) === select(hopActive[i], previousExpected, previousExpected)` — i.e., sequential scope commitments form a linked chain matching what the on-chain registry recorded.

5. **Monotonic narrowing** (per active adjacent pair `i > 0`):
   ```
   scope[i] = Num2Bits(64)(scope[i])
   scope[i-1] = Num2Bits(64)(scope[i-1])
   for each bit b in [0, 64):
     hopActive[i] * scopeBits[i][b] * (1 - scopeBits[i-1][b]) === 0
   ```
   Every bit set in the delegatee's scope must also be set in the delegator's scope. Inactive hops are unconstrained.

6. **Cumulative bit encoding** (per active hop):
   ```
   hopActive[i] * scopeBits[i][4] * (1 - scopeBits[i][3]) === 0
   hopActive[i] * scopeBits[i][4] * (1 - scopeBits[i][2]) === 0
   hopActive[i] * scopeBits[i][3] * (1 - scopeBits[i][2]) === 0
   ```

7. **Terminal scope policy check**:
   ```
   auditBits = Num2Bits(64)(auditPolicyMask)
   termIdx = chainLength - 1
   for each bit b in [0, 64):
     auditBits[b] * (1 - terminalScopeBits[b]) === 0
   policyOk = 1 (all constraints satisfied) or 0
   ```
   Uses a multiplexer on `chainLength` to select the terminal hop's scope bits.

8. **Nullifier-scope binding** (per hop): Each hop's nullifier is cryptographically bound to its scope commitment inside the circuit:
   ```
   hopDigest[i] = Poseidon2(delegationNullifier[i], scopeCommit[i])
   ```
   For inactive hops (`hopActive[i] = 0`), both `delegationNullifier[i]` and `scopeCommit[i]` are constrained to 0 (deterministic padding):
   ```
   (1 - hopActive[i]) * delegationNullifier[i] === 0
   (1 - hopActive[i]) * scopeCommit[i] === 0
   ```
   This ensures inactive padding cannot carry non-trivial digest values.

9. **Chain anchor with nullifier-scope binding**: `chainAnchor = PoseidonN(hopDigest[0], ..., hopDigest[MAX_HOPS-1])`. The auditor reconstructs each `hopDigest[i]` by computing `Poseidon2(nullifier_i, scopeCommit_i)` from the `(delegationNullifier, newScopeCommitment)` pairs emitted in on-chain `DelegationVerified` events, hashes all 8 digests, and verifies the result equals `chainAnchor`. A mismatch proves the prover used fabricated scope–nullifier pairings.

10. **Terminal scope commitment output**: `terminalScopeCommitment = scopeCommit[termIdx]` via multiplexer on `chainLength`. Auditor verifies this matches the on-chain `lastScopeCommitment[sessionNonce]`.

### Required upstream change: blinded scope commitments in `Delegation` and `AgentPolicy` circuits

The blinding salt must originate where scope commitments are first computed — in the `AgentPolicy` circuit (for the handshake root) and the `Delegation` circuit (for each hop). The scope commitment formula changes from:

```
scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)
```

to:

```
scopeCommitment = Poseidon3(permissionBitmask, credentialCommitment, blindingSalt)
```

where `blindingSalt` is a new private input (field element, ≥ 128 bits of entropy) in both circuits. The on-chain `lastScopeCommitment` mapping and `DelegationVerified` events store these blinded commitments. The chain-linking constraint in the existing `Delegation` circuit (`Poseidon2(delegatorScope, delegatorCredCommitment) === previousScopeCommitment`) becomes `Poseidon3(delegatorScope, delegatorCredCommitment, delegatorBlindingSalt) === previousScopeCommitment`, requiring the delegator to supply their blinding salt as an additional private input.

This is a minimal, backward-compatible change: `blindingSalt` is a private input (no public signal layout change), and the on-chain scope commitment values remain opaque field elements of the same size. The only coordination requirement is that each delegator retains their `blindingSalt` to pass it as a private input when the next hop's delegation proof reconstructs their scope commitment for chain linking.

### Gadgets used:

- `Num2Bits(64)` — bit decomposition for scope bitmasks (circomlib)
- `Poseidon3` — blinded scope commitment hashing (circomlib/poseidon)
- `Poseidon2` — nullifier-scope binding (circomlib/poseidon)
- `PoseidonN` (N=8) — chain anchor hashing over hop digests
- `Mux1` / `MultiMux` — hop selection for terminal index
- `IsZero`, `IsEqual` — activation flag logic

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls:
- Any subset of participants in the delegation chain (collusion)
- The auditor's communication channel (can see auditor queries)
- Up to `MAX_HOPS - 1` of the delegation hops

The adversary sees:
- All public outputs of the audit proof (`narrowingValid`, `policyOk`, `chainAnchor`, `terminalScopeCommitment`)
- The public inputs (`rootScopeCommitment`, `chainLength`, `sessionNonce`, `auditPolicyMask`)
- All on-chain events (`HandshakeVerified`, `DelegationVerified`), including every `(delegationNullifier, newScopeCommitment)` pair
- The full agent Merkle tree (all `credCommitment` leaf values are public)

The adversary does NOT control:
- The Poseidon hash function (random oracle model for Poseidon)
- The BN128 pairing (trusted setup for PLONK is universal)
- The blinding salts of honest participants

### Security game: NarrowingAuditSoundness

```
Game NarrowingAuditSoundness(λ):
  1. Challenger sets up Bolyra registry with honest enrollment
  2. A adaptively creates delegation chains (may collude with participants)
  3. A produces (proof π, public inputs/outputs)
  4. A wins if:
     (a) Verifier(π) = ACCEPT, AND
     (b) narrowingValid = 1, AND
     (c) chainAnchor cross-references valid on-chain events
         (each hopDigest[i] matches a DelegationVerified event), AND
     (d) there exists some hop i where the ACTUAL on-chain scope[i] ⊄ scope[i-1]
         (i.e., the real scopes recorded on-chain did NOT narrow monotonically)
```

**Claim**: `Pr[A wins] ≤ negl(λ)` under knowledge soundness of PLONK + collision resistance of Poseidon.

### Privacy game: ScopeRecovery

The prior construction's AuditPrivacy game was vacuously trivial: it required C₀ and C₁ to share identical public outputs (including `chainAnchor`), making the two cases indistinguishable by construction rather than by any cryptographic property. The real privacy threat is scope recovery via brute force. With unblinded scope commitments `Poseidon2(scope, credCommitment)`, an adversary who knows `credCommitment` (public in the agent Merkle tree) and knows scope is 8 bits (256 values) can compute all 256 candidate commitments and match the on-chain value in constant time. This applies to every on-chain `scopeCommitment` emitted in `DelegationVerified` events.

The blinded construction defeats this attack:

```
Game ScopeRecovery(λ):
  1. Challenger enrolls agents in the Merkle tree (credCommitments are public).
  2. Challenger runs an honest delegation chain of length n ≤ MAX_HOPS,
     choosing each blindingSalt[i] ←$ F_p uniformly at random.
  3. A sees:
     - The full agent Merkle tree (all credCommitment values)
     - All on-chain (delegationNullifier[i], scopeCommitment[i]) pairs
     - The audit proof and all public inputs/outputs
     - The scope values and blinding salts of any corrupted hops
       (A controls up to n-1 hops)
  4. A outputs a guess scope*[j] for some honest (uncorrupted) hop j.
  5. A wins if scope*[j] = scope[j].
```

**Claim**: `Pr[A wins] ≤ 1/|F_p| + negl(λ)` under Poseidon preimage resistance, even when `scope[j]` is drawn from a domain as small as {0, 1, ..., 255}.

**Without blinding**: `Pr[A wins] = 1` for 8-bit scopes. The adversary computes `Poseidon2(s, credCommitment[j])` for each `s ∈ {0, ..., 255}` and matches against the on-chain `scopeCommitment[j]`. This requires 256 hash evaluations — trivial.

**With blinding**: The adversary must find `(scope[j], blindingSalt[j])` such that `Poseidon3(scope[j], credCommitment[j], blindingSalt[j]) = scopeCommitment[j]`. Even fixing `scope[j]` to a candidate value, recovering `blindingSalt[j]` requires inverting Poseidon on one of its inputs — a preimage attack. The adversary cannot verify a scope guess without the salt.

**Quantitative bound**: For each candidate scope value `s`, the adversary must check whether `∃ r : Poseidon3(s, credCommitment[j], r) = scopeCommitment[j]`. This is a preimage query. Under the random oracle model for Poseidon, each such query succeeds with probability `1/|F_p|` ≈ `2^{-254}`. Even across all 256 candidate scope values, the total success probability is `256/|F_p|` ≈ `2^{-246}`, which is negligible.

**Collusion resilience**: If A corrupts hops `j-1` and `j+1` (neighbors of the honest hop), A learns `scopeCommit[j]` (on-chain), `credCommitment[j]` (Merkle tree), and can verify narrowing relationships `scope[j] ⊆ scope[j-1]` and `scope[j+1] ⊆ scope[j]`. This constrains `scope[j]` to the set `{s : scope[j+1] ⊆ s ⊆ scope[j-1]}` — potentially as few as 1 value for tight chains. The blinding salt prevents confirming even this narrowed guess: A still cannot verify `Poseidon3(s, credCommitment[j], ?) = scopeCommitment[j]` without the salt. In the degenerate case where narrowing constraints uniquely determine `scope[j]` (e.g., `scope[j-1] = scope[j+1]` forces `scope[j] = scope[j-1]`), the adversary learns the scope from the narrowing structure alone — but this is inherent to the delegation semantics, not a failure of the commitment scheme. The blinding salt ensures that scope recovery is impossible whenever the narrowing constraints leave any ambiguity.

### Relationship between the two games

`NarrowingAuditSoundness` ensures the auditor cannot be deceived about whether narrowing held. `ScopeRecovery` ensures the auditor (or any observer of on-chain state) cannot learn what the actual scope values were. Together, they provide the dual guarantee: the auditor is convinced of the structural property (narrowing) without learning the data (scopes and participants).

## 4. Security argument (named assumption + reduction sketch)

### Assumptions:

1. **Knowledge soundness of PLONK** (Marlin/PLONK proof): any efficient prover producing an accepting proof can be extracted to a valid witness.
2. **Collision resistance of Poseidon** over BN254 scalar field: no efficient adversary finds `(x₁, x₂, x₃) ≠ (y₁, y₂, y₃)` with `Poseidon3(x₁, x₂, x₃) = Poseidon3(y₁, y₂, y₃)`.
3. **Preimage resistance of Poseidon** over BN254 scalar field: given `y`, no efficient adversary finds `(x₁, x₂, x₃)` with `Poseidon3(x₁, x₂, x₃) = y`.
4. **Discrete logarithm hardness on Baby Jubjub**: credential commitments are binding (operator cannot produce two distinct credentials with the same commitment).

### Reduction sketch (soundness):

Suppose adversary A wins `NarrowingAuditSoundness` with non-negligible probability ε. Then:

1. By PLONK knowledge soundness, extract witness `(scope[0..n], credCommitment[0..n], blindingSalt[0..n], delegationNullifier[0..n], ...)` from A's proof.

2. The extracted witness satisfies constraint 3 (blinded scope commitment reconstruction): `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])` for each active hop.

3. The extracted witness satisfies constraint 8 (nullifier-scope binding): `hopDigest[i] = Poseidon2(delegationNullifier[i], scopeCommit[i])` for each hop.

4. The extracted witness satisfies constraint 9 (chain anchor): `chainAnchor = PoseidonN(hopDigest[0], ..., hopDigest[7])`.

5. By game condition (c), the auditor has verified that each `hopDigest[i]` matches the on-chain pair `(nullifier_i^{chain}, scopeCommit_i^{chain})` from `DelegationVerified` events. That is, `hopDigest[i] = Poseidon2(nullifier_i^{chain}, scopeCommit_i^{chain})`.

6. From steps 3 and 5: `Poseidon2(delegationNullifier[i], scopeCommit[i]) = Poseidon2(nullifier_i^{chain}, scopeCommit_i^{chain})`. By collision resistance of Poseidon (Assumption 2): `delegationNullifier[i] = nullifier_i^{chain}` AND `scopeCommit[i] = scopeCommit_i^{chain}`.

7. Therefore the extracted `scopeCommit[i]` equals the on-chain scope commitment. By step 2, `scopeCommit[i] = Poseidon3(scope[i], credCommitment[i], blindingSalt[i])`, and the on-chain scope commitment was computed as `Poseidon3(scope_i^{actual}, credCommitment_i^{actual}, salt_i^{actual})`. By collision resistance of Poseidon3 (Assumption 2): `scope[i] = scope_i^{actual}`, `credCommitment[i] = credCommitment_i^{actual}`, and `blindingSalt[i] = salt_i^{actual}`.

8. The extracted witness satisfies constraint 5 (monotonic narrowing): for every active hop `i`, `scope[i] & scope[i-1] == scope[i]`. By step 7, these are the actual on-chain scopes.

9. Game condition (d) asserts the actual on-chain scopes did NOT narrow at some hop. But step 8 proves they did. Contradiction.

10. Therefore `ε ≤ negl(λ)`.

### Reduction sketch (scope hiding):

Suppose adversary A wins `ScopeRecovery` with non-negligible probability ε > 256/|F_p|. We construct a reduction B that breaks Poseidon3 preimage resistance:

1. B receives a Poseidon3 preimage challenge: given target `y`, find `(x₁, x₂, x₃)` with `Poseidon3(x₁, x₂, x₃) = y`.

2. B sets up the Bolyra registry honestly, but at the target hop `j`, B sets `scopeCommitment[j] = y` (the challenge value) instead of computing it honestly. B simulates the rest of the chain honestly, using the PLONK simulator for the audit proof (honest-verifier ZK).

3. A outputs a guess `scope*[j]`. If A wins, A has identified `scope[j]` such that `∃ (credCommitment[j], blindingSalt[j]) : Poseidon3(scope[j], credCommitment[j], blindingSalt[j]) = y`. Since `credCommitment[j]` is a public Merkle tree leaf (known to B), B can enumerate the at most `T` enrolled credentials and, for each, attempt to find the blinding salt — but A's success already implies a valid preimage exists.

4. More precisely: A's advantage in recovering `scope[j]` beyond random guessing (1/|F_p|) directly yields information about a Poseidon3 preimage. Since `credCommitment[j]` is fixed (known from the Merkle tree), A effectively inverts `r ↦ Poseidon3(s, credCommitment[j], r)` for some `s` — a preimage attack on Poseidon3 with two inputs fixed.

5. Therefore `ε ≤ 256/|F_p| + negl(λ) ≈ negl(λ)`.

**Note on Assumption 3 vs. the ROM**: The reduction above models Poseidon3 as preimage-resistant rather than requiring the full random oracle model. This is a weaker (more conservative) assumption. The ROM would give a tighter bound but is not needed — preimage resistance suffices because the adversary's task is specifically to invert, not to distinguish.

**Note on the soundness reduction and blinding**: The soundness reduction (steps 1–10) is unchanged in structure. The blinding salt adds a third component to the collision-resistance argument in step 7, but the reduction goes through identically: Poseidon3 collision resistance implies all three components (scope, credCommitment, blindingSalt) must match between the extracted witness and the on-chain values.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Blinded scope commitment `Poseidon3(scope, credCommitment, blindingSalt)` | Extension of identity-bound scope commitment with hiding property. Replaces `Poseidon2(scope, credCommitment)` in `AgentPolicy` and `Delegation` circuits. | `draft-bolyra-mutual-zkp-auth-01` §5 (modified) |
| Blinding salt `blindingSalt` | New private input in `AgentPolicy`, `Delegation`, and `DelegationChainAudit` circuits. Field element with ≥ 128 bits of entropy, chosen uniformly at random by the delegator at each hop. | New; required by this construction |
| Delegation nullifier `Poseidon2(delegationTokenHash, sessionNonce)` | Delegation nullifier | Delegation circuit public output index 1 |
| Nullifier-scope digest `Poseidon2(delegationNullifier, scopeCommit)` | Binding primitive; composed from two existing on-chain outputs | Constraint 8 of this construction |
| 64-bit permission bitmask with cumulative encoding | Bolyra permission model (bits 0–7 active, 8–63 reserved) | `CLAUDE.md` Permissions Model |
| `previousScopeCommitment` → `newScopeCommitment` chain | On-chain `lastScopeCommitment` mapping (now stores blinded commitments) | `draft-bolyra-mutual-zkp-auth-01` §5.1 (modified) |
| `rootScopeCommitment` from handshake | `agentPubSignals[2]` stored by registry (now blinded) | Handshake verification step 6b |
| PLONK proving system | Agent/Delegation PLONK option | `CLAUDE.md` Circuits table |
| `sessionNonce` binding | Handshake session nonce | `draft-bolyra-mutual-zkp-auth-01` §4.1 |
| Poseidon hash (BN254 scalar field) | Required hash function | `draft-bolyra-mutual-zkp-auth-01` §3.2 |
| Baby Jubjub EdDSA | Operator signature scheme (used in underlying delegation proofs, not re-verified in audit circuit) | `draft-bolyra-mutual-zkp-auth-01` §3.2 |

The audit circuit does NOT re-verify EdDSA signatures or Merkle membership — those are already enforced by the per-hop `Delegation` circuit proofs verified on-chain. The audit circuit operates one layer above: it proves the *structural property* (monotonic narrowing) over the chain of already-verified hops, and the nullifier-scope binding (constraint 8) ensures the structural proof is anchored to the actual on-chain delegation state rather than fabricated witness data.

### On-chain registry requirement

The `DelegationVerified` event MUST emit both `delegationNullifier` and `newScopeCommitment` as indexed fields. The `AgentPolicy` circuit's scope commitment output (public signal index 2) and the `Delegation` circuit's scope commitment output (public signal index 0) both change from `Poseidon2(scope, credCommitment)` to `Poseidon3(scope, credCommitment, blindingSalt)`. This is a change to the commitment formula but not to the public signal layout or the on-chain storage schema — scope commitments remain single field elements.

### Upstream circuit changes required

| Circuit | Change | Impact |
|---------|--------|--------|
| `AgentPolicy` | Add `blindingSalt` private input; change `scopeCommitment = Poseidon2(permissionBitmask, credentialCommitment)` → `Poseidon3(permissionBitmask, credentialCommitment, blindingSalt)` | +1 private input, +~100 constraints (Poseidon3 vs Poseidon2) |
| `Delegation` | Add `delegatorBlindingSalt` and `delegateeBlindingSalt` private inputs; update chain-linking constraint and `newScopeCommitment` output to use `Poseidon3` | +2 private inputs, +~200 constraints |

These are additive changes with no public signal layout modifications. Existing verifier contracts require redeployment (new `.zkey` / `.vkey`), but the on-chain registry ABI is unchanged.

## 6. Circuit cost estimate

### Constraint breakdown (MAX_HOPS = 8):

| Component | Constraints per hop | Total |
|-----------|-------------------|-------|
| `Num2Bits(64)` for scope | 64 | 512 |
| `Poseidon3` for blinded scope commitment | ~400 | 3,200 |
| `Poseidon2` for nullifier-scope binding (hopDigest) | ~300 | 2,400 |
| Inactive-hop zero constraints (3 per hop: nullifier, scopeCommit, blindingSalt) | 3 | 24 |
| Bitwise subset check (64 bits, 7 active pairs) | 64 per pair | 448 |
| Cumulative bit encoding | 3 | 24 |
| Hop activation logic (binary + monotonicity) | ~5 | 40 |
| Terminal multiplexer (8-way, 64 bits) | ~200 | 200 |
| Policy mask check (64 bits) | 64 | 64 |
| `PoseidonN(8)` for chain anchor (over hopDigests) | ~600 | 600 |
| Chain length consistency | ~16 | 16 |
| **Total** | | **~7,528** |

### Delta from prior construction:

The blinding salt adds ~808 constraints over the prior construction's ~6,720: 8 × (Poseidon3 − Poseidon2 ≈ 100 additional constraints per hop) + 8 × 1 additional zero-constraint per hop for inactive salt padding. This is a 12% increase. The total (~7,528) remains well within the PLONK agent budget.

### Proving time targets:

| System | Constraints | Target | Rationale |
|--------|------------|--------|-----------|
| PLONK (agent-class) | ~7,528 | **< 2 seconds** | Well under the 5s PLONK agent budget; smaller than `AgentPolicy` (~18K) |
| Groth16 (optional) | ~7,528 | **< 1 second** | If circuit-specific ceremony is acceptable |

### Comparison to existing circuits:

- `HumanUniqueness`: ~12,000 constraints → 7,528 is 1.6× smaller
- `AgentPolicy`: ~18,000 constraints → 7,528 is 2.4× smaller
- `Delegation`: ~22,000 constraints → 7,528 is 2.9× smaller

The circuit remains lightweight because it delegates EdDSA verification and Merkle membership to the per-hop `Delegation` proofs already verified on-chain. The Poseidon3 calls for blinded scope commitments and Poseidon2 calls for nullifier-scope binding are the cost of achieving both scope hiding and soundness — a necessary trade for closing the enumeration attack.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), largest US credit union with $176B in assets. Subject to NCUA examination and FFIEC guidance on third-party AI agent use.

**Setup**: NFCU deploys an AI agent pipeline for member loan origination:
1. **Hop 0 (root)**: Member's personal AI assistant (e.g., Claude) — full `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bitmask `0b10000111 = 0x87`)
2. **Hop 1**: NFCU's loan intake agent — narrows to `READ_DATA | WRITE_DATA | FINANCIAL_SMALL` (bitmask `0b00000111 = 0x07`, drops `ACCESS_PII`)
3. **Hop 2**: Third-party credit scoring agent (TransUnion) — narrows to `READ_DATA` only (bitmask `0b00000001 = 0x01`)
4. **Hop 3**: NFCU's underwriting agent — narrows to `READ_DATA | FINANCIAL_SMALL` (bitmask `0b00000101 = 0x05`)

Each delegator chooses a random blinding salt when issuing the delegation. The salt is retained locally by the delegator and passed as a private input to the next hop's delegation proof (for chain-linking) and to the audit proof generator.

**Audit trigger**: NCUA examiner requests proof that the pipeline respected least-privilege at every hop, per FFIEC guidance on AI model risk management (SR 11-7 analogue).

**Without Bolyra** (baseline): NFCU must disclose the full delegation token chain to the examiner, revealing:
- TransUnion's involvement (competitive intelligence)
- The specific permission bitmasks at each hop (proprietary pipeline architecture)
- Each agent's credential commitment (linkable across examinations)

Even with BBS+ selective disclosure, the 8-bit scope bitmask has only 256 possible values. An examiner who sees `scopeCommitment = Poseidon2(scope, credCommitment)` and knows `credCommitment` from the public Merkle tree can brute-force the scope in 256 hash evaluations — rendering selective disclosure moot for the scope dimension.

**With Bolyra `DelegationChainAudit` (blinded)**:

1. NFCU's compliance agent generates a PLONK proof with:
   - Public inputs: `rootScopeCommitment` (from handshake event), `chainLength = 4`, `sessionNonce`, `auditPolicyMask = 0x01` (examiner checks terminal agent had at least `READ_DATA`)
   - Private inputs: all 4 scopes, credential commitments, blinding salts, delegation nullifiers

2. Examiner receives: `(proof, narrowingValid=1, policyOk=1, chainAnchor, terminalScopeCommitment)`

3. Examiner verifies:
   - PLONK proof checks out (no trust in NFCU's systems required)
   - Reconstructs each `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` from on-chain `DelegationVerified` events, hashes all 8 digests (4 real + 4 zero-padded), and confirms the result equals `chainAnchor` — this proves the in-circuit scopes are the actual on-chain scopes, not fabricated values
   - `terminalScopeCommitment` matches `lastScopeCommitment[sessionNonce]` on-chain
   - `narrowingValid = 1` — monotonic narrowing held at every hop
   - `policyOk = 1` — terminal agent had at least `READ_DATA`

4. Examiner learns: the chain has 4 hops, narrowing held, and the terminal agent satisfied the policy. Examiner does NOT learn: who the intermediate agents are, what specific permissions each had, or the pipeline architecture. **Crucially, the examiner cannot brute-force scope values from on-chain scope commitments because each commitment is blinded with a random salt known only to the delegator.**

**Why blinding matters in this scenario**: TransUnion's scope (`READ_DATA = 0x01`) is trivially identifiable from an unblinded commitment — there are only 256 possible 8-bit bitmasks. With blinding, the examiner sees `Poseidon3(0x01, credCommitment_TransUnion, r₂)` on-chain but cannot confirm that `0x01` is the scope without knowing `r₂`. The examiner knows narrowing held (from the proof) but not which specific permissions were granted or revoked at each hop.

### Journalist/source variant:

A journalist's agent delegates to a source's agent through two intermediary relay agents. The journalist generates the audit proof. An editor (auditor) verifies the delegation chain narrowed properly (the source's agent could only `READ_DATA`, not `WRITE_DATA` or `SIGN_ON_BEHALF`) without learning the identities of the relay agents or the source. The blinded scope commitments prevent the editor from inferring scope values even for the small permission space — the relay agents' exact capabilities remain hidden. The `chainAnchor` lets the editor verify both the chain's existence and its scope integrity against on-chain events, without correlating participants or recovering their mandates.

## 8. Why the baseline cannot match

| Capability | Bolyra `DelegationChainAudit` | Baseline (RFC 8693 + BBS+ + WIMSE) |
|-----------|------------------------------|-------------------------------------|
| **Prove narrowing without disclosing scopes** | Bitwise subset check runs on private inputs inside the circuit. Nullifier-scope binding (constraint 8) ensures the private inputs correspond to actual on-chain state. Blinding salt (constraint 3) prevents brute-force recovery of scope values from on-chain commitments even for small (8-bit) scope domains. Auditor sees only `narrowingValid = 1`. | BBS+ can hide individual claims but cannot prove `scope[i] ⊆ scope[i-1]` over hidden bitmasks. Even with selective disclosure, an 8-bit scope has 256 possible values — any observer who knows the credential commitment can brute-force the scope against an unblinded commitment in microseconds. |
| **Scope hiding under enumeration** | `scopeCommit = Poseidon3(scope, credCommitment, blindingSalt)` with 128+ bits of salt entropy. Recovery requires a Poseidon3 preimage attack (≈ 2^254 work). Formally: `Pr[ScopeRecovery] ≤ 256/|F_p| ≈ 2^{-246}`. | No mechanism. BBS+ selective disclosure hides claim values from the verifier, but on-chain scope commitments (if ever posted for cross-reference) are brute-forceable for small domains. The baseline has no equivalent of a computationally hiding commitment for small-domain values because it lacks a blinding primitive in the delegation layer. |
| **Anchor proof to actual chain state** | Each `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` binds the nullifier to its blinded scope commitment inside the circuit. The auditor cross-references each pair against on-chain events. A prover who substitutes fake scopes produces a non-matching `chainAnchor`. | RFC 8693 tokens are bearer artifacts. An auditor verifying a token chain trusts that the AS issued them correctly. There is no cryptographic binding between the token's scope and an independently verifiable anchor — the AS is the anchor. |
| **Hide intermediate participants** | All `credCommitment[i]` values are private inputs. Auditor sees only the `chainAnchor` (hash of bound nullifier-scope pairs). | RFC 8693 `act` claim tree is plaintext. BBS+ selective disclosure operates within a single credential, not across a multi-issuer chain. No standard mechanism hides participants in a multi-hop delegation. |
| **No trusted third party** | PLONK proof is self-verifiable. The nullifier-scope binding ensures the proof's scopes match on-chain reality without querying any authority — the BN254 pairing check and Poseidon preimage binding are the only trust assumptions. | RFC 8693 narrowing enforcement requires the Authorization Server. Auditor who cannot query or trust the AS has no narrowing guarantee. AS compromise breaks the entire chain. |
| **Cross-org without shared AS** | Each hop's delegation proof is independently verified on-chain. The audit circuit chains blinded scope commitments across organizational boundaries using Poseidon — no shared AS or federation protocol needed. | Cross-org delegation requires either a shared AS or WIMSE federation trust anchor. No standard produces a single artifact proving cross-org monotonic narrowing without a common authority that sees all scopes. |
| **Journalist/source anonymity** | Participant identities never appear in any public output. Nullifiers are pseudonymous (Poseidon2 of delegation token hash + nonce) and unlinkable across sessions. Blinding prevents scope inference even when the permission domain is small. | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-to-RS correlation but not AS or auditor correlation via the `act` chain. No mechanism proves "a legitimate holder participated at hop k" without identifying them. |
| **In-circuit enforcement at presentation** | Narrowing is proven in-circuit at the moment the audit proof is generated. The proof IS the enforcement — no gap between issuance-time policy and presentation-time reality. | RFC 8693 enforces narrowing at issuance. Post-issuance, tokens can be presented to any accepting RS. No runtime binding between the narrowing proof and the credential's actual use. |
| **Offline verifiability** | PLONK proof + on-chain event cross-reference. No real-time API calls to any authority. | RFC 7662 introspection requires live AS queries. Signed introspection responses (draft-ietf-oauth-jwt-introspection-response) are offline-verifiable but still reveal scope values. |
| **Composability with Bolyra handshake** | `rootScopeCommitment` directly chains from the `HandshakeVerified` event. The audit proof extends the existing Bolyra proof pipeline with a minimal upstream change (Poseidon2 → Poseidon3 for scope commitments). | Integrating RFC 8693 with a ZKP handshake requires a custom bridge layer. No standard defines how OAuth token exchange interoperates with on-chain ZKP verification. |

**The structural impossibility**: BBS+ provides selective disclosure of *attributes within a single credential*. Monotonic narrowing is a *relational property across a sequence of credentials*. Proving `∀i: scope[i] ⊆ scope[i-1]` over hidden values requires arithmetic over those values — exactly what an R1CS/PLONK circuit provides and what BBS+ signature schemes do not. The blinding salt further widens the gap: even if BBS+ could somehow prove a relational property over hidden scopes, it has no mechanism to make small-domain values (8-bit bitmasks) computationally hiding on-chain — BBS+ hides values from the *verifier* via selective disclosure, but any observer with the public credential commitment and the on-chain scope commitment can enumerate the 256 possible scopes in microseconds. Bolyra's blinded Poseidon3 commitment makes this enumeration futile (2^246 work). No composition of BBS+ derived proofs, RFC 8693 token exchanges, or WIMSE attestations can produce a self-verifiable proof of a relational invariant over hidden multi-credential state that is simultaneously anchored to on-chain reality and resistant to small-domain brute force, without introducing either a trusted aggregator or a computational hiding commitment — the former reintroduces single-point-of-trust that the construction eliminates, and the latter is exactly the blinded Poseidon construction that Bolyra provides and no current standard specifies.
