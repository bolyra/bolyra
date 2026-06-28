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
| `delegationNullifier[i]` | field | Nullifier from the delegation proof at hop `i` |
| `hopActive[i]` | binary | 1 if hop exists, 0 for padding |

#### Public inputs:

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Scope commitment from the initial handshake (on-chain, in `HandshakeVerified` event) |
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

3. **Scope commitment reconstruction** (per active hop): `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])`. For `i = 0`: `scopeCommit[0] === rootScopeCommitment`.

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

### Gadgets used:

- `Num2Bits(64)` — bit decomposition for scope bitmasks (circomlib)
- `Poseidon2` — scope commitment hashing and nullifier-scope binding (circomlib/poseidon)
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
- All on-chain events (`HandshakeVerified`, `DelegationVerified`)

The adversary does NOT control:
- The Poseidon hash function (random oracle model for Poseidon)
- The BN128 pairing (trusted setup for PLONK is universal)

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

**Note on condition (c)**: The prior construction lacked this condition, which created a gap: A could supply real on-chain nullifiers but pair them with fabricated scope values that satisfy narrowing. Constraint 8 (nullifier-scope binding) closes this gap by making the chain anchor commit to `(nullifier, scopeCommitment)` pairs rather than nullifiers alone. The auditor's cross-reference now verifies both components of each pair against on-chain state, so a prover who substitutes a fake scope for a real one produces a `hopDigest` that fails the auditor's off-chain check.

### Privacy game: AuditPrivacy

```
Game AuditPrivacy(λ):
  1. A chooses two valid chains C₀, C₁ of equal length with:
     - Same rootScopeCommitment, same terminalScopeCommitment
     - Same chainLength, same policyOk outcome
     - Same set of on-chain (nullifier, scopeCommitment) pairs
       (hence same chainAnchor)
     - Different intermediate scope VALUES and/or different intermediate participants
  2. Challenger picks b ← {0,1}, proves Cᵦ
  3. A outputs guess b'
  4. A wins if b' = b
```

**Claim**: `|Pr[A wins] - 1/2| ≤ negl(λ)` under zero-knowledge property of PLONK.

**Note**: The privacy game requires equal `chainAnchor` values, which follows automatically when C₀ and C₁ use the same on-chain delegation events. The nullifier-scope binding does not leak additional information because `hopDigest[i]` values are derived from data already public on-chain — the binding merely forces the prover to use the real on-chain data rather than fabricated substitutes.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions:

1. **Knowledge soundness of PLONK** (Marlin/PLONK proof): any efficient prover producing an accepting proof can be extracted to a valid witness.
2. **Collision resistance of Poseidon** over BN254 scalar field: no efficient adversary finds `(x₁, x₂) ≠ (y₁, y₂)` with `Poseidon2(x₁, x₂) = Poseidon2(y₁, y₂)`.
3. **Discrete logarithm hardness on Baby Jubjub**: credential commitments are binding (operator cannot produce two distinct credentials with the same commitment).

### Reduction sketch (soundness):

Suppose adversary A wins `NarrowingAuditSoundness` with non-negligible probability ε. Then:

1. By PLONK knowledge soundness, extract witness `(scope[0..n], credCommitment[0..n], delegationNullifier[0..n], ...)` from A's proof.

2. The extracted witness satisfies constraint 3 (scope commitment reconstruction): `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])` for each active hop.

3. The extracted witness satisfies constraint 8 (nullifier-scope binding): `hopDigest[i] = Poseidon2(delegationNullifier[i], scopeCommit[i])` for each hop.

4. The extracted witness satisfies constraint 9 (chain anchor): `chainAnchor = PoseidonN(hopDigest[0], ..., hopDigest[7])`.

5. By game condition (c), the auditor has verified that each `hopDigest[i]` matches the on-chain pair `(nullifier_i^{chain}, scopeCommit_i^{chain})` from `DelegationVerified` events. That is, `hopDigest[i] = Poseidon2(nullifier_i^{chain}, scopeCommit_i^{chain})`.

6. From steps 3 and 5: `Poseidon2(delegationNullifier[i], scopeCommit[i]) = Poseidon2(nullifier_i^{chain}, scopeCommit_i^{chain})`. By collision resistance of Poseidon (Assumption 2): `delegationNullifier[i] = nullifier_i^{chain}` AND `scopeCommit[i] = scopeCommit_i^{chain}`.

7. Therefore the extracted `scopeCommit[i]` equals the on-chain scope commitment. By step 2, `scopeCommit[i] = Poseidon2(scope[i], credCommitment[i])`, and the on-chain scope commitment was computed as `Poseidon2(scope_i^{actual}, credCommitment_i^{actual})`. By collision resistance: `scope[i] = scope_i^{actual}` and `credCommitment[i] = credCommitment_i^{actual}`.

8. The extracted witness satisfies constraint 5 (monotonic narrowing): for every active hop `i`, `scope[i] & scope[i-1] == scope[i]`. By step 7, these are the actual on-chain scopes.

9. Game condition (d) asserts the actual on-chain scopes did NOT narrow at some hop. But step 8 proves they did. Contradiction.

10. Therefore `ε ≤ negl(λ)`.

**Key improvement over prior reduction**: Steps 5–7 are new. The prior construction's chain anchor committed only to nullifiers, so step 6 would yield `delegationNullifier[i] = nullifier_i^{chain}` but provide no constraint on `scopeCommit[i]`. The adversary could pair real nullifiers with fabricated `(scope, credCommitment)` values satisfying any desired narrowing pattern. The nullifier-scope binding (constraint 8) closes this gap by forcing the in-circuit scope commitments to match the on-chain scope commitments, making the reduction tight.

### Reduction sketch (privacy):

By the honest-verifier zero-knowledge property of PLONK, the proof transcript is simulatable given only public inputs/outputs. Since intermediate scopes and participant identities appear only as private inputs, and the public outputs (`narrowingValid`, `policyOk`, `chainAnchor`, `terminalScopeCommitment`) are identical for C₀ and C₁ by construction, the simulated transcripts are identically distributed. The adversary's advantage is exactly 0.

The nullifier-scope binding does not weaken privacy: each `hopDigest[i]` is derived from `(delegationNullifier[i], scopeCommit[i])`, both of which are already public on-chain via `DelegationVerified` events. The binding forces the prover to use these on-chain values but does not reveal any additional information beyond what the chain of on-chain events already discloses. The actual `scope[i]` and `credCommitment[i]` values that decompose each `scopeCommit[i]` remain private inputs hidden by Poseidon preimage resistance.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope commitment `Poseidon2(scope, credCommitment)` | Identity-bound scope commitment | `draft-bolyra-mutual-zkp-auth-01` §5 |
| Delegation nullifier `Poseidon2(delegationTokenHash, sessionNonce)` | Delegation nullifier | Delegation circuit public output index 1 |
| Nullifier-scope digest `Poseidon2(delegationNullifier, scopeCommit)` | New binding primitive; composed from two existing Poseidon2 outputs already stored on-chain | Constraint 8 of this construction |
| 64-bit permission bitmask with cumulative encoding | Bolyra permission model (bits 0–7 active, 8–63 reserved) | `CLAUDE.md` Permissions Model |
| `previousScopeCommitment` → `newScopeCommitment` chain | On-chain `lastScopeCommitment` mapping | `draft-bolyra-mutual-zkp-auth-01` §5.1 |
| `rootScopeCommitment` from handshake | `agentPubSignals[2]` stored by registry | Handshake verification step 6b |
| PLONK proving system | Agent/Delegation PLONK option | `CLAUDE.md` Circuits table |
| `sessionNonce` binding | Handshake session nonce | `draft-bolyra-mutual-zkp-auth-01` §4.1 |
| Poseidon hash (BN254 scalar field) | Required hash function | `draft-bolyra-mutual-zkp-auth-01` §3.2 |
| Baby Jubjub EdDSA | Operator signature scheme (used in underlying delegation proofs, not re-verified in audit circuit) | `draft-bolyra-mutual-zkp-auth-01` §3.2 |

The audit circuit does NOT re-verify EdDSA signatures or Merkle membership — those are already enforced by the per-hop `Delegation` circuit proofs verified on-chain. The audit circuit operates one layer above: it proves the *structural property* (monotonic narrowing) over the chain of already-verified hops, and the nullifier-scope binding (constraint 8) ensures the structural proof is anchored to the actual on-chain delegation state rather than fabricated witness data.

### On-chain registry requirement

The `DelegationVerified` event MUST emit both `delegationNullifier` and `newScopeCommitment` as indexed fields. The existing Bolyra delegation circuit already outputs both values (public signal indices 1 and 0 respectively), and the registry already stores `newScopeCommitment` in the `lastScopeCommitment` mapping. The only new requirement is that the event log includes both values in a form the auditor can query — this is already the case in the current registry design.

## 6. Circuit cost estimate

### Constraint breakdown (MAX_HOPS = 8):

| Component | Constraints per hop | Total |
|-----------|-------------------|-------|
| `Num2Bits(64)` for scope | 64 | 512 |
| `Poseidon2` for scope commitment | ~300 | 2,400 |
| `Poseidon2` for nullifier-scope binding (hopDigest) | ~300 | 2,400 |
| Inactive-hop zero constraints (2 per hop) | 2 | 16 |
| Bitwise subset check (64 bits, 7 active pairs) | 64 per pair | 448 |
| Cumulative bit encoding | 3 | 24 |
| Hop activation logic (binary + monotonicity) | ~5 | 40 |
| Terminal multiplexer (8-way, 64 bits) | ~200 | 200 |
| Policy mask check (64 bits) | 64 | 64 |
| `PoseidonN(8)` for chain anchor (over hopDigests) | ~600 | 600 |
| Chain length consistency | ~16 | 16 |
| **Total** | | **~6,720** |

### Delta from prior construction:

The nullifier-scope binding adds ~2,416 constraints (8 × Poseidon2 + 8 × 2 zero-constraints), increasing the total from ~4,300 to ~6,720. This is a 56% increase but remains well within budget.

### Proving time targets:

| System | Constraints | Target | Rationale |
|--------|------------|--------|-----------|
| PLONK (agent-class) | ~6,720 | **< 2 seconds** | Well under the 5s PLONK agent budget; smaller than `AgentPolicy` (~18K) |
| Groth16 (optional) | ~6,720 | **< 1 second** | If circuit-specific ceremony is acceptable |

### Comparison to existing circuits:

- `HumanUniqueness`: ~12,000 constraints → 6,720 is 1.8× smaller
- `AgentPolicy`: ~18,000 constraints → 6,720 is 2.7× smaller
- `Delegation`: ~22,000 constraints → 6,720 is 3.3× smaller

The circuit remains lightweight because it delegates EdDSA verification and Merkle membership to the per-hop `Delegation` proofs already verified on-chain. The new Poseidon2 calls for nullifier-scope binding are the cost of closing the soundness gap — a necessary trade.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI pipeline audit at Navy Federal Credit Union

**Stakeholder**: Navy Federal Credit Union (NFCU), largest US credit union with $176B in assets. Subject to NCUA examination and FFIEC guidance on third-party AI agent use.

**Setup**: NFCU deploys an AI agent pipeline for member loan origination:
1. **Hop 0 (root)**: Member's personal AI assistant (e.g., Claude) — full `READ_DATA | WRITE_DATA | FINANCIAL_SMALL | ACCESS_PII` (bitmask `0b10000111 = 0x87`)
2. **Hop 1**: NFCU's loan intake agent — narrows to `READ_DATA | WRITE_DATA | FINANCIAL_SMALL` (bitmask `0b00000111 = 0x07`, drops `ACCESS_PII`)
3. **Hop 2**: Third-party credit scoring agent (TransUnion) — narrows to `READ_DATA` only (bitmask `0b00000001 = 0x01`)
4. **Hop 3**: NFCU's underwriting agent — narrows to `READ_DATA | FINANCIAL_SMALL` (bitmask `0b00000101 = 0x05`)

**Audit trigger**: NCUA examiner requests proof that the pipeline respected least-privilege at every hop, per FFIEC guidance on AI model risk management (SR 11-7 analogue).

**Without Bolyra** (baseline): NFCU must disclose the full delegation token chain to the examiner, revealing:
- TransUnion's involvement (competitive intelligence)
- The specific permission bitmasks at each hop (proprietary pipeline architecture)
- Each agent's credential commitment (linkable across examinations)

The examiner must also trust NFCU's Authorization Server enforced the narrowing — or inspect its policy engine.

**With Bolyra `DelegationChainAudit`**:

1. NFCU's compliance agent generates a PLONK proof with:
   - Public inputs: `rootScopeCommitment` (from handshake event), `chainLength = 4`, `sessionNonce`, `auditPolicyMask = 0x01` (examiner checks terminal agent had at least `READ_DATA`)
   - Private inputs: all 4 scopes, credential commitments, delegation nullifiers

2. Examiner receives: `(proof, narrowingValid=1, policyOk=1, chainAnchor, terminalScopeCommitment)`

3. Examiner verifies:
   - PLONK proof checks out (no trust in NFCU's systems required)
   - Reconstructs each `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` from on-chain `DelegationVerified` events, hashes all 8 digests (4 real + 4 zero-padded), and confirms the result equals `chainAnchor` — this proves the in-circuit scopes are the actual on-chain scopes, not fabricated values
   - `terminalScopeCommitment` matches `lastScopeCommitment[sessionNonce]` on-chain
   - `narrowingValid = 1` — monotonic narrowing held at every hop
   - `policyOk = 1` — terminal agent had at least `READ_DATA`

4. Examiner learns: the chain has 4 hops, narrowing held, and the terminal agent satisfied the policy. Examiner does NOT learn: who the intermediate agents are, what specific permissions each had, or the pipeline architecture.

**Why nullifier-scope binding matters in this scenario**: Without constraint 8, a compromised NFCU compliance agent could generate a proof using the real on-chain nullifiers (which the examiner can verify exist) but substitute fabricated scope values that narrow nicely — even if the actual pipeline violated least-privilege at hop 2. The binding forces the proof to use the actual scope commitments recorded on-chain alongside each nullifier, making such fabrication detectable.

### Journalist/source variant:

A journalist's agent delegates to a source's agent through two intermediary relay agents. The journalist generates the audit proof. An editor (auditor) verifies the delegation chain narrowed properly (the source's agent could only `READ_DATA`, not `WRITE_DATA` or `SIGN_ON_BEHALF`) without learning the identities of the relay agents or the source. The `chainAnchor` — now binding nullifiers to scope commitments — lets the editor verify both the chain's existence and its scope integrity against on-chain events, without correlating participants.

## 8. Why the baseline cannot match

| Capability | Bolyra `DelegationChainAudit` | Baseline (RFC 8693 + BBS+ + WIMSE) |
|-----------|------------------------------|-------------------------------------|
| **Prove narrowing without disclosing scopes** | Bitwise subset check runs on private inputs inside the circuit. Nullifier-scope binding (constraint 8) ensures the private inputs correspond to actual on-chain state, not fabricated values. Auditor sees only `narrowingValid = 1`. | BBS+ can hide individual claims but cannot prove `scope[i] ⊆ scope[i-1]` over hidden bitmasks. The AS log records narrowing, but communicating proof requires disclosing scope values or trusting the AS assertion. |
| **Anchor proof to actual chain state** | Each `hopDigest[i] = Poseidon2(nullifier_i, scopeCommit_i)` binds the nullifier to its scope commitment inside the circuit. The auditor cross-references each pair against on-chain events. A prover who substitutes fake scopes produces a non-matching `chainAnchor`. | RFC 8693 tokens are bearer artifacts. An auditor verifying a token chain trusts that the AS issued them correctly. There is no cryptographic binding between the token's scope and an independently verifiable anchor — the AS is the anchor. |
| **Hide intermediate participants** | All `credCommitment[i]` values are private inputs. Auditor sees only the `chainAnchor` (hash of bound nullifier-scope pairs). | RFC 8693 `act` claim tree is plaintext. BBS+ selective disclosure operates within a single credential, not across a multi-issuer chain. No standard mechanism hides participants in a multi-hop delegation. |
| **No trusted third party** | PLONK proof is self-verifiable. The nullifier-scope binding ensures the proof's scopes match on-chain reality without querying any authority — the BN254 pairing check and Poseidon preimage binding are the only trust assumptions. | RFC 8693 narrowing enforcement requires the Authorization Server. Auditor who cannot query or trust the AS has no narrowing guarantee. AS compromise breaks the entire chain. |
| **Cross-org without shared AS** | Each hop's delegation proof is independently verified on-chain. The audit circuit chains scope commitments across organizational boundaries using Poseidon — no shared AS or federation protocol needed. | Cross-org delegation requires either a shared AS or WIMSE federation trust anchor. No standard produces a single artifact proving cross-org monotonic narrowing without a common authority that sees all scopes. |
| **Journalist/source anonymity** | Participant identities never appear in any public output. Nullifiers are pseudonymous (Poseidon2 of delegation token hash + nonce) and unlinkable across sessions. | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-to-RS correlation but not AS or auditor correlation via the `act` chain. No mechanism proves "a legitimate holder participated at hop k" without identifying them. |
| **In-circuit enforcement at presentation** | Narrowing is proven in-circuit at the moment the audit proof is generated. The proof IS the enforcement — no gap between issuance-time policy and presentation-time reality. | RFC 8693 enforces narrowing at issuance. Post-issuance, tokens can be presented to any accepting RS. No runtime binding between the narrowing proof and the credential's actual use. |
| **Offline verifiability** | PLONK proof + on-chain event cross-reference. No real-time API calls to any authority. | RFC 7662 introspection requires live AS queries. Signed introspection responses (draft-ietf-oauth-jwt-introspection-response) are offline-verifiable but still reveal scope values. |
| **Composability with Bolyra handshake** | `rootScopeCommitment` directly chains from the `HandshakeVerified` event. The audit proof extends the existing Bolyra proof pipeline with zero protocol changes to the handshake or delegation circuits. | Integrating RFC 8693 with a ZKP handshake requires a custom bridge layer. No standard defines how OAuth token exchange interoperates with on-chain ZKP verification. |

**The structural impossibility**: BBS+ provides selective disclosure of *attributes within a single credential*. Monotonic narrowing is a *relational property across a sequence of credentials*. Proving `∀i: scope[i] ⊆ scope[i-1]` over hidden values requires arithmetic over those values — exactly what an R1CS/PLONK circuit provides and what BBS+ signature schemes do not. The nullifier-scope binding further widens the gap: even if BBS+ could somehow prove a relational property over hidden scopes, it has no mechanism to bind each proof step to an independently verifiable on-chain anchor without revealing the scope values. No composition of BBS+ derived proofs, RFC 8693 token exchanges, or WIMSE attestations can produce a self-verifiable proof of a relational invariant over hidden multi-credential state that is simultaneously anchored to on-chain reality, without introducing a trusted aggregator — which reintroduces the single-point-of-trust that the construction eliminates.
