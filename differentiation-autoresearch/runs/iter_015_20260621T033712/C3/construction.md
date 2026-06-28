# Construction

## 1. Statement of claim

An auditor verifies that an N-hop delegation chain narrowed permissions monotonically — each hop's scope is a bitwise subset of its predecessor's, and each hop's expiry is no later than its predecessor's — without learning any intermediate scope values, participant identities, credential commitments, or Merkle tree positions. The proof is a single PLONK proof over a self-contained `DelegationAuditChain` circuit that re-proves the entire chain from scratch (no reliance on a trusted Authorization Server or on-chain intermediate state), anchored only to the root scope commitment emitted by the original handshake.

## 2. Construction (gadgets, circuits, public/private inputs)

### New circuit: `DelegationAuditChain(MAX_HOPS, MAX_DEPTH)`

Parameters: `MAX_HOPS = 8`, `MAX_DEPTH = 20`.

**Private inputs (per hop `i`, 0 ≤ i < MAX_HOPS):**

| Signal | Type | Description |
|--------|------|-------------|
| `hopActive[i]` | bit | 1 if hop i is real, 0 if padding |
| `delegatorScope[i]` | uint64 | Delegator permission bitmask |
| `delegateeScope[i]` | uint64 | Delegatee permission bitmask |
| `delegatorExpiry[i]` | uint64 | Delegator expiry timestamp |
| `delegateeExpiry[i]` | uint64 | Delegatee expiry timestamp |
| `delegatorCredCommitment[i]` | field | Poseidon5 of delegator credential |
| `delegateeCredCommitment[i]` | field | Poseidon5 of delegatee credential |
| `delegatorPubkeyAx[i]`, `delegatorPubkeyAy[i]` | field | Delegator EdDSA public key |
| `sigR8x[i]`, `sigR8y[i]`, `sigS[i]` | field | Delegator EdDSA signature |
| `delegateeMerkleProofSiblings[i][MAX_DEPTH]` | field[] | Delegatee Merkle proof |
| `delegateeMerkleProofIndex[i]` | field | Delegatee leaf index |
| `delegateeMerkleProofLength[i]` | field | Delegatee proof depth |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `rootScopeCommitment` | Scope commitment from the handshake (chain anchor) |
| `sessionNonce` | Session binding (ties audit to a specific handshake) |
| `chainLength` | Number of active hops (1..MAX_HOPS) |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `finalScopeCommitment` | Terminal scope commitment after all hops |
| `auditNullifier` | Poseidon2(rootScopeCommitment, sessionNonce) — replay prevention |
| `finalDelegateeMerkleRoot` | Merkle root of the terminal delegatee (enrollment anchor) |

### Constraint logic (per hop i):

```
// 1. Range checks
Num2Bits(64)(delegatorScope[i])
Num2Bits(64)(delegateeScope[i])
Num2Bits(64)(delegatorExpiry[i])
Num2Bits(64)(delegateeExpiry[i])

// 2. Chain linking — delegator's scope commitment must match prior hop output
// For hop 0: must match rootScopeCommitment (public input)
// For hop i>0: must match newScopeCommitment from hop i-1
let prevSC = (i == 0) ? rootScopeCommitment : newScopeCommitment[i-1]
let computedDelegatorSC = Poseidon2(delegatorScope[i], delegatorCredCommitment[i])
hopActive[i] * (computedDelegatorSC - prevSC) === 0

// 3. Monotonic scope narrowing (bitwise subset)
let delegatorBits = Num2Bits(64)(delegatorScope[i])
let delegateeBits = Num2Bits(64)(delegateeScope[i])
for bit j in [0, 64):
    hopActive[i] * delegateeBits[j] * (1 - delegatorBits[j]) === 0

// 4. Cumulative bit encoding on delegatee scope
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[3]) === 0
hopActive[i] * delegateeBits[4] * (1 - delegateeBits[2]) === 0
hopActive[i] * delegateeBits[3] * (1 - delegateeBits[2]) === 0

// 5. Expiry narrowing
hopActive[i] * LessEqThan(64)(delegateeExpiry[i], delegatorExpiry[i]) === 1

// 6. Delegation token
let delegationToken = Poseidon4(prevSC, delegateeCredCommitment[i],
                                 delegateeScope[i], delegateeExpiry[i])

// 7. EdDSA signature verification
hopActive[i] * EdDSAPoseidonVerifier(
    delegatorPubkeyAx[i], delegatorPubkeyAy[i],
    sigR8x[i], sigR8y[i], sigS[i],
    delegationToken
) === hopActive[i]

// 8. Delegatee enrollment (Merkle membership)
let delegateeMerkleRoot[i] = BinaryMerkleRoot(MAX_DEPTH)(
    delegateeCredCommitment[i],
    delegateeMerkleProofLength[i],
    delegateeMerkleProofIndex[i],
    delegateeMerkleProofSiblings[i]
)

// 9. New scope commitment for chain propagation
newScopeCommitment[i] = Poseidon2(delegateeScope[i], delegateeCredCommitment[i])

// 10. Inactive hop identity: if !hopActive, propagate prior scope commitment
// finalSC = hopActive[i] ? newScopeCommitment[i] : prevSC
```

**Terminal outputs:**
```
finalScopeCommitment = newScopeCommitment[chainLength - 1]
auditNullifier = Poseidon2(rootScopeCommitment, sessionNonce)
finalDelegateeMerkleRoot = delegateeMerkleRoot[chainLength - 1]
```

### Inactive hop handling

For hop `i ≥ chainLength`, `hopActive[i] = 0`. All constraint multiplications by `hopActive` evaluate to 0, making those hops trivially satisfiable. The scope commitment propagates unchanged through inactive hops via a mux: `effectiveSC[i] = hopActive[i] * newScopeCommitment[i] + (1 - hopActive[i]) * prevSC[i]`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary capabilities

The adversary **A** controls:
- All intermediate delegation agents (keys, credentials, enrollment)
- The chain construction (can pick any scope values, expiry values, credential commitments)
- The proving environment (can attempt to forge proofs)

The adversary **sees**:
- `rootScopeCommitment`, `finalScopeCommitment`, `chainLength`, `sessionNonce`, `auditNullifier`, `finalDelegateeMerkleRoot`
- The PLONK proof π

The adversary does **NOT** control:
- The Poseidon hash function (modeled as a random oracle for collision resistance arguments)
- The Baby Jubjub discrete-log problem
- The PLONK/Groth16 CRS (trusted setup or universal SRS)

### Game 1: Narrowing Soundness

```
NarrowingSoundness(A, λ):
  1. A chooses a delegation chain of length N with scope values
     s_0, s_1, ..., s_N where ∃ hop k: s_k ⊄ s_{k-1}
     (i.e., some bit is set in s_k that is not set in s_{k-1})
  2. A produces (π, rootScopeCommitment, finalScopeCommitment,
     chainLength, sessionNonce)
  3. A wins if Verify(vk, π, public_signals) = 1
```

**Claim:** Pr[A wins] ≤ negl(λ) under knowledge soundness of PLONK over BN128.

### Game 2: Participant Privacy

```
ParticipantPrivacy(A, λ):
  1. Challenger picks two delegation chains C_0, C_1 of equal length N,
     with identical rootScopeCommitment and finalScopeCommitment,
     but different intermediate participants and scope values
  2. Challenger picks b ← {0, 1}, generates proof π_b for chain C_b
  3. A sees (π_b, rootScopeCommitment, finalScopeCommitment, chainLength)
  4. A outputs guess b'
  5. A wins if b' = b
```

**Claim:** |Pr[b' = b] - 1/2| ≤ negl(λ) under the zero-knowledge property of PLONK.

### Game 3: Chain Forgery (splice attack)

```
ChainForgery(A, λ):
  1. A produces a valid audit proof for rootScopeCommitment = sc_root
  2. But the chain does NOT start from a delegator whose
     Poseidon2(scope, credCommitment) = sc_root
  3. A wins if Verify(vk, π, public_signals) = 1
```

**Claim:** Pr[A wins] ≤ negl(λ) under Poseidon collision resistance (the adversary would need to find (scope', credComm') ≠ (scope, credComm) with Poseidon2(scope', credComm') = sc_root).

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

1. **Knowledge soundness of PLONK** (alternatively Groth16) over the BN128 pairing group in the algebraic group model + random oracle model (AGM+ROM).
2. **Poseidon collision resistance** over BN254 scalar field F_p — no efficient algorithm finds (x, y) ≠ (x', y') with Poseidon2(x, y) = Poseidon2(x', y'). Extends to Poseidon4, Poseidon5.
3. **Discrete logarithm hardness on Baby Jubjub** — given (Ax, Ay) = s·G, no efficient algorithm recovers s.
4. **EdDSA existential unforgeability** under chosen-message attack (EUF-CMA) on Baby Jubjub with Poseidon hash, reducing to DL hardness + Poseidon modeled as a random oracle.

### Reduction sketch: Narrowing Soundness

Suppose adversary A breaks NarrowingSoundness with non-negligible probability ε. By knowledge soundness of PLONK, there exists an extractor E that, given A's proof π, extracts witnesses (delegatorScope[i], delegateeScope[i], ...) for all hops with probability ≥ ε - negl(λ).

The extracted witnesses satisfy all circuit constraints. In particular, for every active hop k:

```
hopActive[k] * delegateeBits[k][j] * (1 - delegatorBits[k][j]) === 0
    for all j ∈ [0, 64)
```

This means for every active hop, every bit set in `delegateeScope` is also set in `delegatorScope` — i.e., `delegateeScope[k] & ~delegatorScope[k] == 0`, which is the definition of `delegateeScope[k] ⊆ delegatorScope[k]`.

Therefore A's chain must satisfy monotonic narrowing at every hop, contradicting the assumption that some hop expands scope. Contradiction. ∎

### Reduction sketch: Chain Integrity

The chain-linking constraint at hop 0 enforces `Poseidon2(delegatorScope[0], delegatorCredCommitment[0]) = rootScopeCommitment`. By Poseidon collision resistance, the extracted (delegatorScope[0], delegatorCredCommitment[0]) is the unique preimage. Each subsequent hop similarly links via the scope commitment. Therefore the entire chain is cryptographically bound to the root, and splicing a different chain requires a Poseidon collision. ∎

### Privacy argument

By the honest-verifier zero-knowledge property of PLONK (composable ZK in the AGM+ROM), the proof π reveals no information about private inputs beyond what is deducible from the public signals. Since intermediate scope values, credential commitments, Merkle paths, and EdDSA keys are all private inputs, the auditor learns only `rootScopeCommitment`, `finalScopeCommitment`, `chainLength`, `auditNullifier`, and `finalDelegateeMerkleRoot`. ∎

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|------------------|----------------|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Identity-Bound Scope Commitment Chain |
| Credential commitment | `Poseidon5(modelHash, opPubAx, opPubAy, permissionBitmask, expiryTimestamp)` | §3.2 Agent Proof Specification |
| Delegation token | `Poseidon4(prevScopeCommitment, delegateeCredCommitment, delegateeScope, delegateeExpiry)` | §4.2 Delegation Circuit, constraint 6 |
| EdDSA signature | `EdDSAPoseidonVerifier` on Baby Jubjub | §2.2 Cryptographic Primitives |
| Merkle membership | `BinaryMerkleRoot(MAX_DEPTH=20)` with Poseidon2 | §2.2 |
| Scope subset | Per-bit `delegateeBits[j] * (1 - delegatorBits[j]) === 0` | §4.2 constraint 3 |
| Cumulative encoding | Bits 4→3→2 implication chain | §4.2 constraint 4 |
| Nullifier | `Poseidon2(rootScopeCommitment, sessionNonce)` | Adapted from §3.2 agent nullifier pattern |
| Chain anchor | `rootScopeCommitment` from `HandshakeVerified` event | §3.1 step 6b |
| Proving system | PLONK with universal setup (pot17.ptau) | §2.3 OPTIONAL for Delegation circuits |

All hash functions, curves, signature schemes, and constraint patterns are drawn directly from the Bolyra spec. No new primitives are introduced — only a new composition of existing ones into a single circuit.

## 6. Circuit cost estimate

### Per-hop constraint breakdown

| Gadget | Constraints | Count per hop |
|--------|------------|---------------|
| Num2Bits(64) range checks (×4) | 256 | 4 fields |
| Poseidon2 (delegator scope commitment) | 300 | 1 |
| Poseidon2 (new scope commitment) | 300 | 1 |
| Poseidon4 (delegation token) | 450 | 1 |
| Poseidon2 (audit nullifier, hop 0 only) | 300 | 0-1 |
| EdDSAPoseidonVerifier | 6,000 | 1 |
| BinaryMerkleRoot(20) | 6,200 | 1 |
| Scope subset (64 AND gates) | 64 | 1 |
| Cumulative bit encoding | 3 | 1 |
| LessEqThan(64) expiry | 200 | 1 |
| hopActive mux + chain propagation | 80 | 1 |
| **Subtotal per hop** | **~13,850** | |

### Total circuit size

| Chain length | Constraints | SRS required | Proving time (rapidsnark) | Proving time (snarkjs) |
|-------------|-------------|-------------|--------------------------|----------------------|
| 4 hops | ~55,700 | pot16.ptau | ~3s | ~25s |
| 8 hops | ~111,100 | pot17.ptau | ~6s | ~50s |

PLONK proof size: ~800 bytes (constant regardless of circuit size).
Groth16 proof size: 128 bytes (if Groth16 preferred for on-chain gas efficiency).

The 8-hop configuration at ~111K constraints fits within pot17.ptau (2^17 = 131,072 constraints). For deployments that want to stay within the existing pot16.ptau (2^16 = 65,536), a 4-hop maximum is viable.

## 7. Concrete deployment scenario

### Scenario: Multi-agent loan origination pipeline at Navy Federal Credit Union

**Context:** Navy Federal Credit Union (NFCU, $170B assets, 13M members) deploys an AI-assisted loan origination pipeline. A member initiates a home equity loan application through a conversational AI agent. The pipeline involves:

1. **Agent A** (member-facing chatbot): `READ_DATA | WRITE_DATA | ACCESS_PII` (bits 0,1,7 → bitmask `0b10000011 = 0x83`)
2. **Agent B** (credit decisioning model): `READ_DATA | FINANCIAL_SMALL | FINANCIAL_MEDIUM` (bits 0,2,3 → bitmask `0b00001101 = 0x0D`). Delegated from A with PII stripped — bit 7 removed.
3. **Agent C** (document generation): `READ_DATA | WRITE_DATA` (bits 0,1 → bitmask `0b00000011 = 0x03`). Delegated from B with financial permissions stripped.
4. **Agent D** (e-signature orchestrator): `READ_DATA` (bit 0 → bitmask `0b00000001 = 0x01`). Delegated from C with write stripped.

**Audit trigger:** The NCUA examiner conducting a safety-and-soundness exam requires proof that the AI pipeline's delegation chain was properly scoped — no agent exceeded its mandate. Under current NCUA guidelines, the CU must demonstrate adequate controls over third-party/fintech relationships (NCUA Letter 23-CU-15).

**What the examiner sees** (public signals only):
- `rootScopeCommitment`: opaque hash (verifiable against handshake event)
- `finalScopeCommitment`: opaque hash
- `chainLength = 4`
- `auditNullifier`: replay-prevention token
- `finalDelegateeMerkleRoot`: verifiable against on-chain agent registry

**What the examiner does NOT see:**
- Which specific AI models were used (no `modelHash` revealed)
- Which operator signed each credential (no public keys revealed)
- The actual permission bitmasks at any hop (no scope values revealed)
- The Merkle tree positions of any agent (no enrollment indices revealed)

**What the examiner can verify:**
- The chain started from a valid mutual handshake (cross-reference `rootScopeCommitment` with on-chain `HandshakeVerified` event)
- Every hop narrowed permissions monotonically (circuit soundness)
- The terminal agent was a legitimately enrolled entity (cross-reference `finalDelegateeMerkleRoot` with on-chain agent registry root history buffer)
- The proof has not been replayed (audit nullifier uniqueness)

**Verification cost:** A single PLONK `verify()` call on-chain (~300K gas on Base) or off-chain (< 10ms in snarkjs).

### Scenario 2: Journalist/source whistleblower chain

A source inside a financial institution uses a chain of AI agents to relay redacted evidence to an investigative journalist. Each hop strips identifying metadata:

1. **Source agent**: full access to internal documents
2. **Redaction agent**: strips PII, retains financial data
3. **Relay agent**: strips financial specifics, retains summary
4. **Journalist-facing agent**: read-only summary access

The journalist publishes the audit proof alongside the story. Any reader can verify that the delegation chain narrowed monotonically (the source's agent had broader access than the journalist's agent), without learning the source's identity, the intermediate agents' identities, or what specific permissions were held at any hop. The `rootScopeCommitment` is verified against a public handshake event, but the scope commitment is a Poseidon hash — it reveals nothing about the source's actual credential.

## 8. Why the baseline cannot match

| Capability | DelegationAuditChain | RFC 8693 + BBS+ + WIMSE |
|-----------|---------------------|------------------------|
| **Prove narrowing over hidden scopes** | Circuit enforces `delegateeBits[j] * (1 - delegatorBits[j]) === 0` per hop, over private inputs. Auditor sees only the proof. | BBS+ can hide individual claims but cannot prove an ordering/subset relationship over hidden bitmasks. The AS can assert narrowing, but the auditor must trust the AS or see the scopes. |
| **Hide intermediate participants** | All credential commitments, public keys, and Merkle paths are private inputs. Zero-knowledge property guarantees no leakage. | RFC 8693 `act` claim tree is plaintext. BBS+ operates within a single credential, not across a multi-issuer chain. No mechanism to hide who delegated to whom. |
| **No trusted third party** | Proof is self-contained. Verification requires only the PLONK verification key (public) and public signals. No AS needed. | RFC 8693 narrowing is enforced by the AS at issuance time. Auditor assurance requires AS trust or AS policy logs. AS compromise breaks the guarantee. |
| **Cross-org chain audit** | The circuit is organization-agnostic. Any enrolled agent (in the shared Merkle tree) can participate. No shared AS or federation anchor needed. | Cross-org delegation requires a shared AS or WIMSE federation trust anchor. No single standard produces a unified narrowing proof across trust domains. |
| **Whistleblower/source anonymity** | Intermediate identities are private inputs. Even the number of distinct organizations is hidden (only `chainLength` is revealed). | WIMSE SPIFFE IDs are stable identifiers. OIDC PPIDs prevent RS-vs-RS correlation but not auditor correlation via the `act` chain. No mechanism for anonymous participation. |
| **Runtime enforcement** | Narrowing is enforced cryptographically at proof-generation time. A proof for a non-narrowing chain cannot be generated (circuit unsatisfiable). | AS enforces narrowing at issuance. After issuance, the token exists independently — no runtime check that the token is used within its narrowed scope unless the RS independently validates. |
| **Offline verifiability** | PLONK proof is verifiable by anyone with the verification key. No network call, no AS query, no introspection endpoint. | RFC 7662 introspection requires the AS to be online. Signed introspection responses (draft-ietf-oauth-jwt-introspection-response) help but still require AS signing key trust. |

The fundamental gap is structural: the baseline's narrowing assurance flows through a trusted intermediary (the Authorization Server) that sees all scopes in cleartext. Removing the AS removes the assurance. The `DelegationAuditChain` circuit replaces AS trust with mathematical proof — narrowing is verified by constraint satisfaction, not by institutional trust — and does so over encrypted (private) inputs that the auditor never sees.
