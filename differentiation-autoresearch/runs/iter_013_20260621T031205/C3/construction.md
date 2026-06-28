# Construction

## 1. Statement of claim

An auditor verifies that a multi-hop delegation chain narrowed permissions monotonically — each hop's scope is a bitwise subset of its parent, each hop's expiry is ≤ its parent, and every participant is an enrolled agent — without learning any intermediate scope values, participant identities, or the structure of the chain beyond its length. The proof is a single constant-size artifact that works across organizational boundaries without a shared authorization server, and covers AI-agent tool-call pipelines and whistleblower-safe source chains equally.

## 2. Construction (gadgets, circuits, public/private inputs)

### Circuit 1: `DelegationHopAccumulator` (PLONK, per-hop)

This is a modified version of the existing `Delegation` circuit that additionally computes a running accumulator hash over the chain, enabling a final audit proof that summarizes the entire chain without revealing per-hop details.

**Private inputs:**

| Signal | Width | Description |
|--------|-------|-------------|
| `delegatorScope` | 64 bits | Delegator permission bitmask |
| `delegateeScope` | 64 bits | Delegatee permission bitmask |
| `delegatorExpiry` | 64 bits | Delegator expiry timestamp |
| `delegateeExpiry` | 64 bits | Delegatee expiry timestamp |
| `delegatorPubkeyAx`, `delegatorPubkeyAy` | field | Delegator EdDSA pubkey |
| `sigR8x`, `sigR8y`, `sigS` | field | Delegator signature over delegation token |
| `delegatorCredCommitment` | field | Delegator credential commitment |
| `delegateeCredCommitment` | field | Delegatee credential commitment |
| `delegateeMerkleProofLength`, `delegateeMerkleProofIndex`, `delegateeMerkleProofSiblings[20]` | field | Delegatee enrollment proof |
| `previousAccumulator` | field | Running chain accumulator from prior hop |
| `hopIndex` | 8 bits | Position in chain (0-indexed) |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `previousScopeCommitment` | Chain-link from prior hop (read from on-chain state) |
| `sessionNonce` | Session binding |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `newScopeCommitment` | Poseidon2(delegateeScope, delegateeCredCommitment) |
| `delegationNullifier` | Poseidon2(delegationTokenHash, sessionNonce) |
| `delegateeMerkleRoot` | Delegatee enrollment root |
| `newAccumulator` | Poseidon3(previousAccumulator, newScopeCommitment, hopIndex) |

**Constraints (beyond existing Delegation circuit):**

1. All existing Delegation constraints (range checks, chain linking, scope subset, cumulative bit encoding, expiry narrowing, EdDSA signature, delegatee enrollment).
2. `newAccumulator = Poseidon3(previousAccumulator, newScopeCommitment, hopIndex)` — chains the accumulator forward.
3. `hopIndex` range-checked via Num2Bits(8) — max 255 hops.

### Circuit 2: `ChainAuditProof` (PLONK, once per audit)

This circuit proves that a complete delegation chain was accumulated correctly and that the final scope satisfies an auditor-specified minimum policy, without revealing any intermediate state.

**Private inputs:**

| Signal | Width | Description |
|--------|-------|-------------|
| `chainSeed` | field | The initial scopeCommitment from the handshake |
| `finalAccumulator` | field | The accumulator after the last hop |
| `hopCount` | 8 bits | Number of hops in the chain |
| `finalScope` | 64 bits | Terminal delegatee's permission bitmask |
| `finalCredCommitment` | field | Terminal delegatee's credential commitment |
| `rootScope` | 64 bits | Root delegator's permission bitmask |
| `rootCredCommitment` | field | Root delegator's credential commitment |
| `accumulatorTrace[MAX_HOPS]` | field[] | Per-hop accumulator values |
| `scopeCommitmentTrace[MAX_HOPS]` | field[] | Per-hop scope commitments |

**Public inputs:**

| Signal | Description |
|--------|-------------|
| `auditPolicyMask` | Auditor's minimum required permission bits at the terminal |
| `sessionNonce` | Session binding |
| `onChainChainSeed` | The handshake-stored initial scopeCommitment (read from contract) |

**Public outputs:**

| Signal | Description |
|--------|-------------|
| `auditResult` | 1 if chain is valid and policy-satisfying, 0 otherwise |
| `chainLength` | Number of hops (revealed to auditor) |
| `chainDigest` | Poseidon2(finalAccumulator, sessionNonce) — unique chain fingerprint |

**Constraints:**

1. **Seed binding:** `chainSeed === onChainChainSeed` — anchors the proof to the on-chain handshake.
2. **Root scope commitment:** `Poseidon2(rootScope, rootCredCommitment) === chainSeed` — the chain starts from the root delegator.
3. **Accumulator initialization:** `accumulatorTrace[0] === Poseidon3(0, chainSeed, 0)` — accumulator starts from zero with the seed.
4. **Accumulator chain:** For `i` in `[1, hopCount)`: `accumulatorTrace[i] === Poseidon3(accumulatorTrace[i-1], scopeCommitmentTrace[i], i)`.
5. **Final accumulator match:** `accumulatorTrace[hopCount - 1] === finalAccumulator`.
6. **Final scope commitment:** `Poseidon2(finalScope, finalCredCommitment) === scopeCommitmentTrace[hopCount - 1]`.
7. **Terminal policy satisfaction:** For each bit `i` in `[0, 64)`: `auditPolicyBits[i] * (1 - finalScopeBits[i]) === 0`.
8. **Cumulative bit encoding on finalScope:** Standard Bolyra cumulative constraints on bits 2/3/4.
9. **Chain length output:** `chainLength === hopCount`.
10. **Chain digest:** `chainDigest = Poseidon2(finalAccumulator, sessionNonce)`.
11. **Audit result:** `auditResult = 1` (constrained — proof generation fails if chain is invalid).
12. **Unused trace slots:** For `i >= hopCount`, `accumulatorTrace[i]` and `scopeCommitmentTrace[i]` are multiplexed out (standard padding pattern).

**MAX_HOPS = 16** (covers practical multi-tool pipelines; configurable at compile time).

### Gadget: `ScopeSubsetAccumulator`

Reusable sub-circuit used in both circuits above:

```
template ScopeSubsetAccumulator() {
    signal input parentScope;
    signal input childScope;
    // Decomposes both, asserts childBits[i] * (1 - parentBits[i]) === 0
    // Asserts cumulative bit encoding on childScope
}
```

### On-chain components

**`BolyraAuditRegistry.sol`** — extension of the existing registry:

- `mapping(bytes32 => uint256) public chainAccumulators` — stores the latest accumulator per sessionNonce.
- `function submitDelegationHop(...)` — verifies `DelegationHopAccumulator` PLONK proof, updates `chainAccumulators[sessionNonce]` and `lastScopeCommitment[sessionNonce]`.
- `function verifyChainAudit(...)` — verifies `ChainAuditProof` PLONK proof, emits `ChainAudited(sessionNonce, chainLength, chainDigest, auditPolicyMask)`.

## 3. Threat model (adversary capabilities, game definition)

### Adversary model

The adversary `A` controls up to `n-1` of `n` delegation participants. `A` also controls the auditor's view (i.e., `A` can act as auditor). `A` has access to all public signals, on-chain state, and the verification keys. Crucially, `A` may operate across organizational boundaries — different hops may belong to different trust domains with no shared authorization server, no shared BBS+ issuer, and no federated credential infrastructure. The auditor is *distrusting*: it accepts only publicly verifiable cryptographic proofs, not signed attestations from any single organization's infrastructure.

### Game: Delegation Audit Soundness

```
Game DelegationAuditSoundness(λ):
  1. Challenger sets up Bolyra (circuits, keys, Merkle trees).
  2. A adaptively enrolls agents, creates delegation chains,
     and submits per-hop proofs to the on-chain registry.
  3. A wins if it produces a valid ChainAuditProof π where:
     (a) auditResult = 1, AND
     (b) there exists some hop k in the actual chain where
         scope_k is NOT a bitwise subset of scope_{k-1},
         OR delegatee_k is not enrolled,
         OR expiry_k > expiry_{k-1}.

  Advantage: Adv[A] = Pr[A wins]
```

### Game: Delegation Audit Zero-Knowledge

```
Game DelegationAuditPrivacy(λ):
  1. Challenger sets up two delegation chains C₀, C₁ of equal
     length with identical (auditPolicyMask, chainLength,
     sessionNonce) but different intermediate scopes and
     participants.
  2. Challenger flips bit b, generates ChainAuditProof for C_b.
  3. A receives the proof and all public signals.
  4. A outputs guess b'.

  Advantage: Adv[A] = |Pr[b' = b] - 1/2|
```

### Game: Intermediate Participant Anonymity

```
Game IntermediateAnonymity(λ):
  1. A chooses two enrolled agents a₀, a₁ to occupy hop k.
  2. Challenger builds chain with a_b at hop k, generates
     ChainAuditProof.
  3. A receives the proof, all public signals, and on-chain
     state (including per-hop DelegationHopAccumulator public
     outputs).
  4. A outputs guess b'.

  Advantage: Adv[A] = |Pr[b' = b] - 1/2|
```

### Game: Cross-Org Distrusting Auditor Soundness

```
Game CrossOrgDistrust(λ):
  1. Challenger sets up Bolyra with agents enrolled by k
     different organizations (distinct operator keys).
  2. A controls all k organizations and the auditor.
  3. A constructs a delegation chain spanning organizations
     and produces an audit artifact (ZKP or non-ZK).
  4. A wins if:
     (a) the artifact convinces a verifier that narrowing held, AND
     (b) some hop actually violated narrowing, AND
     (c) no single trusted third party was consulted during
         verification (no AS introspection, no issuer callback,
         no federation authority query).

  Advantage: Adv[A] = Pr[A wins]
```

This game captures the structural gap that persists even against BBS+ commit-and-prove extensions: verification must be self-contained in the artifact, with no interactive queries to any organization's infrastructure.

## 4. Security argument (named assumption + reduction sketch)

### Assumptions

- **A1: Poseidon collision resistance** over BN254 scalar field — no efficient adversary can find `(x, y) ≠ (x', y')` such that `Poseidon(x, y) = Poseidon(x', y')`.
- **A2: Knowledge soundness of PLONK** in the algebraic group model (AGM) + random oracle model (ROM) — the PLONK extractor recovers a valid witness from any convincing prover.
- **A3: Discrete log hardness on Baby Jubjub** — given `(Ax, Ay) = s * G`, recovering `s` is infeasible.
- **A4: Honest-verifier zero-knowledge of PLONK** — the simulator produces transcripts indistinguishable from real proofs.

### Soundness reduction

**Theorem:** If `A` wins `DelegationAuditSoundness` with non-negligible advantage, then either (i) PLONK knowledge soundness is broken (against A2), or (ii) Poseidon collision resistance is broken (against A1).

**Sketch:**

1. By A2, extract witness `w` from valid `ChainAuditProof` proof `π`. The witness contains `(rootScope, rootCredCommitment, accumulatorTrace[], scopeCommitmentTrace[], finalScope, finalCredCommitment, hopCount)`.
2. Constraint 2 forces `Poseidon2(rootScope, rootCredCommitment) = onChainChainSeed`. The on-chain seed was set during a verified handshake, so `rootScope` and `rootCredCommitment` are bound to the original delegator.
3. Constraint 3 initializes the accumulator deterministically from the seed.
4. Constraint 4 chains the accumulator: each `accumulatorTrace[i]` commits to the previous accumulator and `scopeCommitmentTrace[i]`. Because Poseidon is collision-resistant (A1), the extracted `scopeCommitmentTrace` is the unique sequence that produces `finalAccumulator`.
5. Each `scopeCommitmentTrace[i]` was a public output of a previously verified `DelegationHopAccumulator` proof. By A2, extract the per-hop witness: that hop's `(delegatorScope, delegateeScope)` satisfy `delegateeBits[j] * (1 - delegatorBits[j]) === 0` for all `j`. This is monotonic narrowing.
6. If `A` produced a valid `ChainAuditProof` where some hop violated narrowing, then either the per-hop PLONK extractor fails (breaks A2) or the accumulator trace was forged without matching the per-hop outputs (breaks A1 on Poseidon3).

**Cross-org distrusting auditor reduction:**

**Theorem:** If `A` wins `CrossOrgDistrust`, then either A1 or A2 is broken.

The reduction is identical to the soundness reduction above. The key observation is that the `ChainAuditProof` verification algorithm requires only the PLONK verification key and the on-chain public state (`onChainChainSeed`, `chainAccumulators`). It does not query any AS, issuer, or federation endpoint. The on-chain state is publicly readable and was itself populated by verified PLONK proofs, creating a closed verification loop with no external trust dependency.

**Privacy reduction:**

By A4 (PLONK HVZK), the `ChainAuditProof` is simulatable given only the public signals `(auditPolicyMask, sessionNonce, onChainChainSeed, auditResult, chainLength, chainDigest)`. Since intermediate scopes, participants, and accumulator traces are private inputs, they are hidden. The `chainDigest = Poseidon2(finalAccumulator, sessionNonce)` reveals nothing about intermediates under A1 (Poseidon is a one-way function in ROM). The per-hop `DelegationHopAccumulator` proofs reveal `newScopeCommitment` and `delegateeMerkleRoot`, but these are identity-bound hashes — recovering the scope or credential from the commitment requires inverting Poseidon (breaks A1). The `delegateeMerkleRoot` is shared across all agents enrolled in the tree, so it reveals only that the delegatee belongs to the tree, not which leaf.

## 5. Bolyra primitive mapping

| Construction element | Bolyra primitive | Spec reference |
|---------------------|-----------------|----------------|
| Scope commitment | `Poseidon2(permissionBitmask, credentialCommitment)` | §4 Composable Delegation |
| Chain linking | `previousScopeCommitment` public input checked against on-chain `lastScopeCommitment` | §4.2 Delegation Circuit |
| Scope subset enforcement | `delegateeBits[i] * (1 - delegatorBits[i]) === 0` for all `i` | §4.2 constraint 3 |
| Cumulative bit encoding | Bits 4→3→2 implication chain | §4.2 constraint 4 |
| Expiry narrowing | `LessEqThan(64)` | §4.2 constraint 5 |
| Delegation token | `Poseidon4(prevScope, delegateeCredComm, delegateeScope, delegateeExpiry)` | §4.2 constraint 6 |
| Delegator authorization | `EdDSAPoseidonVerifier` on Baby Jubjub | §4.2 constraint 7 |
| Delegatee enrollment | `BinaryMerkleRoot(20)` against agent tree | §4.2 constraint 8 |
| Accumulator hash | `Poseidon3(prevAcc, newScopeCommitment, hopIndex)` — new gadget, uses only Poseidon | — |
| Chain digest | `Poseidon2(finalAccumulator, sessionNonce)` — new gadget | — |
| Proving system (per-hop) | PLONK with universal setup (pot16.ptau) | §2.2 AgentPolicy/Delegation PLONK option |
| Proving system (audit) | PLONK with universal setup (pot16.ptau) | §2.2 |

All new gadgets use only Poseidon over BN254 — no new primitives introduced.

## 6. Circuit cost estimate

### `DelegationHopAccumulator` (PLONK)

| Component | Constraints |
|-----------|-------------|
| Existing Delegation circuit constraints | ~28,000 |
| Poseidon3 (accumulator update) | ~700 |
| Num2Bits(8) for hopIndex | 8 |
| **Total** | **~28,700** |

**Proving time target:** < 5s (PLONK agent-class, within pot16.ptau 2^16 = 65,536 constraint budget).

### `ChainAuditProof` (PLONK)

| Component | Constraints |
|-----------|-------------|
| Poseidon2 (root scope commitment check) | ~480 |
| Poseidon3 × 16 (accumulator chain, MAX_HOPS=16) | ~11,200 |
| Poseidon2 (final scope commitment check) | ~480 |
| Poseidon2 (chain digest) | ~480 |
| Num2Bits(64) × 2 (rootScope, finalScope) | 128 |
| Num2Bits(8) (hopCount) | 8 |
| Scope subset (64 AND constraints) | 64 |
| Cumulative bit encoding (3 constraints) | 3 |
| Multiplexer for unused hops (16 selectors) | ~256 |
| Equality constraints (seed binding, accumulator matching) | ~10 |
| **Total** | **~13,100** |

**Proving time target:** < 3s (PLONK, well within 2^16 budget). This is the auditor-facing proof — generated once per audit, not per hop.

### Combined budget

Both circuits fit comfortably under `pot16.ptau` (2^16 = 65,536 constraints). No new trusted setup or ceremony required.

## 7. Concrete deployment scenario

### Scenario: Multi-tool AI agent pipeline at Navy Federal Credit Union

**Stakeholder:** Navy Federal Credit Union (NFCU), the largest credit union in the US (13M+ members), subject to NCUA examination and GENIUS Act compliance.

**Setting:** NFCU deploys an AI agent pipeline for member loan processing. The pipeline has 4 hops:

1. **Root agent** (NFCU-operated, Claude-based) — holds `FINANCIAL_MEDIUM | WRITE_DATA | READ_DATA` (bits 0,1,3 → bitmask `0b00001011`). Authorized to pull credit reports and draft loan decisions.
2. **Credit scoring tool** (Experian API agent) — delegated `READ_DATA` only (bit 0 → `0b00000001`). Reads member data, returns a score. Cannot write or transact.
3. **Document generation tool** (internal DocGen agent) — delegated `WRITE_DATA | READ_DATA` (bits 0,1 → `0b00000011`). Produces the loan offer letter. Cannot transact.
4. **Member notification agent** (SendGrid agent) — delegated `READ_DATA` only (bit 0 → `0b00000001`). Sends the offer to the member. Cannot write internal records or transact.

**Audit trigger:** NCUA examiner arrives for annual examination. Wants to verify that no agent in the loan pipeline exceeded its mandate — specifically, that the Experian agent never had financial transaction authority and the SendGrid agent never had write access to member records.

**Without Bolyra (baseline — including BBS+ commit-and-prove):** An advanced baseline using BBS+ with Camenisch-Lysyanskaya commit-and-prove extensions and Bulletproofs range predicates could, in principle, prove hidden bitmask subset at a single hop within a single issuer's domain. However, the NCUA examiner faces a cross-org chain: NFCU's AS issued hop 1, Experian's infrastructure issued hop 2, and SendGrid's infrastructure issued hop 3. Each BBS+ credential has a different issuer. The examiner must either (a) contact each organization's AS/issuer endpoint to verify that hop's credential and its relationship to the prior hop, or (b) trust a federation authority that aggregates across issuers. Neither produces a self-contained artifact that the examiner can verify offline, without callbacks to infrastructure controlled by the organizations being audited. An auditor who distrusts NFCU's infrastructure — the point of an examination — cannot accept NFCU-signed attestations that narrowing occurred.

**With Bolyra `ChainAuditProof`:**

1. Each delegation hop was proven on-chain via `DelegationHopAccumulator` as the pipeline executed. The on-chain `chainAccumulators[sessionNonce]` and `lastScopeCommitment[sessionNonce]` were updated at each hop.
2. NFCU generates a `ChainAuditProof` with `auditPolicyMask = 0b00000001` (auditor wants to confirm the terminal agent had at least READ_DATA) and submits it.
3. The NCUA examiner verifies the PLONK proof on-chain (or off-chain against the verification key). The examiner learns:
   - `auditResult = 1` — the chain is valid and monotonically narrowing.
   - `chainLength = 4` — there were 4 hops.
   - `chainDigest` — a unique fingerprint for this specific chain (can be logged for future reference).
   - The terminal agent satisfies the audit policy.
4. The examiner does **not** learn: which vendors NFCU uses (Experian, SendGrid), what the intermediate scope values were, which agent models were involved, or the Merkle proof paths.
5. Critically, the examiner's verification requires **zero callbacks** to NFCU, Experian, or SendGrid infrastructure. The proof is self-contained. The examiner trusts math, not the auditee's servers.

**Whistleblower variant (journalist/source chain):** A source inside NFCU routes a document through 3 intermediary agents before it reaches a journalist's agent. Each hop narrows scope (source agent has full read, each intermediary drops one permission tier). The journalist's auditor verifies the chain narrowed correctly — proving the document came through a legitimate delegation chain from an authorized source — without learning any intermediary's identity. The `delegateeMerkleRoot` at each hop proves each intermediary was enrolled in the agent tree, but the tree contains thousands of agents, providing k-anonymity.

## 8. Why the baseline cannot match

### Acknowledging BBS+ commit-and-prove capabilities

The baseline analysis must account for BBS+ extensions beyond basic selective disclosure. The Camenisch-Lysyanskaya (CL) commit-and-prove framework, combined with Bulletproofs inner-product range proofs, enables predicates over committed (hidden) attributes — including proving that a committed bitmask `B_child` is a bitwise subset of a committed bitmask `B_parent` without revealing either value. Concretely, one can commit to each bit of both masks using Pedersen commitments, then prove `childBit_i * (1 - parentBit_i) = 0` using a Bulletproofs-style arithmetic circuit over the commitments. This is a real capability, demonstrated in academic constructions (e.g., Camenisch et al., "Efficient Attributes for Anonymous Credentials," 2012) and partially implemented in libraries like Hyperledger AnonCreds.

**We do not claim that hidden bitmask subset proof is impossible outside ZK-SNARKs.** The differentiator is not the predicate itself — it is the verification model.

### The structural differentiator: self-contained verification for a distrusting cross-org auditor

| Property | Bolyra `ChainAuditProof` | BBS+ commit-and-prove + CL + Bulletproofs |
|----------|------------------------|-------------------------------------------|
| **Single-hop hidden subset proof** | Yes (in-circuit) | **Yes** — CL commit-and-prove with Bulletproofs arithmetic circuits can prove `childBit[i] * (1 - parentBit[i]) = 0` over Pedersen-committed bitmasks. This is a real capability. |
| **Multi-hop chain as a single artifact** | Yes — `ChainAuditProof` collapses an N-hop chain into one PLONK proof (~1.1 KB). The accumulator binds all hops cryptographically. Verification is O(1). | **No** — each hop is a separate BBS+ credential from a separate issuer. The auditor receives N derived proofs, one per hop. There is no standard mechanism to compose N BBS+ proofs from N different issuers into a single verifiable artifact. The auditor must verify each hop independently and manually check that hop k's output links to hop k+1's input. |
| **Cross-org without issuer callbacks** | Yes — PLONK verification requires only the public verification key and on-chain state. No issuer, AS, or federation endpoint is contacted. | **No** — BBS+ verification requires the issuer's public key per credential. For a cross-org chain (Org A → Org B → Org C), the auditor must obtain and trust public keys from each organization. If the auditor distrusts Org A (which is the premise of a regulatory examination), Org A's issuer key is suspect. There is no mechanism to verify that Org A's BBS+ credential was legitimately issued without trusting Org A's key infrastructure. |
| **Distrusting auditor model** | The auditor trusts only: (1) the PLONK verification key (a public parameter generated during universal setup), and (2) the on-chain Merkle roots (publicly auditable state). Neither is controlled by any participant in the chain. | The auditor must trust each issuer's public key — meaning the auditor trusts, at minimum, the key management infrastructure of every organization in the chain. A regulatory examiner auditing NFCU must trust NFCU's BBS+ issuer key to verify NFCU-issued credentials. This is circular: the auditor trusts the auditee's infrastructure to verify the auditee's claims. |
| **Enrollment proof without identity disclosure** | `delegateeMerkleRoot` proves the delegatee is enrolled in a global agent tree (anonymity set = all enrolled agents). The tree root is on-chain and publicly verifiable. | BBS+ proves claims within a credential issued by a specific issuer. The credential itself implies the issuer identity (the issuer's public key is needed for verification). A derived proof from an Experian-issued credential reveals "this was issued by Experian" even with selective disclosure — the verification key is Experian's. |
| **In-circuit enforcement binding** | Narrowing is enforced by circuit constraints — proof generation is impossible if narrowing is violated. Enforcement and proof are the same object. | CL commit-and-prove predicates are verified at presentation time by the verifier, not enforced at issuance. An issuer can issue a credential with `scope = FINANCIAL_UNLIMITED` and the holder can present a derived proof claiming subset compliance. The subset predicate is between the holder's committed value and a reference — but who sets the reference? In a multi-hop chain, the "parent scope" at hop k is itself a committed value from hop k-1's credential, issued by a different organization. Linking these across issuers requires the auditor to verify the cross-issuer binding — which brings us back to the multi-issuer composition problem. |
| **Whistleblower safety** | All participant identities are private inputs to the PLONK circuit. Even the number of distinct organizations is hidden (only `chainLength` is revealed). | BBS+ selective disclosure hides claim values but the credential's verification key identifies the issuer. In a 3-hop whistleblower chain, the auditor learns "hop 1 was issued by Org X, hop 2 by Org Y, hop 3 by Org Z" — potentially enough to identify the source by process of elimination, even without seeing claim values. |
| **Constant-size audit artifact** | Single PLONK proof (~1.1 KB) regardless of chain length. Verification: ~300K gas on EVM, < 1ms off-chain. | N BBS+ derived proofs + N Bulletproofs range/arithmetic proofs. Each BBS+ proof is ~400 bytes; each Bulletproofs arithmetic proof is ~700 bytes for a 64-bit subset predicate. A 16-hop chain produces ~17 KB of proof material, plus N issuer public keys the auditor must resolve. |

### Summary of the gap

The fundamental differentiator is not "can you prove a hidden bitmask subset?" — BBS+ commit-and-prove extensions can. The differentiator is the **verification trust model for a cross-organizational, distrusting auditor**:

1. **BBS+ commit-and-prove** produces per-hop proofs that are individually valid but cannot be composed into a single cross-issuer artifact. The auditor must trust each issuer's key infrastructure, verify each hop independently, and manually confirm cross-hop linkage. For a regulatory examiner auditing the organizations themselves, this is circular — the examiner trusts the auditee's keys to verify the auditee's claims.

2. **Bolyra `ChainAuditProof`** produces a single artifact where the entire chain — including cross-org hops — is collapsed into one PLONK proof. Verification requires only a universal verification key (not controlled by any participant) and publicly auditable on-chain state. The auditor trusts cryptography, not the organizations being audited. This is the trust model a distrusting regulator, a whistleblower's auditor, or a cross-org compliance framework actually needs.
